#include "zara/plugins/manager.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <optional>
#include <sstream>
#include <string_view>
#include <thread>
#include <utility>

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "zara/ai/assistant.hpp"
#include "zara/analysis/program_analysis.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"
#include "zara/security/workflow.hpp"

namespace zara::plugins {

namespace {

constexpr std::string_view kSupportedPluginApiVersion = "1";
constexpr std::chrono::milliseconds kSandboxShutdownGracePeriod{500};

bool environment_truthy(const char* name) {
    const char* value = std::getenv(name);
    if (value == nullptr) {
        return false;
    }

    std::string normalized(value);
    std::transform(
        normalized.begin(),
        normalized.end(),
        normalized.begin(),
        [](unsigned char character) { return static_cast<char>(std::tolower(character)); }
    );
    return normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on";
}

bool is_denied_sandbox_import(std::string_view root) {
    static constexpr std::string_view kDeniedImports[] = {
        "ctypes",
        "importlib",
        "os",
        "shutil",
        "subprocess",
        "sys",
    };

    return std::find(kDeniedImports, std::end(kDeniedImports), root) != std::end(kDeniedImports);
}

std::optional<std::string> validate_sandbox_imports(const std::vector<std::string>& allowed_imports) {
    for (const auto& module_name : allowed_imports) {
        const std::string_view root =
            std::string_view(module_name).substr(0, std::string_view(module_name).find('.'));
        if (is_denied_sandbox_import(root)) {
            return "Plugin sandbox policy rejects allow_imports entry '" + module_name + "'.";
        }
    }
    return std::nullopt;
}

bool production_allows_unsandboxed_plugins() {
    return environment_truthy("ZARA_ENABLE_UNSANDBOXED_PLUGINS");
}

struct HookPayloadBundle {
    std::string summary_json;
    std::string context_json;
    std::string program_json;
    std::string ai_json;
    std::string security_json;
    std::vector<std::string> function_json;
};

std::string sanitize_module_name(std::string value) {
    for (char& character : value) {
        if (!std::isalnum(static_cast<unsigned char>(character))) {
            character = '_';
        }
    }

    if (value.empty() || std::isdigit(static_cast<unsigned char>(value.front()))) {
        value.insert(value.begin(), '_');
    }
    return value;
}

std::optional<std::string> read_text_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        return std::nullopt;
    }

    std::ostringstream stream;
    stream << input.rdbuf();
    return stream.str();
}

std::optional<std::string> extract_json_string(const std::string_view json, const std::string_view field) {
    const std::string key = "\"" + std::string(field) + "\"";
    const auto key_position = json.find(key);
    if (key_position == std::string_view::npos) {
        return std::nullopt;
    }

    const auto colon_position = json.find(':', key_position + key.size());
    if (colon_position == std::string_view::npos) {
        return std::nullopt;
    }

    const auto first_quote = json.find('"', colon_position + 1);
    if (first_quote == std::string_view::npos) {
        return std::nullopt;
    }

    const auto second_quote = json.find('"', first_quote + 1);
    if (second_quote == std::string_view::npos) {
        return std::nullopt;
    }

    return std::string(json.substr(first_quote + 1, second_quote - first_quote - 1));
}

std::optional<bool> extract_json_bool(const std::string_view json, const std::string_view field) {
    const std::string key = "\"" + std::string(field) + "\"";
    const auto key_position = json.find(key);
    if (key_position == std::string_view::npos) {
        return std::nullopt;
    }

    const auto colon_position = json.find(':', key_position + key.size());
    if (colon_position == std::string_view::npos) {
        return std::nullopt;
    }

    const auto value_position = json.find_first_not_of(" \t\r\n", colon_position + 1);
    if (value_position == std::string_view::npos) {
        return std::nullopt;
    }

    if (json.compare(value_position, 4, "true") == 0) {
        return true;
    }
    if (json.compare(value_position, 5, "false") == 0) {
        return false;
    }
    return std::nullopt;
}

std::optional<std::size_t> extract_json_unsigned(const std::string_view json, const std::string_view field) {
    const std::string key = "\"" + std::string(field) + "\"";
    const auto key_position = json.find(key);
    if (key_position == std::string_view::npos) {
        return std::nullopt;
    }

    const auto colon_position = json.find(':', key_position + key.size());
    if (colon_position == std::string_view::npos) {
        return std::nullopt;
    }

    const auto value_position = json.find_first_of("0123456789", colon_position + 1);
    if (value_position == std::string_view::npos) {
        return std::nullopt;
    }

    const auto value_end = json.find_first_not_of("0123456789", value_position);
    return static_cast<std::size_t>(
        std::stoull(std::string(json.substr(value_position, value_end - value_position)))
    );
}

std::vector<std::string> extract_json_string_array(const std::string_view json, const std::string_view field) {
    const std::string key = "\"" + std::string(field) + "\"";
    const auto key_position = json.find(key);
    if (key_position == std::string_view::npos) {
        return {};
    }

    const auto colon_position = json.find(':', key_position + key.size());
    if (colon_position == std::string_view::npos) {
        return {};
    }

    const auto open_bracket = json.find('[', colon_position + 1);
    if (open_bracket == std::string_view::npos) {
        return {};
    }
    const auto close_bracket = json.find(']', open_bracket + 1);
    if (close_bracket == std::string_view::npos) {
        return {};
    }

    std::vector<std::string> values;
    std::size_t cursor = open_bracket + 1;
    while (cursor < close_bracket) {
        const auto first_quote = json.find('"', cursor);
        if (first_quote == std::string_view::npos || first_quote >= close_bracket) {
            break;
        }
        const auto second_quote = json.find('"', first_quote + 1);
        if (second_quote == std::string_view::npos || second_quote > close_bracket) {
            break;
        }
        values.emplace_back(json.substr(first_quote + 1, second_quote - first_quote - 1));
        cursor = second_quote + 1;
    }
    return values;
}

std::vector<std::string> extract_json_object_array(const std::string_view json, const std::string_view field) {
    const std::string key = "\"" + std::string(field) + "\"";
    const auto key_position = json.find(key);
    if (key_position == std::string_view::npos) {
        return {};
    }

    const auto colon_position = json.find(':', key_position + key.size());
    if (colon_position == std::string_view::npos) {
        return {};
    }

    const auto open_bracket = json.find('[', colon_position + 1);
    if (open_bracket == std::string_view::npos) {
        return {};
    }

    std::vector<std::string> objects;
    std::size_t cursor = open_bracket + 1;
    while (cursor < json.size()) {
        const auto open_brace = json.find('{', cursor);
        if (open_brace == std::string_view::npos) {
            break;
        }

        int depth = 0;
        std::size_t close_brace = open_brace;
        for (; close_brace < json.size(); ++close_brace) {
            if (json[close_brace] == '{') {
                ++depth;
            } else if (json[close_brace] == '}') {
                --depth;
                if (depth == 0) {
                    break;
                }
            } else if (json[close_brace] == ']' && depth == 0) {
                break;
            }
        }

        if (depth != 0 || close_brace >= json.size()) {
            break;
        }

        objects.emplace_back(json.substr(open_brace, close_brace - open_brace + 1));
        cursor = close_brace + 1;
        const auto close_bracket = json.find(']', cursor);
        const auto next_brace = json.find('{', cursor);
        if (close_bracket != std::string_view::npos &&
            (next_brace == std::string_view::npos || close_bracket < next_brace)) {
            break;
        }
    }

    return objects;
}

std::string python_string_literal(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);
    for (const char character : value) {
        switch (character) {
        case '\\':
            escaped += "\\\\";
            break;
        case '\'':
            escaped += "\\'";
            break;
        case '\n':
            escaped += "\\n";
            break;
        default:
            escaped.push_back(character);
            break;
        }
    }
    return "'" + escaped + "'";
}

std::string json_escape(const std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);
    for (const char character : value) {
        switch (character) {
        case '\\':
            escaped += "\\\\";
            break;
        case '"':
            escaped += "\\\"";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            escaped.push_back(character);
            break;
        }
    }
    return escaped;
}

std::string json_string(const std::string_view value) {
    return "\"" + json_escape(value) + "\"";
}

std::string json_optional_address(const std::optional<std::uint64_t> value) {
    if (!value.has_value()) {
        return "null";
    }
    return std::to_string(*value);
}

std::string bool_json(const bool value) {
    return value ? "true" : "false";
}

std::string json_string_array(const std::vector<std::string>& values) {
    std::ostringstream stream;
    stream << '[';
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index > 0) {
            stream << ',';
        }
        stream << json_string(values[index]);
    }
    stream << ']';
    return stream.str();
}

bool copy_directory_tree(
    const std::filesystem::path& source_root,
    const std::filesystem::path& destination_root,
    std::string& out_error
) {
    out_error.clear();
    std::error_code error_code;
    std::filesystem::create_directories(destination_root, error_code);
    if (error_code) {
        out_error = "Failed to create destination directory " + destination_root.string() + ": " + error_code.message();
        return false;
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(source_root)) {
        const auto relative_path = std::filesystem::relative(entry.path(), source_root, error_code);
        if (error_code) {
            out_error = "Failed to compute relative marketplace path: " + error_code.message();
            return false;
        }
        const auto target_path = destination_root / relative_path;
        if (entry.is_directory()) {
            std::filesystem::create_directories(target_path, error_code);
            if (error_code) {
                out_error = "Failed to create plugin directory " + target_path.string() + ": " + error_code.message();
                return false;
            }
            continue;
        }
        if (entry.is_regular_file()) {
            std::filesystem::create_directories(target_path.parent_path(), error_code);
            error_code.clear();
            std::filesystem::copy_file(entry.path(), target_path, std::filesystem::copy_options::overwrite_existing, error_code);
            if (error_code) {
                out_error = "Failed to install marketplace file " + target_path.string() + ": " + error_code.message();
                return false;
            }
        }
    }
    return true;
}

std::string build_startup_json(const PluginDescriptor& plugin) {
    std::ostringstream stream;
    stream << '{'
           << "\"name\":" << json_string(plugin.name) << ','
           << "\"version\":" << json_string(plugin.version) << ','
           << "\"api_version\":" << json_string(plugin.api_version) << ','
           << "\"description\":" << json_string(plugin.description) << ','
           << "\"root\":" << json_string(plugin.root_path.string()) << ','
           << "\"entry\":" << json_string(plugin.entry_script.string()) << ','
           << "\"capabilities\":" << json_string_array(plugin.capabilities) << ','
           << "\"sandboxed\":" << bool_json(plugin.sandboxed) << ','
           << "\"timeout_ms\":" << plugin.timeout_ms << ','
           << "\"hooks\":" << json_string_array(plugin.declared_hooks) << ','
           << "\"env\":{";
    for (std::size_t index = 0; index < plugin.allowed_env.size(); ++index) {
        if (index > 0) {
            stream << ',';
        }
        const char* value = std::getenv(plugin.allowed_env[index].c_str());
        stream << json_string(plugin.allowed_env[index]) << ':' << json_string(value == nullptr ? "" : value);
    }
    stream << "}"
           << '}';
    return stream.str();
}

std::string build_summary_json(
    const std::filesystem::path& binary_path,
    const loader::BinaryImage& image,
    const analysis::ProgramAnalysis& program
) {
    std::ostringstream stream;
    stream << '{'
           << "\"path\":" << json_string(std::filesystem::absolute(binary_path).string()) << ','
           << "\"format\":" << json_string(loader::to_string(image.format())) << ','
           << "\"architecture\":" << json_string(loader::to_string(image.architecture())) << ','
           << "\"base_address\":" << image.base_address() << ','
           << "\"entry_point\":" << json_optional_address(image.entry_point()) << ','
           << "\"function_count\":" << program.functions.size() << ','
           << "\"call_count\":" << program.call_graph.size() << ','
           << "\"xref_count\":" << program.xrefs.size() << ','
           << "\"string_count\":" << program.strings.size() << ','
           << "\"import_count\":" << image.imports().size() << ','
           << "\"export_count\":" << image.exports().size()
           << '}';
    return stream.str();
}

std::string build_function_json(const analysis::DiscoveredFunction& function) {
    std::size_t instruction_count = 0;
    for (const auto& block : function.graph.blocks()) {
        instruction_count += block.instructions.size();
    }

    std::ostringstream stream;
    stream << '{'
           << "\"entry_address\":" << function.entry_address << ','
           << "\"name\":" << json_string(function.name) << ','
           << "\"section\":" << json_string(function.section_name) << ','
           << "\"block_count\":" << function.graph.blocks().size() << ','
           << "\"instruction_count\":" << instruction_count << ','
           << "\"loop_count\":" << function.graph.loops().size() << ','
           << "\"switch_count\":" << function.graph.switches().size() << ','
           << "\"calling_convention\":" << json_string(analysis::to_string(function.summary.calling_convention)) << ','
           << "\"stack_frame_size\":" << function.summary.stack_frame_size << ','
           << "\"decompiled\":" << json_string(function.decompiled.pseudocode)
           << '}';
    return stream.str();
}

std::string build_program_json(
    const std::filesystem::path& binary_path,
    const loader::BinaryImage& image,
    const analysis::ProgramAnalysis& program
) {
    std::ostringstream stream;
    stream << '{'
           << "\"path\":" << json_string(std::filesystem::absolute(binary_path).string()) << ','
           << "\"summary\":" << build_summary_json(binary_path, image, program) << ','
           << "\"functions\":[";
    for (std::size_t index = 0; index < program.functions.size(); ++index) {
        if (index > 0) {
            stream << ',';
        }
        stream << build_function_json(program.functions[index]);
    }
    stream << "],\"imports\":" << image.imports().size()
           << ",\"exports\":" << image.exports().size()
           << '}';
    return stream.str();
}

std::string build_ai_json(const std::vector<ai::FunctionInsight>& insights) {
    std::ostringstream stream;
    stream << '[';
    for (std::size_t index = 0; index < insights.size(); ++index) {
        const auto& insight = insights[index];
        if (index > 0) {
            stream << ',';
        }

        stream << '{'
               << "\"entry_address\":" << insight.entry_address << ','
               << "\"current_name\":" << json_string(insight.current_name) << ','
               << "\"suggested_name\":" << json_string(insight.suggested_name) << ','
               << "\"summary\":" << json_string(insight.summary) << ','
               << "\"hints\":" << json_string_array(insight.hints) << ','
               << "\"patterns\":[";
        for (std::size_t pattern_index = 0; pattern_index < insight.patterns.size(); ++pattern_index) {
            const auto& pattern = insight.patterns[pattern_index];
            if (pattern_index > 0) {
                stream << ',';
            }
            stream << '{'
                   << "\"category\":" << json_string(pattern.category) << ','
                   << "\"label\":" << json_string(pattern.label) << ','
                   << "\"confidence\":" << json_string(pattern.confidence) << ','
                   << "\"detail\":" << json_string(pattern.detail)
                   << '}';
        }
        stream << "],\"vulnerability_hints\":[";
        for (std::size_t hint_index = 0; hint_index < insight.vulnerability_hints.size(); ++hint_index) {
            const auto& hint = insight.vulnerability_hints[hint_index];
            if (hint_index > 0) {
                stream << ',';
            }
            stream << '{'
                   << "\"severity\":" << json_string(hint.severity) << ','
                   << "\"title\":" << json_string(hint.title) << ','
                   << "\"detail\":" << json_string(hint.detail)
                   << '}';
        }
        stream << ']'
               << '}';
    }
    stream << ']';
    return stream.str();
}

std::string build_security_json(const security::ExploitReport& report) {
    std::ostringstream stream;
    stream << '{'
           << "\"findings\":[";
    for (std::size_t index = 0; index < report.findings.size(); ++index) {
        const auto& finding = report.findings[index];
        if (index > 0) {
            stream << ',';
        }
        stream << '{'
               << "\"severity\":" << json_string(security::to_string(finding.severity)) << ','
               << "\"category\":" << json_string(finding.category) << ','
               << "\"function_entry\":" << finding.function_entry << ','
               << "\"function_name\":" << json_string(finding.function_name) << ','
               << "\"title\":" << json_string(finding.title) << ','
               << "\"detail\":" << json_string(finding.detail)
               << '}';
    }
    stream << "],\"patterns\":[";
    for (std::size_t index = 0; index < report.patterns.size(); ++index) {
        const auto& pattern = report.patterns[index];
        if (index > 0) {
            stream << ',';
        }
        stream << '{'
               << "\"severity\":" << json_string(security::to_string(pattern.severity)) << ','
               << "\"category\":" << json_string(pattern.category) << ','
               << "\"function_entry\":" << pattern.function_entry << ','
               << "\"function_name\":" << json_string(pattern.function_name) << ','
               << "\"title\":" << json_string(pattern.title) << ','
               << "\"detail\":" << json_string(pattern.detail) << ','
               << "\"poc_notes\":" << json_string_array(pattern.poc_notes)
               << '}';
    }
    stream << "],\"poc_targets\":[";
    for (std::size_t index = 0; index < report.poc_targets.size(); ++index) {
        const auto& target = report.poc_targets[index];
        if (index > 0) {
            stream << ',';
        }
        stream << '{'
               << "\"role\":" << json_string(target.role) << ','
               << "\"function_entry\":" << target.function_entry << ','
               << "\"function_name\":" << json_string(target.function_name) << ','
               << "\"notes\":" << json_string_array(target.notes)
               << '}';
    }
    stream << "],\"gadgets\":[";
    for (std::size_t index = 0; index < report.gadgets.size(); ++index) {
        const auto& gadget = report.gadgets[index];
        if (index > 0) {
            stream << ',';
        }
        stream << '{'
               << "\"address\":" << gadget.address << ','
               << "\"sequence\":" << json_string(gadget.sequence) << ','
               << "\"function_name\":" << json_string(gadget.function_name)
               << '}';
    }
    stream << "],\"poc_scaffold\":" << json_string(report.poc_scaffold) << '}';
    return stream.str();
}

bool build_hook_payloads(
    const std::filesystem::path& binary_path,
    HookPayloadBundle& out_payloads,
    std::string& out_error
) {
    out_error.clear();

    loader::BinaryImage image;
    if (!loader::BinaryImage::load_from_file(binary_path, image, out_error)) {
        return false;
    }

    memory::AddressSpace address_space;
    if (!address_space.map_image(image)) {
        out_error = "Failed to map image into address space.";
        return false;
    }

    const analysis::ProgramAnalysis program = analysis::Analyzer::analyze(image, address_space);
    const auto insights = ai::Assistant::analyze_program(program, image.entry_point());
    const auto report = security::Workflow::analyze_exploit_surface(binary_path, program);

    out_payloads.summary_json = build_summary_json(binary_path, image, program);
    out_payloads.context_json =
        "{\"path\":" + json_string(std::filesystem::absolute(binary_path).string()) + ",\"summary\":" +
        out_payloads.summary_json + '}';
    out_payloads.program_json = build_program_json(binary_path, image, program);
    out_payloads.ai_json = build_ai_json(insights);
    out_payloads.security_json = build_security_json(report);
    out_payloads.function_json.clear();
    out_payloads.function_json.reserve(program.functions.size());
    for (const auto& function : program.functions) {
        out_payloads.function_json.push_back(build_function_json(function));
    }
    return true;
}

bool sandbox_supported() noexcept {
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    return true;
#else
    return false;
#endif
}

std::filesystem::path plugin_host_script_path() {
#if defined(ZARA_PLUGIN_HOST_SCRIPT_SOURCE)
    const auto source_path = std::filesystem::path(ZARA_PLUGIN_HOST_SCRIPT_SOURCE);
    if (std::filesystem::exists(source_path)) {
        return source_path;
    }
#endif
#if defined(ZARA_PLUGIN_HOST_SCRIPT_INSTALL)
    const auto install_path = std::filesystem::path(ZARA_PLUGIN_HOST_SCRIPT_INSTALL);
    if (std::filesystem::exists(install_path)) {
        return install_path;
    }
    return install_path;
#else
    return {};
#endif
}

std::string build_sandbox_command_json(const std::string& hook_name, const std::string& payload_json) {
    std::ostringstream stream;
    stream << '{'
           << "\"command\":\"call\","
           << "\"hook\":" << json_string(hook_name) << ','
           << "\"payload\":" << payload_json
           << '}';
    return stream.str();
}

bool is_success_reply(const std::string_view reply) {
    return reply.find("\"ok\":true") != std::string_view::npos;
}

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
bool write_all(std::FILE* stream, const std::string& line) {
    if (stream == nullptr) {
        return false;
    }
    const auto written = std::fwrite(line.data(), 1, line.size(), stream);
    if (written != line.size()) {
        return false;
    }
    return std::fflush(stream) == 0;
}

bool read_reply_line(const int fd, const std::size_t timeout_ms, std::string& out_line, std::string& out_error) {
    out_error.clear();
    out_line.clear();

    pollfd descriptor{
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };
    const int poll_result = poll(&descriptor, 1, static_cast<int>(timeout_ms));
    if (poll_result < 0) {
        out_error = "Plugin sandbox poll failed: " + std::string(std::strerror(errno));
        return false;
    }
    if (poll_result == 0) {
        out_error = "Plugin sandbox timed out waiting for a reply.";
        return false;
    }

    char character = '\0';
    while (true) {
        const auto bytes_read = read(fd, &character, 1);
        if (bytes_read < 0) {
            out_error = "Plugin sandbox read failed: " + std::string(std::strerror(errno));
            return false;
        }
        if (bytes_read == 0) {
            out_error = "Plugin sandbox closed unexpectedly.";
            return false;
        }
        if (character == '\n') {
            return true;
        }
        out_line.push_back(character);
    }
}
#endif

}  // namespace

PluginManager::PluginManager() = default;

PluginManager::~PluginManager() {
    stop_all_sandboxes();
}

bool PluginManager::is_available() const noexcept {
    return engine_.is_available() || sandbox_supported();
}

bool PluginManager::discover(
    const std::filesystem::path& plugins_directory,
    std::vector<PluginDescriptor>& out_plugins,
    std::string& out_error
) const {
    out_error.clear();
    out_plugins.clear();

    if (!std::filesystem::exists(plugins_directory)) {
        return true;
    }

    for (const auto& entry : std::filesystem::directory_iterator(plugins_directory)) {
        if (!entry.is_directory()) {
            continue;
        }

        const std::filesystem::path root_path = entry.path();
        std::filesystem::path entry_script = root_path / "plugin.py";
        std::string name = root_path.filename().string();
        std::string version = "1.0.0";
        std::string api_version = std::string(kSupportedPluginApiVersion);
        std::string description;
        std::vector<std::string> capabilities;
        std::vector<std::string> declared_hooks;
        bool sandboxed = false;
        std::size_t timeout_ms = 5000;
        std::vector<std::string> allowed_imports;
        std::vector<std::string> allowed_env;

        const std::filesystem::path manifest_path = root_path / "plugin.json";
        if (std::filesystem::exists(manifest_path)) {
            const auto manifest = read_text_file(manifest_path);
            if (!manifest.has_value()) {
                out_error = "Failed to read plugin manifest " + manifest_path.string();
                return false;
            }

            if (const auto manifest_name = extract_json_string(*manifest, "name"); manifest_name.has_value()) {
                name = *manifest_name;
            }
            if (const auto manifest_version = extract_json_string(*manifest, "version"); manifest_version.has_value()) {
                version = *manifest_version;
            }
            if (const auto manifest_api_version = extract_json_string(*manifest, "api_version"); manifest_api_version.has_value()) {
                api_version = *manifest_api_version;
            }
            if (const auto manifest_description = extract_json_string(*manifest, "description"); manifest_description.has_value()) {
                description = *manifest_description;
            }
            if (const auto manifest_entry = extract_json_string(*manifest, "entry"); manifest_entry.has_value()) {
                entry_script = root_path / *manifest_entry;
            }
            if (const auto manifest_sandboxed = extract_json_bool(*manifest, "sandboxed"); manifest_sandboxed.has_value()) {
                sandboxed = *manifest_sandboxed;
            }
            if (const auto manifest_timeout = extract_json_unsigned(*manifest, "timeout_ms"); manifest_timeout.has_value()) {
                timeout_ms = *manifest_timeout;
            }
            capabilities = extract_json_string_array(*manifest, "capabilities");
            declared_hooks = extract_json_string_array(*manifest, "hooks");
            allowed_imports = extract_json_string_array(*manifest, "allow_imports");
            allowed_env = extract_json_string_array(*manifest, "allow_env");
        }

        if (!std::filesystem::exists(entry_script)) {
            continue;
        }

        out_plugins.push_back(
            PluginDescriptor{
                .name = name,
                .version = version,
                .api_version = api_version,
                .description = description,
                .module_name = "zara_plugin_" + sanitize_module_name(root_path.filename().string()),
                .root_path = root_path,
                .entry_script = entry_script,
                .capabilities = std::move(capabilities),
                .declared_hooks = declared_hooks,
                .sandboxed = sandboxed,
                .timeout_ms = timeout_ms,
                .allowed_imports = std::move(allowed_imports),
                .allowed_env = std::move(allowed_env),
            }
        );
    }

    std::sort(
        out_plugins.begin(),
        out_plugins.end(),
        [](const PluginDescriptor& lhs, const PluginDescriptor& rhs) { return lhs.name < rhs.name; }
    );
    return true;
}

PluginManager::SandboxRuntime* PluginManager::find_sandbox(const std::string& module_name) noexcept {
    for (auto& runtime : sandboxes_) {
        if (runtime.module_name == module_name) {
            return &runtime;
        }
    }
    return nullptr;
}

bool PluginManager::run_hook_script(const std::string& script, const std::string& failure_context, std::string& out_error) {
    if (!engine_.execute_string(script, out_error)) {
        out_error = failure_context + ": " + out_error;
        return false;
    }
    return true;
}

bool PluginManager::start_sandbox(const PluginDescriptor& plugin, std::string& out_error) {
    out_error.clear();

    if (!plugin.sandboxed) {
        return true;
    }

    if (!sandbox_supported()) {
        out_error = "Plugin sandboxing is unavailable on this platform.";
        return false;
    }
    if (const auto policy_error = validate_sandbox_imports(plugin.allowed_imports); policy_error.has_value()) {
        out_error = *policy_error;
        return false;
    }

    const auto host_script = plugin_host_script_path();
    if (host_script.empty() || !std::filesystem::exists(host_script)) {
        out_error = "Plugin sandbox host script is unavailable.";
        return false;
    }

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    int parent_to_child[2]{-1, -1};
    int child_to_parent[2]{-1, -1};
    if (pipe(parent_to_child) != 0 || pipe(child_to_parent) != 0) {
        out_error = "Failed to create plugin sandbox pipes: " + std::string(std::strerror(errno));
        if (parent_to_child[0] >= 0) {
            close(parent_to_child[0]);
        }
        if (parent_to_child[1] >= 0) {
            close(parent_to_child[1]);
        }
        if (child_to_parent[0] >= 0) {
            close(child_to_parent[0]);
        }
        if (child_to_parent[1] >= 0) {
            close(child_to_parent[1]);
        }
        return false;
    }

    const pid_t child = fork();
    if (child < 0) {
        out_error = "Failed to fork plugin sandbox: " + std::string(std::strerror(errno));
        close(parent_to_child[0]);
        close(parent_to_child[1]);
        close(child_to_parent[0]);
        close(child_to_parent[1]);
        return false;
    }

    if (child == 0) {
        dup2(parent_to_child[0], STDIN_FILENO);
        dup2(child_to_parent[1], STDOUT_FILENO);
        dup2(child_to_parent[1], STDERR_FILENO);

        close(parent_to_child[0]);
        close(parent_to_child[1]);
        close(child_to_parent[0]);
        close(child_to_parent[1]);

        const std::string allowed_imports_json = json_string_array(plugin.allowed_imports);
        const std::string allowed_env_json = json_string_array(plugin.allowed_env);
        const std::string timeout_value = std::to_string(plugin.timeout_ms);
        execlp(
            "python3",
            "python3",
            "-I",
            "-B",
            host_script.string().c_str(),
            plugin.entry_script.string().c_str(),
            allowed_imports_json.c_str(),
            allowed_env_json.c_str(),
            timeout_value.c_str(),
            static_cast<char*>(nullptr)
        );
        _exit(127);
    }

    close(parent_to_child[0]);
    close(child_to_parent[1]);

    std::FILE* input_stream = fdopen(parent_to_child[1], "w");
    if (input_stream == nullptr) {
        out_error = "Failed to open plugin sandbox input stream.";
        close(parent_to_child[1]);
        close(child_to_parent[0]);
        kill(child, SIGKILL);
        int status = 0;
        waitpid(child, &status, 0);
        return false;
    }

    setvbuf(input_stream, nullptr, _IOLBF, 0);
    sandboxes_.push_back(
        SandboxRuntime{
            .module_name = plugin.module_name,
            .entry_script = plugin.entry_script,
            .timeout_ms = plugin.timeout_ms,
            .process_id = child,
            .output_fd = child_to_parent[0],
            .input_stream = input_stream,
        }
    );
    return true;
#else
    out_error = "Plugin sandboxing is unavailable on this platform.";
    return false;
#endif
}

bool PluginManager::stop_sandbox(SandboxRuntime& runtime, std::string& out_error) {
    out_error.clear();

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    if (runtime.input_stream != nullptr) {
        (void)write_all(runtime.input_stream, "{\"command\":\"shutdown\"}\n");
        std::fclose(runtime.input_stream);
        runtime.input_stream = nullptr;
    }

    if (runtime.output_fd >= 0) {
        close(runtime.output_fd);
        runtime.output_fd = -1;
    }

    if (runtime.process_id > 0) {
        int status = 0;
        bool exited = false;
        const auto deadline = std::chrono::steady_clock::now() + kSandboxShutdownGracePeriod;
        while (std::chrono::steady_clock::now() < deadline) {
            const pid_t wait_result = waitpid(runtime.process_id, &status, WNOHANG);
            if (wait_result == runtime.process_id) {
                exited = true;
                break;
            }
            if (wait_result < 0) {
                out_error = "Failed to wait for plugin sandbox shutdown: " + std::string(std::strerror(errno));
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        if (!exited) {
            if (kill(runtime.process_id, SIGKILL) != 0 && errno != ESRCH) {
                out_error = "Failed to terminate hung plugin sandbox: " + std::string(std::strerror(errno));
                return false;
            }
            if (waitpid(runtime.process_id, &status, 0) < 0 && errno != ECHILD) {
                out_error = "Failed to reap terminated plugin sandbox: " + std::string(std::strerror(errno));
                return false;
            }
        }
        runtime.process_id = -1;
    }
#else
    (void)runtime;
#endif

    return true;
}

void PluginManager::stop_all_sandboxes() noexcept {
    for (auto& runtime : sandboxes_) {
        std::string ignore_error;
        (void)stop_sandbox(runtime, ignore_error);
    }
    sandboxes_.clear();
}

bool PluginManager::send_sandbox_hook(
    const PluginDescriptor& plugin,
    const std::string& hook_name,
    const std::string& payload_json,
    std::string& out_error
) {
    out_error.clear();

    SandboxRuntime* runtime = find_sandbox(plugin.module_name);
    if (runtime == nullptr) {
        out_error = "Plugin sandbox is not running for " + plugin.name;
        return false;
    }

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    const std::string command = build_sandbox_command_json(hook_name, payload_json) + '\n';
    if (!write_all(runtime->input_stream, command)) {
        out_error = "Failed to write command to plugin sandbox.";
        return false;
    }

    std::string reply;
    if (!read_reply_line(runtime->output_fd, runtime->timeout_ms, reply, out_error)) {
        return false;
    }

    if (!is_success_reply(reply)) {
        out_error = extract_json_string(reply, "error").value_or("Plugin sandbox reported an unknown failure.");
        return false;
    }
    return true;
#else
    (void)hook_name;
    (void)payload_json;
    out_error = "Plugin sandboxing is unavailable on this platform.";
    return false;
#endif
}

bool PluginManager::load_all(const std::filesystem::path& plugins_directory, std::string& out_error) {
    out_error.clear();
    stop_all_sandboxes();
    loaded_plugins_.clear();

    if (!discover(plugins_directory, loaded_plugins_, out_error)) {
        return false;
    }

    for (const auto& plugin : loaded_plugins_) {
        if (plugin.api_version != kSupportedPluginApiVersion) {
            out_error = "Plugin " + plugin.name + " targets unsupported API version " + plugin.api_version + ".";
            stop_all_sandboxes();
            loaded_plugins_.clear();
            return false;
        }

        if (!plugin.sandboxed && !production_allows_unsandboxed_plugins()) {
            out_error =
                "Non-sandboxed plugin " + plugin.name +
                " is disabled by default. Set ZARA_ENABLE_UNSANDBOXED_PLUGINS=1 only in trusted developer environments.";
            stop_all_sandboxes();
            loaded_plugins_.clear();
            return false;
        }

        if (!plugin.sandboxed && !engine_.is_available()) {
            out_error = "Embedded Python is unavailable for non-sandboxed plugin " + plugin.name + '.';
            stop_all_sandboxes();
            loaded_plugins_.clear();
            return false;
        }

        if (plugin.sandboxed) {
            if (!start_sandbox(plugin, out_error)) {
                stop_all_sandboxes();
                loaded_plugins_.clear();
                return false;
            }

            if (!send_sandbox_hook(plugin, "on_startup", build_startup_json(plugin), out_error)) {
                stop_all_sandboxes();
                loaded_plugins_.clear();
                return false;
            }
            continue;
        }

        const std::string script =
            "import importlib.util\n"
            "import json\n"
            "_spec = importlib.util.spec_from_file_location(" + python_string_literal(plugin.module_name) + ", " +
            python_string_literal(plugin.entry_script.string()) + ")\n"
            "if _spec is None or _spec.loader is None:\n"
            "    raise RuntimeError('failed to create plugin spec')\n"
            "_module = importlib.util.module_from_spec(_spec)\n"
            "_spec.loader.exec_module(_module)\n"
            "globals()[" + python_string_literal(plugin.module_name) + "] = _module\n"
            "if hasattr(_module, 'on_startup'):\n"
            "    _module.on_startup(json.loads(" + python_string_literal(build_startup_json(plugin)) + "))\n";

        if (!run_hook_script(script, "Plugin load failed for " + plugin.name, out_error)) {
            stop_all_sandboxes();
            loaded_plugins_.clear();
            return false;
        }
    }

    return true;
}

bool PluginManager::run_analysis_hooks(const std::filesystem::path& binary_path, std::string& out_error) {
    out_error.clear();

    HookPayloadBundle payloads;
    if (!build_hook_payloads(binary_path, payloads, out_error)) {
        return false;
    }

    for (const auto& plugin : loaded_plugins_) {
        if (plugin.sandboxed) {
            if (!send_sandbox_hook(plugin, "before_binary_analyzed", payloads.context_json, out_error) ||
                !send_sandbox_hook(plugin, "on_program_analyzed", payloads.program_json, out_error) ||
                !send_sandbox_hook(plugin, "on_ai_insights", payloads.ai_json, out_error) ||
                !send_sandbox_hook(plugin, "on_security_report", payloads.security_json, out_error)) {
                out_error = "Plugin hook failed for " + plugin.name + ": " + out_error;
                return false;
            }
            for (const auto& function_json : payloads.function_json) {
                if (!send_sandbox_hook(plugin, "on_function_analyzed", function_json, out_error)) {
                    out_error = "Plugin hook failed for " + plugin.name + ": " + out_error;
                    return false;
                }
            }
            if (!send_sandbox_hook(plugin, "on_binary_analyzed", payloads.summary_json, out_error)) {
                out_error = "Plugin hook failed for " + plugin.name + ": " + out_error;
                return false;
            }
            continue;
        }

        if (!engine_.is_available()) {
            out_error = "Embedded Python is unavailable.";
            return false;
        }

        const std::string script =
            "import json\n"
            "_plugin = globals().get(" + python_string_literal(plugin.module_name) + ")\n"
            "if _plugin is not None:\n"
            "    _summary = json.loads(" + python_string_literal(payloads.summary_json) + ")\n"
            "    _context = json.loads(" + python_string_literal(payloads.context_json) + ")\n"
            "    _program = json.loads(" + python_string_literal(payloads.program_json) + ")\n"
            "    _insights = json.loads(" + python_string_literal(payloads.ai_json) + ")\n"
            "    _security = json.loads(" + python_string_literal(payloads.security_json) + ")\n"
            "    if hasattr(_plugin, 'before_binary_analyzed'):\n"
            "        _plugin.before_binary_analyzed(_context)\n"
            "    if hasattr(_plugin, 'on_program_analyzed'):\n"
            "        _plugin.on_program_analyzed(_program)\n"
            "    if hasattr(_plugin, 'on_ai_insights'):\n"
            "        _plugin.on_ai_insights(_insights)\n"
            "    if hasattr(_plugin, 'on_security_report'):\n"
            "        _plugin.on_security_report(_security)\n";

        if (!run_hook_script(script, "Plugin hook failed for " + plugin.name, out_error)) {
            return false;
        }

        for (const auto& function_json : payloads.function_json) {
            const std::string function_script =
                "import json\n"
                "_plugin = globals().get(" + python_string_literal(plugin.module_name) + ")\n"
                "if _plugin is not None:\n"
                "    _function = json.loads(" + python_string_literal(function_json) + ")\n"
                "    if hasattr(_plugin, 'on_function_analyzed'):\n"
                "        _plugin.on_function_analyzed(_function)\n";
            if (!run_hook_script(function_script, "Plugin hook failed for " + plugin.name, out_error)) {
                return false;
            }
        }

        const std::string final_script =
            "import json\n"
            "_plugin = globals().get(" + python_string_literal(plugin.module_name) + ")\n"
            "if _plugin is not None:\n"
            "    _summary = json.loads(" + python_string_literal(payloads.summary_json) + ")\n"
            "    if hasattr(_plugin, 'on_binary_analyzed'):\n"
            "        _plugin.on_binary_analyzed(_summary)\n";
        if (!run_hook_script(final_script, "Plugin hook failed for " + plugin.name, out_error)) {
            return false;
        }
    }

    return true;
}

bool PluginManager::discover_marketplace(
    const std::filesystem::path& marketplace_root,
    std::vector<MarketplacePlugin>& out_plugins,
    std::string& out_error
) const {
    out_error.clear();
    out_plugins.clear();

    const std::filesystem::path index_path =
        std::filesystem::is_directory(marketplace_root) ? marketplace_root / "index.json" : marketplace_root;
    if (!std::filesystem::exists(index_path)) {
        return true;
    }

    const auto index_json = read_text_file(index_path);
    if (!index_json.has_value()) {
        out_error = "Failed to read marketplace index " + index_path.string();
        return false;
    }

    for (const auto& object : extract_json_object_array(*index_json, "plugins")) {
        MarketplacePlugin plugin;
        if (const auto name = extract_json_string(object, "name"); name.has_value()) {
            plugin.name = *name;
        }
        if (const auto version = extract_json_string(object, "version"); version.has_value()) {
            plugin.version = *version;
        }
        if (const auto api_version = extract_json_string(object, "api_version"); api_version.has_value()) {
            plugin.api_version = *api_version;
        }
        if (const auto description = extract_json_string(object, "description"); description.has_value()) {
            plugin.description = *description;
        }
        if (const auto package = extract_json_string(object, "path"); package.has_value()) {
            plugin.package_path = index_path.parent_path() / *package;
        }
        if (const auto entry = extract_json_string(object, "entry"); entry.has_value()) {
            plugin.entry_script = plugin.package_path / *entry;
        } else {
            plugin.entry_script = plugin.package_path / "plugin.py";
        }
        if (const auto sandboxed = extract_json_bool(object, "sandboxed"); sandboxed.has_value()) {
            plugin.sandboxed = *sandboxed;
        }
        plugin.capabilities = extract_json_string_array(object, "capabilities");
        plugin.declared_hooks = extract_json_string_array(object, "hooks");
        plugin.root_path = index_path.parent_path();

        if (plugin.name.empty() || plugin.package_path.empty()) {
            out_error = "Marketplace index contains an incomplete plugin entry.";
            return false;
        }
        out_plugins.push_back(std::move(plugin));
    }

    std::sort(
        out_plugins.begin(),
        out_plugins.end(),
        [](const MarketplacePlugin& lhs, const MarketplacePlugin& rhs) { return lhs.name < rhs.name; }
    );
    return true;
}

bool PluginManager::install_from_marketplace(
    const std::filesystem::path& marketplace_root,
    const std::string& plugin_name,
    const std::filesystem::path& destination_root,
    std::string& out_error
) const {
    out_error.clear();

    std::vector<MarketplacePlugin> available;
    if (!discover_marketplace(marketplace_root, available, out_error)) {
        return false;
    }

    const auto plugin_it = std::find_if(
        available.begin(),
        available.end(),
        [&](const MarketplacePlugin& plugin) { return plugin.name == plugin_name; }
    );
    if (plugin_it == available.end()) {
        out_error = "Marketplace plugin not found: " + plugin_name;
        return false;
    }
    if (!std::filesystem::exists(plugin_it->package_path)) {
        out_error = "Marketplace package is missing: " + plugin_it->package_path.string();
        return false;
    }

    const std::filesystem::path install_root = destination_root / sanitize_module_name(plugin_name);
    if (std::filesystem::exists(install_root)) {
        out_error = "Destination already contains plugin " + install_root.string();
        return false;
    }

    return copy_directory_tree(plugin_it->package_path, install_root, out_error);
}

const std::vector<PluginDescriptor>& PluginManager::loaded_plugins() const noexcept {
    return loaded_plugins_;
}

}  // namespace zara::plugins
