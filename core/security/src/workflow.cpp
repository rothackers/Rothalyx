#include "zara/security/workflow.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <sys/wait.h>
#endif

namespace zara::security {

namespace {

constexpr std::size_t kMaxTraceLines = 200000;
constexpr std::size_t kMaxTraceInputLabelBytes = 4096;
constexpr std::size_t kMaxTraceCoverageAddresses = 200000;

std::string trim(std::string value) {
    const auto not_space = [](const unsigned char character) { return !std::isspace(character); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
    value.erase(
        std::find_if(value.rbegin(), value.rend(), not_space).base(),
        value.end()
    );
    return value;
}

std::string lowercase_copy(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](const unsigned char character) { return static_cast<char>(std::tolower(character)); }
    );
    return value;
}

std::string format_address(const std::uint64_t value) {
    std::ostringstream stream;
    stream << "0x" << std::hex << std::uppercase << value;
    return stream.str();
}

std::string escape_python_path(std::string value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (const char character : value) {
        if (character == '\\') {
            escaped += "\\\\";
        } else {
            escaped.push_back(character);
        }
    }
    return escaped;
}

std::string escape_cpp_string(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size());
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

std::string escape_dictionary_token(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (const char character : value) {
        if (character == '"' || character == '\\') {
            escaped.push_back('\\');
        }
        escaped.push_back(character);
    }
    return escaped;
}

std::string escape_json_string(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size());
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

std::string shell_quote(std::string_view value) {
    std::string quoted = "'";
    for (const char character : value) {
        if (character == '\'') {
            quoted += "'\\''";
            continue;
        }
        quoted.push_back(character);
    }
    quoted.push_back('\'');
    return quoted;
}

bool is_safe_relative_artifact_path(const std::filesystem::path& path) {
    if (path.empty() || path.is_absolute()) {
        return false;
    }
    for (const auto& component : path) {
        if (component == "..") {
            return false;
        }
    }
    return true;
}

std::optional<std::size_t> parse_named_counter(const std::string_view line, const std::string_view token) {
    const auto token_index = line.find(token);
    if (token_index == std::string_view::npos) {
        return std::nullopt;
    }

    std::size_t cursor = token_index + token.size();
    while (cursor < line.size() && (line[cursor] == ' ' || line[cursor] == '=')) {
        ++cursor;
    }

    std::size_t end = cursor;
    while (end < line.size() && std::isdigit(static_cast<unsigned char>(line[end])) != 0) {
        ++end;
    }
    if (end == cursor) {
        return std::nullopt;
    }

    try {
        return static_cast<std::size_t>(std::stoull(std::string(line.substr(cursor, end - cursor))));
    } catch (...) {
        return std::nullopt;
    }
}

FuzzProgressEvent classify_fuzz_progress_line(
    const std::string& line,
    const std::size_t sequence,
    const std::string& engine_hint
) {
    FuzzProgressEvent event{
        .sequence = sequence,
        .kind = "log",
        .source_line = line,
        .executions = std::nullopt,
        .coverage = std::nullopt,
        .corpus_size = std::nullopt,
        .crash_detected = false,
    };

    const std::string lowered = lowercase_copy(line);
    const std::string lowered_engine = lowercase_copy(engine_hint);

    if (lowered.find("addresssanitizer") != std::string::npos ||
        lowered.find("ubsan") != std::string::npos ||
        lowered.find("undefinedbehavior") != std::string::npos ||
        lowered.find("crash") != std::string::npos ||
        lowered.find("==error:") != std::string::npos) {
        event.kind = "crash";
        event.crash_detected = true;
    }

    const bool looks_like_afl =
        lowered.find("execs_done") != std::string::npos ||
        lowered.find("paths_total") != std::string::npos ||
        lowered.find("cycles_done") != std::string::npos;
    const bool looks_like_libfuzzer =
        lowered.find("cov:") != std::string::npos ||
        lowered.find("corp:") != std::string::npos ||
        lowered.find("exec/s:") != std::string::npos;

    if (looks_like_libfuzzer ||
        (!looks_like_afl && lowered_engine.find("libfuzzer") != std::string::npos)) {
        event.kind = "libfuzzer-progress";
        event.coverage = parse_named_counter(line, "cov:");
        event.corpus_size = parse_named_counter(line, "corp:");
        event.executions = parse_named_counter(line, "#");
        return event;
    }

    if (looks_like_afl ||
        (!looks_like_libfuzzer && lowered_engine.find("afl") != std::string::npos)) {
        event.kind = "afl-progress";
        event.executions = parse_named_counter(line, "execs_done");
        event.coverage = parse_named_counter(line, "paths_total");
        event.corpus_size = parse_named_counter(line, "cycles_done");
        return event;
    }

    return event;
}

std::string normalize_import_name(std::string value) {
    const std::size_t bang = value.rfind('!');
    if (bang != std::string::npos) {
        value = value.substr(bang + 1);
    }
    if (value.rfind("__isoc99_", 0) == 0) {
        value = value.substr(9);
    }
    if (value.ends_with("_chk")) {
        value = value.substr(0, value.size() - 4);
    }
    return value;
}

bool parse_hex_or_decimal_address(
    const std::string_view token,
    std::uint64_t& out_value
) {
    if (token.empty()) {
        return false;
    }

    std::size_t parsed = 0;
    const int base = token.starts_with("0x") || token.starts_with("0X") ? 16 : 10;
    try {
        out_value = std::stoull(std::string(token), &parsed, base);
        return parsed == token.size();
    } catch (...) {
        return false;
    }
}

std::size_t instruction_count(const analysis::DiscoveredFunction& function) {
    std::size_t count = 0;
    for (const auto& block : function.graph.blocks()) {
        count += block.instructions.size();
    }
    return count;
}

std::string format_signed_offset(const std::int64_t offset) {
    std::ostringstream stream;
    if (offset >= 0) {
        stream << "+0x" << std::hex << std::uppercase << static_cast<std::uint64_t>(offset);
    } else {
        stream << "-0x" << std::hex << std::uppercase << static_cast<std::uint64_t>(-offset);
    }
    return stream.str();
}

bool is_probable_buffer_local(const analysis::LocalVariable& local) {
    if (local.size >= 16) {
        return true;
    }
    const std::string_view name(local.name);
    return name.find("buf") != std::string_view::npos || name.find("stack") != std::string_view::npos ||
           name.find("local") != std::string_view::npos;
}

std::string classify_stack_local(const analysis::LocalVariable& local) {
    if (is_probable_buffer_local(local)) {
        return "buffer";
    }
    return "local";
}

std::string render_stack_visualization(const StackVisualization& visualization) {
    std::ostringstream output;
    output << visualization.function_name << "  frame=" << visualization.frame_size << "  base="
           << visualization.base_register << '\n';
    if (visualization.stack_slots.empty()) {
        output << "  <no recovered stack slots>\n";
        return output.str();
    }

    for (const auto& slot : visualization.stack_slots) {
        output << "  " << std::setw(8) << std::left << format_signed_offset(slot.offset) << "  "
               << std::setw(18) << std::left << slot.classification << "  "
               << std::setw(20) << std::left << slot.label << "  size=" << slot.size << '\n';
    }
    return output.str();
}

std::optional<StackVisualization> build_stack_visualization(const analysis::DiscoveredFunction& function) {
    if (function.summary.stack_frame_size <= 0 && function.summary.locals.empty()) {
        return std::nullopt;
    }

    StackVisualization visualization{
        .function_entry = function.entry_address,
        .function_name = function.name,
        .frame_size = function.summary.stack_frame_size,
        .uses_frame_pointer = function.summary.uses_frame_pointer,
        .base_register = function.summary.uses_frame_pointer ? "bp" : "sp",
        .stack_slots = {},
        .rendered = {},
    };

    if (function.summary.uses_frame_pointer) {
        visualization.stack_slots.push_back(
            StackSlot{
                .offset = 0,
                .size = 8,
                .label = "saved_frame_pointer",
                .classification = "saved-state",
            }
        );
        visualization.stack_slots.push_back(
            StackSlot{
                .offset = 8,
                .size = 8,
                .label = "return_address",
                .classification = "control-data",
            }
        );
    } else {
        visualization.stack_slots.push_back(
            StackSlot{
                .offset = 0,
                .size = 8,
                .label = "return_address",
                .classification = "control-data",
            }
        );
    }

    for (const auto& local : function.summary.locals) {
        visualization.stack_slots.push_back(
            StackSlot{
                .offset = local.stack_offset,
                .size = local.size,
                .label = local.name,
                .classification = classify_stack_local(local),
            }
        );
    }

    std::sort(
        visualization.stack_slots.begin(),
        visualization.stack_slots.end(),
        [](const StackSlot& lhs, const StackSlot& rhs) {
            if (lhs.offset != rhs.offset) {
                return lhs.offset > rhs.offset;
            }
            return lhs.label < rhs.label;
        }
    );
    visualization.rendered = render_stack_visualization(visualization);
    return visualization;
}

bool function_contains_address(const analysis::DiscoveredFunction& function, const std::uint64_t address) {
    for (const auto& block : function.graph.blocks()) {
        for (const auto& instruction : block.instructions) {
            if (instruction.address == address) {
                return true;
            }
        }
    }
    return false;
}

std::vector<std::string> collect_string_labels_for_function(
    const analysis::ProgramAnalysis& program,
    const analysis::DiscoveredFunction& function
) {
    std::vector<std::string> labels;
    for (const auto& xref : program.xrefs) {
        if (xref.kind == xrefs::CrossReferenceKind::String &&
            function_contains_address(function, xref.from_address) &&
            !xref.label.empty()) {
            labels.push_back(xref.label);
        }
    }

    std::sort(labels.begin(), labels.end());
    labels.erase(std::unique(labels.begin(), labels.end()), labels.end());
    return labels;
}

bool is_shell_string(const std::string_view value) {
    return value.find("/bin/sh") != std::string_view::npos ||
           value.find("sh -c") != std::string_view::npos ||
           value.find("cmd.exe") != std::string_view::npos;
}

bool is_gadget_instruction(const disasm::Instruction& instruction) {
    if (instruction.kind == disasm::InstructionKind::Call ||
        instruction.kind == disasm::InstructionKind::Jump ||
        instruction.kind == disasm::InstructionKind::ConditionalJump ||
        instruction.kind == disasm::InstructionKind::Interrupt ||
        instruction.kind == disasm::InstructionKind::DataByte ||
        instruction.kind == disasm::InstructionKind::Unknown) {
        return false;
    }
    return true;
}

std::string format_instruction(const disasm::Instruction& instruction) {
    if (instruction.operands.empty()) {
        return instruction.mnemonic;
    }
    return instruction.mnemonic + " " + instruction.operands;
}

std::vector<Gadget> collect_gadgets(
    const analysis::ProgramAnalysis& program,
    const std::size_t max_gadgets
) {
    std::vector<Gadget> gadgets;
    std::set<std::pair<std::uint64_t, std::string>> seen;

    for (const auto& function : program.functions) {
        for (const auto& block : function.graph.blocks()) {
            for (std::size_t index = 0; index < block.instructions.size(); ++index) {
                if (block.instructions[index].kind != disasm::InstructionKind::Return) {
                    continue;
                }

                for (std::size_t depth = 1; depth <= 3 && depth <= index + 1; ++depth) {
                    const std::size_t start = index + 1 - depth;
                    bool valid = true;
                    std::ostringstream sequence;
                    for (std::size_t position = start; position <= index; ++position) {
                        const auto& instruction = block.instructions[position];
                        if (!is_gadget_instruction(instruction)) {
                            valid = false;
                            break;
                        }
                        if (position > start) {
                            sequence << " ; ";
                        }
                        sequence << format_instruction(instruction);
                    }

                    if (!valid) {
                        continue;
                    }

                    const std::string rendered = sequence.str();
                    const auto key = std::make_pair(block.instructions[start].address, rendered);
                    if (!seen.insert(key).second) {
                        continue;
                    }

                    gadgets.push_back(
                        Gadget{
                            .function_entry = function.entry_address,
                            .function_name = function.name,
                            .address = block.instructions[start].address,
                            .sequence = rendered,
                            .instruction_count = depth,
                        }
                    );
                }
            }
        }
    }

    std::sort(
        gadgets.begin(),
        gadgets.end(),
        [](const Gadget& lhs, const Gadget& rhs) {
            const bool lhs_pop_rdi = lhs.sequence.find("pop rdi") != std::string::npos;
            const bool rhs_pop_rdi = rhs.sequence.find("pop rdi") != std::string::npos;
            if (lhs_pop_rdi != rhs_pop_rdi) {
                return lhs_pop_rdi > rhs_pop_rdi;
            }
            if (lhs.instruction_count != rhs.instruction_count) {
                return lhs.instruction_count > rhs.instruction_count;
            }
            if (lhs.address != rhs.address) {
                return lhs.address < rhs.address;
            }
            return lhs.sequence < rhs.sequence;
        }
    );

    if (gadgets.size() > max_gadgets) {
        gadgets.resize(max_gadgets);
    }
    return gadgets;
}

std::vector<RiskFinding> collect_findings(const analysis::ProgramAnalysis& program) {
    std::unordered_map<std::uint64_t, const analysis::DiscoveredFunction*> functions_by_entry;
    for (const auto& function : program.functions) {
        functions_by_entry.emplace(function.entry_address, &function);
    }

    std::vector<RiskFinding> findings;
    std::set<std::tuple<std::uint64_t, std::string, std::string>> seen;

    for (const auto& edge : program.call_graph) {
        if (!edge.is_import) {
            continue;
        }

        const auto function_it = functions_by_entry.find(edge.caller_entry);
        if (function_it == functions_by_entry.end()) {
            continue;
        }

        const auto& function = *function_it->second;
        const std::string imported_name = normalize_import_name(edge.callee_name);

        auto add_finding = [&](const std::string& category,
                               const Severity severity,
                               const std::string& title,
                               const std::string& detail) {
            const auto key = std::make_tuple(function.entry_address, title, detail);
            if (!seen.insert(key).second) {
                return;
            }
            findings.push_back(
                RiskFinding{
                    .category = category,
                    .severity = severity,
                    .function_entry = function.entry_address,
                    .function_name = function.name,
                    .title = title,
                    .detail = detail,
                }
            );
        };

        if (imported_name == "gets" ||
            imported_name == "strcpy" ||
            imported_name == "strcat" ||
            imported_name == "sprintf" ||
            imported_name == "vsprintf" ||
            imported_name == "scanf" ||
            imported_name == "sscanf" ||
            imported_name == "fscanf") {
            add_finding(
                "unsafe_call",
                Severity::High,
                "Unsafe C library call",
                "Calls " + imported_name + " from " + function.name + " at " + format_address(edge.call_site) + "."
            );
            continue;
        }

        if (imported_name == "system" || imported_name == "popen" || imported_name == "execve") {
            add_finding(
                "command_execution",
                Severity::High,
                "Command execution primitive",
                "Calls " + imported_name + " from " + function.name + " at " + format_address(edge.call_site) + "."
            );
            continue;
        }

        if (imported_name == "memcpy" ||
            imported_name == "memmove" ||
            imported_name == "strncpy" ||
            imported_name == "strncat" ||
            imported_name == "read" ||
            imported_name == "recv") {
            add_finding(
                "memory_copy",
                Severity::Medium,
                "Memory copy or input surface",
                "Calls " + imported_name + " from " + function.name + " at " + format_address(edge.call_site) + "."
            );
            continue;
        }

        if (imported_name == "printf" ||
            imported_name == "fprintf" ||
            imported_name == "snprintf" ||
            imported_name == "vprintf") {
            const auto strings = collect_string_labels_for_function(program, function);
            const auto format_it = std::find_if(
                strings.begin(),
                strings.end(),
                [](const std::string& value) {
                    return value.find('%') != std::string::npos;
                }
            );
            if (format_it != strings.end()) {
                add_finding(
                    "format_string",
                    Severity::Low,
                    "Potential format-string surface",
                    "Calls " + imported_name + " and references format string `" + *format_it + "`."
                );
            }
        }
    }

    for (const auto& function : program.functions) {
        for (const auto& label : collect_string_labels_for_function(program, function)) {
            if (!is_shell_string(label)) {
                continue;
            }

            const auto key = std::make_tuple(function.entry_address, std::string("embedded_shell"), label);
            if (!seen.insert(key).second) {
                continue;
            }

            findings.push_back(
                RiskFinding{
                    .category = "embedded_shell",
                    .severity = Severity::Medium,
                    .function_entry = function.entry_address,
                    .function_name = function.name,
                    .title = "Embedded shell command string",
                    .detail = "References shell-related string `" + label + "`.",
                }
            );
        }
    }

    std::sort(
        findings.begin(),
        findings.end(),
        [](const RiskFinding& lhs, const RiskFinding& rhs) {
            if (lhs.severity != rhs.severity) {
                return static_cast<int>(lhs.severity) > static_cast<int>(rhs.severity);
            }
            if (lhs.function_entry != rhs.function_entry) {
                return lhs.function_entry < rhs.function_entry;
            }
            if (lhs.title != rhs.title) {
                return lhs.title < rhs.title;
            }
            return lhs.detail < rhs.detail;
        }
    );
    return findings;
}

std::vector<VulnerabilityPattern> collect_patterns(
    const analysis::ProgramAnalysis& program,
    const std::vector<RiskFinding>& findings
) {
    std::unordered_map<std::uint64_t, const analysis::DiscoveredFunction*> functions_by_entry;
    for (const auto& function : program.functions) {
        functions_by_entry.emplace(function.entry_address, &function);
    }

    std::vector<VulnerabilityPattern> patterns;
    std::set<std::tuple<std::uint64_t, std::string, std::string>> seen;

    auto add_pattern = [&](const std::string& category,
                           const Severity severity,
                           const analysis::DiscoveredFunction& function,
                           const std::string& title,
                           const std::string& detail,
                           std::vector<std::string> poc_notes) {
        const auto key = std::make_tuple(function.entry_address, category, title);
        if (!seen.insert(key).second) {
            return;
        }

        patterns.push_back(
            VulnerabilityPattern{
                .category = category,
                .severity = severity,
                .function_entry = function.entry_address,
                .function_name = function.name,
                .title = title,
                .detail = detail,
                .poc_notes = std::move(poc_notes),
            }
        );
    };

    for (const auto& finding : findings) {
        const auto function_it = functions_by_entry.find(finding.function_entry);
        if (function_it == functions_by_entry.end()) {
            continue;
        }
        const auto& function = *function_it->second;

        if (finding.category == "unsafe_call") {
            add_pattern(
                "stack_overflow_surface",
                Severity::High,
                function,
                "Overflow-prone input or copy path",
                finding.detail,
                {
                    "Derive the overwrite offset with a cyclic pattern at the vulnerable call site.",
                    "Inspect recovered locals and stack-frame size to estimate the reachable buffer.",
                    "Pivot from the first controllable return address into a short ROP chain.",
                }
            );
            continue;
        }

        if (finding.category == "memory_copy") {
            add_pattern(
                "memory_corruption_surface",
                Severity::Medium,
                function,
                "Input-fed memory copy path",
                finding.detail,
                {
                    "Trace the source buffer and size argument into the recovered locals.",
                    "Break before the copy/input primitive and validate bounds and destination base.",
                }
            );
            continue;
        }

        if (finding.category == "format_string") {
            add_pattern(
                "format_string_surface",
                Severity::Medium,
                function,
                "Format-string candidate",
                finding.detail,
                {
                    "Probe with %p/%x sequences first to confirm disclosure before attempting writes.",
                    "Confirm whether the format string itself is attacker-controlled or merely referenced.",
                }
            );
            continue;
        }

        if (finding.category == "command_execution" || finding.category == "embedded_shell") {
            add_pattern(
                "command_execution_surface",
                finding.category == "command_execution" ? Severity::High : Severity::Medium,
                function,
                "Command-execution candidate",
                finding.detail,
                {
                    "Trace the command buffer or argv construction into this call site.",
                    "Prioritize control of shell string construction before building a ROP path.",
                }
            );
        }
    }

    std::sort(
        patterns.begin(),
        patterns.end(),
        [](const VulnerabilityPattern& lhs, const VulnerabilityPattern& rhs) {
            if (lhs.severity != rhs.severity) {
                return static_cast<int>(lhs.severity) > static_cast<int>(rhs.severity);
            }
            if (lhs.function_entry != rhs.function_entry) {
                return lhs.function_entry < rhs.function_entry;
            }
            if (lhs.category != rhs.category) {
                return lhs.category < rhs.category;
            }
            return lhs.title < rhs.title;
        }
    );
    return patterns;
}

std::vector<PocScaffoldTarget> collect_poc_targets(
    const std::vector<VulnerabilityPattern>& patterns,
    const std::vector<Gadget>& gadgets
) {
    const bool has_pop_rdi = std::any_of(
        gadgets.begin(),
        gadgets.end(),
        [](const Gadget& gadget) { return gadget.sequence.find("pop rdi") != std::string::npos; }
    );

    std::vector<PocScaffoldTarget> targets;
    std::set<std::pair<std::uint64_t, std::string>> seen;
    for (const auto& pattern : patterns) {
        std::string role;
        if (pattern.category == "stack_overflow_surface") {
            role = "control_offset";
        } else if (pattern.category == "memory_corruption_surface") {
            role = "write_primitive";
        } else if (pattern.category == "format_string_surface") {
            role = "leak_surface";
        } else if (pattern.category == "command_execution_surface") {
            role = "command_buffer";
        } else {
            role = "analysis_target";
        }

        if (!seen.insert(std::make_pair(pattern.function_entry, role)).second) {
            continue;
        }

        std::vector<std::string> notes = pattern.poc_notes;
        if (has_pop_rdi && (role == "control_offset" || role == "command_buffer")) {
            notes.push_back("A pop rdi gadget is available, which is useful for amd64 argument setup.");
        }
        targets.push_back(
            PocScaffoldTarget{
                .role = std::move(role),
                .function_entry = pattern.function_entry,
                .function_name = pattern.function_name,
                .notes = std::move(notes),
            }
        );
    }
    return targets;
}

std::vector<StackVisualization> collect_stack_visualizations(
    const analysis::ProgramAnalysis& program,
    const std::vector<VulnerabilityPattern>& patterns
) {
    std::unordered_set<std::uint64_t> preferred_entries;
    for (const auto& pattern : patterns) {
        if (pattern.category == "stack_overflow_surface" || pattern.category == "memory_corruption_surface") {
            preferred_entries.insert(pattern.function_entry);
        }
    }

    std::vector<StackVisualization> visualizations;
    for (const auto& function : program.functions) {
        const bool preferred = preferred_entries.contains(function.entry_address);
        if (!preferred && function.summary.stack_frame_size <= 0 && function.summary.locals.empty()) {
            continue;
        }

        if (const auto visualization = build_stack_visualization(function); visualization.has_value()) {
            visualizations.push_back(*visualization);
        }
    }

    std::sort(
        visualizations.begin(),
        visualizations.end(),
        [&](const StackVisualization& lhs, const StackVisualization& rhs) {
            const bool lhs_preferred = preferred_entries.contains(lhs.function_entry);
            const bool rhs_preferred = preferred_entries.contains(rhs.function_entry);
            if (lhs_preferred != rhs_preferred) {
                return lhs_preferred > rhs_preferred;
            }
            if (lhs.frame_size != rhs.frame_size) {
                return lhs.frame_size > rhs.frame_size;
            }
            return lhs.function_entry < rhs.function_entry;
        }
    );

    if (visualizations.size() > 24) {
        visualizations.resize(24);
    }
    return visualizations;
}

std::vector<std::string> collect_dictionary_tokens(
    const analysis::ProgramAnalysis& program,
    const analysis::DiscoveredFunction& function
) {
    std::vector<std::string> tokens;
    for (const auto& label : collect_string_labels_for_function(program, function)) {
        std::string current;
        auto flush = [&]() {
            if (current.size() >= 3 && current.size() <= 24) {
                tokens.push_back(current);
            }
            current.clear();
        };

        for (const char character : label) {
            const bool keep = std::isalnum(static_cast<unsigned char>(character)) != 0 || character == '_' ||
                              character == '-' || character == '/' || character == '%' || character == '=';
            if (keep) {
                current.push_back(character);
            } else {
                flush();
            }
        }
        flush();
    }

    std::sort(tokens.begin(), tokens.end());
    tokens.erase(std::unique(tokens.begin(), tokens.end()), tokens.end());
    return tokens;
}

std::vector<MutationHook> collect_mutation_hooks(
    const std::filesystem::path& binary_path,
    const analysis::ProgramAnalysis& program,
    const FuzzingReport& mapping
) {
    (void)binary_path;

    std::unordered_map<std::uint64_t, const analysis::DiscoveredFunction*> functions_by_entry;
    for (const auto& function : program.functions) {
        functions_by_entry.emplace(function.entry_address, &function);
    }

    const auto findings = collect_findings(program);
    std::vector<MutationHook> hooks;
    std::set<std::tuple<std::uint64_t, std::string, std::string>> seen;

    auto add_hook = [&](MutationHook hook) {
        const auto key = std::make_tuple(hook.function_entry, hook.kind, hook.label);
        if (!seen.insert(key).second) {
            return;
        }
        hooks.push_back(std::move(hook));
    };

    for (const auto& covered : mapping.covered_functions) {
        const auto function_it = functions_by_entry.find(covered.function_entry);
        if (function_it == functions_by_entry.end()) {
            continue;
        }
        const auto& function = *function_it->second;
        const std::size_t hooks_before = hooks.size();

        for (const auto& local : function.summary.locals) {
            if (!is_probable_buffer_local(local)) {
                continue;
            }
            add_hook(
                MutationHook{
                    .function_entry = function.entry_address,
                    .function_name = function.name,
                    .address = function.entry_address,
                    .kind = "stack-buffer",
                    .label = local.name,
                    .detail = "Mutate payload length and byte distribution to pressure recovered local `" + local.name +
                              "` at " + format_signed_offset(local.stack_offset) + ".",
                    .sample = "offset=" + format_signed_offset(local.stack_offset) + " size=" + std::to_string(local.size),
                }
            );
        }

        for (const auto& finding : findings) {
            if (finding.function_entry != function.entry_address) {
                continue;
            }
            add_hook(
                MutationHook{
                    .function_entry = function.entry_address,
                    .function_name = function.name,
                    .address = function.entry_address,
                    .kind = "input-site",
                    .label = finding.title,
                    .detail = finding.detail,
                    .sample = finding.category,
                }
            );
        }

        for (const auto& token : collect_dictionary_tokens(program, function)) {
            add_hook(
                MutationHook{
                    .function_entry = function.entry_address,
                    .function_name = function.name,
                    .address = std::nullopt,
                    .kind = "dictionary-token",
                    .label = token,
                    .detail = "Preserve token boundaries while mutating request grammar and value lengths.",
                    .sample = token,
                }
            );
        }

        if (hooks.size() == hooks_before) {
            add_hook(
                MutationHook{
                    .function_entry = function.entry_address,
                    .function_name = function.name,
                    .address = covered.contains_crash_address ? std::optional<std::uint64_t>(function.entry_address) : std::nullopt,
                    .kind = "coverage-site",
                    .label = covered.contains_crash_address ? "crash-path" : "hot-path",
                    .detail = covered.contains_crash_address
                                  ? "Bias mutations toward the crashing function and preserve surrounding control bytes."
                                  : "Focus mutations on the hottest covered function to widen path exploration.",
                    .sample = "hits=" + std::to_string(covered.hit_count),
                }
            );
        }
    }

    std::sort(
        hooks.begin(),
        hooks.end(),
        [](const MutationHook& lhs, const MutationHook& rhs) {
            if (lhs.function_entry != rhs.function_entry) {
                return lhs.function_entry < rhs.function_entry;
            }
            if (lhs.kind != rhs.kind) {
                return lhs.kind < rhs.kind;
            }
            return lhs.label < rhs.label;
        }
    );
    return hooks;
}

std::vector<FuzzHarnessArtifact> build_harness_artifacts(
    const std::filesystem::path& binary_path,
    const CrashTrace& trace,
    const FuzzingReport& report
) {
    std::vector<FuzzHarnessArtifact> artifacts;

    std::vector<std::string> dictionary_tokens;
    for (const auto& hook : report.mutation_hooks) {
        if (hook.kind == "dictionary-token" && !hook.sample.empty()) {
            dictionary_tokens.push_back(hook.sample);
        }
    }
    std::sort(dictionary_tokens.begin(), dictionary_tokens.end());
    dictionary_tokens.erase(std::unique(dictionary_tokens.begin(), dictionary_tokens.end()), dictionary_tokens.end());

    std::ostringstream dictionary;
    for (const auto& token : dictionary_tokens) {
        dictionary << '"' << escape_dictionary_token(token) << '"' << '\n';
    }
    if (dictionary_tokens.empty()) {
        dictionary << "\"AAAA\"\n\"%p\"\n\"/bin/sh\"\n";
    }

    std::ostringstream seed;
    if (!trace.input_label.empty()) {
        seed << trace.input_label << '\n';
    }
    for (const auto& token : dictionary_tokens) {
        seed << token << '\n';
    }
    if (seed.str().empty()) {
        seed << "AAAA\n";
    }

    std::vector<std::pair<std::string, std::string>> corpus_entries{
        {"corpus/seed_input.bin", seed.str()},
    };
    for (const auto& function : report.covered_functions) {
        if (corpus_entries.size() >= 9) {
            break;
        }
        std::ostringstream function_seed;
        function_seed << "function=" << function.function_name << '\n';
        function_seed << "entry=" << format_address(function.function_entry) << '\n';
        function_seed << "hits=" << function.hit_count << '\n';
        for (const auto& hook : report.mutation_hooks) {
            if (hook.function_entry != function.function_entry || hook.sample.empty()) {
                continue;
            }
            function_seed << hook.sample << '\n';
        }
        std::ostringstream filename;
        filename << "corpus/function_" << std::hex << std::uppercase << function.function_entry << ".seed";
        corpus_entries.emplace_back(
            filename.str(),
            function_seed.str()
        );
    }

    std::ostringstream afl_script;
    afl_script
        << "#!/usr/bin/env bash\n"
        << "set -euo pipefail\n"
        << "TARGET=${1:-\"" << escape_cpp_string(binary_path.string()) << "\"}\n"
        << "INPUT=${2:-@@}\n"
        << "exec \"$TARGET\" < \"$INPUT\"\n";

    std::ostringstream libfuzzer;
    const std::string escaped_binary = escape_cpp_string(binary_path.string());
    libfuzzer
        << "#include <cstddef>\n"
        << "#include <cstdint>\n"
        << "#include <cstdlib>\n"
        << "#include <filesystem>\n"
        << "#include <fstream>\n"
        << "#include <string>\n\n"
        << "extern \"C\" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {\n"
        << "    if (size == 0 || size > (1u << 20u)) {\n"
        << "        return 0;\n"
        << "    }\n"
        << "    const auto path = std::filesystem::temp_directory_path() / \"zara-libfuzzer-input.bin\";\n"
        << "    {\n"
        << "        std::ofstream output(path, std::ios::binary);\n"
        << "        output.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));\n"
        << "    }\n"
        << "    const std::string command = std::string(\"\\\"" << escaped_binary
        << "\\\" < \\\"\") + path.string() + \"\\\" >/dev/null 2>&1\";\n"
        << "    (void)std::system(command.c_str());\n"
        << "    std::error_code cleanup_error;\n"
        << "    std::filesystem::remove(path, cleanup_error);\n"
        << "    return 0;\n"
        << "}\n";

    std::ostringstream replay_script;
    replay_script
        << "#!/usr/bin/env bash\n"
        << "set -euo pipefail\n"
        << "TARGET=${1:-\"" << escape_cpp_string(binary_path.string()) << "\"}\n"
        << "INPUT=${2:-corpus/seed_input.bin}\n"
        << "exec \"$TARGET\" < \"$INPUT\"\n";

    std::ostringstream sanitizer_repro;
    sanitizer_repro
        << "#!/usr/bin/env bash\n"
        << "set -euo pipefail\n"
        << "TARGET=${1:-\"" << escape_cpp_string(binary_path.string()) << "\"}\n"
        << "INPUT=${2:-corpus/seed_input.bin}\n"
        << "export ASAN_OPTIONS=${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0:symbolize=1}\n"
        << "export UBSAN_OPTIONS=${UBSAN_OPTIONS:-abort_on_error=1:print_stacktrace=1}\n"
        << "exec \"$TARGET\" < \"$INPUT\"\n";

    std::ostringstream corpus_minimizer;
    corpus_minimizer
        << "#!/usr/bin/env bash\n"
        << "set -euo pipefail\n"
        << "INPUT_DIR=${1:-corpus}\n"
        << "OUTPUT_DIR=${2:-minimized-corpus}\n"
        << "TARGET=${3:-\"" << escape_cpp_string(binary_path.string()) << "\"}\n"
        << "mkdir -p \"$OUTPUT_DIR\"\n"
        << "if command -v afl-cmin >/dev/null 2>&1; then\n"
        << "    exec afl-cmin -i \"$INPUT_DIR\" -o \"$OUTPUT_DIR\" -- \"$TARGET\" < @@\n"
        << "fi\n"
        << "echo \"afl-cmin is unavailable; copy interesting seeds into $OUTPUT_DIR manually.\" >&2\n";

    std::ostringstream afl_persistent;
    afl_persistent
        << "#include <cstddef>\n"
        << "#include <cstdint>\n"
        << "#include <cstdlib>\n"
        << "#include <filesystem>\n"
        << "#include <fstream>\n"
        << "#include <string>\n\n"
        << "__AFL_FUZZ_INIT();\n\n"
        << "int main(int argc, char** argv) {\n"
        << "    const std::string target = argc > 1 ? argv[1] : std::string(\"" << escaped_binary << "\");\n"
        << "#ifdef __AFL_HAVE_MANUAL_CONTROL\n"
        << "    __AFL_INIT();\n"
        << "#endif\n"
        << "    while (__AFL_LOOP(1000)) {\n"
        << "        const std::size_t size = __AFL_FUZZ_TESTCASE_LEN;\n"
        << "        unsigned char* data = __AFL_FUZZ_TESTCASE_BUF;\n"
        << "        if (size == 0 || size > (1u << 20u) || data == nullptr) {\n"
        << "            continue;\n"
        << "        }\n"
        << "        const auto path = std::filesystem::temp_directory_path() / \"zara-afl-input.bin\";\n"
        << "        {\n"
        << "            std::ofstream output(path, std::ios::binary);\n"
        << "            output.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));\n"
        << "        }\n"
        << "        const std::string command = std::string(\"\\\"\") + target + \"\\\" < \\\"\" + path.string() + \"\\\" >/dev/null 2>&1\";\n"
        << "        (void)std::system(command.c_str());\n"
        << "        std::error_code cleanup_error;\n"
        << "        std::filesystem::remove(path, cleanup_error);\n"
        << "    }\n"
        << "    return 0;\n"
        << "}\n";

    std::ostringstream coverage_addresses;
    for (const auto address : trace.coverage_addresses) {
        coverage_addresses << format_address(address) << '\n';
    }

    std::ostringstream coverage_report;
    coverage_report << "{\n";
    coverage_report << "  \"crash_summary\": \"" << escape_json_string(report.crash_summary) << "\",\n";
    coverage_report << "  \"covered_functions\": [\n";
    for (std::size_t index = 0; index < report.covered_functions.size(); ++index) {
        const auto& function = report.covered_functions[index];
        coverage_report << "    {\"entry\": \"" << format_address(function.function_entry) << "\", "
                        << "\"name\": \"" << escape_json_string(function.function_name) << "\", "
                        << "\"hits\": " << function.hit_count << ", "
                        << "\"instructions\": " << function.instruction_count << ", "
                        << "\"coverage\": " << function.coverage_ratio << ", "
                        << "\"contains_crash\": " << (function.contains_crash_address ? "true" : "false") << "}";
        coverage_report << (index + 1 == report.covered_functions.size() ? '\n' : ',');
    }
    coverage_report << "  ]\n";
    coverage_report << "}\n";

    std::ostringstream mutation_hooks_json;
    mutation_hooks_json << "{\n";
    mutation_hooks_json << "  \"hooks\": [\n";
    for (std::size_t index = 0; index < report.mutation_hooks.size(); ++index) {
        const auto& hook = report.mutation_hooks[index];
        mutation_hooks_json << "    {\"function\": \"" << escape_json_string(hook.function_name) << "\", "
                            << "\"entry\": \"" << format_address(hook.function_entry) << "\", "
                            << "\"kind\": \"" << escape_json_string(hook.kind) << "\", "
                            << "\"label\": \"" << escape_json_string(hook.label) << "\", "
                            << "\"detail\": \"" << escape_json_string(hook.detail) << "\", "
                            << "\"sample\": \"" << escape_json_string(hook.sample) << "\"}";
        mutation_hooks_json << (index + 1 == report.mutation_hooks.size() ? '\n' : ',');
    }
    mutation_hooks_json << "  ]\n";
    mutation_hooks_json << "}\n";

    std::ostringstream seed_manifest;
    seed_manifest << "{\n";
    seed_manifest << "  \"inputs\": [\n";
    for (std::size_t index = 0; index < corpus_entries.size(); ++index) {
        seed_manifest << "    {\"path\": \"" << escape_json_string(corpus_entries[index].first) << "\"}";
        seed_manifest << (index + 1 == corpus_entries.size() ? '\n' : ',');
    }
    seed_manifest << "  ]\n";
    seed_manifest << "}\n";

    std::ostringstream metadata;
    metadata << "{\n";
    metadata << "  \"binary\": \"" << escape_json_string(binary_path.string()) << "\",\n";
    metadata << "  \"crash_summary\": \"" << escape_json_string(report.crash_summary) << "\",\n";
    metadata << "  \"input_label\": \"" << escape_json_string(trace.input_label) << "\",\n";
    metadata << "  \"covered_functions\": [\n";
    for (std::size_t index = 0; index < report.covered_functions.size(); ++index) {
        const auto& function = report.covered_functions[index];
        metadata << "    {\"entry\": \"" << format_address(function.function_entry) << "\", "
                 << "\"name\": \"" << escape_json_string(function.function_name) << "\", "
                 << "\"hits\": " << function.hit_count << ", "
                 << "\"coverage\": " << function.coverage_ratio << "}";
        metadata << (index + 1 == report.covered_functions.size() ? '\n' : ',');
    }
    metadata << "  ],\n";
    metadata << "  \"mutation_hooks\": [\n";
    for (std::size_t index = 0; index < report.mutation_hooks.size(); ++index) {
        const auto& hook = report.mutation_hooks[index];
        metadata << "    {\"function\": \"" << escape_json_string(hook.function_name) << "\", "
                 << "\"kind\": \"" << escape_json_string(hook.kind) << "\", "
                 << "\"label\": \"" << escape_json_string(hook.label) << "\"}";
        metadata << (index + 1 == report.mutation_hooks.size() ? '\n' : ',');
    }
    metadata << "  ]\n";
    metadata << "}\n";

    std::ostringstream readme;
    readme << "Zara generated fuzz bundle\n\n";
    readme << "Binary: " << binary_path << "\n";
    readme << "Crash summary: " << report.crash_summary << "\n\n";
    readme << "Artifacts\n";
    readme << "- `dictionary.txt`: mutation tokens recovered from covered code paths\n";
    readme << "- `corpus/`: starter corpus plus per-function seed material\n";
    readme << "- `run_target_afl.sh`: AFL++ stdin wrapper\n";
    readme << "- `fuzz_driver_afl_persistent.cpp`: AFL++ persistent-loop driver shim\n";
    readme << "- `fuzz_driver_libfuzzer.cpp`: process-spawning libFuzzer shim\n\n";
    readme << "- `replay_trace.sh`: quick crash/coverage replay helper\n";
    readme << "- `reproduce_with_sanitizers.sh`: ASan/UBSan-oriented reproducer wrapper\n";
    readme << "- `minimize_corpus.sh`: corpus triage/minimization helper\n";
    readme << "- `metadata.json`: machine-readable harness metadata\n";
    readme << "- `coverage_report.json`: covered-function summary for triage dashboards\n";
    readme << "- `mutation_hooks.json`: machine-readable hook inventory\n";
    readme << "- `seed_manifest.json`: corpus asset index\n";
    readme << "- `coverage_addresses.txt`: raw coverage addresses from the imported trace\n\n";
    if (!report.mutation_hooks.empty()) {
        readme << "Mutation hooks\n";
        for (const auto& hook : report.mutation_hooks) {
            readme << "- " << hook.function_name << " [" << hook.kind << "] " << hook.label;
            if (!hook.sample.empty()) {
                readme << " -> " << hook.sample;
            }
            readme << '\n';
        }
    }

    artifacts.push_back(
        FuzzHarnessArtifact{
            .engine = "dictionary",
            .filename = "dictionary.txt",
            .content = dictionary.str(),
        }
    );
    for (const auto& [filename, content] : corpus_entries) {
        artifacts.push_back(
            FuzzHarnessArtifact{
                .engine = "corpus",
                .filename = filename,
                .content = content,
            }
        );
    }
    artifacts.push_back(
        FuzzHarnessArtifact{
            .engine = "aflpp",
            .filename = "run_target_afl.sh",
            .content = afl_script.str(),
        }
    );
    artifacts.push_back(
        FuzzHarnessArtifact{
            .engine = "aflpp",
            .filename = "fuzz_driver_afl_persistent.cpp",
            .content = afl_persistent.str(),
        }
    );
    artifacts.push_back(
        FuzzHarnessArtifact{
            .engine = "libfuzzer",
            .filename = "fuzz_driver_libfuzzer.cpp",
            .content = libfuzzer.str(),
        }
    );
    artifacts.push_back(
        FuzzHarnessArtifact{
            .engine = "replay",
            .filename = "replay_trace.sh",
            .content = replay_script.str(),
        }
    );
    artifacts.push_back(
        FuzzHarnessArtifact{
            .engine = "replay",
            .filename = "reproduce_with_sanitizers.sh",
            .content = sanitizer_repro.str(),
        }
    );
    artifacts.push_back(
        FuzzHarnessArtifact{
            .engine = "corpus",
            .filename = "minimize_corpus.sh",
            .content = corpus_minimizer.str(),
        }
    );
    artifacts.push_back(
        FuzzHarnessArtifact{
            .engine = "metadata",
            .filename = "metadata.json",
            .content = metadata.str(),
        }
    );
    artifacts.push_back(
        FuzzHarnessArtifact{
            .engine = "metadata",
            .filename = "coverage_report.json",
            .content = coverage_report.str(),
        }
    );
    artifacts.push_back(
        FuzzHarnessArtifact{
            .engine = "metadata",
            .filename = "mutation_hooks.json",
            .content = mutation_hooks_json.str(),
        }
    );
    artifacts.push_back(
        FuzzHarnessArtifact{
            .engine = "metadata",
            .filename = "seed_manifest.json",
            .content = seed_manifest.str(),
        }
    );
    artifacts.push_back(
        FuzzHarnessArtifact{
            .engine = "coverage",
            .filename = "coverage_addresses.txt",
            .content = coverage_addresses.str(),
        }
    );
    artifacts.push_back(
        FuzzHarnessArtifact{
            .engine = "bundle",
            .filename = "README.md",
            .content = readme.str(),
        }
    );
    return artifacts;
}

std::string build_poc_scaffold(
    const std::filesystem::path& binary_path,
    const std::vector<Gadget>& gadgets,
    const std::vector<RiskFinding>& findings,
    const std::vector<VulnerabilityPattern>& patterns,
    const std::vector<PocScaffoldTarget>& poc_targets,
    const std::vector<StackVisualization>& stack_visualizations
) {
    std::ostringstream scaffold;
    scaffold
        << "from pwn import *\n\n"
        << "exe = ELF(r\"" << escape_python_path(binary_path.string()) << "\")\n"
        << "context.binary = exe\n\n"
        << "# Replace offset and target logic with real crash-derived values.\n";

    if (!patterns.empty()) {
        scaffold << "# Primary patterns\n";
        for (std::size_t index = 0; index < std::min<std::size_t>(patterns.size(), 4); ++index) {
            scaffold << "# - [" << to_string(patterns[index].severity) << "] "
                     << patterns[index].title << " in "
                     << patterns[index].function_name << '\n';
        }
        scaffold << '\n';
    }

    scaffold
        << "offset = cyclic_find(0x6161616C)\n"
        << "io = process(exe.path)\n"
        << "payload = flat(\n"
        << "    b\"A\" * offset,\n";

    bool emitted_gadget = false;
    for (const auto& gadget : gadgets) {
        if (gadget.sequence.find("pop rdi") == std::string::npos) {
            continue;
        }
        scaffold << "    " << format_address(gadget.address) << ",  # " << gadget.sequence << '\n';
        emitted_gadget = true;
        break;
    }
    if (!emitted_gadget) {
        scaffold << "    0x0,  # TODO: replace with first control gadget\n";
    }

    scaffold
        << "    0x0,  # TODO: argument / return address chain\n"
        << ")\n"
        << "io.sendline(payload)\n"
        << "io.interactive()\n";

    if (!poc_targets.empty()) {
        scaffold << "\n# PoC targets\n";
        for (std::size_t index = 0; index < std::min<std::size_t>(poc_targets.size(), 4); ++index) {
            const auto& target = poc_targets[index];
            scaffold << "# " << target.role << " -> " << target.function_name
                     << " (" << format_address(target.function_entry) << ")\n";
            for (const auto& note : target.notes) {
                scaffold << "#   - " << note << '\n';
            }
        }
    }

    if (!stack_visualizations.empty()) {
        scaffold << "\n# Stack layouts\n";
        for (std::size_t index = 0; index < std::min<std::size_t>(stack_visualizations.size(), 2); ++index) {
            std::istringstream view(stack_visualizations[index].rendered);
            std::string line;
            while (std::getline(view, line)) {
                scaffold << "# " << line << '\n';
            }
        }
    }

    if (!findings.empty()) {
        scaffold << "\n# Findings\n";
        for (std::size_t index = 0; index < std::min<std::size_t>(findings.size(), 5); ++index) {
            scaffold << "# - [" << to_string(findings[index].severity) << "] "
                     << findings[index].title << ": " << findings[index].detail << '\n';
        }
    }

    return scaffold.str();
}

}  // namespace

ExploitReport Workflow::analyze_exploit_surface(
    const std::filesystem::path& binary_path,
    const analysis::ProgramAnalysis& program,
    const std::size_t max_gadgets
) {
    ExploitReport report;
    report.findings = collect_findings(program);
    report.gadgets = collect_gadgets(program, max_gadgets);
    report.patterns = collect_patterns(program, report.findings);
    report.poc_targets = collect_poc_targets(report.patterns, report.gadgets);
    report.stack_visualizations = collect_stack_visualizations(program, report.patterns);
    report.poc_scaffold =
        build_poc_scaffold(
            binary_path,
            report.gadgets,
            report.findings,
            report.patterns,
            report.poc_targets,
            report.stack_visualizations
        );
    return report;
}

FuzzingReport Workflow::map_crash_trace(
    const analysis::ProgramAnalysis& program,
    const CrashTrace& trace,
    const std::size_t max_functions
) {
    FuzzingReport report;

    std::unordered_set<std::uint64_t> unique_hits(
        trace.coverage_addresses.begin(),
        trace.coverage_addresses.end()
    );

    for (const auto& function : program.functions) {
        std::size_t hits = 0;
        bool contains_crash = false;
        for (const auto& block : function.graph.blocks()) {
            for (const auto& instruction : block.instructions) {
                if (unique_hits.contains(instruction.address)) {
                    ++hits;
                }
                if (trace.crash_address.has_value() && instruction.address == *trace.crash_address) {
                    contains_crash = true;
                }
            }
        }

        if (hits == 0 && !contains_crash) {
            continue;
        }

        const std::size_t total = instruction_count(function);
        report.covered_functions.push_back(
            CoveredFunction{
                .function_entry = function.entry_address,
                .function_name = function.name,
                .hit_count = hits,
                .instruction_count = total,
                .coverage_ratio = total == 0 ? 0.0 : static_cast<double>(hits) / static_cast<double>(total),
                .contains_crash_address = contains_crash,
            }
        );
    }

    std::sort(
        report.covered_functions.begin(),
        report.covered_functions.end(),
        [](const CoveredFunction& lhs, const CoveredFunction& rhs) {
            if (lhs.contains_crash_address != rhs.contains_crash_address) {
                return lhs.contains_crash_address > rhs.contains_crash_address;
            }
            if (lhs.hit_count != rhs.hit_count) {
                return lhs.hit_count > rhs.hit_count;
            }
            if (std::abs(lhs.coverage_ratio - rhs.coverage_ratio) > 0.000001) {
                return lhs.coverage_ratio > rhs.coverage_ratio;
            }
            return lhs.function_entry < rhs.function_entry;
        }
    );

    if (report.covered_functions.size() > max_functions) {
        report.covered_functions.resize(max_functions);
    }

    if (trace.crash_address.has_value()) {
        const auto crash_it = std::find_if(
            report.covered_functions.begin(),
            report.covered_functions.end(),
            [](const CoveredFunction& function) { return function.contains_crash_address; }
        );
        if (crash_it != report.covered_functions.end()) {
            report.crash_summary =
                "Crash at " + format_address(*trace.crash_address) + " maps to " + crash_it->function_name + ".";
        } else {
            report.crash_summary =
                "Crash at " + format_address(*trace.crash_address) + " is outside discovered functions.";
        }
    } else {
        report.crash_summary = "Coverage trace does not include an explicit crash address.";
    }

    const auto findings = collect_findings(program);
    if (trace.crash_address.has_value()) {
        for (const auto& finding : findings) {
            if (std::any_of(
                    report.covered_functions.begin(),
                    report.covered_functions.end(),
                    [&](const CoveredFunction& function) {
                        return function.contains_crash_address && function.function_entry == finding.function_entry;
                    }
                )) {
                report.crash_hints.push_back(finding);
            }
        }
    }

    return report;
}

FuzzingReport Workflow::analyze_fuzzing_surface(
    const std::filesystem::path& binary_path,
    const analysis::ProgramAnalysis& program,
    const CrashTrace& trace,
    const std::size_t max_functions
) {
    FuzzingReport report = map_crash_trace(program, trace, max_functions);
    report.mutation_hooks = collect_mutation_hooks(binary_path, program, report);
    report.harness_artifacts = build_harness_artifacts(binary_path, trace, report);
    return report;
}

bool Workflow::parse_trace_file(
    const std::filesystem::path& trace_path,
    CrashTrace& out_trace,
    std::string& out_error
) {
    out_error.clear();
    out_trace = {};

    std::ifstream stream(trace_path);
    if (!stream) {
        out_error = "Failed to open trace file.";
        return false;
    }

    std::string line;
    std::size_t line_number = 0;
    while (std::getline(stream, line)) {
        ++line_number;
        if (line_number > kMaxTraceLines) {
            out_error = "Trace file exceeds the configured line budget.";
            return false;
        }
        line = trim(std::move(line));
        if (line.empty() || line.starts_with('#')) {
            continue;
        }

        auto parse_address_line = [&](const std::string_view token, std::uint64_t& out_value) -> bool {
            if (!parse_hex_or_decimal_address(token, out_value)) {
                out_error = "Invalid address on line " + std::to_string(line_number) + ".";
                return false;
            }
            return true;
        };

        if (std::string_view(line).starts_with("input=")) {
            out_trace.input_label = line.substr(6);
            if (out_trace.input_label.size() > kMaxTraceInputLabelBytes) {
                out_error = "Trace input label exceeds the configured size limit.";
                return false;
            }
            continue;
        }
        if (std::string_view(line).starts_with("crash=")) {
            std::uint64_t address = 0;
            if (!parse_address_line(std::string_view(line).substr(6), address)) {
                return false;
            }
            out_trace.crash_address = address;
            continue;
        }
        if (std::string_view(line).starts_with("cover=")) {
            std::uint64_t address = 0;
            if (!parse_address_line(std::string_view(line).substr(6), address)) {
                return false;
            }
            if (out_trace.coverage_addresses.size() >= kMaxTraceCoverageAddresses) {
                out_error = "Trace coverage exceeds the configured address budget.";
                return false;
            }
            out_trace.coverage_addresses.push_back(address);
            continue;
        }

        std::uint64_t address = 0;
        if (!parse_address_line(line, address)) {
            return false;
        }
        if (out_trace.coverage_addresses.size() >= kMaxTraceCoverageAddresses) {
            out_error = "Trace coverage exceeds the configured address budget.";
            return false;
        }
        out_trace.coverage_addresses.push_back(address);
    }

    return true;
}

bool Workflow::write_harness_bundle(
    const std::filesystem::path& output_directory,
    const FuzzingReport& report,
    std::vector<std::filesystem::path>* out_written_paths,
    std::string& out_error
) {
    out_error.clear();
    if (out_written_paths != nullptr) {
        out_written_paths->clear();
    }

    std::error_code mkdir_error;
    std::filesystem::create_directories(output_directory, mkdir_error);
    if (mkdir_error) {
        out_error = "Failed to create harness output directory.";
        return false;
    }

    for (const auto& artifact : report.harness_artifacts) {
        const std::filesystem::path artifact_path = artifact.filename;
        if (!is_safe_relative_artifact_path(artifact_path)) {
            out_error = "Harness artifact path is unsafe.";
            return false;
        }

        const auto path = output_directory / artifact_path;
        std::filesystem::create_directories(path.parent_path(), mkdir_error);
        if (mkdir_error) {
            out_error = "Failed to create harness artifact directory.";
            return false;
        }
        std::ofstream output(path, std::ios::binary);
        if (!output) {
            out_error = "Failed to open harness artifact for writing.";
            return false;
        }
        output.write(artifact.content.data(), static_cast<std::streamsize>(artifact.content.size()));
        if (!output.good()) {
            out_error = "Failed to write harness artifact.";
            return false;
        }
        output.close();
#if !defined(_WIN32)
        if (path.extension() == ".sh") {
            std::filesystem::permissions(
                path,
                std::filesystem::perms::owner_exec | std::filesystem::perms::owner_read |
                    std::filesystem::perms::owner_write,
                std::filesystem::perm_options::add,
                mkdir_error
            );
        }
#endif
        if (out_written_paths != nullptr) {
            out_written_paths->push_back(path);
        }
    }

    return true;
}

bool Workflow::run_live_fuzz_tool(
    const std::string& command,
    const LiveFuzzOptions& options,
    LiveFuzzResult& out_result,
    std::string& out_error
) {
    out_result = {};
    out_error.clear();

    if (command.empty()) {
        out_error = "Live fuzz command must not be empty.";
        return false;
    }
    if (options.max_output_lines == 0 || options.max_line_bytes == 0) {
        out_error = "Live fuzz output limits must be non-zero.";
        return false;
    }

    out_result.tool_name = options.engine_hint.empty() ? "external-fuzzer" : options.engine_hint;

    std::string shell_command = command;
    if (!options.working_directory.empty()) {
        std::error_code mkdir_error;
        std::filesystem::create_directories(options.working_directory, mkdir_error);
        if (mkdir_error) {
            out_error = "Failed to create the live fuzz working directory.";
            return false;
        }
        shell_command =
            "cd " + shell_quote(options.working_directory.string()) + " && (" + command + ")";
    }
    shell_command += " 2>&1";

#if defined(_WIN32)
    FILE* pipe = _popen(shell_command.c_str(), "r");
#else
    FILE* pipe = popen(shell_command.c_str(), "r");
#endif
    if (pipe == nullptr) {
        out_error = "Failed to launch the external fuzz command.";
        return false;
    }

    std::vector<char> buffer(options.max_line_bytes + 2, '\0');
    std::size_t sequence = 0;
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        std::string line(buffer.data());
        line = trim(line);
        if (line.empty()) {
            continue;
        }

        if (line.size() > options.max_line_bytes) {
            line.resize(options.max_line_bytes);
        }
        if (out_result.output_lines.size() >= options.max_output_lines) {
            out_error = "Live fuzz output exceeded the configured line budget.";
#if defined(_WIN32)
            _pclose(pipe);
#else
            pclose(pipe);
#endif
            return false;
        }

        out_result.output_lines.push_back(line);
        FuzzProgressEvent event = classify_fuzz_progress_line(line, sequence++, options.engine_hint);
        out_result.crash_detected = out_result.crash_detected || event.crash_detected;
        out_result.events.push_back(event);
        if (options.on_event) {
            options.on_event(out_result.events.back());
        }
    }

#if defined(_WIN32)
    const int status = _pclose(pipe);
    out_result.exit_code = status;
#else
    const int status = pclose(pipe);
    if (WIFEXITED(status)) {
        out_result.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        out_result.exit_code = 128 + WTERMSIG(status);
    } else {
        out_result.exit_code = status;
    }
#endif

    return true;
}

std::string_view to_string(const Severity severity) noexcept {
    switch (severity) {
    case Severity::Low:
        return "low";
    case Severity::Medium:
        return "medium";
    case Severity::High:
        return "high";
    default:
        return "unknown";
    }
}

}  // namespace zara::security
