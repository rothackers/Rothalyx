#include "zara/sdk/api.h"

#include "zara/ai/assistant.hpp"
#include "zara/analysis/program_analysis.hpp"
#include "zara/database/project_store.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"

#if defined(ZARA_HAS_SQLITE)
#include <sqlite3.h>
#endif

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr const char* kSdkVersionString = "1.0.0";

void write_error(const std::string& message, char* buffer, const std::size_t buffer_size) {
    if (buffer == nullptr || buffer_size == 0) {
        return;
    }

    const std::size_t copy_size = std::min<std::size_t>(buffer_size - 1, message.size());
    std::memcpy(buffer, message.data(), copy_size);
    buffer[copy_size] = '\0';
}

zara::ai::AssistantOptions convert_ai_options(const zara_ai_options_t* options) {
    if (options == nullptr) {
        return zara::ai::AssistantOptions{};
    }

    zara::ai::AssistantOptions converted;
    const std::string_view backend = options->backend == nullptr ? std::string_view{} : std::string_view(options->backend);
    if (backend == "openai") {
        converted.backend = zara::ai::AssistantBackend::OpenAI;
    } else if (backend == "anthropic") {
        converted.backend = zara::ai::AssistantBackend::Anthropic;
    } else if (backend == "gemini") {
        converted.backend = zara::ai::AssistantBackend::Gemini;
    } else if (backend == "openai_compatible") {
        converted.backend = zara::ai::AssistantBackend::OpenAICompatible;
    } else if (backend == "local_llm") {
        converted.backend = zara::ai::AssistantBackend::LocalLLM;
    } else if (backend == "auto") {
        converted.backend = zara::ai::AssistantBackend::Auto;
    } else {
        converted.backend = zara::ai::AssistantBackend::Heuristic;
    }

    const bool has_model_config =
        (options->api_key != nullptr && *options->api_key != '\0') ||
        (options->model != nullptr && *options->model != '\0') ||
        (options->base_url != nullptr && *options->base_url != '\0') ||
        (options->organization != nullptr && *options->organization != '\0') ||
        (options->project != nullptr && *options->project != '\0') ||
        options->max_model_functions > 0 ||
        options->timeout_ms > 0;

    if (has_model_config) {
        const auto assign_common_model_config = [&](auto& target) {
            if (options->api_key != nullptr) {
                target.api_key = options->api_key;
            }
            if (options->model != nullptr && *options->model != '\0') {
                target.model = options->model;
            }
            if (options->base_url != nullptr && *options->base_url != '\0') {
                target.base_url = options->base_url;
            }
            if (options->max_model_functions > 0) {
                target.max_functions = options->max_model_functions;
            }
            if (options->timeout_ms > 0) {
                target.timeout_ms = options->timeout_ms;
            }
        };

        if (converted.backend == zara::ai::AssistantBackend::Anthropic) {
            zara::ai::AnthropicOptions anthropic;
            assign_common_model_config(anthropic);
            converted.anthropic = std::move(anthropic);
        } else if (converted.backend == zara::ai::AssistantBackend::Gemini) {
            zara::ai::GeminiOptions gemini;
            assign_common_model_config(gemini);
            converted.gemini = std::move(gemini);
        } else if (converted.backend == zara::ai::AssistantBackend::OpenAICompatible ||
                   converted.backend == zara::ai::AssistantBackend::LocalLLM) {
            zara::ai::CompatibleModelOptions compatible;
            assign_common_model_config(compatible);
            converted.compatible = std::move(compatible);
        } else {
            zara::ai::OpenAIOptions openai;
            assign_common_model_config(openai);
            if (options->organization != nullptr) {
                openai.organization = options->organization;
            }
            if (options->project != nullptr) {
                openai.project = options->project;
            }
            converted.openai = std::move(openai);
        }
    }

    return converted;
}

#if defined(ZARA_HAS_SQLITE)
class Statement {
public:
    Statement(sqlite3* database, const char* sql, std::string& out_error) {
        if (sqlite3_prepare_v2(database, sql, -1, &statement_, nullptr) != SQLITE_OK) {
            out_error = sqlite3_errmsg(database);
        }
    }

    ~Statement() {
        if (statement_ != nullptr) {
            sqlite3_finalize(statement_);
        }
    }

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    [[nodiscard]] sqlite3_stmt* get() const noexcept {
        return statement_;
    }

    [[nodiscard]] bool valid() const noexcept {
        return statement_ != nullptr;
    }

private:
    sqlite3_stmt* statement_ = nullptr;
};

std::string column_text(sqlite3_stmt* statement, const int column_index) {
    const unsigned char* text = sqlite3_column_text(statement, column_index);
    return text == nullptr ? std::string() : reinterpret_cast<const char*>(text);
}

std::optional<std::uint64_t> column_optional_u64(sqlite3_stmt* statement, const int column_index) {
    if (sqlite3_column_type(statement, column_index) == SQLITE_NULL) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(sqlite3_column_int64(statement, column_index));
}

bool step_row(sqlite3* database, sqlite3_stmt* statement, std::string& out_error) {
    const int result = sqlite3_step(statement);
    if (result == SQLITE_ROW) {
        return true;
    }
    if (result == SQLITE_DONE) {
        return false;
    }
    out_error = sqlite3_errmsg(database);
    return false;
}

struct RunData {
    int run_id = 0;
    std::string binary_path;
    std::string binary_format;
    std::string architecture;
    std::uint64_t base_address = 0;
    std::optional<std::uint64_t> entry_point;
    int section_count = 0;
    int function_count = 0;
    int import_count = 0;
    int export_count = 0;
    int xref_count = 0;
    int string_count = 0;
    std::string ai_backend;
    std::string ai_model;
    std::string poc_scaffold;
};

struct FunctionData {
    std::string name;
    std::string section_name;
    std::uint64_t entry_address = 0;
    std::uint64_t start_address = 0;
    std::uint64_t end_address = 0;
    int block_count = 0;
    int instruction_count = 0;
    std::string decompiled_pseudocode;
    std::string analysis_summary;
};

struct InsightData {
    std::uint64_t function_entry = 0;
    std::string current_name;
    std::string suggested_name;
    std::string summary;
    std::string hints;
    std::string patterns;
    std::string vulnerability_hints;
};

struct ProjectHandle {
    std::filesystem::path database_path;
    sqlite3* database = nullptr;
    std::optional<RunData> latest_run;
    int cached_function_run_id = -1;
    int cached_ai_run_id = -1;
    std::vector<FunctionData> functions;
    std::vector<InsightData> ai_insights;
};

ProjectHandle* as_handle(zara_project_t* project) {
    return reinterpret_cast<ProjectHandle*>(project);
}

bool ensure_open(ProjectHandle* project, std::string& out_error) {
    if (project == nullptr || project->database == nullptr) {
        out_error = "Project handle is not open.";
        return false;
    }
    return true;
}

void fill_run_record(const RunData& source, zara_run_overview_t* target) {
    target->run_id = source.run_id;
    target->binary_path = source.binary_path.c_str();
    target->binary_format = source.binary_format.c_str();
    target->architecture = source.architecture.c_str();
    target->base_address = source.base_address;
    target->has_entry_point = source.entry_point.has_value() ? 1 : 0;
    target->entry_point = source.entry_point.value_or(0);
    target->section_count = source.section_count;
    target->function_count = source.function_count;
    target->import_count = source.import_count;
    target->export_count = source.export_count;
    target->xref_count = source.xref_count;
    target->string_count = source.string_count;
    target->ai_backend = source.ai_backend.c_str();
    target->ai_model = source.ai_model.c_str();
    target->poc_scaffold = source.poc_scaffold.c_str();
}

void fill_function_record(const FunctionData& source, zara_function_record_t* target) {
    target->name = source.name.c_str();
    target->section_name = source.section_name.c_str();
    target->entry_address = source.entry_address;
    target->start_address = source.start_address;
    target->end_address = source.end_address;
    target->block_count = source.block_count;
    target->instruction_count = source.instruction_count;
    target->decompiled_pseudocode = source.decompiled_pseudocode.c_str();
    target->analysis_summary = source.analysis_summary.c_str();
}

void fill_ai_record(const InsightData& source, zara_ai_insight_record_t* target) {
    target->function_entry = source.function_entry;
    target->current_name = source.current_name.c_str();
    target->suggested_name = source.suggested_name.c_str();
    target->summary = source.summary.c_str();
    target->hints = source.hints.c_str();
    target->patterns = source.patterns.c_str();
    target->vulnerability_hints = source.vulnerability_hints.c_str();
}

bool load_latest_run(ProjectHandle* project, std::string& out_error) {
    if (!ensure_open(project, out_error)) {
        return false;
    }

    Statement statement(
        project->database,
        "SELECT id, binary_path, binary_format, architecture, base_address, entry_point, section_count, "
        "function_count, import_count, export_count, xref_count, string_count, ai_backend, ai_model, poc_scaffold "
        "FROM analysis_runs ORDER BY id DESC LIMIT 1;",
        out_error
    );
    if (!statement.valid()) {
        return false;
    }

    if (!step_row(project->database, statement.get(), out_error)) {
        if (out_error.empty()) {
            out_error = "No analysis runs were found in the project database.";
        }
        return false;
    }

    project->latest_run = RunData{
        .run_id = sqlite3_column_int(statement.get(), 0),
        .binary_path = column_text(statement.get(), 1),
        .binary_format = column_text(statement.get(), 2),
        .architecture = column_text(statement.get(), 3),
        .base_address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 4)),
        .entry_point = column_optional_u64(statement.get(), 5),
        .section_count = sqlite3_column_int(statement.get(), 6),
        .function_count = sqlite3_column_int(statement.get(), 7),
        .import_count = sqlite3_column_int(statement.get(), 8),
        .export_count = sqlite3_column_int(statement.get(), 9),
        .xref_count = sqlite3_column_int(statement.get(), 10),
        .string_count = sqlite3_column_int(statement.get(), 11),
        .ai_backend = column_text(statement.get(), 12),
        .ai_model = column_text(statement.get(), 13),
        .poc_scaffold = column_text(statement.get(), 14),
    };
    return true;
}

bool load_functions(ProjectHandle* project, const int run_id, std::string& out_error) {
    if (!ensure_open(project, out_error)) {
        return false;
    }

    if (project->cached_function_run_id == run_id) {
        return true;
    }

    Statement statement(
        project->database,
        "SELECT f.name, f.section_name, f.entry_address, "
        "COALESCE((SELECT MIN(start_address) FROM basic_blocks b WHERE b.run_id = f.run_id AND b.function_entry = f.entry_address), f.entry_address), "
        "COALESCE((SELECT MAX(end_address) FROM basic_blocks b WHERE b.run_id = f.run_id AND b.function_entry = f.entry_address), f.entry_address), "
        "f.block_count, f.instruction_count, f.decompiled_pseudocode, f.analysis_summary "
        "FROM functions f WHERE f.run_id = ? ORDER BY f.entry_address;",
        out_error
    );
    if (!statement.valid()) {
        return false;
    }

    sqlite3_bind_int(statement.get(), 1, run_id);
    project->functions.clear();
    while (step_row(project->database, statement.get(), out_error)) {
        project->functions.push_back(
            FunctionData{
                .name = column_text(statement.get(), 0),
                .section_name = column_text(statement.get(), 1),
                .entry_address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 2)),
                .start_address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 3)),
                .end_address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 4)),
                .block_count = sqlite3_column_int(statement.get(), 5),
                .instruction_count = sqlite3_column_int(statement.get(), 6),
                .decompiled_pseudocode = column_text(statement.get(), 7),
                .analysis_summary = column_text(statement.get(), 8),
            }
        );
    }

    if (!out_error.empty()) {
        return false;
    }

    project->cached_function_run_id = run_id;
    return true;
}

bool load_ai_insights(ProjectHandle* project, const int run_id, std::string& out_error) {
    if (!ensure_open(project, out_error)) {
        return false;
    }

    if (project->cached_ai_run_id == run_id) {
        return true;
    }

    Statement statement(
        project->database,
        "SELECT function_entry, current_name, suggested_name, summary, hints, patterns, vulnerability_hints "
        "FROM ai_function_insights WHERE run_id = ? ORDER BY function_entry;",
        out_error
    );
    if (!statement.valid()) {
        return false;
    }

    sqlite3_bind_int(statement.get(), 1, run_id);
    project->ai_insights.clear();
    while (step_row(project->database, statement.get(), out_error)) {
        project->ai_insights.push_back(
            InsightData{
                .function_entry = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0)),
                .current_name = column_text(statement.get(), 1),
                .suggested_name = column_text(statement.get(), 2),
                .summary = column_text(statement.get(), 3),
                .hints = column_text(statement.get(), 4),
                .patterns = column_text(statement.get(), 5),
                .vulnerability_hints = column_text(statement.get(), 6),
            }
        );
    }

    if (!out_error.empty()) {
        return false;
    }

    project->cached_ai_run_id = run_id;
    return true;
}
#endif

}  // namespace

extern "C" {

const char* zara_sdk_version_string(void) {
    return kSdkVersionString;
}

uint32_t zara_sdk_abi_version(void) {
    return ZARA_SDK_ABI_VERSION;
}

const char* zara_sdk_supported_plugin_api_version(void) {
    return ZARA_SDK_PLUGIN_API_VERSION;
}

const char* zara_sdk_status_string(const zara_sdk_status_t status) {
    switch (status) {
    case ZARA_SDK_STATUS_OK:
        return "ok";
    case ZARA_SDK_STATUS_INVALID_ARGUMENT:
        return "invalid_argument";
    case ZARA_SDK_STATUS_NOT_FOUND:
        return "not_found";
    case ZARA_SDK_STATUS_UNSUPPORTED:
        return "unsupported";
    case ZARA_SDK_STATUS_ERROR:
    default:
        return "error";
    }
}

zara_sdk_status_t zara_sdk_analyze_binary(
    const char* binary_path,
    const char* project_db_path,
    const zara_ai_options_t* ai_options,
    char* error_buffer,
    const size_t error_buffer_size
) {
    if (binary_path == nullptr || project_db_path == nullptr) {
        write_error("binary_path and project_db_path are required.", error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_INVALID_ARGUMENT;
    }

    std::string error;
    zara::loader::BinaryImage image;
    if (!zara::loader::BinaryImage::load_from_file(binary_path, image, error)) {
        write_error(error, error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_ERROR;
    }

    zara::memory::AddressSpace address_space;
    if (!address_space.map_image(image)) {
        write_error("Failed to map the binary image into the analysis address space.", error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_ERROR;
    }

    const auto program = zara::analysis::Analyzer::analyze(image, address_space);
    const auto assistant_options = convert_ai_options(ai_options);
    zara::database::ProjectStore store(project_db_path);
    if (!store.save_program_analysis(image, program, &assistant_options, error)) {
        write_error(error, error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_ERROR;
    }

    write_error("", error_buffer, error_buffer_size);
    return ZARA_SDK_STATUS_OK;
}

zara_sdk_status_t zara_sdk_open_project(
    const char* project_db_path,
    zara_project_t** out_project,
    char* error_buffer,
    const size_t error_buffer_size
) {
    if (project_db_path == nullptr || out_project == nullptr) {
        write_error("project_db_path and out_project are required.", error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_INVALID_ARGUMENT;
    }

#if !defined(ZARA_HAS_SQLITE)
    write_error("This build does not include SQLite-backed project APIs.", error_buffer, error_buffer_size);
    return ZARA_SDK_STATUS_UNSUPPORTED;
#else
    auto* project = new ProjectHandle{};
    project->database_path = project_db_path;

    zara::database::ProjectStore store(project->database_path);
    std::string error;
    if (!store.initialize(error)) {
        write_error(error, error_buffer, error_buffer_size);
        delete project;
        return ZARA_SDK_STATUS_ERROR;
    }

    if (sqlite3_open_v2(
            project->database_path.string().c_str(),
            &project->database,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
            nullptr
        ) != SQLITE_OK) {
        error = project->database == nullptr ? "Failed to open SQLite database." : sqlite3_errmsg(project->database);
        if (project->database != nullptr) {
            sqlite3_close(project->database);
        }
        delete project;
        write_error(error, error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_ERROR;
    }

    *out_project = reinterpret_cast<zara_project_t*>(project);
    write_error("", error_buffer, error_buffer_size);
    return ZARA_SDK_STATUS_OK;
#endif
}

void zara_sdk_close_project(zara_project_t* project) {
#if defined(ZARA_HAS_SQLITE)
    if (auto* handle = as_handle(project); handle != nullptr && handle->database != nullptr) {
        sqlite3_close(handle->database);
        handle->database = nullptr;
    }
#endif
    delete as_handle(project);
}

zara_sdk_status_t zara_sdk_get_latest_run(
    zara_project_t* project,
    zara_run_overview_t* out_run,
    char* error_buffer,
    const size_t error_buffer_size
) {
    if (project == nullptr || out_run == nullptr) {
        write_error("project and out_run are required.", error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_INVALID_ARGUMENT;
    }

#if !defined(ZARA_HAS_SQLITE)
    write_error("This build does not include SQLite-backed project APIs.", error_buffer, error_buffer_size);
    return ZARA_SDK_STATUS_UNSUPPORTED;
#else
    std::string error;
    auto* handle = as_handle(project);
    if (!load_latest_run(handle, error)) {
        write_error(error, error_buffer, error_buffer_size);
        return error.empty() ? ZARA_SDK_STATUS_NOT_FOUND : ZARA_SDK_STATUS_ERROR;
    }

    fill_run_record(*handle->latest_run, out_run);
    write_error("", error_buffer, error_buffer_size);
    return ZARA_SDK_STATUS_OK;
#endif
}

zara_sdk_status_t zara_sdk_get_function_count(
    zara_project_t* project,
    const int run_id,
    size_t* out_count,
    char* error_buffer,
    const size_t error_buffer_size
) {
    if (project == nullptr || out_count == nullptr) {
        write_error("project and out_count are required.", error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_INVALID_ARGUMENT;
    }

#if !defined(ZARA_HAS_SQLITE)
    write_error("This build does not include SQLite-backed project APIs.", error_buffer, error_buffer_size);
    return ZARA_SDK_STATUS_UNSUPPORTED;
#else
    std::string error;
    auto* handle = as_handle(project);
    if (!load_functions(handle, run_id, error)) {
        write_error(error, error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_ERROR;
    }
    *out_count = handle->functions.size();
    write_error("", error_buffer, error_buffer_size);
    return ZARA_SDK_STATUS_OK;
#endif
}

zara_sdk_status_t zara_sdk_get_function_at(
    zara_project_t* project,
    const int run_id,
    const size_t index,
    zara_function_record_t* out_function,
    char* error_buffer,
    const size_t error_buffer_size
) {
    if (project == nullptr || out_function == nullptr) {
        write_error("project and out_function are required.", error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_INVALID_ARGUMENT;
    }

#if !defined(ZARA_HAS_SQLITE)
    write_error("This build does not include SQLite-backed project APIs.", error_buffer, error_buffer_size);
    return ZARA_SDK_STATUS_UNSUPPORTED;
#else
    std::string error;
    auto* handle = as_handle(project);
    if (!load_functions(handle, run_id, error)) {
        write_error(error, error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_ERROR;
    }
    if (index >= handle->functions.size()) {
        write_error("Requested function index is out of range.", error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_NOT_FOUND;
    }
    fill_function_record(handle->functions[index], out_function);
    write_error("", error_buffer, error_buffer_size);
    return ZARA_SDK_STATUS_OK;
#endif
}

zara_sdk_status_t zara_sdk_get_ai_insight_count(
    zara_project_t* project,
    const int run_id,
    size_t* out_count,
    char* error_buffer,
    const size_t error_buffer_size
) {
    if (project == nullptr || out_count == nullptr) {
        write_error("project and out_count are required.", error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_INVALID_ARGUMENT;
    }

#if !defined(ZARA_HAS_SQLITE)
    write_error("This build does not include SQLite-backed project APIs.", error_buffer, error_buffer_size);
    return ZARA_SDK_STATUS_UNSUPPORTED;
#else
    std::string error;
    auto* handle = as_handle(project);
    if (!load_ai_insights(handle, run_id, error)) {
        write_error(error, error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_ERROR;
    }
    *out_count = handle->ai_insights.size();
    write_error("", error_buffer, error_buffer_size);
    return ZARA_SDK_STATUS_OK;
#endif
}

zara_sdk_status_t zara_sdk_get_ai_insight_at(
    zara_project_t* project,
    const int run_id,
    const size_t index,
    zara_ai_insight_record_t* out_insight,
    char* error_buffer,
    const size_t error_buffer_size
) {
    if (project == nullptr || out_insight == nullptr) {
        write_error("project and out_insight are required.", error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_INVALID_ARGUMENT;
    }

#if !defined(ZARA_HAS_SQLITE)
    write_error("This build does not include SQLite-backed project APIs.", error_buffer, error_buffer_size);
    return ZARA_SDK_STATUS_UNSUPPORTED;
#else
    std::string error;
    auto* handle = as_handle(project);
    if (!load_ai_insights(handle, run_id, error)) {
        write_error(error, error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_ERROR;
    }
    if (index >= handle->ai_insights.size()) {
        write_error("Requested AI insight index is out of range.", error_buffer, error_buffer_size);
        return ZARA_SDK_STATUS_NOT_FOUND;
    }
    fill_ai_record(handle->ai_insights[index], out_insight);
    write_error("", error_buffer, error_buffer_size);
    return ZARA_SDK_STATUS_OK;
#endif
}

}  // extern "C"
