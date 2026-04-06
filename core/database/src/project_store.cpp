#include "zara/database/project_store.hpp"

#include "zara/ai/assistant.hpp"
#include "zara/security/workflow.hpp"

#if defined(ZARA_HAS_SQLITE)
#include <sqlite3.h>
#endif

#include <algorithm>
#include <charconv>
#include <iomanip>
#include <optional>
#include <sstream>
#include <utility>

namespace zara::database {

namespace {

#if defined(ZARA_HAS_SQLITE)
constexpr std::string_view kProjectSchemaVersion = "4";

bool prepare_statement(sqlite3* database, const char* sql, sqlite3_stmt*& out_statement, std::string& out_error);
bool step_statement(sqlite3* database, sqlite3_stmt* statement, std::string& out_error);
void finalize_statement(sqlite3_stmt*& statement);

bool exec_sql(sqlite3* database, const char* sql, std::string& out_error) {
    char* error_message = nullptr;
    const int exec_result = sqlite3_exec(database, sql, nullptr, nullptr, &error_message);
    if (exec_result != SQLITE_OK) {
        out_error = error_message == nullptr ? "SQLite execution failed." : error_message;
        sqlite3_free(error_message);
        return false;
    }

    return true;
}

bool configure_database(sqlite3* database, std::string& out_error) {
    return exec_sql(database, "PRAGMA foreign_keys = ON;", out_error) &&
           exec_sql(database, "PRAGMA busy_timeout = 5000;", out_error) &&
           exec_sql(database, "PRAGMA journal_mode = WAL;", out_error) &&
           exec_sql(database, "PRAGMA synchronous = NORMAL;", out_error);
}

bool set_metadata_value(sqlite3* database, const char* key, const char* value, std::string& out_error) {
    sqlite3_stmt* statement = nullptr;
    if (!prepare_statement(
            database,
            "INSERT INTO project_metadata (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
            statement,
            out_error
        )) {
        return false;
    }

    sqlite3_bind_text(statement, 1, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, value, -1, SQLITE_TRANSIENT);
    const bool ok = step_statement(database, statement, out_error);
    finalize_statement(statement);
    return ok;
}

bool table_exists(sqlite3* database, const char* table_name, std::string& out_error) {
    sqlite3_stmt* statement = nullptr;
    if (!prepare_statement(
            database,
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1;",
            statement,
            out_error
        )) {
        return false;
    }

    sqlite3_bind_text(statement, 1, table_name, -1, SQLITE_TRANSIENT);
    bool exists = false;
    const int step_result = sqlite3_step(statement);
    if (step_result == SQLITE_ROW) {
        exists = true;
    } else if (step_result != SQLITE_DONE) {
        out_error = sqlite3_errmsg(database);
    }
    finalize_statement(statement);
    return exists;
}

std::optional<std::string> get_metadata_value(sqlite3* database, const char* key, std::string& out_error) {
    sqlite3_stmt* statement = nullptr;
    if (!prepare_statement(database, "SELECT value FROM project_metadata WHERE key = ? LIMIT 1;", statement, out_error)) {
        return std::nullopt;
    }

    sqlite3_bind_text(statement, 1, key, -1, SQLITE_TRANSIENT);
    std::optional<std::string> value;
    const int step_result = sqlite3_step(statement);
    if (step_result == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(statement, 0);
        value = text == nullptr ? std::string{} : reinterpret_cast<const char*>(text);
    } else if (step_result != SQLITE_DONE) {
        out_error = sqlite3_errmsg(database);
    }

    finalize_statement(statement);
    return value;
}

bool parse_schema_version(const std::string& text, int& out_version) {
    out_version = 0;
    if (text.empty()) {
        return false;
    }

    const char* begin = text.data();
    const char* end = text.data() + text.size();
    const auto result = std::from_chars(begin, end, out_version);
    return result.ec == std::errc{} && result.ptr == end;
}

bool insert_version_event(
    sqlite3* database,
    sqlite3_stmt* statement,
    const std::optional<sqlite3_int64> run_id,
    const std::string& kind,
    const std::string& title,
    const std::string& detail,
    const std::string& payload,
    std::string& out_error
) {
    if (run_id.has_value()) {
        sqlite3_bind_int64(statement, 1, *run_id);
    } else {
        sqlite3_bind_null(statement, 1);
    }
    sqlite3_bind_text(statement, 2, kind.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, title.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 4, detail.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 5, payload.c_str(), -1, SQLITE_TRANSIENT);
    return step_statement(database, statement, out_error);
}

bool prepare_statement(sqlite3* database, const char* sql, sqlite3_stmt*& out_statement, std::string& out_error) {
    out_statement = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &out_statement, nullptr) != SQLITE_OK) {
        out_error = sqlite3_errmsg(database);
        return false;
    }

    return true;
}

bool table_has_column(sqlite3* database, const char* table_name, const char* column_name, std::string& out_error) {
    std::string pragma = "PRAGMA table_info(" + std::string(table_name) + ");";
    sqlite3_stmt* statement = nullptr;
    if (!prepare_statement(database, pragma.c_str(), statement, out_error)) {
        return false;
    }

    bool found = false;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        const unsigned char* name = sqlite3_column_text(statement, 1);
        if (name != nullptr && std::string_view(reinterpret_cast<const char*>(name)) == column_name) {
            found = true;
            break;
        }
    }

    if (statement != nullptr) {
        sqlite3_finalize(statement);
    }
    return found;
}

bool ensure_column(
    sqlite3* database,
    const char* table_name,
    const char* column_name,
    const char* column_definition,
    std::string& out_error
) {
    if (table_has_column(database, table_name, column_name, out_error)) {
        return true;
    }

    const std::string sql =
        "ALTER TABLE " + std::string(table_name) + " ADD COLUMN " + std::string(column_name) + ' ' +
        std::string(column_definition) + ';';
    return exec_sql(database, sql.c_str(), out_error);
}

bool step_statement(sqlite3* database, sqlite3_stmt* statement, std::string& out_error) {
    if (sqlite3_step(statement) != SQLITE_DONE) {
        out_error = sqlite3_errmsg(database);
        sqlite3_reset(statement);
        sqlite3_clear_bindings(statement);
        return false;
    }

    sqlite3_reset(statement);
    sqlite3_clear_bindings(statement);
    return true;
}

void finalize_statement(sqlite3_stmt*& statement) {
    if (statement != nullptr) {
        sqlite3_finalize(statement);
        statement = nullptr;
    }
}

std::string join_successors(const std::vector<std::uint64_t>& successors) {
    std::ostringstream stream;
    for (std::size_t index = 0; index < successors.size(); ++index) {
        if (index > 0) {
            stream << ',';
        }
        stream << successors[index];
    }

    return stream.str();
}

std::string join_lines(const std::vector<std::string>& values) {
    std::ostringstream stream;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index > 0) {
            stream << '\n';
        }
        stream << values[index];
    }
    return stream.str();
}

std::string join_ai_patterns(const std::vector<ai::PatternDetection>& patterns) {
    std::vector<std::string> lines;
    lines.reserve(patterns.size());
    for (const auto& pattern : patterns) {
        lines.push_back(pattern.category + "|" + pattern.label + "|" + pattern.confidence + "|" + pattern.detail);
    }
    return join_lines(lines);
}

std::string join_ai_vulnerability_hints(const std::vector<ai::VulnerabilityHint>& hints) {
    std::vector<std::string> lines;
    lines.reserve(hints.size());
    for (const auto& hint : hints) {
        lines.push_back(hint.severity + "|" + hint.title + "|" + hint.detail);
    }
    return join_lines(lines);
}

std::string join_poc_notes(const std::vector<std::string>& notes) {
    return join_lines(notes);
}

std::string hash_bytes(const std::span<const std::byte> bytes) {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const auto byte : bytes) {
        hash ^= static_cast<std::uint64_t>(std::to_integer<unsigned char>(byte));
        hash *= 1099511628211ULL;
    }

    std::ostringstream stream;
    stream << std::hex << std::setw(16) << std::setfill('0') << std::nouppercase << hash;
    return stream.str();
}

std::string format_stack_offset(const std::int64_t offset) {
    std::ostringstream stream;
    if (offset >= 0) {
        stream << "+0x" << std::hex << std::uppercase << static_cast<std::uint64_t>(offset);
    } else {
        stream << "-0x" << std::hex << std::uppercase << static_cast<std::uint64_t>(-offset);
    }
    return stream.str();
}

bool is_buffer_local(const analysis::LocalVariable& local) {
    return local.size >= 16 || local.name.find("buf") != std::string::npos || local.name.find("stack") != std::string::npos;
}

std::string render_function_summary(const analysis::DiscoveredFunction& function) {
    std::vector<std::string> lines;
    lines.push_back("Function analysis");
    lines.push_back("Name: " + function.name);
    lines.push_back("Entry: " + std::to_string(function.entry_address));
    lines.push_back("Calling convention: " + std::string(analysis::to_string(function.summary.calling_convention)));
    lines.push_back("Stack frame size: " + std::to_string(function.summary.stack_frame_size));
    lines.push_back("Uses frame pointer: " + std::string(function.summary.uses_frame_pointer ? "yes" : "no"));
    lines.push_back("Unreachable blocks removed: " + std::to_string(function.summary.unreachable_blocks_removed));
    lines.push_back("Copy propagations: " + std::to_string(function.summary.copy_propagations_applied));
    lines.push_back("Dead instructions eliminated: " + std::to_string(function.summary.dead_instructions_eliminated));
    lines.push_back("Linear merges: " + std::to_string(function.summary.cfg_linear_merges));
    lines.push_back("Loops: " + std::to_string(function.graph.loops().size()));
    lines.push_back("Switches: " + std::to_string(function.graph.switches().size()));

    lines.push_back("");
    lines.push_back("Arguments");
    if (function.summary.arguments.empty()) {
        lines.push_back("-");
    } else {
        for (const auto& argument : function.summary.arguments) {
            lines.push_back(
                argument.name + " @" + argument.location + " : " + std::string(ir::to_string(argument.type))
            );
        }
    }

    lines.push_back("");
    lines.push_back("Locals");
    if (function.summary.locals.empty()) {
        lines.push_back("-");
    } else {
        for (const auto& local : function.summary.locals) {
            std::ostringstream stream;
            stream << local.name << " stack[" << local.stack_offset << "] size=" << local.size << " : "
                   << ir::to_string(local.type);
            lines.push_back(stream.str());
        }
    }

    lines.push_back("");
    lines.push_back("Stack Layout");
    if (function.summary.stack_frame_size <= 0 && function.summary.locals.empty()) {
        lines.push_back("-");
    } else {
        if (function.summary.uses_frame_pointer) {
            lines.push_back("+0x0  saved_frame_pointer  size=8");
            lines.push_back("+0x8  return_address       size=8");
        } else {
            lines.push_back("+0x0  return_address       size=8");
        }

        auto locals = function.summary.locals;
        std::sort(
            locals.begin(),
            locals.end(),
            [](const analysis::LocalVariable& lhs, const analysis::LocalVariable& rhs) {
                if (lhs.stack_offset != rhs.stack_offset) {
                    return lhs.stack_offset > rhs.stack_offset;
                }
                return lhs.name < rhs.name;
            }
        );
        for (const auto& local : locals) {
            std::ostringstream stream;
            stream << format_stack_offset(local.stack_offset) << "  "
                   << (is_buffer_local(local) ? "buffer" : "local") << "  "
                   << local.name << "  size=" << local.size;
            lines.push_back(stream.str());
        }
    }

    lines.push_back("");
    lines.push_back("Constants");
    if (function.summary.constants.empty()) {
        lines.push_back("-");
    } else {
        for (const auto& constant : function.summary.constants) {
            lines.push_back(constant.name + "=" + std::to_string(constant.value));
        }
    }

    lines.push_back("");
    lines.push_back("Pointers");
    if (function.summary.pointer_variables.empty()) {
        lines.push_back("-");
    } else {
        lines.insert(lines.end(), function.summary.pointer_variables.begin(), function.summary.pointer_variables.end());
    }

    lines.push_back("");
    lines.push_back("Structs");
    if (function.recovered_types.structs.empty()) {
        lines.push_back("-");
    } else {
        for (const auto& recovered_struct : function.recovered_types.structs) {
            lines.push_back(recovered_struct.owner_name + " : " + recovered_struct.type_name + '*');
            for (const auto& field : recovered_struct.fields) {
                std::ostringstream stream;
                stream << "  +" << field.offset << "  " << field.name << " : " << ir::to_string(field.type)
                       << "  size=" << field.size;
                lines.push_back(stream.str());
            }
        }
    }

    lines.push_back("");
    lines.push_back("Arrays");
    if (function.recovered_types.arrays.empty()) {
        lines.push_back("-");
    } else {
        for (const auto& recovered_array : function.recovered_types.arrays) {
            std::ostringstream stream;
            stream << recovered_array.owner_name << " : " << recovered_array.type_name << "  element="
                   << ir::to_string(recovered_array.element_type) << "  size=" << recovered_array.element_size
                   << "  observed=" << recovered_array.observed_elements
                   << "  indexed=" << (recovered_array.indexed_access ? "yes" : "no");
            lines.push_back(stream.str());
        }
    }

    lines.push_back("");
    lines.push_back("Indirect resolutions");
    if (function.summary.indirect_resolutions.empty()) {
        lines.push_back("-");
    } else {
        for (const auto& resolution : function.summary.indirect_resolutions) {
            std::ostringstream stream;
            stream << resolution.instruction_address << " -> ";
            if (resolution.resolved_target.has_value()) {
                stream << *resolution.resolved_target;
            } else {
                stream << "unknown";
            }
            if (!resolution.label.empty()) {
                stream << "  " << resolution.label;
            }
            lines.push_back(stream.str());
        }
    }

    return join_lines(lines);
}

std::string_view to_string(const disasm::InstructionKind kind) noexcept {
    switch (kind) {
    case disasm::InstructionKind::DataByte:
        return "data_byte";
    case disasm::InstructionKind::Instruction:
        return "instruction";
    case disasm::InstructionKind::Call:
        return "call";
    case disasm::InstructionKind::Jump:
        return "jump";
    case disasm::InstructionKind::ConditionalJump:
        return "conditional_jump";
    case disasm::InstructionKind::Return:
        return "return";
    case disasm::InstructionKind::Interrupt:
        return "interrupt";
    case disasm::InstructionKind::Unknown:
    default:
        return "unknown";
    }
}

bool validate_schema_version(sqlite3* database, std::string& out_error) {
    int current_version = 0;
    if (!parse_schema_version(std::string(kProjectSchemaVersion), current_version)) {
        out_error = "Internal schema version is invalid.";
        return false;
    }

    if (!table_exists(database, "project_metadata", out_error)) {
        return out_error.empty();
    }

    const auto stored = get_metadata_value(database, "schema_version", out_error);
    if (!out_error.empty()) {
        return false;
    }
    if (!stored.has_value() || stored->empty()) {
        return true;
    }

    int stored_version = 0;
    if (!parse_schema_version(*stored, stored_version)) {
        out_error = "Project database schema_version metadata is invalid.";
        return false;
    }
    if (stored_version > current_version) {
        out_error =
            "Project database schema version " + std::to_string(stored_version) +
            " is newer than this Zara build supports.";
        return false;
    }
    return true;
}
#endif

}  // namespace

ProjectStore::ProjectStore(std::filesystem::path database_path)
    : database_path_(std::move(database_path)) {}

bool ProjectStore::initialize(std::string& out_error) const {
    out_error.clear();

#if defined(ZARA_HAS_SQLITE)
    sqlite3* database = nullptr;
    if (sqlite3_open(database_path_.string().c_str(), &database) != SQLITE_OK) {
        out_error = sqlite3_errmsg(database);
        sqlite3_close(database);
        return false;
    }

    if (!configure_database(database, out_error)) {
        sqlite3_close(database);
        return false;
    }

    if (!validate_schema_version(database, out_error)) {
        sqlite3_close(database);
        return false;
    }

    if (table_has_column(database, "analysis_runs", "id", out_error) &&
        !table_has_column(database, "analysis_runs", "architecture", out_error)) {
        constexpr const char* drop_legacy_sql =
            "DROP TABLE IF EXISTS call_edges;"
            "DROP TABLE IF EXISTS xrefs;"
            "DROP TABLE IF EXISTS strings;"
            "DROP TABLE IF EXISTS exports;"
            "DROP TABLE IF EXISTS imports;"
            "DROP TABLE IF EXISTS instructions;"
            "DROP TABLE IF EXISTS basic_blocks;"
            "DROP TABLE IF EXISTS functions;"
            "DROP TABLE IF EXISTS analysis_runs;";

        if (!exec_sql(database, drop_legacy_sql, out_error)) {
            sqlite3_close(database);
            return false;
        }
    }

    constexpr const char* create_schema_sql =
        "CREATE TABLE IF NOT EXISTS project_metadata ("
        "key TEXT PRIMARY KEY,"
        "value TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS project_versions ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER,"
        "kind TEXT NOT NULL,"
        "title TEXT NOT NULL,"
        "detail TEXT NOT NULL,"
        "payload TEXT NOT NULL DEFAULT '',"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE TABLE IF NOT EXISTS analysis_runs ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "binary_path TEXT NOT NULL,"
        "binary_format TEXT NOT NULL,"
        "architecture TEXT NOT NULL,"
        "binary_size INTEGER NOT NULL DEFAULT 0,"
        "binary_hash TEXT NOT NULL DEFAULT '',"
        "base_address INTEGER NOT NULL,"
        "entry_point INTEGER,"
        "section_count INTEGER NOT NULL,"
        "function_count INTEGER NOT NULL,"
        "import_count INTEGER NOT NULL,"
        "export_count INTEGER NOT NULL,"
        "xref_count INTEGER NOT NULL,"
        "string_count INTEGER NOT NULL,"
        "ai_backend TEXT NOT NULL DEFAULT 'heuristic',"
        "ai_model TEXT NOT NULL DEFAULT '',"
        "poc_scaffold TEXT NOT NULL DEFAULT '',"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE TABLE IF NOT EXISTS functions ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER NOT NULL,"
        "name TEXT NOT NULL,"
        "section_name TEXT NOT NULL,"
        "entry_address INTEGER NOT NULL,"
        "block_count INTEGER NOT NULL,"
        "instruction_count INTEGER NOT NULL,"
        "decompiled_pseudocode TEXT NOT NULL DEFAULT '',"
        "analysis_summary TEXT NOT NULL DEFAULT ''"
        ");"
        "CREATE TABLE IF NOT EXISTS basic_blocks ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER NOT NULL,"
        "function_entry INTEGER NOT NULL,"
        "start_address INTEGER NOT NULL,"
        "end_address INTEGER NOT NULL,"
        "successors TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS instructions ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER NOT NULL,"
        "function_entry INTEGER NOT NULL,"
        "block_start INTEGER NOT NULL,"
        "address INTEGER NOT NULL,"
        "size INTEGER NOT NULL,"
        "kind TEXT NOT NULL,"
        "mnemonic TEXT NOT NULL,"
        "operands TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS imports ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER NOT NULL,"
        "address INTEGER NOT NULL,"
        "library_name TEXT NOT NULL,"
        "name TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS exports ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER NOT NULL,"
        "address INTEGER NOT NULL,"
        "name TEXT NOT NULL,"
        "size INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS strings ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER NOT NULL,"
        "start_address INTEGER NOT NULL,"
        "end_address INTEGER NOT NULL,"
        "value TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS xrefs ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER NOT NULL,"
        "kind TEXT NOT NULL,"
        "from_address INTEGER NOT NULL,"
        "to_address INTEGER NOT NULL,"
        "label TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS call_edges ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER NOT NULL,"
        "caller_entry INTEGER NOT NULL,"
        "call_site INTEGER NOT NULL,"
        "callee_entry INTEGER,"
        "callee_name TEXT NOT NULL,"
        "is_import INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS ai_function_insights ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER NOT NULL,"
        "function_entry INTEGER NOT NULL,"
        "current_name TEXT NOT NULL,"
        "suggested_name TEXT NOT NULL,"
        "summary TEXT NOT NULL,"
        "hints TEXT NOT NULL,"
        "patterns TEXT NOT NULL DEFAULT '',"
        "vulnerability_hints TEXT NOT NULL DEFAULT ''"
        ");"
        "CREATE TABLE IF NOT EXISTS security_findings ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER NOT NULL,"
        "function_entry INTEGER NOT NULL,"
        "function_name TEXT NOT NULL,"
        "category TEXT NOT NULL,"
        "severity TEXT NOT NULL,"
        "title TEXT NOT NULL,"
        "detail TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS rop_gadgets ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER NOT NULL,"
        "function_entry INTEGER NOT NULL,"
        "function_name TEXT NOT NULL,"
        "address INTEGER NOT NULL,"
        "sequence TEXT NOT NULL,"
        "instruction_count INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS security_patterns ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER NOT NULL,"
        "function_entry INTEGER NOT NULL,"
        "function_name TEXT NOT NULL,"
        "category TEXT NOT NULL,"
        "severity TEXT NOT NULL,"
        "title TEXT NOT NULL,"
        "detail TEXT NOT NULL,"
        "poc_notes TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS user_comments ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER NOT NULL,"
        "function_entry INTEGER,"
        "address INTEGER NOT NULL,"
        "scope TEXT NOT NULL,"
        "body TEXT NOT NULL,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE TABLE IF NOT EXISTS user_type_annotations ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER NOT NULL,"
        "function_entry INTEGER,"
        "target_kind TEXT NOT NULL,"
        "symbol_name TEXT NOT NULL,"
        "type_name TEXT NOT NULL,"
        "note TEXT NOT NULL DEFAULT '',"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE TABLE IF NOT EXISTS user_symbol_renames ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER NOT NULL,"
        "function_entry INTEGER,"
        "address INTEGER NOT NULL,"
        "target_kind TEXT NOT NULL,"
        "original_name TEXT NOT NULL,"
        "renamed_name TEXT NOT NULL,"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(run_id, target_kind, address)"
        ");"
        "CREATE TABLE IF NOT EXISTS coverage_runs ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "run_id INTEGER NOT NULL,"
        "input_label TEXT NOT NULL DEFAULT '',"
        "crash_address INTEGER,"
        "crash_summary TEXT NOT NULL DEFAULT '',"
        "crash_hints TEXT NOT NULL DEFAULT '',"
        "mutation_hooks TEXT NOT NULL DEFAULT '',"
        "harness_bundle TEXT NOT NULL DEFAULT '',"
        "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE TABLE IF NOT EXISTS coverage_functions ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "coverage_run_id INTEGER NOT NULL,"
        "function_entry INTEGER NOT NULL,"
        "function_name TEXT NOT NULL,"
        "hit_count INTEGER NOT NULL,"
        "instruction_count INTEGER NOT NULL,"
        "coverage_ratio REAL NOT NULL,"
        "contains_crash_address INTEGER NOT NULL"
        ");";

    const bool schema_created = exec_sql(database, create_schema_sql, out_error);
    if (!schema_created) {
        sqlite3_close(database);
        return false;
    }

    const bool success =
        ensure_column(database, "analysis_runs", "poc_scaffold", "TEXT NOT NULL DEFAULT ''", out_error) &&
        ensure_column(database, "analysis_runs", "ai_backend", "TEXT NOT NULL DEFAULT 'heuristic'", out_error) &&
        ensure_column(database, "analysis_runs", "ai_model", "TEXT NOT NULL DEFAULT ''", out_error) &&
        ensure_column(database, "analysis_runs", "binary_size", "INTEGER NOT NULL DEFAULT 0", out_error) &&
        ensure_column(database, "analysis_runs", "binary_hash", "TEXT NOT NULL DEFAULT ''", out_error) &&
        ensure_column(database, "functions", "decompiled_pseudocode", "TEXT NOT NULL DEFAULT ''", out_error) &&
        ensure_column(database, "functions", "analysis_summary", "TEXT NOT NULL DEFAULT ''", out_error) &&
        ensure_column(database, "ai_function_insights", "patterns", "TEXT NOT NULL DEFAULT ''", out_error) &&
        ensure_column(database, "ai_function_insights", "vulnerability_hints", "TEXT NOT NULL DEFAULT ''", out_error) &&
        ensure_column(database, "project_versions", "payload", "TEXT NOT NULL DEFAULT ''", out_error) &&
        ensure_column(database, "user_type_annotations", "note", "TEXT NOT NULL DEFAULT ''", out_error) &&
        ensure_column(database, "coverage_runs", "crash_hints", "TEXT NOT NULL DEFAULT ''", out_error) &&
        ensure_column(database, "coverage_runs", "mutation_hooks", "TEXT NOT NULL DEFAULT ''", out_error) &&
        ensure_column(database, "coverage_runs", "harness_bundle", "TEXT NOT NULL DEFAULT ''", out_error);
    if (success) {
        const bool metadata_ok =
            set_metadata_value(database, "schema_version", kProjectSchemaVersion.data(), out_error) &&
            set_metadata_value(database, "product", "zara", out_error);
        sqlite3_close(database);
        return metadata_ok;
    }
    sqlite3_close(database);
    return false;
#else
    out_error = "SQLite3 was not found when CMake configured the project.";
    return false;
#endif
}

bool ProjectStore::save_program_analysis(
    const loader::BinaryImage& image,
    const analysis::ProgramAnalysis& analysis,
    std::string& out_error
) const {
    return save_program_analysis(image, analysis, nullptr, out_error);
}

bool ProjectStore::save_program_analysis(
    const loader::BinaryImage& image,
    const analysis::ProgramAnalysis& analysis,
    const ai::AssistantOptions* assistant_options,
    std::string& out_error
) const {
    out_error.clear();

#if defined(ZARA_HAS_SQLITE)
    if (!initialize(out_error)) {
        return false;
    }

    sqlite3* database = nullptr;
    if (sqlite3_open(database_path_.string().c_str(), &database) != SQLITE_OK) {
        out_error = sqlite3_errmsg(database);
        sqlite3_close(database);
        return false;
    }

    if (!configure_database(database, out_error)) {
        sqlite3_close(database);
        return false;
    }

    sqlite3_stmt* insert_run = nullptr;
    sqlite3_stmt* insert_function = nullptr;
    sqlite3_stmt* insert_block = nullptr;
    sqlite3_stmt* insert_instruction = nullptr;
    sqlite3_stmt* insert_import = nullptr;
    sqlite3_stmt* insert_export = nullptr;
    sqlite3_stmt* insert_string = nullptr;
    sqlite3_stmt* insert_xref = nullptr;
    sqlite3_stmt* insert_call_edge = nullptr;
    sqlite3_stmt* insert_ai_insight = nullptr;
    sqlite3_stmt* insert_security_finding = nullptr;
    sqlite3_stmt* insert_rop_gadget = nullptr;
    sqlite3_stmt* insert_security_pattern = nullptr;
    sqlite3_stmt* insert_version = nullptr;

    auto cleanup = [&]() {
        finalize_statement(insert_run);
        finalize_statement(insert_function);
        finalize_statement(insert_block);
        finalize_statement(insert_instruction);
        finalize_statement(insert_import);
        finalize_statement(insert_export);
        finalize_statement(insert_string);
        finalize_statement(insert_xref);
        finalize_statement(insert_call_edge);
        finalize_statement(insert_ai_insight);
        finalize_statement(insert_security_finding);
        finalize_statement(insert_rop_gadget);
        finalize_statement(insert_security_pattern);
        finalize_statement(insert_version);
        sqlite3_close(database);
    };

    if (!exec_sql(database, "BEGIN IMMEDIATE TRANSACTION;", out_error)) {
        cleanup();
        return false;
    }

    bool success = false;
    do {
        ai::AssistantRunMetadata ai_metadata;
        const auto ai_insights = assistant_options == nullptr
                                     ? ai::Assistant::analyze_program(analysis, image.entry_point())
                                     : ai::Assistant::analyze_program(
                                           analysis,
                                           image.entry_point(),
                                           *assistant_options,
                                           &ai_metadata
                                       );
        if (assistant_options == nullptr) {
            ai_metadata.backend = "heuristic";
        }
        const auto security_report = security::Workflow::analyze_exploit_surface(image.source_path(), analysis);
        const std::string binary_hash = hash_bytes(image.raw_image());

        constexpr const char* insert_run_sql =
            "INSERT INTO analysis_runs (binary_path, binary_format, architecture, binary_size, binary_hash, base_address, entry_point, section_count, function_count, import_count, export_count, xref_count, string_count, ai_backend, ai_model, poc_scaffold) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
        constexpr const char* insert_function_sql =
            "INSERT INTO functions (run_id, name, section_name, entry_address, block_count, instruction_count, decompiled_pseudocode, analysis_summary) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
        constexpr const char* insert_block_sql =
            "INSERT INTO basic_blocks (run_id, function_entry, start_address, end_address, successors) "
            "VALUES (?, ?, ?, ?, ?);";
        constexpr const char* insert_instruction_sql =
            "INSERT INTO instructions (run_id, function_entry, block_start, address, size, kind, mnemonic, operands) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
        constexpr const char* insert_import_sql =
            "INSERT INTO imports (run_id, address, library_name, name) VALUES (?, ?, ?, ?);";
        constexpr const char* insert_export_sql =
            "INSERT INTO exports (run_id, address, name, size) VALUES (?, ?, ?, ?);";
        constexpr const char* insert_string_sql =
            "INSERT INTO strings (run_id, start_address, end_address, value) VALUES (?, ?, ?, ?);";
        constexpr const char* insert_xref_sql =
            "INSERT INTO xrefs (run_id, kind, from_address, to_address, label) VALUES (?, ?, ?, ?, ?);";
        constexpr const char* insert_call_edge_sql =
            "INSERT INTO call_edges (run_id, caller_entry, call_site, callee_entry, callee_name, is_import) VALUES (?, ?, ?, ?, ?, ?);";
        constexpr const char* insert_ai_insight_sql =
            "INSERT INTO ai_function_insights (run_id, function_entry, current_name, suggested_name, summary, hints, patterns, vulnerability_hints) VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
        constexpr const char* insert_security_finding_sql =
            "INSERT INTO security_findings (run_id, function_entry, function_name, category, severity, title, detail) VALUES (?, ?, ?, ?, ?, ?, ?);";
        constexpr const char* insert_rop_gadget_sql =
            "INSERT INTO rop_gadgets (run_id, function_entry, function_name, address, sequence, instruction_count) VALUES (?, ?, ?, ?, ?, ?);";
        constexpr const char* insert_security_pattern_sql =
            "INSERT INTO security_patterns (run_id, function_entry, function_name, category, severity, title, detail, poc_notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
        constexpr const char* insert_version_sql =
            "INSERT INTO project_versions (run_id, kind, title, detail, payload) VALUES (?, ?, ?, ?, ?);";

        if (!prepare_statement(database, insert_run_sql, insert_run, out_error) ||
            !prepare_statement(database, insert_function_sql, insert_function, out_error) ||
            !prepare_statement(database, insert_block_sql, insert_block, out_error) ||
            !prepare_statement(database, insert_instruction_sql, insert_instruction, out_error) ||
            !prepare_statement(database, insert_import_sql, insert_import, out_error) ||
            !prepare_statement(database, insert_export_sql, insert_export, out_error) ||
            !prepare_statement(database, insert_string_sql, insert_string, out_error) ||
            !prepare_statement(database, insert_xref_sql, insert_xref, out_error) ||
            !prepare_statement(database, insert_call_edge_sql, insert_call_edge, out_error) ||
            !prepare_statement(database, insert_ai_insight_sql, insert_ai_insight, out_error) ||
            !prepare_statement(database, insert_security_finding_sql, insert_security_finding, out_error) ||
            !prepare_statement(database, insert_rop_gadget_sql, insert_rop_gadget, out_error) ||
            !prepare_statement(database, insert_security_pattern_sql, insert_security_pattern, out_error) ||
            !prepare_statement(database, insert_version_sql, insert_version, out_error)) {
            break;
        }

        sqlite3_bind_text(insert_run, 1, image.source_path().string().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_run, 2, loader::to_string(image.format()).data(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_run, 3, loader::to_string(image.architecture()).data(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(insert_run, 4, static_cast<sqlite3_int64>(image.raw_image().size()));
        sqlite3_bind_text(insert_run, 5, binary_hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(insert_run, 6, static_cast<sqlite3_int64>(image.base_address()));
        if (image.entry_point().has_value()) {
            sqlite3_bind_int64(insert_run, 7, static_cast<sqlite3_int64>(*image.entry_point()));
        } else {
            sqlite3_bind_null(insert_run, 7);
        }
        sqlite3_bind_int(insert_run, 8, static_cast<int>(image.sections().size()));
        sqlite3_bind_int(insert_run, 9, static_cast<int>(analysis.functions.size()));
        sqlite3_bind_int(insert_run, 10, static_cast<int>(image.imports().size()));
        sqlite3_bind_int(insert_run, 11, static_cast<int>(image.exports().size()));
        sqlite3_bind_int(insert_run, 12, static_cast<int>(analysis.xrefs.size()));
        sqlite3_bind_int(insert_run, 13, static_cast<int>(analysis.strings.size()));
        sqlite3_bind_text(insert_run, 14, ai_metadata.backend.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_run, 15, ai_metadata.model.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_run, 16, security_report.poc_scaffold.c_str(), -1, SQLITE_TRANSIENT);
        if (!step_statement(database, insert_run, out_error)) {
            break;
        }

        const sqlite3_int64 run_id = sqlite3_last_insert_rowid(database);

        std::optional<sqlite3_int64> previous_run_id;
        {
            sqlite3_stmt* select_previous_run = nullptr;
            if (!prepare_statement(
                    database,
                    "SELECT id FROM analysis_runs WHERE id < ? ORDER BY id DESC LIMIT 1;",
                    select_previous_run,
                    out_error
                )) {
                break;
            }

            sqlite3_bind_int64(select_previous_run, 1, run_id);
            if (sqlite3_step(select_previous_run) == SQLITE_ROW) {
                previous_run_id = sqlite3_column_int64(select_previous_run, 0);
            }
            finalize_statement(select_previous_run);
        }
        if (!out_error.empty()) {
            break;
        }

        if (previous_run_id.has_value()) {
            sqlite3_stmt* copy_comments = nullptr;
            sqlite3_stmt* copy_type_annotations = nullptr;
            sqlite3_stmt* copy_symbol_renames = nullptr;
            if (!prepare_statement(
                    database,
                    "INSERT INTO user_comments (run_id, function_entry, address, scope, body, created_at, updated_at) "
                    "SELECT ?, function_entry, address, scope, body, created_at, updated_at "
                    "FROM user_comments WHERE run_id = ?;",
                    copy_comments,
                    out_error
                ) ||
                !prepare_statement(
                    database,
                    "INSERT INTO user_type_annotations (run_id, function_entry, target_kind, symbol_name, type_name, note, created_at, updated_at) "
                    "SELECT ?, function_entry, target_kind, symbol_name, type_name, note, created_at, updated_at "
                    "FROM user_type_annotations WHERE run_id = ?;",
                    copy_type_annotations,
                    out_error
                ) ||
                !prepare_statement(
                    database,
                    "INSERT INTO user_symbol_renames (run_id, function_entry, address, target_kind, original_name, renamed_name, created_at, updated_at) "
                    "SELECT ?, function_entry, address, target_kind, original_name, renamed_name, created_at, updated_at "
                    "FROM user_symbol_renames WHERE run_id = ?;",
                    copy_symbol_renames,
                    out_error
                )) {
                finalize_statement(copy_comments);
                finalize_statement(copy_type_annotations);
                finalize_statement(copy_symbol_renames);
                break;
            }

            sqlite3_bind_int64(copy_comments, 1, run_id);
            sqlite3_bind_int64(copy_comments, 2, *previous_run_id);
            const bool comments_ok = step_statement(database, copy_comments, out_error);
            finalize_statement(copy_comments);
            if (!comments_ok) {
                finalize_statement(copy_type_annotations);
                break;
            }

            sqlite3_bind_int64(copy_type_annotations, 1, run_id);
            sqlite3_bind_int64(copy_type_annotations, 2, *previous_run_id);
            const bool types_ok = step_statement(database, copy_type_annotations, out_error);
            finalize_statement(copy_type_annotations);
            if (!types_ok) {
                finalize_statement(copy_symbol_renames);
                break;
            }

            sqlite3_bind_int64(copy_symbol_renames, 1, run_id);
            sqlite3_bind_int64(copy_symbol_renames, 2, *previous_run_id);
            const bool renames_ok = step_statement(database, copy_symbol_renames, out_error);
            finalize_statement(copy_symbol_renames);
            if (!renames_ok) {
                break;
            }
        }

        for (const auto& function : analysis.functions) {
            int instruction_count = 0;
            for (const auto& block : function.graph.blocks()) {
                instruction_count += static_cast<int>(block.instructions.size());
            }

            sqlite3_bind_int64(insert_function, 1, run_id);
            sqlite3_bind_text(insert_function, 2, function.name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(insert_function, 3, function.section_name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(insert_function, 4, static_cast<sqlite3_int64>(function.entry_address));
            sqlite3_bind_int(insert_function, 5, static_cast<int>(function.graph.blocks().size()));
            sqlite3_bind_int(insert_function, 6, instruction_count);
            sqlite3_bind_text(insert_function, 7, function.decompiled.pseudocode.c_str(), -1, SQLITE_TRANSIENT);
            const std::string analysis_summary = render_function_summary(function);
            sqlite3_bind_text(insert_function, 8, analysis_summary.c_str(), -1, SQLITE_TRANSIENT);
            if (!step_statement(database, insert_function, out_error)) {
                break;
            }

            for (const auto& block : function.graph.blocks()) {
                const std::string successors = join_successors(block.successors);

                sqlite3_bind_int64(insert_block, 1, run_id);
                sqlite3_bind_int64(insert_block, 2, static_cast<sqlite3_int64>(function.entry_address));
                sqlite3_bind_int64(insert_block, 3, static_cast<sqlite3_int64>(block.start_address));
                sqlite3_bind_int64(insert_block, 4, static_cast<sqlite3_int64>(block.end_address));
                sqlite3_bind_text(insert_block, 5, successors.c_str(), -1, SQLITE_TRANSIENT);
                if (!step_statement(database, insert_block, out_error)) {
                    break;
                }

                for (const auto& instruction : block.instructions) {
                    sqlite3_bind_int64(insert_instruction, 1, run_id);
                    sqlite3_bind_int64(insert_instruction, 2, static_cast<sqlite3_int64>(function.entry_address));
                    sqlite3_bind_int64(insert_instruction, 3, static_cast<sqlite3_int64>(block.start_address));
                    sqlite3_bind_int64(insert_instruction, 4, static_cast<sqlite3_int64>(instruction.address));
                    sqlite3_bind_int(insert_instruction, 5, instruction.size);
                    sqlite3_bind_text(insert_instruction, 6, to_string(instruction.kind).data(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(insert_instruction, 7, instruction.mnemonic.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(insert_instruction, 8, instruction.operands.c_str(), -1, SQLITE_TRANSIENT);
                    if (!step_statement(database, insert_instruction, out_error)) {
                        break;
                    }
                }

                if (!out_error.empty()) {
                    break;
                }
            }

            if (!out_error.empty()) {
                break;
            }
        }

        if (!out_error.empty()) {
            break;
        }

        for (const auto& imported : image.imports()) {
            sqlite3_bind_int64(insert_import, 1, run_id);
            sqlite3_bind_int64(insert_import, 2, static_cast<sqlite3_int64>(imported.address));
            sqlite3_bind_text(insert_import, 3, imported.library.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(insert_import, 4, imported.name.c_str(), -1, SQLITE_TRANSIENT);
            if (!step_statement(database, insert_import, out_error)) {
                break;
            }
        }
        if (!out_error.empty()) {
            break;
        }

        for (const auto& exported : image.exports()) {
            sqlite3_bind_int64(insert_export, 1, run_id);
            sqlite3_bind_int64(insert_export, 2, static_cast<sqlite3_int64>(exported.address));
            sqlite3_bind_text(insert_export, 3, exported.name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(insert_export, 4, static_cast<sqlite3_int64>(exported.size));
            if (!step_statement(database, insert_export, out_error)) {
                break;
            }
        }
        if (!out_error.empty()) {
            break;
        }

        for (const auto& extracted : analysis.strings) {
            sqlite3_bind_int64(insert_string, 1, run_id);
            sqlite3_bind_int64(insert_string, 2, static_cast<sqlite3_int64>(extracted.start_address));
            sqlite3_bind_int64(insert_string, 3, static_cast<sqlite3_int64>(extracted.end_address));
            sqlite3_bind_text(insert_string, 4, extracted.value.c_str(), -1, SQLITE_TRANSIENT);
            if (!step_statement(database, insert_string, out_error)) {
                break;
            }
        }
        if (!out_error.empty()) {
            break;
        }

        for (const auto& reference : analysis.xrefs) {
            sqlite3_bind_int64(insert_xref, 1, run_id);
            sqlite3_bind_text(insert_xref, 2, xrefs::to_string(reference.kind).data(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(insert_xref, 3, static_cast<sqlite3_int64>(reference.from_address));
            sqlite3_bind_int64(insert_xref, 4, static_cast<sqlite3_int64>(reference.to_address));
            sqlite3_bind_text(insert_xref, 5, reference.label.c_str(), -1, SQLITE_TRANSIENT);
            if (!step_statement(database, insert_xref, out_error)) {
                break;
            }
        }
        if (!out_error.empty()) {
            break;
        }

        for (const auto& edge : analysis.call_graph) {
            sqlite3_bind_int64(insert_call_edge, 1, run_id);
            sqlite3_bind_int64(insert_call_edge, 2, static_cast<sqlite3_int64>(edge.caller_entry));
            sqlite3_bind_int64(insert_call_edge, 3, static_cast<sqlite3_int64>(edge.call_site));
            if (edge.callee_entry.has_value()) {
                sqlite3_bind_int64(insert_call_edge, 4, static_cast<sqlite3_int64>(*edge.callee_entry));
            } else {
                sqlite3_bind_null(insert_call_edge, 4);
            }
            sqlite3_bind_text(insert_call_edge, 5, edge.callee_name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(insert_call_edge, 6, edge.is_import ? 1 : 0);
            if (!step_statement(database, insert_call_edge, out_error)) {
                break;
            }
        }
        if (!out_error.empty()) {
            break;
        }

        for (const auto& insight : ai_insights) {
            const std::string hints = join_lines(insight.hints);
            const std::string patterns = join_ai_patterns(insight.patterns);
            const std::string vulnerability_hints = join_ai_vulnerability_hints(insight.vulnerability_hints);
            sqlite3_bind_int64(insert_ai_insight, 1, run_id);
            sqlite3_bind_int64(insert_ai_insight, 2, static_cast<sqlite3_int64>(insight.entry_address));
            sqlite3_bind_text(insert_ai_insight, 3, insight.current_name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(insert_ai_insight, 4, insight.suggested_name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(insert_ai_insight, 5, insight.summary.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(insert_ai_insight, 6, hints.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(insert_ai_insight, 7, patterns.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(insert_ai_insight, 8, vulnerability_hints.c_str(), -1, SQLITE_TRANSIENT);
            if (!step_statement(database, insert_ai_insight, out_error)) {
                break;
            }
        }
        if (!out_error.empty()) {
            break;
        }

        for (const auto& finding : security_report.findings) {
            sqlite3_bind_int64(insert_security_finding, 1, run_id);
            sqlite3_bind_int64(insert_security_finding, 2, static_cast<sqlite3_int64>(finding.function_entry));
            sqlite3_bind_text(insert_security_finding, 3, finding.function_name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(insert_security_finding, 4, finding.category.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(
                insert_security_finding,
                5,
                security::to_string(finding.severity).data(),
                -1,
                SQLITE_TRANSIENT
            );
            sqlite3_bind_text(insert_security_finding, 6, finding.title.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(insert_security_finding, 7, finding.detail.c_str(), -1, SQLITE_TRANSIENT);
            if (!step_statement(database, insert_security_finding, out_error)) {
                break;
            }
        }
        if (!out_error.empty()) {
            break;
        }

        for (const auto& gadget : security_report.gadgets) {
            sqlite3_bind_int64(insert_rop_gadget, 1, run_id);
            sqlite3_bind_int64(insert_rop_gadget, 2, static_cast<sqlite3_int64>(gadget.function_entry));
            sqlite3_bind_text(insert_rop_gadget, 3, gadget.function_name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(insert_rop_gadget, 4, static_cast<sqlite3_int64>(gadget.address));
            sqlite3_bind_text(insert_rop_gadget, 5, gadget.sequence.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(insert_rop_gadget, 6, static_cast<int>(gadget.instruction_count));
            if (!step_statement(database, insert_rop_gadget, out_error)) {
                break;
            }
        }
        if (!out_error.empty()) {
            break;
        }

        for (const auto& pattern : security_report.patterns) {
            const std::string poc_notes = join_poc_notes(pattern.poc_notes);
            sqlite3_bind_int64(insert_security_pattern, 1, run_id);
            sqlite3_bind_int64(insert_security_pattern, 2, static_cast<sqlite3_int64>(pattern.function_entry));
            sqlite3_bind_text(insert_security_pattern, 3, pattern.function_name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(insert_security_pattern, 4, pattern.category.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(
                insert_security_pattern,
                5,
                security::to_string(pattern.severity).data(),
                -1,
                SQLITE_TRANSIENT
            );
            sqlite3_bind_text(insert_security_pattern, 6, pattern.title.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(insert_security_pattern, 7, pattern.detail.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(insert_security_pattern, 8, poc_notes.c_str(), -1, SQLITE_TRANSIENT);
            if (!step_statement(database, insert_security_pattern, out_error)) {
                break;
            }
        }
        if (!out_error.empty()) {
            break;
        }

        {
            std::ostringstream detail;
            detail << "Persisted analysis run for " << image.source_path().filename().string() << " ("
                   << analysis.functions.size() << " functions, " << analysis.call_graph.size() << " call edges, "
                   << analysis.xrefs.size() << " xrefs).";
            std::ostringstream payload;
            payload << "format=" << loader::to_string(image.format()) << '\n'
                    << "arch=" << loader::to_string(image.architecture()) << '\n'
                    << "binary=" << image.source_path().string() << '\n'
                    << "functions=" << analysis.functions.size() << '\n'
                    << "imports=" << image.imports().size() << '\n'
                    << "exports=" << image.exports().size() << '\n'
                    << "comments_carried=" << (previous_run_id.has_value() ? "yes" : "no");
            if (!insert_version_event(
                    database,
                    insert_version,
                    run_id,
                    "analysis",
                    "Persisted analysis run",
                    detail.str(),
                    payload.str(),
                    out_error
                )) {
                break;
            }
        }

        if (!exec_sql(database, "COMMIT;", out_error)) {
            break;
        }

        success = true;
    } while (false);

    if (!success) {
        std::string rollback_error;
        exec_sql(database, "ROLLBACK;", rollback_error);
    }

    cleanup();
    return success;
#else
    (void)image;
    (void)analysis;
    out_error = "SQLite3 backend is unavailable; program analysis was not persisted.";
    return false;
#endif
}

std::optional<CachedAnalysisRun>
ProjectStore::find_cached_analysis_run(const loader::BinaryImage& image, std::string& out_error) const {
    out_error.clear();

#if defined(ZARA_HAS_SQLITE)
    if (!initialize(out_error)) {
        return std::nullopt;
    }

    sqlite3* database = nullptr;
    if (sqlite3_open(database_path_.string().c_str(), &database) != SQLITE_OK) {
        out_error = database == nullptr ? "Failed to open SQLite database." : sqlite3_errmsg(database);
        sqlite3_close(database);
        return std::nullopt;
    }

    if (!configure_database(database, out_error)) {
        sqlite3_close(database);
        return std::nullopt;
    }

    sqlite3_stmt* statement = nullptr;
    const bool prepared = prepare_statement(
        database,
        "SELECT id, binary_hash, binary_size "
        "FROM analysis_runs "
        "WHERE binary_hash = ? AND binary_size = ? "
        "ORDER BY id DESC LIMIT 1;",
        statement,
        out_error
    );
    if (!prepared) {
        sqlite3_close(database);
        return std::nullopt;
    }

    const std::string binary_hash = hash_bytes(image.raw_image());
    sqlite3_bind_text(statement, 1, binary_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 2, static_cast<sqlite3_int64>(image.raw_image().size()));

    std::optional<CachedAnalysisRun> match;
    if (sqlite3_step(statement) == SQLITE_ROW) {
        const unsigned char* stored_hash = sqlite3_column_text(statement, 1);
        match = CachedAnalysisRun{
            .run_id = sqlite3_column_int(statement, 0),
            .binary_hash = stored_hash == nullptr ? std::string{} : reinterpret_cast<const char*>(stored_hash),
            .binary_size = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 2)),
        };
    }
    finalize_statement(statement);
    sqlite3_close(database);
    return match;
#else
    (void)image;
    out_error = "SQLite3 was not found when CMake configured the project.";
    return std::nullopt;
#endif
}

const std::filesystem::path& ProjectStore::path() const noexcept {
    return database_path_;
}

}  // namespace zara::database
