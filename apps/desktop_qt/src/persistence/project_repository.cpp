#include "zara/desktop_qt/persistence/project_repository.hpp"

#include "zara/database/project_store.hpp"

#include <sqlite3.h>

#include <sstream>
#include <optional>
#include <string_view>

namespace zara::desktop_qt::persistence {

namespace {

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

std::string column_text(sqlite3_stmt* statement, int column_index) {
    const unsigned char* value = sqlite3_column_text(statement, column_index);
    if (value == nullptr) {
        return {};
    }
    return reinterpret_cast<const char*>(value);
}

std::optional<std::uint64_t> column_optional_uint64(sqlite3_stmt* statement, int column_index) {
    if (sqlite3_column_type(statement, column_index) == SQLITE_NULL) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(sqlite3_column_int64(statement, column_index));
}

bool step_row(sqlite3* database, sqlite3_stmt* statement, std::string& out_error) {
    const int step_result = sqlite3_step(statement);
    if (step_result == SQLITE_ROW) {
        return true;
    }
    if (step_result == SQLITE_DONE) {
        return false;
    }

    out_error = sqlite3_errmsg(database);
    return false;
}

bool step_done(sqlite3* database, sqlite3_stmt* statement, std::string& out_error) {
    const int step_result = sqlite3_step(statement);
    if (step_result == SQLITE_DONE) {
        sqlite3_reset(statement);
        sqlite3_clear_bindings(statement);
        return true;
    }

    out_error = sqlite3_errmsg(database);
    sqlite3_reset(statement);
    sqlite3_clear_bindings(statement);
    return false;
}

bool exec_sql(sqlite3* database, const char* sql, std::string& out_error) {
    char* error_message = nullptr;
    const int exec_result = sqlite3_exec(database, sql, nullptr, nullptr, &error_message);
    if (exec_result == SQLITE_OK) {
        return true;
    }

    out_error = error_message == nullptr ? "SQLite execution failed." : error_message;
    sqlite3_free(error_message);
    return false;
}

bool configure_database(sqlite3* database, std::string& out_error) {
    return exec_sql(database, "PRAGMA foreign_keys = ON;", out_error) &&
           exec_sql(database, "PRAGMA busy_timeout = 5000;", out_error) &&
           exec_sql(database, "PRAGMA journal_mode = WAL;", out_error) &&
           exec_sql(database, "PRAGMA synchronous = NORMAL;", out_error);
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

std::vector<std::uint64_t> parse_successors(const std::string& text) {
    std::vector<std::uint64_t> values;
    std::stringstream stream(text);
    std::string token;
    while (std::getline(stream, token, ',')) {
        if (token.empty()) {
            continue;
        }
        values.push_back(static_cast<std::uint64_t>(std::stoull(token)));
    }
    return values;
}

std::string format_address(const std::uint64_t address) {
    std::ostringstream stream;
    stream << "0x" << std::uppercase << std::hex << address;
    return stream.str();
}

}  // namespace

ProjectRepository::ProjectRepository(std::filesystem::path database_path)
    : database_path_(std::move(database_path)) {}

ProjectRepository::~ProjectRepository() {
    close();
}

bool ProjectRepository::open(std::string& out_error) {
    out_error.clear();
    close();

    zara::database::ProjectStore store(database_path_);
    if (!store.initialize(out_error)) {
        return false;
    }

    if (sqlite3_open_v2(
            database_path_.string().c_str(),
            &database_,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
            nullptr
        ) != SQLITE_OK) {
        out_error = database_ == nullptr ? "Failed to open SQLite database." : sqlite3_errmsg(database_);
        close();
        return false;
    }

    if (!configure_database(database_, out_error)) {
        close();
        return false;
    }

    return true;
}

void ProjectRepository::close() {
    if (database_ != nullptr) {
        sqlite3_close(database_);
        database_ = nullptr;
    }
}

std::optional<RunOverview> ProjectRepository::load_latest_run(std::string& out_error) const {
    if (!require_open(out_error)) {
        return std::nullopt;
    }

    Statement statement(
        database_,
        "SELECT id, binary_path, binary_format, architecture, base_address, entry_point, section_count, "
        "function_count, import_count, export_count, xref_count, string_count, poc_scaffold "
        "FROM analysis_runs ORDER BY id DESC LIMIT 1",
        out_error
    );
    if (!statement.valid()) {
        return std::nullopt;
    }

    if (!step_row(database_, statement.get(), out_error)) {
        return std::nullopt;
    }

    RunOverview run;
    run.run_id = sqlite3_column_int(statement.get(), 0);
    run.binary_path = column_text(statement.get(), 1);
    run.binary_format = column_text(statement.get(), 2);
    run.architecture = column_text(statement.get(), 3);
    run.base_address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 4));
    run.entry_point = column_optional_uint64(statement.get(), 5);
    run.section_count = sqlite3_column_int(statement.get(), 6);
    run.function_count = sqlite3_column_int(statement.get(), 7);
    run.import_count = sqlite3_column_int(statement.get(), 8);
    run.export_count = sqlite3_column_int(statement.get(), 9);
    run.xref_count = sqlite3_column_int(statement.get(), 10);
    run.string_count = sqlite3_column_int(statement.get(), 11);
    run.poc_scaffold = column_text(statement.get(), 12);
    return run;
}

int ProjectRepository::load_run_count(std::string& out_error) const {
    if (!require_open(out_error)) {
        return 0;
    }

    Statement statement(database_, "SELECT COUNT(*) FROM analysis_runs", out_error);
    if (!statement.valid()) {
        return 0;
    }
    if (!step_row(database_, statement.get(), out_error)) {
        return 0;
    }
    return sqlite3_column_int(statement.get(), 0);
}

std::vector<FunctionSummary> ProjectRepository::load_functions(int run_id, std::string& out_error) const {
    std::vector<FunctionSummary> functions;
    if (!require_open(out_error)) {
        return functions;
    }

    Statement statement(
        database_,
        "SELECT COALESCE(sr.renamed_name, f.name), f.section_name, f.entry_address, "
        "COALESCE(bounds.min_start, f.entry_address), COALESCE(bounds.max_end, f.entry_address), "
        "f.block_count, f.instruction_count "
        "FROM functions f "
        "LEFT JOIN ("
        "    SELECT run_id, function_entry, MIN(start_address) AS min_start, MAX(end_address) AS max_end "
        "    FROM basic_blocks WHERE run_id = ? GROUP BY run_id, function_entry"
        ") bounds ON bounds.run_id = f.run_id AND bounds.function_entry = f.entry_address "
        "LEFT JOIN user_symbol_renames sr ON sr.run_id = f.run_id AND sr.target_kind = 'function' AND sr.address = f.entry_address "
        "WHERE f.run_id = ? ORDER BY f.entry_address",
        out_error
    );
    if (!statement.valid()) {
        return functions;
    }

    sqlite3_bind_int(statement.get(), 1, run_id);
    sqlite3_bind_int(statement.get(), 2, run_id);
    while (step_row(database_, statement.get(), out_error)) {
        FunctionSummary function;
        function.name = column_text(statement.get(), 0);
        function.section_name = column_text(statement.get(), 1);
        function.entry_address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 2));
        function.start_address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 3));
        function.end_address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 4));
        function.block_count = sqlite3_column_int(statement.get(), 5);
        function.instruction_count = sqlite3_column_int(statement.get(), 6);
        functions.push_back(std::move(function));
    }
    if (!out_error.empty()) {
        functions.clear();
    }
    return functions;
}

std::vector<CallRecord> ProjectRepository::load_call_edges(int run_id, std::string& out_error) const {
    std::vector<CallRecord> calls;
    if (!require_open(out_error)) {
        return calls;
    }

    Statement statement(
        database_,
        "SELECT c.caller_entry, c.call_site, c.callee_entry, "
        "CASE WHEN c.is_import = 0 THEN COALESCE(sr.renamed_name, c.callee_name) ELSE c.callee_name END, "
        "c.is_import "
        "FROM call_edges c "
        "LEFT JOIN user_symbol_renames sr ON sr.run_id = c.run_id AND sr.target_kind = 'function' AND sr.address = c.callee_entry "
        "WHERE c.run_id = ? ORDER BY c.caller_entry, c.call_site",
        out_error
    );
    if (!statement.valid()) {
        return calls;
    }

    sqlite3_bind_int(statement.get(), 1, run_id);
    while (step_row(database_, statement.get(), out_error)) {
        CallRecord call;
        call.caller_entry = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
        call.call_site = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 1));
        call.callee_entry = column_optional_uint64(statement.get(), 2);
        call.callee_name = column_text(statement.get(), 3);
        call.is_import = sqlite3_column_int(statement.get(), 4) != 0;
        calls.push_back(std::move(call));
    }
    if (!out_error.empty()) {
        calls.clear();
    }
    return calls;
}

std::vector<ImportRecord> ProjectRepository::load_imports(int run_id, std::string& out_error) const {
    std::vector<ImportRecord> imports;
    if (!require_open(out_error)) {
        return imports;
    }

    Statement statement(
        database_,
        "SELECT address, library_name, name FROM imports WHERE run_id = ? ORDER BY address",
        out_error
    );
    if (!statement.valid()) {
        return imports;
    }

    sqlite3_bind_int(statement.get(), 1, run_id);
    while (step_row(database_, statement.get(), out_error)) {
        ImportRecord record;
        record.address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
        record.library_name = column_text(statement.get(), 1);
        record.name = column_text(statement.get(), 2);
        imports.push_back(std::move(record));
    }
    if (!out_error.empty()) {
        imports.clear();
    }
    return imports;
}

std::vector<ExportRecord> ProjectRepository::load_exports(int run_id, std::string& out_error) const {
    std::vector<ExportRecord> exports;
    if (!require_open(out_error)) {
        return exports;
    }

    Statement statement(
        database_,
        "SELECT address, name, size FROM exports WHERE run_id = ? ORDER BY address",
        out_error
    );
    if (!statement.valid()) {
        return exports;
    }

    sqlite3_bind_int(statement.get(), 1, run_id);
    while (step_row(database_, statement.get(), out_error)) {
        ExportRecord record;
        record.address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
        record.name = column_text(statement.get(), 1);
        record.size = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 2));
        exports.push_back(std::move(record));
    }
    if (!out_error.empty()) {
        exports.clear();
    }
    return exports;
}

std::vector<XrefRecord> ProjectRepository::load_xrefs(int run_id, std::string& out_error) const {
    std::vector<XrefRecord> xrefs;
    if (!require_open(out_error)) {
        return xrefs;
    }

    Statement statement(
        database_,
        "SELECT kind, from_address, to_address, label FROM xrefs WHERE run_id = ? ORDER BY from_address, to_address",
        out_error
    );
    if (!statement.valid()) {
        return xrefs;
    }

    sqlite3_bind_int(statement.get(), 1, run_id);
    while (step_row(database_, statement.get(), out_error)) {
        XrefRecord record;
        record.kind = column_text(statement.get(), 0);
        record.from_address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 1));
        record.to_address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 2));
        record.label = column_text(statement.get(), 3);
        xrefs.push_back(std::move(record));
    }
    if (!out_error.empty()) {
        xrefs.clear();
    }
    return xrefs;
}

std::vector<StringRecord> ProjectRepository::load_strings(int run_id, std::string& out_error) const {
    std::vector<StringRecord> strings;
    if (!require_open(out_error)) {
        return strings;
    }

    Statement statement(
        database_,
        "SELECT start_address, value FROM strings WHERE run_id = ? ORDER BY start_address",
        out_error
    );
    if (!statement.valid()) {
        return strings;
    }

    sqlite3_bind_int(statement.get(), 1, run_id);
    while (step_row(database_, statement.get(), out_error)) {
        StringRecord record;
        record.address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
        record.value = column_text(statement.get(), 1);
        strings.push_back(std::move(record));
    }
    if (!out_error.empty()) {
        strings.clear();
    }
    return strings;
}

std::vector<CommentRecord> ProjectRepository::load_comments(int run_id, std::string& out_error) const {
    std::vector<CommentRecord> comments;
    if (!require_open(out_error)) {
        return comments;
    }

    Statement statement(
        database_,
        "SELECT id, function_entry, address, scope, body, created_at, updated_at "
        "FROM user_comments WHERE run_id = ? ORDER BY address, id",
        out_error
    );
    if (!statement.valid()) {
        return comments;
    }

    sqlite3_bind_int(statement.get(), 1, run_id);
    while (step_row(database_, statement.get(), out_error)) {
        CommentRecord record;
        record.id = sqlite3_column_int(statement.get(), 0);
        record.function_entry = column_optional_uint64(statement.get(), 1);
        record.address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 2));
        record.scope = column_text(statement.get(), 3);
        record.body = column_text(statement.get(), 4);
        record.created_at = column_text(statement.get(), 5);
        record.updated_at = column_text(statement.get(), 6);
        comments.push_back(std::move(record));
    }
    if (!out_error.empty()) {
        comments.clear();
    }
    return comments;
}

std::vector<TypeAnnotationRecord> ProjectRepository::load_type_annotations(int run_id, std::string& out_error) const {
    std::vector<TypeAnnotationRecord> annotations;
    if (!require_open(out_error)) {
        return annotations;
    }

    Statement statement(
        database_,
        "SELECT id, function_entry, target_kind, symbol_name, type_name, note, created_at, updated_at "
        "FROM user_type_annotations WHERE run_id = ? ORDER BY symbol_name, id",
        out_error
    );
    if (!statement.valid()) {
        return annotations;
    }

    sqlite3_bind_int(statement.get(), 1, run_id);
    while (step_row(database_, statement.get(), out_error)) {
        TypeAnnotationRecord record;
        record.id = sqlite3_column_int(statement.get(), 0);
        record.function_entry = column_optional_uint64(statement.get(), 1);
        record.target_kind = column_text(statement.get(), 2);
        record.symbol_name = column_text(statement.get(), 3);
        record.type_name = column_text(statement.get(), 4);
        record.note = column_text(statement.get(), 5);
        record.created_at = column_text(statement.get(), 6);
        record.updated_at = column_text(statement.get(), 7);
        annotations.push_back(std::move(record));
    }
    if (!out_error.empty()) {
        annotations.clear();
    }
    return annotations;
}

std::vector<VersionRecord> ProjectRepository::load_versions(std::string& out_error) const {
    std::vector<VersionRecord> versions;
    if (!require_open(out_error)) {
        return versions;
    }

    Statement statement(
        database_,
        "SELECT id, run_id, kind, title, detail, payload, created_at "
        "FROM project_versions ORDER BY id DESC",
        out_error
    );
    if (!statement.valid()) {
        return versions;
    }

    while (step_row(database_, statement.get(), out_error)) {
        VersionRecord record;
        record.id = sqlite3_column_int(statement.get(), 0);
        if (sqlite3_column_type(statement.get(), 1) != SQLITE_NULL) {
            record.run_id = sqlite3_column_int(statement.get(), 1);
        }
        record.kind = column_text(statement.get(), 2);
        record.title = column_text(statement.get(), 3);
        record.detail = column_text(statement.get(), 4);
        record.payload = column_text(statement.get(), 5);
        record.created_at = column_text(statement.get(), 6);
        versions.push_back(std::move(record));
    }
    if (!out_error.empty()) {
        versions.clear();
    }
    return versions;
}

std::optional<CoverageOverview> ProjectRepository::load_latest_coverage(int run_id, std::string& out_error) const {
    if (!require_open(out_error)) {
        return std::nullopt;
    }

    CoverageOverview coverage;
    {
        Statement statement(
            database_,
            "SELECT id, input_label, crash_address, crash_summary, crash_hints, mutation_hooks, harness_bundle, created_at "
            "FROM coverage_runs WHERE run_id = ? ORDER BY id DESC LIMIT 1",
            out_error
        );
        if (!statement.valid()) {
            return std::nullopt;
        }

        sqlite3_bind_int(statement.get(), 1, run_id);
        if (!step_row(database_, statement.get(), out_error)) {
            return std::nullopt;
        }

        coverage.coverage_run_id = sqlite3_column_int(statement.get(), 0);
        coverage.input_label = column_text(statement.get(), 1);
        coverage.crash_address = column_optional_uint64(statement.get(), 2);
        coverage.crash_summary = column_text(statement.get(), 3);
        coverage.crash_hints = column_text(statement.get(), 4);
        coverage.mutation_hooks = column_text(statement.get(), 5);
        coverage.harness_bundle = column_text(statement.get(), 6);
        coverage.imported_at = column_text(statement.get(), 7);
    }

    {
        Statement statement(
            database_,
            "SELECT cf.function_entry, COALESCE(sr.renamed_name, cf.function_name), cf.hit_count, "
            "cf.instruction_count, cf.coverage_ratio, cf.contains_crash_address "
            "FROM coverage_functions cf "
            "LEFT JOIN coverage_runs cr ON cr.id = cf.coverage_run_id "
            "LEFT JOIN user_symbol_renames sr ON sr.run_id = cr.run_id AND sr.target_kind = 'function' AND sr.address = cf.function_entry "
            "WHERE cf.coverage_run_id = ? "
            "ORDER BY cf.contains_crash_address DESC, cf.coverage_ratio DESC, cf.hit_count DESC, cf.function_entry ASC",
            out_error
        );
        if (!statement.valid()) {
            return std::nullopt;
        }

        sqlite3_bind_int(statement.get(), 1, coverage.coverage_run_id);
        while (step_row(database_, statement.get(), out_error)) {
            CoverageFunctionRecord record;
            record.function_entry = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
            record.function_name = column_text(statement.get(), 1);
            record.hit_count = static_cast<std::size_t>(sqlite3_column_int64(statement.get(), 2));
            record.instruction_count = static_cast<std::size_t>(sqlite3_column_int64(statement.get(), 3));
            record.coverage_ratio = sqlite3_column_double(statement.get(), 4);
            record.contains_crash_address = sqlite3_column_int(statement.get(), 5) != 0;
            coverage.functions.push_back(std::move(record));
        }
        if (!out_error.empty()) {
            return std::nullopt;
        }
    }

    return coverage;
}

std::optional<FunctionDetails>
ProjectRepository::load_function_details(int run_id, std::uint64_t function_entry, std::string& out_error) const {
    if (!require_open(out_error)) {
        return std::nullopt;
    }

    FunctionDetails details;

    {
        Statement statement(
            database_,
            "SELECT COALESCE(sr.renamed_name, f.name), f.section_name, f.entry_address, f.block_count, "
            "f.instruction_count, f.decompiled_pseudocode, f.analysis_summary "
            "FROM functions f "
            "LEFT JOIN user_symbol_renames sr ON sr.run_id = f.run_id AND sr.target_kind = 'function' AND sr.address = f.entry_address "
            "WHERE f.run_id = ? AND f.entry_address = ? LIMIT 1",
            out_error
        );
        if (!statement.valid()) {
            return std::nullopt;
        }

        sqlite3_bind_int(statement.get(), 1, run_id);
        sqlite3_bind_int64(statement.get(), 2, static_cast<sqlite3_int64>(function_entry));
        if (!step_row(database_, statement.get(), out_error)) {
            return std::nullopt;
        }

        details.summary.name = column_text(statement.get(), 0);
        details.summary.section_name = column_text(statement.get(), 1);
        details.summary.entry_address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 2));
        details.summary.block_count = sqlite3_column_int(statement.get(), 3);
        details.summary.instruction_count = sqlite3_column_int(statement.get(), 4);
        details.summary.decompiled_pseudocode = column_text(statement.get(), 5);
        details.summary.analysis_summary = column_text(statement.get(), 6);
    }

    {
        Statement statement(
            database_,
            "SELECT start_address, end_address, successors FROM basic_blocks "
            "WHERE run_id = ? AND function_entry = ? ORDER BY start_address",
            out_error
        );
        if (!statement.valid()) {
            return std::nullopt;
        }

        sqlite3_bind_int(statement.get(), 1, run_id);
        sqlite3_bind_int64(statement.get(), 2, static_cast<sqlite3_int64>(function_entry));
        while (step_row(database_, statement.get(), out_error)) {
            BasicBlockRecord record;
            record.start_address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
            record.end_address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 1));
            record.successors = parse_successors(column_text(statement.get(), 2));
            details.blocks.push_back(std::move(record));
        }
        if (!out_error.empty()) {
            return std::nullopt;
        }
    }

    {
        Statement statement(
            database_,
            "SELECT block_start, address, mnemonic, operands, kind "
            "FROM instructions WHERE run_id = ? AND function_entry = ? ORDER BY address",
            out_error
        );
        if (!statement.valid()) {
            return std::nullopt;
        }

        sqlite3_bind_int(statement.get(), 1, run_id);
        sqlite3_bind_int64(statement.get(), 2, static_cast<sqlite3_int64>(function_entry));
        while (step_row(database_, statement.get(), out_error)) {
            InstructionRecord record;
            record.block_start = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
            record.address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 1));
            record.mnemonic = column_text(statement.get(), 2);
            record.operands = column_text(statement.get(), 3);
            record.kind = column_text(statement.get(), 4);
            details.instructions.push_back(std::move(record));
        }
        if (!out_error.empty()) {
            return std::nullopt;
        }
    }

    {
        Statement statement(
            database_,
            "SELECT c.caller_entry, c.call_site, c.callee_entry, "
            "CASE WHEN c.is_import = 0 THEN COALESCE(sr.renamed_name, c.callee_name) ELSE c.callee_name END, "
            "c.is_import "
            "FROM call_edges c "
            "LEFT JOIN user_symbol_renames sr ON sr.run_id = c.run_id AND sr.target_kind = 'function' AND sr.address = c.callee_entry "
            "WHERE c.run_id = ? AND c.caller_entry = ? ORDER BY c.call_site",
            out_error
        );
        if (!statement.valid()) {
            return std::nullopt;
        }

        sqlite3_bind_int(statement.get(), 1, run_id);
        sqlite3_bind_int64(statement.get(), 2, static_cast<sqlite3_int64>(function_entry));
        while (step_row(database_, statement.get(), out_error)) {
            CallRecord record;
            record.caller_entry = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
            record.call_site = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 1));
            record.callee_entry = column_optional_uint64(statement.get(), 2);
            record.callee_name = column_text(statement.get(), 3);
            record.is_import = sqlite3_column_int(statement.get(), 4) != 0;
            details.outgoing_calls.push_back(std::move(record));
        }
        if (!out_error.empty()) {
            return std::nullopt;
        }
    }

    {
        Statement statement(
            database_,
            "SELECT caller_entry, call_site FROM call_edges "
            "WHERE run_id = ? AND callee_entry = ? ORDER BY caller_entry, call_site",
            out_error
        );
        if (!statement.valid()) {
            return std::nullopt;
        }

        sqlite3_bind_int(statement.get(), 1, run_id);
        sqlite3_bind_int64(statement.get(), 2, static_cast<sqlite3_int64>(function_entry));
        while (step_row(database_, statement.get(), out_error)) {
            CallRecord record;
            record.caller_entry = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
            record.call_site = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 1));
            record.callee_entry = function_entry;
            details.incoming_calls.push_back(std::move(record));
        }
        if (!out_error.empty()) {
            return std::nullopt;
        }
    }

    {
        Statement statement(
            database_,
            "SELECT kind, from_address, to_address, label "
            "FROM xrefs WHERE run_id = ? AND (from_address IN ("
            "SELECT address FROM instructions WHERE run_id = ? AND function_entry = ?"
            ") OR to_address = ?) ORDER BY from_address, to_address",
            out_error
        );
        if (!statement.valid()) {
            return std::nullopt;
        }

        sqlite3_bind_int(statement.get(), 1, run_id);
        sqlite3_bind_int(statement.get(), 2, run_id);
        sqlite3_bind_int64(statement.get(), 3, static_cast<sqlite3_int64>(function_entry));
        sqlite3_bind_int64(statement.get(), 4, static_cast<sqlite3_int64>(function_entry));
        while (step_row(database_, statement.get(), out_error)) {
            XrefRecord record;
            record.kind = column_text(statement.get(), 0);
            record.from_address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 1));
            record.to_address = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 2));
            record.label = column_text(statement.get(), 3);
            details.xrefs.push_back(std::move(record));
        }
        if (!out_error.empty()) {
            return std::nullopt;
        }
    }

    return details;
}

bool ProjectRepository::save_comment(
    int run_id,
    const CommentRecord& record,
    int* out_saved_id,
    std::string& out_error
) {
    if (out_saved_id != nullptr) {
        *out_saved_id = 0;
    }
    if (!require_open(out_error)) {
        return false;
    }

    if (record.body.empty()) {
        out_error = "Comment body cannot be empty.";
        return false;
    }

    if (!exec_sql(database_, "BEGIN IMMEDIATE TRANSACTION;", out_error)) {
        return false;
    }

    bool success = false;
    do {
        Statement statement(
            database_,
            record.id == 0
                ? "INSERT INTO user_comments (run_id, function_entry, address, scope, body) VALUES (?, ?, ?, ?, ?)"
                : "UPDATE user_comments SET function_entry = ?, address = ?, scope = ?, body = ?, updated_at = CURRENT_TIMESTAMP "
                  "WHERE id = ? AND run_id = ?",
            out_error
        );
        if (!statement.valid()) {
            break;
        }

        int saved_id = record.id;
        if (record.id == 0) {
            sqlite3_bind_int(statement.get(), 1, run_id);
            if (record.function_entry.has_value()) {
                sqlite3_bind_int64(statement.get(), 2, static_cast<sqlite3_int64>(*record.function_entry));
            } else {
                sqlite3_bind_null(statement.get(), 2);
            }
            sqlite3_bind_int64(statement.get(), 3, static_cast<sqlite3_int64>(record.address));
            sqlite3_bind_text(statement.get(), 4, record.scope.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement.get(), 5, record.body.c_str(), -1, SQLITE_TRANSIENT);
            if (!step_done(database_, statement.get(), out_error)) {
                break;
            }
            saved_id = static_cast<int>(sqlite3_last_insert_rowid(database_));
        } else {
            if (record.function_entry.has_value()) {
                sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(*record.function_entry));
            } else {
                sqlite3_bind_null(statement.get(), 1);
            }
            sqlite3_bind_int64(statement.get(), 2, static_cast<sqlite3_int64>(record.address));
            sqlite3_bind_text(statement.get(), 3, record.scope.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement.get(), 4, record.body.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(statement.get(), 5, record.id);
            sqlite3_bind_int(statement.get(), 6, run_id);
            if (!step_done(database_, statement.get(), out_error)) {
                break;
            }
        }

        Statement version_statement(
            database_,
            "INSERT INTO project_versions (run_id, kind, title, detail, payload) VALUES (?, ?, ?, ?, ?)",
            out_error
        );
        if (!version_statement.valid()) {
            break;
        }
        sqlite3_bind_int(version_statement.get(), 1, run_id);
        sqlite3_bind_text(version_statement.get(), 2, record.id == 0 ? "comment_created" : "comment_updated", -1, SQLITE_TRANSIENT);
        const std::string title = record.id == 0 ? "Saved user comment" : "Updated user comment";
        const std::string detail = "Comment @" + format_address(record.address) + " [" + record.scope + "]";
        const std::string payload = record.body;
        sqlite3_bind_text(version_statement.get(), 3, title.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 4, detail.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 5, payload.c_str(), -1, SQLITE_TRANSIENT);
        if (!step_done(database_, version_statement.get(), out_error)) {
            break;
        }

        if (!exec_sql(database_, "COMMIT;", out_error)) {
            break;
        }
        if (out_saved_id != nullptr) {
            *out_saved_id = saved_id;
        }
        success = true;
    } while (false);

    if (!success) {
        std::string rollback_error;
        (void)exec_sql(database_, "ROLLBACK;", rollback_error);
    }
    return success;
}

bool ProjectRepository::delete_comment(int comment_id, std::string& out_error) {
    if (!require_open(out_error)) {
        return false;
    }

    if (!exec_sql(database_, "BEGIN IMMEDIATE TRANSACTION;", out_error)) {
        return false;
    }

    bool success = false;
    do {
        Statement lookup(
            database_,
            "SELECT run_id, address, scope, body FROM user_comments WHERE id = ? LIMIT 1",
            out_error
        );
        if (!lookup.valid()) {
            break;
        }
        sqlite3_bind_int(lookup.get(), 1, comment_id);
        if (!step_row(database_, lookup.get(), out_error)) {
            if (out_error.empty()) {
                out_error = "Comment record was not found.";
            }
            break;
        }
        const int run_id = sqlite3_column_int(lookup.get(), 0);
        const auto address = static_cast<std::uint64_t>(sqlite3_column_int64(lookup.get(), 1));
        const std::string scope = column_text(lookup.get(), 2);
        const std::string body = column_text(lookup.get(), 3);

        Statement remove(database_, "DELETE FROM user_comments WHERE id = ?", out_error);
        if (!remove.valid()) {
            break;
        }
        sqlite3_bind_int(remove.get(), 1, comment_id);
        if (!step_done(database_, remove.get(), out_error)) {
            break;
        }

        Statement version_statement(
            database_,
            "INSERT INTO project_versions (run_id, kind, title, detail, payload) VALUES (?, ?, ?, ?, ?)",
            out_error
        );
        if (!version_statement.valid()) {
            break;
        }
        const std::string detail = "Removed comment @" + format_address(address) + " [" + scope + "]";
        sqlite3_bind_int(version_statement.get(), 1, run_id);
        sqlite3_bind_text(version_statement.get(), 2, "comment_deleted", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 3, "Deleted user comment", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 4, detail.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 5, body.c_str(), -1, SQLITE_TRANSIENT);
        if (!step_done(database_, version_statement.get(), out_error)) {
            break;
        }

        if (!exec_sql(database_, "COMMIT;", out_error)) {
            break;
        }
        success = true;
    } while (false);

    if (!success) {
        std::string rollback_error;
        (void)exec_sql(database_, "ROLLBACK;", rollback_error);
    }
    return success;
}

bool ProjectRepository::save_type_annotation(
    int run_id,
    const TypeAnnotationRecord& record,
    int* out_saved_id,
    std::string& out_error
) {
    if (out_saved_id != nullptr) {
        *out_saved_id = 0;
    }
    if (!require_open(out_error)) {
        return false;
    }

    if (record.symbol_name.empty() || record.type_name.empty()) {
        out_error = "Type annotations require both a symbol and a type.";
        return false;
    }

    if (!exec_sql(database_, "BEGIN IMMEDIATE TRANSACTION;", out_error)) {
        return false;
    }

    bool success = false;
    do {
        Statement statement(
            database_,
            record.id == 0
                ? "INSERT INTO user_type_annotations (run_id, function_entry, target_kind, symbol_name, type_name, note) "
                  "VALUES (?, ?, ?, ?, ?, ?)"
                : "UPDATE user_type_annotations SET function_entry = ?, target_kind = ?, symbol_name = ?, type_name = ?, note = ?, "
                  "updated_at = CURRENT_TIMESTAMP WHERE id = ? AND run_id = ?",
            out_error
        );
        if (!statement.valid()) {
            break;
        }

        int saved_id = record.id;
        if (record.id == 0) {
            sqlite3_bind_int(statement.get(), 1, run_id);
            if (record.function_entry.has_value()) {
                sqlite3_bind_int64(statement.get(), 2, static_cast<sqlite3_int64>(*record.function_entry));
            } else {
                sqlite3_bind_null(statement.get(), 2);
            }
            sqlite3_bind_text(statement.get(), 3, record.target_kind.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement.get(), 4, record.symbol_name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement.get(), 5, record.type_name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement.get(), 6, record.note.c_str(), -1, SQLITE_TRANSIENT);
            if (!step_done(database_, statement.get(), out_error)) {
                break;
            }
            saved_id = static_cast<int>(sqlite3_last_insert_rowid(database_));
        } else {
            if (record.function_entry.has_value()) {
                sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(*record.function_entry));
            } else {
                sqlite3_bind_null(statement.get(), 1);
            }
            sqlite3_bind_text(statement.get(), 2, record.target_kind.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement.get(), 3, record.symbol_name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement.get(), 4, record.type_name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement.get(), 5, record.note.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(statement.get(), 6, record.id);
            sqlite3_bind_int(statement.get(), 7, run_id);
            if (!step_done(database_, statement.get(), out_error)) {
                break;
            }
        }

        Statement version_statement(
            database_,
            "INSERT INTO project_versions (run_id, kind, title, detail, payload) VALUES (?, ?, ?, ?, ?)",
            out_error
        );
        if (!version_statement.valid()) {
            break;
        }
        const std::string title = record.id == 0 ? "Saved type annotation" : "Updated type annotation";
        const std::string detail = record.symbol_name + " : " + record.type_name + " [" + record.target_kind + "]";
        const std::string payload = record.note;
        sqlite3_bind_int(version_statement.get(), 1, run_id);
        sqlite3_bind_text(version_statement.get(), 2, record.id == 0 ? "type_created" : "type_updated", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 3, title.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 4, detail.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 5, payload.c_str(), -1, SQLITE_TRANSIENT);
        if (!step_done(database_, version_statement.get(), out_error)) {
            break;
        }

        if (!exec_sql(database_, "COMMIT;", out_error)) {
            break;
        }
        if (out_saved_id != nullptr) {
            *out_saved_id = saved_id;
        }
        success = true;
    } while (false);

    if (!success) {
        std::string rollback_error;
        (void)exec_sql(database_, "ROLLBACK;", rollback_error);
    }
    return success;
}

bool ProjectRepository::delete_type_annotation(int annotation_id, std::string& out_error) {
    if (!require_open(out_error)) {
        return false;
    }

    if (!exec_sql(database_, "BEGIN IMMEDIATE TRANSACTION;", out_error)) {
        return false;
    }

    bool success = false;
    do {
        Statement lookup(
            database_,
            "SELECT run_id, target_kind, symbol_name, type_name, note FROM user_type_annotations WHERE id = ? LIMIT 1",
            out_error
        );
        if (!lookup.valid()) {
            break;
        }
        sqlite3_bind_int(lookup.get(), 1, annotation_id);
        if (!step_row(database_, lookup.get(), out_error)) {
            if (out_error.empty()) {
                out_error = "Type annotation record was not found.";
            }
            break;
        }
        const int run_id = sqlite3_column_int(lookup.get(), 0);
        const std::string target_kind = column_text(lookup.get(), 1);
        const std::string symbol_name = column_text(lookup.get(), 2);
        const std::string type_name = column_text(lookup.get(), 3);
        const std::string note = column_text(lookup.get(), 4);

        Statement remove(database_, "DELETE FROM user_type_annotations WHERE id = ?", out_error);
        if (!remove.valid()) {
            break;
        }
        sqlite3_bind_int(remove.get(), 1, annotation_id);
        if (!step_done(database_, remove.get(), out_error)) {
            break;
        }

        Statement version_statement(
            database_,
            "INSERT INTO project_versions (run_id, kind, title, detail, payload) VALUES (?, ?, ?, ?, ?)",
            out_error
        );
        if (!version_statement.valid()) {
            break;
        }
        const std::string detail = "Removed type annotation " + symbol_name + " : " + type_name + " [" + target_kind + "]";
        sqlite3_bind_int(version_statement.get(), 1, run_id);
        sqlite3_bind_text(version_statement.get(), 2, "type_deleted", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 3, "Deleted type annotation", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 4, detail.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 5, note.c_str(), -1, SQLITE_TRANSIENT);
        if (!step_done(database_, version_statement.get(), out_error)) {
            break;
        }

        if (!exec_sql(database_, "COMMIT;", out_error)) {
            break;
        }
        success = true;
    } while (false);

    if (!success) {
        std::string rollback_error;
        (void)exec_sql(database_, "ROLLBACK;", rollback_error);
    }
    return success;
}

bool ProjectRepository::save_symbol_rename(
    const int run_id,
    const SymbolRenameRecord& record,
    int* out_saved_id,
    std::string& out_error
) {
    if (out_saved_id != nullptr) {
        *out_saved_id = 0;
    }
    if (!require_open(out_error)) {
        return false;
    }

    if (record.target_kind.empty() || record.original_name.empty() || record.renamed_name.empty()) {
        out_error = "Symbol renames require a target kind, original name, and replacement name.";
        return false;
    }

    if (!exec_sql(database_, "BEGIN IMMEDIATE TRANSACTION;", out_error)) {
        return false;
    }

    bool success = false;
    do {
        int saved_id = 0;
        Statement lookup(
            database_,
            "SELECT id FROM user_symbol_renames WHERE run_id = ? AND target_kind = ? AND address = ? LIMIT 1",
            out_error
        );
        if (!lookup.valid()) {
            break;
        }
        sqlite3_bind_int(lookup.get(), 1, run_id);
        sqlite3_bind_text(lookup.get(), 2, record.target_kind.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(lookup.get(), 3, static_cast<sqlite3_int64>(record.address));
        const bool has_existing = step_row(database_, lookup.get(), out_error);
        if (!out_error.empty()) {
            break;
        }
        if (has_existing) {
            saved_id = sqlite3_column_int(lookup.get(), 0);
        }

        Statement statement(
            database_,
            has_existing
                ? "UPDATE user_symbol_renames SET function_entry = ?, original_name = ?, renamed_name = ?, "
                  "updated_at = CURRENT_TIMESTAMP WHERE id = ? AND run_id = ?"
                : "INSERT INTO user_symbol_renames (run_id, function_entry, address, target_kind, original_name, renamed_name) "
                  "VALUES (?, ?, ?, ?, ?, ?)",
            out_error
        );
        if (!statement.valid()) {
            break;
        }

        if (has_existing) {
            if (record.function_entry.has_value()) {
                sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(*record.function_entry));
            } else {
                sqlite3_bind_null(statement.get(), 1);
            }
            sqlite3_bind_text(statement.get(), 2, record.original_name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement.get(), 3, record.renamed_name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(statement.get(), 4, saved_id);
            sqlite3_bind_int(statement.get(), 5, run_id);
        } else {
            sqlite3_bind_int(statement.get(), 1, run_id);
            if (record.function_entry.has_value()) {
                sqlite3_bind_int64(statement.get(), 2, static_cast<sqlite3_int64>(*record.function_entry));
            } else {
                sqlite3_bind_null(statement.get(), 2);
            }
            sqlite3_bind_int64(statement.get(), 3, static_cast<sqlite3_int64>(record.address));
            sqlite3_bind_text(statement.get(), 4, record.target_kind.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement.get(), 5, record.original_name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(statement.get(), 6, record.renamed_name.c_str(), -1, SQLITE_TRANSIENT);
        }

        if (!step_done(database_, statement.get(), out_error)) {
            break;
        }
        if (!has_existing) {
            saved_id = static_cast<int>(sqlite3_last_insert_rowid(database_));
        }

        Statement version_statement(
            database_,
            "INSERT INTO project_versions (run_id, kind, title, detail, payload) VALUES (?, ?, ?, ?, ?)",
            out_error
        );
        if (!version_statement.valid()) {
            break;
        }
        const std::string detail =
            record.original_name + " -> " + record.renamed_name + " [" + record.target_kind + "] @" +
            format_address(record.address);
        sqlite3_bind_int(version_statement.get(), 1, run_id);
        sqlite3_bind_text(version_statement.get(), 2, has_existing ? "symbol_rename_updated" : "symbol_renamed", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 3, has_existing ? "Updated symbol rename" : "Saved symbol rename", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 4, detail.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 5, record.renamed_name.c_str(), -1, SQLITE_TRANSIENT);
        if (!step_done(database_, version_statement.get(), out_error)) {
            break;
        }

        if (!exec_sql(database_, "COMMIT;", out_error)) {
            break;
        }
        if (out_saved_id != nullptr) {
            *out_saved_id = saved_id;
        }
        success = true;
    } while (false);

    if (!success) {
        std::string rollback_error;
        (void)exec_sql(database_, "ROLLBACK;", rollback_error);
    }
    return success;
}

bool ProjectRepository::save_coverage_report(
    int run_id,
    const zara::security::CrashTrace& trace,
    const zara::security::FuzzingReport& report,
    std::string& out_error
) {
    if (!require_open(out_error)) {
        return false;
    }

    if (!exec_sql(database_, "BEGIN IMMEDIATE TRANSACTION;", out_error)) {
        return false;
    }

    bool success = false;
    do {
        Statement run_statement(
            database_,
            "INSERT INTO coverage_runs (run_id, input_label, crash_address, crash_summary, crash_hints, mutation_hooks, harness_bundle) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            out_error
        );
        if (!run_statement.valid()) {
            break;
        }

        sqlite3_bind_int(run_statement.get(), 1, run_id);
        sqlite3_bind_text(run_statement.get(), 2, trace.input_label.c_str(), -1, SQLITE_TRANSIENT);
        if (trace.crash_address.has_value()) {
            sqlite3_bind_int64(run_statement.get(), 3, static_cast<sqlite3_int64>(*trace.crash_address));
        } else {
            sqlite3_bind_null(run_statement.get(), 3);
        }
        sqlite3_bind_text(run_statement.get(), 4, report.crash_summary.c_str(), -1, SQLITE_TRANSIENT);

        std::vector<std::string> hints;
        hints.reserve(report.crash_hints.size());
        for (const auto& hint : report.crash_hints) {
            hints.push_back(
                hint.title + " [" + std::string(zara::security::to_string(hint.severity)) + "] " + hint.detail
            );
        }
        const std::string crash_hints = join_lines(hints);
        std::vector<std::string> mutation_hooks;
        mutation_hooks.reserve(report.mutation_hooks.size());
        for (const auto& hook : report.mutation_hooks) {
            std::string line = hook.function_name + " [" + hook.kind + "] " + hook.label + " :: " + hook.detail;
            if (!hook.sample.empty()) {
                line += " -> " + hook.sample;
            }
            mutation_hooks.push_back(std::move(line));
        }
        const std::string mutation_hook_text = join_lines(mutation_hooks);
        std::vector<std::string> harness_lines;
        harness_lines.reserve(report.harness_artifacts.size());
        for (const auto& artifact : report.harness_artifacts) {
            harness_lines.push_back(artifact.engine + " -> " + artifact.filename);
        }
        const std::string harness_bundle = join_lines(harness_lines);
        sqlite3_bind_text(run_statement.get(), 5, crash_hints.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(run_statement.get(), 6, mutation_hook_text.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(run_statement.get(), 7, harness_bundle.c_str(), -1, SQLITE_TRANSIENT);
        if (!step_done(database_, run_statement.get(), out_error)) {
            break;
        }
        const int coverage_run_id = static_cast<int>(sqlite3_last_insert_rowid(database_));

        Statement function_statement(
            database_,
            "INSERT INTO coverage_functions (coverage_run_id, function_entry, function_name, hit_count, instruction_count, coverage_ratio, contains_crash_address) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            out_error
        );
        if (!function_statement.valid()) {
            break;
        }

        for (const auto& function : report.covered_functions) {
            sqlite3_bind_int(function_statement.get(), 1, coverage_run_id);
            sqlite3_bind_int64(function_statement.get(), 2, static_cast<sqlite3_int64>(function.function_entry));
            sqlite3_bind_text(function_statement.get(), 3, function.function_name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(function_statement.get(), 4, static_cast<sqlite3_int64>(function.hit_count));
            sqlite3_bind_int64(function_statement.get(), 5, static_cast<sqlite3_int64>(function.instruction_count));
            sqlite3_bind_double(function_statement.get(), 6, function.coverage_ratio);
            sqlite3_bind_int(function_statement.get(), 7, function.contains_crash_address ? 1 : 0);
            if (!step_done(database_, function_statement.get(), out_error)) {
                break;
            }
        }
        if (!out_error.empty()) {
            break;
        }

        Statement version_statement(
            database_,
            "INSERT INTO project_versions (run_id, kind, title, detail, payload) VALUES (?, ?, ?, ?, ?)",
            out_error
        );
        if (!version_statement.valid()) {
            break;
        }
        std::ostringstream detail;
        detail << "Imported coverage trace with " << report.covered_functions.size() << " covered function(s)";
        if (!trace.input_label.empty()) {
            detail << " from " << trace.input_label;
        }
        std::string payload = report.crash_summary;
        if (!crash_hints.empty()) {
            payload += "\n" + crash_hints;
        }
        if (!mutation_hook_text.empty()) {
            payload += "\n\nMutation hooks\n" + mutation_hook_text;
        }
        if (!harness_bundle.empty()) {
            payload += "\n\nHarness bundle\n" + harness_bundle;
        }
        sqlite3_bind_int(version_statement.get(), 1, run_id);
        sqlite3_bind_text(version_statement.get(), 2, "coverage_imported", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 3, "Imported coverage trace", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 4, detail.str().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(version_statement.get(), 5, payload.c_str(), -1, SQLITE_TRANSIENT);
        if (!step_done(database_, version_statement.get(), out_error)) {
            break;
        }

        if (!exec_sql(database_, "COMMIT;", out_error)) {
            break;
        }
        success = true;
    } while (false);

    if (!success) {
        std::string rollback_error;
        (void)exec_sql(database_, "ROLLBACK;", rollback_error);
    }
    return success;
}

const std::filesystem::path& ProjectRepository::path() const noexcept {
    return database_path_;
}

bool ProjectRepository::is_open() const noexcept {
    return database_ != nullptr;
}

bool ProjectRepository::require_open(std::string& out_error) const {
    out_error.clear();
    if (database_ != nullptr) {
        return true;
    }
    out_error = "Project database is not open.";
    return false;
}

}  // namespace zara::desktop_qt::persistence
