#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "zara/security/workflow.hpp"

struct sqlite3;

namespace zara::desktop_qt::persistence {

struct RunOverview {
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
    std::string poc_scaffold;
};

struct FunctionSummary {
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

struct BasicBlockRecord {
    std::uint64_t start_address = 0;
    std::uint64_t end_address = 0;
    std::vector<std::uint64_t> successors;
};

struct InstructionRecord {
    std::uint64_t block_start = 0;
    std::uint64_t address = 0;
    std::string mnemonic;
    std::string operands;
    std::string kind;
};

struct CallRecord {
    std::uint64_t caller_entry = 0;
    std::uint64_t call_site = 0;
    std::optional<std::uint64_t> callee_entry;
    std::string callee_name;
    bool is_import = false;
};

struct XrefRecord {
    std::string kind;
    std::uint64_t from_address = 0;
    std::uint64_t to_address = 0;
    std::string label;
};

struct ImportRecord {
    std::uint64_t address = 0;
    std::string library_name;
    std::string name;
};

struct ExportRecord {
    std::uint64_t address = 0;
    std::string name;
    std::uint64_t size = 0;
};

struct StringRecord {
    std::uint64_t address = 0;
    std::string value;
};

struct CommentRecord {
    int id = 0;
    std::optional<std::uint64_t> function_entry;
    std::uint64_t address = 0;
    std::string scope;
    std::string body;
    std::string created_at;
    std::string updated_at;
};

struct TypeAnnotationRecord {
    int id = 0;
    std::optional<std::uint64_t> function_entry;
    std::string target_kind;
    std::string symbol_name;
    std::string type_name;
    std::string note;
    std::string created_at;
    std::string updated_at;
};

struct SymbolRenameRecord {
    int id = 0;
    std::optional<std::uint64_t> function_entry;
    std::uint64_t address = 0;
    std::string target_kind;
    std::string original_name;
    std::string renamed_name;
    std::string created_at;
    std::string updated_at;
};

struct VersionRecord {
    int id = 0;
    std::optional<int> run_id;
    std::string kind;
    std::string title;
    std::string detail;
    std::string payload;
    std::string created_at;
};

struct CoverageFunctionRecord {
    std::uint64_t function_entry = 0;
    std::string function_name;
    std::size_t hit_count = 0;
    std::size_t instruction_count = 0;
    double coverage_ratio = 0.0;
    bool contains_crash_address = false;
};

struct CoverageOverview {
    int coverage_run_id = 0;
    std::string input_label;
    std::optional<std::uint64_t> crash_address;
    std::string crash_summary;
    std::string crash_hints;
    std::string mutation_hooks;
    std::string harness_bundle;
    std::string imported_at;
    std::vector<CoverageFunctionRecord> functions;
};

struct FunctionDetails {
    FunctionSummary summary;
    std::vector<BasicBlockRecord> blocks;
    std::vector<InstructionRecord> instructions;
    std::vector<CallRecord> outgoing_calls;
    std::vector<CallRecord> incoming_calls;
    std::vector<XrefRecord> xrefs;
};

class ProjectRepository {
public:
    explicit ProjectRepository(std::filesystem::path database_path);
    ~ProjectRepository();

    ProjectRepository(const ProjectRepository&) = delete;
    ProjectRepository& operator=(const ProjectRepository&) = delete;

    [[nodiscard]] bool open(std::string& out_error);
    void close();

    [[nodiscard]] std::optional<RunOverview> load_latest_run(std::string& out_error) const;
    [[nodiscard]] int load_run_count(std::string& out_error) const;
    [[nodiscard]] std::vector<FunctionSummary> load_functions(int run_id, std::string& out_error) const;
    [[nodiscard]] std::vector<CallRecord> load_call_edges(int run_id, std::string& out_error) const;
    [[nodiscard]] std::vector<ImportRecord> load_imports(int run_id, std::string& out_error) const;
    [[nodiscard]] std::vector<ExportRecord> load_exports(int run_id, std::string& out_error) const;
    [[nodiscard]] std::vector<XrefRecord> load_xrefs(int run_id, std::string& out_error) const;
    [[nodiscard]] std::vector<StringRecord> load_strings(int run_id, std::string& out_error) const;
    [[nodiscard]] std::vector<CommentRecord> load_comments(int run_id, std::string& out_error) const;
    [[nodiscard]] std::vector<TypeAnnotationRecord> load_type_annotations(int run_id, std::string& out_error) const;
    [[nodiscard]] std::vector<VersionRecord> load_versions(std::string& out_error) const;
    [[nodiscard]] std::optional<CoverageOverview> load_latest_coverage(int run_id, std::string& out_error) const;
    [[nodiscard]] std::optional<FunctionDetails>
    load_function_details(int run_id, std::uint64_t function_entry, std::string& out_error) const;
    [[nodiscard]] bool save_comment(
        int run_id,
        const CommentRecord& record,
        int* out_saved_id,
        std::string& out_error
    );
    [[nodiscard]] bool delete_comment(int comment_id, std::string& out_error);
    [[nodiscard]] bool save_type_annotation(
        int run_id,
        const TypeAnnotationRecord& record,
        int* out_saved_id,
        std::string& out_error
    );
    [[nodiscard]] bool delete_type_annotation(int annotation_id, std::string& out_error);
    [[nodiscard]] bool save_symbol_rename(
        int run_id,
        const SymbolRenameRecord& record,
        int* out_saved_id,
        std::string& out_error
    );
    [[nodiscard]] bool save_coverage_report(
        int run_id,
        const security::CrashTrace& trace,
        const security::FuzzingReport& report,
        std::string& out_error
    );

    [[nodiscard]] const std::filesystem::path& path() const noexcept;
    [[nodiscard]] bool is_open() const noexcept;

private:
    [[nodiscard]] bool require_open(std::string& out_error) const;

    std::filesystem::path database_path_;
    sqlite3* database_ = nullptr;
};

}  // namespace zara::desktop_qt::persistence
