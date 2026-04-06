#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "zara/desktop_qt/persistence/project_repository.hpp"
#include "zara/security/workflow.hpp"

namespace zara::desktop_qt::app {

struct WorkspaceSnapshot {
    persistence::RunOverview run;
    std::vector<persistence::FunctionSummary> functions;
    std::vector<persistence::CallRecord> call_edges;
    std::vector<persistence::ImportRecord> imports;
    std::vector<persistence::ExportRecord> exports;
    std::vector<persistence::XrefRecord> xrefs;
    std::vector<persistence::StringRecord> strings;
    std::vector<persistence::CommentRecord> comments;
    std::vector<persistence::TypeAnnotationRecord> type_annotations;
    std::vector<persistence::VersionRecord> versions;
    std::optional<persistence::CoverageOverview> coverage;
};

class WorkspaceController {
public:
    explicit WorkspaceController(std::filesystem::path database_path);

    [[nodiscard]] bool open(std::string& out_error);
    [[nodiscard]] std::optional<persistence::FunctionDetails>
    load_function(std::uint64_t entry_address, std::string& out_error);
    [[nodiscard]] bool save_comment(
        const persistence::CommentRecord& record,
        int* out_saved_id,
        std::string& out_error
    );
    [[nodiscard]] bool delete_comment(int comment_id, std::string& out_error);
    [[nodiscard]] bool save_type_annotation(
        const persistence::TypeAnnotationRecord& record,
        int* out_saved_id,
        std::string& out_error
    );
    [[nodiscard]] bool delete_type_annotation(int annotation_id, std::string& out_error);
    [[nodiscard]] bool save_symbol_rename(
        const persistence::SymbolRenameRecord& record,
        int* out_saved_id,
        std::string& out_error
    );
    [[nodiscard]] bool save_coverage_report(
        const security::CrashTrace& trace,
        const security::FuzzingReport& report,
        std::string& out_error
    );

    [[nodiscard]] const WorkspaceSnapshot* workspace() const noexcept;
    [[nodiscard]] const std::filesystem::path& project_path() const noexcept;

    [[nodiscard]] static std::string format_address(std::uint64_t address);
    [[nodiscard]] static std::string format_optional_address(const std::optional<std::uint64_t>& address);
    [[nodiscard]] static std::string format_successors(const std::vector<std::uint64_t>& successors);

private:
    [[nodiscard]] bool reload_workspace(std::string& out_error);

    persistence::ProjectRepository repository_;
    std::optional<WorkspaceSnapshot> workspace_;
};

}  // namespace zara::desktop_qt::app
