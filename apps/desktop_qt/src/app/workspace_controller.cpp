#include "zara/desktop_qt/app/workspace_controller.hpp"

#include <iomanip>
#include <sstream>

namespace zara::desktop_qt::app {

WorkspaceController::WorkspaceController(std::filesystem::path database_path)
    : repository_(std::move(database_path)) {}

bool WorkspaceController::open(std::string& out_error) {
    out_error.clear();
    workspace_.reset();

    if (!repository_.open(out_error)) {
        return false;
    }

    return reload_workspace(out_error);
}

bool WorkspaceController::reload_workspace(std::string& out_error) {
    out_error.clear();
    workspace_.reset();

    const std::optional<persistence::RunOverview> run = repository_.load_latest_run(out_error);
    if (!run.has_value()) {
        if (out_error.empty()) {
            out_error = "The selected database does not contain a persisted analysis run.";
        }
        return false;
    }

    WorkspaceSnapshot snapshot;
    snapshot.run = *run;
    snapshot.functions = repository_.load_functions(run->run_id, out_error);
    if (!out_error.empty()) {
        return false;
    }
    snapshot.call_edges = repository_.load_call_edges(run->run_id, out_error);
    if (!out_error.empty()) {
        return false;
    }
    snapshot.imports = repository_.load_imports(run->run_id, out_error);
    if (!out_error.empty()) {
        return false;
    }
    snapshot.exports = repository_.load_exports(run->run_id, out_error);
    if (!out_error.empty()) {
        return false;
    }
    snapshot.xrefs = repository_.load_xrefs(run->run_id, out_error);
    if (!out_error.empty()) {
        return false;
    }
    snapshot.strings = repository_.load_strings(run->run_id, out_error);
    if (!out_error.empty()) {
        return false;
    }
    snapshot.comments = repository_.load_comments(run->run_id, out_error);
    if (!out_error.empty()) {
        return false;
    }
    snapshot.type_annotations = repository_.load_type_annotations(run->run_id, out_error);
    if (!out_error.empty()) {
        return false;
    }
    snapshot.versions = repository_.load_versions(out_error);
    if (!out_error.empty()) {
        return false;
    }
    snapshot.coverage = repository_.load_latest_coverage(run->run_id, out_error);
    if (!out_error.empty()) {
        return false;
    }

    workspace_ = std::move(snapshot);
    return true;
}

std::optional<persistence::FunctionDetails>
WorkspaceController::load_function(std::uint64_t entry_address, std::string& out_error) {
    out_error.clear();
    if (!workspace_.has_value()) {
        out_error = "No workspace is loaded.";
        return std::nullopt;
    }
    return repository_.load_function_details(workspace_->run.run_id, entry_address, out_error);
}

bool WorkspaceController::save_comment(
    const persistence::CommentRecord& record,
    int* out_saved_id,
    std::string& out_error
) {
    out_error.clear();
    if (!workspace_.has_value()) {
        out_error = "No workspace is loaded.";
        return false;
    }
    if (!repository_.save_comment(workspace_->run.run_id, record, out_saved_id, out_error)) {
        return false;
    }
    return reload_workspace(out_error);
}

bool WorkspaceController::delete_comment(const int comment_id, std::string& out_error) {
    out_error.clear();
    if (!workspace_.has_value()) {
        out_error = "No workspace is loaded.";
        return false;
    }
    if (!repository_.delete_comment(comment_id, out_error)) {
        return false;
    }
    return reload_workspace(out_error);
}

bool WorkspaceController::save_type_annotation(
    const persistence::TypeAnnotationRecord& record,
    int* out_saved_id,
    std::string& out_error
) {
    out_error.clear();
    if (!workspace_.has_value()) {
        out_error = "No workspace is loaded.";
        return false;
    }
    if (!repository_.save_type_annotation(workspace_->run.run_id, record, out_saved_id, out_error)) {
        return false;
    }
    return reload_workspace(out_error);
}

bool WorkspaceController::delete_type_annotation(const int annotation_id, std::string& out_error) {
    out_error.clear();
    if (!workspace_.has_value()) {
        out_error = "No workspace is loaded.";
        return false;
    }
    if (!repository_.delete_type_annotation(annotation_id, out_error)) {
        return false;
    }
    return reload_workspace(out_error);
}

bool WorkspaceController::save_symbol_rename(
    const persistence::SymbolRenameRecord& record,
    int* out_saved_id,
    std::string& out_error
) {
    out_error.clear();
    if (!workspace_.has_value()) {
        out_error = "No workspace is loaded.";
        return false;
    }
    if (!repository_.save_symbol_rename(workspace_->run.run_id, record, out_saved_id, out_error)) {
        return false;
    }
    return reload_workspace(out_error);
}

bool WorkspaceController::save_coverage_report(
    const security::CrashTrace& trace,
    const security::FuzzingReport& report,
    std::string& out_error
) {
    out_error.clear();
    if (!workspace_.has_value()) {
        out_error = "No workspace is loaded.";
        return false;
    }
    if (!repository_.save_coverage_report(workspace_->run.run_id, trace, report, out_error)) {
        return false;
    }
    return reload_workspace(out_error);
}

const WorkspaceSnapshot* WorkspaceController::workspace() const noexcept {
    return workspace_.has_value() ? &workspace_.value() : nullptr;
}

const std::filesystem::path& WorkspaceController::project_path() const noexcept {
    return repository_.path();
}

std::string WorkspaceController::format_address(std::uint64_t address) {
    std::ostringstream stream;
    stream << "0x" << std::uppercase << std::hex << address;
    return stream.str();
}

std::string WorkspaceController::format_optional_address(const std::optional<std::uint64_t>& address) {
    if (!address.has_value()) {
        return "-";
    }
    return format_address(*address);
}

std::string WorkspaceController::format_successors(const std::vector<std::uint64_t>& successors) {
    if (successors.empty()) {
        return "-";
    }

    std::ostringstream stream;
    for (std::size_t index = 0; index < successors.size(); ++index) {
        if (index > 0) {
            stream << ", ";
        }
        stream << format_address(successors[index]);
    }
    return stream.str();
}

}  // namespace zara::desktop_qt::app
