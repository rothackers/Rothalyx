#include "zara/desktop_qt/app/analysis_runner.hpp"
#include "zara/desktop_qt/app/workspace_controller.hpp"
#include "zara/desktop_qt/persistence/project_repository.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: zara_native_analysis_smoke <binary-path>\n";
        return EXIT_FAILURE;
    }

    const std::filesystem::path binary_path(argv[1]);
    const auto unique_id = std::chrono::steady_clock::now().time_since_epoch().count();
    const std::filesystem::path project_path =
        std::filesystem::temp_directory_path() / ("zara-native-analysis-" + std::to_string(unique_id) + ".sqlite");

    zara::desktop_qt::app::LiveProgram program;
    std::string error;
    const bool load_ok = zara::desktop_qt::app::AnalysisRunner::load_program(binary_path, program, error);
    if (!load_ok) {
        std::cerr << "lazy load failed: " << error << '\n';
        return EXIT_FAILURE;
    }
    if (!program.analysis.lazy_materialization || program.analysis.functions.empty() || program.analysis.is_fully_materialized()) {
        std::cerr << "expected native load_program to keep lazy analysis shells\n";
        return EXIT_FAILURE;
    }
    (void)program.analysis.materialize_function(program.analysis.functions.front().entry_address);

    program = {};
    error.clear();
    const bool ok = zara::desktop_qt::app::AnalysisRunner::analyze_binary_to_project(
        binary_path,
        project_path,
        nullptr,
        program,
        error
    );
    if (!ok) {
        std::cerr << "analysis failed: " << error << '\n';
        return EXIT_FAILURE;
    }

    if (program.analysis.functions.empty()) {
        std::cerr << "expected discovered functions from native analysis runner\n";
        return EXIT_FAILURE;
    }

    zara::desktop_qt::app::WorkspaceController controller(project_path);
    if (!controller.open(error)) {
        std::cerr << "failed to reopen persisted project: " << error << '\n';
        return EXIT_FAILURE;
    }

    const auto* workspace = controller.workspace();
    if (workspace == nullptr) {
        std::cerr << "workspace snapshot was not available after open\n";
        return EXIT_FAILURE;
    }
    if (workspace->functions.empty()) {
        std::cerr << "persisted workspace did not expose any functions\n";
        return EXIT_FAILURE;
    }
    if (workspace->run.binary_path.empty()) {
        std::cerr << "persisted run did not record the binary path\n";
        return EXIT_FAILURE;
    }

    zara::desktop_qt::persistence::ProjectRepository repository(project_path);
    if (!repository.open(error)) {
        std::cerr << "failed to reopen repository for cache validation: " << error << '\n';
        return EXIT_FAILURE;
    }
    const int run_count_before = repository.load_run_count(error);
    if (!error.empty() || run_count_before != 1) {
        std::cerr << "expected one persisted analysis run before cache validation, got " << run_count_before
                  << " error=" << error << '\n';
        return EXIT_FAILURE;
    }

    zara::desktop_qt::app::LiveProgram cached_program;
    error.clear();
    const bool cached_ok = zara::desktop_qt::app::AnalysisRunner::analyze_binary_to_project(
        binary_path,
        project_path,
        nullptr,
        cached_program,
        error
    );
    if (!cached_ok) {
        std::cerr << "cached analysis failed: " << error << '\n';
        return EXIT_FAILURE;
    }
    if (!cached_program.project_cache_hit) {
        std::cerr << "expected persisted project cache hit on repeated native analysis\n";
        return EXIT_FAILURE;
    }
    error.clear();
    const int run_count_after = repository.load_run_count(error);
    if (!error.empty() || run_count_after != 1) {
        std::cerr << "expected cached analysis to avoid creating a second run, got " << run_count_after
                  << " error=" << error << '\n';
        return EXIT_FAILURE;
    }

    std::error_code cleanup_error;
    std::filesystem::remove(project_path, cleanup_error);
    return EXIT_SUCCESS;
}
