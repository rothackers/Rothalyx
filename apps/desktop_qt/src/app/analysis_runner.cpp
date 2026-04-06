#include "zara/desktop_qt/app/analysis_runner.hpp"

#include <algorithm>
#include <thread>

#include "zara/database/project_store.hpp"

namespace zara::desktop_qt::app {

namespace {

std::size_t recommended_analysis_threads() {
    const std::size_t hardware_threads = std::max<std::size_t>(1, std::thread::hardware_concurrency());
    return std::min<std::size_t>(4, hardware_threads);
}

loader::LoadOptions desktop_load_options() {
    loader::LoadOptions options;
    options.policy.strict_validation = true;
    options.policy.max_total_mapped_bytes = 384u * 1024u * 1024u;
    options.policy.max_mapped_section_size = 96u * 1024u * 1024u;
    return options;
}

analysis::AnalyzeOptions desktop_analyze_options(const bool materialize_functions) {
    return analysis::AnalyzeOptions{
        .materialize_functions = materialize_functions,
        .use_cache = true,
        .max_worker_threads = recommended_analysis_threads(),
    };
}

}  // namespace

bool AnalysisRunner::load_program(
    const std::filesystem::path& binary_path,
    LiveProgram& out_program,
    std::string& out_error
) {
    out_error.clear();
    out_program = {};

    if (!loader::BinaryImage::load_from_file(binary_path, out_program.image, out_error, desktop_load_options())) {
        return false;
    }

    if (!out_program.address_space.map_image(out_program.image)) {
        out_error = "Failed to map image into the analysis address space.";
        return false;
    }

    out_program.analysis = analysis::Analyzer::analyze(
        out_program.image,
        out_program.address_space,
        desktop_analyze_options(false)
    );
    return true;
}

bool AnalysisRunner::analyze_binary_to_project(
    const std::filesystem::path& binary_path,
    const std::filesystem::path& project_path,
    const ai::AssistantOptions* assistant_options,
    LiveProgram& out_program,
    std::string& out_error
) {
    out_error.clear();
    out_program = {};

    if (!loader::BinaryImage::load_from_file(binary_path, out_program.image, out_error, desktop_load_options())) {
        return false;
    }

    database::ProjectStore project_store(project_path);
    if (const auto cached_run = project_store.find_cached_analysis_run(out_program.image, out_error);
        cached_run.has_value()) {
        if (!out_program.address_space.map_image(out_program.image)) {
            out_error = "Failed to map image into the analysis address space.";
            return false;
        }
        out_program.project_cache_hit = true;
        out_program.cached_run_id = cached_run->run_id;
        return true;
    }
    out_error.clear();

    if (!out_program.address_space.map_image(out_program.image)) {
        out_error = "Failed to map image into the analysis address space.";
        return false;
    }

    out_program.analysis = analysis::Analyzer::analyze(
        out_program.image,
        out_program.address_space,
        desktop_analyze_options(false)
    );
    out_program.analysis.materialize_all();

    if (!project_store.save_program_analysis(out_program.image, out_program.analysis, assistant_options, out_error)) {
        return false;
    }

    return true;
}

}  // namespace zara::desktop_qt::app
