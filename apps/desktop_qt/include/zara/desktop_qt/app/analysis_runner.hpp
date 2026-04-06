#pragma once

#include <filesystem>
#include <optional>
#include <string>

#include "zara/ai/assistant.hpp"
#include "zara/analysis/program_analysis.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"

namespace zara::desktop_qt::app {

struct LiveProgram {
    loader::BinaryImage image;
    memory::AddressSpace address_space;
    analysis::ProgramAnalysis analysis;
    bool project_cache_hit = false;
    std::optional<int> cached_run_id;
};

struct AnalysisJobResult {
    bool success = false;
    LiveProgram program;
    std::string error;
};

class AnalysisRunner {
public:
    [[nodiscard]] static bool load_program(
        const std::filesystem::path& binary_path,
        LiveProgram& out_program,
        std::string& out_error
    );

    [[nodiscard]] static bool analyze_binary_to_project(
        const std::filesystem::path& binary_path,
        const std::filesystem::path& project_path,
        const ai::AssistantOptions* assistant_options,
        LiveProgram& out_program,
        std::string& out_error
    );
};

}  // namespace zara::desktop_qt::app
