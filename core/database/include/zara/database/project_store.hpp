#pragma once

#include <filesystem>
#include <optional>
#include <string>

#include "zara/ai/assistant.hpp"
#include "zara/analysis/program_analysis.hpp"
#include "zara/cfg/function_graph.hpp"
#include "zara/loader/binary_image.hpp"

namespace zara::database {

struct CachedAnalysisRun {
    int run_id = 0;
    std::string binary_hash;
    std::uint64_t binary_size = 0;
};

class ProjectStore {
public:
    explicit ProjectStore(std::filesystem::path database_path);

    [[nodiscard]] bool initialize(std::string& out_error) const;
    [[nodiscard]] bool save_program_analysis(
        const loader::BinaryImage& image,
        const analysis::ProgramAnalysis& analysis,
        std::string& out_error
    ) const;
    [[nodiscard]] bool save_program_analysis(
        const loader::BinaryImage& image,
        const analysis::ProgramAnalysis& analysis,
        const ai::AssistantOptions* assistant_options,
        std::string& out_error
    ) const;
    [[nodiscard]] std::optional<CachedAnalysisRun>
    find_cached_analysis_run(const loader::BinaryImage& image, std::string& out_error) const;
    [[nodiscard]] const std::filesystem::path& path() const noexcept;

private:
    std::filesystem::path database_path_;
};

}  // namespace zara::database
