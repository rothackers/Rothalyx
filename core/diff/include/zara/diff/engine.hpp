#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "zara/analysis/program_analysis.hpp"

namespace zara::diff {

enum class ChangeKind {
    Unchanged,
    Modified,
    Added,
    Removed,
};

struct FunctionChange {
    ChangeKind kind = ChangeKind::Modified;
    std::string old_name;
    std::string new_name;
    std::uint64_t old_entry = 0;
    std::uint64_t new_entry = 0;
    double similarity = 0.0;
};

struct Result {
    std::vector<FunctionChange> changes;
    std::size_t unchanged_count = 0;
    std::size_t modified_count = 0;
    std::size_t added_count = 0;
    std::size_t removed_count = 0;
};

class Engine {
public:
    [[nodiscard]] static Result diff(
        const analysis::ProgramAnalysis& before,
        const analysis::ProgramAnalysis& after
    );
};

[[nodiscard]] std::string_view to_string(ChangeKind kind) noexcept;

}  // namespace zara::diff
