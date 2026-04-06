#include "zara/debugger/session.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <utility>

namespace zara::debugger {

namespace {

std::string pseudocode_excerpt(const std::string& pseudocode) {
    std::istringstream input(pseudocode);
    std::ostringstream excerpt;
    std::string line;
    std::size_t emitted = 0;
    while (std::getline(input, line) && emitted < 8) {
        if (emitted > 0) {
            excerpt << '\n';
        }
        excerpt << line;
        ++emitted;
    }
    return excerpt.str();
}

std::optional<StaticLocation> resolve_location(
    const analysis::ProgramAnalysis& analysis,
    const std::uint64_t instruction_pointer
) {
    for (const auto& function : analysis.functions) {
        for (const auto& block : function.graph.blocks()) {
            for (const auto& instruction : block.instructions) {
                const auto end_address = instruction.address + std::max<std::uint8_t>(instruction.size, 1);
                if (instruction_pointer < instruction.address || instruction_pointer >= end_address) {
                    continue;
                }

                return StaticLocation{
                    .function_name = function.name,
                    .function_entry = function.entry_address,
                    .block_start = block.start_address,
                    .instruction_address = instruction.address,
                    .mnemonic = instruction.mnemonic,
                    .operands = instruction.operands,
                    .pseudocode_excerpt = pseudocode_excerpt(function.decompiled.pseudocode),
                };
            }
        }
    }

    return std::nullopt;
}

}  // namespace

bool capture_runtime_snapshot(
    DebugSession& session,
    const loader::BinaryImage& image,
    const analysis::ProgramAnalysis& analysis,
    const StopEvent& stop,
    RuntimeSnapshot& out_snapshot,
    std::string& out_error
) {
    out_error.clear();
    out_snapshot = {};
    out_snapshot.stop = stop;

    if (!session.read_registers(out_snapshot.registers, out_error)) {
        return false;
    }

    const std::uint64_t instruction_pointer = out_snapshot.registers.rip;
    if (!session.read_memory(instruction_pointer, 16, out_snapshot.instruction_bytes, out_error)) {
        out_error = "Failed to capture runtime bytes: " + out_error;
        return false;
    }

    out_snapshot.location = resolve_location(analysis, instruction_pointer);
    if (!out_snapshot.location.has_value() && image.entry_point().has_value()) {
        out_snapshot.location = resolve_location(analysis, *image.entry_point());
    }

    return true;
}

}  // namespace zara::debugger
