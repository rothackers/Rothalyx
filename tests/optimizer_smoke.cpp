#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

#include "zara/analysis/program_analysis.hpp"
#include "zara/memory/address_space.hpp"

namespace {

std::vector<std::byte> to_bytes(const std::vector<std::uint8_t>& values) {
    return std::vector<std::byte>(
        reinterpret_cast<const std::byte*>(values.data()),
        reinterpret_cast<const std::byte*>(values.data() + values.size())
    );
}

bool contains_destination_prefix(
    const zara::ssa::Function& function,
    const std::string_view prefix
) {
    for (const auto& block : function.blocks) {
        for (const auto& phi : block.phi_nodes) {
            if (std::string_view(phi.result_name).rfind(prefix, 0) == 0) {
                return true;
            }
        }
        for (const auto& instruction : block.instructions) {
            if (instruction.destination.has_value() &&
                std::string_view(instruction.destination->name).rfind(prefix, 0) == 0) {
                return true;
            }
        }
    }
    return false;
}

}  // namespace

int main() {
    constexpr std::uint64_t kTextBase = 0x1000;

    const std::vector<std::uint8_t> code_bytes{
        0x55,
        0x89, 0xE5,
        0xB8, 0x07, 0x00, 0x00, 0x00,
        0x89, 0xC1,
        0x89, 0xCB,
        0xBE, 0x09, 0x00, 0x00, 0x00,
        0x83, 0xC3, 0x01,
        0x89, 0xD8,
        0x5D,
        0xC3,
    };

    zara::memory::AddressSpace address_space;
    const auto image = zara::loader::BinaryImage::from_components(
        "optimizer.bin",
        zara::loader::BinaryFormat::Raw,
        zara::loader::Architecture::X86,
        kTextBase,
        kTextBase,
        {
            zara::loader::Section{
                .name = ".text",
                .virtual_address = kTextBase,
                .bytes = to_bytes(code_bytes),
                .readable = true,
                .writable = false,
                .executable = true,
            },
        },
        {},
        {
            zara::loader::ExportedSymbol{
                .name = "opt_fn",
                .address = kTextBase,
                .size = static_cast<std::uint64_t>(code_bytes.size()),
            },
        }
    );

    if (!address_space.map_image(image)) {
        std::cerr << "failed to map optimizer image\n";
        return 1;
    }

    const auto analysis = zara::analysis::Analyzer::analyze(image, address_space);
    const auto function_it = std::find_if(
        analysis.functions.begin(),
        analysis.functions.end(),
        [](const zara::analysis::DiscoveredFunction& function) { return function.name == "opt_fn"; }
    );
    if (function_it == analysis.functions.end()) {
        std::cerr << "failed to recover optimizer test function\n";
        return 2;
    }

    if (function_it->summary.copy_propagations_applied == 0) {
        std::cerr << "expected copy propagation to rewrite SSA uses\n";
        return 3;
    }

    if (function_it->summary.dead_instructions_eliminated == 0) {
        std::cerr << "expected dead code elimination to remove dead definitions\n";
        return 4;
    }

    if (contains_destination_prefix(function_it->ssa_form, "ecx.") ||
        contains_destination_prefix(function_it->ssa_form, "esi.")) {
        std::cerr << "copy propagation / DCE left dead register definitions in final SSA\n";
        return 5;
    }

    return 0;
}
