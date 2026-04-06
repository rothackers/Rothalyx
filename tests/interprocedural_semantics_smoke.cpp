#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
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

}  // namespace

int main() {
    constexpr std::uint64_t kTextBase = 0x1000;
    const std::vector<std::uint8_t> code_bytes{
        0x55,
        0x48, 0x89, 0xE5,
        0xE8, 0x05, 0x00, 0x00, 0x00,
        0x5D,
        0xC3,
        0x90,
        0x90,
        0x90,
        0x55,
        0x48, 0x89, 0xE5,
        0x8B, 0x47, 0x04,
        0x8B, 0x4F, 0x08,
        0x01, 0xC8,
        0x5D,
        0xC3,
    };

    const auto image = zara::loader::BinaryImage::from_components(
        "interprocedural.bin",
        zara::loader::BinaryFormat::Raw,
        zara::loader::Architecture::X86_64,
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
        }
    );

    zara::memory::AddressSpace address_space;
    if (!address_space.map_image(image)) {
        std::cerr << "failed to map interprocedural test image\n";
        return 1;
    }

    auto analysis = zara::analysis::Analyzer::analyze(image, address_space);
    if (analysis.functions.size() < 2) {
        std::cerr << "expected at least two discovered functions\n";
        return 2;
    }

    const auto caller_it = std::find_if(
        analysis.functions.begin(),
        analysis.functions.end(),
        [](const zara::analysis::DiscoveredFunction& function) { return function.entry_address == 0x1000; }
    );
    const auto callee_it = std::find_if(
        analysis.functions.begin(),
        analysis.functions.end(),
        [](const zara::analysis::DiscoveredFunction& function) { return function.entry_address == 0x100E; }
    );
    if (caller_it == analysis.functions.end() || callee_it == analysis.functions.end()) {
        std::cerr << "failed to resolve caller/callee pair\n";
        return 3;
    }

    if (caller_it->decompiled.pseudocode.find("sub_0000100E(") == std::string::npos ||
        caller_it->decompiled.pseudocode.find("arg_0") == std::string::npos) {
        std::cerr << "expected signature-aware interprocedural decompilation\n";
        std::cerr << "caller pseudocode:\n" << caller_it->decompiled.pseudocode << '\n';
        return 4;
    }

    if (callee_it->decompiled.pseudocode.find("arg_0->field_4") == std::string::npos &&
        callee_it->decompiled.pseudocode.find("arg_0->field_8") == std::string::npos) {
        std::cerr << "expected typed callee decompilation\n";
        std::cerr << "callee pseudocode:\n" << callee_it->decompiled.pseudocode << '\n';
        return 5;
    }

    return 0;
}
