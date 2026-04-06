#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "zara/analysis/program_analysis.hpp"
#include "zara/loader/binary_image.hpp"
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

    zara::analysis::Analyzer::clear_cache();

    std::vector<std::uint8_t> code_bytes{
        0x55,
        0x89, 0xE5,
        0x31, 0xC0,
        0xC3,
    };
    while (code_bytes.size() < 0x20) {
        code_bytes.push_back(0x90);
    }
    code_bytes.insert(
        code_bytes.end(),
        {
            0x8B, 0xFF,
            0x55,
            0x8B, 0xEC,
            0x31, 0xC0,
            0xC3,
        }
    );

    const auto image = zara::loader::BinaryImage::from_components(
        "signature-discovery.bin",
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
        }
    );

    zara::memory::AddressSpace address_space;
    if (!address_space.map_image(image)) {
        std::cerr << "failed to map signature discovery image\n";
        return 1;
    }

    const auto analysis = zara::analysis::Analyzer::analyze(image, address_space);
    const auto signature_function = std::find_if(
        analysis.functions.begin(),
        analysis.functions.end(),
        [](const zara::analysis::DiscoveredFunction& function) { return function.entry_address == 0x1020; }
    );
    if (signature_function == analysis.functions.end()) {
        std::cerr << "expected signature-only function at 0x1020\n";
        return 2;
    }

    const auto heuristic_false_positive = std::find_if(
        analysis.functions.begin(),
        analysis.functions.end(),
        [](const zara::analysis::DiscoveredFunction& function) { return function.entry_address == 0x1022; }
    );
    if (heuristic_false_positive != analysis.functions.end()) {
        std::cerr << "heuristic scan should not accept nested hotpatch prologue at 0x1022\n";
        return 3;
    }

    if (analysis.functions.size() != 2) {
        std::cerr << "expected two functions after signature discovery, got " << analysis.functions.size() << '\n';
        return 4;
    }

    if (signature_function->graph.blocks().empty() ||
        signature_function->graph.blocks().front().instructions.empty() ||
        signature_function->graph.blocks().front().instructions.front().mnemonic != "mov") {
        std::cerr << "expected x86 hotpatch signature to decode into a real function body\n";
        return 5;
    }

    return 0;
}
