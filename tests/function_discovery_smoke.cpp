#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "zara/analysis/program_analysis.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"

int main() {
    const std::vector<std::byte> text_bytes{
        std::byte{0x55},                    // push rbp
        std::byte{0x48}, std::byte{0x89}, std::byte{0xE5},  // mov rbp, rsp
        std::byte{0x55},                    // fake nested prologue start
        std::byte{0x48}, std::byte{0x89}, std::byte{0xE5},
        std::byte{0xE8}, std::byte{0x03}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},  // call 0x1010
        std::byte{0x5D},                    // pop rbp
        std::byte{0xC3},                    // ret
        std::byte{0x90},                    // padding
        std::byte{0x55},                    // sub_1010
        std::byte{0x48}, std::byte{0x89}, std::byte{0xE5},
        std::byte{0x31}, std::byte{0xC0},
        std::byte{0xC3},
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
        std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
        std::byte{0x55},                    // heuristic-only function at 0x1020
        std::byte{0x48}, std::byte{0x89}, std::byte{0xE5},
        std::byte{0x31}, std::byte{0xC0},
        std::byte{0xC3},
    };

    const auto image = zara::loader::BinaryImage::from_components(
        "synthetic-discovery.bin",
        zara::loader::BinaryFormat::Raw,
        zara::loader::Architecture::X86_64,
        0x1000,
        0x1000,
        {
            zara::loader::Section{
                .name = ".text",
                .virtual_address = 0x1000,
                .file_offset = 0,
                .bytes = text_bytes,
                .readable = true,
                .writable = false,
                .executable = true,
            },
        }
    );

    zara::memory::AddressSpace address_space;
    if (!address_space.map_image(image)) {
        std::cerr << "failed to map synthetic image\n";
        return 1;
    }

    const auto analysis = zara::analysis::Analyzer::analyze(image, address_space);
    if (analysis.functions.size() != 3) {
        std::cerr << "expected three validated functions, got " << analysis.functions.size() << '\n';
        return 2;
    }

    const std::vector<std::uint64_t> expected_entries{0x1000, 0x1010, 0x1020};
    for (const auto entry : expected_entries) {
        const auto it = std::find_if(
            analysis.functions.begin(),
            analysis.functions.end(),
            [&](const zara::analysis::DiscoveredFunction& function) { return function.entry_address == entry; }
        );
        if (it == analysis.functions.end()) {
            std::cerr << "missing expected function entry 0x" << std::hex << entry << std::dec << '\n';
            return 3;
        }
    }

    const auto false_positive = std::find_if(
        analysis.functions.begin(),
        analysis.functions.end(),
        [](const zara::analysis::DiscoveredFunction& function) { return function.entry_address == 0x1004; }
    );
    if (false_positive != analysis.functions.end()) {
        std::cerr << "heuristic boundary validation should reject overlapping false positive\n";
        return 4;
    }

    const auto call_edge = std::find_if(
        analysis.call_graph.begin(),
        analysis.call_graph.end(),
        [](const zara::analysis::CallGraphEdge& edge) {
            return edge.caller_entry == 0x1000 && edge.callee_entry.has_value() && *edge.callee_entry == 0x1010;
        }
    );
    if (call_edge == analysis.call_graph.end()) {
        std::cerr << "expected direct call edge from 0x1000 to 0x1010\n";
        return 5;
    }

    return 0;
}
