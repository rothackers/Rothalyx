#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "zara/analysis/program_analysis.hpp"
#include "zara/memory/address_space.hpp"

int main() {
    constexpr std::uint64_t kCodeBase = 0x1000;
    constexpr std::uint64_t kDataBase = 0x1020;

    const std::array<std::uint8_t, 27> code_bytes{
        0x55,
        0x48, 0x89, 0xE5,
        0x48, 0x8D, 0x3D, 0x15, 0x00, 0x00, 0x00,
        0x74, 0x05,
        0xE8, 0x03, 0x00, 0x00, 0x00,
        0x31, 0xC0,
        0xC3,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3
    };

    const std::array<std::uint8_t, 6> data_bytes{
        0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x00,
    };

    zara::memory::AddressSpace address_space;
    if (!address_space.map_segment(
            zara::memory::Segment{
                .name = ".text",
                .base_address = kCodeBase,
                .bytes = std::vector<std::byte>(
                    reinterpret_cast<const std::byte*>(code_bytes.data()),
                    reinterpret_cast<const std::byte*>(code_bytes.data() + code_bytes.size())
                ),
                .permissions =
                    zara::memory::Permissions{
                        .readable = true,
                        .writable = false,
                        .executable = true,
                    },
            }
        ) ||
        !address_space.map_segment(
            zara::memory::Segment{
                .name = ".rodata",
                .base_address = kDataBase,
                .bytes = std::vector<std::byte>(
                    reinterpret_cast<const std::byte*>(data_bytes.data()),
                    reinterpret_cast<const std::byte*>(data_bytes.data() + data_bytes.size())
                ),
                .permissions =
                    zara::memory::Permissions{
                        .readable = true,
                        .writable = false,
                        .executable = false,
                    },
            }
        )) {
        std::cerr << "segment mapping failed\n";
        return 1;
    }

    const auto image = zara::loader::BinaryImage::from_components(
        "synthetic.bin",
        zara::loader::BinaryFormat::Raw,
        zara::loader::Architecture::X86_64,
        kCodeBase,
        kCodeBase,
        {
            zara::loader::Section{
                .name = ".text",
                .virtual_address = kCodeBase,
                .bytes = std::vector<std::byte>(
                    reinterpret_cast<const std::byte*>(code_bytes.data()),
                    reinterpret_cast<const std::byte*>(code_bytes.data() + code_bytes.size())
                ),
                .readable = true,
                .writable = false,
                .executable = true,
            },
            zara::loader::Section{
                .name = ".rodata",
                .virtual_address = kDataBase,
                .bytes = std::vector<std::byte>(
                    reinterpret_cast<const std::byte*>(data_bytes.data()),
                    reinterpret_cast<const std::byte*>(data_bytes.data() + data_bytes.size())
                ),
                .readable = true,
                .writable = false,
                .executable = false,
            },
        }
    );

    const auto analysis = zara::analysis::Analyzer::analyze(image, address_space);
    if (analysis.functions.size() != 2) {
        std::cerr << "expected 2 discovered functions, got " << analysis.functions.size() << '\n';
        return 2;
    }

    const auto has_root = std::any_of(
        analysis.functions.begin(),
        analysis.functions.end(),
        [](const zara::analysis::DiscoveredFunction& function) { return function.entry_address == 0x1000; }
    );
    const auto has_callee = std::any_of(
        analysis.functions.begin(),
        analysis.functions.end(),
        [](const zara::analysis::DiscoveredFunction& function) { return function.entry_address == 0x1015; }
    );
    if (!has_root || !has_callee) {
        std::cerr << "missing expected function entries\n";
        return 3;
    }

    const auto has_edge = std::any_of(
        analysis.call_graph.begin(),
        analysis.call_graph.end(),
        [](const zara::analysis::CallGraphEdge& edge) {
            return edge.caller_entry == 0x1000 &&
                   edge.call_site == 0x100D &&
                   edge.callee_entry.has_value() &&
                   *edge.callee_entry == 0x1015 &&
                   !edge.is_import;
        }
    );
    if (!has_edge) {
        std::cerr << "missing expected internal call edge\n";
        return 4;
    }

    return 0;
}
