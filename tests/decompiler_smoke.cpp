#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
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
    const auto function_it = std::find_if(
        analysis.functions.begin(),
        analysis.functions.end(),
        [](const zara::analysis::DiscoveredFunction& function) { return function.entry_address == 0x1000; }
    );
    if (function_it == analysis.functions.end()) {
        std::cerr << "failed to find root function\n";
        return 2;
    }

    const std::string& pseudocode = function_it->decompiled.pseudocode;
    if (pseudocode.find("sub_00001000(") == std::string::npos) {
        std::cerr << "missing decompiled function header\n";
        return 3;
    }

    if (pseudocode.find("if (condition") == std::string::npos &&
        pseudocode.find("if (") == std::string::npos) {
        std::cerr << "missing conditional branch in pseudocode\n";
        return 4;
    }

    if (pseudocode.find("call_1015();") == std::string::npos &&
        pseudocode.find("sub_00001015(") == std::string::npos) {
        std::cerr << "missing direct call pseudocode\n";
        return 5;
    }

    if (pseudocode.find("return") == std::string::npos) {
        std::cerr << "missing return statement\n";
        return 6;
    }

    if (pseudocode.find("phi(") != std::string::npos) {
        std::cerr << "decompiler output still contains raw phi nodes\n";
        return 7;
    }

    return 0;
}
