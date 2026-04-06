#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
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

template <typename T>
void write_value(std::vector<std::byte>& bytes, const std::size_t offset, const T value) {
    std::memcpy(bytes.data() + static_cast<std::ptrdiff_t>(offset), &value, sizeof(value));
}

}  // namespace

int main() {
    constexpr std::uint64_t kTextBase = 0x1000;
    constexpr std::uint64_t kTableBase = 0x1060;

    std::vector<std::uint8_t> text_bytes(0x40, 0x90);
    const std::vector<std::uint8_t> loop_bytes{
        0x90, 0x90,
        0x31, 0xC0,
        0x83, 0xF8, 0x03,
        0x7D, 0x05,
        0x83, 0xC0, 0x01,
        0xEB, 0xF6,
        0xC3,
    };
    const std::vector<std::uint8_t> switch_bytes{
        0x83, 0xFF, 0x01,
        0x77, 0x17,
        0xFF, 0x24, 0xFD, 0x60, 0x10, 0x00, 0x00,
        0x90, 0x90, 0x90, 0x90,
        0xB8, 0x0A, 0x00, 0x00, 0x00, 0xC3,
        0xB8, 0x14, 0x00, 0x00, 0x00, 0xC3,
        0x31, 0xC0, 0xC3,
    };
    std::copy(loop_bytes.begin(), loop_bytes.end(), text_bytes.begin());
    std::copy(switch_bytes.begin(), switch_bytes.end(), text_bytes.begin() + 0x20);

    std::vector<std::byte> table_bytes(16, std::byte{0});
    write_value<std::uint64_t>(table_bytes, 0, 0x1030);
    write_value<std::uint64_t>(table_bytes, 8, 0x1036);

    zara::memory::AddressSpace address_space;
    const auto image = zara::loader::BinaryImage::from_components(
        "decompiler-structured.bin",
        zara::loader::BinaryFormat::Raw,
        zara::loader::Architecture::X86_64,
        kTextBase,
        0x1002,
        {
            zara::loader::Section{
                .name = ".text",
                .virtual_address = kTextBase,
                .bytes = to_bytes(text_bytes),
                .readable = true,
                .writable = false,
                .executable = true,
            },
            zara::loader::Section{
                .name = ".rodata",
                .virtual_address = kTableBase,
                .bytes = table_bytes,
                .readable = true,
                .writable = false,
                .executable = false,
            },
        },
        {},
        {
            zara::loader::ExportedSymbol{
                .name = "loop_fn",
                .address = 0x1002,
                .size = static_cast<std::uint64_t>(loop_bytes.size()),
            },
            zara::loader::ExportedSymbol{
                .name = "switch_fn",
                .address = 0x1020,
                .size = static_cast<std::uint64_t>(switch_bytes.size()),
            },
        }
    );

    if (!address_space.map_image(image)) {
        std::cerr << "failed to map structured decompiler image\n";
        return 1;
    }

    const auto analysis = zara::analysis::Analyzer::analyze(image, address_space);
    const auto loop_it = std::find_if(
        analysis.functions.begin(),
        analysis.functions.end(),
        [](const zara::analysis::DiscoveredFunction& function) { return function.name == "loop_fn"; }
    );
    const auto switch_it = std::find_if(
        analysis.functions.begin(),
        analysis.functions.end(),
        [](const zara::analysis::DiscoveredFunction& function) { return function.name == "switch_fn"; }
    );
    if (loop_it == analysis.functions.end() || switch_it == analysis.functions.end()) {
        std::cerr << "missing exported functions in analysis\n";
        return 2;
    }

    if (loop_it->decompiled.pseudocode.find("while (") == std::string::npos) {
        std::cerr << "loop pseudocode did not recover while-structure\n";
        return 3;
    }
    if (switch_it->decompiled.pseudocode.find("switch (") == std::string::npos ||
        switch_it->decompiled.pseudocode.find("case 0:") == std::string::npos ||
        switch_it->decompiled.pseudocode.find("default:") == std::string::npos) {
        std::cerr << "switch pseudocode did not recover switch-structure\n";
        return 4;
    }

    return 0;
}
