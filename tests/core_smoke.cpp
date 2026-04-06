#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>

#include "zara/disasm/disassembler.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"

namespace {

const zara::loader::Section* choose_decode_section(
    const zara::loader::BinaryImage& image,
    const std::optional<std::uint64_t> preferred_address
) {
    if (preferred_address.has_value()) {
        for (const auto& section : image.sections()) {
            const auto end = section.virtual_address + static_cast<std::uint64_t>(section.bytes.size());
            if (*preferred_address >= section.virtual_address && *preferred_address < end) {
                return &section;
            }
        }
    }

    for (const auto& section : image.sections()) {
        if (section.executable && !section.bytes.empty()) {
            return &section;
        }
    }

    if (!image.sections().empty()) {
        return &image.sections().front();
    }

    return nullptr;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: zara_core_smoke <binary>\n";
        return 1;
    }

    zara::loader::BinaryImage image;
    std::string error;
    if (!zara::loader::BinaryImage::load_from_file(std::filesystem::path(argv[1]), image, error)) {
        std::cerr << "load failed: " << error << '\n';
        return 2;
    }

    zara::memory::AddressSpace address_space;
    if (!address_space.map_image(image)) {
        std::cerr << "address space map failed\n";
        return 3;
    }

    const auto* section = choose_decode_section(image, image.entry_point());
    if (section == nullptr) {
        std::cerr << "no decode section available\n";
        return 4;
    }

    std::uint64_t start_address = section->virtual_address;
    if (image.entry_point().has_value()) {
        const auto end = section->virtual_address + static_cast<std::uint64_t>(section->bytes.size());
        if (*image.entry_point() >= section->virtual_address && *image.entry_point() < end) {
            start_address = *image.entry_point();
        }
    }

    const auto decode_length = static_cast<std::size_t>(
        std::min<std::uint64_t>(
            32,
            static_cast<std::uint64_t>(section->bytes.size()) - (start_address - section->virtual_address)
        )
    );

    zara::disasm::Disassembler disassembler;
    const auto instructions = disassembler.decode(address_space, start_address, decode_length, image.architecture());
    if (instructions.empty()) {
        std::cerr << "no instructions decoded\n";
        return 5;
    }

    if (image.format() == zara::loader::BinaryFormat::ELF) {
        if (image.architecture() != zara::loader::Architecture::X86_64) {
            std::cerr << "unexpected architecture for ELF test target\n";
            return 6;
        }

        if (instructions.front().mnemonic == "db") {
            std::cerr << "expected Capstone-backed instruction decode for ELF target\n";
            return 7;
        }
    }

    return 0;
}
