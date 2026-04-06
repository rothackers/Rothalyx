#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <vector>

#include "zara/analysis/program_analysis.hpp"
#include "zara/disasm/disassembler.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"

namespace {

template <typename T>
void write_value(std::vector<std::byte>& bytes, const std::size_t offset, const T value) {
    if (offset + sizeof(T) > bytes.size()) {
        throw std::runtime_error("test image write overflow");
    }

    std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

void write_ascii(std::vector<std::byte>& bytes, const std::size_t offset, const std::string_view text) {
    if (offset + text.size() > bytes.size()) {
        throw std::runtime_error("test image write overflow");
    }

    std::memcpy(bytes.data() + offset, text.data(), text.size());
}

std::filesystem::path write_synthetic_arm_pe() {
    constexpr std::size_t kImageSize = 0x400;
    constexpr std::size_t kDosPeOffset = 0x80;
    constexpr std::size_t kFileHeaderOffset = kDosPeOffset + 4;
    constexpr std::size_t kOptionalHeaderOffset = kFileHeaderOffset + 20;
    constexpr std::size_t kSectionTableOffset = kOptionalHeaderOffset + 224;
    constexpr std::size_t kCodeOffset = 0x200;

    std::vector<std::byte> bytes(kImageSize, std::byte{0});
    const std::array<std::uint8_t, 16> text_bytes{
        0x00, 0x48, 0x2D, 0xE9,  // push {fp, lr}
        0x0D, 0xB0, 0xA0, 0xE1,  // mov fp, sp
        0x01, 0x00, 0xA0, 0xE3,  // mov r0, #1
        0x1E, 0xFF, 0x2F, 0xE1,  // bx lr
    };

    write_ascii(bytes, 0x00, "MZ");
    write_value<std::uint32_t>(bytes, 0x3C, 0x80);

    write_ascii(bytes, kDosPeOffset, "PE\0\0");
    write_value<std::uint16_t>(bytes, kFileHeaderOffset + 0, 0x01C0);
    write_value<std::uint16_t>(bytes, kFileHeaderOffset + 2, 1);
    write_value<std::uint16_t>(bytes, kFileHeaderOffset + 16, 224);
    write_value<std::uint16_t>(bytes, kFileHeaderOffset + 18, 0x0102);

    write_value<std::uint16_t>(bytes, kOptionalHeaderOffset + 0, 0x010B);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 4, 0x200);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 8, 0x200);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 16, 0x1000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 20, 0x1000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 24, 0x2000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 28, 0x100000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 32, 0x1000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 36, 0x200);
    write_value<std::uint16_t>(bytes, kOptionalHeaderOffset + 40, 6);
    write_value<std::uint16_t>(bytes, kOptionalHeaderOffset + 48, 3);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 56, 0x3000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 60, 0x200);
    write_value<std::uint16_t>(bytes, kOptionalHeaderOffset + 68, 3);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 72, 0x100000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 76, 0x1000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 80, 0x100000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 84, 0x1000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 92, 0);

    write_ascii(bytes, kSectionTableOffset + 0, ".text");
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 8, 0x20);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 12, 0x1000);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 16, 0x200);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 20, kCodeOffset);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 36, 0x60000020);

    std::memcpy(bytes.data() + kCodeOffset, text_bytes.data(), text_bytes.size());

    const std::filesystem::path output_path = std::filesystem::temp_directory_path() / "zara_synthetic_arm.exe";
    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    output.close();
    return output_path;
}

}  // namespace

int main() {
    const std::filesystem::path binary_path = write_synthetic_arm_pe();

    zara::loader::BinaryImage image;
    std::string error;
    if (!zara::loader::BinaryImage::load_from_file(binary_path, image, error)) {
        std::cerr << "load failed: " << error << '\n';
        return 1;
    }

    if (image.format() != zara::loader::BinaryFormat::PE) {
        std::cerr << "expected PE format\n";
        return 2;
    }
    if (image.architecture() != zara::loader::Architecture::ARM) {
        std::cerr << "expected ARM architecture\n";
        return 3;
    }
    if (!image.entry_point().has_value() || *image.entry_point() != 0x101000ULL) {
        std::cerr << "unexpected ARM entry point\n";
        return 4;
    }

    zara::memory::AddressSpace address_space;
    if (!address_space.map_image(image)) {
        std::cerr << "failed to map ARM image\n";
        return 5;
    }

    zara::disasm::Disassembler disassembler;
    if (!disassembler.is_supported(image.architecture())) {
        std::cerr << "expected ARM decode support\n";
        return 6;
    }

    const auto instructions = disassembler.decode(address_space, *image.entry_point(), 16, image.architecture());
    if (instructions.size() < 4 || instructions.front().mnemonic == "db") {
        std::cerr << "expected real ARM instructions\n";
        return 7;
    }
    if (instructions.front().mnemonic != "push" || instructions.back().kind != zara::disasm::InstructionKind::Return) {
        std::cerr << "unexpected ARM instruction classification\n";
        return 8;
    }

    const auto program = zara::analysis::Analyzer::analyze(image, address_space);
    if (program.functions.empty() || program.functions.front().entry_address != *image.entry_point()) {
        std::cerr << "expected discovered ARM entry function\n";
        return 9;
    }
    if (program.functions.front().summary.calling_convention != zara::analysis::CallingConvention::AAPCS32) {
        std::cerr << "expected AAPCS32 calling convention\n";
        return 10;
    }

    return 0;
}
