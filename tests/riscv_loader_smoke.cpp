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

std::filesystem::path write_synthetic_riscv_elf() {
    constexpr std::size_t kImageSize = 0x300;
    constexpr std::size_t kHeaderOffset = 0x00;
    constexpr std::size_t kProgramHeaderOffset = 0x40;
    constexpr std::size_t kCodeOffset = 0x100;
    constexpr std::size_t kShstrtabOffset = 0x180;
    constexpr std::size_t kSectionHeaderOffset = 0x200;
    constexpr std::uint64_t kTextAddress = 0x401000;

    std::vector<std::byte> bytes(kImageSize, std::byte{0});
    const std::array<std::uint8_t, 8> code_bytes{
        0x13, 0x05, 0x10, 0x00,  // addi a0, zero, 1
        0x67, 0x80, 0x00, 0x00,  // ret
    };
    const std::string shstrtab = std::string("\0.text\0.shstrtab\0", 17);

    write_value<std::uint8_t>(bytes, kHeaderOffset + 0x00, 0x7F);
    write_value<std::uint8_t>(bytes, kHeaderOffset + 0x01, 'E');
    write_value<std::uint8_t>(bytes, kHeaderOffset + 0x02, 'L');
    write_value<std::uint8_t>(bytes, kHeaderOffset + 0x03, 'F');
    write_value<std::uint8_t>(bytes, kHeaderOffset + 0x04, 2);
    write_value<std::uint8_t>(bytes, kHeaderOffset + 0x05, 1);
    write_value<std::uint8_t>(bytes, kHeaderOffset + 0x06, 1);
    write_value<std::uint16_t>(bytes, kHeaderOffset + 0x10, 2);
    write_value<std::uint16_t>(bytes, kHeaderOffset + 0x12, 243);
    write_value<std::uint32_t>(bytes, kHeaderOffset + 0x14, 1);
    write_value<std::uint64_t>(bytes, kHeaderOffset + 0x18, kTextAddress);
    write_value<std::uint64_t>(bytes, kHeaderOffset + 0x20, kProgramHeaderOffset);
    write_value<std::uint64_t>(bytes, kHeaderOffset + 0x28, kSectionHeaderOffset);
    write_value<std::uint16_t>(bytes, kHeaderOffset + 0x34, 64);
    write_value<std::uint16_t>(bytes, kHeaderOffset + 0x36, 56);
    write_value<std::uint16_t>(bytes, kHeaderOffset + 0x38, 1);
    write_value<std::uint16_t>(bytes, kHeaderOffset + 0x3A, 64);
    write_value<std::uint16_t>(bytes, kHeaderOffset + 0x3C, 3);
    write_value<std::uint16_t>(bytes, kHeaderOffset + 0x3E, 2);

    write_value<std::uint32_t>(bytes, kProgramHeaderOffset + 0x00, 1);
    write_value<std::uint32_t>(bytes, kProgramHeaderOffset + 0x04, 5);
    write_value<std::uint64_t>(bytes, kProgramHeaderOffset + 0x08, kCodeOffset);
    write_value<std::uint64_t>(bytes, kProgramHeaderOffset + 0x10, kTextAddress);
    write_value<std::uint64_t>(bytes, kProgramHeaderOffset + 0x18, kTextAddress);
    write_value<std::uint64_t>(bytes, kProgramHeaderOffset + 0x20, code_bytes.size());
    write_value<std::uint64_t>(bytes, kProgramHeaderOffset + 0x28, code_bytes.size());
    write_value<std::uint64_t>(bytes, kProgramHeaderOffset + 0x30, 0x1000);

    std::memcpy(bytes.data() + kCodeOffset, code_bytes.data(), code_bytes.size());
    write_ascii(bytes, kShstrtabOffset, shstrtab);

    constexpr std::size_t kSectionHeaderSize = 64;
    constexpr std::size_t kTextSectionOffset = kSectionHeaderOffset + kSectionHeaderSize;
    constexpr std::size_t kShstrtabSectionOffset = kTextSectionOffset + kSectionHeaderSize;

    write_value<std::uint32_t>(bytes, kTextSectionOffset + 0x00, 1);
    write_value<std::uint32_t>(bytes, kTextSectionOffset + 0x04, 1);
    write_value<std::uint64_t>(bytes, kTextSectionOffset + 0x08, 0x6);
    write_value<std::uint64_t>(bytes, kTextSectionOffset + 0x10, kTextAddress);
    write_value<std::uint64_t>(bytes, kTextSectionOffset + 0x18, kCodeOffset);
    write_value<std::uint64_t>(bytes, kTextSectionOffset + 0x20, code_bytes.size());
    write_value<std::uint64_t>(bytes, kTextSectionOffset + 0x30, 4);

    write_value<std::uint32_t>(bytes, kShstrtabSectionOffset + 0x00, 7);
    write_value<std::uint32_t>(bytes, kShstrtabSectionOffset + 0x04, 3);
    write_value<std::uint64_t>(bytes, kShstrtabSectionOffset + 0x18, kShstrtabOffset);
    write_value<std::uint64_t>(bytes, kShstrtabSectionOffset + 0x20, shstrtab.size());
    write_value<std::uint64_t>(bytes, kShstrtabSectionOffset + 0x30, 1);

    const std::filesystem::path output_path =
        std::filesystem::temp_directory_path() / "zara_synthetic_riscv64.elf";
    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    output.close();
    return output_path;
}

}  // namespace

int main() {
    const std::filesystem::path binary_path = write_synthetic_riscv_elf();

    zara::loader::BinaryImage image;
    std::string error;
    if (!zara::loader::BinaryImage::load_from_file(binary_path, image, error)) {
        std::cerr << "load failed: " << error << '\n';
        return 1;
    }
    if (image.architecture() != zara::loader::Architecture::RISCV64) {
        std::cerr << "expected riscv64 architecture\n";
        return 2;
    }
    if (!image.entry_point().has_value() || *image.entry_point() != 0x401000ULL) {
        std::cerr << "unexpected entry point\n";
        return 3;
    }

    zara::memory::AddressSpace address_space;
    if (!address_space.map_image(image)) {
        std::cerr << "failed to map riscv image\n";
        return 4;
    }

    zara::disasm::Disassembler disassembler;
    if (!disassembler.is_supported(zara::loader::Architecture::RISCV64)) {
        std::cerr << "expected riscv64 decode support\n";
        return 5;
    }

    const auto instructions = disassembler.decode(address_space, *image.entry_point(), 8, image.architecture());
    if (instructions.size() < 2 || instructions.front().mnemonic == "db") {
        std::cerr << "expected real riscv64 instructions\n";
        return 6;
    }
    if (instructions.front().mnemonic != "addi") {
        std::cerr << "unexpected first riscv64 mnemonic: " << instructions.front().mnemonic << '\n';
        return 7;
    }

    const auto analysis = zara::analysis::Analyzer::analyze(image, address_space);
    if (analysis.functions.empty()) {
        std::cerr << "expected discovered riscv64 function\n";
        return 8;
    }
    if (analysis.functions.front().summary.calling_convention != zara::analysis::CallingConvention::RiscV64SysV) {
        std::cerr << "expected riscv64 calling convention\n";
        return 9;
    }

    std::error_code cleanup_error;
    std::filesystem::remove(binary_path, cleanup_error);
    return 0;
}
