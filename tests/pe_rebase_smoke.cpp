#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

#include "zara/loader/binary_image.hpp"

namespace {

template <typename T>
void write_value(std::vector<std::byte>& bytes, const std::size_t offset, const T value) {
    if (offset + sizeof(T) > bytes.size()) {
        throw std::runtime_error("test image write overflow");
    }
    std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

void write_ascii(std::vector<std::byte>& bytes, const std::size_t offset, const char* text) {
    const std::size_t size = std::strlen(text);
    if (offset + size > bytes.size()) {
        throw std::runtime_error("test image write overflow");
    }
    std::memcpy(bytes.data() + offset, text, size);
}

std::filesystem::path write_synthetic_rebased_pe() {
    constexpr std::size_t kImageSize = 0x800;
    constexpr std::size_t kPeOffset = 0x80;
    constexpr std::size_t kFileHeaderOffset = kPeOffset + 4;
    constexpr std::size_t kOptionalHeaderOffset = kFileHeaderOffset + 20;
    constexpr std::size_t kSectionTableOffset = kOptionalHeaderOffset + 224;

    std::vector<std::byte> bytes(kImageSize, std::byte{0});

    write_ascii(bytes, 0x00, "MZ");
    write_value<std::uint32_t>(bytes, 0x3C, 0x80);
    write_ascii(bytes, kPeOffset, "PE\0\0");

    write_value<std::uint16_t>(bytes, kFileHeaderOffset + 0, 0x014C);
    write_value<std::uint16_t>(bytes, kFileHeaderOffset + 2, 3);
    write_value<std::uint16_t>(bytes, kFileHeaderOffset + 16, 224);
    write_value<std::uint16_t>(bytes, kFileHeaderOffset + 18, 0x0102);

    write_value<std::uint16_t>(bytes, kOptionalHeaderOffset + 0, 0x010B);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 4, 0x200);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 8, 0x200);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 16, 0x1000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 20, 0x1000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 24, 0x2000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 28, 0x400000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 32, 0x1000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 36, 0x200);
    write_value<std::uint16_t>(bytes, kOptionalHeaderOffset + 40, 4);
    write_value<std::uint16_t>(bytes, kOptionalHeaderOffset + 48, 3);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 56, 0x4000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 60, 0x200);
    write_value<std::uint16_t>(bytes, kOptionalHeaderOffset + 68, 3);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 72, 0x100000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 76, 0x1000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 80, 0x100000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 84, 0x1000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 92, 16);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 96 + (5 * 8), 0x3000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 96 + (5 * 8) + 4, 0x0C);

    write_ascii(bytes, kSectionTableOffset + 0, ".text");
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 8, 0x10);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 12, 0x1000);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 16, 0x200);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 20, 0x200);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 36, 0x60000020);

    write_ascii(bytes, kSectionTableOffset + 40, ".data");
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 48, 0x200);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 52, 0x2000);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 56, 0x200);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 60, 0x400);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 76, 0xC0000040);

    write_ascii(bytes, kSectionTableOffset + 80, ".reloc");
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 88, 0x200);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 92, 0x3000);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 96, 0x200);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 100, 0x600);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 116, 0x42000040);

    bytes[0x200] = std::byte{0xC3};
    write_value<std::uint32_t>(bytes, 0x400, 0x401000);
    write_value<std::uint32_t>(bytes, 0x600, 0x2000);
    write_value<std::uint32_t>(bytes, 0x604, 0x000C);
    write_value<std::uint16_t>(bytes, 0x608, 0x3000);
    write_value<std::uint16_t>(bytes, 0x60A, 0x0000);

    const std::filesystem::path output_path =
        std::filesystem::temp_directory_path() / "zara_synthetic_rebase.exe";
    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    output.close();
    return output_path;
}

std::uint32_t read_u32(const std::vector<std::byte>& bytes) {
    std::uint32_t value = 0;
    std::memcpy(&value, bytes.data(), sizeof(value));
    return value;
}

}  // namespace

int main() {
    const auto binary_path = write_synthetic_rebased_pe();

    zara::loader::BinaryImage image;
    std::string error;
    if (!zara::loader::BinaryImage::load_from_file(
            binary_path,
            image,
            error,
            zara::loader::LoadOptions{.base_address = 0x1000, .rebase_address = 0x500000}
        )) {
        std::cerr << "load failed: " << error << '\n';
        return 1;
    }

    if (image.base_address() != 0x500000 || !image.entry_point().has_value() || *image.entry_point() != 0x501000) {
        std::cerr << "unexpected first rebase result\n";
        return 2;
    }

    const auto data_section = std::find_if(
        image.sections().begin(),
        image.sections().end(),
        [](const zara::loader::Section& section) { return section.name == ".data"; }
    );
    if (data_section == image.sections().end() || data_section->bytes.size() < 4) {
        std::cerr << "failed to locate rebased data section\n";
        return 3;
    }

    if (read_u32(data_section->bytes) != 0x501000) {
        std::cerr << "base relocation patch was not applied on first rebase\n";
        return 4;
    }

    image.apply_rebase(0x600000);
    const auto rebased_data = std::find_if(
        image.sections().begin(),
        image.sections().end(),
        [](const zara::loader::Section& section) { return section.name == ".data"; }
    );
    if (image.base_address() != 0x600000 || !image.entry_point().has_value() || *image.entry_point() != 0x601000) {
        std::cerr << "unexpected second rebase result\n";
        return 5;
    }
    if (rebased_data == image.sections().end() || read_u32(rebased_data->bytes) != 0x601000) {
        std::cerr << "base relocation patch was not updated on repeated rebase\n";
        return 6;
    }

    return 0;
}
