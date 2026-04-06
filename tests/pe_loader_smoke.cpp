#include <algorithm>
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

#include "zara/loader/binary_image.hpp"

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

std::filesystem::path write_synthetic_pe() {
    constexpr std::size_t kImageSize = 0x800;
    constexpr std::size_t kDosPeOffset = 0x80;
    constexpr std::size_t kFileHeaderOffset = kDosPeOffset + 4;
    constexpr std::size_t kOptionalHeaderOffset = kFileHeaderOffset + 20;
    constexpr std::size_t kSectionTableOffset = kOptionalHeaderOffset + 224;

    std::vector<std::byte> bytes(kImageSize, std::byte{0});
    const std::array<std::uint8_t, 7> text_bytes{
        0xFF, 0x15, 0x50, 0x30, 0x40, 0x00, 0xC3,
    };

    write_ascii(bytes, 0x00, "MZ");
    write_value<std::uint32_t>(bytes, 0x3C, 0x80);

    write_ascii(bytes, kDosPeOffset, "PE\0\0");
    write_value<std::uint16_t>(bytes, kFileHeaderOffset + 0, 0x014C);
    write_value<std::uint16_t>(bytes, kFileHeaderOffset + 2, 3);
    write_value<std::uint16_t>(bytes, kFileHeaderOffset + 16, 224);
    write_value<std::uint16_t>(bytes, kFileHeaderOffset + 18, 0x0102);

    write_value<std::uint16_t>(bytes, kOptionalHeaderOffset + 0, 0x010B);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 4, 0x200);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 8, 0x400);
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
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 96, 0x2000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 100, 0x80);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 104, 0x3000);
    write_value<std::uint32_t>(bytes, kOptionalHeaderOffset + 108, 0x80);

    write_ascii(bytes, kSectionTableOffset + 0, ".text");
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 8, 0x10);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 12, 0x1000);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 16, 0x200);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 20, 0x200);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 36, 0x60000020);

    write_ascii(bytes, kSectionTableOffset + 40, ".rdata");
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 48, 0x200);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 52, 0x2000);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 56, 0x200);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 60, 0x400);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 76, 0x40000040);

    write_ascii(bytes, kSectionTableOffset + 80, ".idata");
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 88, 0x200);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 92, 0x3000);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 96, 0x200);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 100, 0x600);
    write_value<std::uint32_t>(bytes, kSectionTableOffset + 116, 0xC0000040);

    std::memcpy(bytes.data() + 0x200, text_bytes.data(), text_bytes.size());

    write_value<std::uint32_t>(bytes, 0x400 + 12, 0x2040);
    write_value<std::uint32_t>(bytes, 0x400 + 16, 1);
    write_value<std::uint32_t>(bytes, 0x400 + 20, 1);
    write_value<std::uint32_t>(bytes, 0x400 + 24, 1);
    write_value<std::uint32_t>(bytes, 0x400 + 28, 0x2050);
    write_value<std::uint32_t>(bytes, 0x400 + 32, 0x2054);
    write_value<std::uint32_t>(bytes, 0x400 + 36, 0x2058);
    write_ascii(bytes, 0x440, "zarape.dll\0");
    write_value<std::uint32_t>(bytes, 0x450, 0x1000);
    write_value<std::uint32_t>(bytes, 0x454, 0x2060);
    write_value<std::uint16_t>(bytes, 0x458, 0);
    write_ascii(bytes, 0x460, "ExportedFunc\0");

    write_value<std::uint32_t>(bytes, 0x600 + 0, 0x3040);
    write_value<std::uint32_t>(bytes, 0x600 + 12, 0x3070);
    write_value<std::uint32_t>(bytes, 0x600 + 16, 0x3050);
    write_value<std::uint32_t>(bytes, 0x640, 0x3060);
    write_value<std::uint32_t>(bytes, 0x644, 0x0000);
    write_value<std::uint32_t>(bytes, 0x650, 0x3060);
    write_value<std::uint32_t>(bytes, 0x654, 0x0000);
    write_value<std::uint16_t>(bytes, 0x660, 0);
    write_ascii(bytes, 0x662, "ExitProcess\0");
    write_ascii(bytes, 0x670, "KERNEL32.dll\0");

    const std::filesystem::path output_path =
        std::filesystem::temp_directory_path() / "zara_synthetic_import_export.exe";
    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    output.close();

    return output_path;
}

}  // namespace

int main() {
    const std::filesystem::path binary_path = write_synthetic_pe();

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

    if (image.architecture() != zara::loader::Architecture::X86) {
        std::cerr << "expected x86 architecture\n";
        return 3;
    }

    if (!image.entry_point().has_value() || *image.entry_point() != 0x401000) {
        std::cerr << "unexpected entry point\n";
        return 4;
    }

    if (image.sections().size() != 3) {
        std::cerr << "expected three mapped sections\n";
        return 5;
    }

    const auto imported = std::find_if(
        image.imports().begin(),
        image.imports().end(),
        [](const zara::loader::ImportedSymbol& symbol) {
            return symbol.library == "KERNEL32.dll" &&
                   symbol.name == "ExitProcess" &&
                   symbol.address == 0x403050;
        }
    );
    if (imported == image.imports().end()) {
        std::cerr << "expected KERNEL32.dll!ExitProcess import at 0x403050\n";
        return 6;
    }

    const auto exported = std::find_if(
        image.exports().begin(),
        image.exports().end(),
        [](const zara::loader::ExportedSymbol& symbol) {
            return symbol.name == "ExportedFunc" && symbol.address == 0x401000;
        }
    );
    if (exported == image.exports().end()) {
        std::cerr << "expected ExportedFunc export at 0x401000\n";
        return 7;
    }

    return 0;
}
