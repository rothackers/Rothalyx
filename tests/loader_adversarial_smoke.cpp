#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "zara/loader/binary_image.hpp"

namespace {

bool write_bytes(const std::filesystem::path& path, const std::vector<std::byte>& bytes) {
    std::ofstream stream(path, std::ios::binary);
    if (!stream) {
        return false;
    }
    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(stream);
}

bool expect_load_failure(const std::filesystem::path& path, const std::string& label) {
    zara::loader::BinaryImage image;
    std::string error;
    if (zara::loader::BinaryImage::load_from_file(path, image, error)) {
        std::cerr << label << " unexpectedly loaded successfully\n";
        return false;
    }
    if (error.empty()) {
        std::cerr << label << " failed without an error message\n";
        return false;
    }
    return true;
}

}  // namespace

int main() {
    const auto root = std::filesystem::temp_directory_path() / "zara_loader_adversarial";
    std::error_code remove_error;
    std::filesystem::remove_all(root, remove_error);
    std::filesystem::create_directories(root, remove_error);

    const auto elf_path = root / "truncated-elf.bin";
    const auto pe_path = root / "truncated-pe.bin";
    const auto macho_path = root / "truncated-macho.bin";

    const std::vector<std::byte> elf_bytes{
        std::byte{0x7F}, std::byte{'E'}, std::byte{'L'}, std::byte{'F'},
        std::byte{0x02}, std::byte{0x01}, std::byte{0x01}, std::byte{0x00},
    };

    std::vector<std::byte> pe_bytes(0x40, std::byte{0x00});
    pe_bytes[0] = std::byte{'M'};
    pe_bytes[1] = std::byte{'Z'};
    pe_bytes[0x3C] = std::byte{0xF0};
    pe_bytes[0x3D] = std::byte{0xFF};
    pe_bytes[0x3E] = std::byte{0xFF};
    pe_bytes[0x3F] = std::byte{0x7F};

    const std::vector<std::byte> macho_bytes{
        std::byte{0xCF}, std::byte{0xFA}, std::byte{0xED}, std::byte{0xFE},
        std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
    };

    if (!write_bytes(elf_path, elf_bytes) || !write_bytes(pe_path, pe_bytes) || !write_bytes(macho_path, macho_bytes)) {
        std::cerr << "failed to write adversarial loader fixtures\n";
        return 1;
    }

    if (!expect_load_failure(elf_path, "truncated ELF") ||
        !expect_load_failure(pe_path, "truncated PE") ||
        !expect_load_failure(macho_path, "truncated Mach-O")) {
        return 2;
    }

    return 0;
}
