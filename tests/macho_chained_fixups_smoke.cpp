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

std::filesystem::path write_synthetic_macho_with_chained_fixups() {
    constexpr std::size_t kImageSize = 0x600;
    constexpr std::size_t kHeaderOffset = 0x00;
    constexpr std::size_t kCommandsOffset = 0x20;
    constexpr std::size_t kTextSegmentOffset = kCommandsOffset;
    constexpr std::size_t kDataSegmentOffset = kTextSegmentOffset + 0x98;
    constexpr std::size_t kMainCommandOffset = kDataSegmentOffset + 0x98;
    constexpr std::size_t kSymtabOffset = kMainCommandOffset + 0x18;
    constexpr std::size_t kDylibOffset = kSymtabOffset + 0x18;
    constexpr std::size_t kFixupsCommandOffset = kDylibOffset + 0x30;
    constexpr std::size_t kCodeOffset = 0x200;
    constexpr std::size_t kDataOffset = 0x300;
    constexpr std::size_t kSymbolTableOffset = 0x380;
    constexpr std::size_t kFixupsOffset = 0x400;
    constexpr std::size_t kStringTableOffset = 0x480;

    std::vector<std::byte> bytes(kImageSize, std::byte{0});
    const std::array<std::uint8_t, 8> code_bytes{
        0x55, 0x48, 0x89, 0xE5,  // push rbp; mov rbp, rsp
        0x5D, 0xC3, 0x90, 0x90,  // pop rbp; ret; nop; nop
    };
    const std::string dylib_name = "libSystem.B.dylib";
    const std::string symbol_strings = std::string("\0_main\0", 7);
    const std::string fixup_symbols = std::string("\0_puts\0", 7);

    write_value<std::uint32_t>(bytes, kHeaderOffset + 0x00, 0xFEEDFACF);
    write_value<std::uint32_t>(bytes, kHeaderOffset + 0x04, 0x01000007);
    write_value<std::uint32_t>(bytes, kHeaderOffset + 0x08, 0);
    write_value<std::uint32_t>(bytes, kHeaderOffset + 0x0C, 2);
    write_value<std::uint32_t>(bytes, kHeaderOffset + 0x10, 6);
    write_value<std::uint32_t>(bytes, kHeaderOffset + 0x14, 0x1A0);
    write_value<std::uint32_t>(bytes, kHeaderOffset + 0x18, 0);
    write_value<std::uint32_t>(bytes, kHeaderOffset + 0x1C, 0);

    write_value<std::uint32_t>(bytes, kTextSegmentOffset + 0x00, 0x19);
    write_value<std::uint32_t>(bytes, kTextSegmentOffset + 0x04, 0x98);
    write_ascii(bytes, kTextSegmentOffset + 0x08, "__TEXT");
    write_value<std::uint64_t>(bytes, kTextSegmentOffset + 0x18, 0x100000000ULL);
    write_value<std::uint64_t>(bytes, kTextSegmentOffset + 0x20, 0x1000);
    write_value<std::uint64_t>(bytes, kTextSegmentOffset + 0x28, 0x0);
    write_value<std::uint64_t>(bytes, kTextSegmentOffset + 0x30, 0x208);
    write_value<std::uint32_t>(bytes, kTextSegmentOffset + 0x38, 7);
    write_value<std::uint32_t>(bytes, kTextSegmentOffset + 0x3C, 5);
    write_value<std::uint32_t>(bytes, kTextSegmentOffset + 0x40, 1);

    write_ascii(bytes, kTextSegmentOffset + 0x48, "__text");
    write_ascii(bytes, kTextSegmentOffset + 0x58, "__TEXT");
    write_value<std::uint64_t>(bytes, kTextSegmentOffset + 0x68, 0x100000200ULL);
    write_value<std::uint64_t>(bytes, kTextSegmentOffset + 0x70, static_cast<std::uint64_t>(code_bytes.size()));
    write_value<std::uint32_t>(bytes, kTextSegmentOffset + 0x78, kCodeOffset);
    write_value<std::uint32_t>(bytes, kTextSegmentOffset + 0x88, 0x80000400U);

    write_value<std::uint32_t>(bytes, kDataSegmentOffset + 0x00, 0x19);
    write_value<std::uint32_t>(bytes, kDataSegmentOffset + 0x04, 0x98);
    write_ascii(bytes, kDataSegmentOffset + 0x08, "__DATA_CONST");
    write_value<std::uint64_t>(bytes, kDataSegmentOffset + 0x18, 0x100001000ULL);
    write_value<std::uint64_t>(bytes, kDataSegmentOffset + 0x20, 0x1000);
    write_value<std::uint64_t>(bytes, kDataSegmentOffset + 0x28, kDataOffset);
    write_value<std::uint64_t>(bytes, kDataSegmentOffset + 0x30, 0x10);
    write_value<std::uint32_t>(bytes, kDataSegmentOffset + 0x38, 3);
    write_value<std::uint32_t>(bytes, kDataSegmentOffset + 0x3C, 3);
    write_value<std::uint32_t>(bytes, kDataSegmentOffset + 0x40, 1);

    write_ascii(bytes, kDataSegmentOffset + 0x48, "__const");
    write_ascii(bytes, kDataSegmentOffset + 0x58, "__DATA_CONST");
    write_value<std::uint64_t>(bytes, kDataSegmentOffset + 0x68, 0x100001000ULL);
    write_value<std::uint64_t>(bytes, kDataSegmentOffset + 0x70, 0x10);
    write_value<std::uint32_t>(bytes, kDataSegmentOffset + 0x78, kDataOffset);

    write_value<std::uint32_t>(bytes, kMainCommandOffset + 0x00, 0x80000028);
    write_value<std::uint32_t>(bytes, kMainCommandOffset + 0x04, 0x18);
    write_value<std::uint64_t>(bytes, kMainCommandOffset + 0x08, kCodeOffset);

    write_value<std::uint32_t>(bytes, kSymtabOffset + 0x00, 0x2);
    write_value<std::uint32_t>(bytes, kSymtabOffset + 0x04, 0x18);
    write_value<std::uint32_t>(bytes, kSymtabOffset + 0x08, kSymbolTableOffset);
    write_value<std::uint32_t>(bytes, kSymtabOffset + 0x0C, 1);
    write_value<std::uint32_t>(bytes, kSymtabOffset + 0x10, kStringTableOffset);
    write_value<std::uint32_t>(bytes, kSymtabOffset + 0x14, symbol_strings.size());

    write_value<std::uint32_t>(bytes, kDylibOffset + 0x00, 0xC);
    write_value<std::uint32_t>(bytes, kDylibOffset + 0x04, 0x30);
    write_value<std::uint32_t>(bytes, kDylibOffset + 0x08, 0x18);
    write_ascii(bytes, kDylibOffset + 0x18, dylib_name + std::string(1, '\0'));

    write_value<std::uint32_t>(bytes, kFixupsCommandOffset + 0x00, 0x80000034U);
    write_value<std::uint32_t>(bytes, kFixupsCommandOffset + 0x04, 0x10);
    write_value<std::uint32_t>(bytes, kFixupsCommandOffset + 0x08, kFixupsOffset);
    write_value<std::uint32_t>(bytes, kFixupsCommandOffset + 0x0C, 0x4C);

    std::memcpy(bytes.data() + kCodeOffset, code_bytes.data(), code_bytes.size());

    const std::uint64_t rebase_slot = 0x200ULL | (static_cast<std::uint64_t>(1) << 51U);
    const std::uint64_t bind_slot = (1ULL << 63U);
    write_value<std::uint64_t>(bytes, kDataOffset + 0x00, rebase_slot);
    write_value<std::uint64_t>(bytes, kDataOffset + 0x08, bind_slot);

    write_value<std::uint32_t>(bytes, kSymbolTableOffset + 0x00, 1);
    write_value<std::uint8_t>(bytes, kSymbolTableOffset + 0x04, 0x0F);
    write_value<std::uint8_t>(bytes, kSymbolTableOffset + 0x05, 1);
    write_value<std::uint16_t>(bytes, kSymbolTableOffset + 0x06, 1);
    write_value<std::uint64_t>(bytes, kSymbolTableOffset + 0x08, 0x100000200ULL);
    write_ascii(bytes, kStringTableOffset, symbol_strings);

    write_value<std::uint32_t>(bytes, kFixupsOffset + 0x00, 0);
    write_value<std::uint32_t>(bytes, kFixupsOffset + 0x04, 0x1C);
    write_value<std::uint32_t>(bytes, kFixupsOffset + 0x08, 0x40);
    write_value<std::uint32_t>(bytes, kFixupsOffset + 0x0C, 0x44);
    write_value<std::uint32_t>(bytes, kFixupsOffset + 0x10, 1);
    write_value<std::uint32_t>(bytes, kFixupsOffset + 0x14, 1);
    write_value<std::uint32_t>(bytes, kFixupsOffset + 0x18, 0);

    write_value<std::uint32_t>(bytes, kFixupsOffset + 0x1C, 2);
    write_value<std::uint32_t>(bytes, kFixupsOffset + 0x20, 0);
    write_value<std::uint32_t>(bytes, kFixupsOffset + 0x24, 12);

    write_value<std::uint32_t>(bytes, kFixupsOffset + 0x28, 24);
    write_value<std::uint16_t>(bytes, kFixupsOffset + 0x2C, 0x1000);
    write_value<std::uint16_t>(bytes, kFixupsOffset + 0x2E, 6);
    write_value<std::uint64_t>(bytes, kFixupsOffset + 0x30, 0x1000);
    write_value<std::uint32_t>(bytes, kFixupsOffset + 0x38, 0);
    write_value<std::uint16_t>(bytes, kFixupsOffset + 0x3C, 1);
    write_value<std::uint16_t>(bytes, kFixupsOffset + 0x3E, 0);

    write_value<std::uint32_t>(bytes, kFixupsOffset + 0x40, (1U << 9U) | 1U);
    write_ascii(bytes, kFixupsOffset + 0x44, fixup_symbols);

    const std::filesystem::path output_path =
        std::filesystem::temp_directory_path() / "zara_synthetic_chained_fixups.macho";
    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    output.close();
    return output_path;
}

}  // namespace

int main() {
    const std::filesystem::path binary_path = write_synthetic_macho_with_chained_fixups();

    zara::loader::BinaryImage image;
    std::string error;
    if (!zara::loader::BinaryImage::load_from_file(
            binary_path,
            image,
            error,
            zara::loader::LoadOptions{.base_address = 0x1000, .rebase_address = 0x200000000ULL}
        )) {
        std::cerr << "load failed: " << error << '\n';
        return 1;
    }

    if (image.format() != zara::loader::BinaryFormat::MachO) {
        std::cerr << "expected Mach-O format\n";
        return 2;
    }
    if (image.architecture() != zara::loader::Architecture::X86_64) {
        std::cerr << "expected x86_64 architecture\n";
        return 3;
    }
    if (!image.entry_point().has_value() || *image.entry_point() != 0x200000200ULL) {
        std::cerr << "unexpected rebased entry point\n";
        return 4;
    }

    const auto imported = std::find_if(
        image.imports().begin(),
        image.imports().end(),
        [](const zara::loader::ImportedSymbol& symbol) {
            return symbol.library == "libSystem.B.dylib" &&
                   symbol.name == "puts" &&
                   symbol.address == 0x200001008ULL;
        }
    );
    if (imported == image.imports().end()) {
        std::cerr << "expected chained-fixup import\n";
        for (const auto& symbol : image.imports()) {
            std::cerr << "import: " << symbol.library << "!" << symbol.name << " @ 0x" << std::hex << symbol.address << '\n';
        }
        return 5;
    }

    const auto exported = std::find_if(
        image.exports().begin(),
        image.exports().end(),
        [](const zara::loader::ExportedSymbol& symbol) {
            return symbol.name == "main" && symbol.address == 0x200000200ULL;
        }
    );
    if (exported == image.exports().end()) {
        std::cerr << "expected rebased export\n";
        return 6;
    }

    zara::memory::AddressSpace address_space;
    if (!address_space.map_image(image)) {
        std::cerr << "failed to map macho image\n";
        return 7;
    }

    const auto bytes = address_space.read_bytes(0x200001000ULL, 16);
    if (bytes.size() < 16) {
        std::cerr << "failed to read rebased chained-fixup data\n";
        return 8;
    }

    std::uint64_t rebased_target = 0;
    std::memcpy(&rebased_target, bytes.data(), sizeof(rebased_target));
    if (rebased_target != 0x200000200ULL) {
        std::cerr << "unexpected chained rebase target: 0x" << std::hex << rebased_target << '\n';
        return 9;
    }

    std::error_code cleanup_error;
    std::filesystem::remove(binary_path, cleanup_error);
    return 0;
}
