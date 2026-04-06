#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "zara/memory/address_space.hpp"

int main() {
    zara::memory::AddressSpace address_space;
    if (!address_space.map_segment(
            zara::memory::Segment{
                .name = ".text",
                .base_address = 0x1000,
                .bytes = {std::byte{0x90}, std::byte{0xC3}},
                .permissions = {.readable = true, .writable = false, .executable = true},
            }
        ) ||
        !address_space.map_segment(
            zara::memory::Segment{
                .name = ".data",
                .base_address = 0x2000,
                .bytes = {std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03}},
                .permissions = {.readable = true, .writable = true, .executable = false},
            }
        )) {
        std::cerr << "failed to map test segments\n";
        return 1;
    }

    if (address_space.write_byte(0x1000, std::byte{0xCC})) {
        std::cerr << "write_byte should reject read-only segment\n";
        return 2;
    }

    const std::array<std::byte, 2> patch{std::byte{0xAA}, std::byte{0xBB}};
    if (!address_space.write_bytes(0x2001, patch)) {
        std::cerr << "write_bytes failed on writable segment\n";
        return 3;
    }

    const auto bytes = address_space.read_bytes(0x2000, 4);
    if (bytes.size() != 4 ||
        bytes[0] != std::byte{0x00} ||
        bytes[1] != std::byte{0xAA} ||
        bytes[2] != std::byte{0xBB} ||
        bytes[3] != std::byte{0x03}) {
        std::cerr << "unexpected write_bytes result\n";
        return 4;
    }

    if (!address_space.fill(0x2000, 2, std::byte{0x11})) {
        std::cerr << "fill failed on writable segment\n";
        return 5;
    }

    const auto filled = address_space.read_bytes(0x2000, 4);
    if (filled[0] != std::byte{0x11} || filled[1] != std::byte{0x11}) {
        std::cerr << "unexpected fill result\n";
        return 6;
    }

    if (!address_space.patch_bytes(0x1000, {std::byte{0xCC}})) {
        std::cerr << "patch_bytes should allow code patching\n";
        return 7;
    }

    const auto patched = address_space.read_byte(0x1000);
    if (!patched.has_value() || *patched != std::byte{0xCC}) {
        std::cerr << "patch_bytes did not modify code byte\n";
        return 8;
    }

    const auto perms = address_space.permissions(0x1000);
    if (!perms.has_value() || !perms->executable || perms->writable) {
        std::cerr << "unexpected permissions result\n";
        return 9;
    }

    zara::memory::AddressSpace image_space;
    const auto image = zara::loader::BinaryImage::from_components(
        "synthetic.bin",
        zara::loader::BinaryFormat::Raw,
        zara::loader::Architecture::X86_64,
        0x400000,
        0x401000,
        {
            zara::loader::Section{
                .name = ".text",
                .virtual_address = 0x401000,
                .file_offset = 0,
                .bytes = {std::byte{0x90}, std::byte{0xC3}},
                .readable = true,
                .writable = false,
                .executable = true,
            },
            zara::loader::Section{
                .name = ".idata",
                .virtual_address = 0x403000,
                .file_offset = 2,
                .bytes = {std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}},
                .readable = true,
                .writable = true,
                .executable = false,
            },
        },
        {
            zara::loader::ImportedSymbol{
                .library = "libc.so.6",
                .name = "puts",
                .address = 0x403000,
            },
        },
        {
            zara::loader::ExportedSymbol{
                .name = "entry",
                .address = 0x401000,
                .size = 2,
            },
        }
    );

    if (!image_space.map_image(image)) {
        std::cerr << "failed to map synthetic image for symbol tests\n";
        return 10;
    }

    const auto entry = image_space.resolve_symbol("entry");
    if (!entry.has_value() || entry->address != 0x401000 || entry->kind != zara::memory::SymbolKind::Export) {
        std::cerr << "failed to resolve export symbol\n";
        return 11;
    }

    const auto qualified_import = image_space.resolve_symbol("libc.so.6!puts");
    if (!qualified_import.has_value() ||
        qualified_import->address != 0x403000 ||
        qualified_import->kind != zara::memory::SymbolKind::Import) {
        std::cerr << "failed to resolve qualified import symbol\n";
        return 12;
    }

    const auto exact = image_space.symbol_at(0x401000);
    if (!exact.has_value() || exact->name != "entry") {
        std::cerr << "failed to resolve exact symbol at address\n";
        return 13;
    }

    const auto nearest = image_space.nearest_symbol(0x401001);
    if (!nearest.has_value() || nearest->name != "entry") {
        std::cerr << "failed to resolve nearest symbol\n";
        return 14;
    }

    if (!image_space.add_symbol(
            zara::memory::Symbol{
                .name = "renamed_entry",
                .address = 0x401000,
                .size = 2,
                .kind = zara::memory::SymbolKind::User,
            }
        )) {
        std::cerr << "failed to add user symbol override\n";
        return 15;
    }

    const auto renamed_exact = image_space.symbol_at(0x401000);
    if (!renamed_exact.has_value() || renamed_exact->name != "renamed_entry") {
        std::cerr << "user symbol should take priority at exact symbol lookup\n";
        return 16;
    }

    const auto renamed_nearest = image_space.nearest_symbol(0x401001);
    if (!renamed_nearest.has_value() || renamed_nearest->name != "renamed_entry") {
        std::cerr << "user symbol should take priority for nearest symbol lookup\n";
        return 17;
    }

    return 0;
}
