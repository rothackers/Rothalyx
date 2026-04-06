#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>

#include "zara/cfg/function_graph.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"
#include "zara/xrefs/analysis.hpp"

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
        std::cerr << "usage: zara_import_smoke <binary>\n";
        return 1;
    }

    zara::loader::BinaryImage image;
    std::string error;
    if (!zara::loader::BinaryImage::load_from_file(std::filesystem::path(argv[1]), image, error)) {
        std::cerr << "load failed: " << error << '\n';
        return 2;
    }

    if (image.format() != zara::loader::BinaryFormat::ELF) {
        std::cerr << "expected ELF binary for import smoke test\n";
        return 3;
    }

    if (image.imports().empty()) {
        std::cerr << "expected at least one import\n";
        return 4;
    }

    const auto has_libc_start_main = std::any_of(
        image.imports().begin(),
        image.imports().end(),
        [](const zara::loader::ImportedSymbol& imported) {
            return imported.name == "__libc_start_main";
        }
    );
    if (!has_libc_start_main) {
        std::cerr << "expected __libc_start_main import\n";
        return 5;
    }

    zara::memory::AddressSpace address_space;
    if (!address_space.map_image(image)) {
        std::cerr << "address space map failed\n";
        return 6;
    }

    const auto* decode_section = choose_decode_section(image, image.entry_point());
    if (decode_section == nullptr) {
        std::cerr << "failed to select decode section\n";
        return 7;
    }

    std::uint64_t decode_start = decode_section->virtual_address;
    if (image.entry_point().has_value()) {
        const auto end = decode_section->virtual_address + static_cast<std::uint64_t>(decode_section->bytes.size());
        if (*image.entry_point() >= decode_section->virtual_address && *image.entry_point() < end) {
            decode_start = *image.entry_point();
        }
    }

    const auto graph = zara::cfg::FunctionGraph::analyze(
        "entry_stub",
        address_space,
        *decode_section,
        decode_start,
        image.architecture()
    );
    const auto strings = zara::xrefs::Analyzer::extract_strings(image);
    const auto xrefs = zara::xrefs::Analyzer::build_cross_references(graph, strings, image.imports());

    const auto has_import_xref = std::any_of(
        xrefs.begin(),
        xrefs.end(),
        [](const zara::xrefs::CrossReference& xref) {
            return xref.kind == zara::xrefs::CrossReferenceKind::Import &&
                   xref.label == "__libc_start_main";
        }
    );
    if (!has_import_xref) {
        std::cerr << "expected import xref to __libc_start_main\n";
        return 8;
    }

    return 0;
}
