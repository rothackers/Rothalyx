#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "zara/cfg/function_graph.hpp"
#include "zara/memory/address_space.hpp"
#include "zara/xrefs/analysis.hpp"

int main() {
    constexpr std::uint64_t kCodeBase = 0x1000;
    constexpr std::uint64_t kDataBase = 0x1020;

    const std::array<std::uint8_t, 27> code_bytes{
        0x55,
        0x48, 0x89, 0xE5,
        0x48, 0x8D, 0x3D, 0x15, 0x00, 0x00, 0x00,
        0x74, 0x05,
        0xE8, 0x03, 0x00, 0x00, 0x00,
        0x31, 0xC0,
        0xC3,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3
    };

    const std::array<std::uint8_t, 6> data_bytes{
        0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x00,
    };

    zara::memory::AddressSpace address_space;
    if (!address_space.map_segment(
            zara::memory::Segment{
                .name = ".text",
                .base_address = kCodeBase,
                .bytes = std::vector<std::byte>(reinterpret_cast<const std::byte*>(code_bytes.data()), reinterpret_cast<const std::byte*>(code_bytes.data() + code_bytes.size())),
                .permissions =
                    zara::memory::Permissions{
                        .readable = true,
                        .writable = false,
                        .executable = true,
                    },
            }
        )) {
        std::cerr << "failed to map code segment\n";
        return 1;
    }

    if (!address_space.map_segment(
            zara::memory::Segment{
                .name = ".rodata",
                .base_address = kDataBase,
                .bytes = std::vector<std::byte>(reinterpret_cast<const std::byte*>(data_bytes.data()), reinterpret_cast<const std::byte*>(data_bytes.data() + data_bytes.size())),
                .permissions =
                    zara::memory::Permissions{
                        .readable = true,
                        .writable = false,
                        .executable = false,
                    },
            }
        )) {
        std::cerr << "failed to map data segment\n";
        return 2;
    }

    const zara::loader::Section text_section{
        .name = ".text",
        .virtual_address = kCodeBase,
        .bytes = std::vector<std::byte>(reinterpret_cast<const std::byte*>(code_bytes.data()), reinterpret_cast<const std::byte*>(code_bytes.data() + code_bytes.size())),
        .readable = true,
        .writable = false,
        .executable = true,
    };

    const auto graph = zara::cfg::FunctionGraph::analyze(
        "synthetic_entry",
        address_space,
        text_section,
        kCodeBase,
        zara::loader::Architecture::X86_64
    );

    if (graph.blocks().size() != 3) {
        std::cerr << "unexpected block count: " << graph.blocks().size() << '\n';
        return 3;
    }

    if (graph.direct_call_targets().size() != 1 || graph.direct_call_targets().front() != 0x1015) {
        std::cerr << "direct call target discovery failed\n";
        return 4;
    }

    const std::vector<zara::xrefs::ExtractedString> synthetic_strings{
        zara::xrefs::ExtractedString{
            .start_address = kDataBase,
            .end_address = kDataBase + 5,
            .value = "hello",
        }
    };

    const auto xrefs = zara::xrefs::Analyzer::build_cross_references(graph, synthetic_strings);
    const auto has_string_xref = std::any_of(
        xrefs.begin(),
        xrefs.end(),
        [&](const zara::xrefs::CrossReference& xref) {
            return xref.kind == zara::xrefs::CrossReferenceKind::String &&
                   xref.from_address == 0x1004 &&
                   xref.to_address == kDataBase;
        }
    );
    if (!has_string_xref) {
        std::cerr << "string xref discovery failed\n";
        return 5;
    }

    const auto has_call_xref = std::any_of(
        xrefs.begin(),
        xrefs.end(),
        [](const zara::xrefs::CrossReference& xref) {
            return xref.kind == zara::xrefs::CrossReferenceKind::Call &&
                   xref.from_address == 0x100D &&
                   xref.to_address == 0x1015;
        }
    );
    if (!has_call_xref) {
        std::cerr << "call xref discovery failed\n";
        return 6;
    }

    const auto has_jump_xref = std::any_of(
        xrefs.begin(),
        xrefs.end(),
        [](const zara::xrefs::CrossReference& xref) {
            return xref.kind == zara::xrefs::CrossReferenceKind::Jump &&
                   xref.from_address == 0x100B &&
                   xref.to_address == 0x1012;
        }
    );
    if (!has_jump_xref) {
        std::cerr << "jump xref discovery failed\n";
        return 7;
    }

    return 0;
}
