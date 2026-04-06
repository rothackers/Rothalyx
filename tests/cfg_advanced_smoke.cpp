#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

#include "zara/cfg/function_graph.hpp"
#include "zara/memory/address_space.hpp"

namespace {

std::vector<std::byte> to_bytes(const std::vector<std::uint8_t>& values) {
    return std::vector<std::byte>(reinterpret_cast<const std::byte*>(values.data()), reinterpret_cast<const std::byte*>(values.data() + values.size()));
}

template <typename T>
void write_value(std::vector<std::byte>& bytes, const std::size_t offset, const T value) {
    std::memcpy(bytes.data() + static_cast<std::ptrdiff_t>(offset), &value, sizeof(value));
}

bool contains_address(const std::vector<std::uint64_t>& values, const std::uint64_t needle) {
    return std::find(values.begin(), values.end(), needle) != values.end();
}

}  // namespace

int main() {
    constexpr std::uint64_t kTextBase = 0x1000;
    constexpr std::uint64_t kTableBase = 0x1060;

    std::vector<std::uint8_t> text_bytes(0x40, 0x90);

    const std::vector<std::uint8_t> loop_bytes{
        0x90, 0x90,
        0x31, 0xC0,
        0x83, 0xF8, 0x03,
        0x7D, 0x05,
        0x83, 0xC0, 0x01,
        0xEB, 0xF6,
        0xC3,
    };
    std::copy(loop_bytes.begin(), loop_bytes.end(), text_bytes.begin());

    const std::vector<std::uint8_t> switch_bytes{
        0x83, 0xFF, 0x01,
        0x77, 0x17,
        0xFF, 0x24, 0xFD, 0x60, 0x10, 0x00, 0x00,
        0x90, 0x90, 0x90, 0x90,
        0xB8, 0x0A, 0x00, 0x00, 0x00, 0xC3,
        0xB8, 0x14, 0x00, 0x00, 0x00, 0xC3,
        0x31, 0xC0, 0xC3,
    };
    std::copy(switch_bytes.begin(), switch_bytes.end(), text_bytes.begin() + 0x20);

    std::vector<std::byte> table_bytes(16, std::byte{0});
    write_value<std::uint64_t>(table_bytes, 0, 0x1030);
    write_value<std::uint64_t>(table_bytes, 8, 0x1036);

    zara::memory::AddressSpace address_space;
    if (!address_space.map_segment(
            zara::memory::Segment{
                .name = ".text",
                .base_address = kTextBase,
                .bytes = to_bytes(text_bytes),
                .permissions = {.readable = true, .writable = false, .executable = true},
            }
        ) ||
        !address_space.map_segment(
            zara::memory::Segment{
                .name = ".rodata",
                .base_address = kTableBase,
                .bytes = table_bytes,
                .permissions = {.readable = true, .writable = false, .executable = false},
            }
        )) {
        std::cerr << "failed to map synthetic cfg segments\n";
        return 1;
    }

    const zara::loader::Section text_section{
        .name = ".text",
        .virtual_address = kTextBase,
        .bytes = to_bytes(text_bytes),
        .readable = true,
        .writable = false,
        .executable = true,
    };

    const auto loop_graph = zara::cfg::FunctionGraph::analyze(
        "loop_fn",
        address_space,
        text_section,
        0x1002,
        zara::loader::Architecture::X86_64
    );
    if (loop_graph.loops().empty()) {
        std::cerr << "expected natural loop detection\n";
        return 2;
    }
    if (loop_graph.loops().front().header_address != 0x1002 &&
        loop_graph.loops().front().header_address != 0x1004 &&
        loop_graph.loops().front().header_address != 0x1009) {
        std::cerr << "unexpected loop header address\n";
        return 3;
    }
    if (!contains_address(loop_graph.loops().front().body_blocks, 0x100A) &&
        !contains_address(loop_graph.loops().front().body_blocks, 0x1009)) {
        std::cerr << "loop body recovery missed back edge block\n";
        return 4;
    }

    const auto switch_graph = zara::cfg::FunctionGraph::analyze(
        "switch_fn",
        address_space,
        text_section,
        0x1020,
        zara::loader::Architecture::X86_64
    );
    if (switch_graph.switches().size() != 1) {
        std::cerr << "expected one recovered switch\n";
        return 5;
    }

    const auto& recovered_switch = switch_graph.switches().front();
    if (recovered_switch.table_address != kTableBase ||
        !recovered_switch.default_target.has_value() ||
        *recovered_switch.default_target != 0x103C ||
        recovered_switch.cases.size() != 2 ||
        recovered_switch.cases[0].target != 0x1030 ||
        recovered_switch.cases[1].target != 0x1036) {
        std::cerr << "switch table recovery mismatch: table=0x" << std::hex << recovered_switch.table_address;
        if (recovered_switch.default_target.has_value()) {
            std::cerr << " default=0x" << *recovered_switch.default_target;
        } else {
            std::cerr << " default=<none>";
        }
        std::cerr << " cases=" << std::dec << recovered_switch.cases.size();
        for (const auto& switch_case : recovered_switch.cases) {
            std::cerr << " [" << switch_case.value << "->0x" << std::hex << switch_case.target << std::dec << "]";
        }
        std::cerr << '\n';
        return 6;
    }

    const auto dispatch_block = std::find_if(
        switch_graph.blocks().begin(),
        switch_graph.blocks().end(),
        [](const zara::cfg::BasicBlock& block) { return block.start_address == 0x1025; }
    );
    if (dispatch_block == switch_graph.blocks().end()) {
        std::cerr << "failed to find switch dispatch block\n";
        return 7;
    }

    if (!contains_address(dispatch_block->successors, 0x1030) ||
        !contains_address(dispatch_block->successors, 0x1036) ||
        !contains_address(dispatch_block->successors, 0x103C)) {
        std::cerr << "switch dispatch successors are incomplete\n";
        return 8;
    }

    return 0;
}
