#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "zara/analysis/program_analysis.hpp"
#include "zara/memory/address_space.hpp"

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
                .bytes = std::vector<std::byte>(
                    reinterpret_cast<const std::byte*>(code_bytes.data()),
                    reinterpret_cast<const std::byte*>(code_bytes.data() + code_bytes.size())
                ),
                .permissions =
                    zara::memory::Permissions{
                        .readable = true,
                        .writable = false,
                        .executable = true,
                    },
            }
        ) ||
        !address_space.map_segment(
            zara::memory::Segment{
                .name = ".rodata",
                .base_address = kDataBase,
                .bytes = std::vector<std::byte>(
                    reinterpret_cast<const std::byte*>(data_bytes.data()),
                    reinterpret_cast<const std::byte*>(data_bytes.data() + data_bytes.size())
                ),
                .permissions =
                    zara::memory::Permissions{
                        .readable = true,
                        .writable = false,
                        .executable = false,
                    },
            }
        )) {
        std::cerr << "segment mapping failed\n";
        return 1;
    }

    const auto image = zara::loader::BinaryImage::from_components(
        "synthetic.bin",
        zara::loader::BinaryFormat::Raw,
        zara::loader::Architecture::X86_64,
        kCodeBase,
        kCodeBase,
        {
            zara::loader::Section{
                .name = ".text",
                .virtual_address = kCodeBase,
                .bytes = std::vector<std::byte>(
                    reinterpret_cast<const std::byte*>(code_bytes.data()),
                    reinterpret_cast<const std::byte*>(code_bytes.data() + code_bytes.size())
                ),
                .readable = true,
                .writable = false,
                .executable = true,
            },
            zara::loader::Section{
                .name = ".rodata",
                .virtual_address = kDataBase,
                .bytes = std::vector<std::byte>(
                    reinterpret_cast<const std::byte*>(data_bytes.data()),
                    reinterpret_cast<const std::byte*>(data_bytes.data() + data_bytes.size())
                ),
                .readable = true,
                .writable = false,
                .executable = false,
            },
        }
    );

    const auto analysis = zara::analysis::Analyzer::analyze(image, address_space);
    const auto function_it = std::find_if(
        analysis.functions.begin(),
        analysis.functions.end(),
        [](const zara::analysis::DiscoveredFunction& function) { return function.entry_address == 0x1000; }
    );
    if (function_it == analysis.functions.end()) {
        std::cerr << "failed to find root function\n";
        return 2;
    }

    if (function_it->lifted_ir.blocks.empty()) {
        std::cerr << "lifted ir is empty\n";
        return 3;
    }

    const auto has_store = std::any_of(
        function_it->lifted_ir.blocks.begin(),
        function_it->lifted_ir.blocks.end(),
        [](const zara::ir::BasicBlock& block) {
            return std::any_of(
                block.instructions.begin(),
                block.instructions.end(),
                [](const zara::ir::Instruction& instruction) {
                    return instruction.kind == zara::ir::InstructionKind::Store;
                }
            );
        }
    );
    if (!has_store) {
        std::cerr << "expected a store instruction in lifted ir\n";
        return 4;
    }

    const auto has_lea_assign = std::any_of(
        function_it->lifted_ir.blocks.begin(),
        function_it->lifted_ir.blocks.end(),
        [](const zara::ir::BasicBlock& block) {
            return std::any_of(
                block.instructions.begin(),
                block.instructions.end(),
                [](const zara::ir::Instruction& instruction) {
                    return instruction.kind == zara::ir::InstructionKind::Assign &&
                           instruction.destination.has_value() &&
                           instruction.destination->name == "rdi" &&
                           !instruction.inputs.empty() &&
                           instruction.inputs.front().kind == zara::ir::ValueKind::MemoryAddress;
                }
            );
        }
    );
    if (!has_lea_assign) {
        std::cerr << "expected effective-address assignment for rdi\n";
        return 5;
    }

    const auto has_conditional_branch = std::any_of(
        function_it->lifted_ir.blocks.begin(),
        function_it->lifted_ir.blocks.end(),
        [](const zara::ir::BasicBlock& block) {
            return std::any_of(
                block.instructions.begin(),
                block.instructions.end(),
                [](const zara::ir::Instruction& instruction) {
                    return instruction.kind == zara::ir::InstructionKind::CondBranch &&
                           instruction.true_target.has_value() &&
                           *instruction.true_target == 0x1012 &&
                           instruction.false_target.has_value() &&
                           *instruction.false_target == 0x100D;
                }
            );
        }
    );
    if (!has_conditional_branch) {
        std::cerr << "expected lifted conditional branch\n";
        return 6;
    }

    const auto has_direct_call = std::any_of(
        function_it->lifted_ir.blocks.begin(),
        function_it->lifted_ir.blocks.end(),
        [](const zara::ir::BasicBlock& block) {
            return std::any_of(
                block.instructions.begin(),
                block.instructions.end(),
                [](const zara::ir::Instruction& instruction) {
                    return instruction.kind == zara::ir::InstructionKind::Call &&
                           instruction.true_target.has_value() &&
                           *instruction.true_target == 0x1015;
                }
            );
        }
    );
    if (!has_direct_call) {
        std::cerr << "expected lifted direct call\n";
        return 7;
    }

    const auto has_zero_assign = std::any_of(
        function_it->lifted_ir.blocks.begin(),
        function_it->lifted_ir.blocks.end(),
        [](const zara::ir::BasicBlock& block) {
            return std::any_of(
                block.instructions.begin(),
                block.instructions.end(),
                [](const zara::ir::Instruction& instruction) {
                    return instruction.kind == zara::ir::InstructionKind::Assign &&
                           instruction.destination.has_value() &&
                           instruction.destination->name == "eax" &&
                           instruction.inputs.size() == 1 &&
                           instruction.inputs.front().kind == zara::ir::ValueKind::Immediate &&
                           instruction.inputs.front().immediate == 0;
                }
            );
        }
    );
    if (!has_zero_assign) {
        std::cerr << "expected xor-zero register assignment\n";
        return 8;
    }

    return 0;
}
