#include <algorithm>
#include <cstdint>
#include <iostream>

#include "zara/ssa/builder.hpp"

namespace {

zara::ir::Value reg(const char* name) {
    return zara::ir::Value{
        .kind = zara::ir::ValueKind::Register,
        .type = zara::ir::ScalarType::I32,
        .name = name,
    };
}

zara::ir::Value imm(const std::int64_t value) {
    return zara::ir::Value{
        .kind = zara::ir::ValueKind::Immediate,
        .type = zara::ir::ScalarType::I32,
        .immediate = value,
    };
}

}  // namespace

int main() {
    const zara::ir::Function function{
        .name = "ssa_fixture",
        .entry_address = 0x1000,
        .blocks =
            {
                zara::ir::BasicBlock{
                    .start_address = 0x1000,
                    .instructions =
                        {
                            zara::ir::Instruction{
                                .address = 0x1000,
                                .kind = zara::ir::InstructionKind::Assign,
                                .destination = reg("eax"),
                                .inputs = {imm(1)},
                            },
                            zara::ir::Instruction{
                                .address = 0x1004,
                                .kind = zara::ir::InstructionKind::CondBranch,
                                .inputs = {reg("eax")},
                                .true_target = 0x1010,
                                .false_target = 0x1020,
                                .text = "jne",
                            },
                        },
                    .successors = {0x1010, 0x1020},
                },
                zara::ir::BasicBlock{
                    .start_address = 0x1010,
                    .instructions =
                        {
                            zara::ir::Instruction{
                                .address = 0x1010,
                                .kind = zara::ir::InstructionKind::Assign,
                                .destination = reg("eax"),
                                .inputs = {imm(2)},
                            },
                            zara::ir::Instruction{
                                .address = 0x1014,
                                .kind = zara::ir::InstructionKind::Branch,
                                .true_target = 0x1030,
                                .text = "jmp",
                            },
                        },
                    .successors = {0x1030},
                },
                zara::ir::BasicBlock{
                    .start_address = 0x1020,
                    .instructions =
                        {
                            zara::ir::Instruction{
                                .address = 0x1020,
                                .kind = zara::ir::InstructionKind::Assign,
                                .destination = reg("eax"),
                                .inputs = {imm(3)},
                            },
                            zara::ir::Instruction{
                                .address = 0x1024,
                                .kind = zara::ir::InstructionKind::Branch,
                                .true_target = 0x1030,
                                .text = "jmp",
                            },
                        },
                    .successors = {0x1030},
                },
                zara::ir::BasicBlock{
                    .start_address = 0x1030,
                    .instructions =
                        {
                            zara::ir::Instruction{
                                .address = 0x1030,
                                .kind = zara::ir::InstructionKind::Assign,
                                .destination = reg("ebx"),
                                .inputs = {reg("eax")},
                            },
                            zara::ir::Instruction{
                                .address = 0x1034,
                                .kind = zara::ir::InstructionKind::Return,
                                .text = "ret",
                            },
                        },
                    .successors = {},
                },
            },
    };

    const auto ssa_function = zara::ssa::Builder::build(function);
    const auto block_it = std::find_if(
        ssa_function.blocks.begin(),
        ssa_function.blocks.end(),
        [](const zara::ssa::BasicBlock& block) { return block.start_address == 0x1030; }
    );
    if (block_it == ssa_function.blocks.end()) {
        std::cerr << "missing join block\n";
        return 1;
    }

    if (block_it->phi_nodes.size() != 1 || block_it->phi_nodes.front().variable != "eax") {
        std::cerr << "expected single phi node for eax\n";
        return 2;
    }

    const auto& phi = block_it->phi_nodes.front();
    if (phi.result_name.empty() || phi.result_name.rfind("eax.", 0) != 0) {
        std::cerr << "unexpected phi result name\n";
        return 3;
    }

    if (phi.incoming.size() != 2) {
        std::cerr << "expected two phi incoming values\n";
        return 4;
    }

    const auto has_true_incoming = std::any_of(
        phi.incoming.begin(),
        phi.incoming.end(),
        [](const auto& incoming) { return incoming.first == 0x1010 && incoming.second.rfind("eax.", 0) == 0; }
    );
    const auto has_false_incoming = std::any_of(
        phi.incoming.begin(),
        phi.incoming.end(),
        [](const auto& incoming) { return incoming.first == 0x1020 && incoming.second.rfind("eax.", 0) == 0; }
    );
    if (!has_true_incoming || !has_false_incoming) {
        std::cerr << "missing phi incoming edges\n";
        return 5;
    }

    if (block_it->instructions.empty() ||
        !block_it->instructions.front().inputs.size() ||
        block_it->instructions.front().inputs.front().name != phi.result_name) {
        std::cerr << "expected phi result to feed join-block use\n";
        return 6;
    }

    return 0;
}
