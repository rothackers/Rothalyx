#include <cstdint>
#include <iostream>
#include <vector>

#include "zara/decompiler/decompiler.hpp"

namespace {

zara::disasm::Instruction make_instruction(
    const std::uint64_t address,
    const std::string& mnemonic,
    const zara::disasm::InstructionKind kind = zara::disasm::InstructionKind::Instruction
) {
    return zara::disasm::Instruction{
        .address = address,
        .size = 1,
        .kind = kind,
        .bytes = {0x90},
        .mnemonic = mnemonic,
        .operands = {},
        .decoded_operands = {},
        .control_flow_target = std::nullopt,
        .data_references = {},
    };
}

zara::ir::Value reg(const char* name, const zara::ir::ScalarType type = zara::ir::ScalarType::I32) {
    return zara::ir::Value{
        .kind = zara::ir::ValueKind::Register,
        .type = type,
        .name = name,
    };
}

zara::ir::Value temp(const char* name, const zara::ir::ScalarType type = zara::ir::ScalarType::I32) {
    return zara::ir::Value{
        .kind = zara::ir::ValueKind::Temporary,
        .type = type,
        .name = name,
    };
}

zara::ir::Value imm(const std::int64_t value, const zara::ir::ScalarType type = zara::ir::ScalarType::I64) {
    return zara::ir::Value{
        .kind = zara::ir::ValueKind::Immediate,
        .type = type,
        .immediate = value,
    };
}

zara::ir::Value mem(const char* base, const std::int64_t displacement, const zara::ir::ScalarType type) {
    return zara::ir::Value{
        .kind = zara::ir::ValueKind::MemoryAddress,
        .type = type,
        .memory =
            zara::ir::MemoryAddress{
                .segment = {},
                .base = base,
                .index = {},
                .displacement = displacement,
                .scale = 1,
            },
    };
}

}  // namespace

int main() {
    const auto graph = zara::cfg::FunctionGraph::from_linear(
        "decompiler_quality",
        {
            make_instruction(0x1000, "mov"),
            make_instruction(0x1004, "mov"),
            make_instruction(0x1008, "mov"),
            make_instruction(0x100C, "ret", zara::disasm::InstructionKind::Return),
        }
    );

    const zara::ssa::Function function{
        .name = "decompiler_quality",
        .entry_address = 0x1000,
        .blocks =
            {
                zara::ssa::BasicBlock{
                    .start_address = 0x1000,
                    .phi_nodes = {},
                    .instructions =
                        {
                            zara::ir::Instruction{
                                .address = 0x1000,
                                .kind = zara::ir::InstructionKind::Assign,
                                .destination = reg("sp.0", zara::ir::ScalarType::Pointer),
                                .inputs = {imm(0, zara::ir::ScalarType::Pointer)},
                            },
                            zara::ir::Instruction{
                                .address = 0x1001,
                                .kind = zara::ir::InstructionKind::Assign,
                                .destination = reg("frame.0", zara::ir::ScalarType::Pointer),
                                .inputs = {imm(0, zara::ir::ScalarType::Pointer)},
                            },
                            zara::ir::Instruction{
                                .address = 0x1004,
                                .kind = zara::ir::InstructionKind::Load,
                                .destination = temp("load_0", zara::ir::ScalarType::I32),
                                .inputs = {mem("rdi.0", 4, zara::ir::ScalarType::I32)},
                            },
                            zara::ir::Instruction{
                                .address = 0x1008,
                                .kind = zara::ir::InstructionKind::Store,
                                .inputs =
                                    {
                                        mem("rdi.0", 12, zara::ir::ScalarType::I32),
                                        temp("load_0", zara::ir::ScalarType::I32),
                                    },
                            },
                            zara::ir::Instruction{
                                .address = 0x100C,
                                .kind = zara::ir::InstructionKind::Return,
                                .text = "ret",
                            },
                        },
                    .predecessors = {},
                    .successors = {},
                },
            },
        .immediate_dominators = {},
    };

    zara::type::FunctionTypes recovered_types{
        .variables =
            {
                zara::type::RecoveredVariable{.name = "rdi.0", .type = zara::ir::ScalarType::Pointer},
                zara::type::RecoveredVariable{.name = "sp.0", .type = zara::ir::ScalarType::Pointer},
                zara::type::RecoveredVariable{.name = "frame.0", .type = zara::ir::ScalarType::Pointer},
                zara::type::RecoveredVariable{.name = "load_0", .type = zara::ir::ScalarType::I32},
            },
        .structs =
            {
                zara::type::RecoveredStruct{
                    .owner_name = "rdi.0",
                    .type_name = "widget",
                    .fields =
                        {
                            zara::type::RecoveredStructField{
                                .name = "field_4",
                                .offset = 4,
                                .size = 4,
                                .type = zara::ir::ScalarType::I32,
                            },
                            zara::type::RecoveredStructField{
                                .name = "field_12",
                                .offset = 12,
                                .size = 4,
                                .type = zara::ir::ScalarType::I32,
                            },
                        },
                },
            },
        .arrays = {},
    };

    const auto decompiled = zara::decompiler::Decompiler::decompile(graph, function, recovered_types);
    if (decompiled.pseudocode.find("struct widget {") == std::string::npos ||
        decompiled.pseudocode.find("int32_t field_4;") == std::string::npos ||
        decompiled.pseudocode.find("int32_t field_12;") == std::string::npos) {
        std::cerr << "expected recovered struct definitions in pseudocode\n";
        return 1;
    }
    if (decompiled.pseudocode.find("widget* arg_0") == std::string::npos) {
        std::cerr << "expected recovered struct type on the argument\n";
        return 2;
    }
    if (decompiled.pseudocode.find("arg_0->field_12 = arg_0->field_4;") == std::string::npos) {
        std::cerr << "expected typed and inlined struct access in pseudocode\n";
        return 3;
    }
    if (decompiled.pseudocode.find("stack_temp") != std::string::npos ||
        decompiled.pseudocode.find("frame_temp") != std::string::npos ||
        decompiled.pseudocode.find("loaded_value") != std::string::npos) {
        std::cerr << "expected decompiler to suppress temporary/noise locals\n";
        return 4;
    }

    return 0;
}
