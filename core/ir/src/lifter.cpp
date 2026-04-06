#include "zara/ir/lifter.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <optional>
#include <sstream>
#include <unordered_set>
#include <utility>

namespace zara::ir {

namespace {

std::string lowercase_copy(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](const unsigned char character) { return static_cast<char>(std::tolower(character)); }
    );
    return value;
}

std::string hex_suffix(const std::uint64_t value) {
    std::ostringstream stream;
    stream << std::hex << std::uppercase << value;
    return stream.str();
}

ScalarType register_type(const std::string& register_name) {
    static const std::unordered_set<std::string> kPointerRegisters{
        "rip", "eip", "rsp", "esp", "rbp", "ebp", "sp", "x29", "fp", "r1", "r31",
    };
    static const std::unordered_set<std::string> kByteRegisters{
        "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh",
        "sil", "dil", "spl", "bpl",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    };
    static const std::unordered_set<std::string> kWordRegisters{
        "ax", "bx", "cx", "dx", "si", "di", "sp", "bp",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
        "ip",
    };

    if (register_name.empty()) {
        return ScalarType::Unknown;
    }

    if (kPointerRegisters.contains(register_name)) {
        return ScalarType::Pointer;
    }

    if (kByteRegisters.contains(register_name)) {
        return ScalarType::I8;
    }

    if (kWordRegisters.contains(register_name)) {
        return ScalarType::I16;
    }

    if (register_name.size() >= 2 && register_name[0] == 'e') {
        return ScalarType::I32;
    }

    if (register_name.size() >= 2 && register_name[0] == 'w' &&
        std::isdigit(static_cast<unsigned char>(register_name[1])) != 0) {
        return ScalarType::I32;
    }

    if (register_name.size() >= 2 && register_name[0] == 'x' &&
        std::isdigit(static_cast<unsigned char>(register_name[1])) != 0) {
        return ScalarType::I64;
    }

    if (register_name[0] == 'r') {
        return ScalarType::I64;
    }

    if (register_name[0] == 'a' || register_name[0] == 'v') {
        return ScalarType::I64;
    }

    return ScalarType::Unknown;
}

ScalarType coalesce_type(const ScalarType preferred_type, const ScalarType fallback_type) {
    return preferred_type == ScalarType::Unknown ? fallback_type : preferred_type;
}

ScalarType operand_type(const disasm::Operand& operand) {
    switch (operand.kind) {
    case disasm::OperandKind::Register:
        return register_type(operand.register_name);
    case disasm::OperandKind::Immediate:
    case disasm::OperandKind::Memory:
    case disasm::OperandKind::Unknown:
    default:
        return ScalarType::Unknown;
    }
}

Value make_register(std::string register_name) {
    return Value{
        .kind = ValueKind::Register,
        .type = register_type(register_name),
        .name = std::move(register_name),
    };
}

Value make_immediate(const std::int64_t immediate, const ScalarType type = ScalarType::Unknown) {
    return Value{
        .kind = ValueKind::Immediate,
        .type = type,
        .name = {},
        .immediate = immediate,
    };
}

Value make_memory_address(
    std::string base,
    std::string index,
    const std::int64_t displacement,
    const std::uint8_t scale,
    std::string segment = {}
) {
    return Value{
        .kind = ValueKind::MemoryAddress,
        .type = ScalarType::Pointer,
        .name = {},
        .immediate = 0,
        .memory =
            MemoryAddress{
                .segment = std::move(segment),
                .base = std::move(base),
                .index = std::move(index),
                .displacement = displacement,
                .scale = static_cast<std::uint8_t>(scale == 0 ? 1 : scale),
            },
    };
}

Value make_temporary(const std::uint64_t address, const std::size_t index, std::string_view prefix, const ScalarType type) {
    return Value{
        .kind = ValueKind::Temporary,
        .type = type,
        .name = std::string(prefix) + "_" + hex_suffix(address) + "_" + std::to_string(index),
    };
}

std::string stack_pointer_name(const loader::Architecture architecture) {
    switch (architecture) {
    case loader::Architecture::X86:
        return "esp";
    case loader::Architecture::X86_64:
        return "rsp";
    case loader::Architecture::ARM:
    case loader::Architecture::ARM64:
    case loader::Architecture::RISCV64:
    case loader::Architecture::MIPS64:
        return "sp";
    case loader::Architecture::PPC64:
        return "r1";
    case loader::Architecture::Unknown:
    default:
        return "sp";
    }
}

std::string frame_pointer_name(const loader::Architecture architecture) {
    switch (architecture) {
    case loader::Architecture::X86:
        return "ebp";
    case loader::Architecture::X86_64:
        return "rbp";
    case loader::Architecture::ARM:
        return "fp";
    case loader::Architecture::ARM64:
        return "x29";
    case loader::Architecture::RISCV64:
        return "s0";
    case loader::Architecture::MIPS64:
        return "fp";
    case loader::Architecture::PPC64:
        return "r31";
    case loader::Architecture::Unknown:
    default:
        return "bp";
    }
}

std::int64_t pointer_size(const loader::Architecture architecture) {
    switch (architecture) {
    case loader::Architecture::X86:
    case loader::Architecture::ARM:
        return 4;
    case loader::Architecture::X86_64:
    case loader::Architecture::ARM64:
    case loader::Architecture::RISCV64:
    case loader::Architecture::MIPS64:
    case loader::Architecture::PPC64:
        return 8;
    case loader::Architecture::Unknown:
    default:
        return 8;
    }
}

std::vector<std::string> call_argument_registers(const loader::Architecture architecture) {
    switch (architecture) {
    case loader::Architecture::X86_64:
        return {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
    case loader::Architecture::ARM:
        return {"r0", "r1", "r2", "r3"};
    case loader::Architecture::ARM64:
        return {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
    case loader::Architecture::RISCV64:
        return {"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"};
    case loader::Architecture::MIPS64:
        return {"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"};
    case loader::Architecture::PPC64:
        return {"r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"};
    case loader::Architecture::X86:
    case loader::Architecture::Unknown:
    default:
        return {};
    }
}

std::optional<std::uint64_t> fallthrough_successor(
    const cfg::BasicBlock& block,
    const std::optional<std::uint64_t> direct_target
) {
    for (const auto successor : block.successors) {
        if (!direct_target.has_value() || successor != *direct_target) {
            return successor;
        }
    }

    return std::nullopt;
}

struct LiftContext {
    BasicBlock* block = nullptr;
    loader::Architecture architecture = loader::Architecture::Unknown;
    std::size_t temp_index = 0;
    std::optional<Value> last_condition;

    [[nodiscard]] Value next_temporary(const std::uint64_t address, std::string_view prefix, const ScalarType type = ScalarType::Unknown) {
        return make_temporary(address, temp_index++, prefix, type);
    }

    void emit(Instruction instruction) {
        block->instructions.push_back(std::move(instruction));
    }
};

Value materialize_value(
    LiftContext& context,
    const disasm::Operand& operand,
    const std::uint64_t address,
    const ScalarType preferred_type = ScalarType::Unknown
) {
    switch (operand.kind) {
    case disasm::OperandKind::Register:
        return make_register(operand.register_name);
    case disasm::OperandKind::Immediate:
        return make_immediate(operand.immediate, coalesce_type(preferred_type, operand_type(operand)));
    case disasm::OperandKind::Memory: {
        const Value address_value = make_memory_address(
            operand.memory.base,
            operand.memory.index,
            operand.memory.displacement,
            operand.memory.scale,
            operand.memory.segment
        );
        Value temporary = context.next_temporary(address, "load", coalesce_type(preferred_type, operand_type(operand)));
        context.emit(
            Instruction{
                .address = address,
                .kind = InstructionKind::Load,
                .destination = temporary,
                .inputs = {address_value},
                .text = "materialize memory operand",
            }
        );
        return temporary;
    }
    case disasm::OperandKind::Unknown:
    default:
        return context.next_temporary(address, "unknown", preferred_type);
    }
}

Value address_value(const disasm::Operand& operand) {
    if (operand.kind != disasm::OperandKind::Memory) {
        return {};
    }

    return make_memory_address(
        operand.memory.base,
        operand.memory.index,
        operand.memory.displacement,
        operand.memory.scale,
        operand.memory.segment
    );
}

void emit_flags_update(LiftContext& context, const std::uint64_t address, const Value& source, std::string_view text) {
    Value flags = context.next_temporary(address, "flags", ScalarType::Bool);
    context.emit(
        Instruction{
            .address = address,
            .kind = InstructionKind::SetFlags,
            .destination = flags,
            .inputs = {source},
            .text = std::string(text),
        }
    );
    context.last_condition = flags;
}

void lift_binary_assignment(
    LiftContext& context,
    const disasm::Instruction& instruction,
    const BinaryOperator operation
) {
    if (instruction.decoded_operands.size() < 2) {
        context.emit(
            Instruction{
                .address = instruction.address,
                .kind = InstructionKind::Intrinsic,
                .text = instruction.mnemonic + " " + instruction.operands,
            }
        );
        return;
    }

    const disasm::Operand& destination = instruction.decoded_operands[0];
    const disasm::Operand& source = instruction.decoded_operands[1];

    if (destination.kind == disasm::OperandKind::Register) {
        const Value destination_register = make_register(destination.register_name);
        if (operation == BinaryOperator::Xor &&
            source.kind == disasm::OperandKind::Register &&
            lowercase_copy(source.register_name) == lowercase_copy(destination.register_name)) {
            context.emit(
                Instruction{
                    .address = instruction.address,
                    .kind = InstructionKind::Assign,
                    .destination = destination_register,
                    .inputs = {make_immediate(0, destination_register.type)},
                    .text = "zero register",
                }
            );
            emit_flags_update(context, instruction.address, destination_register, instruction.mnemonic);
            return;
        }

        const Value rhs = materialize_value(context, source, instruction.address, destination_register.type);
        context.emit(
            Instruction{
                .address = instruction.address,
                .kind = InstructionKind::Binary,
                .destination = destination_register,
                .inputs = {destination_register, rhs},
                .binary_operator = operation,
                .text = instruction.mnemonic,
            }
        );
        emit_flags_update(context, instruction.address, destination_register, instruction.mnemonic);
        return;
    }

    if (destination.kind == disasm::OperandKind::Memory) {
        const Value memory = address_value(destination);
        const Value current_value = materialize_value(context, destination, instruction.address);
        const Value rhs = materialize_value(context, source, instruction.address, current_value.type);
        const Value result = context.next_temporary(instruction.address, "arith", current_value.type);

        context.emit(
            Instruction{
                .address = instruction.address,
                .kind = InstructionKind::Binary,
                .destination = result,
                .inputs = {current_value, rhs},
                .binary_operator = operation,
                .text = instruction.mnemonic,
            }
        );
        context.emit(
            Instruction{
                .address = instruction.address,
                .kind = InstructionKind::Store,
                .inputs = {memory, result},
                .text = "write back arithmetic result",
            }
        );
        emit_flags_update(context, instruction.address, result, instruction.mnemonic);
        return;
    }

    context.emit(
        Instruction{
            .address = instruction.address,
            .kind = InstructionKind::Intrinsic,
            .text = instruction.mnemonic + " " + instruction.operands,
        }
    );
}

void lift_compare_like(
    LiftContext& context,
    const disasm::Instruction& instruction,
    const InstructionKind ir_kind
) {
    if (instruction.decoded_operands.size() < 2) {
        context.emit(
            Instruction{
                .address = instruction.address,
                .kind = InstructionKind::Intrinsic,
                .text = instruction.mnemonic + " " + instruction.operands,
            }
        );
        return;
    }

    const Value lhs = materialize_value(context, instruction.decoded_operands[0], instruction.address);
    const Value rhs = materialize_value(context, instruction.decoded_operands[1], instruction.address, lhs.type);
    Value flags = context.next_temporary(instruction.address, "flags", ScalarType::Bool);
    context.emit(
        Instruction{
            .address = instruction.address,
            .kind = ir_kind,
            .destination = flags,
            .inputs = {lhs, rhs},
            .text = instruction.mnemonic,
        }
    );
    context.last_condition = flags;
}

void lift_move_like(LiftContext& context, const disasm::Instruction& instruction) {
    if (instruction.decoded_operands.size() < 2) {
        context.emit(
            Instruction{
                .address = instruction.address,
                .kind = InstructionKind::Intrinsic,
                .text = instruction.mnemonic + " " + instruction.operands,
            }
        );
        return;
    }

    const disasm::Operand& destination = instruction.decoded_operands[0];
    const disasm::Operand& source = instruction.decoded_operands[1];

    if (destination.kind == disasm::OperandKind::Register) {
        const Value dest = make_register(destination.register_name);
        if (source.kind == disasm::OperandKind::Memory) {
            const Value address = address_value(source);
            context.emit(
                Instruction{
                    .address = instruction.address,
                    .kind = InstructionKind::Load,
                    .destination = dest,
                    .inputs = {address},
                    .text = instruction.mnemonic,
                }
            );
        } else {
            const Value src = materialize_value(context, source, instruction.address, dest.type);
            context.emit(
                Instruction{
                    .address = instruction.address,
                    .kind = InstructionKind::Assign,
                    .destination = dest,
                    .inputs = {src},
                    .text = instruction.mnemonic,
                }
            );
        }
        return;
    }

    if (destination.kind == disasm::OperandKind::Memory) {
        const Value destination_memory = address_value(destination);
        const Value source_value = materialize_value(context, source, instruction.address);
        context.emit(
            Instruction{
                .address = instruction.address,
                .kind = InstructionKind::Store,
                .inputs = {destination_memory, source_value},
                .text = instruction.mnemonic,
            }
        );
        return;
    }

    context.emit(
        Instruction{
            .address = instruction.address,
            .kind = InstructionKind::Intrinsic,
            .text = instruction.mnemonic + " " + instruction.operands,
        }
    );
}

void lift_lea(LiftContext& context, const disasm::Instruction& instruction) {
    if (instruction.decoded_operands.size() < 2 ||
        instruction.decoded_operands[0].kind != disasm::OperandKind::Register ||
        instruction.decoded_operands[1].kind != disasm::OperandKind::Memory) {
        context.emit(
            Instruction{
                .address = instruction.address,
                .kind = InstructionKind::Intrinsic,
                .text = instruction.mnemonic + " " + instruction.operands,
            }
        );
        return;
    }

    context.emit(
        Instruction{
            .address = instruction.address,
            .kind = InstructionKind::Assign,
            .destination = make_register(instruction.decoded_operands[0].register_name),
            .inputs = {address_value(instruction.decoded_operands[1])},
            .text = "effective address",
        }
    );
}

void lift_push(LiftContext& context, const disasm::Instruction& instruction) {
    if (instruction.decoded_operands.empty()) {
        context.emit(
            Instruction{
                .address = instruction.address,
                .kind = InstructionKind::Intrinsic,
                .text = instruction.mnemonic,
            }
        );
        return;
    }

    const Value stack_pointer = make_register(stack_pointer_name(context.architecture));
    const Value decremented = context.next_temporary(instruction.address, "sp", ScalarType::Pointer);
    context.emit(
        Instruction{
            .address = instruction.address,
            .kind = InstructionKind::Binary,
            .destination = decremented,
            .inputs = {stack_pointer, make_immediate(pointer_size(context.architecture), ScalarType::Pointer)},
            .binary_operator = BinaryOperator::Sub,
            .text = "push adjust stack",
        }
    );
    context.emit(
        Instruction{
            .address = instruction.address,
            .kind = InstructionKind::Assign,
            .destination = stack_pointer,
            .inputs = {decremented},
            .text = "push write stack pointer",
        }
    );
    context.emit(
        Instruction{
            .address = instruction.address,
            .kind = InstructionKind::Store,
            .inputs = {
                make_memory_address(decremented.name, {}, 0, 1),
                materialize_value(context, instruction.decoded_operands[0], instruction.address),
            },
            .text = "push store value",
        }
    );
}

void lift_pop(LiftContext& context, const disasm::Instruction& instruction) {
    const Value stack_pointer = make_register(stack_pointer_name(context.architecture));
    const Value loaded = context.next_temporary(instruction.address, "pop", ScalarType::Unknown);
    context.emit(
        Instruction{
            .address = instruction.address,
            .kind = InstructionKind::Load,
            .destination = loaded,
            .inputs = {make_memory_address(stack_pointer.name, {}, 0, 1)},
            .text = "pop load value",
        }
    );

    if (!instruction.decoded_operands.empty() && instruction.decoded_operands[0].kind == disasm::OperandKind::Register) {
        context.emit(
            Instruction{
                .address = instruction.address,
                .kind = InstructionKind::Assign,
                .destination = make_register(instruction.decoded_operands[0].register_name),
                .inputs = {loaded},
                .text = "pop assign destination",
            }
        );
    }

    const Value incremented = context.next_temporary(instruction.address, "sp", ScalarType::Pointer);
    context.emit(
        Instruction{
            .address = instruction.address,
            .kind = InstructionKind::Binary,
            .destination = incremented,
            .inputs = {stack_pointer, make_immediate(pointer_size(context.architecture), ScalarType::Pointer)},
            .binary_operator = BinaryOperator::Add,
            .text = "pop adjust stack",
        }
    );
    context.emit(
        Instruction{
            .address = instruction.address,
            .kind = InstructionKind::Assign,
            .destination = stack_pointer,
            .inputs = {incremented},
            .text = "pop write stack pointer",
        }
    );
}

void lift_leave(LiftContext& context, const disasm::Instruction& instruction) {
    const Value stack_pointer = make_register(stack_pointer_name(context.architecture));
    const Value frame_pointer = make_register(frame_pointer_name(context.architecture));
    context.emit(
        Instruction{
            .address = instruction.address,
            .kind = InstructionKind::Assign,
            .destination = stack_pointer,
            .inputs = {frame_pointer},
            .text = "leave move frame to stack",
        }
    );

    const Value restored_frame = context.next_temporary(instruction.address, "frame", frame_pointer.type);
    context.emit(
        Instruction{
            .address = instruction.address,
            .kind = InstructionKind::Load,
            .destination = restored_frame,
            .inputs = {make_memory_address(stack_pointer.name, {}, 0, 1)},
            .text = "leave restore frame pointer",
        }
    );

    const Value incremented = context.next_temporary(instruction.address, "sp", ScalarType::Pointer);
    context.emit(
        Instruction{
            .address = instruction.address,
            .kind = InstructionKind::Binary,
            .destination = incremented,
            .inputs = {stack_pointer, make_immediate(pointer_size(context.architecture), ScalarType::Pointer)},
            .binary_operator = BinaryOperator::Add,
            .text = "leave advance stack",
        }
    );
    context.emit(
        Instruction{
            .address = instruction.address,
            .kind = InstructionKind::Assign,
            .destination = frame_pointer,
            .inputs = {restored_frame},
            .text = "leave assign frame pointer",
        }
    );
    context.emit(
        Instruction{
            .address = instruction.address,
            .kind = InstructionKind::Assign,
            .destination = stack_pointer,
            .inputs = {incremented},
            .text = "leave assign stack pointer",
        }
    );
}

Instruction intrinsic_from(const disasm::Instruction& instruction) {
    return Instruction{
        .address = instruction.address,
        .kind = InstructionKind::Intrinsic,
        .text = instruction.mnemonic + (instruction.operands.empty() ? "" : " " + instruction.operands),
    };
}

}  // namespace

Function Lifter::lift(const cfg::FunctionGraph& graph, const loader::Architecture architecture) {
    Function function;
    function.name = graph.name();
    function.entry_address = graph.entry_address();
    function.blocks.reserve(graph.blocks().size());

    for (const auto& block : graph.blocks()) {
        BasicBlock lifted_block;
        lifted_block.start_address = block.start_address;
        lifted_block.successors = block.successors;

        LiftContext context{
            .block = &lifted_block,
            .architecture = architecture,
            .temp_index = 0,
            .last_condition = std::nullopt,
        };

        for (const auto& instruction : block.instructions) {
            const std::string mnemonic = lowercase_copy(instruction.mnemonic);

            if (instruction.kind == disasm::InstructionKind::Return) {
                context.emit(
                    Instruction{
                        .address = instruction.address,
                        .kind = InstructionKind::Return,
                        .text = instruction.mnemonic,
                    }
                );
                continue;
            }

            if (instruction.kind == disasm::InstructionKind::Call) {
                Instruction call{
                    .address = instruction.address,
                    .kind = InstructionKind::Call,
                    .text = instruction.mnemonic,
                };
                if (instruction.control_flow_target.has_value()) {
                    call.true_target = instruction.control_flow_target;
                } else if (!instruction.decoded_operands.empty()) {
                    call.inputs.push_back(materialize_value(context, instruction.decoded_operands.front(), instruction.address, ScalarType::Pointer));
                }
                for (const auto& argument_register : call_argument_registers(context.architecture)) {
                    call.inputs.push_back(make_register(argument_register));
                }
                context.emit(std::move(call));
                continue;
            }

            if (instruction.kind == disasm::InstructionKind::Jump) {
                Instruction branch{
                    .address = instruction.address,
                    .kind = InstructionKind::Branch,
                    .text = instruction.mnemonic,
                };
                if (instruction.control_flow_target.has_value()) {
                    branch.true_target = instruction.control_flow_target;
                } else if (!instruction.decoded_operands.empty()) {
                    branch.inputs.push_back(materialize_value(context, instruction.decoded_operands.front(), instruction.address, ScalarType::Pointer));
                }
                context.emit(std::move(branch));
                continue;
            }

            if (instruction.kind == disasm::InstructionKind::ConditionalJump) {
                Instruction branch{
                    .address = instruction.address,
                    .kind = InstructionKind::CondBranch,
                    .text = instruction.mnemonic,
                };
                if (context.last_condition.has_value()) {
                    branch.inputs.push_back(*context.last_condition);
                }
                branch.true_target = instruction.control_flow_target;
                branch.false_target = fallthrough_successor(block, instruction.control_flow_target);
                context.emit(std::move(branch));
                continue;
            }

            if (mnemonic == "mov" || mnemonic == "movzx" || mnemonic == "movsx" || mnemonic == "movsxd" || mnemonic == "movabs") {
                lift_move_like(context, instruction);
                continue;
            }

            if (mnemonic == "lea") {
                lift_lea(context, instruction);
                continue;
            }

            if (mnemonic == "add") {
                lift_binary_assignment(context, instruction, BinaryOperator::Add);
                continue;
            }

            if (mnemonic == "sub") {
                lift_binary_assignment(context, instruction, BinaryOperator::Sub);
                continue;
            }

            if (mnemonic == "and") {
                lift_binary_assignment(context, instruction, BinaryOperator::And);
                continue;
            }

            if (mnemonic == "or") {
                lift_binary_assignment(context, instruction, BinaryOperator::Or);
                continue;
            }

            if (mnemonic == "xor") {
                lift_binary_assignment(context, instruction, BinaryOperator::Xor);
                continue;
            }

            if (mnemonic == "cmp") {
                lift_compare_like(context, instruction, InstructionKind::Compare);
                continue;
            }

            if (mnemonic == "test") {
                lift_compare_like(context, instruction, InstructionKind::Test);
                continue;
            }

            if (mnemonic == "push") {
                lift_push(context, instruction);
                continue;
            }

            if (mnemonic == "pop") {
                lift_pop(context, instruction);
                continue;
            }

            if (mnemonic == "leave") {
                lift_leave(context, instruction);
                continue;
            }

            if (mnemonic == "nop" || mnemonic == "endbr64") {
                context.emit(
                    Instruction{
                        .address = instruction.address,
                        .kind = InstructionKind::Nop,
                        .text = instruction.mnemonic,
                    }
                );
                continue;
            }

            if (instruction.kind == disasm::InstructionKind::DataByte) {
                context.emit(intrinsic_from(instruction));
                continue;
            }

            context.emit(intrinsic_from(instruction));
        }

        function.blocks.push_back(std::move(lifted_block));
    }

    return function;
}

std::string_view to_string(const ScalarType type) noexcept {
    switch (type) {
    case ScalarType::Bool:
        return "bool";
    case ScalarType::I8:
        return "i8";
    case ScalarType::I16:
        return "i16";
    case ScalarType::I32:
        return "i32";
    case ScalarType::I64:
        return "i64";
    case ScalarType::Pointer:
        return "ptr";
    case ScalarType::Unknown:
    default:
        return "unknown";
    }
}

std::string_view to_string(const ValueKind kind) noexcept {
    switch (kind) {
    case ValueKind::Register:
        return "register";
    case ValueKind::Immediate:
        return "immediate";
    case ValueKind::MemoryAddress:
        return "memory_address";
    case ValueKind::Temporary:
        return "temporary";
    case ValueKind::Invalid:
    default:
        return "invalid";
    }
}

std::string_view to_string(const BinaryOperator operation) noexcept {
    switch (operation) {
    case BinaryOperator::Add:
        return "add";
    case BinaryOperator::Sub:
        return "sub";
    case BinaryOperator::And:
        return "and";
    case BinaryOperator::Or:
        return "or";
    case BinaryOperator::Xor:
        return "xor";
    default:
        return "binary";
    }
}

std::string_view to_string(const InstructionKind kind) noexcept {
    switch (kind) {
    case InstructionKind::Assign:
        return "assign";
    case InstructionKind::Load:
        return "load";
    case InstructionKind::Store:
        return "store";
    case InstructionKind::Binary:
        return "binary";
    case InstructionKind::Compare:
        return "compare";
    case InstructionKind::Test:
        return "test";
    case InstructionKind::SetFlags:
        return "set_flags";
    case InstructionKind::Call:
        return "call";
    case InstructionKind::Branch:
        return "branch";
    case InstructionKind::CondBranch:
        return "cond_branch";
    case InstructionKind::Return:
        return "return";
    case InstructionKind::Nop:
        return "nop";
    case InstructionKind::Intrinsic:
    default:
        return "intrinsic";
    }
}

std::string format_value(const Value& value) {
    switch (value.kind) {
    case ValueKind::Register:
    case ValueKind::Temporary:
        return value.name;
    case ValueKind::Immediate: {
        std::ostringstream stream;
        stream << value.immediate;
        return stream.str();
    }
    case ValueKind::MemoryAddress: {
        std::ostringstream stream;
        if (!value.memory.segment.empty()) {
            stream << value.memory.segment << ':';
        }
        stream << '[';
        bool needs_separator = false;
        if (!value.memory.base.empty()) {
            stream << value.memory.base;
            needs_separator = true;
        }
        if (!value.memory.index.empty()) {
            if (needs_separator) {
                stream << " + ";
            }
            stream << value.memory.index;
            if (value.memory.scale > 1) {
                stream << '*' << static_cast<unsigned int>(value.memory.scale);
            }
            needs_separator = true;
        }
        if (value.memory.displacement != 0 || !needs_separator) {
            if (needs_separator) {
                stream << (value.memory.displacement >= 0 ? " + " : " - ");
                stream << std::llabs(value.memory.displacement);
            } else {
                stream << value.memory.displacement;
            }
        }
        stream << ']';
        return stream.str();
    }
    case ValueKind::Invalid:
    default:
        return "<invalid>";
    }
}

std::string format_instruction(const Instruction& instruction) {
    std::ostringstream stream;
    stream << to_string(instruction.kind);

    if (instruction.kind == InstructionKind::Binary && instruction.binary_operator.has_value()) {
        stream << '.' << to_string(*instruction.binary_operator);
    }

    if (instruction.destination.has_value()) {
        stream << ' ' << format_value(*instruction.destination) << " =";
    }

    if (!instruction.inputs.empty()) {
        stream << ' ';
        for (std::size_t index = 0; index < instruction.inputs.size(); ++index) {
            if (index > 0) {
                stream << ", ";
            }
            stream << format_value(instruction.inputs[index]);
        }
    }

    if (instruction.true_target.has_value()) {
        stream << " -> 0x" << std::hex << std::uppercase << *instruction.true_target << std::dec;
    }
    if (instruction.false_target.has_value()) {
        stream << ", else 0x" << std::hex << std::uppercase << *instruction.false_target << std::dec;
    }

    if (!instruction.text.empty()) {
        stream << "    ; " << instruction.text;
    }

    return stream.str();
}

}  // namespace zara::ir
