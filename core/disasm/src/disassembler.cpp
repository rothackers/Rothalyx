#include "zara/disasm/disassembler.hpp"

#if defined(ZARA_HAS_CAPSTONE)
#include <capstone/capstone.h>
#if defined(CS_ARCH_RISCV) && defined(CS_MODE_RISCV64) && defined(CS_MODE_RISCVC) && \
    defined(RISCV_OP_INVALID) && defined(RISCV_OP_REG) && defined(RISCV_OP_IMM) && \
    defined(RISCV_OP_MEM) && defined(RISCV_REG_INVALID)
#define ZARA_CAPSTONE_HAS_RISCV 1
#else
#define ZARA_CAPSTONE_HAS_RISCV 0
#endif
#endif

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <optional>
#include <sstream>

namespace zara::disasm {

namespace {

constexpr ArchitectureDescriptor kUnknownDescriptor{
    .architecture = loader::Architecture::Unknown,
    .name = "unknown",
    .pointer_size = 0,
    .instruction_alignment = 1,
    .stack_pointer = {},
    .frame_pointer = {},
    .link_register = {},
};

constexpr ArchitectureDescriptor kX86Descriptor{
    .architecture = loader::Architecture::X86,
    .name = "x86",
    .pointer_size = 4,
    .instruction_alignment = 1,
    .stack_pointer = "esp",
    .frame_pointer = "ebp",
    .link_register = {},
};

constexpr ArchitectureDescriptor kX86_64Descriptor{
    .architecture = loader::Architecture::X86_64,
    .name = "x86_64",
    .pointer_size = 8,
    .instruction_alignment = 1,
    .stack_pointer = "rsp",
    .frame_pointer = "rbp",
    .link_register = {},
};

constexpr ArchitectureDescriptor kArmDescriptor{
    .architecture = loader::Architecture::ARM,
    .name = "arm",
    .pointer_size = 4,
    .instruction_alignment = 4,
    .stack_pointer = "sp",
    .frame_pointer = "fp",
    .link_register = "lr",
};

constexpr ArchitectureDescriptor kArm64Descriptor{
    .architecture = loader::Architecture::ARM64,
    .name = "arm64",
    .pointer_size = 8,
    .instruction_alignment = 4,
    .stack_pointer = "sp",
    .frame_pointer = "x29",
    .link_register = "x30",
};

constexpr ArchitectureDescriptor kRiscV64Descriptor{
    .architecture = loader::Architecture::RISCV64,
    .name = "riscv64",
    .pointer_size = 8,
    .instruction_alignment = 2,
    .stack_pointer = "sp",
    .frame_pointer = "s0",
    .link_register = "ra",
};

constexpr ArchitectureDescriptor kMips64Descriptor{
    .architecture = loader::Architecture::MIPS64,
    .name = "mips64",
    .pointer_size = 8,
    .instruction_alignment = 4,
    .stack_pointer = "sp",
    .frame_pointer = "fp",
    .link_register = "ra",
};

constexpr ArchitectureDescriptor kPpc64Descriptor{
    .architecture = loader::Architecture::PPC64,
    .name = "ppc64",
    .pointer_size = 8,
    .instruction_alignment = 4,
    .stack_pointer = "r1",
    .frame_pointer = "r31",
    .link_register = "lr",
};

std::string format_hex_byte(const std::uint8_t value) {
    std::ostringstream stream;
    stream << "0x";
    stream.setf(std::ios::hex, std::ios::basefield);
    stream.setf(std::ios::uppercase);
    if (value < 0x10) {
        stream << '0';
    }
    stream << static_cast<unsigned int>(value);
    return stream.str();
}

std::vector<Instruction> decode_as_data_bytes(
    const std::vector<std::byte>& raw_bytes,
    const std::uint64_t start_address
) {
    std::vector<Instruction> instructions;
    instructions.reserve(raw_bytes.size());

    for (std::size_t index = 0; index < raw_bytes.size(); ++index) {
        const auto value = static_cast<std::uint8_t>(std::to_integer<unsigned int>(raw_bytes[index]));
        instructions.push_back(
            Instruction{
                .address = start_address + index,
                .size = 1,
                .kind = InstructionKind::DataByte,
                .bytes = {value},
                .mnemonic = "db",
                .operands = format_hex_byte(value),
                .decoded_operands = {},
                .control_flow_target = std::nullopt,
                .data_references = {},
            }
        );
    }

    return instructions;
}

#if defined(ZARA_HAS_CAPSTONE)
bool capstone_mode_for_architecture(const loader::Architecture architecture, cs_arch& out_arch, cs_mode& out_mode) {
    switch (architecture) {
    case loader::Architecture::X86:
        out_arch = CS_ARCH_X86;
        out_mode = static_cast<cs_mode>(CS_MODE_32 | CS_MODE_LITTLE_ENDIAN);
        return true;
    case loader::Architecture::X86_64:
        out_arch = CS_ARCH_X86;
        out_mode = static_cast<cs_mode>(CS_MODE_64 | CS_MODE_LITTLE_ENDIAN);
        return true;
    case loader::Architecture::ARM:
        out_arch = CS_ARCH_ARM;
        out_mode = static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN);
        return true;
    case loader::Architecture::ARM64:
        out_arch = CS_ARCH_ARM64;
        out_mode = static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN);
        return true;
    case loader::Architecture::RISCV64:
#if ZARA_CAPSTONE_HAS_RISCV
        out_arch = CS_ARCH_RISCV;
        out_mode = static_cast<cs_mode>(CS_MODE_RISCV64 | CS_MODE_RISCVC | CS_MODE_LITTLE_ENDIAN);
        return true;
#else
        return false;
#endif
    case loader::Architecture::MIPS64:
        out_arch = CS_ARCH_MIPS;
        out_mode = static_cast<cs_mode>(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN);
        return true;
    case loader::Architecture::PPC64:
        out_arch = CS_ARCH_PPC;
        out_mode = static_cast<cs_mode>(CS_MODE_64 | CS_MODE_LITTLE_ENDIAN);
        return true;
    case loader::Architecture::Unknown:
    default:
        return false;
    }
}

InstructionKind classify_instruction(
    csh handle,
    const cs_insn& instruction,
    const loader::Architecture architecture
) {
    if (cs_insn_group(handle, &instruction, CS_GRP_CALL)) {
        return InstructionKind::Call;
    }

    if (cs_insn_group(handle, &instruction, CS_GRP_RET)) {
        return InstructionKind::Return;
    }

    if (cs_insn_group(handle, &instruction, CS_GRP_INT)) {
        return InstructionKind::Interrupt;
    }

    if (cs_insn_group(handle, &instruction, CS_GRP_JUMP)) {
        if (architecture == loader::Architecture::X86 || architecture == loader::Architecture::X86_64) {
            if (instruction.id == X86_INS_JMP || instruction.id == X86_INS_LJMP) {
                return InstructionKind::Jump;
            }

            return InstructionKind::ConditionalJump;
        }

        if (architecture == loader::Architecture::ARM) {
            const std::string mnemonic = instruction.mnemonic;
            std::string operands = instruction.op_str;
            std::transform(
                operands.begin(),
                operands.end(),
                operands.begin(),
                [](const unsigned char character) { return static_cast<char>(std::tolower(character)); }
            );
            if ((mnemonic == "bx" && operands == "lr") ||
                (mnemonic == "mov" && operands == "pc, lr") ||
                (mnemonic == "pop" && operands.find("pc") != std::string::npos)) {
                return InstructionKind::Return;
            }

            if (mnemonic == "b" || mnemonic == "bx") {
                return InstructionKind::Jump;
            }

            return InstructionKind::ConditionalJump;
        }

        if (architecture == loader::Architecture::RISCV64) {
            const std::string mnemonic = instruction.mnemonic;
            if (mnemonic == "ret") {
                return InstructionKind::Return;
            }
            if (mnemonic == "j" || mnemonic == "jr" || mnemonic == "c.j" || mnemonic == "c.jr") {
                return InstructionKind::Jump;
            }
            return InstructionKind::ConditionalJump;
        }

        if (architecture == loader::Architecture::MIPS64) {
            const std::string mnemonic = instruction.mnemonic;
            std::string operands = instruction.op_str;
            std::transform(
                operands.begin(),
                operands.end(),
                operands.begin(),
                [](const unsigned char character) { return static_cast<char>(std::tolower(character)); }
            );
            if ((mnemonic == "jr" || mnemonic == "jr64" || mnemonic == "jrc") && operands == "ra") {
                return InstructionKind::Return;
            }
            if (mnemonic == "j" || mnemonic == "jr" || mnemonic == "jr64" || mnemonic == "jrc" || mnemonic == "b") {
                return InstructionKind::Jump;
            }
            return InstructionKind::ConditionalJump;
        }

        if (architecture == loader::Architecture::PPC64) {
            const std::string mnemonic = instruction.mnemonic;
            if (mnemonic == "blr" || mnemonic == "blrl" || mnemonic == "bclr") {
                return InstructionKind::Return;
            }
            if (mnemonic == "b" || mnemonic == "ba" || mnemonic == "bctr" || mnemonic == "bcctr") {
                return InstructionKind::Jump;
            }
            return InstructionKind::ConditionalJump;
        }

        const std::string mnemonic = instruction.mnemonic;
        if (mnemonic == "b" || mnemonic == "br") {
            return InstructionKind::Jump;
        }

        return InstructionKind::ConditionalJump;
    }

    return InstructionKind::Instruction;
}

std::optional<std::uint64_t> extract_control_flow_target(
    const cs_insn& instruction,
    const loader::Architecture architecture
) {
    if (instruction.detail == nullptr) {
        return std::nullopt;
    }

    if (architecture == loader::Architecture::X86 || architecture == loader::Architecture::X86_64) {
        const cs_x86& x86 = instruction.detail->x86;
        for (std::uint8_t operand_index = 0; operand_index < x86.op_count; ++operand_index) {
            const cs_x86_op& operand = x86.operands[operand_index];
            if (operand.type == X86_OP_IMM && operand.imm >= 0) {
                return static_cast<std::uint64_t>(operand.imm);
            }
        }
    } else if (architecture == loader::Architecture::ARM) {
        const cs_arm& arm = instruction.detail->arm;
        for (std::uint8_t operand_index = 0; operand_index < arm.op_count; ++operand_index) {
            const cs_arm_op& operand = arm.operands[operand_index];
            if (operand.type == ARM_OP_IMM && operand.imm >= 0) {
                return static_cast<std::uint64_t>(operand.imm);
            }
        }
    } else if (architecture == loader::Architecture::ARM64) {
        const cs_arm64& arm64 = instruction.detail->arm64;
        for (std::uint8_t operand_index = 0; operand_index < arm64.op_count; ++operand_index) {
            const cs_arm64_op& operand = arm64.operands[operand_index];
            if (operand.type == ARM64_OP_IMM && operand.imm >= 0) {
                return static_cast<std::uint64_t>(operand.imm);
            }
        }
    } else if (architecture == loader::Architecture::RISCV64) {
#if ZARA_CAPSTONE_HAS_RISCV
        const cs_riscv& riscv = instruction.detail->riscv;
        for (std::uint8_t operand_index = 0; operand_index < riscv.op_count; ++operand_index) {
            const cs_riscv_op& operand = riscv.operands[operand_index];
            if (operand.type == RISCV_OP_IMM && operand.imm >= 0) {
                return static_cast<std::uint64_t>(operand.imm);
            }
        }
#endif
    } else if (architecture == loader::Architecture::MIPS64) {
        const cs_mips& mips = instruction.detail->mips;
        for (std::uint8_t operand_index = 0; operand_index < mips.op_count; ++operand_index) {
            const cs_mips_op& operand = mips.operands[operand_index];
            if (operand.type == MIPS_OP_IMM && operand.imm >= 0) {
                return static_cast<std::uint64_t>(operand.imm);
            }
        }
    } else if (architecture == loader::Architecture::PPC64) {
        const cs_ppc& ppc = instruction.detail->ppc;
        for (std::uint8_t operand_index = 0; operand_index < ppc.op_count; ++operand_index) {
            const cs_ppc_op& operand = ppc.operands[operand_index];
            if (operand.type == PPC_OP_IMM && operand.imm >= 0) {
                return static_cast<std::uint64_t>(operand.imm);
            }
        }
    }

    return std::nullopt;
}

std::vector<std::uint64_t> extract_data_references(
    const cs_insn& instruction,
    const loader::Architecture architecture
) {
    std::vector<std::uint64_t> references;

    if (instruction.detail == nullptr) {
        return references;
    }

    if (architecture == loader::Architecture::X86 || architecture == loader::Architecture::X86_64) {
        const cs_x86& x86 = instruction.detail->x86;
        for (std::uint8_t operand_index = 0; operand_index < x86.op_count; ++operand_index) {
            const cs_x86_op& operand = x86.operands[operand_index];
            if (operand.type != X86_OP_MEM) {
                continue;
            }

            std::optional<std::uint64_t> target;
            if (operand.mem.base == X86_REG_RIP) {
                const auto next_address = instruction.address + instruction.size;
                target = static_cast<std::uint64_t>(
                    static_cast<std::int64_t>(next_address) + operand.mem.disp
                );
            } else if (operand.mem.base == X86_REG_INVALID && operand.mem.index == X86_REG_INVALID && operand.mem.disp >= 0) {
                target = static_cast<std::uint64_t>(operand.mem.disp);
            }

            if (target.has_value()) {
                references.push_back(*target);
            }
        }
    } else if (architecture == loader::Architecture::ARM) {
        const cs_arm& arm = instruction.detail->arm;
        for (std::uint8_t operand_index = 0; operand_index < arm.op_count; ++operand_index) {
            const cs_arm_op& operand = arm.operands[operand_index];
            if (operand.type == ARM_OP_IMM && operand.imm >= 0) {
                const std::string mnemonic = instruction.mnemonic;
                if (mnemonic == "adr") {
                    references.push_back(static_cast<std::uint64_t>(operand.imm));
                }
                continue;
            }

            if (operand.type != ARM_OP_MEM) {
                continue;
            }

            std::optional<std::uint64_t> target;
            if (operand.mem.base == ARM_REG_PC) {
                const auto pc_base = instruction.address + 8;
                target = static_cast<std::uint64_t>(static_cast<std::int64_t>(pc_base) + operand.mem.disp);
            } else if (operand.mem.base == ARM_REG_INVALID && operand.mem.index == ARM_REG_INVALID && operand.mem.disp >= 0) {
                target = static_cast<std::uint64_t>(operand.mem.disp);
            }

            if (target.has_value()) {
                references.push_back(*target);
            }
        }
    } else if (architecture == loader::Architecture::ARM64) {
        const cs_arm64& arm64 = instruction.detail->arm64;
        for (std::uint8_t operand_index = 0; operand_index < arm64.op_count; ++operand_index) {
            const cs_arm64_op& operand = arm64.operands[operand_index];
            if (operand.type == ARM64_OP_IMM && operand.imm >= 0) {
                const std::string mnemonic = instruction.mnemonic;
                if (mnemonic == "adr" || mnemonic == "adrp") {
                    references.push_back(static_cast<std::uint64_t>(operand.imm));
                }
            }
        }
    } else if (architecture == loader::Architecture::RISCV64) {
#if ZARA_CAPSTONE_HAS_RISCV
        const cs_riscv& riscv = instruction.detail->riscv;
        for (std::uint8_t operand_index = 0; operand_index < riscv.op_count; ++operand_index) {
            const cs_riscv_op& operand = riscv.operands[operand_index];
            if (operand.type == RISCV_OP_MEM && operand.mem.base == RISCV_REG_INVALID && operand.mem.disp >= 0) {
                references.push_back(static_cast<std::uint64_t>(operand.mem.disp));
            } else if (operand.type == RISCV_OP_IMM && operand.imm >= 0 && instruction.mnemonic == std::string("auipc")) {
                references.push_back(static_cast<std::uint64_t>(operand.imm));
            }
        }
#endif
    } else if (architecture == loader::Architecture::MIPS64) {
        const cs_mips& mips = instruction.detail->mips;
        for (std::uint8_t operand_index = 0; operand_index < mips.op_count; ++operand_index) {
            const cs_mips_op& operand = mips.operands[operand_index];
            if (operand.type == MIPS_OP_MEM && operand.mem.base == MIPS_REG_INVALID && operand.mem.disp >= 0) {
                references.push_back(static_cast<std::uint64_t>(operand.mem.disp));
            }
        }
    } else if (architecture == loader::Architecture::PPC64) {
        const cs_ppc& ppc = instruction.detail->ppc;
        for (std::uint8_t operand_index = 0; operand_index < ppc.op_count; ++operand_index) {
            const cs_ppc_op& operand = ppc.operands[operand_index];
            if (operand.type == PPC_OP_MEM && operand.mem.base == PPC_REG_INVALID && operand.mem.disp >= 0) {
                references.push_back(static_cast<std::uint64_t>(operand.mem.disp));
            }
        }
    }

    std::sort(references.begin(), references.end());
    references.erase(std::unique(references.begin(), references.end()), references.end());
    return references;
}

std::string lowercase_copy(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](const unsigned char character) { return static_cast<char>(std::tolower(character)); }
    );
    return value;
}

std::string register_name(csh handle, const unsigned int register_id) {
    if (register_id == 0) {
        return {};
    }

    const char* raw_name = cs_reg_name(handle, register_id);
    if (raw_name == nullptr) {
        return {};
    }

    return lowercase_copy(raw_name);
}

std::vector<Operand> extract_operands(
    csh handle,
    const cs_insn& instruction,
    const loader::Architecture architecture
) {
    std::vector<Operand> operands;

    if (instruction.detail == nullptr) {
        return operands;
    }

    if (architecture == loader::Architecture::X86 || architecture == loader::Architecture::X86_64) {
        const cs_x86& x86 = instruction.detail->x86;
        operands.reserve(x86.op_count);

        for (std::uint8_t operand_index = 0; operand_index < x86.op_count; ++operand_index) {
            const cs_x86_op& x86_operand = x86.operands[operand_index];
            Operand operand;
            operand.is_read = x86_operand.access == 0 || (x86_operand.access & CS_AC_READ) != 0;
            operand.is_write = (x86_operand.access & CS_AC_WRITE) != 0;

            switch (x86_operand.type) {
            case X86_OP_REG:
                operand.kind = OperandKind::Register;
                operand.register_name = register_name(handle, x86_operand.reg);
                operand.text = operand.register_name;
                break;
            case X86_OP_IMM:
                operand.kind = OperandKind::Immediate;
                operand.immediate = x86_operand.imm;
                operand.text = std::to_string(x86_operand.imm);
                break;
            case X86_OP_MEM:
                operand.kind = OperandKind::Memory;
                operand.memory.segment = register_name(handle, x86_operand.mem.segment);
                operand.memory.base = register_name(handle, x86_operand.mem.base);
                operand.memory.index = register_name(handle, x86_operand.mem.index);
                operand.memory.displacement = x86_operand.mem.disp;
                operand.memory.scale = x86_operand.mem.scale == 0 ? 1 : static_cast<std::uint8_t>(x86_operand.mem.scale);
                break;
            case X86_OP_INVALID:
            default:
                operand.kind = OperandKind::Unknown;
                break;
            }

            operands.push_back(std::move(operand));
        }
    } else if (architecture == loader::Architecture::ARM) {
        const cs_arm& arm = instruction.detail->arm;
        operands.reserve(arm.op_count);

        for (std::uint8_t operand_index = 0; operand_index < arm.op_count; ++operand_index) {
            const cs_arm_op& arm_operand = arm.operands[operand_index];
            Operand operand;
            operand.is_read = arm_operand.access == 0 || (arm_operand.access & CS_AC_READ) != 0;
            operand.is_write = (arm_operand.access & CS_AC_WRITE) != 0;

            switch (arm_operand.type) {
            case ARM_OP_REG:
                operand.kind = OperandKind::Register;
                operand.register_name = register_name(handle, arm_operand.reg);
                operand.text = operand.register_name;
                break;
            case ARM_OP_IMM:
                operand.kind = OperandKind::Immediate;
                operand.immediate = arm_operand.imm;
                operand.text = std::to_string(arm_operand.imm);
                break;
            case ARM_OP_MEM:
                operand.kind = OperandKind::Memory;
                operand.memory.base = register_name(handle, arm_operand.mem.base);
                operand.memory.index = register_name(handle, arm_operand.mem.index);
                operand.memory.displacement = arm_operand.mem.disp;
                operand.memory.scale = arm_operand.mem.scale == 0 ? 1 : static_cast<std::uint8_t>(std::abs(arm_operand.mem.scale));
                break;
            case ARM_OP_INVALID:
            default:
                operand.kind = OperandKind::Unknown;
                break;
            }

            operands.push_back(std::move(operand));
        }
    } else if (architecture == loader::Architecture::ARM64) {
        const cs_arm64& arm64 = instruction.detail->arm64;
        operands.reserve(arm64.op_count);

        for (std::uint8_t operand_index = 0; operand_index < arm64.op_count; ++operand_index) {
            const cs_arm64_op& arm64_operand = arm64.operands[operand_index];
            Operand operand;
            operand.is_read = arm64_operand.access == 0 || (arm64_operand.access & CS_AC_READ) != 0;
            operand.is_write = (arm64_operand.access & CS_AC_WRITE) != 0;

            switch (arm64_operand.type) {
            case ARM64_OP_REG:
                operand.kind = OperandKind::Register;
                operand.register_name = register_name(handle, arm64_operand.reg);
                operand.text = operand.register_name;
                break;
            case ARM64_OP_IMM:
                operand.kind = OperandKind::Immediate;
                operand.immediate = arm64_operand.imm;
                operand.text = std::to_string(arm64_operand.imm);
                break;
            case ARM64_OP_MEM:
                operand.kind = OperandKind::Memory;
                operand.memory.base = register_name(handle, arm64_operand.mem.base);
                operand.memory.index = register_name(handle, arm64_operand.mem.index);
                operand.memory.displacement = arm64_operand.mem.disp;
                operand.memory.scale = 1;
                break;
            default:
                operand.kind = OperandKind::Unknown;
                break;
            }

            operands.push_back(std::move(operand));
        }
    } else if (architecture == loader::Architecture::RISCV64) {
#if ZARA_CAPSTONE_HAS_RISCV
        const cs_riscv& riscv = instruction.detail->riscv;
        operands.reserve(riscv.op_count);

        for (std::uint8_t operand_index = 0; operand_index < riscv.op_count; ++operand_index) {
            const cs_riscv_op& riscv_operand = riscv.operands[operand_index];
            Operand operand;
            operand.is_read = true;
            operand.is_write = false;

            switch (riscv_operand.type) {
            case RISCV_OP_REG:
                operand.kind = OperandKind::Register;
                operand.register_name = register_name(handle, riscv_operand.reg);
                operand.text = operand.register_name;
                break;
            case RISCV_OP_IMM:
                operand.kind = OperandKind::Immediate;
                operand.immediate = riscv_operand.imm;
                operand.text = std::to_string(riscv_operand.imm);
                break;
            case RISCV_OP_MEM:
                operand.kind = OperandKind::Memory;
                operand.memory.base = register_name(handle, riscv_operand.mem.base);
                operand.memory.displacement = riscv_operand.mem.disp;
                operand.memory.scale = 1;
                break;
            case RISCV_OP_INVALID:
            default:
                operand.kind = OperandKind::Unknown;
                break;
            }

            operands.push_back(std::move(operand));
        }
#endif
    } else if (architecture == loader::Architecture::MIPS64) {
        const cs_mips& mips = instruction.detail->mips;
        operands.reserve(mips.op_count);

        for (std::uint8_t operand_index = 0; operand_index < mips.op_count; ++operand_index) {
            const cs_mips_op& mips_operand = mips.operands[operand_index];
            Operand operand;
            operand.is_read = true;
            operand.is_write = false;

            switch (mips_operand.type) {
            case MIPS_OP_REG:
                operand.kind = OperandKind::Register;
                operand.register_name = register_name(handle, mips_operand.reg);
                operand.text = operand.register_name;
                break;
            case MIPS_OP_IMM:
                operand.kind = OperandKind::Immediate;
                operand.immediate = mips_operand.imm;
                operand.text = std::to_string(mips_operand.imm);
                break;
            case MIPS_OP_MEM:
                operand.kind = OperandKind::Memory;
                operand.memory.base = register_name(handle, mips_operand.mem.base);
                operand.memory.displacement = mips_operand.mem.disp;
                operand.memory.scale = 1;
                break;
            case MIPS_OP_INVALID:
            default:
                operand.kind = OperandKind::Unknown;
                break;
            }

            operands.push_back(std::move(operand));
        }
    } else if (architecture == loader::Architecture::PPC64) {
        const cs_ppc& ppc = instruction.detail->ppc;
        operands.reserve(ppc.op_count);

        for (std::uint8_t operand_index = 0; operand_index < ppc.op_count; ++operand_index) {
            const cs_ppc_op& ppc_operand = ppc.operands[operand_index];
            Operand operand;
            operand.is_read = true;
            operand.is_write = false;

            switch (ppc_operand.type) {
            case PPC_OP_REG:
                operand.kind = OperandKind::Register;
                operand.register_name = register_name(handle, ppc_operand.reg);
                operand.text = operand.register_name;
                break;
            case PPC_OP_IMM:
                operand.kind = OperandKind::Immediate;
                operand.immediate = ppc_operand.imm;
                operand.text = std::to_string(ppc_operand.imm);
                break;
            case PPC_OP_MEM:
                operand.kind = OperandKind::Memory;
                operand.memory.base = register_name(handle, ppc_operand.mem.base);
                operand.memory.displacement = ppc_operand.mem.disp;
                operand.memory.scale = 1;
                break;
            case PPC_OP_INVALID:
            default:
                operand.kind = OperandKind::Unknown;
                break;
            }

            operands.push_back(std::move(operand));
        }
    }

    return operands;
}
#endif

}  // namespace

std::vector<Instruction> Disassembler::decode(
    const memory::AddressSpace& address_space,
    const std::uint64_t start_address,
    const std::size_t max_bytes,
    const loader::Architecture architecture
) const {
    const std::vector<std::byte> raw_bytes = address_space.read_bytes(start_address, max_bytes);
    if (raw_bytes.empty()) {
        return {};
    }

#if defined(ZARA_HAS_CAPSTONE)
    cs_arch capstone_arch = CS_ARCH_X86;
    cs_mode capstone_mode = CS_MODE_LITTLE_ENDIAN;
    if (capstone_mode_for_architecture(architecture, capstone_arch, capstone_mode)) {
        csh handle = 0;
        if (cs_open(capstone_arch, capstone_mode, &handle) == CS_ERR_OK) {
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

            cs_insn* decoded_instructions = nullptr;
            const auto instruction_count = cs_disasm(
                handle,
                reinterpret_cast<const std::uint8_t*>(raw_bytes.data()),
                raw_bytes.size(),
                start_address,
                0,
                &decoded_instructions
            );

            if (instruction_count > 0) {
                std::vector<Instruction> instructions;
                instructions.reserve(instruction_count);

                for (std::size_t index = 0; index < instruction_count; ++index) {
                    const cs_insn& decoded = decoded_instructions[index];
                    instructions.push_back(
                        Instruction{
                            .address = decoded.address,
                            .size = static_cast<std::uint8_t>(decoded.size),
                            .kind = classify_instruction(handle, decoded, architecture),
                            .bytes = std::vector<std::uint8_t>(decoded.bytes, decoded.bytes + decoded.size),
                            .mnemonic = decoded.mnemonic,
                            .operands = decoded.op_str,
                            .decoded_operands = extract_operands(handle, decoded, architecture),
                            .control_flow_target = extract_control_flow_target(decoded, architecture),
                            .data_references = extract_data_references(decoded, architecture),
                        }
                    );
                }

                cs_free(decoded_instructions, instruction_count);
                cs_close(&handle);
                return instructions;
            }

            cs_close(&handle);
        }
    }
#endif

    return decode_as_data_bytes(raw_bytes, start_address);
}

bool Disassembler::is_supported(const loader::Architecture architecture) const noexcept {
#if defined(ZARA_HAS_CAPSTONE)
    cs_arch capstone_arch = CS_ARCH_X86;
    cs_mode capstone_mode = CS_MODE_LITTLE_ENDIAN;
    return capstone_mode_for_architecture(architecture, capstone_arch, capstone_mode);
#else
    (void)architecture;
    return false;
#endif
}

const ArchitectureDescriptor* describe_architecture(const loader::Architecture architecture) noexcept {
    switch (architecture) {
    case loader::Architecture::X86:
        return &kX86Descriptor;
    case loader::Architecture::X86_64:
        return &kX86_64Descriptor;
    case loader::Architecture::ARM:
        return &kArmDescriptor;
    case loader::Architecture::ARM64:
        return &kArm64Descriptor;
    case loader::Architecture::RISCV64:
        return &kRiscV64Descriptor;
    case loader::Architecture::MIPS64:
        return &kMips64Descriptor;
    case loader::Architecture::PPC64:
        return &kPpc64Descriptor;
    case loader::Architecture::Unknown:
    default:
        return &kUnknownDescriptor;
    }
}

}  // namespace zara::disasm
