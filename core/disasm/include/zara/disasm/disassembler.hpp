#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"

namespace zara::disasm {

enum class InstructionKind {
    Unknown,
    DataByte,
    Instruction,
    Call,
    Jump,
    ConditionalJump,
    Return,
    Interrupt,
};

enum class OperandKind {
    Unknown,
    Register,
    Immediate,
    Memory,
};

struct MemoryOperand {
    std::string segment;
    std::string base;
    std::string index;
    std::int64_t displacement = 0;
    std::uint8_t scale = 1;
};

struct Operand {
    OperandKind kind = OperandKind::Unknown;
    std::string text;
    std::string register_name;
    std::int64_t immediate = 0;
    MemoryOperand memory;
    bool is_read = false;
    bool is_write = false;
};

struct Instruction {
    std::uint64_t address = 0;
    std::uint8_t size = 0;
    InstructionKind kind = InstructionKind::Unknown;
    std::vector<std::uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
    std::vector<Operand> decoded_operands;
    std::optional<std::uint64_t> control_flow_target;
    std::vector<std::uint64_t> data_references;
};

struct ArchitectureDescriptor {
    loader::Architecture architecture = loader::Architecture::Unknown;
    std::string_view name = "unknown";
    std::size_t pointer_size = 0;
    std::size_t instruction_alignment = 1;
    std::string_view stack_pointer;
    std::string_view frame_pointer;
    std::string_view link_register;
};

class Disassembler {
public:
    [[nodiscard]] std::vector<Instruction> decode(
        const memory::AddressSpace& address_space,
        std::uint64_t start_address,
        std::size_t max_bytes,
        loader::Architecture architecture
    ) const;

    [[nodiscard]] bool is_supported(loader::Architecture architecture) const noexcept;
};

[[nodiscard]] const ArchitectureDescriptor* describe_architecture(loader::Architecture architecture) noexcept;

}  // namespace zara::disasm
