#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "zara/cfg/function_graph.hpp"
#include "zara/loader/binary_image.hpp"

namespace zara::ir {

enum class ScalarType {
    Unknown,
    Bool,
    I8,
    I16,
    I32,
    I64,
    Pointer,
};

enum class ValueKind {
    Invalid,
    Register,
    Immediate,
    MemoryAddress,
    Temporary,
};

struct MemoryAddress {
    std::string segment;
    std::string base;
    std::string index;
    std::int64_t displacement = 0;
    std::uint8_t scale = 1;
};

struct Value {
    ValueKind kind = ValueKind::Invalid;
    ScalarType type = ScalarType::Unknown;
    std::string name;
    std::int64_t immediate = 0;
    MemoryAddress memory;
};

enum class BinaryOperator {
    Add,
    Sub,
    And,
    Or,
    Xor,
};

enum class InstructionKind {
    Assign,
    Load,
    Store,
    Binary,
    Compare,
    Test,
    SetFlags,
    Call,
    Branch,
    CondBranch,
    Return,
    Nop,
    Intrinsic,
};

struct Instruction {
    std::uint64_t address = 0;
    InstructionKind kind = InstructionKind::Intrinsic;
    std::optional<Value> destination;
    std::vector<Value> inputs;
    std::optional<BinaryOperator> binary_operator;
    std::optional<std::uint64_t> true_target;
    std::optional<std::uint64_t> false_target;
    std::string text;
};

struct BasicBlock {
    std::uint64_t start_address = 0;
    std::vector<Instruction> instructions;
    std::vector<std::uint64_t> successors;
};

struct Function {
    std::string name;
    std::uint64_t entry_address = 0;
    std::vector<BasicBlock> blocks;
};

class Lifter {
public:
    [[nodiscard]] static Function lift(
        const cfg::FunctionGraph& graph,
        loader::Architecture architecture
    );
};

[[nodiscard]] std::string_view to_string(ScalarType type) noexcept;
[[nodiscard]] std::string_view to_string(ValueKind kind) noexcept;
[[nodiscard]] std::string_view to_string(BinaryOperator operation) noexcept;
[[nodiscard]] std::string_view to_string(InstructionKind kind) noexcept;
[[nodiscard]] std::string format_value(const Value& value);
[[nodiscard]] std::string format_instruction(const Instruction& instruction);

}  // namespace zara::ir
