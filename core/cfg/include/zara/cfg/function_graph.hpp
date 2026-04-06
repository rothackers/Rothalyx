#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "zara/disasm/disassembler.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"

namespace zara::cfg {

struct BasicBlock {
    std::uint64_t start_address = 0;
    std::uint64_t end_address = 0;
    std::vector<disasm::Instruction> instructions;
    std::vector<std::uint64_t> successors;
};

struct LoopInfo {
    std::uint64_t header_address = 0;
    std::vector<std::uint64_t> latch_blocks;
    std::vector<std::uint64_t> body_blocks;
};

struct SwitchCase {
    std::int64_t value = 0;
    std::uint64_t target = 0;
};

struct SwitchInfo {
    std::uint64_t dispatch_block = 0;
    std::uint64_t jump_address = 0;
    std::uint64_t table_address = 0;
    std::optional<std::uint64_t> default_target;
    std::vector<SwitchCase> cases;
};

class FunctionGraph {
public:
    static FunctionGraph from_linear(std::string name, std::vector<disasm::Instruction> instructions);
    static FunctionGraph analyze(
        std::string name,
        const memory::AddressSpace& address_space,
        const loader::Section& section,
        std::uint64_t entry_address,
        loader::Architecture architecture,
        std::size_t max_block_bytes = 4096
    );

    [[nodiscard]] const std::string& name() const noexcept;
    [[nodiscard]] std::uint64_t entry_address() const noexcept;
    [[nodiscard]] const std::vector<BasicBlock>& blocks() const noexcept;
    [[nodiscard]] const std::vector<std::uint64_t>& direct_call_targets() const noexcept;
    [[nodiscard]] const std::vector<LoopInfo>& loops() const noexcept;
    [[nodiscard]] const std::vector<SwitchInfo>& switches() const noexcept;
    [[nodiscard]] std::size_t unreachable_blocks_removed() const noexcept;
    [[nodiscard]] std::size_t linear_block_merges() const noexcept;

private:
    std::string name_;
    std::uint64_t entry_address_ = 0;
    std::vector<BasicBlock> blocks_;
    std::vector<std::uint64_t> direct_call_targets_;
    std::vector<LoopInfo> loops_;
    std::vector<SwitchInfo> switches_;
    std::size_t unreachable_blocks_removed_ = 0;
    std::size_t linear_block_merges_ = 0;
};

}  // namespace zara::cfg
