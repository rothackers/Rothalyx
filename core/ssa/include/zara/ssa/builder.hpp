#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "zara/ir/lifter.hpp"

namespace zara::ssa {

struct PhiNode {
    std::string variable;
    std::string result_name;
    std::vector<std::pair<std::uint64_t, std::string>> incoming;
};

struct BasicBlock {
    std::uint64_t start_address = 0;
    std::vector<PhiNode> phi_nodes;
    std::vector<ir::Instruction> instructions;
    std::vector<std::uint64_t> predecessors;
    std::vector<std::uint64_t> successors;
};

struct Function {
    std::string name;
    std::uint64_t entry_address = 0;
    std::vector<BasicBlock> blocks;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> immediate_dominators;
};

class Builder {
public:
    [[nodiscard]] static Function build(const ir::Function& function);
};

[[nodiscard]] std::string format_phi(const PhiNode& phi);

}  // namespace zara::ssa
