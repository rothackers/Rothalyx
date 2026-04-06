#include "zara/ssa/builder.hpp"

#include <algorithm>
#include <functional>
#include <optional>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace zara::ssa {

namespace {

using AddressSet = std::set<std::uint64_t>;

bool is_ssa_name_kind(const ir::ValueKind kind) {
    return kind == ir::ValueKind::Register || kind == ir::ValueKind::Temporary;
}

void collect_value_names(const ir::Value& value, std::unordered_set<std::string>& out_names) {
    if (is_ssa_name_kind(value.kind) && !value.name.empty()) {
        out_names.insert(value.name);
    }

    if (value.kind == ir::ValueKind::MemoryAddress) {
        if (!value.memory.base.empty()) {
            out_names.insert(value.memory.base);
        }
        if (!value.memory.index.empty()) {
            out_names.insert(value.memory.index);
        }
    }
}

void rename_value(
    ir::Value& value,
    const std::function<std::string(const std::string&)>& current_name
) {
    if (is_ssa_name_kind(value.kind) && !value.name.empty()) {
        value.name = current_name(value.name);
        return;
    }

    if (value.kind == ir::ValueKind::MemoryAddress) {
        if (!value.memory.base.empty()) {
            value.memory.base = current_name(value.memory.base);
        }
        if (!value.memory.index.empty()) {
            value.memory.index = current_name(value.memory.index);
        }
    }
}

bool defines_variable(const ir::Instruction& instruction) {
    return instruction.destination.has_value() && is_ssa_name_kind(instruction.destination->kind);
}

std::string defined_variable(const ir::Instruction& instruction) {
    if (!defines_variable(instruction)) {
        return {};
    }

    return instruction.destination->name;
}

}  // namespace

Function Builder::build(const ir::Function& function) {
    Function ssa_function;
    ssa_function.name = function.name;
    ssa_function.entry_address = function.entry_address;
    ssa_function.blocks.reserve(function.blocks.size());

    std::unordered_map<std::uint64_t, std::size_t> block_index_by_address;
    for (std::size_t index = 0; index < function.blocks.size(); ++index) {
        const auto& source_block = function.blocks[index];
        ssa_function.blocks.push_back(
            BasicBlock{
                .start_address = source_block.start_address,
                .phi_nodes = {},
                .instructions = source_block.instructions,
                .predecessors = {},
                .successors = source_block.successors,
            }
        );
        block_index_by_address.emplace(source_block.start_address, index);
    }

    for (const auto& block : ssa_function.blocks) {
        for (const auto successor : block.successors) {
            const auto successor_it = block_index_by_address.find(successor);
            if (successor_it == block_index_by_address.end()) {
                continue;
            }
            ssa_function.blocks[successor_it->second].predecessors.push_back(block.start_address);
        }
    }

    for (auto& block : ssa_function.blocks) {
        std::sort(block.predecessors.begin(), block.predecessors.end());
        block.predecessors.erase(std::unique(block.predecessors.begin(), block.predecessors.end()), block.predecessors.end());
    }

    std::vector<std::uint64_t> block_order;
    block_order.reserve(ssa_function.blocks.size());
    for (const auto& block : ssa_function.blocks) {
        block_order.push_back(block.start_address);
    }

    std::unordered_map<std::uint64_t, AddressSet> dominators;
    const AddressSet all_blocks(block_order.begin(), block_order.end());
    for (const auto block_start : block_order) {
        if (block_start == ssa_function.entry_address) {
            dominators[block_start] = {block_start};
        } else {
            dominators[block_start] = all_blocks;
        }
    }

    bool changed = true;
    while (changed) {
        changed = false;

        for (const auto& block : ssa_function.blocks) {
            if (block.start_address == ssa_function.entry_address) {
                continue;
            }

            AddressSet new_dominators = all_blocks;
            if (block.predecessors.empty()) {
                new_dominators.clear();
            } else {
                bool first_predecessor = true;
                for (const auto predecessor : block.predecessors) {
                    if (first_predecessor) {
                        new_dominators = dominators[predecessor];
                        first_predecessor = false;
                    } else {
                        AddressSet intersection;
                        std::set_intersection(
                            new_dominators.begin(),
                            new_dominators.end(),
                            dominators[predecessor].begin(),
                            dominators[predecessor].end(),
                            std::inserter(intersection, intersection.begin())
                        );
                        new_dominators = std::move(intersection);
                    }
                }
            }

            new_dominators.insert(block.start_address);
            if (dominators[block.start_address] != new_dominators) {
                dominators[block.start_address] = std::move(new_dominators);
                changed = true;
            }
        }
    }

    std::unordered_map<std::uint64_t, std::optional<std::uint64_t>> immediate_dominator;
    immediate_dominator[ssa_function.entry_address] = std::nullopt;
    for (const auto& block : ssa_function.blocks) {
        if (block.start_address == ssa_function.entry_address) {
            continue;
        }

        std::optional<std::uint64_t> idom;
        for (const auto candidate : dominators[block.start_address]) {
            if (candidate == block.start_address) {
                continue;
            }

            bool dominated_by_other_candidate = false;
            for (const auto other : dominators[block.start_address]) {
                if (other == block.start_address || other == candidate) {
                    continue;
                }
                if (dominators[other].contains(candidate)) {
                    dominated_by_other_candidate = true;
                    break;
                }
            }

            if (!dominated_by_other_candidate) {
                idom = candidate;
                break;
            }
        }

        immediate_dominator[block.start_address] = idom;
        if (idom.has_value()) {
            ssa_function.immediate_dominators.emplace_back(block.start_address, *idom);
        }
    }

    std::unordered_map<std::uint64_t, AddressSet> dominance_frontier;
    for (const auto& block : ssa_function.blocks) {
        if (block.predecessors.size() < 2) {
            continue;
        }

        const auto block_idom = immediate_dominator[block.start_address];
        for (const auto predecessor : block.predecessors) {
            std::optional<std::uint64_t> runner = predecessor;
            while (runner.has_value() && runner != block_idom) {
                dominance_frontier[*runner].insert(block.start_address);
                runner = immediate_dominator[*runner];
            }
        }
    }

    std::unordered_map<std::string, AddressSet> definition_sites;
    std::unordered_set<std::string> all_variables;
    for (const auto& block : ssa_function.blocks) {
        for (const auto& instruction : block.instructions) {
            if (instruction.destination.has_value()) {
                collect_value_names(*instruction.destination, all_variables);
            }
            for (const auto& input : instruction.inputs) {
                collect_value_names(input, all_variables);
            }

            if (defines_variable(instruction)) {
                definition_sites[defined_variable(instruction)].insert(block.start_address);
            }
        }
    }

    std::unordered_map<std::uint64_t, std::vector<std::string>> phi_variables_by_block;
    for (const auto& [variable, defining_blocks] : definition_sites) {
        std::vector<std::uint64_t> worklist(defining_blocks.begin(), defining_blocks.end());
        AddressSet placed_phis;

        while (!worklist.empty()) {
            const std::uint64_t block_start = worklist.back();
            worklist.pop_back();

            for (const auto frontier_block : dominance_frontier[block_start]) {
                if (!placed_phis.insert(frontier_block).second) {
                    continue;
                }

                phi_variables_by_block[frontier_block].push_back(variable);
                if (!defining_blocks.contains(frontier_block)) {
                    worklist.push_back(frontier_block);
                }
            }
        }
    }

    for (auto& block : ssa_function.blocks) {
        auto phi_variables_it = phi_variables_by_block.find(block.start_address);
        if (phi_variables_it == phi_variables_by_block.end()) {
            continue;
        }

        std::sort(phi_variables_it->second.begin(), phi_variables_it->second.end());
        phi_variables_it->second.erase(
            std::unique(phi_variables_it->second.begin(), phi_variables_it->second.end()),
            phi_variables_it->second.end()
        );

        for (const auto& variable : phi_variables_it->second) {
            block.phi_nodes.push_back(
                PhiNode{
                    .variable = variable,
                }
            );
        }
    }

    std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> dom_tree_children;
    for (const auto& [block_start, idom] : immediate_dominator) {
        if (idom.has_value()) {
            dom_tree_children[*idom].push_back(block_start);
        }
    }
    for (auto& [_, children] : dom_tree_children) {
        std::sort(children.begin(), children.end());
    }

    std::unordered_map<std::string, std::vector<std::string>> version_stack;
    std::unordered_map<std::string, std::size_t> version_counter;
    for (const auto& variable : all_variables) {
        version_stack[variable] = {variable + ".0"};
        version_counter[variable] = 1;
    }

    auto current_name = [&](const std::string& variable) -> std::string {
        const auto stack_it = version_stack.find(variable);
        if (stack_it == version_stack.end() || stack_it->second.empty()) {
            return variable + ".0";
        }
        return stack_it->second.back();
    };

    auto next_name = [&](const std::string& variable) -> std::string {
        const std::string name = variable + "." + std::to_string(version_counter[variable]++);
        version_stack[variable].push_back(name);
        return name;
    };

    struct RenameFrame {
        std::uint64_t block_start = 0;
        bool exit = false;
        std::vector<std::string> pushed_variables;
    };

    if (!ssa_function.blocks.empty()) {
        std::vector<RenameFrame> stack;
        stack.push_back(RenameFrame{.block_start = ssa_function.entry_address, .exit = false, .pushed_variables = {}});

        while (!stack.empty()) {
            RenameFrame frame = std::move(stack.back());
            stack.pop_back();

            auto& block = ssa_function.blocks[block_index_by_address.at(frame.block_start)];
            if (frame.exit) {
                for (auto it = frame.pushed_variables.rbegin(); it != frame.pushed_variables.rend(); ++it) {
                    auto stack_it = version_stack.find(*it);
                    if (stack_it != version_stack.end() && stack_it->second.size() > 1) {
                        stack_it->second.pop_back();
                    }
                }
                continue;
            }

            for (auto& phi : block.phi_nodes) {
                phi.result_name = next_name(phi.variable);
                frame.pushed_variables.push_back(phi.variable);
            }

            for (auto& instruction : block.instructions) {
                for (auto& input : instruction.inputs) {
                    rename_value(input, current_name);
                }

                if (instruction.destination.has_value()) {
                    if (is_ssa_name_kind(instruction.destination->kind)) {
                        const std::string base_variable = instruction.destination->name;
                        instruction.destination->name = next_name(base_variable);
                        frame.pushed_variables.push_back(base_variable);
                    } else {
                        rename_value(*instruction.destination, current_name);
                    }
                }
            }

            for (const auto successor : block.successors) {
                const auto successor_it = block_index_by_address.find(successor);
                if (successor_it == block_index_by_address.end()) {
                    continue;
                }

                auto& successor_block = ssa_function.blocks[successor_it->second];
                for (auto& phi : successor_block.phi_nodes) {
                    phi.incoming.emplace_back(block.start_address, current_name(phi.variable));
                }
            }

            stack.push_back(
                RenameFrame{
                    .block_start = frame.block_start,
                    .exit = true,
                    .pushed_variables = std::move(frame.pushed_variables),
                }
            );

            const auto children_it = dom_tree_children.find(block.start_address);
            if (children_it == dom_tree_children.end()) {
                continue;
            }
            for (auto child_it = children_it->second.rbegin(); child_it != children_it->second.rend(); ++child_it) {
                stack.push_back(RenameFrame{.block_start = *child_it, .exit = false, .pushed_variables = {}});
            }
        }
    }

    for (auto& block : ssa_function.blocks) {
        for (auto& phi : block.phi_nodes) {
            std::sort(phi.incoming.begin(), phi.incoming.end());
            phi.incoming.erase(std::unique(phi.incoming.begin(), phi.incoming.end()), phi.incoming.end());
        }
    }

    std::sort(ssa_function.immediate_dominators.begin(), ssa_function.immediate_dominators.end());
    return ssa_function;
}

std::string format_phi(const PhiNode& phi) {
    std::ostringstream stream;
    stream << phi.result_name << " = phi(";
    for (std::size_t index = 0; index < phi.incoming.size(); ++index) {
        if (index > 0) {
            stream << ", ";
        }
        stream << "0x" << std::hex << std::uppercase << phi.incoming[index].first << std::dec;
        stream << ": " << phi.incoming[index].second;
    }
    stream << ')';
    return stream.str();
}

}  // namespace zara::ssa
