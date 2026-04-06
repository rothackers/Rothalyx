#include "zara/cfg/function_graph.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace zara::cfg {

namespace {

using BlockMap = std::unordered_map<std::uint64_t, BasicBlock>;
using PredecessorMap = std::unordered_map<std::uint64_t, std::vector<std::uint64_t>>;
using AddressSet = std::set<std::uint64_t>;

struct SwitchBounds {
    std::size_t case_count = 0;
    std::optional<std::uint64_t> default_target;
};

bool is_in_section(const loader::Section& section, const std::uint64_t address) {
    const auto section_end = section.virtual_address + static_cast<std::uint64_t>(section.bytes.size());
    return address >= section.virtual_address && address < section_end;
}

bool instruction_has_fallthrough(const disasm::Instruction& instruction) {
    switch (instruction.kind) {
    case disasm::InstructionKind::Jump:
    case disasm::InstructionKind::Return:
    case disasm::InstructionKind::Interrupt:
        return false;
    case disasm::InstructionKind::ConditionalJump:
    case disasm::InstructionKind::Call:
    case disasm::InstructionKind::Instruction:
    case disasm::InstructionKind::DataByte:
    case disasm::InstructionKind::Unknown:
    default:
        return true;
    }
}

void deduplicate_addresses(std::vector<std::uint64_t>& addresses) {
    std::sort(addresses.begin(), addresses.end());
    addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());
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

std::string normalize_register_family(std::string name, const loader::Architecture architecture) {
    name = lowercase_copy(std::move(name));

    if (architecture == loader::Architecture::X86_64) {
        if (name == "rdi" || name == "edi" || name == "di" || name == "dil") {
            return "rdi";
        }
        if (name == "rsi" || name == "esi" || name == "si" || name == "sil") {
            return "rsi";
        }
        if (name == "rax" || name == "eax" || name == "ax" || name == "al" || name == "ah") {
            return "rax";
        }
        if (name == "rcx" || name == "ecx" || name == "cx" || name == "cl" || name == "ch") {
            return "rcx";
        }
        if (name == "rdx" || name == "edx" || name == "dx" || name == "dl" || name == "dh") {
            return "rdx";
        }
    }

    if (architecture == loader::Architecture::X86) {
        if (name == "edi" || name == "di") {
            return "edi";
        }
        if (name == "esi" || name == "si") {
            return "esi";
        }
        if (name == "eax" || name == "ax" || name == "al" || name == "ah") {
            return "eax";
        }
        if (name == "ecx" || name == "cx" || name == "cl" || name == "ch") {
            return "ecx";
        }
        if (name == "edx" || name == "dx" || name == "dl" || name == "dh") {
            return "edx";
        }
    }

    if (architecture == loader::Architecture::ARM) {
        if (name == "r11" || name == "fp") {
            return "fp";
        }
        if (name == "r13" || name == "sp") {
            return "sp";
        }
        if (name == "r15" || name == "pc") {
            return "pc";
        }
    }

    if (architecture == loader::Architecture::RISCV64) {
        if (name == "x2" || name == "sp") {
            return "sp";
        }
        if (name == "x8" || name == "s0" || name == "fp") {
            return "s0";
        }
        if (name == "x10" || name == "a0") {
            return "a0";
        }
        if (name == "x11" || name == "a1") {
            return "a1";
        }
    }

    return name;
}

std::size_t pointer_size(const loader::Architecture architecture) {
    switch (architecture) {
    case loader::Architecture::X86:
    case loader::Architecture::ARM:
        return 4;
    case loader::Architecture::X86_64:
    case loader::Architecture::ARM64:
    case loader::Architecture::RISCV64:
        return 8;
    case loader::Architecture::Unknown:
    default:
        return 8;
    }
}

std::optional<std::uint64_t> read_pointer(
    const memory::AddressSpace& address_space,
    const std::uint64_t address,
    const std::size_t width
) {
    const auto bytes = address_space.read_bytes(address, width);
    if (bytes.size() != width) {
        return std::nullopt;
    }

    if (width == 4) {
        std::uint32_t value = 0;
        std::memcpy(&value, bytes.data(), sizeof(value));
        return static_cast<std::uint64_t>(value);
    }

    if (width == 8) {
        std::uint64_t value = 0;
        std::memcpy(&value, bytes.data(), sizeof(value));
        return value;
    }

    return std::nullopt;
}

PredecessorMap build_predecessors(const BlockMap& blocks) {
    PredecessorMap predecessors;
    for (const auto& [start_address, block] : blocks) {
        predecessors[start_address];
        for (const auto successor : block.successors) {
            if (!blocks.contains(successor)) {
                continue;
            }
            predecessors[successor].push_back(start_address);
        }
    }

    for (auto& [_, incoming] : predecessors) {
        deduplicate_addresses(incoming);
    }
    return predecessors;
}

std::optional<std::uint64_t> switch_table_address(const disasm::Instruction& instruction) {
    if (!instruction.data_references.empty()) {
        return instruction.data_references.front();
    }

    for (const auto& operand : instruction.decoded_operands) {
        if (operand.kind != disasm::OperandKind::Memory) {
            continue;
        }
        if (operand.memory.displacement >= 0) {
            return static_cast<std::uint64_t>(operand.memory.displacement);
        }
    }

    return std::nullopt;
}

std::optional<std::string> switch_index_register(const disasm::Instruction& instruction) {
    for (const auto& operand : instruction.decoded_operands) {
        if (operand.kind != disasm::OperandKind::Memory) {
            continue;
        }
        if (!operand.memory.index.empty()) {
            return operand.memory.index;
        }
        if (!operand.memory.base.empty()) {
            const std::string base = lowercase_copy(operand.memory.base);
            if (base != "rip" && base != "eip") {
                return operand.memory.base;
            }
        }
    }

    return std::nullopt;
}

std::optional<SwitchBounds> find_switch_bounds(
    const BasicBlock& block,
    const PredecessorMap& predecessors,
    const BlockMap& blocks,
    const std::string& index_register,
    const loader::Architecture architecture
) {
    const std::string normalized_index = normalize_register_family(index_register, architecture);
    const auto predecessor_it = predecessors.find(block.start_address);
    if (predecessor_it == predecessors.end()) {
        return std::nullopt;
    }

    for (const auto predecessor_start : predecessor_it->second) {
        const auto block_it = blocks.find(predecessor_start);
        if (block_it == blocks.end() || block_it->second.instructions.empty()) {
            continue;
        }

        const auto& predecessor = block_it->second;
        const auto& terminator = predecessor.instructions.back();
        if (terminator.kind != disasm::InstructionKind::ConditionalJump || predecessor.successors.size() != 2) {
            continue;
        }

        if (std::find(predecessor.successors.begin(), predecessor.successors.end(), block.start_address) ==
            predecessor.successors.end()) {
            continue;
        }

        SwitchBounds bounds;
        for (const auto successor : predecessor.successors) {
            if (successor != block.start_address) {
                bounds.default_target = successor;
                break;
            }
        }

        for (auto instruction_it = predecessor.instructions.rbegin();
             instruction_it != predecessor.instructions.rend();
             ++instruction_it) {
            const auto mnemonic = lowercase_copy(instruction_it->mnemonic);
            if (mnemonic != "cmp" || instruction_it->decoded_operands.size() < 2) {
                continue;
            }

            const auto& lhs = instruction_it->decoded_operands[0];
            const auto& rhs = instruction_it->decoded_operands[1];
            if (lhs.kind == disasm::OperandKind::Register &&
                normalize_register_family(lhs.register_name, architecture) == normalized_index &&
                rhs.kind == disasm::OperandKind::Immediate &&
                rhs.immediate >= 0) {
                bounds.case_count = static_cast<std::size_t>(rhs.immediate + 1);
                return bounds;
            }

            if (rhs.kind == disasm::OperandKind::Register &&
                normalize_register_family(rhs.register_name, architecture) == normalized_index &&
                lhs.kind == disasm::OperandKind::Immediate &&
                lhs.immediate >= 0) {
                bounds.case_count = static_cast<std::size_t>(lhs.immediate + 1);
                return bounds;
            }
        }

        return bounds;
    }

    return std::nullopt;
}

std::optional<SwitchInfo> resolve_switch(
    const BasicBlock& block,
    const PredecessorMap& predecessors,
    const BlockMap& blocks,
    const memory::AddressSpace& address_space,
    const loader::Section& section,
    const loader::Architecture architecture
) {
    if (block.instructions.empty()) {
        return std::nullopt;
    }

    const auto& jump = block.instructions.back();
    if (jump.kind != disasm::InstructionKind::Jump || jump.control_flow_target.has_value()) {
        return std::nullopt;
    }

    const auto table_address = switch_table_address(jump);
    const auto index_register = switch_index_register(jump);
    if (!table_address.has_value() || !index_register.has_value()) {
        return std::nullopt;
    }

    const auto pointer_width = pointer_size(architecture);
    std::size_t case_count = 0;
    std::optional<std::uint64_t> default_target;
    const auto bounds = find_switch_bounds(block, predecessors, blocks, *index_register, architecture);
    if (bounds.has_value()) {
        case_count = bounds->case_count;
        default_target = bounds->default_target;
    }

    if (case_count == 0) {
        case_count = 16;
    }

    SwitchInfo info{
        .dispatch_block = block.start_address,
        .jump_address = jump.address,
        .table_address = *table_address,
        .default_target = default_target,
        .cases = {},
    };

    for (std::size_t index = 0; index < case_count; ++index) {
        const auto target = read_pointer(address_space, *table_address + (index * pointer_width), pointer_width);
        if (!target.has_value() || !is_in_section(section, *target)) {
            if (bounds.has_value()) {
                return std::nullopt;
            }
            break;
        }

        info.cases.push_back(
            SwitchCase{
                .value = static_cast<std::int64_t>(index),
                .target = *target,
            }
        );
    }

    if (info.cases.size() < 2) {
        return std::nullopt;
    }

    std::sort(
        info.cases.begin(),
        info.cases.end(),
        [](const SwitchCase& lhs, const SwitchCase& rhs) { return lhs.value < rhs.value; }
    );
    return info;
}

bool can_merge_linear_blocks(const BasicBlock& block, const BasicBlock& successor) {
    if (block.instructions.empty() || successor.instructions.empty()) {
        return false;
    }

    const auto& terminator = block.instructions.back();
    switch (terminator.kind) {
    case disasm::InstructionKind::Instruction:
    case disasm::InstructionKind::Unknown:
    case disasm::InstructionKind::DataByte:
        break;
    case disasm::InstructionKind::Call:
    case disasm::InstructionKind::Jump:
    case disasm::InstructionKind::ConditionalJump:
    case disasm::InstructionKind::Return:
    case disasm::InstructionKind::Interrupt:
    default:
        return false;
    }

    return block.end_address == successor.start_address;
}

std::size_t remove_unreachable_blocks(BlockMap& blocks, const std::uint64_t entry_address) {
    std::vector<std::uint64_t> stack{entry_address};
    std::unordered_set<std::uint64_t> reachable;

    while (!stack.empty()) {
        const auto block_start = stack.back();
        stack.pop_back();

        if (!reachable.insert(block_start).second) {
            continue;
        }

        const auto block_it = blocks.find(block_start);
        if (block_it == blocks.end()) {
            continue;
        }

        for (const auto successor : block_it->second.successors) {
            if (blocks.contains(successor)) {
                stack.push_back(successor);
            }
        }
    }

    std::size_t removed = 0;
    for (auto block_it = blocks.begin(); block_it != blocks.end();) {
        if (!reachable.contains(block_it->first)) {
            block_it = blocks.erase(block_it);
            ++removed;
            continue;
        }
        ++block_it;
    }

    return removed;
}

std::size_t merge_linear_blocks(BlockMap& blocks) {
    std::size_t merges = 0;

    bool changed = true;
    while (changed) {
        changed = false;
        const auto predecessors = build_predecessors(blocks);

        for (auto block_it = blocks.begin(); block_it != blocks.end(); ++block_it) {
            auto& block = block_it->second;
            if (block.successors.size() != 1) {
                continue;
            }

            const auto successor_start = block.successors.front();
            const auto successor_it = blocks.find(successor_start);
            if (successor_it == blocks.end()) {
                continue;
            }

            const auto predecessor_it = predecessors.find(successor_start);
            if (predecessor_it == predecessors.end() || predecessor_it->second.size() != 1 ||
                predecessor_it->second.front() != block.start_address) {
                continue;
            }

            if (!can_merge_linear_blocks(block, successor_it->second)) {
                continue;
            }

            block.instructions.insert(
                block.instructions.end(),
                successor_it->second.instructions.begin(),
                successor_it->second.instructions.end()
            );
            block.end_address = successor_it->second.end_address;
            block.successors = successor_it->second.successors;
            blocks.erase(successor_it);
            ++merges;
            changed = true;
            break;
        }
    }

    return merges;
}

std::vector<LoopInfo> collect_loops(const std::vector<BasicBlock>& blocks, const std::uint64_t entry_address) {
    std::unordered_map<std::uint64_t, BasicBlock> blocks_by_start;
    std::vector<std::uint64_t> block_order;
    for (const auto& block : blocks) {
        blocks_by_start.emplace(block.start_address, block);
        block_order.push_back(block.start_address);
    }

    const auto predecessors = build_predecessors(blocks_by_start);
    const AddressSet all_blocks(block_order.begin(), block_order.end());

    std::unordered_map<std::uint64_t, AddressSet> dominators;
    for (const auto block_start : block_order) {
        dominators[block_start] = block_start == entry_address ? AddressSet{block_start} : all_blocks;
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& block : blocks) {
            if (block.start_address == entry_address) {
                continue;
            }

            AddressSet next = all_blocks;
            const auto predecessor_it = predecessors.find(block.start_address);
            if (predecessor_it == predecessors.end() || predecessor_it->second.empty()) {
                next.clear();
            } else {
                bool first = true;
                for (const auto predecessor : predecessor_it->second) {
                    if (first) {
                        next = dominators[predecessor];
                        first = false;
                        continue;
                    }

                    AddressSet intersection;
                    std::set_intersection(
                        next.begin(),
                        next.end(),
                        dominators[predecessor].begin(),
                        dominators[predecessor].end(),
                        std::inserter(intersection, intersection.begin())
                    );
                    next = std::move(intersection);
                }
            }

            next.insert(block.start_address);
            if (dominators[block.start_address] != next) {
                dominators[block.start_address] = std::move(next);
                changed = true;
            }
        }
    }

    std::unordered_map<std::uint64_t, LoopInfo> loops_by_header;
    for (const auto& block : blocks) {
        for (const auto successor : block.successors) {
            if (!dominators[block.start_address].contains(successor)) {
                continue;
            }

            auto& loop = loops_by_header[successor];
            loop.header_address = successor;
            loop.latch_blocks.push_back(block.start_address);

            std::unordered_set<std::uint64_t> body;
            std::vector<std::uint64_t> worklist{block.start_address};
            body.insert(successor);
            while (!worklist.empty()) {
                const auto current = worklist.back();
                worklist.pop_back();
                if (!body.insert(current).second) {
                    continue;
                }

                const auto predecessor_it = predecessors.find(current);
                if (predecessor_it == predecessors.end()) {
                    continue;
                }
                for (const auto predecessor : predecessor_it->second) {
                    if (!body.contains(predecessor)) {
                        worklist.push_back(predecessor);
                    }
                }
            }

            loop.body_blocks.insert(loop.body_blocks.end(), body.begin(), body.end());
        }
    }

    std::vector<LoopInfo> loops;
    loops.reserve(loops_by_header.size());
    for (auto& [_, loop] : loops_by_header) {
        deduplicate_addresses(loop.latch_blocks);
        deduplicate_addresses(loop.body_blocks);
        loops.push_back(std::move(loop));
    }

    std::sort(
        loops.begin(),
        loops.end(),
        [](const LoopInfo& lhs, const LoopInfo& rhs) { return lhs.header_address < rhs.header_address; }
    );
    return loops;
}

std::vector<SwitchInfo> collect_switches(
    const std::vector<BasicBlock>& blocks,
    const memory::AddressSpace& address_space,
    const loader::Section& section,
    const loader::Architecture architecture
) {
    BlockMap blocks_by_start;
    for (const auto& block : blocks) {
        blocks_by_start.emplace(block.start_address, block);
    }

    const auto predecessors = build_predecessors(blocks_by_start);
    std::vector<SwitchInfo> switches;
    for (const auto& block : blocks) {
        if (const auto info = resolve_switch(block, predecessors, blocks_by_start, address_space, section, architecture);
            info.has_value()) {
            switches.push_back(*info);
        }
    }

    std::sort(
        switches.begin(),
        switches.end(),
        [](const SwitchInfo& lhs, const SwitchInfo& rhs) { return lhs.dispatch_block < rhs.dispatch_block; }
    );
    switches.erase(
        std::unique(
            switches.begin(),
            switches.end(),
            [](const SwitchInfo& lhs, const SwitchInfo& rhs) {
                return lhs.dispatch_block == rhs.dispatch_block && lhs.jump_address == rhs.jump_address;
            }
        ),
        switches.end()
    );
    return switches;
}

}  // namespace

FunctionGraph FunctionGraph::from_linear(std::string name, std::vector<disasm::Instruction> instructions) {
    FunctionGraph graph;
    graph.name_ = std::move(name);

    if (!instructions.empty()) {
        graph.entry_address_ = instructions.front().address;
        graph.blocks_.push_back(
            BasicBlock{
                .start_address = instructions.front().address,
                .end_address = instructions.back().address + instructions.back().size,
                .instructions = std::move(instructions),
                .successors = {},
            }
        );
    }

    return graph;
}

FunctionGraph FunctionGraph::analyze(
    std::string name,
    const memory::AddressSpace& address_space,
    const loader::Section& section,
    const std::uint64_t entry_address,
    const loader::Architecture architecture,
    const std::size_t max_block_bytes
) {
    FunctionGraph graph;
    graph.name_ = std::move(name);
    graph.entry_address_ = entry_address;

    if (section.bytes.empty() || !is_in_section(section, entry_address)) {
        return graph;
    }

    disasm::Disassembler disassembler;
    BlockMap blocks;
    std::vector<std::uint64_t> pending_block_starts{entry_address};
    std::unordered_set<std::uint64_t> known_block_starts{entry_address};
    std::unordered_set<std::uint64_t> visited_block_starts;

    auto enqueue_block_start = [&](const std::uint64_t address) {
        if (!is_in_section(section, address)) {
            return;
        }
        if (known_block_starts.insert(address).second) {
            pending_block_starts.push_back(address);
        }
    };

    auto decode_block = [&](const std::uint64_t block_start) {
        if (!visited_block_starts.insert(block_start).second || !is_in_section(section, block_start)) {
            return;
        }

        const auto remaining_bytes =
            static_cast<std::uint64_t>(section.bytes.size()) - (block_start - section.virtual_address);
        const auto decode_length = static_cast<std::size_t>(std::min<std::uint64_t>(max_block_bytes, remaining_bytes));
        const auto decoded_instructions = disassembler.decode(address_space, block_start, decode_length, architecture);
        if (decoded_instructions.empty()) {
            return;
        }

        BasicBlock block;
        block.start_address = block_start;

        bool terminated = false;
        for (const auto& instruction : decoded_instructions) {
            if (!is_in_section(section, instruction.address)) {
                break;
            }

            block.instructions.push_back(instruction);
            const std::uint64_t next_address = instruction.address + instruction.size;

            auto enqueue_successor = [&](const std::uint64_t address) {
                if (!is_in_section(section, address)) {
                    return;
                }

                block.successors.push_back(address);
                enqueue_block_start(address);
            };

            if (instruction.kind == disasm::InstructionKind::Call && instruction.control_flow_target.has_value()) {
                graph.direct_call_targets_.push_back(*instruction.control_flow_target);
            }

            switch (instruction.kind) {
            case disasm::InstructionKind::Call:
                if (next_address > instruction.address && is_in_section(section, next_address)) {
                    enqueue_successor(next_address);
                }
                block.end_address = next_address;
                terminated = true;
                break;
            case disasm::InstructionKind::Jump:
                if (instruction.control_flow_target.has_value()) {
                    enqueue_successor(*instruction.control_flow_target);
                }
                block.end_address = next_address;
                terminated = true;
                break;
            case disasm::InstructionKind::ConditionalJump:
                if (instruction.control_flow_target.has_value()) {
                    enqueue_successor(*instruction.control_flow_target);
                }
                if (next_address > instruction.address && is_in_section(section, next_address)) {
                    enqueue_successor(next_address);
                }
                block.end_address = next_address;
                terminated = true;
                break;
            case disasm::InstructionKind::Return:
            case disasm::InstructionKind::Interrupt:
                block.end_address = next_address;
                terminated = true;
                break;
            case disasm::InstructionKind::Unknown:
            case disasm::InstructionKind::DataByte:
            case disasm::InstructionKind::Instruction:
            default:
                if (next_address >= section.virtual_address + static_cast<std::uint64_t>(section.bytes.size())) {
                    block.end_address = next_address;
                    terminated = true;
                    break;
                }

                if (instruction_has_fallthrough(instruction) &&
                    known_block_starts.contains(next_address) &&
                    next_address != block_start) {
                    enqueue_successor(next_address);
                    block.end_address = next_address;
                    terminated = true;
                }
                break;
            }

            if (terminated) {
                break;
            }
        }

        if (block.instructions.empty()) {
            return;
        }

        if (!terminated) {
            const auto next_address = block.instructions.back().address + block.instructions.back().size;
            block.end_address = next_address;
            if (next_address > block.instructions.back().address && is_in_section(section, next_address)) {
                block.successors.push_back(next_address);
                enqueue_block_start(next_address);
            }
        }

        deduplicate_addresses(block.successors);
        blocks[block.start_address] = std::move(block);
    };

    while (!pending_block_starts.empty()) {
        const auto block_start = pending_block_starts.back();
        pending_block_starts.pop_back();
        decode_block(block_start);
    }

    bool changed = true;
    std::unordered_set<std::uint64_t> resolved_switch_dispatches;
    while (changed) {
        changed = false;

        const auto predecessors = build_predecessors(blocks);
        for (auto& [block_start, block] : blocks) {
            if (resolved_switch_dispatches.contains(block_start)) {
                continue;
            }

            const auto switch_info =
                resolve_switch(block, predecessors, blocks, address_space, section, architecture);
            if (!switch_info.has_value()) {
                continue;
            }

            resolved_switch_dispatches.insert(block_start);
            std::vector<std::uint64_t> switch_targets;
            for (const auto& switch_case : switch_info->cases) {
                switch_targets.push_back(switch_case.target);
            }
            if (switch_info->default_target.has_value()) {
                switch_targets.push_back(*switch_info->default_target);
            }

            for (const auto target : switch_targets) {
                if (!is_in_section(section, target)) {
                    continue;
                }
                block.successors.push_back(target);
                enqueue_block_start(target);
            }
            deduplicate_addresses(block.successors);
            changed = true;
        }

        while (!pending_block_starts.empty()) {
            const auto block_start = pending_block_starts.back();
            pending_block_starts.pop_back();
            decode_block(block_start);
            changed = true;
        }
    }

    graph.unreachable_blocks_removed_ = remove_unreachable_blocks(blocks, graph.entry_address_);
    graph.linear_block_merges_ = merge_linear_blocks(blocks);

    graph.blocks_.reserve(blocks.size());
    for (auto& [_, block] : blocks) {
        deduplicate_addresses(block.successors);
        graph.blocks_.push_back(std::move(block));
    }

    std::sort(
        graph.blocks_.begin(),
        graph.blocks_.end(),
        [](const BasicBlock& lhs, const BasicBlock& rhs) { return lhs.start_address < rhs.start_address; }
    );
    deduplicate_addresses(graph.direct_call_targets_);
    graph.switches_ = collect_switches(graph.blocks_, address_space, section, architecture);
    graph.loops_ = collect_loops(graph.blocks_, graph.entry_address_);
    return graph;
}

const std::string& FunctionGraph::name() const noexcept {
    return name_;
}

std::uint64_t FunctionGraph::entry_address() const noexcept {
    return entry_address_;
}

const std::vector<BasicBlock>& FunctionGraph::blocks() const noexcept {
    return blocks_;
}

const std::vector<std::uint64_t>& FunctionGraph::direct_call_targets() const noexcept {
    return direct_call_targets_;
}

const std::vector<LoopInfo>& FunctionGraph::loops() const noexcept {
    return loops_;
}

const std::vector<SwitchInfo>& FunctionGraph::switches() const noexcept {
    return switches_;
}

std::size_t FunctionGraph::unreachable_blocks_removed() const noexcept {
    return unreachable_blocks_removed_;
}

std::size_t FunctionGraph::linear_block_merges() const noexcept {
    return linear_block_merges_;
}

}  // namespace zara::cfg
