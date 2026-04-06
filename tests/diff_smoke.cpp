#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "zara/analysis/program_analysis.hpp"
#include "zara/diff/engine.hpp"

namespace {

zara::analysis::DiscoveredFunction make_function(
    const std::string& name,
    const std::uint64_t entry,
    const std::vector<std::string>& mnemonics
) {
    std::vector<zara::disasm::Instruction> instructions;
    std::uint64_t address = entry;
    for (const auto& mnemonic : mnemonics) {
        zara::disasm::InstructionKind kind = zara::disasm::InstructionKind::Instruction;
        if (mnemonic == "call") {
            kind = zara::disasm::InstructionKind::Call;
        } else if (mnemonic == "ret") {
            kind = zara::disasm::InstructionKind::Return;
        }

        instructions.push_back(
            zara::disasm::Instruction{
                .address = address,
                .size = 1,
                .kind = kind,
                .bytes = {0x90},
                .mnemonic = mnemonic,
                .operands = {},
                .decoded_operands = {},
                .control_flow_target = std::nullopt,
                .data_references = {},
            }
        );
        ++address;
    }

    return zara::analysis::DiscoveredFunction{
        .name = name,
        .section_name = ".text",
        .entry_address = entry,
        .graph = zara::cfg::FunctionGraph::from_linear(name, std::move(instructions)),
        .lifted_ir = {},
        .ssa_form = {},
        .recovered_types = {},
        .decompiled = {},
        .summary = {},
        .analysis_materialized = true,
    };
}

}  // namespace

int main() {
    zara::analysis::ProgramAnalysis before{
        .functions =
            {
                make_function("foo", 0x1000, {"push", "mov", "ret"}),
                make_function("bar", 0x1100, {"mov", "add", "ret"}),
                make_function("qux", 0x1200, {"xor", "xor", "ret"}),
            },
        .call_graph = {},
        .strings = {},
        .xrefs = {},
        .lazy_materialization = false,
        .cache_key = {},
        .internal_state = {},
    };

    zara::analysis::ProgramAnalysis after{
        .functions =
            {
                make_function("foo", 0x2000, {"push", "mov", "ret"}),
                make_function("bar", 0x2100, {"mov", "sub", "ret"}),
                make_function("baz", 0x2200, {"call", "ret"}),
            },
        .call_graph = {},
        .strings = {},
        .xrefs = {},
        .lazy_materialization = false,
        .cache_key = {},
        .internal_state = {},
    };

    const auto result = zara::diff::Engine::diff(before, after);
    if (result.unchanged_count != 1) {
        std::cerr << "expected one unchanged function, got " << result.unchanged_count << '\n';
        return 1;
    }
    if (result.modified_count != 1) {
        std::cerr << "expected one modified function, got " << result.modified_count << '\n';
        return 2;
    }
    if (result.added_count != 1) {
        std::cerr << "expected one added function, got " << result.added_count << '\n';
        return 3;
    }
    if (result.removed_count != 1) {
        std::cerr << "expected one removed function, got " << result.removed_count << '\n';
        return 4;
    }

    const auto has_foo = std::any_of(
        result.changes.begin(),
        result.changes.end(),
        [](const zara::diff::FunctionChange& change) {
            return change.kind == zara::diff::ChangeKind::Unchanged &&
                   change.old_name == "foo" &&
                   change.new_name == "foo";
        }
    );
    const auto has_bar = std::any_of(
        result.changes.begin(),
        result.changes.end(),
        [](const zara::diff::FunctionChange& change) {
            return change.kind == zara::diff::ChangeKind::Modified &&
                   change.old_name == "bar" &&
                   change.new_name == "bar" &&
                   change.similarity > 0.5;
        }
    );
    const auto has_baz = std::any_of(
        result.changes.begin(),
        result.changes.end(),
        [](const zara::diff::FunctionChange& change) {
            return change.kind == zara::diff::ChangeKind::Added &&
                   change.new_name == "baz";
        }
    );
    const auto has_qux = std::any_of(
        result.changes.begin(),
        result.changes.end(),
        [](const zara::diff::FunctionChange& change) {
            return change.kind == zara::diff::ChangeKind::Removed &&
                   change.old_name == "qux";
        }
    );

    if (!has_foo || !has_bar || !has_baz || !has_qux) {
        std::cerr << "missing expected diff classifications\n";
        return 5;
    }

    return 0;
}
