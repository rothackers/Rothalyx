#include <algorithm>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "zara/ai/assistant.hpp"

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

zara::analysis::DiscoveredFunction make_function(
    const std::string& name,
    const std::uint64_t entry,
    std::vector<zara::disasm::Instruction> instructions
) {
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
    zara::analysis::ProgramAnalysis program{
        .functions =
            {
                make_function(
                    "sub_00001000",
                    0x1000,
                    {
                        make_instruction(0x1000, "call", zara::disasm::InstructionKind::Call),
                        make_instruction(0x1001, "ret", zara::disasm::InstructionKind::Return),
                    }
                ),
                make_function(
                    "sub_00002000",
                    0x2000,
                    {
                        make_instruction(0x2000, "call", zara::disasm::InstructionKind::Call),
                        make_instruction(0x2001, "call", zara::disasm::InstructionKind::Call),
                        make_instruction(0x2002, "ret", zara::disasm::InstructionKind::Return),
                    }
                ),
            },
        .call_graph =
            {
                zara::analysis::CallGraphEdge{
                    .caller_entry = 0x1000,
                    .call_site = 0x1000,
                    .callee_entry = std::nullopt,
                    .callee_name = "libc.so.6!__libc_start_main",
                    .is_import = true,
                },
                zara::analysis::CallGraphEdge{
                    .caller_entry = 0x2000,
                    .call_site = 0x2000,
                    .callee_entry = std::nullopt,
                    .callee_name = "strlen",
                    .is_import = true,
                },
                zara::analysis::CallGraphEdge{
                    .caller_entry = 0x2000,
                    .call_site = 0x2001,
                    .callee_entry = std::nullopt,
                    .callee_name = "memcmp",
                    .is_import = true,
                },
            },
        .strings = {},
        .xrefs =
            {
                zara::xrefs::CrossReference{
                    .kind = zara::xrefs::CrossReferenceKind::String,
                    .from_address = 0x2000,
                    .to_address = 0x3000,
                    .label = "password check",
                },
            },
        .lazy_materialization = false,
        .cache_key = {},
        .internal_state = {},
    };

    const auto insights = zara::ai::Assistant::analyze_program(program, 0x1000);
    if (insights.size() != 2) {
        std::cerr << "expected 2 insights, got " << insights.size() << '\n';
        return 1;
    }

    const auto entry_it = std::find_if(
        insights.begin(),
        insights.end(),
        [](const zara::ai::FunctionInsight& insight) { return insight.entry_address == 0x1000; }
    );
    if (entry_it == insights.end() ||
        entry_it->suggested_name != "entry_startup" ||
        entry_it->summary.find("Runtime entry") == std::string::npos) {
        std::cerr << "missing startup insight\n";
        return 2;
    }

    const auto compare_it = std::find_if(
        insights.begin(),
        insights.end(),
        [](const zara::ai::FunctionInsight& insight) { return insight.entry_address == 0x2000; }
    );
    if (compare_it == insights.end() ||
        compare_it->suggested_name != "string_compare_helper" ||
        compare_it->summary.find("String and memory comparison") == std::string::npos) {
        std::cerr << "missing string helper insight\n";
        return 3;
    }

    const auto has_string_hint = std::any_of(
        compare_it->hints.begin(),
        compare_it->hints.end(),
        [](const std::string& hint) { return hint.find("password check") != std::string::npos; }
    );
    if (!has_string_hint) {
        std::cerr << "missing string hint\n";
        return 4;
    }

    const auto has_pattern = std::any_of(
        compare_it->patterns.begin(),
        compare_it->patterns.end(),
        [](const zara::ai::PatternDetection& pattern) {
            return pattern.category == "comparison" && pattern.label.find("comparison") != std::string::npos;
        }
    );
    if (!has_pattern) {
        std::cerr << "missing comparison pattern\n";
        return 5;
    }

    const auto has_vulnerability_hint = std::any_of(
        compare_it->vulnerability_hints.begin(),
        compare_it->vulnerability_hints.end(),
        [](const zara::ai::VulnerabilityHint& hint) { return hint.title.find("Format-string") != std::string::npos; }
    );
    if (has_vulnerability_hint) {
        std::cerr << "unexpected vulnerability hint for compare helper\n";
        return 6;
    }

    return 0;
}
