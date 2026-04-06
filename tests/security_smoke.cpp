#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "zara/security/workflow.hpp"

namespace {

zara::disasm::Instruction make_instruction(
    const std::uint64_t address,
    const std::string& mnemonic,
    const std::string& operands = {},
    const zara::disasm::InstructionKind kind = zara::disasm::InstructionKind::Instruction
) {
    return zara::disasm::Instruction{
        .address = address,
        .size = 1,
        .kind = kind,
        .bytes = {0x90},
        .mnemonic = mnemonic,
        .operands = operands,
        .decoded_operands = {},
        .control_flow_target = std::nullopt,
        .data_references = {},
    };
}

zara::analysis::DiscoveredFunction make_function(
    const std::string& name,
    const std::uint64_t entry,
    std::vector<zara::disasm::Instruction> instructions,
    zara::analysis::FunctionAnalysisSummary summary = {}
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
        .summary = std::move(summary),
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
                        make_instruction(0x1000, "pop", "rdi"),
                        make_instruction(0x1001, "ret", {}, zara::disasm::InstructionKind::Return),
                    },
                    zara::analysis::FunctionAnalysisSummary{
                        .constants = {},
                        .unreachable_blocks_removed = 0,
                        .copy_propagations_applied = 0,
                        .dead_instructions_eliminated = 0,
                        .cfg_linear_merges = 0,
                        .stack_pointer_states = {},
                        .stack_frame_size = 32,
                        .uses_frame_pointer = true,
                        .locals =
                            {
                                zara::analysis::LocalVariable{
                                    .name = "buf_20",
                                    .stack_offset = -0x20,
                                    .size = 32,
                                    .type = zara::ir::ScalarType::Unknown,
                                },
                            },
                    }
                ),
                make_function(
                    "sub_00001100",
                    0x1100,
                    {
                        make_instruction(0x1100, "nop"),
                        make_instruction(0x1101, "ret", {}, zara::disasm::InstructionKind::Return),
                    }
                ),
            },
        .call_graph =
            {
                zara::analysis::CallGraphEdge{
                    .caller_entry = 0x1000,
                    .call_site = 0x1000,
                    .callee_entry = std::nullopt,
                    .callee_name = "gets",
                    .is_import = true,
                },
                zara::analysis::CallGraphEdge{
                    .caller_entry = 0x1100,
                    .call_site = 0x1100,
                    .callee_entry = std::nullopt,
                    .callee_name = "libc.so.6!system",
                    .is_import = true,
                },
            },
        .strings = {},
        .xrefs =
            {
                zara::xrefs::CrossReference{
                    .kind = zara::xrefs::CrossReferenceKind::String,
                    .from_address = 0x1100,
                    .to_address = 0x3000,
                    .label = "/bin/sh -c whoami",
                },
            },
        .lazy_materialization = false,
        .cache_key = {},
        .internal_state = {},
    };

    const auto exploit_report = zara::security::Workflow::analyze_exploit_surface("fixture.bin", program);
    const auto has_unsafe_call = std::any_of(
        exploit_report.findings.begin(),
        exploit_report.findings.end(),
        [](const zara::security::RiskFinding& finding) {
            return finding.title == "Unsafe C library call" && finding.function_entry == 0x1000;
        }
    );
    const auto has_command_exec = std::any_of(
        exploit_report.findings.begin(),
        exploit_report.findings.end(),
        [](const zara::security::RiskFinding& finding) {
            return finding.title == "Command execution primitive" && finding.function_entry == 0x1100;
        }
    );
    const auto has_pop_rdi = std::any_of(
        exploit_report.gadgets.begin(),
        exploit_report.gadgets.end(),
        [](const zara::security::Gadget& gadget) { return gadget.sequence == "pop rdi ; ret"; }
    );
    const auto has_overflow_pattern = std::any_of(
        exploit_report.patterns.begin(),
        exploit_report.patterns.end(),
        [](const zara::security::VulnerabilityPattern& pattern) {
            return pattern.category == "stack_overflow_surface" && pattern.function_entry == 0x1000;
        }
    );
    const auto has_command_target = std::any_of(
        exploit_report.poc_targets.begin(),
        exploit_report.poc_targets.end(),
        [](const zara::security::PocScaffoldTarget& target) {
            return target.role == "command_buffer" && target.function_entry == 0x1100;
        }
    );

    if (!has_unsafe_call || !has_command_exec || !has_pop_rdi || !has_overflow_pattern || !has_command_target) {
        std::cerr << "missing exploit findings or gadget\n";
        return 1;
    }
    if (exploit_report.stack_visualizations.empty() ||
        exploit_report.stack_visualizations.front().rendered.find("buf_20") == std::string::npos) {
        std::cerr << "missing stack visualization\n";
        return 7;
    }
    if (exploit_report.poc_scaffold.find("from pwn import *") == std::string::npos ||
        exploit_report.poc_scaffold.find("PoC targets") == std::string::npos ||
        exploit_report.poc_scaffold.find("Stack layouts") == std::string::npos) {
        std::cerr << "missing poc scaffold\n";
        return 2;
    }

    const auto trace_path =
        std::filesystem::temp_directory_path() / "zara_security_trace_smoke.txt";
    {
        std::ofstream trace(trace_path);
        trace << "input=seed-1\n";
        trace << "crash=0x1001\n";
        trace << "cover=0x1000\n";
        trace << "0x1001\n";
        trace << "0x1100\n";
    }

    zara::security::CrashTrace trace;
    std::string error;
    if (!zara::security::Workflow::parse_trace_file(trace_path, trace, error)) {
        std::cerr << "trace parse failed: " << error << '\n';
        return 3;
    }

    const auto fuzz_report = zara::security::Workflow::analyze_fuzzing_surface("fixture.bin", program, trace);
    if (fuzz_report.crash_summary.find("sub_00001000") == std::string::npos) {
        std::cerr << "unexpected crash summary: " << fuzz_report.crash_summary << '\n';
        return 4;
    }
    if (fuzz_report.covered_functions.size() != 2 ||
        !fuzz_report.covered_functions.front().contains_crash_address) {
        std::cerr << "unexpected covered function mapping\n";
        return 5;
    }
    if (fuzz_report.crash_hints.empty()) {
        std::cerr << "expected crash hints\n";
        return 6;
    }
    if (fuzz_report.mutation_hooks.empty() || fuzz_report.harness_artifacts.size() < 4) {
        std::cerr << "expected mutation hooks and harness artifacts\n";
        return 8;
    }

    std::set<std::string> artifact_names;
    for (const auto& artifact : fuzz_report.harness_artifacts) {
        artifact_names.insert(artifact.filename);
    }
    if (!artifact_names.contains("fuzz_driver_afl_persistent.cpp") ||
        !artifact_names.contains("reproduce_with_sanitizers.sh") ||
        !artifact_names.contains("coverage_report.json") ||
        !artifact_names.contains("mutation_hooks.json") ||
        !artifact_names.contains("seed_manifest.json")) {
        std::cerr << "expected deeper fuzzing harness artifacts\n";
        return 9;
    }

    const auto bundle_root = std::filesystem::temp_directory_path() / "zara_security_bundle_smoke";
    std::error_code remove_error;
    std::filesystem::remove_all(bundle_root, remove_error);
    std::vector<std::filesystem::path> written_paths;
    if (!zara::security::Workflow::write_harness_bundle(bundle_root, fuzz_report, &written_paths, error)) {
        std::cerr << "failed to write harness bundle: " << error << '\n';
        return 10;
    }
    if (!std::filesystem::exists(bundle_root / "reproduce_with_sanitizers.sh") ||
        !std::filesystem::exists(bundle_root / "fuzz_driver_afl_persistent.cpp") ||
        !std::filesystem::exists(bundle_root / "mutation_hooks.json")) {
        std::cerr << "expected written fuzz bundle artifacts\n";
        return 11;
    }

    const auto oversized_trace_path =
        std::filesystem::temp_directory_path() / "zara_security_trace_oversized.txt";
    {
        std::ofstream trace(oversized_trace_path);
        trace << "input=" << std::string(5000, 'A') << '\n';
    }

    zara::security::CrashTrace rejected_trace;
    error.clear();
    if (zara::security::Workflow::parse_trace_file(oversized_trace_path, rejected_trace, error)) {
        std::cerr << "expected oversized trace metadata to be rejected\n";
        return 12;
    }
    if (error.find("size limit") == std::string::npos) {
        std::cerr << "unexpected trace hardening error: " << error << '\n';
        return 13;
    }

    return 0;
}
