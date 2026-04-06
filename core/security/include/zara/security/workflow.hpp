#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "zara/analysis/program_analysis.hpp"

namespace zara::security {

enum class Severity {
    Low,
    Medium,
    High,
};

struct Gadget {
    std::uint64_t function_entry = 0;
    std::string function_name;
    std::uint64_t address = 0;
    std::string sequence;
    std::size_t instruction_count = 0;
};

struct RiskFinding {
    std::string category;
    Severity severity = Severity::Low;
    std::uint64_t function_entry = 0;
    std::string function_name;
    std::string title;
    std::string detail;
};

struct VulnerabilityPattern {
    std::string category;
    Severity severity = Severity::Low;
    std::uint64_t function_entry = 0;
    std::string function_name;
    std::string title;
    std::string detail;
    std::vector<std::string> poc_notes;
};

struct PocScaffoldTarget {
    std::string role;
    std::uint64_t function_entry = 0;
    std::string function_name;
    std::vector<std::string> notes;
};

struct StackSlot {
    std::int64_t offset = 0;
    std::uint64_t size = 0;
    std::string label;
    std::string classification;
};

struct StackVisualization {
    std::uint64_t function_entry = 0;
    std::string function_name;
    std::int64_t frame_size = 0;
    bool uses_frame_pointer = false;
    std::string base_register;
    std::vector<StackSlot> stack_slots;
    std::string rendered;
};

struct ExploitReport {
    std::vector<Gadget> gadgets;
    std::vector<RiskFinding> findings;
    std::vector<VulnerabilityPattern> patterns;
    std::vector<PocScaffoldTarget> poc_targets;
    std::vector<StackVisualization> stack_visualizations;
    std::string poc_scaffold;
};

struct CrashTrace {
    std::string input_label;
    std::optional<std::uint64_t> crash_address;
    std::vector<std::uint64_t> coverage_addresses;
};

struct CoveredFunction {
    std::uint64_t function_entry = 0;
    std::string function_name;
    std::size_t hit_count = 0;
    std::size_t instruction_count = 0;
    double coverage_ratio = 0.0;
    bool contains_crash_address = false;
};

struct MutationHook {
    std::uint64_t function_entry = 0;
    std::string function_name;
    std::optional<std::uint64_t> address;
    std::string kind;
    std::string label;
    std::string detail;
    std::string sample;
};

struct FuzzHarnessArtifact {
    std::string engine;
    std::string filename;
    std::string content;
};

struct FuzzingReport {
    std::string crash_summary;
    std::vector<CoveredFunction> covered_functions;
    std::vector<RiskFinding> crash_hints;
    std::vector<MutationHook> mutation_hooks;
    std::vector<FuzzHarnessArtifact> harness_artifacts;
};

struct FuzzProgressEvent {
    std::size_t sequence = 0;
    std::string kind;
    std::string source_line;
    std::optional<std::size_t> executions;
    std::optional<std::size_t> coverage;
    std::optional<std::size_t> corpus_size;
    bool crash_detected = false;
};

struct LiveFuzzOptions {
    std::filesystem::path working_directory;
    std::string engine_hint;
    std::size_t max_output_lines = 4096;
    std::size_t max_line_bytes = 16384;
    std::function<void(const FuzzProgressEvent&)> on_event;
};

struct LiveFuzzResult {
    std::string tool_name;
    int exit_code = -1;
    bool crash_detected = false;
    std::vector<std::string> output_lines;
    std::vector<FuzzProgressEvent> events;
};

class Workflow {
public:
    [[nodiscard]] static ExploitReport analyze_exploit_surface(
        const std::filesystem::path& binary_path,
        const analysis::ProgramAnalysis& program,
        std::size_t max_gadgets = 128
    );

    [[nodiscard]] static FuzzingReport map_crash_trace(
        const analysis::ProgramAnalysis& program,
        const CrashTrace& trace,
        std::size_t max_functions = 32
    );

    [[nodiscard]] static FuzzingReport analyze_fuzzing_surface(
        const std::filesystem::path& binary_path,
        const analysis::ProgramAnalysis& program,
        const CrashTrace& trace,
        std::size_t max_functions = 32
    );

    [[nodiscard]] static bool parse_trace_file(
        const std::filesystem::path& trace_path,
        CrashTrace& out_trace,
        std::string& out_error
    );

    [[nodiscard]] static bool write_harness_bundle(
        const std::filesystem::path& output_directory,
        const FuzzingReport& report,
        std::vector<std::filesystem::path>* out_written_paths,
        std::string& out_error
    );

    [[nodiscard]] static bool run_live_fuzz_tool(
        const std::string& command,
        const LiveFuzzOptions& options,
        LiveFuzzResult& out_result,
        std::string& out_error
    );
};

[[nodiscard]] std::string_view to_string(Severity severity) noexcept;

}  // namespace zara::security
