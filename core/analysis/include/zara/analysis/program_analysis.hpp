#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "zara/cfg/function_graph.hpp"
#include "zara/decompiler/decompiler.hpp"
#include "zara/ir/lifter.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"
#include "zara/ssa/builder.hpp"
#include "zara/type/recovery.hpp"
#include "zara/xrefs/analysis.hpp"

namespace zara::analysis {

enum class CallingConvention {
    Unknown,
    Cdecl32,
    SysVAMD64,
    AAPCS32,
    AAPCS64,
    RiscV64SysV,
    MipsN64,
    Ppc64ElfV2,
};

struct ConstantValue {
    std::string name;
    std::int64_t value = 0;
};

struct StackPointerState {
    std::uint64_t address = 0;
    std::int64_t offset = 0;
};

struct LocalVariable {
    std::string name;
    std::int64_t stack_offset = 0;
    std::uint64_t size = 0;
    ir::ScalarType type = ir::ScalarType::Unknown;
};

struct ArgumentInfo {
    std::string name;
    std::string location;
    ir::ScalarType type = ir::ScalarType::Unknown;
};

struct ReturnInfo {
    std::string location;
    ir::ScalarType type = ir::ScalarType::Unknown;
};

struct IndirectResolution {
    std::uint64_t instruction_address = 0;
    std::optional<std::uint64_t> resolved_target;
    std::string label;
};

struct FunctionAnalysisSummary {
    std::vector<ConstantValue> constants;
    std::size_t unreachable_blocks_removed = 0;
    std::size_t copy_propagations_applied = 0;
    std::size_t dead_instructions_eliminated = 0;
    std::size_t cfg_linear_merges = 0;
    std::vector<StackPointerState> stack_pointer_states;
    std::int64_t stack_frame_size = 0;
    bool uses_frame_pointer = false;
    std::vector<LocalVariable> locals;
    std::vector<std::string> pointer_variables;
    CallingConvention calling_convention = CallingConvention::Unknown;
    std::vector<ArgumentInfo> arguments;
    std::optional<ReturnInfo> return_value;
    std::vector<IndirectResolution> indirect_resolutions;
};

struct DiscoveredFunction {
    std::string name;
    std::string section_name;
    std::uint64_t entry_address = 0;
    cfg::FunctionGraph graph;
    ir::Function lifted_ir;
    ssa::Function ssa_form;
    type::FunctionTypes recovered_types;
    decompiler::DecompiledFunction decompiled;
    FunctionAnalysisSummary summary;
    bool analysis_materialized = true;
};

struct CallGraphEdge {
    std::uint64_t caller_entry = 0;
    std::uint64_t call_site = 0;
    std::optional<std::uint64_t> callee_entry;
    std::string callee_name;
    bool is_import = false;
};

struct ProgramAnalysis {
    std::vector<DiscoveredFunction> functions;
    std::vector<CallGraphEdge> call_graph;
    std::vector<xrefs::ExtractedString> strings;
    std::vector<xrefs::CrossReference> xrefs;
    bool lazy_materialization = false;
    std::string cache_key;
    std::shared_ptr<void> internal_state;

    [[nodiscard]] bool materialize_function(std::uint64_t entry_address);
    void materialize_all();
    [[nodiscard]] bool is_fully_materialized() const noexcept;
};

struct AnalyzeOptions {
    bool materialize_functions = true;
    bool use_cache = true;
    std::size_t max_worker_threads = 0;
};

struct AnalysisCacheStats {
    std::size_t discovery_hits = 0;
    std::size_t discovery_misses = 0;
    std::size_t function_hits = 0;
    std::size_t function_misses = 0;
    std::size_t lazy_materializations = 0;
};

class Analyzer {
public:
    [[nodiscard]] static ProgramAnalysis analyze(
        const loader::BinaryImage& image,
        const memory::AddressSpace& address_space,
        AnalyzeOptions options = {}
    );
    static void clear_cache();
    [[nodiscard]] static AnalysisCacheStats cache_stats();
};

[[nodiscard]] std::string_view to_string(CallingConvention convention) noexcept;

}  // namespace zara::analysis
