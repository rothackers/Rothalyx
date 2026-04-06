#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "zara/cfg/function_graph.hpp"
#include "zara/ssa/builder.hpp"
#include "zara/type/recovery.hpp"

namespace zara::decompiler {

struct DecompiledFunction {
    std::string name;
    std::string pseudocode;
};

struct CallSignatureArgument {
    std::string name;
    std::string owner_name;
    std::string decl_type;
    ir::ScalarType scalar_type = ir::ScalarType::Unknown;
};

struct CallTargetInfo {
    std::optional<std::uint64_t> entry_address;
    std::string display_name;
    std::string return_type = "void";
    std::vector<CallSignatureArgument> arguments;
    bool is_import = false;
};

struct ProgramMetadata {
    std::unordered_map<std::uint64_t, CallTargetInfo> call_targets_by_site;
};

class Decompiler {
public:
    [[nodiscard]] static DecompiledFunction decompile(
        const cfg::FunctionGraph& graph,
        const ssa::Function& function,
        const type::FunctionTypes& recovered_types,
        const ProgramMetadata* metadata = nullptr
    );
};

}  // namespace zara::decompiler
