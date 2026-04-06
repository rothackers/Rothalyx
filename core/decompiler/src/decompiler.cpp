#include "zara/decompiler/decompiler.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <queue>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace zara::decompiler {

namespace {

constexpr std::size_t kInlineUseThreshold = 1;
constexpr std::size_t kMaxStructuredRegionDepth = 128;
constexpr std::size_t kMaxStructuredRegionEmissions = 20000;

std::string sanitize_identifier(std::string value) {
    for (char& character : value) {
        if (!std::isalnum(static_cast<unsigned char>(character)) && character != '_') {
            character = '_';
        }
    }
    if (value.empty()) {
        return "value";
    }
    if (std::isdigit(static_cast<unsigned char>(value.front())) != 0) {
        value.insert(value.begin(), '_');
    }
    return value;
}

std::string strip_ssa_suffix(std::string value) {
    const auto dot = value.rfind('.');
    if (dot == std::string::npos || dot + 1 >= value.size()) {
        return value;
    }
    const auto suffix = value.substr(dot + 1);
    if (!suffix.empty() &&
        std::all_of(
            suffix.begin(),
            suffix.end(),
            [](const unsigned char character) { return std::isdigit(character) != 0; }
        )) {
        value.erase(dot);
    }
    return value;
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

bool is_argument_register(const std::string_view name, std::size_t& out_index) {
    static const std::vector<std::string> kArgumentRegisters{
        "rdi",
        "rsi",
        "rdx",
        "rcx",
        "r8",
        "r9",
        "edi",
        "esi",
        "edx",
        "ecx",
        "x0",
        "x1",
        "x2",
        "x3",
        "x4",
        "x5",
        "x6",
        "x7",
    };

    for (std::size_t index = 0; index < kArgumentRegisters.size(); ++index) {
        if (kArgumentRegisters[index] == name) {
            out_index = index;
            return true;
        }
    }
    return false;
}

bool is_return_register(const std::string_view name) {
    return name == "rax" || name == "eax" || name == "x0";
}

std::string render_type(const ir::ScalarType type) {
    switch (type) {
    case ir::ScalarType::Bool:
        return "bool";
    case ir::ScalarType::I8:
        return "int8_t";
    case ir::ScalarType::I16:
        return "int16_t";
    case ir::ScalarType::I32:
        return "int32_t";
    case ir::ScalarType::I64:
        return "int64_t";
    case ir::ScalarType::Pointer:
        return "uintptr_t";
    case ir::ScalarType::Unknown:
    default:
        return "unknown_t";
    }
}

bool is_noise_local_name(const std::string_view lowered_name) {
    return lowered_name == "frame_ptr" || lowered_name == "stack_ptr" ||
           lowered_name == "condition" || lowered_name == "loaded_value" ||
           lowered_name == "unknown_value" || lowered_name == "popped_value" ||
           lowered_name == "tmp" || lowered_name.rfind("tmp_", 0) == 0 ||
           lowered_name == "stack_temp" || lowered_name.rfind("stack_temp_", 0) == 0 ||
           lowered_name == "frame_temp" || lowered_name.rfind("frame_temp_", 0) == 0;
}

int type_rank(const ir::ScalarType type) {
    switch (type) {
    case ir::ScalarType::Pointer:
        return 6;
    case ir::ScalarType::I64:
        return 5;
    case ir::ScalarType::I32:
        return 4;
    case ir::ScalarType::I16:
        return 3;
    case ir::ScalarType::I8:
        return 2;
    case ir::ScalarType::Bool:
        return 1;
    case ir::ScalarType::Unknown:
    default:
        return 0;
    }
}

ir::ScalarType merge_type(const ir::ScalarType current, const ir::ScalarType incoming) {
    if (current == ir::ScalarType::Unknown) {
        return incoming;
    }
    if (incoming == ir::ScalarType::Unknown || current == incoming) {
        return current;
    }
    return type_rank(incoming) > type_rank(current) ? incoming : current;
}

std::string indentation(const int level) {
    return std::string(static_cast<std::size_t>(std::max(level, 0)) * 4, ' ');
}

struct NormalizedFunction {
    ssa::Function function;
    std::unordered_map<std::string, ir::Value> trivial_aliases;
};

struct NamingState {
    std::unordered_map<std::string, std::string> names;
    std::unordered_map<std::string, ir::ScalarType> declaration_types;
    std::unordered_map<std::string, std::size_t> use_counts;
    std::unordered_map<std::string, std::size_t> collisions;
};

bool is_simple_value(const ir::Value& value) {
    switch (value.kind) {
    case ir::ValueKind::Immediate:
    case ir::ValueKind::Register:
    case ir::ValueKind::Temporary:
    case ir::ValueKind::MemoryAddress:
        return true;
    case ir::ValueKind::Invalid:
    default:
        return false;
    }
}

void replace_alias_in_value(const std::unordered_map<std::string, ir::Value>& aliases, ir::Value& value) {
    if ((value.kind != ir::ValueKind::Register && value.kind != ir::ValueKind::Temporary) || value.name.empty()) {
        return;
    }

    std::unordered_set<std::string> seen;
    while (true) {
        const auto alias_it = aliases.find(value.name);
        if (alias_it == aliases.end()) {
            break;
        }
        if (!seen.insert(value.name).second) {
            break;
        }
        value = alias_it->second;
    }
}

NormalizedFunction normalize_function(const ssa::Function& source) {
    NormalizedFunction normalized{.function = source, .trivial_aliases = {}};

    bool changed = true;
    while (changed) {
        changed = false;
        for (auto& block : normalized.function.blocks) {
            block.phi_nodes.erase(
                std::remove_if(
                    block.phi_nodes.begin(),
                    block.phi_nodes.end(),
                    [&](const ssa::PhiNode& phi) {
                        if (phi.result_name.empty() || phi.incoming.empty()) {
                            return false;
                        }

                        std::optional<std::string> shared_name;
                        bool all_same = true;
                        for (const auto& incoming : phi.incoming) {
                            if (incoming.second.empty()) {
                                all_same = false;
                                break;
                            }
                            if (!shared_name.has_value()) {
                                shared_name = incoming.second;
                            } else if (*shared_name != incoming.second) {
                                all_same = false;
                                break;
                            }
                        }
                        if (!all_same || !shared_name.has_value()) {
                            return false;
                        }

                        normalized.trivial_aliases[phi.result_name] =
                            ir::Value{
                                .kind = ir::ValueKind::Temporary,
                                .type = ir::ScalarType::Unknown,
                                .name = *shared_name,
                            };
                        changed = true;
                        return true;
                    }
                ),
                block.phi_nodes.end()
            );

            for (auto& instruction : block.instructions) {
                for (auto& input : instruction.inputs) {
                    replace_alias_in_value(normalized.trivial_aliases, input);
                }
                if (instruction.destination.has_value()) {
                    replace_alias_in_value(normalized.trivial_aliases, *instruction.destination);
                }
            }
        }
    }

    return normalized;
}

void observe_name(NamingState& state, const std::string& name, const ir::ScalarType type) {
    if (name.empty()) {
        return;
    }
    state.declaration_types[name] = merge_type(state.declaration_types[name], type);
}

void count_value_use(NamingState& state, const ir::Value& value) {
    if ((value.kind == ir::ValueKind::Register || value.kind == ir::ValueKind::Temporary) && !value.name.empty()) {
        ++state.use_counts[value.name];
    }
}

std::string friendly_base_name(const std::string& raw_name, NamingState& state) {
    const std::string lowered = lowercase_copy(strip_ssa_suffix(raw_name));
    std::size_t argument_index = 0;
    if (is_argument_register(lowered, argument_index)) {
        return "arg_" + std::to_string(argument_index);
    }
    if (lowered == "rbp" || lowered == "ebp" || lowered == "x29") {
        return "frame_ptr";
    }
    if (lowered == "rsp" || lowered == "esp" || lowered == "sp") {
        return "stack_ptr";
    }
    if (is_return_register(lowered)) {
        return "result";
    }
    if (lowered.rfind("flags_", 0) == 0) {
        return "condition";
    }
    if (lowered.rfind("load_", 0) == 0) {
        return "loaded_value";
    }
    if (lowered.rfind("arith_", 0) == 0) {
        return "tmp";
    }
    if (lowered.rfind("unknown_", 0) == 0) {
        return "unknown_value";
    }
    if (lowered.rfind("sp_", 0) == 0) {
        return "stack_temp";
    }
    if (lowered.rfind("frame_", 0) == 0) {
        return "frame_temp";
    }
    if (lowered.rfind("pop_", 0) == 0) {
        return "popped_value";
    }
    return sanitize_identifier(lowered);
}

std::string assign_friendly_name(const std::string& raw_name, NamingState& state) {
    const auto existing = state.names.find(raw_name);
    if (existing != state.names.end()) {
        return existing->second;
    }

    const std::string base = friendly_base_name(raw_name, state);
    auto& collision = state.collisions[base];
    std::string assigned = base;
    if (collision > 0) {
        assigned += '_' + std::to_string(collision);
    }
    ++collision;
    assigned = sanitize_identifier(assigned);
    state.names.emplace(raw_name, assigned);
    return assigned;
}

NamingState build_naming_state(const ssa::Function& function, const type::FunctionTypes& recovered_types) {
    NamingState state;

    for (const auto& variable : recovered_types.variables) {
        observe_name(state, variable.name, variable.type);
    }

    for (const auto& block : function.blocks) {
        for (const auto& phi : block.phi_nodes) {
            observe_name(state, phi.result_name, ir::ScalarType::Unknown);
            for (const auto& incoming : phi.incoming) {
                observe_name(state, incoming.second, ir::ScalarType::Unknown);
                ++state.use_counts[incoming.second];
            }
        }

        for (const auto& instruction : block.instructions) {
            if (instruction.destination.has_value() &&
                (instruction.destination->kind == ir::ValueKind::Register ||
                 instruction.destination->kind == ir::ValueKind::Temporary)) {
                observe_name(state, instruction.destination->name, instruction.destination->type);
            }
            for (const auto& input : instruction.inputs) {
                count_value_use(state, input);
                if (input.kind == ir::ValueKind::MemoryAddress) {
                    observe_name(state, input.memory.base, ir::ScalarType::Pointer);
                    observe_name(state, input.memory.index, ir::ScalarType::Pointer);
                }
            }
        }
    }

    for (const auto& [name, _] : state.declaration_types) {
        (void)assign_friendly_name(name, state);
    }
    return state;
}

struct RenderContext {
    const cfg::FunctionGraph& graph;
    const ssa::Function& function;
    const type::FunctionTypes& recovered_types;
    const ProgramMetadata* metadata;
    NormalizedFunction normalized;
    NamingState naming;
    std::unordered_map<std::uint64_t, const ssa::BasicBlock*> blocks_by_address;
    std::unordered_map<std::uint64_t, const cfg::BasicBlock*> cfg_blocks_by_address;
    std::unordered_map<std::uint64_t, const cfg::LoopInfo*> loops_by_header;
    std::unordered_map<std::uint64_t, const cfg::SwitchInfo*> switches_by_dispatch;
    std::unordered_map<std::uint64_t, std::size_t> block_order;
    std::unordered_set<std::uint64_t> emitted_blocks;
    std::unordered_map<std::string, std::string> inline_expressions;
    std::size_t active_region_depth = 0;
    std::size_t max_region_depth = kMaxStructuredRegionDepth;
    std::size_t emitted_region_count = 0;
    std::size_t max_region_emissions = kMaxStructuredRegionEmissions;
};

class RegionGuard {
public:
    explicit RegionGuard(RenderContext& context) : context_(context) {
        ++context_.active_region_depth;
    }

    ~RegionGuard() {
        if (context_.active_region_depth > 0) {
            --context_.active_region_depth;
        }
    }

private:
    RenderContext& context_;
};

bool allow_region_emission(RenderContext& context, std::ostringstream& stream, const int indent) {
    if (context.active_region_depth > context.max_region_depth) {
        stream << indentation(indent) << "/* structured output truncated: region-depth budget exceeded */\n";
        return false;
    }
    if (context.emitted_region_count >= context.max_region_emissions) {
        stream << indentation(indent) << "/* structured output truncated: region emission budget exceeded */\n";
        return false;
    }
    ++context.emitted_region_count;
    return true;
}

std::string basename_for_symbol(std::string value) {
    const auto bang = value.rfind('!');
    if (bang != std::string::npos && bang + 1 < value.size()) {
        value = value.substr(bang + 1);
    }
    const auto scope = value.rfind("::");
    if (scope != std::string::npos && scope + 2 < value.size()) {
        value = value.substr(scope + 2);
    }
    return value;
}

std::string render_recovered_type_definitions(const type::FunctionTypes& recovered_types) {
    if (recovered_types.structs.empty() && recovered_types.arrays.empty()) {
        return {};
    }

    std::ostringstream stream;
    std::unordered_set<std::string> emitted_names;

    for (const auto& recovered_struct : recovered_types.structs) {
        if (!emitted_names.insert(recovered_struct.type_name).second) {
            continue;
        }
        stream << "struct " << sanitize_identifier(recovered_struct.type_name) << " {\n";
        for (const auto& field : recovered_struct.fields) {
            stream << indentation(1) << render_type(field.type) << ' '
                   << sanitize_identifier(field.name) << ";\n";
        }
        stream << "};\n\n";
    }

    for (const auto& recovered_array : recovered_types.arrays) {
        if (!emitted_names.insert(recovered_array.type_name).second) {
            continue;
        }
        const auto observed_elements = std::max<std::size_t>(1, recovered_array.observed_elements);
        stream << "typedef " << render_type(recovered_array.element_type) << ' '
               << sanitize_identifier(recovered_array.type_name) << '[' << observed_elements << "];\n\n";
    }

    return stream.str();
}

const ssa::BasicBlock* find_block(const RenderContext& context, const std::uint64_t address) {
    const auto it = context.blocks_by_address.find(address);
    return it == context.blocks_by_address.end() ? nullptr : it->second;
}

const cfg::BasicBlock* find_cfg_block(const RenderContext& context, const std::uint64_t address) {
    const auto it = context.cfg_blocks_by_address.find(address);
    return it == context.cfg_blocks_by_address.end() ? nullptr : it->second;
}

std::string render_value(const RenderContext& context, const ir::Value& value, bool allow_inline = true);

std::string render_named_identifier(
    const RenderContext& context,
    const std::string_view raw_name,
    const bool allow_inline = false
) {
    if (raw_name.empty()) {
        return {};
    }

    if (allow_inline) {
        const auto inline_it = context.inline_expressions.find(std::string(raw_name));
        if (inline_it != context.inline_expressions.end()) {
            return inline_it->second;
        }
    }

    const auto name_it = context.naming.names.find(std::string(raw_name));
    if (name_it != context.naming.names.end()) {
        return sanitize_identifier(name_it->second);
    }

    return sanitize_identifier(strip_ssa_suffix(std::string(raw_name)));
}

const type::RecoveredStructField* find_struct_field(
    const type::RecoveredStruct& recovered_struct,
    const std::int64_t offset
) {
    const auto it = std::find_if(
        recovered_struct.fields.begin(),
        recovered_struct.fields.end(),
        [&](const type::RecoveredStructField& field) { return field.offset == offset; }
    );
    return it == recovered_struct.fields.end() ? nullptr : &(*it);
}

const type::RecoveredStruct* find_matching_struct(
    const type::FunctionTypes& recovered_types,
    const std::string_view owner_name
) {
    if (const auto* recovered = type::find_struct(recovered_types, owner_name); recovered != nullptr) {
        return recovered;
    }

    const std::string normalized_owner = lowercase_copy(strip_ssa_suffix(std::string(owner_name)));
    const auto it = std::find_if(
        recovered_types.structs.begin(),
        recovered_types.structs.end(),
        [&](const type::RecoveredStruct& recovered) {
            return lowercase_copy(strip_ssa_suffix(recovered.owner_name)) == normalized_owner;
        }
    );
    return it == recovered_types.structs.end() ? nullptr : &(*it);
}

const type::RecoveredArray* find_matching_array(
    const type::FunctionTypes& recovered_types,
    const std::string_view owner_name
) {
    if (const auto* recovered = type::find_array(recovered_types, owner_name); recovered != nullptr) {
        return recovered;
    }

    const std::string normalized_owner = lowercase_copy(strip_ssa_suffix(std::string(owner_name)));
    const auto it = std::find_if(
        recovered_types.arrays.begin(),
        recovered_types.arrays.end(),
        [&](const type::RecoveredArray& recovered) {
            return lowercase_copy(strip_ssa_suffix(recovered.owner_name)) == normalized_owner;
        }
    );
    return it == recovered_types.arrays.end() ? nullptr : &(*it);
}

std::optional<std::string> render_typed_memory_access(const RenderContext& context, const ir::Value& value) {
    if (value.kind != ir::ValueKind::MemoryAddress) {
        return std::nullopt;
    }

    const std::string owner_name = !value.memory.base.empty() ? value.memory.base : value.memory.index;
    if (owner_name.empty()) {
        return std::nullopt;
    }

    const std::string owner = render_named_identifier(context, owner_name);
    if (owner.empty()) {
        return std::nullopt;
    }

    if (value.memory.index.empty()) {
        if (const auto* recovered_struct = find_matching_struct(context.recovered_types, owner_name);
            recovered_struct != nullptr) {
            if (const auto* field = find_struct_field(*recovered_struct, value.memory.displacement); field != nullptr) {
                return owner + "->" + sanitize_identifier(field->name);
            }
        }
    }

    if (const auto* recovered_array = find_matching_array(context.recovered_types, owner_name); recovered_array != nullptr) {
        const auto element_size = std::max<std::uint64_t>(1, recovered_array->element_size);
        std::string index_expression;
        if (!value.memory.index.empty()) {
            index_expression = render_named_identifier(context, value.memory.index, true);
            if (value.memory.scale > 1 && value.memory.scale != element_size) {
                if (value.memory.scale % element_size == 0) {
                    index_expression += " * " + std::to_string(value.memory.scale / element_size);
                } else {
                    return std::nullopt;
                }
            }
        } else {
            if (value.memory.displacement % static_cast<std::int64_t>(element_size) != 0) {
                return std::nullopt;
            }
            index_expression = std::to_string(value.memory.displacement / static_cast<std::int64_t>(element_size));
        }

        if (!value.memory.index.empty() && value.memory.displacement != 0) {
            if (value.memory.displacement % static_cast<std::int64_t>(element_size) != 0) {
                return std::nullopt;
            }
            const auto element_offset = value.memory.displacement / static_cast<std::int64_t>(element_size);
            if (element_offset > 0) {
                index_expression += " + " + std::to_string(element_offset);
            } else if (element_offset < 0) {
                index_expression += " - " + std::to_string(std::llabs(element_offset));
            }
        }

        return owner + "[" + index_expression + "]";
    }

    return std::nullopt;
}

const CallTargetInfo* find_call_target_info(const RenderContext& context, const std::uint64_t address) {
    if (context.metadata == nullptr) {
        return nullptr;
    }

    const auto it = context.metadata->call_targets_by_site.find(address);
    return it == context.metadata->call_targets_by_site.end() ? nullptr : &it->second;
}

std::string render_memory_address(const RenderContext& context, const ir::Value& value) {
    std::ostringstream stream;
    stream << '(';
    bool needs_separator = false;

    if (!value.memory.base.empty()) {
        stream << render_named_identifier(context, value.memory.base);
        needs_separator = true;
    }
    if (!value.memory.index.empty()) {
        if (needs_separator) {
            stream << " + ";
        }
        stream << render_named_identifier(context, value.memory.index);
        if (value.memory.scale > 1) {
            stream << " * " << static_cast<unsigned int>(value.memory.scale);
        }
        needs_separator = true;
    }
    if (value.memory.displacement != 0 || !needs_separator) {
        if (needs_separator) {
            stream << (value.memory.displacement >= 0 ? " + " : " - ");
            stream << std::llabs(value.memory.displacement);
        } else {
            stream << value.memory.displacement;
        }
    }
    stream << ')';
    return stream.str();
}

std::string render_binary_expression(const std::string& lhs, const std::string& rhs, const ir::BinaryOperator operation) {
    switch (operation) {
    case ir::BinaryOperator::Add:
        if (rhs == "0") {
            return lhs;
        }
        if (lhs == "0") {
            return rhs;
        }
        return lhs + " + " + rhs;
    case ir::BinaryOperator::Sub:
        if (rhs == "0") {
            return lhs;
        }
        return lhs + " - " + rhs;
    case ir::BinaryOperator::And:
        if (lhs == rhs) {
            return lhs;
        }
        return lhs + " & " + rhs;
    case ir::BinaryOperator::Or:
        if (rhs == "0") {
            return lhs;
        }
        if (lhs == "0") {
            return rhs;
        }
        if (lhs == rhs) {
            return lhs;
        }
        return lhs + " | " + rhs;
    case ir::BinaryOperator::Xor:
        if (lhs == rhs) {
            return "0";
        }
        if (rhs == "0") {
            return lhs;
        }
        return lhs + " ^ " + rhs;
    }
    return lhs + " ? " + rhs;
}

std::string render_call_expression(const RenderContext& context, const ir::Instruction& instruction) {
    const CallTargetInfo* target_info = find_call_target_info(context, instruction.address);
    std::size_t argument_offset = 0;
    std::string callee_expression;

    if (target_info != nullptr && !target_info->display_name.empty()) {
        callee_expression = sanitize_identifier(basename_for_symbol(target_info->display_name));
        if (!instruction.true_target.has_value() && !instruction.inputs.empty()) {
            argument_offset = 1;
        }
    } else if (instruction.true_target.has_value()) {
        std::ostringstream stream;
        stream << "sub_" << std::hex << std::uppercase << *instruction.true_target;
        callee_expression = stream.str();
    } else if (!instruction.inputs.empty()) {
        callee_expression = "(*" + render_value(context, instruction.inputs.front()) + ')';
        argument_offset = 1;
    } else {
        callee_expression = "call";
    }

    std::vector<std::string> arguments;
    const std::size_t available_inputs =
        instruction.inputs.size() > argument_offset ? instruction.inputs.size() - argument_offset : 0;
    const std::size_t typed_argument_count =
        target_info == nullptr ? 0 : std::min<std::size_t>(available_inputs, target_info->arguments.size());

    for (std::size_t index = 0; index < typed_argument_count; ++index) {
        const auto& argument = target_info->arguments[index];
        std::string rendered = render_value(context, instruction.inputs[argument_offset + index]);
        if (!argument.decl_type.empty() && argument.decl_type != "unknown_t" &&
            argument.decl_type != "uintptr_t" && argument.decl_type != "int64_t") {
            rendered = "(" + argument.decl_type + ")" + rendered;
        }
        arguments.push_back(std::move(rendered));
    }

    for (std::size_t index = typed_argument_count; index < available_inputs; ++index) {
        arguments.push_back(render_value(context, instruction.inputs[argument_offset + index]));
    }

    std::ostringstream stream;
    stream << callee_expression << '(';
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        if (index > 0) {
            stream << ", ";
        }
        stream << arguments[index];
    }
    stream << ')';
    return stream.str();
}

std::string render_value(const RenderContext& context, const ir::Value& value, const bool allow_inline) {
    switch (value.kind) {
    case ir::ValueKind::Register:
    case ir::ValueKind::Temporary:
        if (allow_inline) {
            const auto inline_it = context.inline_expressions.find(value.name);
            if (inline_it != context.inline_expressions.end()) {
                return inline_it->second;
            }
        }
        if (const auto name_it = context.naming.names.find(value.name); name_it != context.naming.names.end()) {
            return sanitize_identifier(name_it->second);
        }
        return sanitize_identifier(strip_ssa_suffix(value.name));
    case ir::ValueKind::Immediate:
        return std::to_string(value.immediate);
    case ir::ValueKind::MemoryAddress:
        return render_memory_address(context, value);
    case ir::ValueKind::Invalid:
    default:
        return "invalid_value";
    }
}

bool is_inline_candidate(const RenderContext& context, const ir::Instruction& instruction) {
    if (!instruction.destination.has_value() ||
        (instruction.destination->kind != ir::ValueKind::Temporary &&
         instruction.destination->kind != ir::ValueKind::Register) ||
        instruction.destination->name.empty()) {
        return false;
    }

    const auto use_count_it = context.naming.use_counts.find(instruction.destination->name);
    const std::size_t use_count = use_count_it == context.naming.use_counts.end() ? 0 : use_count_it->second;
    if (use_count > kInlineUseThreshold) {
        return false;
    }

    switch (instruction.kind) {
    case ir::InstructionKind::Assign:
    case ir::InstructionKind::Load:
    case ir::InstructionKind::Binary:
    case ir::InstructionKind::Compare:
    case ir::InstructionKind::Test:
        return true;
    case ir::InstructionKind::Store:
    case ir::InstructionKind::Call:
    case ir::InstructionKind::Branch:
    case ir::InstructionKind::CondBranch:
    case ir::InstructionKind::Return:
    case ir::InstructionKind::Nop:
    case ir::InstructionKind::SetFlags:
    case ir::InstructionKind::Intrinsic:
    default:
        return false;
    }
}

bool should_skip_local_declaration(
    const RenderContext& context,
    const std::string& raw_name,
    const std::string& friendly_name
) {
    const std::string lowered_raw = lowercase_copy(strip_ssa_suffix(raw_name));
    const std::string lowered_friendly = lowercase_copy(friendly_name);

    std::size_t argument_index = 0;
    if (is_argument_register(lowered_raw, argument_index) || is_return_register(lowered_raw)) {
        return true;
    }
    if (is_noise_local_name(lowered_friendly)) {
        return true;
    }
    if (lowered_raw.rfind("flags_", 0) == 0 || lowered_raw.rfind("load_", 0) == 0 ||
        lowered_raw.rfind("arith_", 0) == 0 || lowered_raw.rfind("unknown_", 0) == 0 ||
        lowered_raw.rfind("sp_", 0) == 0 || lowered_raw.rfind("frame_", 0) == 0 ||
        lowered_raw.rfind("pop_", 0) == 0) {
        return true;
    }

    const auto use_count_it = context.naming.use_counts.find(raw_name);
    const std::size_t use_count = use_count_it == context.naming.use_counts.end() ? 0 : use_count_it->second;
    if (context.inline_expressions.contains(raw_name) && use_count <= kInlineUseThreshold) {
        return true;
    }

    return false;
}

std::string compare_operator_from_mnemonic(const std::string_view mnemonic) {
    const std::string lowered = lowercase_copy(std::string(mnemonic));
    if (lowered == "je" || lowered == "jz") {
        return "==";
    }
    if (lowered == "jne" || lowered == "jnz") {
        return "!=";
    }
    if (lowered == "ja" || lowered == "jg") {
        return ">";
    }
    if (lowered == "jae" || lowered == "jnb" || lowered == "jge") {
        return ">=";
    }
    if (lowered == "jb" || lowered == "jc" || lowered == "jl") {
        return "<";
    }
    if (lowered == "jbe" || lowered == "jle") {
        return "<=";
    }
    return "!=";
}

std::optional<std::string> try_render_condition_from_producer(
    const RenderContext& context,
    const ssa::BasicBlock& block,
    const ir::Instruction& branch
) {
    if (branch.inputs.empty()) {
        return std::nullopt;
    }

    const ir::Value& condition = branch.inputs.front();
    if ((condition.kind != ir::ValueKind::Register && condition.kind != ir::ValueKind::Temporary) || condition.name.empty()) {
        if (condition.kind == ir::ValueKind::Immediate) {
            return condition.immediate == 0 ? "false" : "true";
        }
        return std::nullopt;
    }

    for (auto instruction_it = block.instructions.rbegin(); instruction_it != block.instructions.rend(); ++instruction_it) {
        if (!instruction_it->destination.has_value() || instruction_it->destination->name != condition.name) {
            continue;
        }

        if ((instruction_it->kind == ir::InstructionKind::Compare || instruction_it->kind == ir::InstructionKind::Test) &&
            instruction_it->inputs.size() >= 2) {
            const std::string lhs = render_value(context, instruction_it->inputs[0]);
            const std::string rhs = render_value(context, instruction_it->inputs[1]);
            if (instruction_it->kind == ir::InstructionKind::Compare) {
                return lhs + ' ' + compare_operator_from_mnemonic(branch.text) + ' ' + rhs;
            }

            const std::string test_expr = '(' + lhs + " & " + rhs + ')';
            const std::string lowered = lowercase_copy(branch.text);
            if (lowered == "je" || lowered == "jz") {
                return test_expr + " == 0";
            }
            if (lowered == "jne" || lowered == "jnz") {
                return test_expr + " != 0";
            }
            return test_expr;
        }

        if (instruction_it->kind == ir::InstructionKind::Assign && !instruction_it->inputs.empty()) {
            return render_value(context, instruction_it->inputs.front());
        }
    }

    return render_value(context, condition);
}

bool is_return_instruction(const ir::Instruction& instruction) {
    return instruction.kind == ir::InstructionKind::Return;
}

bool is_branch_instruction(const ir::Instruction& instruction) {
    return instruction.kind == ir::InstructionKind::Branch || instruction.kind == ir::InstructionKind::CondBranch;
}

bool is_condition_producer(const ir::Instruction& instruction) {
    return instruction.kind == ir::InstructionKind::Compare ||
           instruction.kind == ir::InstructionKind::Test ||
           instruction.kind == ir::InstructionKind::SetFlags;
}

std::string render_statement(const RenderContext& context, const ir::Instruction& instruction) {
    switch (instruction.kind) {
    case ir::InstructionKind::Assign:
        if (instruction.destination.has_value() && !instruction.inputs.empty()) {
            return render_value(context, *instruction.destination, false) + " = " +
                   render_value(context, instruction.inputs.front()) + ';';
        }
        break;
    case ir::InstructionKind::Load:
        if (instruction.destination.has_value() && !instruction.inputs.empty()) {
            if (const auto typed_access = render_typed_memory_access(context, instruction.inputs.front());
                typed_access.has_value()) {
                return render_value(context, *instruction.destination, false) + " = " + *typed_access + ';';
            }
            return render_value(context, *instruction.destination, false) + " = *" +
                   render_value(context, instruction.inputs.front()) + ';';
        }
        break;
    case ir::InstructionKind::Store:
        if (instruction.inputs.size() >= 2) {
            if (const auto typed_access = render_typed_memory_access(context, instruction.inputs[0]);
                typed_access.has_value()) {
                return *typed_access + " = " + render_value(context, instruction.inputs[1]) + ';';
            }
            return "*" + render_value(context, instruction.inputs[0]) + " = " +
                   render_value(context, instruction.inputs[1]) + ';';
        }
        break;
    case ir::InstructionKind::Binary:
        if (instruction.destination.has_value() && instruction.inputs.size() >= 2 && instruction.binary_operator.has_value()) {
            return render_value(context, *instruction.destination, false) + " = " +
                   render_binary_expression(
                       render_value(context, instruction.inputs[0]),
                       render_value(context, instruction.inputs[1]),
                       *instruction.binary_operator
                   ) +
                   ';';
        }
        break;
    case ir::InstructionKind::Call:
        return render_call_expression(context, instruction) + ';';
    case ir::InstructionKind::Intrinsic:
        return "/* " + instruction.text + " */";
    case ir::InstructionKind::Nop:
        return "/* nop */";
    case ir::InstructionKind::Compare:
    case ir::InstructionKind::Test:
    case ir::InstructionKind::SetFlags:
    case ir::InstructionKind::Branch:
    case ir::InstructionKind::CondBranch:
    case ir::InstructionKind::Return:
        break;
    }

    return "/* " + ir::format_instruction(instruction) + " */";
}

std::optional<std::uint64_t> common_successor(
    const RenderContext& context,
    const std::vector<std::uint64_t>& starts,
    const std::unordered_set<std::uint64_t>& excluded
) {
    if (starts.size() < 2) {
        return std::nullopt;
    }

    std::vector<std::unordered_set<std::uint64_t>> reachables;
    reachables.reserve(starts.size());

    for (const auto start : starts) {
        std::unordered_set<std::uint64_t> reachable;
        std::vector<std::uint64_t> stack{start};
        while (!stack.empty()) {
            const auto current = stack.back();
            stack.pop_back();
            if (excluded.contains(current) || !reachable.insert(current).second) {
                continue;
            }
            const auto* block = find_block(context, current);
            if (block == nullptr) {
                continue;
            }
            for (const auto successor : block->successors) {
                stack.push_back(successor);
            }
        }
        reachables.push_back(std::move(reachable));
    }

    std::optional<std::uint64_t> best;
    std::size_t best_order = std::numeric_limits<std::size_t>::max();
    for (const auto& [address, order] : context.block_order) {
        if (excluded.contains(address)) {
            continue;
        }
        bool present_in_all = true;
        for (const auto& reachable : reachables) {
            if (!reachable.contains(address)) {
                present_in_all = false;
                break;
            }
        }
        if (present_in_all && order < best_order) {
            best = address;
            best_order = order;
        }
    }
    return best;
}

std::string switch_expression(const RenderContext& context, const std::uint64_t dispatch_address) {
    const auto* cfg_block = find_cfg_block(context, dispatch_address);
    if (cfg_block == nullptr || cfg_block->instructions.empty()) {
        return "selector";
    }

    const auto& instruction = cfg_block->instructions.back();
    for (const auto& operand : instruction.decoded_operands) {
        if (operand.kind == disasm::OperandKind::Memory && !operand.memory.index.empty()) {
            if (const auto name_it = context.naming.names.find(operand.memory.index); name_it != context.naming.names.end()) {
                return sanitize_identifier(name_it->second);
            }
            return sanitize_identifier(strip_ssa_suffix(operand.memory.index));
        }
    }
    return "selector";
}

std::string render_return_statement(const RenderContext& context, const ssa::BasicBlock& block) {
    for (auto instruction_it = block.instructions.rbegin(); instruction_it != block.instructions.rend(); ++instruction_it) {
        if (instruction_it->kind == ir::InstructionKind::Return) {
            continue;
        }
        if (!instruction_it->destination.has_value()) {
            continue;
        }
        const auto& destination = *instruction_it->destination;
        const std::string lowered = lowercase_copy(strip_ssa_suffix(destination.name));
        if (!is_return_register(lowered)) {
            continue;
        }
        if (context.inline_expressions.contains(destination.name)) {
            return "return " + context.inline_expressions.at(destination.name) + ';';
        }
        return "return " + render_value(context, destination) + ';';
    }
    return "return;";
}

bool block_has_loop_side_effects(const ssa::BasicBlock& block) {
    for (const auto& instruction : block.instructions) {
        if (instruction.kind == ir::InstructionKind::CondBranch || is_condition_producer(instruction)) {
            continue;
        }
        if (instruction.kind == ir::InstructionKind::Nop) {
            continue;
        }
        return true;
    }
    return false;
}

void build_inline_expressions(RenderContext& context) {
    for (const auto& block : context.normalized.function.blocks) {
        for (const auto& instruction : block.instructions) {
            if (!is_inline_candidate(context, instruction) || !instruction.destination.has_value()) {
                continue;
            }

            std::string expression;
            switch (instruction.kind) {
            case ir::InstructionKind::Assign:
                if (!instruction.inputs.empty()) {
                    expression = render_value(context, instruction.inputs.front());
                }
                break;
            case ir::InstructionKind::Load:
                if (!instruction.inputs.empty()) {
                    if (const auto typed_access = render_typed_memory_access(context, instruction.inputs.front());
                        typed_access.has_value()) {
                        expression = *typed_access;
                    } else {
                        expression = "*" + render_value(context, instruction.inputs.front());
                    }
                }
                break;
            case ir::InstructionKind::Binary:
                if (instruction.binary_operator.has_value() && instruction.inputs.size() >= 2) {
                    expression = '(' + render_binary_expression(
                        render_value(context, instruction.inputs[0]),
                        render_value(context, instruction.inputs[1]),
                        *instruction.binary_operator
                    ) + ')';
                }
                break;
            case ir::InstructionKind::Compare:
            case ir::InstructionKind::Test:
                break;
            case ir::InstructionKind::Store:
            case ir::InstructionKind::Call:
            case ir::InstructionKind::Branch:
            case ir::InstructionKind::CondBranch:
            case ir::InstructionKind::Return:
            case ir::InstructionKind::Nop:
            case ir::InstructionKind::SetFlags:
            case ir::InstructionKind::Intrinsic:
                break;
            }

            if (!expression.empty()) {
                context.inline_expressions[instruction.destination->name] = expression;
            }
        }
    }
}

void emit_linear_region(
    RenderContext& context,
    std::ostringstream& stream,
    std::optional<std::uint64_t> current,
    const std::optional<std::uint64_t> stop,
    const std::optional<std::unordered_set<std::uint64_t>>& allowed,
    const int indent
);

void emit_block_body(
    RenderContext& context,
    std::ostringstream& stream,
    const ssa::BasicBlock& block,
    const int indent,
    const bool skip_condition_producers
) {
    for (std::size_t index = 0; index < block.instructions.size(); ++index) {
        const auto& instruction = block.instructions[index];
        if (is_branch_instruction(instruction)) {
            continue;
        }
        if (instruction.kind == ir::InstructionKind::Return) {
            continue;
        }
        if (skip_condition_producers && is_condition_producer(instruction)) {
            continue;
        }
        if (instruction.destination.has_value() && context.inline_expressions.contains(instruction.destination->name)) {
            continue;
        }
        const std::string statement = render_statement(context, instruction);
        if (!statement.empty()) {
            stream << indentation(indent) << statement << '\n';
        }
    }
}

void emit_if_region(
    RenderContext& context,
    std::ostringstream& stream,
    const ssa::BasicBlock& block,
    const int indent,
    const std::optional<std::unordered_set<std::uint64_t>>& allowed,
    std::optional<std::uint64_t>& out_next
) {
    RegionGuard guard(context);
    if (!allow_region_emission(context, stream, indent)) {
        out_next = std::nullopt;
        return;
    }

    const auto& branch = block.instructions.back();
    const auto true_target = branch.true_target;
    const auto false_target = branch.false_target;
    if (!true_target.has_value() || !false_target.has_value()) {
        out_next = std::nullopt;
        return;
    }

    const std::unordered_set<std::uint64_t> excluded{block.start_address, *true_target, *false_target};
    const auto join = common_successor(context, {*true_target, *false_target}, excluded);

    context.emitted_blocks.insert(block.start_address);
    emit_block_body(context, stream, block, indent, true);
    stream << indentation(indent) << "if (" << try_render_condition_from_producer(context, block, branch).value_or("condition")
           << ") {\n";
    emit_linear_region(context, stream, *true_target, join, allowed, indent + 1);
    stream << indentation(indent) << '}';

    if (join.has_value() ? *false_target != *join : !context.emitted_blocks.contains(*false_target)) {
        stream << " else {\n";
        emit_linear_region(context, stream, *false_target, join, allowed, indent + 1);
        stream << indentation(indent) << '}';
    }
    stream << '\n';
    out_next = join;
}

void emit_loop_region(
    RenderContext& context,
    std::ostringstream& stream,
    const cfg::LoopInfo& loop,
    const int indent,
    std::optional<std::uint64_t>& out_next
) {
    RegionGuard guard(context);
    if (!allow_region_emission(context, stream, indent)) {
        out_next = std::nullopt;
        return;
    }

    const auto* header = find_block(context, loop.header_address);
    if (header == nullptr || header->instructions.empty()) {
        out_next = std::nullopt;
        return;
    }

    std::unordered_set<std::uint64_t> loop_blocks(loop.body_blocks.begin(), loop.body_blocks.end());
    loop_blocks.insert(loop.header_address);

    std::optional<std::uint64_t> loop_body_entry;
    std::optional<std::uint64_t> loop_exit;
    for (const auto successor : header->successors) {
        if (loop_blocks.contains(successor) && successor != loop.header_address && !loop_body_entry.has_value()) {
            loop_body_entry = successor;
        }
        if (!loop_blocks.contains(successor) && !loop_exit.has_value()) {
            loop_exit = successor;
        }
    }

    if (!loop_body_entry.has_value()) {
        for (const auto block_address : loop.body_blocks) {
            if (block_address != loop.header_address) {
                loop_body_entry = block_address;
                break;
            }
        }
    }

    const auto& branch = header->instructions.back();
    context.emitted_blocks.insert(header->start_address);

    const bool use_infinite_loop = block_has_loop_side_effects(*header);
    if (use_infinite_loop) {
        stream << indentation(indent) << "while (true) {\n";
        emit_block_body(context, stream, *header, indent + 1, true);
        stream << indentation(indent + 1) << "if (!("
               << try_render_condition_from_producer(context, *header, branch).value_or("condition") << ")) {\n";
        stream << indentation(indent + 2) << "break;\n";
        stream << indentation(indent + 1) << "}\n";
    } else {
        stream << indentation(indent) << "while ("
               << try_render_condition_from_producer(context, *header, branch).value_or("condition") << ") {\n";
    }

    if (loop_body_entry.has_value()) {
        emit_linear_region(context, stream, *loop_body_entry, loop.header_address, loop_blocks, indent + 1);
    }
    for (const auto block_address : loop.body_blocks) {
        if (block_address == loop.header_address || context.emitted_blocks.contains(block_address)) {
            continue;
        }
        emit_linear_region(context, stream, block_address, loop.header_address, loop_blocks, indent + 1);
    }

    stream << indentation(indent) << "}\n";
    out_next = loop_exit;
}

void emit_switch_region(
    RenderContext& context,
    std::ostringstream& stream,
    const cfg::SwitchInfo& switch_info,
    const int indent,
    const std::optional<std::unordered_set<std::uint64_t>>& allowed,
    std::optional<std::uint64_t>& out_next
) {
    RegionGuard guard(context);
    if (!allow_region_emission(context, stream, indent)) {
        out_next = std::nullopt;
        return;
    }

    const auto* dispatch = find_block(context, switch_info.dispatch_block);
    if (dispatch == nullptr) {
        out_next = std::nullopt;
        return;
    }

    std::vector<std::uint64_t> case_starts;
    for (const auto& switch_case : switch_info.cases) {
        case_starts.push_back(switch_case.target);
    }
    if (switch_info.default_target.has_value()) {
        case_starts.push_back(*switch_info.default_target);
    }

    const std::unordered_set<std::uint64_t> excluded{
        switch_info.dispatch_block,
    };
    const auto join = common_successor(context, case_starts, excluded);

    context.emitted_blocks.insert(dispatch->start_address);
    emit_block_body(context, stream, *dispatch, indent, false);
    stream << indentation(indent) << "switch (" << switch_expression(context, switch_info.dispatch_block) << ") {\n";

    for (const auto& switch_case : switch_info.cases) {
        stream << indentation(indent) << "case " << switch_case.value << ":\n";
        emit_linear_region(context, stream, switch_case.target, join, allowed, indent + 1);
        stream << indentation(indent + 1) << "break;\n";
    }

    if (switch_info.default_target.has_value()) {
        stream << indentation(indent) << "default:\n";
        emit_linear_region(context, stream, *switch_info.default_target, join, allowed, indent + 1);
        stream << indentation(indent + 1) << "break;\n";
    }

    stream << indentation(indent) << "}\n";
    out_next = join;
}

void emit_linear_region(
    RenderContext& context,
    std::ostringstream& stream,
    std::optional<std::uint64_t> current,
    const std::optional<std::uint64_t> stop,
    const std::optional<std::unordered_set<std::uint64_t>>& allowed,
    const int indent
) {
    RegionGuard guard(context);
    if (!allow_region_emission(context, stream, indent)) {
        return;
    }

    while (current.has_value()) {
        if (stop.has_value() && *current == *stop) {
            return;
        }
        if (allowed.has_value() && !allowed->contains(*current)) {
            return;
        }
        if (context.emitted_blocks.contains(*current)) {
            return;
        }

        const auto* block = find_block(context, *current);
        if (block == nullptr || block->instructions.empty()) {
            return;
        }

        if (!allowed.has_value()) {
            if (const auto loop_it = context.loops_by_header.find(*current); loop_it != context.loops_by_header.end()) {
                std::optional<std::uint64_t> next;
                emit_loop_region(context, stream, *loop_it->second, indent, next);
                current = next;
                continue;
            }
            if (const auto switch_it = context.switches_by_dispatch.find(*current);
                switch_it != context.switches_by_dispatch.end()) {
                std::optional<std::uint64_t> next;
                emit_switch_region(context, stream, *switch_it->second, indent, allowed, next);
                current = next;
                continue;
            }
        }

        const auto& terminator = block->instructions.back();
        if (terminator.kind == ir::InstructionKind::CondBranch &&
            terminator.true_target.has_value() &&
            terminator.false_target.has_value() &&
            (!allowed.has_value() || (allowed->contains(*terminator.true_target) && allowed->contains(*terminator.false_target)))) {
            std::optional<std::uint64_t> next;
            emit_if_region(context, stream, *block, indent, allowed, next);
            current = next;
            continue;
        }

        context.emitted_blocks.insert(block->start_address);
        if (block->start_address != context.function.entry_address && block->predecessors.size() > 1) {
            std::ostringstream label_stream;
            label_stream << std::hex << std::uppercase << block->start_address;
            stream << indentation(indent) << "label_" << label_stream.str() << ":\n";
        }

        emit_block_body(context, stream, *block, indent, false);

        if (terminator.kind == ir::InstructionKind::Return) {
            stream << indentation(indent) << render_return_statement(context, *block) << '\n';
            return;
        }

        if (terminator.kind == ir::InstructionKind::Branch) {
            if (terminator.true_target.has_value()) {
                if (allowed.has_value() && !allowed->contains(*terminator.true_target)) {
                    return;
                }
                current = terminator.true_target;
                continue;
            }
            if (!terminator.inputs.empty()) {
                stream << indentation(indent) << "goto *" << render_value(context, terminator.inputs.front()) << ";\n";
            }
            return;
        }

        if (terminator.kind == ir::InstructionKind::CondBranch) {
            const auto condition = try_render_condition_from_producer(context, *block, terminator).value_or("condition");
            stream << indentation(indent) << "if (" << condition << ") {\n";
            if (terminator.true_target.has_value()) {
                emit_linear_region(context, stream, *terminator.true_target, stop, allowed, indent + 1);
            }
            stream << indentation(indent) << "} else {\n";
            if (terminator.false_target.has_value()) {
                emit_linear_region(context, stream, *terminator.false_target, stop, allowed, indent + 1);
            }
            stream << indentation(indent) << "}\n";
            return;
        }

        current = block->successors.empty() ? std::nullopt : std::optional<std::uint64_t>(block->successors.front());
    }
}

RenderContext build_context(
    const cfg::FunctionGraph& graph,
    const ssa::Function& function,
    const type::FunctionTypes& recovered_types,
    const ProgramMetadata* metadata
) {
    RenderContext context{
        .graph = graph,
        .function = function,
        .recovered_types = recovered_types,
        .metadata = metadata,
        .normalized = normalize_function(function),
        .naming = {},
        .blocks_by_address = {},
        .cfg_blocks_by_address = {},
        .loops_by_header = {},
        .switches_by_dispatch = {},
        .block_order = {},
        .emitted_blocks = {},
        .inline_expressions = {},
    };

    context.naming = build_naming_state(context.normalized.function, recovered_types);
    for (std::size_t index = 0; index < context.normalized.function.blocks.size(); ++index) {
        const auto& block = context.normalized.function.blocks[index];
        context.blocks_by_address.emplace(block.start_address, &block);
        context.block_order.emplace(block.start_address, index);
    }
    for (const auto& block : graph.blocks()) {
        context.cfg_blocks_by_address.emplace(block.start_address, &block);
    }
    for (const auto& loop : graph.loops()) {
        context.loops_by_header.emplace(loop.header_address, &loop);
    }
    for (const auto& switch_info : graph.switches()) {
        context.switches_by_dispatch.emplace(switch_info.dispatch_block, &switch_info);
    }

    build_inline_expressions(context);
    return context;
}

}  // namespace

DecompiledFunction Decompiler::decompile(
    const cfg::FunctionGraph& graph,
    const ssa::Function& function,
    const type::FunctionTypes& recovered_types,
    const ProgramMetadata* metadata
) {
    RenderContext context = build_context(graph, function, recovered_types, metadata);

    std::vector<std::pair<std::size_t, std::string>> arguments;
    std::string return_type = "void";
    std::vector<std::pair<std::string, std::string>> locals;

    for (const auto& [raw_name, recovered_type] : context.naming.declaration_types) {
        if (recovered_type == ir::ScalarType::Unknown) {
            continue;
        }
        const auto lowered = lowercase_copy(strip_ssa_suffix(raw_name));
        const std::string declaration_type =
            type::render_decl_type_for_prefix(recovered_types, raw_name, recovered_type);
        std::size_t argument_index = 0;
        if (is_argument_register(lowered, argument_index)) {
            arguments.emplace_back(argument_index, declaration_type);
            continue;
        }
        if (is_return_register(lowered)) {
            return_type = declaration_type;
            continue;
        }

        const auto name_it = context.naming.names.find(raw_name);
        if (name_it == context.naming.names.end()) {
            continue;
        }
        const std::string friendly_name = name_it->second;
        if (should_skip_local_declaration(context, raw_name, friendly_name)) {
            continue;
        }
        locals.emplace_back(friendly_name, declaration_type);
    }

    std::sort(arguments.begin(), arguments.end(), [](const auto& lhs, const auto& rhs) { return lhs.first < rhs.first; });
    arguments.erase(
        std::unique(arguments.begin(), arguments.end(), [](const auto& lhs, const auto& rhs) { return lhs.first == rhs.first; }),
        arguments.end()
    );
    std::sort(locals.begin(), locals.end(), [](const auto& lhs, const auto& rhs) { return lhs.first < rhs.first; });
    locals.erase(
        std::unique(locals.begin(), locals.end(), [](const auto& lhs, const auto& rhs) { return lhs.first == rhs.first; }),
        locals.end()
    );

    std::ostringstream stream;
    const std::string recovered_type_definitions = render_recovered_type_definitions(recovered_types);
    if (!recovered_type_definitions.empty()) {
        stream << recovered_type_definitions;
    }
    stream << return_type << ' ' << sanitize_identifier(function.name) << '(';
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        if (index > 0) {
            stream << ", ";
        }
        stream << arguments[index].second << " arg_" << arguments[index].first;
    }
    stream << ") {\n";

    for (const auto& [name, type] : locals) {
        stream << indentation(1) << type << ' ' << sanitize_identifier(name) << ";\n";
    }
    if (!locals.empty()) {
        stream << '\n';
    }

    emit_linear_region(context, stream, function.entry_address, std::nullopt, std::nullopt, 1);
    stream << "}\n";

    return DecompiledFunction{
        .name = function.name,
        .pseudocode = stream.str(),
    };
}

}  // namespace zara::decompiler
