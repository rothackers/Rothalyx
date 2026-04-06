#include "zara/type/recovery.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <set>
#include <unordered_map>
#include <utility>

namespace zara::type {

namespace {

struct MemoryAccessObservation {
    std::string owner_name;
    std::int64_t displacement = 0;
    std::uint64_t size = 0;
    std::uint8_t scale = 1;
    ir::ScalarType type = ir::ScalarType::Unknown;
    bool indexed = false;
};

int type_rank(const ir::ScalarType type) {
    switch (type) {
    case ir::ScalarType::Pointer:
        return 5;
    case ir::ScalarType::I64:
        return 4;
    case ir::ScalarType::I32:
        return 3;
    case ir::ScalarType::I16:
        return 2;
    case ir::ScalarType::I8:
        return 1;
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
    if (incoming == ir::ScalarType::Unknown) {
        return current;
    }
    if (current == incoming) {
        return current;
    }

    return type_rank(incoming) > type_rank(current) ? incoming : current;
}

std::uint64_t type_size(const ir::ScalarType type) {
    switch (type) {
    case ir::ScalarType::Bool:
    case ir::ScalarType::I8:
        return 1;
    case ir::ScalarType::I16:
        return 2;
    case ir::ScalarType::I32:
        return 4;
    case ir::ScalarType::Pointer:
    case ir::ScalarType::I64:
    case ir::ScalarType::Unknown:
    default:
        return 8;
    }
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

std::string base_name(std::string value) {
    return sanitize_identifier(lowercase_copy(strip_ssa_suffix(std::move(value))));
}

bool is_stack_like_base(const std::string_view raw_name) {
    const std::string lowered = lowercase_copy(strip_ssa_suffix(std::string(raw_name)));
    return lowered == "rbp" || lowered == "ebp" || lowered == "rsp" || lowered == "esp" || lowered == "sp" ||
           lowered == "fp" || lowered == "x29";
}

std::string c_decl_type(const ir::ScalarType type) {
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

void merge_name_type(
    std::unordered_map<std::string, ir::ScalarType>& types,
    const std::string& name,
    const ir::ScalarType incoming_type
) {
    if (name.empty() || incoming_type == ir::ScalarType::Unknown) {
        return;
    }

    types[name] = merge_type(types[name], incoming_type);
}

void observe_value(std::unordered_map<std::string, ir::ScalarType>& types, const ir::Value& value) {
    if ((value.kind == ir::ValueKind::Register || value.kind == ir::ValueKind::Temporary) && !value.name.empty()) {
        merge_name_type(types, value.name, value.type);
        return;
    }

    if (value.kind == ir::ValueKind::MemoryAddress) {
        merge_name_type(types, value.memory.base, ir::ScalarType::Pointer);
        merge_name_type(types, value.memory.index, ir::ScalarType::Pointer);
    }
}

ir::ScalarType inferred_value_type(
    const std::unordered_map<std::string, ir::ScalarType>& types,
    const ir::Value& value
) {
    if (value.type != ir::ScalarType::Unknown) {
        return value.type;
    }

    if ((value.kind == ir::ValueKind::Register || value.kind == ir::ValueKind::Temporary) && !value.name.empty()) {
        const auto it = types.find(value.name);
        if (it != types.end()) {
            return it->second;
        }
    }

    if (value.kind == ir::ValueKind::MemoryAddress) {
        return ir::ScalarType::Pointer;
    }

    return ir::ScalarType::Unknown;
}

void observe_memory_access(
    std::unordered_map<std::string, std::vector<MemoryAccessObservation>>& accesses_by_owner,
    std::unordered_map<std::string, ir::ScalarType>& variable_types,
    const ir::Value& value,
    const ir::ScalarType associated_type
) {
    if (value.kind != ir::ValueKind::MemoryAddress) {
        return;
    }

    const std::string owner_name = !value.memory.base.empty() ? value.memory.base : value.memory.index;
    if (owner_name.empty()) {
        return;
    }

    const ir::ScalarType resolved_type = associated_type == ir::ScalarType::Unknown ? value.type : associated_type;
    accesses_by_owner[owner_name].push_back(
        MemoryAccessObservation{
            .owner_name = owner_name,
            .displacement = value.memory.displacement,
            .size = type_size(resolved_type),
            .scale = static_cast<std::uint8_t>(value.memory.scale == 0 ? 1 : value.memory.scale),
            .type = resolved_type,
            .indexed = !value.memory.index.empty(),
        }
    );
    merge_name_type(variable_types, owner_name, ir::ScalarType::Pointer);
}

std::size_t count_observed_elements(
    const std::vector<MemoryAccessObservation>& observations,
    const std::uint64_t element_size
) {
    if (element_size == 0) {
        return 0;
    }

    std::set<std::int64_t> element_offsets;
    for (const auto& observation : observations) {
        element_offsets.insert(observation.displacement / static_cast<std::int64_t>(element_size));
    }
    return element_offsets.size();
}

std::optional<RecoveredArray> recover_array(
    const std::string& owner_name,
    const std::vector<MemoryAccessObservation>& observations
) {
    std::vector<MemoryAccessObservation> indexed;
    std::copy_if(
        observations.begin(),
        observations.end(),
        std::back_inserter(indexed),
        [](const MemoryAccessObservation& observation) { return observation.indexed; }
    );

    if (!indexed.empty()) {
        ir::ScalarType element_type = ir::ScalarType::Unknown;
        std::uint64_t element_size = 0;
        for (const auto& observation : indexed) {
            element_type = merge_type(element_type, observation.type);
            element_size = std::max<std::uint64_t>(
                element_size,
                std::max<std::uint64_t>(observation.scale, observation.size)
            );
        }
        if (element_size == 0) {
            element_size = type_size(element_type);
        }
        return RecoveredArray{
            .owner_name = owner_name,
            .type_name = "array_" + base_name(owner_name),
            .element_type = element_type,
            .element_size = element_size,
            .observed_elements = std::max<std::size_t>(1, count_observed_elements(indexed, element_size)),
            .indexed_access = true,
        };
    }

    if (observations.size() < 3) {
        return std::nullopt;
    }

    ir::ScalarType element_type = observations.front().type;
    std::uint64_t element_size = observations.front().size;
    std::set<std::int64_t> offsets;
    for (const auto& observation : observations) {
        element_type = merge_type(element_type, observation.type);
        element_size = std::min<std::uint64_t>(element_size, observation.size);
        offsets.insert(observation.displacement);
    }

    if (offsets.size() < 3 || element_size == 0) {
        return std::nullopt;
    }

    auto offset_it = offsets.begin();
    auto previous = *offset_it++;
    while (offset_it != offsets.end()) {
        if (*offset_it - previous != static_cast<std::int64_t>(element_size)) {
            return std::nullopt;
        }
        previous = *offset_it++;
    }

    return RecoveredArray{
        .owner_name = owner_name,
        .type_name = "array_" + base_name(owner_name),
        .element_type = element_type,
        .element_size = element_size,
        .observed_elements = offsets.size(),
        .indexed_access = false,
    };
}

std::optional<RecoveredStruct> recover_struct(
    const std::string& owner_name,
    const std::vector<MemoryAccessObservation>& observations
) {
    if (is_stack_like_base(owner_name)) {
        return std::nullopt;
    }

    std::unordered_map<std::int64_t, RecoveredStructField> fields_by_offset;
    for (const auto& observation : observations) {
        if (observation.indexed) {
            continue;
        }

        auto& field = fields_by_offset[observation.displacement];
        field.offset = observation.displacement;
        field.size = std::max(field.size, observation.size);
        field.type = merge_type(field.type, observation.type);
    }

    if (fields_by_offset.size() < 2) {
        return std::nullopt;
    }

    RecoveredStruct recovered{
        .owner_name = owner_name,
        .type_name = "struct_" + base_name(owner_name),
        .fields = {},
    };
    recovered.fields.reserve(fields_by_offset.size());
    for (auto& [offset, field] : fields_by_offset) {
        if (field.type == ir::ScalarType::Unknown) {
            field.type = ir::ScalarType::I32;
        }
        if (field.size == 0) {
            field.size = type_size(field.type);
        }
        switch (field.type) {
        case ir::ScalarType::Bool:
            field.name = "flag_" + std::to_string(std::llabs(offset));
            break;
        case ir::ScalarType::Pointer:
            field.name = "ptr_" + std::to_string(std::llabs(offset));
            break;
        case ir::ScalarType::I8:
            field.name = "byte_" + std::to_string(std::llabs(offset));
            break;
        default:
            field.name = "field_" + std::to_string(std::llabs(offset));
            break;
        }
        recovered.fields.push_back(std::move(field));
    }

    std::sort(
        recovered.fields.begin(),
        recovered.fields.end(),
        [](const RecoveredStructField& lhs, const RecoveredStructField& rhs) { return lhs.offset < rhs.offset; }
    );
    return recovered;
}

}  // namespace

FunctionTypes Recoverer::recover(const ssa::Function& function) {
    std::unordered_map<std::string, ir::ScalarType> variable_types;

    for (const auto& block : function.blocks) {
        for (const auto& phi : block.phi_nodes) {
            merge_name_type(variable_types, phi.result_name, ir::ScalarType::Unknown);
            for (const auto& incoming : phi.incoming) {
                merge_name_type(variable_types, incoming.second, ir::ScalarType::Unknown);
            }
        }

        for (const auto& instruction : block.instructions) {
            if (instruction.destination.has_value()) {
                observe_value(variable_types, *instruction.destination);
            }
            for (const auto& input : instruction.inputs) {
                observe_value(variable_types, input);
            }
        }
    }

    bool changed = true;
    while (changed) {
        changed = false;

        auto merge_and_track = [&](const std::string& name, const ir::ScalarType type) {
            const ir::ScalarType before = variable_types[name];
            const ir::ScalarType after = merge_type(before, type);
            if (after != before) {
                variable_types[name] = after;
                changed = true;
            }
        };

        for (const auto& block : function.blocks) {
            for (const auto& phi : block.phi_nodes) {
                ir::ScalarType phi_type = variable_types[phi.result_name];
                for (const auto& incoming : phi.incoming) {
                    phi_type = merge_type(phi_type, variable_types[incoming.second]);
                }
                merge_and_track(phi.result_name, phi_type);
                for (const auto& incoming : phi.incoming) {
                    merge_and_track(incoming.second, phi_type);
                }
            }

            for (const auto& instruction : block.instructions) {
                switch (instruction.kind) {
                case ir::InstructionKind::Assign:
                    if (instruction.destination.has_value() && !instruction.inputs.empty()) {
                        const auto inferred = merge_type(
                            inferred_value_type(variable_types, *instruction.destination),
                            inferred_value_type(variable_types, instruction.inputs.front())
                        );
                        if (!instruction.destination->name.empty()) {
                            merge_and_track(instruction.destination->name, inferred);
                        }
                        if (!instruction.inputs.front().name.empty()) {
                            merge_and_track(instruction.inputs.front().name, inferred);
                        }
                    }
                    break;
                case ir::InstructionKind::Load:
                    if (instruction.destination.has_value()) {
                        const auto inferred = inferred_value_type(variable_types, *instruction.destination);
                        merge_and_track(instruction.destination->name, inferred);
                    }
                    break;
                case ir::InstructionKind::Binary:
                    if (instruction.destination.has_value() && instruction.inputs.size() >= 2) {
                        const auto inferred = merge_type(
                            inferred_value_type(variable_types, instruction.inputs[0]),
                            inferred_value_type(variable_types, instruction.inputs[1])
                        );
                        merge_and_track(instruction.destination->name, inferred);
                        for (const auto& input : instruction.inputs) {
                            if (!input.name.empty()) {
                                merge_and_track(input.name, inferred);
                            }
                        }
                    }
                    break;
                case ir::InstructionKind::Compare:
                case ir::InstructionKind::Test:
                    if (instruction.inputs.size() >= 2) {
                        const auto inferred = merge_type(
                            inferred_value_type(variable_types, instruction.inputs[0]),
                            inferred_value_type(variable_types, instruction.inputs[1])
                        );
                        for (const auto& input : instruction.inputs) {
                            if (!input.name.empty()) {
                                merge_and_track(input.name, inferred);
                            }
                        }
                        if (instruction.destination.has_value() && !instruction.destination->name.empty()) {
                            merge_and_track(instruction.destination->name, ir::ScalarType::Bool);
                        }
                    }
                    break;
                case ir::InstructionKind::CondBranch:
                    if (!instruction.inputs.empty() && !instruction.inputs.front().name.empty()) {
                        merge_and_track(instruction.inputs.front().name, ir::ScalarType::Bool);
                    }
                    break;
                case ir::InstructionKind::Store:
                case ir::InstructionKind::SetFlags:
                case ir::InstructionKind::Call:
                case ir::InstructionKind::Branch:
                case ir::InstructionKind::Return:
                case ir::InstructionKind::Nop:
                case ir::InstructionKind::Intrinsic:
                default:
                    break;
                }
            }
        }
    }

    std::unordered_map<std::string, std::vector<MemoryAccessObservation>> accesses_by_owner;
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) {
            if (instruction.kind == ir::InstructionKind::Load && !instruction.inputs.empty()) {
                const ir::ScalarType payload_type =
                    instruction.destination.has_value()
                        ? inferred_value_type(variable_types, *instruction.destination)
                        : ir::ScalarType::Unknown;
                observe_memory_access(accesses_by_owner, variable_types, instruction.inputs.front(), payload_type);
                continue;
            }

            if (instruction.kind == ir::InstructionKind::Store && instruction.inputs.size() >= 2) {
                observe_memory_access(
                    accesses_by_owner,
                    variable_types,
                    instruction.inputs.front(),
                    inferred_value_type(variable_types, instruction.inputs[1])
                );
                continue;
            }

            for (const auto& input : instruction.inputs) {
                if (input.kind != ir::ValueKind::MemoryAddress) {
                    continue;
                }
                observe_memory_access(accesses_by_owner, variable_types, input, ir::ScalarType::Unknown);
            }
        }
    }

    FunctionTypes result;
    result.variables.reserve(variable_types.size());
    for (const auto& [owner_name, observations] : accesses_by_owner) {
        if (const auto recovered_array = recover_array(owner_name, observations); recovered_array.has_value()) {
            result.arrays.push_back(*recovered_array);
        }
        if (const auto recovered_struct = recover_struct(owner_name, observations); recovered_struct.has_value()) {
            result.structs.push_back(*recovered_struct);
        }
    }

    for (const auto& [name, recovered_type] : variable_types) {
        if (name.empty()) {
            continue;
        }

        result.variables.push_back(
            RecoveredVariable{
                .name = name,
                .type = recovered_type,
            }
        );
    }

    std::sort(
        result.variables.begin(),
        result.variables.end(),
        [](const RecoveredVariable& lhs, const RecoveredVariable& rhs) { return lhs.name < rhs.name; }
    );
    std::sort(
        result.structs.begin(),
        result.structs.end(),
        [](const RecoveredStruct& lhs, const RecoveredStruct& rhs) { return lhs.owner_name < rhs.owner_name; }
    );
    std::sort(
        result.arrays.begin(),
        result.arrays.end(),
        [](const RecoveredArray& lhs, const RecoveredArray& rhs) { return lhs.owner_name < rhs.owner_name; }
    );
    return result;
}

const RecoveredStruct* find_struct(const FunctionTypes& types, const std::string_view owner_name) noexcept {
    const auto it = std::find_if(
        types.structs.begin(),
        types.structs.end(),
        [&](const RecoveredStruct& recovered) { return recovered.owner_name == owner_name; }
    );
    return it == types.structs.end() ? nullptr : &(*it);
}

const RecoveredArray* find_array(const FunctionTypes& types, const std::string_view owner_name) noexcept {
    const auto it = std::find_if(
        types.arrays.begin(),
        types.arrays.end(),
        [&](const RecoveredArray& recovered) { return recovered.owner_name == owner_name; }
    );
    return it == types.arrays.end() ? nullptr : &(*it);
}

const RecoveredStruct* find_struct_prefix(const FunctionTypes& types, const std::string_view owner_name) noexcept {
    if (const auto* exact = find_struct(types, owner_name); exact != nullptr) {
        return exact;
    }

    const auto it = std::find_if(
        types.structs.begin(),
        types.structs.end(),
        [&](const RecoveredStruct& recovered) {
            return recovered.owner_name.starts_with(owner_name) &&
                   (recovered.owner_name.size() == owner_name.size() || recovered.owner_name[owner_name.size()] == '.');
        }
    );
    return it == types.structs.end() ? nullptr : &(*it);
}

const RecoveredArray* find_array_prefix(const FunctionTypes& types, const std::string_view owner_name) noexcept {
    if (const auto* exact = find_array(types, owner_name); exact != nullptr) {
        return exact;
    }

    const auto it = std::find_if(
        types.arrays.begin(),
        types.arrays.end(),
        [&](const RecoveredArray& recovered) {
            return recovered.owner_name.starts_with(owner_name) &&
                   (recovered.owner_name.size() == owner_name.size() || recovered.owner_name[owner_name.size()] == '.');
        }
    );
    return it == types.arrays.end() ? nullptr : &(*it);
}

std::string render_decl_type(
    const FunctionTypes& types,
    const std::string_view owner_name,
    const ir::ScalarType fallback
) {
    if (const auto* recovered_struct = find_struct(types, owner_name); recovered_struct != nullptr) {
        return recovered_struct->type_name + "*";
    }
    if (const auto* recovered_array = find_array(types, owner_name); recovered_array != nullptr) {
        return c_decl_type(recovered_array->element_type) + "*";
    }
    return c_decl_type(fallback);
}

std::string render_decl_type_for_prefix(
    const FunctionTypes& types,
    const std::string_view owner_name,
    const ir::ScalarType fallback
) {
    if (const auto* recovered_struct = find_struct_prefix(types, owner_name); recovered_struct != nullptr) {
        return recovered_struct->type_name + "*";
    }
    if (const auto* recovered_array = find_array_prefix(types, owner_name); recovered_array != nullptr) {
        return c_decl_type(recovered_array->element_type) + "*";
    }
    return c_decl_type(fallback);
}

}  // namespace zara::type
