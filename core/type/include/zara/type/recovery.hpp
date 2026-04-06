#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "zara/ir/lifter.hpp"
#include "zara/ssa/builder.hpp"

namespace zara::type {

struct RecoveredVariable {
    std::string name;
    ir::ScalarType type = ir::ScalarType::Unknown;
};

struct RecoveredStructField {
    std::string name;
    std::int64_t offset = 0;
    std::uint64_t size = 0;
    ir::ScalarType type = ir::ScalarType::Unknown;
};

struct RecoveredStruct {
    std::string owner_name;
    std::string type_name;
    std::vector<RecoveredStructField> fields;
};

struct RecoveredArray {
    std::string owner_name;
    std::string type_name;
    ir::ScalarType element_type = ir::ScalarType::Unknown;
    std::uint64_t element_size = 0;
    std::size_t observed_elements = 0;
    bool indexed_access = false;
};

struct FunctionTypes {
    std::vector<RecoveredVariable> variables;
    std::vector<RecoveredStruct> structs;
    std::vector<RecoveredArray> arrays;
};

class Recoverer {
public:
    [[nodiscard]] static FunctionTypes recover(const ssa::Function& function);
};

[[nodiscard]] const RecoveredStruct* find_struct(const FunctionTypes& types, std::string_view owner_name) noexcept;
[[nodiscard]] const RecoveredArray* find_array(const FunctionTypes& types, std::string_view owner_name) noexcept;
[[nodiscard]] const RecoveredStruct* find_struct_prefix(const FunctionTypes& types, std::string_view owner_name) noexcept;
[[nodiscard]] const RecoveredArray* find_array_prefix(const FunctionTypes& types, std::string_view owner_name) noexcept;
[[nodiscard]] std::string render_decl_type(
    const FunctionTypes& types,
    std::string_view owner_name,
    ir::ScalarType fallback
);
[[nodiscard]] std::string render_decl_type_for_prefix(
    const FunctionTypes& types,
    std::string_view owner_name,
    ir::ScalarType fallback
);

}  // namespace zara::type
