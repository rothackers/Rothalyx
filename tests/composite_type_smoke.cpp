#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

#include "zara/analysis/program_analysis.hpp"
#include "zara/memory/address_space.hpp"

namespace {

std::vector<std::byte> to_bytes(const std::vector<std::uint8_t>& values) {
    return std::vector<std::byte>(
        reinterpret_cast<const std::byte*>(values.data()),
        reinterpret_cast<const std::byte*>(values.data() + values.size())
    );
}

const zara::type::RecoveredStruct* find_struct_prefix_local(
    const zara::type::FunctionTypes& types,
    const std::string_view prefix
) {
    const auto it = std::find_if(
        types.structs.begin(),
        types.structs.end(),
        [&](const zara::type::RecoveredStruct& recovered) {
            return std::string_view(recovered.owner_name).rfind(prefix, 0) == 0;
        }
    );
    return it == types.structs.end() ? nullptr : &(*it);
}

const zara::type::RecoveredArray* find_array_prefix_local(
    const zara::type::FunctionTypes& types,
    const std::string_view prefix
) {
    const auto it = std::find_if(
        types.arrays.begin(),
        types.arrays.end(),
        [&](const zara::type::RecoveredArray& recovered) {
            return std::string_view(recovered.owner_name).rfind(prefix, 0) == 0;
        }
    );
    return it == types.arrays.end() ? nullptr : &(*it);
}

bool has_field_offset(const zara::type::RecoveredStruct& recovered, const std::int64_t offset) {
    return std::any_of(
        recovered.fields.begin(),
        recovered.fields.end(),
        [&](const zara::type::RecoveredStructField& field) { return field.offset == offset; }
    );
}

}  // namespace

int main() {
    constexpr std::uint64_t kTextBase = 0x1000;

    const std::vector<std::uint8_t> code_bytes{
        0x55,
        0x48, 0x89, 0xE5,
        0x8B, 0x47, 0x04,
        0x8B, 0x4F, 0x08,
        0x8B, 0x14, 0x86,
        0x89, 0x57, 0x0C,
        0x89, 0xD0,
        0xC9,
        0xC3,
    };

    zara::memory::AddressSpace address_space;
    const auto image = zara::loader::BinaryImage::from_components(
        "composite-type.bin",
        zara::loader::BinaryFormat::Raw,
        zara::loader::Architecture::X86_64,
        kTextBase,
        kTextBase,
        {
            zara::loader::Section{
                .name = ".text",
                .virtual_address = kTextBase,
                .bytes = to_bytes(code_bytes),
                .readable = true,
                .writable = false,
                .executable = true,
            },
        }
    );

    if (!address_space.map_image(image)) {
        std::cerr << "failed to map composite test image\n";
        return 1;
    }

    const auto analysis = zara::analysis::Analyzer::analyze(image, address_space);
    if (analysis.functions.empty()) {
        std::cerr << "expected at least one function\n";
        return 2;
    }

    const auto& function = analysis.functions.front();
    const auto* recovered_struct = find_struct_prefix_local(function.recovered_types, "rdi.");
    if (recovered_struct == nullptr) {
        std::cerr << "expected recovered struct for rdi-based accesses\n";
        return 3;
    }
    if (!has_field_offset(*recovered_struct, 4) ||
        !has_field_offset(*recovered_struct, 8) ||
        !has_field_offset(*recovered_struct, 12)) {
        std::cerr << "recovered struct fields are incomplete\n";
        return 4;
    }

    const auto* recovered_array = find_array_prefix_local(function.recovered_types, "rsi.");
    if (recovered_array == nullptr) {
        std::cerr << "expected recovered array for rsi-based indexed access\n";
        return 5;
    }
    if (recovered_array->element_size != 4 || recovered_array->element_type != zara::ir::ScalarType::I32 ||
        !recovered_array->indexed_access) {
        std::cerr << "recovered array metadata is incomplete\n";
        return 6;
    }

    const std::string decl_type = zara::type::render_decl_type(
        function.recovered_types,
        recovered_struct->owner_name,
        zara::ir::ScalarType::Pointer
    );
    if (decl_type.find("struct_") != 0 || decl_type.back() != '*') {
        std::cerr << "expected structured declaration type for recovered struct owner\n";
        return 7;
    }

    if (function.decompiled.pseudocode.find("->field_12") == std::string::npos) {
        std::cerr << "expected typed struct store access in decompiler output\n";
        return 8;
    }
    if (function.decompiled.pseudocode.find("arg_1[") == std::string::npos) {
        std::cerr << "expected typed array indexing in decompiler output\n";
        return 9;
    }

    return 0;
}
