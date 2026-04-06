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
    return std::vector<std::byte>(reinterpret_cast<const std::byte*>(values.data()), reinterpret_cast<const std::byte*>(values.data() + values.size()));
}

bool has_constant_prefix(
    const std::vector<zara::analysis::ConstantValue>& constants,
    const std::string_view prefix,
    const std::int64_t expected
) {
    return std::any_of(
        constants.begin(),
        constants.end(),
        [&](const zara::analysis::ConstantValue& constant) {
            return std::string_view(constant.name).rfind(prefix, 0) == 0 && constant.value == expected;
        }
    );
}

bool has_type_prefix(
    const zara::type::FunctionTypes& types,
    const std::string_view prefix,
    const zara::ir::ScalarType expected
) {
    return std::any_of(
        types.variables.begin(),
        types.variables.end(),
        [&](const zara::type::RecoveredVariable& variable) {
            return std::string_view(variable.name).rfind(prefix, 0) == 0 && variable.type == expected;
        }
    );
}

bool contains_string(const std::vector<std::string>& values, const std::string_view needle) {
    return std::any_of(
        values.begin(),
        values.end(),
        [&](const std::string& value) { return value == needle; }
    );
}

bool has_argument_location(
    const std::vector<zara::analysis::ArgumentInfo>& arguments,
    const std::string_view location
) {
    return std::any_of(
        arguments.begin(),
        arguments.end(),
        [&](const zara::analysis::ArgumentInfo& argument) { return argument.location == location; }
    );
}

}  // namespace

int main() {
    constexpr std::uint64_t kTextBase = 0x1000;
    constexpr std::uint64_t kImportBase = 0x2000;

    const std::vector<std::uint8_t> code_bytes{
        0x55,
        0x48, 0x89, 0xE5,
        0x48, 0x83, 0xEC, 0x20,
        0x48, 0x89, 0x7D, 0xF8,
        0x48, 0x8D, 0x75, 0xF8,
        0x8B, 0x07,
        0x31, 0xC0,
        0x85, 0xC0,
        0x75, 0x12,
        0xFF, 0x14, 0x25, 0x00, 0x20, 0x00, 0x00,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC9,
        0xC3,
        0x90, 0x90, 0x90, 0x90,
        0xB8, 0x02, 0x00, 0x00, 0x00,
        0xC9,
        0xC3,
    };

    zara::memory::AddressSpace address_space;
    const auto image = zara::loader::BinaryImage::from_components(
        "analysis-engine.bin",
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
            zara::loader::Section{
                .name = ".idata",
                .virtual_address = kImportBase,
                .bytes = std::vector<std::byte>(8, std::byte{0}),
                .readable = true,
                .writable = true,
                .executable = false,
            },
        },
        {
            zara::loader::ImportedSymbol{
                .library = "libc.so.6",
                .name = "puts",
                .address = kImportBase,
            },
        }
    );

    if (!address_space.map_image(image)) {
        std::cerr << "failed to map synthetic analysis image\n";
        return 1;
    }

    const auto analysis = zara::analysis::Analyzer::analyze(image, address_space);
    const auto function_it = std::find_if(
        analysis.functions.begin(),
        analysis.functions.end(),
        [](const zara::analysis::DiscoveredFunction& function) { return function.entry_address == 0x1000; }
    );
    if (function_it == analysis.functions.end()) {
        std::cerr << "failed to recover analysis target function\n";
        return 2;
    }

    const auto& summary = function_it->summary;
    if (!has_constant_prefix(summary.constants, "eax.", 0) || !has_constant_prefix(summary.constants, "eax.", 1)) {
        std::cerr << "constant propagation summary is incomplete\n";
        return 3;
    }

    if (summary.unreachable_blocks_removed == 0) {
        std::cerr << "expected unreachable block removal after branch folding\n";
        return 4;
    }

    if (summary.stack_frame_size != 40 || !summary.uses_frame_pointer || summary.stack_pointer_states.empty()) {
        std::cerr << "stack frame reconstruction failed\n";
        return 5;
    }

    const auto local_it = std::find_if(
        summary.locals.begin(),
        summary.locals.end(),
        [](const zara::analysis::LocalVariable& local) { return local.stack_offset == -8; }
    );
    if (local_it == summary.locals.end()) {
        std::cerr << "local variable recovery missed [rbp-8]\n";
        return 6;
    }

    if (!has_type_prefix(function_it->recovered_types, "rdi.", zara::ir::ScalarType::Pointer) ||
        !has_type_prefix(function_it->recovered_types, "flags_", zara::ir::ScalarType::Bool)) {
        std::cerr << "type inference / typed IR propagation is incomplete\n";
        return 7;
    }

    if (!contains_string(summary.pointer_variables, "rdi") || !contains_string(summary.pointer_variables, "rsi")) {
        std::cerr << "pointer tracking failed\n";
        return 8;
    }

    if (summary.calling_convention != zara::analysis::CallingConvention::SysVAMD64 ||
        summary.arguments.empty() ||
        !has_argument_location(summary.arguments, "rdi")) {
        std::cerr << "calling convention / argument inference failed\n";
        return 9;
    }

    if (!summary.return_value.has_value() ||
        summary.return_value->location != "rax" ||
        summary.return_value->type != zara::ir::ScalarType::I32) {
        std::cerr << "return inference failed\n";
        return 10;
    }

    const auto indirect_it = std::find_if(
        summary.indirect_resolutions.begin(),
        summary.indirect_resolutions.end(),
        [](const zara::analysis::IndirectResolution& resolution) {
            return resolution.label == "libc.so.6!puts";
        }
    );
    if (indirect_it == summary.indirect_resolutions.end()) {
        std::cerr << "indirect import resolution failed\n";
        return 11;
    }

    return 0;
}
