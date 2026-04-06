#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "zara/cfg/function_graph.hpp"
#include "zara/loader/binary_image.hpp"

namespace zara::xrefs {

enum class CrossReferenceKind {
    Call,
    Jump,
    Import,
    Data,
    String,
};

struct ExtractedString {
    std::uint64_t start_address = 0;
    std::uint64_t end_address = 0;
    std::string value;
};

struct CrossReference {
    CrossReferenceKind kind = CrossReferenceKind::Data;
    std::uint64_t from_address = 0;
    std::uint64_t to_address = 0;
    std::string label;
};

class Analyzer {
public:
    [[nodiscard]] static std::vector<ExtractedString> extract_strings(
        const loader::BinaryImage& image,
        std::size_t minimum_length = 4
    );

    [[nodiscard]] static std::vector<CrossReference> build_cross_references(
        const cfg::FunctionGraph& graph,
        const std::vector<ExtractedString>& strings,
        std::span<const loader::ImportedSymbol> imports = {}
    );
};

[[nodiscard]] std::string_view to_string(CrossReferenceKind kind) noexcept;

}  // namespace zara::xrefs
