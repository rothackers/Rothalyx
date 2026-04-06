#include "zara/xrefs/analysis.hpp"

#include <algorithm>
#include <cctype>

namespace zara::xrefs {

namespace {

bool is_ascii_string_byte(const std::byte value) {
    const auto numeric = std::to_integer<unsigned char>(value);
    return numeric >= 0x20 && numeric <= 0x7E;
}

const ExtractedString* find_string_for_address(
    const std::vector<ExtractedString>& strings,
    const std::uint64_t address
) {
    for (const auto& extracted : strings) {
        if (address >= extracted.start_address && address < extracted.end_address) {
            return &extracted;
        }
    }

    return nullptr;
}

const loader::ImportedSymbol* find_import_for_address(
    const std::span<const loader::ImportedSymbol> imports,
    const std::uint64_t address
) {
    for (const auto& imported : imports) {
        if (imported.address == address) {
            return &imported;
        }
    }

    return nullptr;
}

void deduplicate_xrefs(std::vector<CrossReference>& xrefs) {
    std::sort(
        xrefs.begin(),
        xrefs.end(),
        [](const CrossReference& lhs, const CrossReference& rhs) {
            if (lhs.from_address != rhs.from_address) {
                return lhs.from_address < rhs.from_address;
            }
            if (lhs.to_address != rhs.to_address) {
                return lhs.to_address < rhs.to_address;
            }
            return static_cast<int>(lhs.kind) < static_cast<int>(rhs.kind);
        }
    );

    xrefs.erase(
        std::unique(
            xrefs.begin(),
            xrefs.end(),
            [](const CrossReference& lhs, const CrossReference& rhs) {
                return lhs.kind == rhs.kind &&
                       lhs.from_address == rhs.from_address &&
                       lhs.to_address == rhs.to_address &&
                       lhs.label == rhs.label;
            }
        ),
        xrefs.end()
    );
}

}  // namespace

std::vector<ExtractedString> Analyzer::extract_strings(
    const loader::BinaryImage& image,
    const std::size_t minimum_length
) {
    std::vector<ExtractedString> strings;

    for (const auto& section : image.sections()) {
        if (!section.readable || section.executable || section.bytes.empty()) {
            continue;
        }

        std::size_t index = 0;
        while (index < section.bytes.size()) {
            while (index < section.bytes.size() && !is_ascii_string_byte(section.bytes[index])) {
                ++index;
            }

            const std::size_t start = index;
            while (index < section.bytes.size() && is_ascii_string_byte(section.bytes[index])) {
                ++index;
            }

            const std::size_t length = index - start;
            if (length >= minimum_length) {
                std::string value;
                value.reserve(length);
                for (std::size_t string_index = start; string_index < index; ++string_index) {
                    value.push_back(static_cast<char>(std::to_integer<unsigned char>(section.bytes[string_index])));
                }

                strings.push_back(
                    ExtractedString{
                        .start_address = section.virtual_address + start,
                        .end_address = section.virtual_address + index,
                        .value = std::move(value),
                    }
                );
            }

            if (index < section.bytes.size() && section.bytes[index] == std::byte{0}) {
                ++index;
            }
        }
    }

    return strings;
}

std::vector<CrossReference> Analyzer::build_cross_references(
    const cfg::FunctionGraph& graph,
    const std::vector<ExtractedString>& strings,
    const std::span<const loader::ImportedSymbol> imports
) {
    std::vector<CrossReference> xrefs;

    for (const auto& block : graph.blocks()) {
        for (const auto& instruction : block.instructions) {
            if (instruction.control_flow_target.has_value()) {
                switch (instruction.kind) {
                case disasm::InstructionKind::Call:
                    xrefs.push_back(
                        CrossReference{
                            .kind = CrossReferenceKind::Call,
                            .from_address = instruction.address,
                            .to_address = *instruction.control_flow_target,
                            .label = instruction.mnemonic,
                        }
                    );
                    break;
                case disasm::InstructionKind::Jump:
                case disasm::InstructionKind::ConditionalJump:
                    xrefs.push_back(
                        CrossReference{
                            .kind = CrossReferenceKind::Jump,
                            .from_address = instruction.address,
                            .to_address = *instruction.control_flow_target,
                            .label = instruction.mnemonic,
                        }
                    );
                    break;
                case disasm::InstructionKind::Unknown:
                case disasm::InstructionKind::DataByte:
                case disasm::InstructionKind::Instruction:
                case disasm::InstructionKind::Return:
                case disasm::InstructionKind::Interrupt:
                default:
                    break;
                }
            }

            for (const auto reference_address : instruction.data_references) {
                const loader::ImportedSymbol* imported_symbol = find_import_for_address(imports, reference_address);
                const ExtractedString* extracted_string = find_string_for_address(strings, reference_address);
                xrefs.push_back(
                    CrossReference{
                        .kind =
                            imported_symbol != nullptr ? CrossReferenceKind::Import :
                            extracted_string != nullptr ? CrossReferenceKind::String :
                            CrossReferenceKind::Data,
                        .from_address = instruction.address,
                        .to_address = reference_address,
                        .label =
                            imported_symbol != nullptr
                                ? (imported_symbol->library.empty()
                                       ? imported_symbol->name
                                       : imported_symbol->library + "!" + imported_symbol->name)
                                :
                            extracted_string != nullptr ? extracted_string->value :
                            instruction.mnemonic,
                    }
                );
            }
        }
    }

    deduplicate_xrefs(xrefs);
    return xrefs;
}

std::string_view to_string(const CrossReferenceKind kind) noexcept {
    switch (kind) {
    case CrossReferenceKind::Call:
        return "call";
    case CrossReferenceKind::Jump:
        return "jump";
    case CrossReferenceKind::Import:
        return "import";
    case CrossReferenceKind::Data:
        return "data";
    case CrossReferenceKind::String:
        return "string";
    default:
        return "unknown";
    }
}

}  // namespace zara::xrefs
