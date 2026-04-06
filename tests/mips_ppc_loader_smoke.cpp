#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

#include "zara/analysis/program_analysis.hpp"
#include "zara/disasm/disassembler.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"

namespace {

std::vector<std::byte> to_bytes(const std::vector<std::uint8_t>& values) {
    return std::vector<std::byte>(
        reinterpret_cast<const std::byte*>(values.data()),
        reinterpret_cast<const std::byte*>(values.data() + values.size())
    );
}

bool verify_architecture(
    const zara::loader::Architecture architecture,
    const std::string_view name,
    const std::vector<std::uint8_t>& code_bytes,
    const std::string_view expected_first_mnemonic
) {
    constexpr std::uint64_t kTextBase = 0x1000;
    const auto image = zara::loader::BinaryImage::from_components(
        std::string(name) + ".bin",
        zara::loader::BinaryFormat::Raw,
        architecture,
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

    zara::memory::AddressSpace address_space;
    if (!address_space.map_image(image)) {
        std::cerr << "failed to map " << name << " image\n";
        return false;
    }

    zara::disasm::Disassembler disassembler;
    if (!disassembler.is_supported(architecture)) {
        std::cerr << "expected decode support for " << name << '\n';
        return false;
    }

    const auto instructions = disassembler.decode(address_space, kTextBase, code_bytes.size(), architecture);
    if (instructions.empty() || instructions.front().mnemonic == "db") {
        std::cerr << "expected decoded instructions for " << name << '\n';
        return false;
    }
    if (instructions.front().mnemonic != expected_first_mnemonic) {
        std::cerr << "unexpected first mnemonic for " << name << ": " << instructions.front().mnemonic << '\n';
        return false;
    }

    const auto analysis = zara::analysis::Analyzer::analyze(image, address_space);
    if (analysis.functions.empty() || analysis.functions.front().entry_address != kTextBase) {
        std::cerr << "expected entry-driven analysis for " << name << '\n';
        return false;
    }
    const auto& blocks = analysis.functions.front().graph.blocks();
    if (blocks.empty() ||
        blocks.front().instructions.empty() ||
        blocks.front().instructions.front().mnemonic == "db") {
        std::cerr << "expected analyzed instructions for " << name << '\n';
        return false;
    }

    return true;
}

}  // namespace

int main() {
    const std::vector<std::uint8_t> mips64_code{
        0xF0, 0xFF, 0xBD, 0x67,  // daddiu sp, sp, -16
        0x08, 0x00, 0xBF, 0xFF,  // sd ra, 8(sp)
        0x08, 0x00, 0xE0, 0x03,  // jr ra
        0x00, 0x00, 0x00, 0x00,  // nop
    };
    if (!verify_architecture(zara::loader::Architecture::MIPS64, "mips64", mips64_code, "daddiu")) {
        return 1;
    }

    const std::vector<std::uint8_t> ppc64_code{
        0xA6, 0x02, 0x08, 0x7C,  // mflr r0
        0xE1, 0xFF, 0x21, 0xF8,  // stdu r1, -32(r1)
        0x20, 0x00, 0x80, 0x4E,  // blr
        0x00, 0x00, 0x00, 0x60,  // nop
    };
    if (!verify_architecture(zara::loader::Architecture::PPC64, "ppc64", ppc64_code, "mflr")) {
        return 2;
    }

    return 0;
}
