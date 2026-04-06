#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace zara::loader {

enum class BinaryFormat {
    Unknown,
    ELF,
    MachO,
    PE,
    Raw,
};

enum class Architecture {
    Unknown,
    X86,
    X86_64,
    ARM,
    ARM64,
    RISCV64,
    MIPS64,
    PPC64,
};

enum class RelocationEncoding {
    Additive,
    MachOChained64,
    MachOChained64Offset,
    MachOChained32,
    MachOChained32Cache,
    MachOChained32Firmware,
    MachOChained64KernelCache,
    MachOChainedX8664KernelCache,
    MachOChainedArm64e,
    MachOChainedArm64eOffset,
    MachOChainedArm64eUserland,
    MachOChainedArm64eUserland24,
    MachOChainedArm64eSharedCache,
    MachOChainedArm64eSegmented,
};

struct Section {
    std::string name;
    std::uint64_t virtual_address = 0;
    std::uint64_t file_offset = 0;
    std::vector<std::byte> bytes;
    bool readable = true;
    bool writable = false;
    bool executable = false;
};

struct ImportedSymbol {
    std::string library;
    std::string name;
    std::uint64_t address = 0;
};

struct ExportedSymbol {
    std::string name;
    std::uint64_t address = 0;
    std::uint64_t size = 0;
};

struct RelocationPatch {
    std::uint64_t address = 0;
    std::uint8_t width = 0;
    RelocationEncoding encoding = RelocationEncoding::Additive;
    std::uint64_t target = 0;
    std::uint8_t high8 = 0;
    std::uint32_t auxiliary = 0;
};

struct ParsePolicy {
    std::size_t max_path_length = 4096;
    std::size_t max_file_size_bytes = 256u * 1024u * 1024u;
    std::size_t max_section_count = 8192;
    std::size_t max_program_header_count = 4096;
    std::size_t max_symbol_count = 200000;
    std::size_t max_import_count = 50000;
    std::size_t max_export_count = 50000;
    std::size_t max_relocation_count = 200000;
    std::size_t max_mapped_section_size = 64u * 1024u * 1024u;
    std::size_t max_total_mapped_bytes = 512u * 1024u * 1024u;
    std::size_t max_string_table_size = 64u * 1024u * 1024u;
    std::size_t max_macho_load_commands = 4096;
    std::size_t max_macho_dylib_count = 4096;
    std::size_t max_section_name_length = 256;
    std::size_t max_symbol_name_length = 1024;
    bool strict_validation = true;
};

struct LoadOptions {
    std::uint64_t base_address = 0x1000;
    std::optional<std::uint64_t> rebase_address;
    ParsePolicy policy;
};

class BinaryImage;

namespace detail {
struct DecodedMachOChainedFixup {
    bool bind = false;
    std::size_t import_index = 0;
    std::uint16_t next = 0;
    std::uint8_t width = 0;
    std::optional<RelocationPatch> relocation;
};

bool parse_elf64(
    const std::filesystem::path& path,
    const std::vector<std::byte>& bytes,
    BinaryImage& out_image,
    std::string& out_error,
    const LoadOptions& options
);
bool parse_pe(
    const std::filesystem::path& path,
    const std::vector<std::byte>& bytes,
    BinaryImage& out_image,
    std::string& out_error,
    const LoadOptions& options
);
bool parse_macho(
    const std::filesystem::path& path,
    const std::vector<std::byte>& bytes,
    BinaryImage& out_image,
    std::string& out_error,
    const LoadOptions& options
);
void populate_raw_image(
    BinaryImage& image,
    const std::filesystem::path& path,
    const std::vector<std::byte>& bytes,
    const LoadOptions& options
);
bool decode_macho_chained_fixup_for_testing(
    std::uint16_t pointer_format,
    std::uint64_t raw_value,
    std::uint64_t preferred_base,
    std::span<const std::uint64_t> segment_addresses,
    DecodedMachOChainedFixup& out_fixup,
    std::string& out_error
);
}  // namespace detail

class BinaryImage {
public:
    [[nodiscard]] static BinaryImage from_components(
        std::filesystem::path source_path,
        BinaryFormat format,
        Architecture architecture,
        std::uint64_t base_address,
        std::optional<std::uint64_t> entry_point,
        std::vector<Section> sections,
        std::vector<ImportedSymbol> imports = {},
        std::vector<ExportedSymbol> exports = {},
        std::vector<std::byte> raw_image = {}
    );

    static bool load_from_file(
        const std::filesystem::path& path,
        BinaryImage& out_image,
        std::string& out_error,
        const LoadOptions& options = {}
    );

    [[nodiscard]] const std::filesystem::path& source_path() const noexcept;
    [[nodiscard]] BinaryFormat format() const noexcept;
    [[nodiscard]] Architecture architecture() const noexcept;
    [[nodiscard]] std::uint64_t base_address() const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> preferred_load_address() const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> entry_point() const noexcept;
    [[nodiscard]] std::span<const std::byte> raw_image() const noexcept;
    [[nodiscard]] const std::vector<Section>& sections() const noexcept;
    [[nodiscard]] const std::vector<ImportedSymbol>& imports() const noexcept;
    [[nodiscard]] const std::vector<ExportedSymbol>& exports() const noexcept;
    [[nodiscard]] std::int64_t rebase_delta() const noexcept;
    void apply_rebase(std::uint64_t new_base_address);

private:
    friend bool detail::parse_elf64(
        const std::filesystem::path& path,
        const std::vector<std::byte>& bytes,
        BinaryImage& out_image,
        std::string& out_error,
        const LoadOptions& options
    );
    friend bool detail::parse_pe(
        const std::filesystem::path& path,
        const std::vector<std::byte>& bytes,
        BinaryImage& out_image,
        std::string& out_error,
        const LoadOptions& options
    );
    friend bool detail::parse_macho(
        const std::filesystem::path& path,
        const std::vector<std::byte>& bytes,
        BinaryImage& out_image,
        std::string& out_error,
        const LoadOptions& options
    );
    friend void detail::populate_raw_image(
        BinaryImage& image,
        const std::filesystem::path& path,
        const std::vector<std::byte>& bytes,
        const LoadOptions& options
    );

    std::filesystem::path source_path_;
    BinaryFormat format_ = BinaryFormat::Unknown;
    Architecture architecture_ = Architecture::Unknown;
    std::uint64_t base_address_ = 0;
    std::optional<std::uint64_t> preferred_load_address_;
    std::optional<std::uint64_t> entry_point_;
    std::vector<std::byte> raw_image_;
    std::vector<Section> sections_;
    std::vector<ImportedSymbol> imports_;
    std::vector<ExportedSymbol> exports_;
    std::vector<RelocationPatch> relocations_;
};

[[nodiscard]] std::string_view to_string(BinaryFormat format) noexcept;
[[nodiscard]] std::string_view to_string(Architecture architecture) noexcept;

}  // namespace zara::loader
