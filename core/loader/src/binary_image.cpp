#include "zara/loader/binary_image.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <optional>
#include <span>
#include <unordered_map>
#include <utility>

namespace zara::loader {

namespace detail {

constexpr std::array<unsigned char, 4> kElfMagic{0x7F, 'E', 'L', 'F'};
constexpr std::array<unsigned char, 2> kMZMagic{'M', 'Z'};
constexpr std::array<unsigned char, 4> kPESignature{'P', 'E', 0x00, 0x00};
constexpr std::array<unsigned char, 4> kMachOMagic64{0xCF, 0xFA, 0xED, 0xFE};

constexpr std::uint8_t kElfClass64 = 2;
constexpr std::uint8_t kElfDataLittleEndian = 1;
constexpr std::uint16_t kElfTypeSharedObject = 3;
constexpr std::uint16_t kElfMachineX86 = 3;
constexpr std::uint16_t kElfMachineX86_64 = 62;
constexpr std::uint16_t kElfMachineArm = 40;
constexpr std::uint16_t kElfMachineArm64 = 183;
constexpr std::uint16_t kElfMachineRiscV = 243;
constexpr std::uint16_t kElfMachineMips = 8;
constexpr std::uint16_t kElfMachinePpc64 = 21;
constexpr std::uint32_t kElfProgramHeaderTypeLoad = 1;
constexpr std::uint32_t kElfSectionTypeRel = 9;
constexpr std::uint32_t kElfSectionTypeRela = 4;
constexpr std::uint64_t kElfSectionFlagWrite = 0x1;
constexpr std::uint64_t kElfSectionFlagAlloc = 0x2;
constexpr std::uint64_t kElfSectionFlagExecute = 0x4;
constexpr std::uint32_t kElfSectionTypeNoBits = 8;
constexpr std::uint32_t kElfSectionTypeDynSym = 11;
constexpr std::uint16_t kElfSectionIndexUndefined = 0;
constexpr std::uint8_t kElfSymbolBindingGlobal = 1;
constexpr std::uint8_t kElfSymbolBindingWeak = 2;

constexpr std::uint16_t kPeMachineX86 = 0x014C;
constexpr std::uint16_t kPeMachineX86_64 = 0x8664;
constexpr std::uint16_t kPeMachineArm = 0x01C0;
constexpr std::uint16_t kPeOptionalHeader32Magic = 0x010B;
constexpr std::uint16_t kPeOptionalHeader64Magic = 0x020B;
constexpr std::uint32_t kPeDataDirectoryExport = 0;
constexpr std::uint32_t kPeDataDirectoryImport = 1;
constexpr std::uint32_t kPeDataDirectoryBaseRelocation = 5;
constexpr std::uint32_t kPeSectionContainsCode = 0x00000020;
constexpr std::uint32_t kPeSectionMemoryRead = 0x40000000;
constexpr std::uint32_t kPeSectionMemoryWrite = 0x80000000;
constexpr std::uint32_t kPeSectionMemoryExecute = 0x20000000;
constexpr std::uint16_t kPeRelocationAbsolute = 0;
constexpr std::uint16_t kPeRelocationHighLow = 3;
constexpr std::uint16_t kPeRelocationDir64 = 10;

constexpr std::uint32_t kElfRelocationType386Relative = 8;
constexpr std::uint32_t kElfRelocationTypeX86_64Relative = 8;
constexpr std::uint32_t kElfRelocationTypeArm64Relative = 1027;

constexpr std::uint32_t kMachOCpuTypeX86_64 = 0x01000007;
constexpr std::uint32_t kMachOCpuTypeArm64 = 0x0100000C;
constexpr std::uint32_t kMachOCpuTypePowerPC64 = 0x01000012;
constexpr std::uint32_t kMachOLoadCommandSegment64 = 0x19;
constexpr std::uint32_t kMachOLoadCommandSymtab = 0x2;
constexpr std::uint32_t kMachOLoadCommandDysymtab = 0xb;
constexpr std::uint32_t kMachOLoadCommandLoadDylib = 0xc;
constexpr std::uint32_t kMachOLoadCommandDyldChainedFixups = 0x80000034U;
constexpr std::uint32_t kMachOLoadCommandMain = 0x80000028;
constexpr std::uint8_t kMachONTypeMask = 0x0e;
constexpr std::uint8_t kMachONTypeUndefined = 0x0;
constexpr std::uint8_t kMachONTypeSection = 0x0e;
constexpr std::uint8_t kMachONTypeExternal = 0x01;
constexpr std::uint32_t kMachOSectionTypeMask = 0x000000ff;
constexpr std::uint32_t kMachOSectionTypeNonLazySymbolPointers = 0x6;
constexpr std::uint32_t kMachOSectionTypeLazySymbolPointers = 0x7;
constexpr std::uint32_t kMachOIndirectSymbolLocal = 0x80000000U;
constexpr std::uint32_t kMachOIndirectSymbolAbsolute = 0x40000000U;
constexpr std::uint32_t kMachORelocationTypeUnsigned = 0;
constexpr std::uint16_t kDyldChainedPtrStartNone = 0xFFFFU;
constexpr std::uint16_t kDyldChainedPtrStartMulti = 0x8000U;
constexpr std::uint16_t kDyldChainedPtrStartLast = 0x8000U;
constexpr std::uint16_t kDyldChainedPtrArm64e = 1;
constexpr std::uint16_t kDyldChainedPtr64 = 2;
constexpr std::uint16_t kDyldChainedPtr32 = 3;
constexpr std::uint16_t kDyldChainedPtr32Cache = 4;
constexpr std::uint16_t kDyldChainedPtr32Firmware = 5;
constexpr std::uint16_t kDyldChainedPtr64Offset = 6;
constexpr std::uint16_t kDyldChainedPtrArm64eOffset = 7;
constexpr std::uint16_t kDyldChainedPtr64KernelCache = 8;
constexpr std::uint16_t kDyldChainedPtrArm64eUserland = 9;
constexpr std::uint16_t kDyldChainedPtrArm64eFirmware = 10;
constexpr std::uint16_t kDyldChainedPtrX8664KernelCache = 11;
constexpr std::uint16_t kDyldChainedPtrArm64eUserland24 = 12;
constexpr std::uint16_t kDyldChainedPtrArm64eSharedCache = 13;
constexpr std::uint16_t kDyldChainedPtrArm64eSegmented = 14;
constexpr std::uint32_t kDyldChainedImport = 1;
constexpr std::uint32_t kDyldChainedImportAddend = 2;
constexpr std::uint32_t kDyldChainedImportAddend64 = 3;

struct Elf64Header {
    unsigned char ident[16];
    std::uint16_t type;
    std::uint16_t machine;
    std::uint32_t version;
    std::uint64_t entry;
    std::uint64_t program_header_offset;
    std::uint64_t section_header_offset;
    std::uint32_t flags;
    std::uint16_t header_size;
    std::uint16_t program_header_entry_size;
    std::uint16_t program_header_count;
    std::uint16_t section_header_entry_size;
    std::uint16_t section_header_count;
    std::uint16_t section_name_string_table_index;
};

struct Elf64SectionHeader {
    std::uint32_t name_offset;
    std::uint32_t type;
    std::uint64_t flags;
    std::uint64_t address;
    std::uint64_t offset;
    std::uint64_t size;
    std::uint32_t link;
    std::uint32_t info;
    std::uint64_t address_align;
    std::uint64_t entry_size;
};

struct Elf64ProgramHeader {
    std::uint32_t type;
    std::uint32_t flags;
    std::uint64_t offset;
    std::uint64_t virtual_address;
    std::uint64_t physical_address;
    std::uint64_t file_size;
    std::uint64_t memory_size;
    std::uint64_t alignment;
};

struct Elf64Symbol {
    std::uint32_t name_offset;
    std::uint8_t info;
    std::uint8_t other;
    std::uint16_t section_index;
    std::uint64_t value;
    std::uint64_t size;
};

struct Elf64Rela {
    std::uint64_t offset;
    std::uint64_t info;
    std::int64_t addend;
};

struct Elf64Rel {
    std::uint64_t offset;
    std::uint64_t info;
};

struct ParsedElfSection {
    Elf64SectionHeader header;
    std::string name;
};

struct ParsedElfSymbol {
    std::string name;
    std::uint16_t section_index = 0;
    std::uint64_t value = 0;
    std::uint64_t size = 0;
    std::uint8_t binding = 0;
};

struct PeDosHeader {
    std::uint16_t magic;
    std::uint8_t unused[58];
    std::uint32_t pe_offset;
};

struct PeFileHeader {
    std::uint16_t machine;
    std::uint16_t section_count;
    std::uint32_t timestamp;
    std::uint32_t pointer_to_symbol_table;
    std::uint32_t number_of_symbols;
    std::uint16_t optional_header_size;
    std::uint16_t characteristics;
};

struct PeSectionHeader {
    char name[8];
    std::uint32_t virtual_size;
    std::uint32_t virtual_address;
    std::uint32_t size_of_raw_data;
    std::uint32_t pointer_to_raw_data;
    std::uint32_t pointer_to_relocations;
    std::uint32_t pointer_to_linenumbers;
    std::uint16_t number_of_relocations;
    std::uint16_t number_of_linenumbers;
    std::uint32_t characteristics;
};

struct PeDataDirectory {
    std::uint32_t virtual_address;
    std::uint32_t size;
};

struct PeImportDescriptor {
    std::uint32_t original_first_thunk;
    std::uint32_t time_date_stamp;
    std::uint32_t forwarder_chain;
    std::uint32_t name_rva;
    std::uint32_t first_thunk;
};

struct PeExportDirectory {
    std::uint32_t characteristics;
    std::uint32_t time_date_stamp;
    std::uint16_t major_version;
    std::uint16_t minor_version;
    std::uint32_t name_rva;
    std::uint32_t base;
    std::uint32_t number_of_functions;
    std::uint32_t number_of_names;
    std::uint32_t address_of_functions;
    std::uint32_t address_of_names;
    std::uint32_t address_of_name_ordinals;
};

struct PeBaseRelocationBlock {
    std::uint32_t page_rva;
    std::uint32_t block_size;
};

struct MachOHeader64 {
    std::uint32_t magic;
    std::uint32_t cpu_type;
    std::uint32_t cpu_subtype;
    std::uint32_t file_type;
    std::uint32_t command_count;
    std::uint32_t commands_size;
    std::uint32_t flags;
    std::uint32_t reserved;
};

struct MachOLoadCommand {
    std::uint32_t command;
    std::uint32_t command_size;
};

struct MachOSegmentCommand64 {
    std::uint32_t command;
    std::uint32_t command_size;
    char segment_name[16];
    std::uint64_t virtual_address;
    std::uint64_t virtual_size;
    std::uint64_t file_offset;
    std::uint64_t file_size;
    std::uint32_t max_protection;
    std::uint32_t initial_protection;
    std::uint32_t section_count;
    std::uint32_t flags;
};

struct MachOSection64 {
    char section_name[16];
    char segment_name[16];
    std::uint64_t address;
    std::uint64_t size;
    std::uint32_t offset;
    std::uint32_t align;
    std::uint32_t relocation_offset;
    std::uint32_t relocation_count;
    std::uint32_t flags;
    std::uint32_t reserved1;
    std::uint32_t reserved2;
    std::uint32_t reserved3;
};

struct MachORelocationInfo {
    std::int32_t address;
    std::uint32_t raw;
};

struct MachOSymtabCommand {
    std::uint32_t command;
    std::uint32_t command_size;
    std::uint32_t symbol_offset;
    std::uint32_t symbol_count;
    std::uint32_t string_offset;
    std::uint32_t string_size;
};

struct MachODysymtabCommand {
    std::uint32_t command;
    std::uint32_t command_size;
    std::uint32_t local_symbol_index;
    std::uint32_t local_symbol_count;
    std::uint32_t external_defined_symbol_index;
    std::uint32_t external_defined_symbol_count;
    std::uint32_t undefined_symbol_index;
    std::uint32_t undefined_symbol_count;
    std::uint32_t toc_offset;
    std::uint32_t toc_count;
    std::uint32_t module_table_offset;
    std::uint32_t module_table_count;
    std::uint32_t external_reference_symbol_offset;
    std::uint32_t external_reference_symbol_count;
    std::uint32_t indirect_symbol_offset;
    std::uint32_t indirect_symbol_count;
    std::uint32_t external_relocation_offset;
    std::uint32_t external_relocation_count;
    std::uint32_t local_relocation_offset;
    std::uint32_t local_relocation_count;
};

struct MachONList64 {
    std::uint32_t string_index;
    std::uint8_t type;
    std::uint8_t section_index;
    std::uint16_t description;
    std::uint64_t value;
};

struct MachOMainCommand {
    std::uint32_t command;
    std::uint32_t command_size;
    std::uint64_t entry_offset;
    std::uint64_t stack_size;
};

struct MachODylibCommand {
    std::uint32_t command;
    std::uint32_t command_size;
    std::uint32_t name_offset;
    std::uint32_t timestamp;
    std::uint32_t current_version;
    std::uint32_t compatibility_version;
};

#pragma pack(push, 1)

struct MachOLinkeditDataCommand {
    std::uint32_t command;
    std::uint32_t command_size;
    std::uint32_t data_offset;
    std::uint32_t data_size;
};

struct DyldChainedFixupsHeader {
    std::uint32_t fixups_version;
    std::uint32_t starts_offset;
    std::uint32_t imports_offset;
    std::uint32_t symbols_offset;
    std::uint32_t imports_count;
    std::uint32_t imports_format;
    std::uint32_t symbols_format;
};

struct DyldChainedStartsInImageHeader {
    std::uint32_t segment_count;
};

struct DyldChainedStartsInSegmentHeader {
    std::uint32_t size;
    std::uint16_t page_size;
    std::uint16_t pointer_format;
    std::uint64_t segment_offset;
    std::uint32_t max_valid_pointer;
    std::uint16_t page_count;
};

#pragma pack(pop)

struct ParsedMachOSection {
    MachOSection64 header;
    std::string name;
    std::string segment_name;
};

struct ParsedMachOSymbol {
    std::string name;
    std::uint8_t type = 0;
    std::uint8_t section_index = 0;
    std::uint16_t description = 0;
    std::uint64_t value = 0;
};

static_assert(sizeof(Elf64Header) == 64);
static_assert(sizeof(Elf64SectionHeader) == 64);
static_assert(sizeof(Elf64ProgramHeader) == 56);
static_assert(sizeof(Elf64Symbol) == 24);
static_assert(sizeof(Elf64Rela) == 24);
static_assert(sizeof(Elf64Rel) == 16);
static_assert(sizeof(PeDosHeader) == 64);
static_assert(sizeof(PeFileHeader) == 20);
static_assert(sizeof(PeSectionHeader) == 40);
static_assert(sizeof(PeDataDirectory) == 8);
static_assert(sizeof(PeImportDescriptor) == 20);
static_assert(sizeof(PeExportDirectory) == 40);
static_assert(sizeof(PeBaseRelocationBlock) == 8);
static_assert(sizeof(MachOHeader64) == 32);
static_assert(sizeof(MachOLoadCommand) == 8);
static_assert(sizeof(MachOSegmentCommand64) == 72);
static_assert(sizeof(MachOSection64) == 80);
static_assert(sizeof(MachORelocationInfo) == 8);
static_assert(sizeof(MachOSymtabCommand) == 24);
static_assert(sizeof(MachODysymtabCommand) == 80);
static_assert(sizeof(MachONList64) == 16);
static_assert(sizeof(MachOMainCommand) == 24);
static_assert(sizeof(MachODylibCommand) == 24);
static_assert(sizeof(MachOLinkeditDataCommand) == 16);
static_assert(sizeof(DyldChainedFixupsHeader) == 28);
static_assert(sizeof(DyldChainedStartsInImageHeader) == 4);
static_assert(sizeof(DyldChainedStartsInSegmentHeader) == 22);

std::vector<std::byte> to_bytes(const std::vector<char>& buffer) {
    std::vector<std::byte> bytes;
    bytes.reserve(buffer.size());

    for (char value : buffer) {
        bytes.push_back(static_cast<std::byte>(value));
    }

    return bytes;
}

template <typename T>
bool read_object(const std::span<const std::byte> bytes, const std::size_t offset, T& out_value) {
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) {
        return false;
    }

    std::memcpy(&out_value, bytes.data() + offset, sizeof(T));
    return true;
}

template <typename T>
std::optional<T> read_scalar(const std::span<const std::byte> bytes, const std::size_t offset) {
    T value{};
    if (!read_object(bytes, offset, value)) {
        return std::nullopt;
    }

    return value;
}

bool has_prefix(const std::span<const std::byte> bytes, const std::span<const unsigned char> prefix) {
    if (prefix.size() > bytes.size()) {
        return false;
    }

    for (std::size_t index = 0; index < prefix.size(); ++index) {
        if (std::to_integer<unsigned char>(bytes[index]) != prefix[index]) {
            return false;
        }
    }

    return true;
}

std::string read_null_terminated_string(const std::span<const std::byte> bytes, const std::size_t offset) {
    if (offset >= bytes.size()) {
        return {};
    }

    std::string value;
    for (std::size_t index = offset; index < bytes.size(); ++index) {
        const char character = static_cast<char>(std::to_integer<unsigned char>(bytes[index]));
        if (character == '\0') {
            break;
        }

        value.push_back(character);
    }

    return value;
}

std::string trim_pe_section_name(const char* raw_name) {
    std::string value(raw_name, raw_name + 8);
    const auto terminator = value.find('\0');
    if (terminator != std::string::npos) {
        value.resize(terminator);
    }

    return value;
}

std::string trim_macho_name(const char* raw_name, const std::size_t size) {
    std::string value(raw_name, raw_name + static_cast<std::ptrdiff_t>(size));
    const auto terminator = value.find('\0');
    if (terminator != std::string::npos) {
        value.resize(terminator);
    }
    return value;
}

Architecture architecture_from_elf_machine(const std::uint16_t machine) {
    switch (machine) {
    case kElfMachineX86:
        return Architecture::X86;
    case kElfMachineX86_64:
        return Architecture::X86_64;
    case kElfMachineArm:
        return Architecture::ARM;
    case kElfMachineArm64:
        return Architecture::ARM64;
    case kElfMachineRiscV:
        return Architecture::RISCV64;
    case kElfMachineMips:
        return Architecture::MIPS64;
    case kElfMachinePpc64:
        return Architecture::PPC64;
    default:
        return Architecture::Unknown;
    }
}

Architecture architecture_from_macho_cpu_type(const std::uint32_t cpu_type) {
    switch (cpu_type) {
    case kMachOCpuTypeX86_64:
        return Architecture::X86_64;
    case kMachOCpuTypeArm64:
        return Architecture::ARM64;
    case kMachOCpuTypePowerPC64:
        return Architecture::PPC64;
    default:
        return Architecture::Unknown;
    }
}

Architecture architecture_from_pe_machine(const std::uint16_t machine) {
    switch (machine) {
    case kPeMachineX86:
        return Architecture::X86;
    case kPeMachineX86_64:
        return Architecture::X86_64;
    case kPeMachineArm:
        return Architecture::ARM;
    default:
        return Architecture::Unknown;
    }
}

struct ChainedImportRecord {
    std::string library;
    std::string name;
    std::int64_t addend = 0;
    bool weak = false;
};

std::string library_name_from_ordinal(
    const std::vector<std::string>& dylibs,
    const std::int32_t ordinal
) {
    if (ordinal > 0 && static_cast<std::size_t>(ordinal) <= dylibs.size()) {
        return dylibs[static_cast<std::size_t>(ordinal - 1)];
    }
    if (ordinal == -2) {
        return "flat_lookup";
    }
    if (ordinal == -3) {
        return "weak_lookup";
    }
    if (ordinal == -1) {
        return "main_executable";
    }
    return {};
}

std::optional<std::span<const std::byte>> span_subrange(
    const std::span<const std::byte> bytes,
    const std::size_t offset,
    const std::size_t size
) {
    if (offset > bytes.size() || size > bytes.size() - offset) {
        return std::nullopt;
    }
    return bytes.subspan(offset, size);
}

bool read_virtual_bytes(
    const BinaryImage& image,
    const std::uint64_t address,
    const std::size_t size,
    std::span<const std::byte>& out_bytes
) {
    for (const auto& section : image.sections()) {
        const auto end_address = section.virtual_address + static_cast<std::uint64_t>(section.bytes.size());
        if (address < section.virtual_address || address >= end_address) {
            continue;
        }

        const auto offset = static_cast<std::size_t>(address - section.virtual_address);
        if (offset > section.bytes.size() || size > section.bytes.size() - offset) {
            return false;
        }
        out_bytes = std::span<const std::byte>(section.bytes).subspan(offset, size);
        return true;
    }
    return false;
}

std::optional<std::uint64_t> read_virtual_qword(
    const BinaryImage& image,
    const std::uint64_t address
) {
    std::span<const std::byte> bytes;
    if (!read_virtual_bytes(image, address, sizeof(std::uint64_t), bytes)) {
        return std::nullopt;
    }

    std::uint64_t value = 0;
    std::memcpy(&value, bytes.data(), sizeof(value));
    return value;
}

std::optional<std::vector<ChainedImportRecord>> parse_chained_imports(
    const std::span<const std::byte> fixups_data,
    const DyldChainedFixupsHeader& header,
    const std::vector<std::string>& dylibs,
    std::string& out_error
) {
    std::size_t import_entry_size = 0;
    switch (header.imports_format) {
    case kDyldChainedImport:
        import_entry_size = sizeof(std::uint32_t);
        break;
    case kDyldChainedImportAddend:
        import_entry_size = sizeof(std::uint32_t) + sizeof(std::int32_t);
        break;
    case kDyldChainedImportAddend64:
        import_entry_size = sizeof(std::uint64_t) + sizeof(std::int64_t);
        break;
    default:
        out_error = "Unsupported Mach-O chained import format.";
        return std::nullopt;
    }

    const std::uint64_t imports_bytes = static_cast<std::uint64_t>(header.imports_count) * import_entry_size;
    const auto import_span = span_subrange(
        fixups_data,
        static_cast<std::size_t>(header.imports_offset),
        static_cast<std::size_t>(imports_bytes)
    );
    if (!import_span.has_value()) {
        out_error = "Mach-O chained import table is out of bounds.";
        return std::nullopt;
    }

    if (header.symbols_offset > fixups_data.size()) {
        out_error = "Mach-O chained import symbol strings are out of bounds.";
        return std::nullopt;
    }
    const auto symbols = fixups_data.subspan(static_cast<std::size_t>(header.symbols_offset));

    std::vector<ChainedImportRecord> imports;
    imports.reserve(header.imports_count);
    for (std::uint32_t index = 0; index < header.imports_count; ++index) {
        const std::size_t entry_offset = static_cast<std::size_t>(index) * import_entry_size;
        std::int32_t ordinal = 0;
        std::uint32_t name_offset = 0;
        std::int64_t addend = 0;
        bool weak = false;

        if (header.imports_format == kDyldChainedImport) {
            const auto raw = read_scalar<std::uint32_t>(*import_span, entry_offset);
            if (!raw.has_value()) {
                out_error = "Mach-O chained import entry is truncated.";
                return std::nullopt;
            }
            ordinal = static_cast<std::int32_t>(static_cast<std::int8_t>(*raw & 0xFFU));
            weak = ((*raw >> 8U) & 0x1U) != 0;
            name_offset = *raw >> 9U;
        } else if (header.imports_format == kDyldChainedImportAddend) {
            const auto raw = read_scalar<std::uint32_t>(*import_span, entry_offset);
            const auto raw_addend = read_scalar<std::int32_t>(*import_span, entry_offset + sizeof(std::uint32_t));
            if (!raw.has_value() || !raw_addend.has_value()) {
                out_error = "Mach-O chained import entry is truncated.";
                return std::nullopt;
            }
            ordinal = static_cast<std::int32_t>(static_cast<std::int8_t>(*raw & 0xFFU));
            weak = ((*raw >> 8U) & 0x1U) != 0;
            name_offset = *raw >> 9U;
            addend = *raw_addend;
        } else {
            const auto raw = read_scalar<std::uint64_t>(*import_span, entry_offset);
            const auto raw_addend = read_scalar<std::int64_t>(*import_span, entry_offset + sizeof(std::uint64_t));
            if (!raw.has_value() || !raw_addend.has_value()) {
                out_error = "Mach-O chained import entry is truncated.";
                return std::nullopt;
            }
            ordinal = static_cast<std::int32_t>(static_cast<std::int16_t>(*raw & 0xFFFFU));
            weak = ((*raw >> 16U) & 0x1U) != 0;
            name_offset = static_cast<std::uint32_t>(*raw >> 32U);
            addend = *raw_addend;
        }

        const std::string symbol_name = read_null_terminated_string(symbols, name_offset);
        imports.push_back(
            ChainedImportRecord{
                .library = library_name_from_ordinal(dylibs, ordinal),
                .name = !symbol_name.empty() && symbol_name.front() == '_' ? symbol_name.substr(1) : symbol_name,
                .addend = addend,
                .weak = weak,
            }
        );
    }

    return imports;
}

std::uint64_t macho_segment_address(
    const std::vector<MachOSegmentCommand64>& segments,
    const std::size_t segment_index
) {
    if (segment_index >= segments.size()) {
        return 0;
    }
    return segments[segment_index].virtual_address;
}

std::optional<std::uint8_t> macho_chained_stride(const std::uint16_t pointer_format) {
    switch (pointer_format) {
    case kDyldChainedPtrArm64eOffset:
    case kDyldChainedPtrArm64eFirmware:
    case kDyldChainedPtrArm64eSegmented:
        return 4;
    case kDyldChainedPtrX8664KernelCache:
        return 1;
    case kDyldChainedPtrArm64e:
    case kDyldChainedPtr64:
    case kDyldChainedPtr32:
    case kDyldChainedPtr32Cache:
    case kDyldChainedPtr32Firmware:
    case kDyldChainedPtr64Offset:
    case kDyldChainedPtr64KernelCache:
    case kDyldChainedPtrArm64eUserland:
    case kDyldChainedPtrArm64eUserland24:
    case kDyldChainedPtrArm64eSharedCache:
        return 8;
    default:
        return std::nullopt;
    }
}

std::optional<std::uint8_t> macho_chained_pointer_width(const std::uint16_t pointer_format) {
    switch (pointer_format) {
    case kDyldChainedPtr32:
    case kDyldChainedPtr32Cache:
    case kDyldChainedPtr32Firmware:
        return 4;
    case kDyldChainedPtrArm64e:
    case kDyldChainedPtr64:
    case kDyldChainedPtr64Offset:
    case kDyldChainedPtrArm64eOffset:
    case kDyldChainedPtr64KernelCache:
    case kDyldChainedPtrArm64eUserland:
    case kDyldChainedPtrArm64eFirmware:
    case kDyldChainedPtrX8664KernelCache:
    case kDyldChainedPtrArm64eUserland24:
    case kDyldChainedPtrArm64eSharedCache:
    case kDyldChainedPtrArm64eSegmented:
        return 8;
    default:
        return std::nullopt;
    }
}

std::optional<RelocationEncoding> macho_chained_relocation_encoding(const std::uint16_t pointer_format) {
    switch (pointer_format) {
    case kDyldChainedPtr64:
        return RelocationEncoding::MachOChained64;
    case kDyldChainedPtr64Offset:
        return RelocationEncoding::MachOChained64Offset;
    case kDyldChainedPtr32:
        return RelocationEncoding::MachOChained32;
    case kDyldChainedPtr32Cache:
        return RelocationEncoding::MachOChained32Cache;
    case kDyldChainedPtr32Firmware:
        return RelocationEncoding::MachOChained32Firmware;
    case kDyldChainedPtr64KernelCache:
        return RelocationEncoding::MachOChained64KernelCache;
    case kDyldChainedPtrX8664KernelCache:
        return RelocationEncoding::MachOChainedX8664KernelCache;
    case kDyldChainedPtrArm64e:
    case kDyldChainedPtrArm64eFirmware:
        return RelocationEncoding::MachOChainedArm64e;
    case kDyldChainedPtrArm64eOffset:
        return RelocationEncoding::MachOChainedArm64eOffset;
    case kDyldChainedPtrArm64eUserland:
        return RelocationEncoding::MachOChainedArm64eUserland;
    case kDyldChainedPtrArm64eUserland24:
        return RelocationEncoding::MachOChainedArm64eUserland24;
    case kDyldChainedPtrArm64eSharedCache:
        return RelocationEncoding::MachOChainedArm64eSharedCache;
    case kDyldChainedPtrArm64eSegmented:
        return RelocationEncoding::MachOChainedArm64eSegmented;
    default:
        return std::nullopt;
    }
}

std::optional<std::uint8_t> macho_relocation_width(const std::uint32_t encoded_length) {
    switch (encoded_length & 0x3U) {
    case 0:
        return 1;
    case 1:
        return 2;
    case 2:
        return 4;
    case 3:
        return 8;
    default:
        return std::nullopt;
    }
}

struct DecodedChainedFixup {
    bool bind = false;
    std::size_t import_index = 0;
    std::uint16_t next = 0;
    std::uint8_t width = 0;
    std::optional<RelocationPatch> relocation;
};

std::optional<DecodedChainedFixup> decode_macho_chained_fixup(
    const std::uint16_t pointer_format,
    const std::uint64_t raw_value,
    const std::uint64_t preferred_base,
    const std::vector<MachOSegmentCommand64>& segments,
    std::string& out_error
) {
    const auto width = macho_chained_pointer_width(pointer_format);
    if (!width.has_value()) {
        out_error = "Unsupported Mach-O chained pointer width.";
        return std::nullopt;
    }

    const auto encoding = macho_chained_relocation_encoding(pointer_format);
    if (!encoding.has_value()) {
        out_error = "Unsupported Mach-O chained pointer format.";
        return std::nullopt;
    }

    DecodedChainedFixup decoded{
        .bind = false,
        .import_index = 0,
        .next = 0,
        .width = *width,
        .relocation = std::nullopt,
    };

    auto set_relocation = [&](const std::uint64_t absolute_target, const std::uint32_t auxiliary = 0) {
        decoded.relocation = RelocationPatch{
            .address = 0,
            .width = *width,
            .encoding = *encoding,
            .target = absolute_target,
            .high8 = 0,
            .auxiliary = auxiliary,
        };
    };

    switch (pointer_format) {
    case kDyldChainedPtr64:
    case kDyldChainedPtr64Offset: {
        decoded.bind = ((raw_value >> 63U) & 0x1U) != 0;
        decoded.next = static_cast<std::uint16_t>((raw_value >> 51U) & 0xFFFU);
        if (decoded.bind) {
            decoded.import_index = static_cast<std::size_t>(raw_value & 0x00FFFFFFU);
            return decoded;
        }

        const std::uint64_t low_target = raw_value & ((1ULL << 36U) - 1U);
        const std::uint64_t absolute_target =
            (pointer_format == kDyldChainedPtr64)
                ? (low_target | (static_cast<std::uint64_t>((raw_value >> 36U) & 0xFFU) << 56U))
                : preferred_base + (low_target | (static_cast<std::uint64_t>((raw_value >> 36U) & 0xFFU) << 56U));
        set_relocation(absolute_target);
        return decoded;
    }
    case kDyldChainedPtr32: {
        const std::uint32_t raw32 = static_cast<std::uint32_t>(raw_value & 0xFFFFFFFFU);
        decoded.bind = ((raw32 >> 31U) & 0x1U) != 0;
        decoded.next = static_cast<std::uint16_t>((raw32 >> 26U) & 0x1FU);
        if (decoded.bind) {
            decoded.import_index = static_cast<std::size_t>(raw32 & 0xFFFFFU);
            return decoded;
        }
        set_relocation(static_cast<std::uint64_t>(raw32 & 0x03FFFFFFU));
        return decoded;
    }
    case kDyldChainedPtr32Cache: {
        const std::uint32_t raw32 = static_cast<std::uint32_t>(raw_value & 0xFFFFFFFFU);
        decoded.next = static_cast<std::uint16_t>((raw32 >> 30U) & 0x3U);
        set_relocation(preferred_base + static_cast<std::uint64_t>(raw32 & 0x3FFFFFFFU));
        return decoded;
    }
    case kDyldChainedPtr32Firmware: {
        const std::uint32_t raw32 = static_cast<std::uint32_t>(raw_value & 0xFFFFFFFFU);
        decoded.next = static_cast<std::uint16_t>((raw32 >> 26U) & 0x3FU);
        set_relocation(static_cast<std::uint64_t>(raw32 & 0x03FFFFFFU));
        return decoded;
    }
    case kDyldChainedPtr64KernelCache:
    case kDyldChainedPtrX8664KernelCache: {
        decoded.next = static_cast<std::uint16_t>((raw_value >> 51U) & 0xFFFU);
        set_relocation(preferred_base + (raw_value & 0x3FFFFFFFU), static_cast<std::uint32_t>((raw_value >> 30U) & 0x3U));
        return decoded;
    }
    case kDyldChainedPtrArm64e:
    case kDyldChainedPtrArm64eFirmware:
    case kDyldChainedPtrArm64eOffset:
    case kDyldChainedPtrArm64eUserland:
    case kDyldChainedPtrArm64eUserland24: {
        const bool auth = ((raw_value >> 63U) & 0x1U) != 0;
        decoded.bind = ((raw_value >> 62U) & 0x1U) != 0;
        decoded.next = static_cast<std::uint16_t>((raw_value >> 51U) & 0x7FFU);

        if (decoded.bind) {
            const std::uint64_t import_mask =
                pointer_format == kDyldChainedPtrArm64eUserland24 ? 0xFFFFFFULL : 0xFFFFULL;
            decoded.import_index = static_cast<std::size_t>(raw_value & import_mask);
            return decoded;
        }

        if (auth) {
            const std::uint64_t runtime_offset = raw_value & 0xFFFFFFFFULL;
            set_relocation(preferred_base + runtime_offset);
            return decoded;
        }

        const std::uint64_t low_target = raw_value & ((1ULL << 43U) - 1U);
        const std::uint64_t composed_target =
            low_target | (static_cast<std::uint64_t>((raw_value >> 43U) & 0xFFU) << 56U);
        const bool offset_target =
            pointer_format == kDyldChainedPtrArm64eOffset ||
            pointer_format == kDyldChainedPtrArm64eUserland ||
            pointer_format == kDyldChainedPtrArm64eUserland24;
        set_relocation(offset_target ? preferred_base + composed_target : composed_target);
        return decoded;
    }
    case kDyldChainedPtrArm64eSharedCache: {
        decoded.next = static_cast<std::uint16_t>((raw_value >> 51U) & 0x7FFU);
        set_relocation(preferred_base + (raw_value & ((1ULL << 34U) - 1U)));
        return decoded;
    }
    case kDyldChainedPtrArm64eSegmented: {
        decoded.next = static_cast<std::uint16_t>((raw_value >> 51U) & 0xFFFU);
        const std::uint32_t low = static_cast<std::uint32_t>(raw_value & 0xFFFFFFFFU);
        const std::uint32_t target_segment_offset = low & 0x0FFFFFFFU;
        const std::uint32_t target_segment_index = (low >> 28U) & 0xFU;
        const std::uint64_t absolute_target =
            macho_segment_address(segments, target_segment_index) + target_segment_offset;
        set_relocation(absolute_target, target_segment_index);
        return decoded;
    }
    default:
        out_error = "Unsupported Mach-O chained pointer format.";
        return std::nullopt;
    }
}

bool decode_macho_chained_fixup_for_testing(
    const std::uint16_t pointer_format,
    const std::uint64_t raw_value,
    const std::uint64_t preferred_base,
    const std::span<const std::uint64_t> segment_addresses,
    DecodedMachOChainedFixup& out_fixup,
    std::string& out_error
) {
    std::vector<MachOSegmentCommand64> segments;
    segments.reserve(segment_addresses.size());
    for (const auto address : segment_addresses) {
        segments.push_back(
            MachOSegmentCommand64{
                .command = 0,
                .command_size = 0,
                .segment_name = {},
                .virtual_address = address,
                .virtual_size = 0,
                .file_offset = 0,
                .file_size = 0,
                .max_protection = 0,
                .initial_protection = 0,
                .section_count = 0,
                .flags = 0,
            }
        );
    }

    const auto decoded = decode_macho_chained_fixup(pointer_format, raw_value, preferred_base, segments, out_error);
    if (!decoded.has_value()) {
        return false;
    }

    out_fixup.bind = decoded->bind;
    out_fixup.import_index = decoded->import_index;
    out_fixup.next = decoded->next;
    out_fixup.width = decoded->width;
    out_fixup.relocation = decoded->relocation;
    return true;
}

bool is_global_or_weak_symbol(const std::uint8_t info) {
    const std::uint8_t binding = info >> 4;
    return binding == kElfSymbolBindingGlobal || binding == kElfSymbolBindingWeak;
}

void deduplicate_imports(std::vector<ImportedSymbol>& imports) {
    std::sort(
        imports.begin(),
        imports.end(),
        [](const ImportedSymbol& lhs, const ImportedSymbol& rhs) {
            if (lhs.address != rhs.address) {
                return lhs.address < rhs.address;
            }
            if (lhs.library != rhs.library) {
                return lhs.library < rhs.library;
            }
            return lhs.name < rhs.name;
        }
    );

    imports.erase(
        std::unique(
            imports.begin(),
            imports.end(),
            [](const ImportedSymbol& lhs, const ImportedSymbol& rhs) {
                return lhs.address == rhs.address &&
                       lhs.library == rhs.library &&
                       lhs.name == rhs.name;
            }
        ),
        imports.end()
    );
}

void deduplicate_exports(std::vector<ExportedSymbol>& exports) {
    std::sort(
        exports.begin(),
        exports.end(),
        [](const ExportedSymbol& lhs, const ExportedSymbol& rhs) {
            if (lhs.address != rhs.address) {
                return lhs.address < rhs.address;
            }
            return lhs.name < rhs.name;
        }
    );

    exports.erase(
        std::unique(
            exports.begin(),
            exports.end(),
            [](const ExportedSymbol& lhs, const ExportedSymbol& rhs) {
                return lhs.address == rhs.address &&
                       lhs.size == rhs.size &&
                       lhs.name == rhs.name;
            }
        ),
        exports.end()
    );
}

void deduplicate_relocations(std::vector<RelocationPatch>& relocations) {
    std::sort(
        relocations.begin(),
        relocations.end(),
        [](const RelocationPatch& lhs, const RelocationPatch& rhs) {
            if (lhs.address != rhs.address) {
                return lhs.address < rhs.address;
            }
            if (lhs.width != rhs.width) {
                return lhs.width < rhs.width;
            }
            if (lhs.encoding != rhs.encoding) {
                return lhs.encoding < rhs.encoding;
            }
            if (lhs.target != rhs.target) {
                return lhs.target < rhs.target;
            }
            if (lhs.high8 != rhs.high8) {
                return lhs.high8 < rhs.high8;
            }
            return lhs.auxiliary < rhs.auxiliary;
        }
    );

    relocations.erase(
        std::unique(
            relocations.begin(),
            relocations.end(),
            [](const RelocationPatch& lhs, const RelocationPatch& rhs) {
                return lhs.address == rhs.address &&
                       lhs.width == rhs.width &&
                       lhs.encoding == rhs.encoding &&
                       lhs.target == rhs.target &&
                       lhs.high8 == rhs.high8 &&
                       lhs.auxiliary == rhs.auxiliary;
            }
        ),
        relocations.end()
    );
}

std::optional<std::size_t> pe_rva_to_file_offset(
    const std::uint32_t rva,
    const std::vector<PeSectionHeader>& sections,
    const std::size_t size_of_headers
) {
    if (rva < size_of_headers) {
        return static_cast<std::size_t>(rva);
    }

    for (const auto& section : sections) {
        const std::uint32_t section_size = std::max(section.virtual_size, section.size_of_raw_data);
        if (rva >= section.virtual_address && rva < section.virtual_address + section_size) {
            return static_cast<std::size_t>(section.pointer_to_raw_data + (rva - section.virtual_address));
        }
    }

    return std::nullopt;
}

bool contains_file_range(
    const std::vector<std::byte>& bytes,
    const std::uint64_t offset,
    const std::uint64_t size
) {
    return offset <= bytes.size() && size <= bytes.size() - offset;
}

std::optional<std::uint64_t> macho_file_offset_to_virtual_address(
    const std::uint64_t file_offset,
    const std::vector<MachOSegmentCommand64>& segments
) {
    for (const auto& segment : segments) {
        if (segment.file_size == 0) {
            continue;
        }
        if (file_offset >= segment.file_offset && file_offset < segment.file_offset + segment.file_size) {
            return segment.virtual_address + (file_offset - segment.file_offset);
        }
    }
    return std::nullopt;
}

std::optional<std::string> read_macho_command_string(
    const std::span<const std::byte> bytes,
    const std::size_t command_offset,
    const std::uint32_t command_size,
    const std::uint32_t string_offset
) {
    if (string_offset >= command_size) {
        return std::nullopt;
    }
    return read_null_terminated_string(bytes, command_offset + string_offset);
}

std::optional<std::string> read_pe_string(
    const std::span<const std::byte> bytes,
    const std::uint32_t rva,
    const std::vector<PeSectionHeader>& sections,
    const std::size_t size_of_headers
) {
    const auto offset = pe_rva_to_file_offset(rva, sections, size_of_headers);
    if (!offset.has_value()) {
        return std::nullopt;
    }

    return read_null_terminated_string(bytes, *offset);
}

bool validate_limit(
    const std::size_t value,
    const std::size_t limit,
    const std::string_view label,
    std::string& out_error
) {
    if (value <= limit) {
        return true;
    }

    out_error = std::string(label) + " exceeds the configured parse limit.";
    return false;
}

bool validate_string_length(
    const std::string_view value,
    const std::size_t limit,
    const std::string_view label,
    std::string& out_error
) {
    if (value.size() <= limit) {
        return true;
    }

    out_error = std::string(label) + " exceeds the configured parse limit.";
    return false;
}

bool validate_multiple(
    const std::size_t size,
    const std::size_t entry_size,
    const bool strict_validation,
    const std::string_view label,
    std::string& out_error
) {
    if (!strict_validation || entry_size == 0 || (size % entry_size) == 0) {
        return true;
    }

    out_error = std::string(label) + " size is not aligned to the entry size.";
    return false;
}

bool account_mapped_bytes(
    const std::size_t section_size,
    std::size_t& total_mapped_bytes,
    const ParsePolicy& policy,
    const std::string_view label,
    std::string& out_error
) {
    if (!validate_limit(section_size, policy.max_mapped_section_size, label, out_error)) {
        return false;
    }

    if (section_size > policy.max_total_mapped_bytes ||
        total_mapped_bytes > policy.max_total_mapped_bytes - section_size) {
        out_error = "Mapped section bytes exceed the configured parse limit.";
        return false;
    }

    total_mapped_bytes += section_size;
    return true;
}

bool push_import(
    std::vector<ImportedSymbol>& imports,
    ImportedSymbol symbol,
    const ParsePolicy& policy,
    std::string& out_error
) {
    if (imports.size() >= policy.max_import_count) {
        out_error = "Import count exceeds the configured parse limit.";
        return false;
    }
    if (!validate_string_length(symbol.library, policy.max_symbol_name_length, "Import library name", out_error) ||
        !validate_string_length(symbol.name, policy.max_symbol_name_length, "Import symbol name", out_error)) {
        return false;
    }

    imports.push_back(std::move(symbol));
    return true;
}

bool push_export(
    std::vector<ExportedSymbol>& exports,
    ExportedSymbol symbol,
    const ParsePolicy& policy,
    std::string& out_error
) {
    if (exports.size() >= policy.max_export_count) {
        out_error = "Export count exceeds the configured parse limit.";
        return false;
    }
    if (!validate_string_length(symbol.name, policy.max_symbol_name_length, "Export symbol name", out_error)) {
        return false;
    }

    exports.push_back(std::move(symbol));
    return true;
}

bool push_relocation(
    std::vector<RelocationPatch>& relocations,
    RelocationPatch patch,
    const ParsePolicy& policy,
    std::string& out_error
) {
    if (relocations.size() >= policy.max_relocation_count) {
        out_error = "Relocation count exceeds the configured parse limit.";
        return false;
    }

    relocations.push_back(patch);
    return true;
}

bool validate_image_metadata_names(const BinaryImage& image, const ParsePolicy& policy, std::string& out_error) {
    if (!validate_string_length(image.source_path().string(), policy.max_path_length, "Input path", out_error)) {
        return false;
    }

    for (const auto& section : image.sections()) {
        if (!validate_string_length(section.name, policy.max_section_name_length, "Section name", out_error)) {
            return false;
        }
    }
    for (const auto& imported : image.imports()) {
        if (!validate_string_length(imported.library, policy.max_symbol_name_length, "Import library name", out_error) ||
            !validate_string_length(imported.name, policy.max_symbol_name_length, "Import symbol name", out_error)) {
            return false;
        }
    }
    for (const auto& exported : image.exports()) {
        if (!validate_string_length(exported.name, policy.max_symbol_name_length, "Export symbol name", out_error)) {
            return false;
        }
    }
    return true;
}

void populate_raw_image(
    BinaryImage& image,
    const std::filesystem::path& path,
    const std::vector<std::byte>& bytes,
    const LoadOptions& options
) {
    image.source_path_ = path;
    image.format_ = BinaryFormat::Raw;
    image.architecture_ = Architecture::Unknown;
    image.base_address_ = options.base_address;
    image.preferred_load_address_ = options.base_address;
    image.entry_point_.reset();
    image.raw_image_ = bytes;
    image.sections_.push_back(
        Section{
            .name = ".raw",
            .virtual_address = options.base_address,
            .file_offset = 0,
            .bytes = image.raw_image_,
            .readable = true,
            .writable = false,
            .executable = true,
        }
    );
}

bool parse_elf64(
    const std::filesystem::path& path,
    const std::vector<std::byte>& bytes,
    BinaryImage& out_image,
    std::string& out_error,
    const LoadOptions& options
) {
    const std::span<const std::byte> view(bytes.data(), bytes.size());
    const ParsePolicy& policy = options.policy;

    Elf64Header header{};
    if (!read_object(view, 0, header)) {
        out_error = "ELF header is truncated.";
        return false;
    }

    if (header.ident[4] != kElfClass64 || header.ident[5] != kElfDataLittleEndian) {
        out_error = "Only ELF64 little-endian binaries are supported right now.";
        return false;
    }

    if (!validate_limit(header.section_header_count, policy.max_section_count, "ELF section count", out_error) ||
        !validate_limit(header.program_header_count, policy.max_program_header_count, "ELF program header count", out_error)) {
        return false;
    }

    if (header.section_header_entry_size != sizeof(Elf64SectionHeader)) {
        out_error = "Unsupported ELF section header size.";
        return false;
    }

    if (header.program_header_count > 0 && header.program_header_entry_size != sizeof(Elf64ProgramHeader)) {
        out_error = "Unsupported ELF program header size.";
        return false;
    }

    const std::uint64_t section_table_size =
        static_cast<std::uint64_t>(header.section_header_entry_size) * header.section_header_count;
    if (header.section_header_offset > bytes.size() || section_table_size > bytes.size() - header.section_header_offset) {
        out_error = "ELF section table is out of bounds.";
        return false;
    }

    if (header.section_name_string_table_index >= header.section_header_count) {
        out_error = "ELF section name string table index is invalid.";
        return false;
    }

    if (header.program_header_count > 0) {
        const std::uint64_t program_header_table_size =
            static_cast<std::uint64_t>(header.program_header_entry_size) * header.program_header_count;
        if (header.program_header_offset > bytes.size() ||
            program_header_table_size > bytes.size() - header.program_header_offset) {
            out_error = "ELF program header table is out of bounds.";
            return false;
        }
    }

    Elf64SectionHeader string_table_header{};
    const auto string_table_header_offset =
        header.section_header_offset +
        (static_cast<std::uint64_t>(header.section_name_string_table_index) * sizeof(Elf64SectionHeader));
    if (!read_object(view, static_cast<std::size_t>(string_table_header_offset), string_table_header)) {
        out_error = "Failed to read ELF section name string table header.";
        return false;
    }

    if (string_table_header.offset > bytes.size() || string_table_header.size > bytes.size() - string_table_header.offset) {
        out_error = "ELF section name string table is out of bounds.";
        return false;
    }

    if (!validate_limit(
            static_cast<std::size_t>(string_table_header.size),
            policy.max_string_table_size,
            "ELF section name string table",
            out_error
        )) {
        return false;
    }

    const auto string_table = view.subspan(
        static_cast<std::size_t>(string_table_header.offset),
        static_cast<std::size_t>(string_table_header.size)
    );

    std::vector<ParsedElfSection> parsed_sections;
    parsed_sections.reserve(header.section_header_count);
    for (std::uint16_t index = 0; index < header.section_header_count; ++index) {
        Elf64SectionHeader section_header{};
        const auto section_header_offset =
            header.section_header_offset + (static_cast<std::uint64_t>(index) * sizeof(Elf64SectionHeader));
        if (!read_object(view, static_cast<std::size_t>(section_header_offset), section_header)) {
            out_error = "Failed to read ELF section header.";
            return false;
        }

        parsed_sections.push_back(
            ParsedElfSection{
                .header = section_header,
                .name = read_null_terminated_string(string_table, section_header.name_offset),
            }
        );
    }

    BinaryImage image;
    image.source_path_ = path;
    image.format_ = BinaryFormat::ELF;
    image.architecture_ = architecture_from_elf_machine(header.machine);
    image.base_address_ = std::numeric_limits<std::uint64_t>::max();
    image.entry_point_ = header.entry;
    image.raw_image_ = bytes;
    std::size_t total_mapped_bytes = 0;

    for (std::uint16_t index = 0; index < header.program_header_count; ++index) {
        Elf64ProgramHeader program_header{};
        const auto program_header_offset =
            header.program_header_offset + (static_cast<std::uint64_t>(index) * sizeof(Elf64ProgramHeader));
        if (!read_object(view, static_cast<std::size_t>(program_header_offset), program_header)) {
            out_error = "Failed to read ELF program header.";
            return false;
        }

        if (program_header.type == kElfProgramHeaderTypeLoad) {
            image.base_address_ = std::min(image.base_address_, program_header.virtual_address);
        }
    }

    for (const auto& parsed_section : parsed_sections) {
        const Elf64SectionHeader& section_header = parsed_section.header;
        if ((section_header.flags & kElfSectionFlagAlloc) == 0 || section_header.size == 0) {
            continue;
        }

        std::vector<std::byte> section_bytes;
        if (section_header.type == kElfSectionTypeNoBits) {
            const auto section_size = static_cast<std::size_t>(section_header.size);
            if (!account_mapped_bytes(section_size, total_mapped_bytes, policy, "ELF section", out_error)) {
                return false;
            }
            section_bytes.resize(section_size, std::byte{0});
        } else {
            if (section_header.offset > bytes.size() || section_header.size > bytes.size() - section_header.offset) {
                out_error = "ELF section contents are out of bounds.";
                return false;
            }

            const auto section_size = static_cast<std::size_t>(section_header.size);
            if (!account_mapped_bytes(section_size, total_mapped_bytes, policy, "ELF section", out_error)) {
                return false;
            }

            section_bytes.assign(
                bytes.begin() + static_cast<std::ptrdiff_t>(section_header.offset),
                bytes.begin() + static_cast<std::ptrdiff_t>(section_header.offset + section_header.size)
            );
        }

        image.sections_.push_back(
            Section{
                .name = parsed_section.name,
                .virtual_address = section_header.address,
                .file_offset = section_header.type == kElfSectionTypeNoBits ? 0 : section_header.offset,
                .bytes = std::move(section_bytes),
                .readable = true,
                .writable = (section_header.flags & kElfSectionFlagWrite) != 0,
                .executable = (section_header.flags & kElfSectionFlagExecute) != 0,
            }
        );
    }

    std::unordered_map<std::size_t, std::vector<ParsedElfSymbol>> symbol_tables;
    for (std::size_t section_index = 0; section_index < parsed_sections.size(); ++section_index) {
        const ParsedElfSection& parsed_section = parsed_sections[section_index];
        if (parsed_section.header.type != kElfSectionTypeDynSym || parsed_section.header.size == 0) {
            continue;
        }

        const std::size_t entry_size =
            parsed_section.header.entry_size == 0 ? sizeof(Elf64Symbol) : static_cast<std::size_t>(parsed_section.header.entry_size);
        if (entry_size != sizeof(Elf64Symbol)) {
            out_error = "Unsupported ELF symbol entry size.";
            return false;
        }

        if (parsed_section.header.link >= parsed_sections.size()) {
            out_error = "ELF symbol table references an invalid string table.";
            return false;
        }

        const ParsedElfSection& string_section = parsed_sections[parsed_section.header.link];
        if (string_section.header.offset > bytes.size() ||
            string_section.header.size > bytes.size() - string_section.header.offset) {
            out_error = "ELF symbol string table is out of bounds.";
            return false;
        }

        if (!validate_limit(
                static_cast<std::size_t>(string_section.header.size),
                policy.max_string_table_size,
                "ELF symbol string table",
                out_error
            )) {
            return false;
        }

        const auto symbol_string_table = view.subspan(
            static_cast<std::size_t>(string_section.header.offset),
            static_cast<std::size_t>(string_section.header.size)
        );

        if (parsed_section.header.offset > bytes.size() ||
            parsed_section.header.size > bytes.size() - parsed_section.header.offset) {
            out_error = "ELF symbol table is out of bounds.";
            return false;
        }

        if (!validate_multiple(
                static_cast<std::size_t>(parsed_section.header.size),
                entry_size,
                policy.strict_validation,
                "ELF symbol table",
                out_error
            )) {
            return false;
        }
        const std::size_t symbol_count = static_cast<std::size_t>(parsed_section.header.size / entry_size);
        if (!validate_limit(symbol_count, policy.max_symbol_count, "ELF symbol count", out_error)) {
            return false;
        }
        std::vector<ParsedElfSymbol> symbols;
        symbols.reserve(symbol_count);

        for (std::size_t symbol_index = 0; symbol_index < symbol_count; ++symbol_index) {
            Elf64Symbol symbol{};
            if (!read_object(
                    view,
                    static_cast<std::size_t>(parsed_section.header.offset) + (symbol_index * entry_size),
                    symbol
                )) {
                out_error = "Failed to read ELF symbol.";
                return false;
            }

            const std::string symbol_name = read_null_terminated_string(symbol_string_table, symbol.name_offset);
            symbols.push_back(
                ParsedElfSymbol{
                    .name = symbol_name,
                    .section_index = symbol.section_index,
                    .value = symbol.value,
                    .size = symbol.size,
                    .binding = static_cast<std::uint8_t>(symbol.info >> 4),
                }
            );

            if (symbol_name.empty() ||
                symbol.section_index == kElfSectionIndexUndefined ||
                !is_global_or_weak_symbol(symbol.info)) {
                continue;
            }

            if (!push_export(
                    image.exports_,
                    ExportedSymbol{
                        .name = symbol_name,
                        .address = symbol.value,
                        .size = symbol.size,
                    },
                    policy,
                    out_error
                )) {
                return false;
            }
        }

        symbol_tables.emplace(section_index, std::move(symbols));
    }

    for (const auto& parsed_section : parsed_sections) {
        if ((parsed_section.header.type != kElfSectionTypeRela &&
             parsed_section.header.type != kElfSectionTypeRel) ||
            parsed_section.header.size == 0) {
            continue;
        }

        const bool is_rela = parsed_section.header.type == kElfSectionTypeRela;
        const std::size_t default_entry_size = is_rela ? sizeof(Elf64Rela) : sizeof(Elf64Rel);
        const std::size_t entry_size =
            parsed_section.header.entry_size == 0 ? default_entry_size
                                                  : static_cast<std::size_t>(parsed_section.header.entry_size);
        if (entry_size != default_entry_size) {
            continue;
        }

        if (parsed_section.header.offset > bytes.size() ||
            parsed_section.header.size > bytes.size() - parsed_section.header.offset) {
            out_error = "ELF relocation table is out of bounds.";
            return false;
        }

        if (!validate_multiple(
                static_cast<std::size_t>(parsed_section.header.size),
                entry_size,
                policy.strict_validation,
                "ELF relocation table",
                out_error
            )) {
            return false;
        }
        const std::size_t relocation_count = static_cast<std::size_t>(parsed_section.header.size / entry_size);
        if (!validate_limit(relocation_count, policy.max_relocation_count, "ELF relocation count", out_error)) {
            return false;
        }
        for (std::size_t relocation_index = 0; relocation_index < relocation_count; ++relocation_index) {
            std::uint64_t relocation_offset = 0;
            std::uint64_t relocation_info = 0;
            if (is_rela) {
                Elf64Rela relocation{};
                if (!read_object(
                        view,
                        static_cast<std::size_t>(parsed_section.header.offset) + (relocation_index * entry_size),
                        relocation
                    )) {
                    out_error = "Failed to read ELF relocation entry.";
                    return false;
                }

                relocation_offset = relocation.offset;
                relocation_info = relocation.info;
            } else {
                Elf64Rel relocation{};
                if (!read_object(
                        view,
                        static_cast<std::size_t>(parsed_section.header.offset) + (relocation_index * entry_size),
                        relocation
                    )) {
                    out_error = "Failed to read ELF relocation entry.";
                    return false;
                }

                relocation_offset = relocation.offset;
                relocation_info = relocation.info;
            }

            const auto relocation_type = static_cast<std::uint32_t>(relocation_info & 0xFFFFFFFFU);
            const bool is_relative_relocation =
                (image.architecture_ == Architecture::X86 && relocation_type == kElfRelocationType386Relative) ||
                (image.architecture_ == Architecture::X86_64 && relocation_type == kElfRelocationTypeX86_64Relative) ||
                (image.architecture_ == Architecture::ARM64 && relocation_type == kElfRelocationTypeArm64Relative);
            if (is_relative_relocation) {
                if (!push_relocation(
                        image.relocations_,
                        RelocationPatch{
                            .address = relocation_offset,
                            .width = 8,
                        },
                        policy,
                        out_error
                    )) {
                    return false;
                }
            }

            const auto symbol_table_it = symbol_tables.find(parsed_section.header.link);
            if (symbol_table_it == symbol_tables.end()) {
                continue;
            }

            const std::vector<ParsedElfSymbol>& symbols = symbol_table_it->second;
            const std::size_t symbol_index = static_cast<std::size_t>(relocation_info >> 32U);
            if (symbol_index >= symbols.size()) {
                continue;
            }

            const ParsedElfSymbol& symbol = symbols[symbol_index];
            if (symbol.section_index != kElfSectionIndexUndefined || symbol.name.empty()) {
                continue;
            }

            if (!push_import(
                    image.imports_,
                    ImportedSymbol{
                        .library = {},
                        .name = symbol.name,
                        .address = relocation_offset,
                    },
                    policy,
                    out_error
                )) {
                return false;
            }
        }
    }

    if (image.sections_.empty()) {
        out_error = "ELF file did not expose any allocatable sections.";
        return false;
    }

    if (image.base_address_ == std::numeric_limits<std::uint64_t>::max()) {
        for (const auto& section : image.sections_) {
            image.base_address_ = std::min(image.base_address_, section.virtual_address);
        }
    }

    if (image.base_address_ == std::numeric_limits<std::uint64_t>::max()) {
        image.base_address_ = 0;
    }

    image.preferred_load_address_ = image.base_address_;

    if (header.type == kElfTypeSharedObject) {
        image.base_address_ = 0;
    }

    deduplicate_imports(image.imports_);
    deduplicate_exports(image.exports_);
    deduplicate_relocations(image.relocations_);

    out_image = std::move(image);
    return true;
}

bool parse_pe(
    const std::filesystem::path& path,
    const std::vector<std::byte>& bytes,
    BinaryImage& out_image,
    std::string& out_error,
    const LoadOptions& options
) {
    const std::span<const std::byte> view(bytes.data(), bytes.size());
    const ParsePolicy& policy = options.policy;

    PeDosHeader dos_header{};
    if (!read_object(view, 0, dos_header)) {
        out_error = "DOS header is truncated.";
        return false;
    }

    const std::size_t pe_offset = dos_header.pe_offset;
    if (pe_offset > bytes.size() || bytes.size() - pe_offset < kPESignature.size() + sizeof(PeFileHeader)) {
        out_error = "PE header is out of bounds.";
        return false;
    }

    if (!has_prefix(view.subspan(pe_offset), std::span<const unsigned char>(kPESignature))) {
        out_error = "PE signature is invalid.";
        return false;
    }

    PeFileHeader file_header{};
    if (!read_object(view, pe_offset + kPESignature.size(), file_header)) {
        out_error = "PE file header is truncated.";
        return false;
    }

    if (!validate_limit(file_header.section_count, policy.max_section_count, "PE section count", out_error)) {
        return false;
    }

    const std::size_t optional_header_offset = pe_offset + kPESignature.size() + sizeof(PeFileHeader);
    if (optional_header_offset > bytes.size() || file_header.optional_header_size > bytes.size() - optional_header_offset) {
        out_error = "PE optional header is out of bounds.";
        return false;
    }

    const auto optional_magic = read_scalar<std::uint16_t>(view, optional_header_offset);
    const auto entry_point_rva = read_scalar<std::uint32_t>(view, optional_header_offset + 16);
    if (!optional_magic.has_value() || !entry_point_rva.has_value()) {
        out_error = "PE optional header is truncated.";
        return false;
    }

    std::uint64_t image_base = 0;
    std::uint32_t size_of_headers = 0;
    std::uint32_t number_of_rva_and_sizes = 0;
    std::size_t data_directory_offset = 0;
    std::size_t thunk_entry_size = 0;
    if (*optional_magic == kPeOptionalHeader32Magic) {
        const auto value = read_scalar<std::uint32_t>(view, optional_header_offset + 28);
        const auto headers_value = read_scalar<std::uint32_t>(view, optional_header_offset + 60);
        const auto directory_count = read_scalar<std::uint32_t>(view, optional_header_offset + 92);
        if (!value.has_value() || !headers_value.has_value() || !directory_count.has_value()) {
            out_error = "PE32 optional header is truncated.";
            return false;
        }

        image_base = *value;
        size_of_headers = *headers_value;
        number_of_rva_and_sizes = *directory_count;
        data_directory_offset = optional_header_offset + 96;
        thunk_entry_size = sizeof(std::uint32_t);
    } else if (*optional_magic == kPeOptionalHeader64Magic) {
        const auto value = read_scalar<std::uint64_t>(view, optional_header_offset + 24);
        const auto headers_value = read_scalar<std::uint32_t>(view, optional_header_offset + 60);
        const auto directory_count = read_scalar<std::uint32_t>(view, optional_header_offset + 108);
        if (!value.has_value() || !headers_value.has_value() || !directory_count.has_value()) {
            out_error = "PE32+ optional header is truncated.";
            return false;
        }

        image_base = *value;
        size_of_headers = *headers_value;
        number_of_rva_and_sizes = *directory_count;
        data_directory_offset = optional_header_offset + 112;
        thunk_entry_size = sizeof(std::uint64_t);
    } else {
        out_error = "Unsupported PE optional header format.";
        return false;
    }

    const std::size_t section_table_offset = optional_header_offset + file_header.optional_header_size;
    const std::uint64_t section_table_size = static_cast<std::uint64_t>(file_header.section_count) * sizeof(PeSectionHeader);
    if (section_table_offset > bytes.size() || section_table_size > bytes.size() - section_table_offset) {
        out_error = "PE section table is out of bounds.";
        return false;
    }

    std::vector<PeSectionHeader> parsed_sections;
    parsed_sections.reserve(file_header.section_count);
    for (std::uint16_t index = 0; index < file_header.section_count; ++index) {
        PeSectionHeader section_header{};
        const auto header_offset = section_table_offset + (static_cast<std::size_t>(index) * sizeof(PeSectionHeader));
        if (!read_object(view, header_offset, section_header)) {
            out_error = "Failed to read PE section header.";
            return false;
        }

        parsed_sections.push_back(section_header);
    }

    auto read_data_directory = [&](const std::uint32_t directory_index) -> std::optional<PeDataDirectory> {
        if (directory_index >= number_of_rva_and_sizes) {
            return std::nullopt;
        }

        const std::size_t directory_offset =
            data_directory_offset + (static_cast<std::size_t>(directory_index) * sizeof(PeDataDirectory));
        const std::size_t optional_header_end = optional_header_offset + file_header.optional_header_size;
        if (directory_offset > optional_header_end ||
            sizeof(PeDataDirectory) > optional_header_end - directory_offset) {
            return std::nullopt;
        }

        PeDataDirectory directory{};
        if (!read_object(view, directory_offset, directory)) {
            return std::nullopt;
        }

        return directory;
    };

    BinaryImage image;
    image.source_path_ = path;
    image.format_ = BinaryFormat::PE;
    image.architecture_ = architecture_from_pe_machine(file_header.machine);
    image.base_address_ = image_base;
    image.preferred_load_address_ = image_base;
    image.entry_point_ = image_base + static_cast<std::uint64_t>(*entry_point_rva);
    image.raw_image_ = bytes;
    std::size_t total_mapped_bytes = 0;

    for (const auto& section_header : parsed_sections) {
        const std::size_t mapped_size = std::max(
            static_cast<std::size_t>(section_header.virtual_size),
            static_cast<std::size_t>(section_header.size_of_raw_data)
        );
        if (mapped_size == 0) {
            continue;
        }

        if (!account_mapped_bytes(mapped_size, total_mapped_bytes, policy, "PE section", out_error)) {
            return false;
        }

        std::vector<std::byte> section_bytes(mapped_size, std::byte{0});
        if (section_header.size_of_raw_data > 0) {
            if (section_header.pointer_to_raw_data > bytes.size() ||
                section_header.size_of_raw_data > bytes.size() - section_header.pointer_to_raw_data) {
                out_error = "PE section contents are out of bounds.";
                return false;
            }

            std::copy_n(
                bytes.begin() + static_cast<std::ptrdiff_t>(section_header.pointer_to_raw_data),
                static_cast<std::ptrdiff_t>(section_header.size_of_raw_data),
                section_bytes.begin()
            );
        }

        image.sections_.push_back(
            Section{
                .name = trim_pe_section_name(section_header.name),
                .virtual_address = image_base + static_cast<std::uint64_t>(section_header.virtual_address),
                .file_offset = section_header.pointer_to_raw_data,
                .bytes = std::move(section_bytes),
                .readable = (section_header.characteristics & kPeSectionMemoryRead) != 0 ||
                            (section_header.characteristics & kPeSectionContainsCode) != 0,
                .writable = (section_header.characteristics & kPeSectionMemoryWrite) != 0,
                .executable = (section_header.characteristics & kPeSectionMemoryExecute) != 0 ||
                              (section_header.characteristics & kPeSectionContainsCode) != 0,
            }
        );
    }

        if (const auto import_directory = read_data_directory(kPeDataDirectoryImport);
        import_directory.has_value() && import_directory->virtual_address != 0 && import_directory->size != 0) {
        const auto descriptor_table_offset = pe_rva_to_file_offset(
            import_directory->virtual_address,
            parsed_sections,
            size_of_headers
        );
        if (!descriptor_table_offset.has_value()) {
            out_error = "PE import directory is out of bounds.";
            return false;
        }

        for (std::size_t descriptor_index = 0;; ++descriptor_index) {
            if (descriptor_index >= policy.max_import_count) {
                out_error = "PE import descriptor count exceeds the configured parse limit.";
                return false;
            }

            const std::size_t descriptor_offset =
                *descriptor_table_offset + (descriptor_index * sizeof(PeImportDescriptor));
            PeImportDescriptor descriptor{};
            if (!read_object(view, descriptor_offset, descriptor)) {
                out_error = "PE import descriptor is truncated.";
                return false;
            }

            if (descriptor.original_first_thunk == 0 &&
                descriptor.time_date_stamp == 0 &&
                descriptor.forwarder_chain == 0 &&
                descriptor.name_rva == 0 &&
                descriptor.first_thunk == 0) {
                break;
            }

            const auto library_name = read_pe_string(view, descriptor.name_rva, parsed_sections, size_of_headers);
            if (!library_name.has_value()) {
                out_error = "PE import library name is out of bounds.";
                return false;
            }

            const std::uint32_t lookup_table_rva =
                descriptor.original_first_thunk != 0 ? descriptor.original_first_thunk : descriptor.first_thunk;
            const auto lookup_table_offset = pe_rva_to_file_offset(lookup_table_rva, parsed_sections, size_of_headers);
            if (!lookup_table_offset.has_value()) {
                out_error = "PE import thunk table is out of bounds.";
                return false;
            }

            for (std::size_t thunk_index = 0;; ++thunk_index) {
                const std::size_t thunk_offset = *lookup_table_offset + (thunk_index * thunk_entry_size);
                std::uint64_t thunk_value = 0;
                if (thunk_entry_size == sizeof(std::uint64_t)) {
                    const auto value = read_scalar<std::uint64_t>(view, thunk_offset);
                    if (!value.has_value()) {
                        out_error = "PE import thunk entry is truncated.";
                        return false;
                    }

                    thunk_value = *value;
                } else {
                    const auto value = read_scalar<std::uint32_t>(view, thunk_offset);
                    if (!value.has_value()) {
                        out_error = "PE import thunk entry is truncated.";
                        return false;
                    }

                    thunk_value = *value;
                }

                if (thunk_value == 0) {
                    break;
                }

                std::string import_name;
                if ((thunk_entry_size == sizeof(std::uint64_t) &&
                     (thunk_value & 0x8000000000000000ULL) != 0) ||
                    (thunk_entry_size == sizeof(std::uint32_t) &&
                     (thunk_value & 0x80000000ULL) != 0)) {
                    import_name = "ordinal_" + std::to_string(static_cast<std::uint16_t>(thunk_value & 0xFFFFU));
                } else {
                    const auto name_table_offset = pe_rva_to_file_offset(
                        static_cast<std::uint32_t>(thunk_value),
                        parsed_sections,
                        size_of_headers
                    );
                    if (!name_table_offset.has_value() || *name_table_offset + 2 > bytes.size()) {
                        out_error = "PE import name table is out of bounds.";
                        return false;
                    }

                    import_name = read_null_terminated_string(view, *name_table_offset + 2);
                    if (import_name.empty()) {
                        out_error = "PE import name is empty or truncated.";
                        return false;
                    }
                }

                if (!push_import(
                        image.imports_,
                        ImportedSymbol{
                            .library = *library_name,
                            .name = import_name,
                            .address = image_base + descriptor.first_thunk + (thunk_index * thunk_entry_size),
                        },
                        policy,
                        out_error
                    )) {
                    return false;
                }
            }
        }
    }

    if (const auto export_directory = read_data_directory(kPeDataDirectoryExport);
        export_directory.has_value() && export_directory->virtual_address != 0 && export_directory->size != 0) {
        const auto export_table_offset = pe_rva_to_file_offset(
            export_directory->virtual_address,
            parsed_sections,
            size_of_headers
        );
        if (!export_table_offset.has_value()) {
            out_error = "PE export directory is out of bounds.";
            return false;
        }

        PeExportDirectory directory{};
        if (!read_object(view, *export_table_offset, directory)) {
            out_error = "PE export directory is truncated.";
            return false;
        }

        const auto functions_offset = pe_rva_to_file_offset(
            directory.address_of_functions,
            parsed_sections,
            size_of_headers
        );
        if (!functions_offset.has_value()) {
            out_error = "PE export address table is out of bounds.";
            return false;
        }

        if (!validate_limit(directory.number_of_functions, policy.max_export_count, "PE export count", out_error) ||
            !validate_limit(directory.number_of_names, policy.max_export_count, "PE export name count", out_error)) {
            return false;
        }

        std::vector<std::optional<std::string>> names_by_ordinal(directory.number_of_functions);
        if (directory.number_of_names > 0) {
            const auto names_offset = pe_rva_to_file_offset(
                directory.address_of_names,
                parsed_sections,
                size_of_headers
            );
            const auto ordinals_offset = pe_rva_to_file_offset(
                directory.address_of_name_ordinals,
                parsed_sections,
                size_of_headers
            );
            if (!names_offset.has_value() || !ordinals_offset.has_value()) {
                out_error = "PE export name tables are out of bounds.";
                return false;
            }

            for (std::uint32_t name_index = 0; name_index < directory.number_of_names; ++name_index) {
                const auto name_rva = read_scalar<std::uint32_t>(view, *names_offset + (name_index * sizeof(std::uint32_t)));
                const auto ordinal = read_scalar<std::uint16_t>(view, *ordinals_offset + (name_index * sizeof(std::uint16_t)));
                if (!name_rva.has_value() || !ordinal.has_value()) {
                    out_error = "PE export name table is truncated.";
                    return false;
                }

                if (*ordinal >= directory.number_of_functions) {
                    continue;
                }

                const auto export_name = read_pe_string(view, *name_rva, parsed_sections, size_of_headers);
                if (!export_name.has_value() || export_name->empty()) {
                    out_error = "PE export name is out of bounds.";
                    return false;
                }

                names_by_ordinal[*ordinal] = *export_name;
            }
        }

        for (std::uint32_t function_index = 0; function_index < directory.number_of_functions; ++function_index) {
            const auto function_rva = read_scalar<std::uint32_t>(
                view,
                *functions_offset + (function_index * sizeof(std::uint32_t))
            );
            if (!function_rva.has_value()) {
                out_error = "PE export address table is truncated.";
                return false;
            }

            if (*function_rva == 0) {
                continue;
            }

            if (!push_export(
                    image.exports_,
                    ExportedSymbol{
                        .name = names_by_ordinal[function_index].value_or(
                            "ordinal_" + std::to_string(directory.base + function_index)
                        ),
                        .address = image_base + *function_rva,
                        .size = 0,
                    },
                    policy,
                    out_error
                )) {
                return false;
            }
        }
    }

    if (const auto relocation_directory = read_data_directory(kPeDataDirectoryBaseRelocation);
        relocation_directory.has_value() && relocation_directory->virtual_address != 0 && relocation_directory->size != 0) {
        const auto relocation_table_offset = pe_rva_to_file_offset(
            relocation_directory->virtual_address,
            parsed_sections,
            size_of_headers
        );
        if (!relocation_table_offset.has_value()) {
            out_error = "PE base relocation table is out of bounds.";
            return false;
        }

        const std::size_t relocation_table_end =
            *relocation_table_offset + static_cast<std::size_t>(relocation_directory->size);
        if (relocation_table_end > bytes.size()) {
            out_error = "PE base relocation table is truncated.";
            return false;
        }

        std::size_t cursor = *relocation_table_offset;
        while (cursor + sizeof(PeBaseRelocationBlock) <= relocation_table_end) {
            PeBaseRelocationBlock block{};
            if (!read_object(view, cursor, block)) {
                out_error = "Failed to read PE base relocation block.";
                return false;
            }

            if (block.block_size < sizeof(PeBaseRelocationBlock)) {
                out_error = "PE base relocation block size is invalid.";
                return false;
            }

            const std::size_t block_end = cursor + static_cast<std::size_t>(block.block_size);
            if (block_end > relocation_table_end) {
                out_error = "PE base relocation block is out of bounds.";
                return false;
            }

            const std::size_t entry_count =
                (static_cast<std::size_t>(block.block_size) - sizeof(PeBaseRelocationBlock)) / sizeof(std::uint16_t);
            for (std::size_t entry_index = 0; entry_index < entry_count; ++entry_index) {
                const auto raw_entry = read_scalar<std::uint16_t>(
                    view,
                    cursor + sizeof(PeBaseRelocationBlock) + (entry_index * sizeof(std::uint16_t))
                );
                if (!raw_entry.has_value()) {
                    out_error = "PE base relocation entry is truncated.";
                    return false;
                }

                const std::uint16_t type = static_cast<std::uint16_t>(*raw_entry >> 12U);
                const std::uint16_t offset_in_page = static_cast<std::uint16_t>(*raw_entry & 0x0FFFU);
                if (type == kPeRelocationAbsolute) {
                    continue;
                }

                if (type != kPeRelocationHighLow && type != kPeRelocationDir64) {
                    continue;
                }

                if (!push_relocation(
                        image.relocations_,
                        RelocationPatch{
                            .address = image_base + static_cast<std::uint64_t>(block.page_rva) + offset_in_page,
                            .width = static_cast<std::uint8_t>(type == kPeRelocationDir64 ? 8 : 4),
                        },
                        policy,
                        out_error
                    )) {
                    return false;
                }
            }

            cursor = block_end;
        }
    }

    if (image.sections_.empty()) {
        out_error = "PE file did not expose any mapped sections.";
        return false;
    }

    deduplicate_imports(image.imports_);
    deduplicate_exports(image.exports_);
    deduplicate_relocations(image.relocations_);

    out_image = std::move(image);
    return true;
}

bool parse_macho(
    const std::filesystem::path& path,
    const std::vector<std::byte>& bytes,
    BinaryImage& out_image,
    std::string& out_error,
    const LoadOptions& options
) {
    const std::span<const std::byte> view(bytes.data(), bytes.size());
    const ParsePolicy& policy = options.policy;

    MachOHeader64 header{};
    if (!read_object(view, 0, header)) {
        out_error = "Mach-O header is truncated.";
        return false;
    }

    if (header.magic != 0xFEEDFACFU) {
        out_error = "Only 64-bit little-endian Mach-O binaries are supported right now.";
        return false;
    }

    if (!validate_limit(header.command_count, policy.max_macho_load_commands, "Mach-O load command count", out_error) ||
        !validate_limit(header.commands_size, policy.max_string_table_size, "Mach-O load command bytes", out_error)) {
        return false;
    }

    const std::size_t commands_offset = sizeof(MachOHeader64);
    if (!contains_file_range(bytes, commands_offset, header.commands_size)) {
        out_error = "Mach-O load commands are out of bounds.";
        return false;
    }

    std::vector<MachOSegmentCommand64> segments;
    std::vector<ParsedMachOSection> parsed_sections;
    std::vector<std::string> dylibs;
    std::optional<MachOSymtabCommand> symtab_command;
    std::optional<MachODysymtabCommand> dysymtab_command;
    std::optional<MachOMainCommand> main_command;
    std::optional<MachOLinkeditDataCommand> chained_fixups_command;

    std::size_t command_offset = commands_offset;
    std::size_t parsed_section_count = 0;
    for (std::uint32_t command_index = 0; command_index < header.command_count; ++command_index) {
        MachOLoadCommand load_command{};
        if (!read_object(view, command_offset, load_command)) {
            out_error = "Mach-O load command is truncated.";
            return false;
        }

        if (load_command.command_size < sizeof(MachOLoadCommand) ||
            !contains_file_range(bytes, command_offset, load_command.command_size)) {
            out_error = "Mach-O load command is out of bounds.";
            return false;
        }

        switch (load_command.command) {
        case kMachOLoadCommandSegment64: {
            MachOSegmentCommand64 segment{};
            if (!read_object(view, command_offset, segment)) {
                out_error = "Mach-O segment command is truncated.";
                return false;
            }

            if (segment.command_size < sizeof(MachOSegmentCommand64) ||
                segment.command_size <
                    sizeof(MachOSegmentCommand64) + (static_cast<std::uint64_t>(segment.section_count) * sizeof(MachOSection64))) {
                out_error = "Mach-O segment command size is invalid.";
                return false;
            }

            if (!validate_limit(
                    parsed_section_count + segment.section_count,
                    policy.max_section_count,
                    "Mach-O section count",
                    out_error
                )) {
                return false;
            }

            segments.push_back(segment);
            std::size_t section_offset = command_offset + sizeof(MachOSegmentCommand64);
            for (std::uint32_t section_index = 0; section_index < segment.section_count; ++section_index) {
                MachOSection64 section{};
                if (!read_object(view, section_offset, section)) {
                    out_error = "Mach-O section is truncated.";
                    return false;
                }

                parsed_sections.push_back(
                    ParsedMachOSection{
                        .header = section,
                        .name = trim_macho_name(section.section_name, sizeof(section.section_name)),
                        .segment_name = trim_macho_name(section.segment_name, sizeof(section.segment_name)),
                    }
                );
                section_offset += sizeof(MachOSection64);
                ++parsed_section_count;
            }
            break;
        }
        case kMachOLoadCommandSymtab: {
            MachOSymtabCommand symtab{};
            if (!read_object(view, command_offset, symtab)) {
                out_error = "Mach-O symtab command is truncated.";
                return false;
            }
            symtab_command = symtab;
            break;
        }
        case kMachOLoadCommandDysymtab: {
            MachODysymtabCommand dysymtab{};
            if (!read_object(view, command_offset, dysymtab)) {
                out_error = "Mach-O dysymtab command is truncated.";
                return false;
            }
            dysymtab_command = dysymtab;
            break;
        }
        case kMachOLoadCommandMain: {
            MachOMainCommand main{};
            if (!read_object(view, command_offset, main)) {
                out_error = "Mach-O entry command is truncated.";
                return false;
            }
            main_command = main;
            break;
        }
        case kMachOLoadCommandDyldChainedFixups: {
            MachOLinkeditDataCommand linkedit{};
            if (!read_object(view, command_offset, linkedit)) {
                out_error = "Mach-O chained fixups command is truncated.";
                return false;
            }
            chained_fixups_command = linkedit;
            break;
        }
        case kMachOLoadCommandLoadDylib: {
            MachODylibCommand dylib{};
            if (!read_object(view, command_offset, dylib)) {
                out_error = "Mach-O dylib command is truncated.";
                return false;
            }

            const auto dylib_name = read_macho_command_string(view, command_offset, dylib.command_size, dylib.name_offset);
            if (dylib_name.has_value()) {
                if (!validate_limit(dylibs.size() + 1, policy.max_macho_dylib_count, "Mach-O dylib count", out_error)) {
                    return false;
                }
                dylibs.push_back(*dylib_name);
            }
            break;
        }
        default:
            break;
        }

        command_offset += load_command.command_size;
    }

    BinaryImage image;
    image.source_path_ = path;
    image.format_ = BinaryFormat::MachO;
    image.architecture_ = architecture_from_macho_cpu_type(header.cpu_type);
    image.raw_image_ = bytes;
    std::size_t total_mapped_bytes = 0;

    image.base_address_ = std::numeric_limits<std::uint64_t>::max();
    for (const auto& segment : segments) {
        if (segment.virtual_size == 0) {
            continue;
        }
        image.base_address_ = std::min(image.base_address_, segment.virtual_address);
    }
    if (image.base_address_ == std::numeric_limits<std::uint64_t>::max()) {
        image.base_address_ = options.base_address;
    }
    image.preferred_load_address_ = image.base_address_;

    for (const auto& parsed_section : parsed_sections) {
        const auto segment_it = std::find_if(
            segments.begin(),
            segments.end(),
            [&](const MachOSegmentCommand64& segment) {
                return trim_macho_name(segment.segment_name, sizeof(segment.segment_name)) == parsed_section.segment_name;
            }
        );

        const std::uint32_t protection = segment_it == segments.end() ? 0u : segment_it->initial_protection;
        const auto section_size = static_cast<std::size_t>(parsed_section.header.size);
        if (!account_mapped_bytes(section_size, total_mapped_bytes, policy, "Mach-O section", out_error)) {
            return false;
        }
        std::vector<std::byte> section_bytes(section_size, std::byte{0});
        if (parsed_section.header.offset != 0 && contains_file_range(bytes, parsed_section.header.offset, parsed_section.header.size)) {
            std::copy_n(
                bytes.begin() + static_cast<std::ptrdiff_t>(parsed_section.header.offset),
                static_cast<std::ptrdiff_t>(parsed_section.header.size),
                section_bytes.begin()
            );
        }

        image.sections_.push_back(
            Section{
                .name = parsed_section.segment_name + ":" + parsed_section.name,
                .virtual_address = parsed_section.header.address,
                .file_offset = parsed_section.header.offset,
                .bytes = std::move(section_bytes),
                .readable = (protection & 0x1U) != 0,
                .writable = (protection & 0x2U) != 0,
                .executable = (protection & 0x4U) != 0,
            }
        );
    }

    if (main_command.has_value()) {
        image.entry_point_ = macho_file_offset_to_virtual_address(main_command->entry_offset, segments);
    }

    std::vector<ParsedMachOSymbol> symbols;
    if (symtab_command.has_value()) {
        if (!validate_limit(symtab_command->symbol_count, policy.max_symbol_count, "Mach-O symbol count", out_error) ||
            !validate_limit(symtab_command->string_size, policy.max_string_table_size, "Mach-O string table", out_error)) {
            return false;
        }
        if (!contains_file_range(bytes, symtab_command->symbol_offset, static_cast<std::uint64_t>(symtab_command->symbol_count) * sizeof(MachONList64)) ||
            !contains_file_range(bytes, symtab_command->string_offset, symtab_command->string_size)) {
            out_error = "Mach-O symbol table is out of bounds.";
            return false;
        }

        const auto string_table = view.subspan(symtab_command->string_offset, symtab_command->string_size);
        symbols.reserve(symtab_command->symbol_count);
        for (std::uint32_t symbol_index = 0; symbol_index < symtab_command->symbol_count; ++symbol_index) {
            MachONList64 symbol{};
            if (!read_object(
                    view,
                    symtab_command->symbol_offset + (static_cast<std::size_t>(symbol_index) * sizeof(MachONList64)),
                    symbol
                )) {
                out_error = "Mach-O symbol is truncated.";
                return false;
            }

            const std::string name = read_null_terminated_string(string_table, symbol.string_index);
            symbols.push_back(
                ParsedMachOSymbol{
                    .name = name,
                    .type = symbol.type,
                    .section_index = symbol.section_index,
                    .description = symbol.description,
                    .value = symbol.value,
                }
            );

            if (name.empty()) {
                continue;
            }

            const bool is_external = (symbol.type & kMachONTypeExternal) != 0;
            const std::uint8_t type = static_cast<std::uint8_t>(symbol.type & kMachONTypeMask);
            if (is_external && type == kMachONTypeSection) {
                if (!push_export(
                        image.exports_,
                        ExportedSymbol{
                            .name = name[0] == '_' ? name.substr(1) : name,
                            .address = symbol.value,
                            .size = 0,
                        },
                        policy,
                        out_error
                    )) {
                    return false;
                }
            }
        }
    }

    if (dysymtab_command.has_value() && !symbols.empty() && dysymtab_command->indirect_symbol_count > 0) {
        if (!validate_limit(
                dysymtab_command->indirect_symbol_count,
                policy.max_relocation_count,
                "Mach-O indirect symbol count",
                out_error
            )) {
            return false;
        }
        if (!contains_file_range(
                bytes,
                dysymtab_command->indirect_symbol_offset,
                static_cast<std::uint64_t>(dysymtab_command->indirect_symbol_count) * sizeof(std::uint32_t)
            )) {
            out_error = "Mach-O indirect symbol table is out of bounds.";
            return false;
        }

        std::vector<std::uint32_t> indirect_symbols;
        indirect_symbols.reserve(dysymtab_command->indirect_symbol_count);
        for (std::uint32_t index = 0; index < dysymtab_command->indirect_symbol_count; ++index) {
            const auto value = read_scalar<std::uint32_t>(
                view,
                dysymtab_command->indirect_symbol_offset + (static_cast<std::size_t>(index) * sizeof(std::uint32_t))
            );
            if (!value.has_value()) {
                out_error = "Mach-O indirect symbol entry is truncated.";
                return false;
            }
            indirect_symbols.push_back(*value);
        }

        const std::size_t pointer_size =
            image.architecture_ == Architecture::X86 ||
                    image.architecture_ == Architecture::ARM
                ? sizeof(std::uint32_t)
                : sizeof(std::uint64_t);

        for (const auto& section : parsed_sections) {
            const std::uint32_t section_type = section.header.flags & kMachOSectionTypeMask;
            if (section_type != kMachOSectionTypeNonLazySymbolPointers &&
                section_type != kMachOSectionTypeLazySymbolPointers) {
                continue;
            }

            const std::size_t pointer_count = pointer_size == 0 ? 0 : static_cast<std::size_t>(section.header.size / pointer_size);
            for (std::size_t pointer_index = 0; pointer_index < pointer_count; ++pointer_index) {
                const std::size_t indirect_index = static_cast<std::size_t>(section.header.reserved1) + pointer_index;
                if (indirect_index >= indirect_symbols.size()) {
                    continue;
                }

                const std::uint32_t symbol_index = indirect_symbols[indirect_index];
                if (symbol_index == kMachOIndirectSymbolLocal || symbol_index == kMachOIndirectSymbolAbsolute) {
                    continue;
                }
                if (symbol_index >= symbols.size()) {
                    continue;
                }

                const ParsedMachOSymbol& symbol = symbols[symbol_index];
                const bool is_external = (symbol.type & kMachONTypeExternal) != 0;
                const std::uint8_t type = static_cast<std::uint8_t>(symbol.type & kMachONTypeMask);
                if (!is_external || type != kMachONTypeUndefined || symbol.name.empty()) {
                    continue;
                }

                const std::uint16_t ordinal = static_cast<std::uint16_t>((symbol.description >> 8) & 0xff);
                const std::string library =
                    ordinal > 0 && static_cast<std::size_t>(ordinal) <= dylibs.size() ? dylibs[ordinal - 1] : std::string{};
                if (!push_import(
                        image.imports_,
                        ImportedSymbol{
                            .library = library,
                            .name = symbol.name[0] == '_' ? symbol.name.substr(1) : symbol.name,
                            .address = section.header.address + (pointer_index * pointer_size),
                        },
                        policy,
                        out_error
                    )) {
                    return false;
                }
            }
        }
    }

    if (chained_fixups_command.has_value()) {
        if (!contains_file_range(bytes, chained_fixups_command->data_offset, chained_fixups_command->data_size)) {
            out_error = "Mach-O chained fixups payload is out of bounds.";
            return false;
        }

        const auto fixups_data =
            view.subspan(static_cast<std::size_t>(chained_fixups_command->data_offset), chained_fixups_command->data_size);
        DyldChainedFixupsHeader fixups_header{};
        if (!read_object(fixups_data, 0, fixups_header)) {
            out_error = "Mach-O chained fixups header is truncated.";
            return false;
        }
        if (fixups_header.fixups_version != 0) {
            out_error = "Unsupported Mach-O chained fixups version.";
            return false;
        }
        if (fixups_header.symbols_format != 0) {
            out_error = "Compressed Mach-O chained fixup symbols are not supported.";
            return false;
        }

        const auto chained_imports = parse_chained_imports(fixups_data, fixups_header, dylibs, out_error);
        if (!chained_imports.has_value()) {
            return false;
        }

        if (fixups_header.starts_offset > fixups_data.size()) {
            out_error = "Mach-O chained fixup starts payload is out of bounds.";
            return false;
        }

        DyldChainedStartsInImageHeader starts_image{};
        if (!read_object(fixups_data, static_cast<std::size_t>(fixups_header.starts_offset), starts_image)) {
            out_error = "Mach-O chained segment starts header is truncated.";
            return false;
        }
        if (!validate_limit(starts_image.segment_count, policy.max_program_header_count, "Mach-O chained segment count", out_error)) {
            return false;
        }

        const std::size_t segment_offsets_base =
            static_cast<std::size_t>(fixups_header.starts_offset) + sizeof(DyldChainedStartsInImageHeader);
        const auto segment_offsets_span = span_subrange(
            fixups_data,
            segment_offsets_base,
            static_cast<std::size_t>(starts_image.segment_count) * sizeof(std::uint32_t)
        );
        if (!segment_offsets_span.has_value()) {
            out_error = "Mach-O chained segment offset table is out of bounds.";
            return false;
        }

        for (std::uint32_t segment_index = 0; segment_index < starts_image.segment_count; ++segment_index) {
            const auto relative_offset =
                read_scalar<std::uint32_t>(*segment_offsets_span, static_cast<std::size_t>(segment_index) * sizeof(std::uint32_t));
            if (!relative_offset.has_value() || *relative_offset == 0) {
                continue;
            }

            const std::size_t segment_info_offset = static_cast<std::size_t>(fixups_header.starts_offset) + *relative_offset;
            DyldChainedStartsInSegmentHeader segment_starts{};
            if (!read_object(fixups_data, segment_info_offset, segment_starts)) {
                out_error = "Mach-O chained segment-start record is truncated.";
                return false;
            }
            if (segment_starts.size < sizeof(DyldChainedStartsInSegmentHeader)) {
                out_error = "Mach-O chained segment-start record size is invalid.";
                return false;
            }

            const auto segment_span =
                span_subrange(fixups_data, segment_info_offset, static_cast<std::size_t>(segment_starts.size));
            if (!segment_span.has_value()) {
                out_error = "Mach-O chained segment-start payload is out of bounds.";
                return false;
            }

            const std::size_t page_starts_offset = sizeof(DyldChainedStartsInSegmentHeader);
            const std::size_t page_starts_bytes = static_cast<std::size_t>(segment_starts.page_count) * sizeof(std::uint16_t);
            const auto page_starts = span_subrange(*segment_span, page_starts_offset, page_starts_bytes);
            if (!page_starts.has_value()) {
                out_error = "Mach-O chained page-start table is out of bounds.";
                return false;
            }

            const auto chain_stride = macho_chained_stride(segment_starts.pointer_format);
            const auto pointer_width = macho_chained_pointer_width(segment_starts.pointer_format);
            if (!chain_stride.has_value() || !pointer_width.has_value()) {
                continue;
            }

            const auto* segment =
                segment_index < segments.size() ? &segments[static_cast<std::size_t>(segment_index)] : nullptr;
            const std::uint64_t segment_base =
                segment != nullptr
                    ? segment->virtual_address
                    : image.preferred_load_address_.value_or(image.base_address_) + segment_starts.segment_offset;
            const std::uint64_t segment_end =
                segment != nullptr ? segment->virtual_address + segment->virtual_size : segment_base;

            const std::size_t overflow_words =
                (segment_starts.size - sizeof(DyldChainedStartsInSegmentHeader) - page_starts_bytes) / sizeof(std::uint16_t);
            const auto overflow_starts = span_subrange(
                *segment_span,
                page_starts_offset + page_starts_bytes,
                overflow_words * sizeof(std::uint16_t)
            );

            auto enqueue_chain_start = [&](const std::uint16_t start, const std::size_t page_index) -> bool {
                if (start == kDyldChainedPtrStartNone) {
                    return true;
                }
                const std::uint64_t page_address =
                    segment_base + (static_cast<std::uint64_t>(page_index) * segment_starts.page_size);
                std::uint64_t chain_address = page_address + start;
                std::size_t chain_steps = 0;
                while (true) {
                    if (segment != nullptr &&
                        (chain_address < segment_base || chain_address + *pointer_width > segment_end)) {
                        return true;
                    }

                    std::span<const std::byte> chain_bytes;
                    if (!read_virtual_bytes(image, chain_address, *pointer_width, chain_bytes)) {
                        return true;
                    }
                    std::uint64_t raw_value = 0;
                    std::memcpy(&raw_value, chain_bytes.data(), *pointer_width);

                    const auto decoded =
                        decode_macho_chained_fixup(
                            segment_starts.pointer_format,
                            raw_value,
                            image.preferred_load_address_.value_or(image.base_address_),
                            segments,
                            out_error
                        );
                    if (!decoded.has_value()) {
                        return false;
                    }

                    if (decoded->bind) {
                        if (decoded->import_index < chained_imports->size()) {
                            const auto& import = (*chained_imports)[decoded->import_index];
                            if (!import.name.empty() &&
                                !push_import(
                                    image.imports_,
                                    ImportedSymbol{
                                        .library = import.library,
                                        .name = import.name,
                                        .address = chain_address,
                                    },
                                    policy,
                                    out_error
                                )) {
                                return false;
                            }
                        }
                    } else if (decoded->relocation.has_value()) {
                        auto patch = *decoded->relocation;
                        patch.address = chain_address;
                        if (!push_relocation(image.relocations_, patch, policy, out_error)) {
                            return false;
                        }
                    }

                    if (decoded->next == 0) {
                        return true;
                    }
                    chain_address += static_cast<std::uint64_t>(decoded->next) * *chain_stride;
                    if (++chain_steps > policy.max_relocation_count) {
                        out_error = "Mach-O chained fixup chain exceeds the configured parse limit.";
                        return false;
                    }
                }
            };

            for (std::size_t page_index = 0; page_index < segment_starts.page_count; ++page_index) {
                const auto page_start = read_scalar<std::uint16_t>(*page_starts, page_index * sizeof(std::uint16_t));
                if (!page_start.has_value()) {
                    out_error = "Mach-O chained page-start entry is truncated.";
                    return false;
                }
                if (*page_start == kDyldChainedPtrStartNone) {
                    continue;
                }

                if ((*page_start & kDyldChainedPtrStartMulti) != 0) {
                    if (!overflow_starts.has_value()) {
                        out_error = "Mach-O chained overflow start table is missing.";
                        return false;
                    }
                    std::size_t overflow_index = static_cast<std::size_t>(*page_start & ~kDyldChainedPtrStartMulti);
                    while (overflow_index < overflow_words) {
                        const auto overflow_value =
                            read_scalar<std::uint16_t>(*overflow_starts, overflow_index * sizeof(std::uint16_t));
                        if (!overflow_value.has_value()) {
                            out_error = "Mach-O chained overflow start entry is truncated.";
                            return false;
                        }
                        const std::uint16_t chain_start = static_cast<std::uint16_t>(*overflow_value & ~kDyldChainedPtrStartLast);
                        if (!enqueue_chain_start(chain_start, page_index)) {
                            return false;
                        }
                        if ((*overflow_value & kDyldChainedPtrStartLast) != 0) {
                            break;
                        }
                        ++overflow_index;
                    }
                    continue;
                }

                if (!enqueue_chain_start(*page_start, page_index)) {
                    return false;
                }
            }
        }
    }

    std::size_t parsed_relocation_count = 0;
    for (const auto& section : parsed_sections) {
        if (section.header.relocation_count == 0) {
            continue;
        }

        if (!validate_limit(
                parsed_relocation_count + section.header.relocation_count,
                policy.max_relocation_count,
                "Mach-O relocation count",
                out_error
            )) {
            return false;
        }

        const std::uint64_t relocation_bytes =
            static_cast<std::uint64_t>(section.header.relocation_count) * sizeof(MachORelocationInfo);
        if (!contains_file_range(bytes, section.header.relocation_offset, relocation_bytes)) {
            out_error = "Mach-O relocation table is out of bounds.";
            return false;
        }

        parsed_relocation_count += section.header.relocation_count;
        for (std::uint32_t relocation_index = 0; relocation_index < section.header.relocation_count; ++relocation_index) {
            MachORelocationInfo relocation{};
            if (!read_object(
                    view,
                    section.header.relocation_offset +
                        (static_cast<std::size_t>(relocation_index) * sizeof(MachORelocationInfo)),
                    relocation
                )) {
                out_error = "Mach-O relocation entry is truncated.";
                return false;
            }

            // Scattered relocations encode their tag in the high bit of r_address.
            if (relocation.address < 0) {
                continue;
            }

            const bool is_pc_relative = ((relocation.raw >> 24U) & 0x1U) != 0;
            const auto width = macho_relocation_width((relocation.raw >> 25U) & 0x3U);
            const bool is_external = ((relocation.raw >> 27U) & 0x1U) != 0;
            const std::uint32_t relocation_type = relocation.raw >> 28U;
            if (is_pc_relative || !width.has_value() || relocation_type != kMachORelocationTypeUnsigned) {
                continue;
            }

            const std::uint64_t offset_in_section = static_cast<std::uint32_t>(relocation.address);
            if (offset_in_section > section.header.size ||
                *width > section.header.size - offset_in_section) {
                continue;
            }

            bool applies_to_rebase = !is_external;
            if (is_external) {
                const std::size_t symbol_index = static_cast<std::size_t>(relocation.raw & 0x00FFFFFFU);
                if (symbol_index < symbols.size()) {
                    const ParsedMachOSymbol& symbol = symbols[symbol_index];
                    const std::uint8_t type = static_cast<std::uint8_t>(symbol.type & kMachONTypeMask);
                    applies_to_rebase = type == kMachONTypeSection && symbol.value != 0;
                }
            }

            if (!applies_to_rebase) {
                continue;
            }

            if (!push_relocation(
                    image.relocations_,
                    RelocationPatch{
                        .address = section.header.address + offset_in_section,
                        .width = *width,
                    },
                    policy,
                    out_error
                )) {
                return false;
            }
        }
    }

    if (image.sections_.empty()) {
        out_error = "Mach-O file did not expose any mapped sections.";
        return false;
    }

    deduplicate_imports(image.imports_);
    deduplicate_exports(image.exports_);
    deduplicate_relocations(image.relocations_);
    out_image = std::move(image);
    return true;
}

}  // namespace detail

BinaryImage BinaryImage::from_components(
    std::filesystem::path source_path,
    const BinaryFormat format,
    const Architecture architecture,
    const std::uint64_t base_address,
    const std::optional<std::uint64_t> entry_point,
    std::vector<Section> sections,
    std::vector<ImportedSymbol> imports,
    std::vector<ExportedSymbol> exports,
    std::vector<std::byte> raw_image
) {
    BinaryImage image;
    image.source_path_ = std::move(source_path);
    image.format_ = format;
    image.architecture_ = architecture;
    image.base_address_ = base_address;
    image.preferred_load_address_ = base_address;
    image.entry_point_ = entry_point;
    image.sections_ = std::move(sections);
    image.imports_ = std::move(imports);
    image.exports_ = std::move(exports);
    image.raw_image_ = std::move(raw_image);
    return image;
}

bool BinaryImage::load_from_file(
    const std::filesystem::path& path,
    BinaryImage& out_image,
    std::string& out_error,
    const LoadOptions& options
) {
    out_error.clear();
    const ParsePolicy& policy = options.policy;

    if (path.string().size() > policy.max_path_length) {
        out_error = "Input path exceeds the configured parse limit.";
        return false;
    }

    if (!std::filesystem::exists(path)) {
        out_error = "Input file does not exist.";
        return false;
    }

    if (!std::filesystem::is_regular_file(path)) {
        out_error = "Input path is not a regular file.";
        return false;
    }

    std::error_code file_size_error;
    const auto file_size = std::filesystem::file_size(path, file_size_error);
    if (file_size_error) {
        out_error = "Failed to query input file size.";
        return false;
    }
    if (file_size > policy.max_file_size_bytes) {
        out_error = "Input file exceeds the configured parse size limit.";
        return false;
    }

    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        out_error = "Failed to open input file.";
        return false;
    }

    const std::vector<char> buffer{
        std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>()
    };

    if (buffer.empty()) {
        out_error = "Input file is empty.";
        return false;
    }

    const std::vector<std::byte> bytes = detail::to_bytes(buffer);

    BinaryImage image;
    const std::span<const std::byte> view(bytes.data(), bytes.size());
    if (detail::has_prefix(view, std::span<const unsigned char>(detail::kElfMagic))) {
        if (!detail::parse_elf64(path, bytes, image, out_error, options)) {
            return false;
        }
    } else if (detail::has_prefix(view, std::span<const unsigned char>(detail::kMachOMagic64))) {
        if (!detail::parse_macho(path, bytes, image, out_error, options)) {
            return false;
        }
    } else if (detail::has_prefix(view, std::span<const unsigned char>(detail::kMZMagic))) {
        if (!detail::parse_pe(path, bytes, image, out_error, options)) {
            return false;
        }
    } else {
        if (bytes.size() > policy.max_mapped_section_size || bytes.size() > policy.max_total_mapped_bytes) {
            out_error = "Raw image exceeds the configured mapped size limit.";
            return false;
        }
        detail::populate_raw_image(image, path, bytes, options);
    }

    if (options.rebase_address.has_value()) {
        image.apply_rebase(*options.rebase_address);
    }
    if (!detail::validate_image_metadata_names(image, policy, out_error)) {
        return false;
    }

    out_image = std::move(image);
    return true;
}

const std::filesystem::path& BinaryImage::source_path() const noexcept {
    return source_path_;
}

BinaryFormat BinaryImage::format() const noexcept {
    return format_;
}

Architecture BinaryImage::architecture() const noexcept {
    return architecture_;
}

std::uint64_t BinaryImage::base_address() const noexcept {
    return base_address_;
}

std::optional<std::uint64_t> BinaryImage::preferred_load_address() const noexcept {
    return preferred_load_address_;
}

std::optional<std::uint64_t> BinaryImage::entry_point() const noexcept {
    return entry_point_;
}

std::span<const std::byte> BinaryImage::raw_image() const noexcept {
    return raw_image_;
}

const std::vector<Section>& BinaryImage::sections() const noexcept {
    return sections_;
}

const std::vector<ImportedSymbol>& BinaryImage::imports() const noexcept {
    return imports_;
}

const std::vector<ExportedSymbol>& BinaryImage::exports() const noexcept {
    return exports_;
}

std::int64_t BinaryImage::rebase_delta() const noexcept {
    if (!preferred_load_address_.has_value()) {
        return 0;
    }
    return static_cast<std::int64_t>(base_address_) - static_cast<std::int64_t>(*preferred_load_address_);
}

void BinaryImage::apply_rebase(const std::uint64_t new_base_address) {
    const std::uint64_t original_base = preferred_load_address_.value_or(base_address_);
    if (new_base_address == base_address_) {
        base_address_ = new_base_address;
        if (!preferred_load_address_.has_value()) {
            preferred_load_address_ = original_base;
        }
        return;
    }

    const std::int64_t current_delta = static_cast<std::int64_t>(base_address_) - static_cast<std::int64_t>(original_base);
    const std::int64_t new_delta = static_cast<std::int64_t>(new_base_address) - static_cast<std::int64_t>(original_base);
    const std::int64_t delta = new_delta - current_delta;
    auto rebase_address = [&](std::uint64_t& address) {
        address = static_cast<std::uint64_t>(static_cast<std::int64_t>(address) + delta);
    };
    auto apply_relocation_delta = [&](const RelocationPatch& patch) {
        if (patch.width == 0) {
            return true;
        }

        for (auto& section : sections_) {
            const auto section_end = section.virtual_address + static_cast<std::uint64_t>(section.bytes.size());
            if (patch.address < section.virtual_address || patch.address >= section_end) {
                continue;
            }

            const auto offset = static_cast<std::size_t>(patch.address - section.virtual_address);
            if (offset > section.bytes.size() || patch.width > section.bytes.size() - offset) {
                return false;
            }

            switch (patch.encoding) {
            case RelocationEncoding::MachOChained64:
            case RelocationEncoding::MachOChained64Offset:
            case RelocationEncoding::MachOChained32:
            case RelocationEncoding::MachOChained32Cache:
            case RelocationEncoding::MachOChained32Firmware:
            case RelocationEncoding::MachOChained64KernelCache:
            case RelocationEncoding::MachOChainedX8664KernelCache:
            case RelocationEncoding::MachOChainedArm64e:
            case RelocationEncoding::MachOChainedArm64eOffset:
            case RelocationEncoding::MachOChainedArm64eUserland:
            case RelocationEncoding::MachOChainedArm64eUserland24:
            case RelocationEncoding::MachOChainedArm64eSharedCache:
            case RelocationEncoding::MachOChainedArm64eSegmented: {
                const std::uint64_t resolved_target =
                    static_cast<std::uint64_t>(static_cast<std::int64_t>(patch.target) + new_delta);
                if (patch.width == sizeof(std::uint32_t)) {
                    const std::uint32_t narrowed = static_cast<std::uint32_t>(resolved_target);
                    std::memcpy(section.bytes.data() + static_cast<std::ptrdiff_t>(offset), &narrowed, sizeof(narrowed));
                    return true;
                }
                if (patch.width == sizeof(std::uint64_t)) {
                    std::memcpy(
                        section.bytes.data() + static_cast<std::ptrdiff_t>(offset),
                        &resolved_target,
                        sizeof(resolved_target)
                    );
                    return true;
                }
                return false;
            }
            case RelocationEncoding::Additive:
            default:
                break;
            }

            if (delta == 0) {
                return true;
            }

            if (patch.width == 4) {
                std::uint32_t value = 0;
                std::memcpy(&value, section.bytes.data() + static_cast<std::ptrdiff_t>(offset), sizeof(value));
                value = static_cast<std::uint32_t>(static_cast<std::int64_t>(value) + delta);
                std::memcpy(section.bytes.data() + static_cast<std::ptrdiff_t>(offset), &value, sizeof(value));
                return true;
            }

            if (patch.width == 8) {
                std::uint64_t value = 0;
                std::memcpy(&value, section.bytes.data() + static_cast<std::ptrdiff_t>(offset), sizeof(value));
                value = static_cast<std::uint64_t>(static_cast<std::int64_t>(value) + delta);
                std::memcpy(section.bytes.data() + static_cast<std::ptrdiff_t>(offset), &value, sizeof(value));
                return true;
            }

            return false;
        }

        return false;
    };

    if (entry_point_.has_value()) {
        rebase_address(*entry_point_);
    }

    for (auto& section : sections_) {
        rebase_address(section.virtual_address);
    }
    for (auto& imported : imports_) {
        rebase_address(imported.address);
    }
    for (auto& exported : exports_) {
        rebase_address(exported.address);
    }
    for (auto& relocation : relocations_) {
        rebase_address(relocation.address);
    }
    for (const auto& relocation : relocations_) {
        (void)apply_relocation_delta(relocation);
    }

    preferred_load_address_ = original_base;
    base_address_ = new_base_address;
}

std::string_view to_string(const BinaryFormat format) noexcept {
    switch (format) {
    case BinaryFormat::ELF:
        return "elf";
    case BinaryFormat::MachO:
        return "macho";
    case BinaryFormat::PE:
        return "pe";
    case BinaryFormat::Raw:
        return "raw";
    case BinaryFormat::Unknown:
    default:
        return "unknown";
    }
}

std::string_view to_string(const Architecture architecture) noexcept {
    switch (architecture) {
    case Architecture::X86:
        return "x86";
    case Architecture::X86_64:
        return "x86_64";
    case Architecture::ARM:
        return "arm";
    case Architecture::ARM64:
        return "arm64";
    case Architecture::RISCV64:
        return "riscv64";
    case Architecture::MIPS64:
        return "mips64";
    case Architecture::PPC64:
        return "ppc64";
    case Architecture::Unknown:
    default:
        return "unknown";
    }
}

}  // namespace zara::loader
