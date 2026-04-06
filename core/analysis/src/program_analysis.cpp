#include "zara/analysis/program_analysis.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <future>
#include <iomanip>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "zara/disasm/disassembler.hpp"

namespace zara::analysis {

namespace {

enum class SeedOrigin {
    Heuristic,
    Signature,
    CallTarget,
    Export,
    Entry,
};

struct FunctionSeed {
    std::uint64_t address = 0;
    SeedOrigin origin = SeedOrigin::Heuristic;
};

struct FunctionSignaturePattern {
    loader::Architecture architecture = loader::Architecture::Unknown;
    std::string_view name;
    std::vector<int> bytes;
};

struct FunctionRange {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
};

struct PendingFunction {
    std::string name;
    std::string section_name;
    std::uint64_t entry_address = 0;
    cfg::FunctionGraph graph;
};

struct CachedDiscovery {
    std::vector<PendingFunction> functions;
    std::vector<CallGraphEdge> call_graph;
    std::vector<xrefs::ExtractedString> strings;
    std::vector<xrefs::CrossReference> xrefs;
};

struct ProgramAnalysisState {
    loader::BinaryImage image;
    memory::AddressSpace address_space;
    std::unordered_map<std::uint64_t, PendingFunction> pending_functions;
    std::string program_cache_key;
    bool use_cache = true;
    std::mutex mutex;
};

struct AnalysisCaches {
    std::mutex mutex;
    std::unordered_map<std::string, CachedDiscovery> discovery_cache;
    std::deque<std::string> discovery_order;
    std::unordered_map<std::string, DiscoveredFunction> function_cache;
    std::deque<std::string> function_order;
    std::atomic<std::size_t> discovery_hits{0};
    std::atomic<std::size_t> discovery_misses{0};
    std::atomic<std::size_t> function_hits{0};
    std::atomic<std::size_t> function_misses{0};
    std::atomic<std::size_t> lazy_materializations{0};
};

struct KnownCondition {
    enum class Kind {
        Compare,
        Test,
    };

    Kind kind = Kind::Compare;
    std::int64_t lhs = 0;
    std::int64_t rhs = 0;
};

struct SimplificationResult {
    std::size_t unreachable_blocks_removed = 0;
    std::size_t rewrites_applied = 0;
};

constexpr std::size_t kMaxDiscoveryCacheEntries = 8;
constexpr std::size_t kMaxFunctionCacheEntries = 256;

std::string stack_pointer_name(loader::Architecture architecture);
std::string frame_pointer_name(loader::Architecture architecture);
std::string return_register_name(loader::Architecture architecture);
std::vector<std::string> argument_registers(loader::Architecture architecture);

AnalysisCaches& global_caches() {
    static AnalysisCaches caches;
    return caches;
}

void append_cache_order(std::deque<std::string>& order, const std::string& key) {
    order.erase(std::remove(order.begin(), order.end(), key), order.end());
    order.push_back(key);
}

template <typename CacheMap>
void prune_cache(CacheMap& cache, std::deque<std::string>& order, const std::size_t max_entries) {
    while (order.size() > max_entries) {
        const std::string oldest = order.front();
        order.pop_front();
        cache.erase(oldest);
    }
}

std::uint64_t hash_bytes(
    std::uint64_t hash,
    const unsigned char* bytes,
    const std::size_t size
) {
    constexpr std::uint64_t kFnvPrime = 1099511628211ULL;
    for (std::size_t index = 0; index < size; ++index) {
        hash ^= static_cast<std::uint64_t>(bytes[index]);
        hash *= kFnvPrime;
    }
    return hash;
}

template <typename T>
std::uint64_t hash_append(std::uint64_t hash, const T& value) {
    return hash_bytes(
        hash,
        reinterpret_cast<const unsigned char*>(&value),
        sizeof(T)
    );
}

std::uint64_t hash_append_string(std::uint64_t hash, const std::string_view value) {
    return hash_bytes(
        hash,
        reinterpret_cast<const unsigned char*>(value.data()),
        value.size()
    );
}

std::string build_program_cache_key(const loader::BinaryImage& image) {
    constexpr std::uint64_t kFnvOffset = 1469598103934665603ULL;
    std::uint64_t hash = kFnvOffset;
    hash = hash_append(hash, static_cast<std::uint32_t>(image.format()));
    hash = hash_append(hash, static_cast<std::uint32_t>(image.architecture()));
    hash = hash_append(hash, image.base_address());

    const std::filesystem::path source_path = image.source_path();
    std::error_code error;
    const bool has_real_file =
        !source_path.empty() && std::filesystem::exists(source_path, error) && !error;
    if (has_real_file) {
        const auto absolute = std::filesystem::absolute(source_path, error);
        hash = hash_append_string(hash, error ? source_path.string() : absolute.string());
        error.clear();
        const auto file_size = std::filesystem::file_size(source_path, error);
        if (!error) {
            hash = hash_append(hash, file_size);
        }
        error.clear();
        const auto last_write = std::filesystem::last_write_time(source_path, error);
        if (!error) {
            const auto ticks = last_write.time_since_epoch().count();
            hash = hash_append(hash, ticks);
        }
    } else {
        hash = hash_append_string(hash, source_path.string());
        for (const auto& section : image.sections()) {
            hash = hash_append_string(hash, section.name);
            hash = hash_append(hash, section.virtual_address);
            hash = hash_append(hash, static_cast<std::uint64_t>(section.bytes.size()));
            if (!section.bytes.empty()) {
                hash = hash_bytes(
                    hash,
                    reinterpret_cast<const unsigned char*>(section.bytes.data()),
                    section.bytes.size()
                );
            }
        }
    }

    std::ostringstream stream;
    stream << std::hex << std::uppercase << hash;
    return stream.str();
}

std::string function_cache_key(const std::string_view program_key, const std::uint64_t entry_address) {
    std::ostringstream stream;
    stream << program_key << ':' << std::hex << std::uppercase << entry_address;
    return stream.str();
}

std::optional<CachedDiscovery> lookup_discovery_cache(const std::string& key) {
    auto& caches = global_caches();
    std::scoped_lock lock(caches.mutex);
    const auto it = caches.discovery_cache.find(key);
    if (it == caches.discovery_cache.end()) {
        ++caches.discovery_misses;
        return std::nullopt;
    }
    ++caches.discovery_hits;
    append_cache_order(caches.discovery_order, key);
    return it->second;
}

void store_discovery_cache(const std::string& key, CachedDiscovery entry) {
    auto& caches = global_caches();
    std::scoped_lock lock(caches.mutex);
    caches.discovery_cache[key] = std::move(entry);
    append_cache_order(caches.discovery_order, key);
    prune_cache(caches.discovery_cache, caches.discovery_order, kMaxDiscoveryCacheEntries);
}

std::optional<DiscoveredFunction> lookup_function_cache(const std::string& key) {
    auto& caches = global_caches();
    std::scoped_lock lock(caches.mutex);
    const auto it = caches.function_cache.find(key);
    if (it == caches.function_cache.end()) {
        ++caches.function_misses;
        return std::nullopt;
    }
    ++caches.function_hits;
    append_cache_order(caches.function_order, key);
    return it->second;
}

void store_function_cache(const std::string& key, DiscoveredFunction function) {
    auto& caches = global_caches();
    std::scoped_lock lock(caches.mutex);
    caches.function_cache[key] = std::move(function);
    append_cache_order(caches.function_order, key);
    prune_cache(caches.function_cache, caches.function_order, kMaxFunctionCacheEntries);
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

std::string format_function_name(const std::uint64_t entry_address) {
    std::ostringstream stream;
    stream << "sub_" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << entry_address;
    return stream.str();
}

std::string format_import_name(const loader::ImportedSymbol& imported) {
    if (imported.library.empty()) {
        return imported.name;
    }

    return imported.library + "!" + imported.name;
}

std::string base_name(const std::string& name) {
    const auto dot = name.find('.');
    if (dot == std::string::npos) {
        return name;
    }
    return name.substr(0, dot);
}

std::string normalize_register_family(std::string name, const loader::Architecture architecture) {
    name = lowercase_copy(base_name(std::move(name)));

    if (architecture == loader::Architecture::X86_64) {
        if (name == "rax" || name == "eax" || name == "ax" || name == "al" || name == "ah") {
            return "rax";
        }
        if (name == "rdi" || name == "edi" || name == "di" || name == "dil") {
            return "rdi";
        }
        if (name == "rsi" || name == "esi" || name == "si" || name == "sil") {
            return "rsi";
        }
        if (name == "rdx" || name == "edx" || name == "dx" || name == "dl" || name == "dh") {
            return "rdx";
        }
        if (name == "rcx" || name == "ecx" || name == "cx" || name == "cl" || name == "ch") {
            return "rcx";
        }
        if (name == "rsp" || name == "esp" || name == "sp" || name == "spl") {
            return "rsp";
        }
        if (name == "rbp" || name == "ebp" || name == "bp" || name == "bpl") {
            return "rbp";
        }
    }

    if (architecture == loader::Architecture::X86) {
        if (name == "eax" || name == "ax" || name == "al" || name == "ah") {
            return "eax";
        }
        if (name == "edi" || name == "di") {
            return "edi";
        }
        if (name == "esi" || name == "si") {
            return "esi";
        }
        if (name == "edx" || name == "dx" || name == "dl" || name == "dh") {
            return "edx";
        }
        if (name == "ecx" || name == "cx" || name == "cl" || name == "ch") {
            return "ecx";
        }
        if (name == "esp" || name == "sp") {
            return "esp";
        }
        if (name == "ebp" || name == "bp") {
            return "ebp";
        }
    }

    if (architecture == loader::Architecture::ARM) {
        if (name == "r11" || name == "fp") {
            return "fp";
        }
        if (name == "r13" || name == "sp") {
            return "sp";
        }
        if (name == "r14" || name == "lr") {
            return "lr";
        }
        if (name == "r15" || name == "pc") {
            return "pc";
        }
    }

    if (architecture == loader::Architecture::RISCV64) {
        if (name == "x1" || name == "ra") {
            return "ra";
        }
        if (name == "x2" || name == "sp") {
            return "sp";
        }
        if (name == "x8" || name == "s0" || name == "fp") {
            return "s0";
        }
        if (name == "x10" || name == "a0") {
            return "a0";
        }
        if (name == "x11" || name == "a1") {
            return "a1";
        }
        if (name == "x12" || name == "a2") {
            return "a2";
        }
        if (name == "x13" || name == "a3") {
            return "a3";
        }
        if (name == "x14" || name == "a4") {
            return "a4";
        }
        if (name == "x15" || name == "a5") {
            return "a5";
        }
        if (name == "x16" || name == "a6") {
            return "a6";
        }
        if (name == "x17" || name == "a7") {
            return "a7";
        }
    }

    if (architecture == loader::Architecture::MIPS64) {
        if (name == "sp" || name == "$sp") {
            return "sp";
        }
        if (name == "fp" || name == "s8" || name == "$fp" || name == "$s8") {
            return "fp";
        }
        if (name == "ra" || name == "$ra") {
            return "ra";
        }
        if (name == "v0" || name == "$v0") {
            return "v0";
        }
        if (name == "a0" || name == "$a0") {
            return "a0";
        }
        if (name == "a1" || name == "$a1") {
            return "a1";
        }
        if (name == "a2" || name == "$a2") {
            return "a2";
        }
        if (name == "a3" || name == "$a3") {
            return "a3";
        }
        if (name == "a4" || name == "$a4") {
            return "a4";
        }
        if (name == "a5" || name == "$a5") {
            return "a5";
        }
        if (name == "a6" || name == "$a6") {
            return "a6";
        }
        if (name == "a7" || name == "$a7") {
            return "a7";
        }
    }

    if (architecture == loader::Architecture::PPC64) {
        if (name == "r1") {
            return "r1";
        }
        if (name == "r31") {
            return "r31";
        }
        if (name == "lr") {
            return "lr";
        }
        if (name == "r3") {
            return "r3";
        }
        if (name == "r4") {
            return "r4";
        }
        if (name == "r5") {
            return "r5";
        }
        if (name == "r6") {
            return "r6";
        }
        if (name == "r7") {
            return "r7";
        }
        if (name == "r8") {
            return "r8";
        }
        if (name == "r9") {
            return "r9";
        }
        if (name == "r10") {
            return "r10";
        }
    }

    return name;
}

int seed_priority(const SeedOrigin origin) {
    switch (origin) {
    case SeedOrigin::Entry:
        return 5;
    case SeedOrigin::Export:
        return 4;
    case SeedOrigin::CallTarget:
        return 3;
    case SeedOrigin::Signature:
        return 2;
    case SeedOrigin::Heuristic:
    default:
        return 1;
    }
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
    if (incoming == ir::ScalarType::Unknown) {
        return current;
    }
    if (current == incoming) {
        return current;
    }
    return type_rank(incoming) > type_rank(current) ? incoming : current;
}

std::uint64_t type_size(const ir::ScalarType type, const loader::Architecture architecture) {
    switch (type) {
    case ir::ScalarType::Bool:
    case ir::ScalarType::I8:
        return 1;
    case ir::ScalarType::I16:
        return 2;
    case ir::ScalarType::I32:
        return 4;
    case ir::ScalarType::Pointer:
        return (architecture == loader::Architecture::X86 || architecture == loader::Architecture::ARM) ? 4 : 8;
    case ir::ScalarType::I64:
    case ir::ScalarType::Unknown:
    default:
        return 8;
    }
}

ir::Value make_immediate_value(const std::int64_t value, const ir::ScalarType type = ir::ScalarType::Unknown) {
    return ir::Value{
        .kind = ir::ValueKind::Immediate,
        .type = type,
        .name = {},
        .immediate = value,
        .memory = {},
    };
}

bool is_executable_section(const loader::Section& section) {
    return section.executable && !section.bytes.empty();
}

bool is_in_section(const loader::Section& section, const std::uint64_t address) {
    const auto end = section.virtual_address + static_cast<std::uint64_t>(section.bytes.size());
    return address >= section.virtual_address && address < end;
}

bool looks_like_padding_byte(const std::byte byte) {
    const auto value = std::to_integer<unsigned char>(byte);
    return value == 0x00 || value == 0x90 || value == 0xCC;
}

bool looks_like_function_terminator_byte(const std::byte byte) {
    const auto value = std::to_integer<unsigned char>(byte);
    return value == 0xC2 || value == 0xC3 || value == 0xCA || value == 0xCB;
}

bool has_likely_function_boundary(
    const loader::Section& section,
    const std::size_t offset,
    const loader::Architecture architecture,
    const std::size_t alignment
) {
    if (offset == 0) {
        return true;
    }

    const auto previous = section.bytes[offset - 1];
    if (looks_like_padding_byte(previous)) {
        return true;
    }

    switch (architecture) {
    case loader::Architecture::X86:
    case loader::Architecture::X86_64:
        return looks_like_function_terminator_byte(previous);
    case loader::Architecture::ARM:
    case loader::Architecture::ARM64: {
        if (alignment <= 1 || offset < alignment) {
            return false;
        }

        const auto boundary_start = offset - alignment;
        return std::all_of(
            section.bytes.begin() + static_cast<std::ptrdiff_t>(boundary_start),
            section.bytes.begin() + static_cast<std::ptrdiff_t>(offset),
            [](const std::byte byte) { return looks_like_padding_byte(byte); }
        );
    }
    case loader::Architecture::RISCV64: {
        if (alignment <= 1 || offset < alignment) {
            return false;
        }
        const auto boundary_start = offset - alignment;
        return std::all_of(
            section.bytes.begin() + static_cast<std::ptrdiff_t>(boundary_start),
            section.bytes.begin() + static_cast<std::ptrdiff_t>(offset),
            [](const std::byte byte) { return looks_like_padding_byte(byte); }
        );
    }
    case loader::Architecture::MIPS64:
    case loader::Architecture::PPC64: {
        if (alignment <= 1 || offset < alignment) {
            return false;
        }
        const auto boundary_start = offset - alignment;
        return std::all_of(
            section.bytes.begin() + static_cast<std::ptrdiff_t>(boundary_start),
            section.bytes.begin() + static_cast<std::ptrdiff_t>(offset),
            [](const std::byte byte) { return looks_like_padding_byte(byte); }
        );
    }
    case loader::Architecture::Unknown:
    default:
        return false;
    }
}

const loader::Section* find_executable_section_for_address(
    const loader::BinaryImage& image,
    const std::uint64_t address
) {
    for (const auto& section : image.sections()) {
        if (is_executable_section(section) && is_in_section(section, address)) {
            return &section;
        }
    }

    return nullptr;
}

template <std::size_t N>
bool has_prefix(const std::vector<std::byte>& bytes, const std::size_t offset, const std::array<unsigned char, N>& pattern) {
    if (offset + pattern.size() > bytes.size()) {
        return false;
    }

    for (std::size_t index = 0; index < pattern.size(); ++index) {
        if (std::to_integer<unsigned char>(bytes[offset + index]) != pattern[index]) {
            return false;
        }
    }

    return true;
}

bool matches_signature_pattern(
    const std::vector<std::byte>& bytes,
    const std::size_t offset,
    const std::vector<int>& pattern
) {
    if (offset + pattern.size() > bytes.size()) {
        return false;
    }

    for (std::size_t index = 0; index < pattern.size(); ++index) {
        const auto expected = pattern[index];
        if (expected < 0) {
            continue;
        }
        if (std::to_integer<unsigned char>(bytes[offset + index]) != static_cast<unsigned char>(expected)) {
            return false;
        }
    }

    return true;
}

bool looks_like_x86_prologue(
    const loader::Section& section,
    const std::size_t offset,
    const loader::Architecture architecture
) {
    constexpr std::array<unsigned char, 4> kEndBr64{0xF3, 0x0F, 0x1E, 0xFA};
    constexpr std::array<unsigned char, 4> kFramePrologue64{0x55, 0x48, 0x89, 0xE5};
    constexpr std::array<unsigned char, 3> kFramePrologue32{0x55, 0x89, 0xE5};
    constexpr std::array<unsigned char, 3> kStackAllocShort{0x48, 0x83, 0xEC};
    constexpr std::array<unsigned char, 3> kStackAllocLong{0x48, 0x81, 0xEC};

    if (has_prefix(section.bytes, offset, kEndBr64)) {
        return true;
    }

    if (architecture == loader::Architecture::X86_64) {
        return has_prefix(section.bytes, offset, kFramePrologue64) ||
               has_prefix(section.bytes, offset, kStackAllocShort) ||
               has_prefix(section.bytes, offset, kStackAllocLong);
    }

    return has_prefix(section.bytes, offset, kFramePrologue32);
}

bool looks_like_arm64_prologue(
    const memory::AddressSpace& address_space,
    const std::uint64_t address
) {
    disasm::Disassembler disassembler;
    const auto instructions = disassembler.decode(address_space, address, 8, loader::Architecture::ARM64);
    if (instructions.empty() || instructions.front().mnemonic == "db") {
        return false;
    }

    const auto& first = instructions.front();
    if (first.mnemonic == "pacibsp" || first.mnemonic == "paciasp") {
        return true;
    }

    if (first.mnemonic == "stp" &&
        first.operands.find("x29") != std::string::npos &&
        first.operands.find("x30") != std::string::npos &&
        first.operands.find("[sp") != std::string::npos) {
        return true;
    }

    if (first.mnemonic == "sub" && first.operands.rfind("sp, sp", 0) == 0) {
        return true;
    }

    return false;
}

bool looks_like_arm_prologue(
    const memory::AddressSpace& address_space,
    const std::uint64_t address
) {
    disasm::Disassembler disassembler;
    const auto instructions = disassembler.decode(address_space, address, 8, loader::Architecture::ARM);
    if (instructions.empty() || instructions.front().mnemonic == "db") {
        return false;
    }

    const auto& first = instructions.front();
    const std::string operands = lowercase_copy(first.operands);
    if (first.mnemonic == "push" && operands.find("lr") != std::string::npos) {
        return true;
    }

    if (first.mnemonic == "stmdb" &&
        operands.find("sp!") != std::string::npos &&
        operands.find("lr") != std::string::npos) {
        return true;
    }

    if (first.mnemonic == "sub" && operands.rfind("sp, sp", 0) == 0) {
        return true;
    }

    return false;
}

bool looks_like_riscv64_prologue(
    const memory::AddressSpace& address_space,
    const std::uint64_t address
) {
    disasm::Disassembler disassembler;
    const auto instructions = disassembler.decode(address_space, address, 16, loader::Architecture::RISCV64);
    if (instructions.empty() || instructions.front().mnemonic == "db") {
        return false;
    }

    for (const auto& instruction : instructions) {
        const std::string mnemonic = lowercase_copy(instruction.mnemonic);
        const std::string operands = lowercase_copy(instruction.operands);
        if ((mnemonic == "addi" || mnemonic == "c.addi16sp") &&
            operands.rfind("sp, sp, -", 0) == 0) {
            return true;
        }
        if ((mnemonic == "sd" || mnemonic == "c.sdsp") &&
            operands.find("ra") != std::string::npos &&
            operands.find("(sp)") != std::string::npos) {
            return true;
        }
        if ((mnemonic == "sd" || mnemonic == "c.sdsp") &&
            (operands.find("s0") != std::string::npos || operands.find("fp") != std::string::npos) &&
            operands.find("(sp)") != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool looks_like_mips64_prologue(
    const memory::AddressSpace& address_space,
    const std::uint64_t address
) {
    disasm::Disassembler disassembler;
    const auto instructions = disassembler.decode(address_space, address, 16, loader::Architecture::MIPS64);
    if (instructions.empty() || instructions.front().mnemonic == "db") {
        return false;
    }

    for (const auto& instruction : instructions) {
        const std::string mnemonic = lowercase_copy(instruction.mnemonic);
        const std::string operands = lowercase_copy(instruction.operands);
        if ((mnemonic == "daddiu" || mnemonic == "addiu") && operands.rfind("sp, sp, -", 0) == 0) {
            return true;
        }
        if ((mnemonic == "sd" || mnemonic == "sw") &&
            operands.find("ra") != std::string::npos &&
            operands.find("(sp)") != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool looks_like_ppc64_prologue(
    const memory::AddressSpace& address_space,
    const std::uint64_t address
) {
    disasm::Disassembler disassembler;
    const auto instructions = disassembler.decode(address_space, address, 16, loader::Architecture::PPC64);
    if (instructions.empty() || instructions.front().mnemonic == "db") {
        return false;
    }

    for (const auto& instruction : instructions) {
        const std::string mnemonic = lowercase_copy(instruction.mnemonic);
        const std::string operands = lowercase_copy(instruction.operands);
        if (mnemonic == "mflr") {
            return true;
        }
        if (mnemonic == "stdu" && operands.rfind("r1, -", 0) == 0) {
            return true;
        }
        if (mnemonic == "std" &&
            operands.find("r0") != std::string::npos &&
            operands.find("(r1)") != std::string::npos) {
            return true;
        }
    }
    return false;
}

const std::vector<FunctionSignaturePattern>& function_signatures() {
    static const std::vector<FunctionSignaturePattern> patterns{
        {
            .architecture = loader::Architecture::X86,
            .name = "msvc_hotpatch_frame",
            .bytes = {0x8B, 0xFF, 0x55, 0x8B, 0xEC},
        },
        {
            .architecture = loader::Architecture::X86,
            .name = "msvc_hotpatch_frame_alloc8",
            .bytes = {0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0xEC, -1},
        },
        {
            .architecture = loader::Architecture::X86_64,
            .name = "msvc_nonframe_save_stack",
            .bytes = {0x48, 0x89, 0x5C, 0x24, -1, 0x57, 0x48, 0x83, 0xEC, -1},
        },
        {
            .architecture = loader::Architecture::X86_64,
            .name = "msvc_push_rbx_stack_alloc",
            .bytes = {0x40, 0x53, 0x48, 0x83, 0xEC, -1},
        },
        {
            .architecture = loader::Architecture::ARM64,
            .name = "arm64_frame_pair",
            .bytes = {0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91},
        },
        {
            .architecture = loader::Architecture::MIPS64,
            .name = "mips64_stack_frame",
            .bytes = {0xF0, 0xFF, 0xBD, 0x67},
        },
        {
            .architecture = loader::Architecture::PPC64,
            .name = "ppc64_linkage_frame",
            .bytes = {0xF8, 0x21, -1, -1},
        },
    };
    return patterns;
}

std::vector<FunctionSeed> deduplicate_seeds(std::vector<FunctionSeed> seeds) {
    std::unordered_map<std::uint64_t, FunctionSeed> best_by_address;
    for (const auto& seed : seeds) {
        const auto existing = best_by_address.find(seed.address);
        if (existing == best_by_address.end() || seed_priority(seed.origin) > seed_priority(existing->second.origin)) {
            best_by_address[seed.address] = seed;
        }
    }

    std::vector<FunctionSeed> deduplicated;
    deduplicated.reserve(best_by_address.size());
    for (const auto& [_, seed] : best_by_address) {
        deduplicated.push_back(seed);
    }

    std::sort(
        deduplicated.begin(),
        deduplicated.end(),
        [](const FunctionSeed& lhs, const FunctionSeed& rhs) {
            if (seed_priority(lhs.origin) != seed_priority(rhs.origin)) {
                return seed_priority(lhs.origin) < seed_priority(rhs.origin);
            }
            return lhs.address < rhs.address;
        }
    );
    return deduplicated;
}

std::vector<FunctionSeed> collect_strong_seeds(const loader::BinaryImage& image) {
    std::vector<FunctionSeed> seeds;

    if (image.entry_point().has_value()) {
        if (find_executable_section_for_address(image, *image.entry_point()) != nullptr) {
            seeds.push_back(FunctionSeed{.address = *image.entry_point(), .origin = SeedOrigin::Entry});
        }
    }

    for (const auto& exported : image.exports()) {
        if (find_executable_section_for_address(image, exported.address) != nullptr) {
            seeds.push_back(FunctionSeed{.address = exported.address, .origin = SeedOrigin::Export});
        }
    }

    return deduplicate_seeds(std::move(seeds));
}

std::vector<FunctionSeed> collect_heuristic_seeds(
    const loader::BinaryImage& image,
    const memory::AddressSpace& address_space
) {
    std::vector<FunctionSeed> seeds;
    const auto* descriptor = disasm::describe_architecture(image.architecture());
    const std::size_t alignment = descriptor == nullptr ? 1 : std::max<std::size_t>(1, descriptor->instruction_alignment);

    for (const auto& section : image.sections()) {
        if (!is_executable_section(section)) {
            continue;
        }

        for (std::size_t offset = 0; offset < section.bytes.size(); offset += alignment) {
            if (!has_likely_function_boundary(section, offset, image.architecture(), alignment)) {
                continue;
            }

            const std::uint64_t address = section.virtual_address + offset;
            bool matches = false;

            switch (image.architecture()) {
            case loader::Architecture::X86:
            case loader::Architecture::X86_64:
                matches = looks_like_x86_prologue(section, offset, image.architecture());
                break;
            case loader::Architecture::ARM:
                matches = looks_like_arm_prologue(address_space, address);
                break;
            case loader::Architecture::ARM64:
                matches = looks_like_arm64_prologue(address_space, address);
                break;
            case loader::Architecture::RISCV64:
                matches = looks_like_riscv64_prologue(address_space, address);
                break;
            case loader::Architecture::MIPS64:
                matches = looks_like_mips64_prologue(address_space, address);
                break;
            case loader::Architecture::PPC64:
                matches = looks_like_ppc64_prologue(address_space, address);
                break;
            case loader::Architecture::Unknown:
            default:
                matches = false;
                break;
            }

            if (matches) {
                seeds.push_back(FunctionSeed{.address = address, .origin = SeedOrigin::Heuristic});
            }
        }
    }

    return deduplicate_seeds(std::move(seeds));
}

std::vector<FunctionSeed> collect_signature_seeds(
    const loader::BinaryImage& image,
    const memory::AddressSpace& address_space
) {
    std::vector<FunctionSeed> seeds;
    const auto* descriptor = disasm::describe_architecture(image.architecture());
    const std::size_t alignment = descriptor == nullptr ? 1 : std::max<std::size_t>(1, descriptor->instruction_alignment);
    (void)address_space;

    std::vector<const FunctionSignaturePattern*> signatures;
    for (const auto& pattern : function_signatures()) {
        if (pattern.architecture == image.architecture()) {
            signatures.push_back(&pattern);
        }
    }

    if (signatures.empty()) {
        return {};
    }

    for (const auto& section : image.sections()) {
        if (!is_executable_section(section)) {
            continue;
        }

        for (std::size_t offset = 0; offset < section.bytes.size(); offset += alignment) {
            if (!has_likely_function_boundary(section, offset, image.architecture(), alignment)) {
                continue;
            }

            for (const auto* signature : signatures) {
                if (matches_signature_pattern(section.bytes, offset, signature->bytes)) {
                    const std::uint64_t address = section.virtual_address + offset;
                    seeds.push_back(FunctionSeed{.address = address, .origin = SeedOrigin::Signature});
                    break;
                }
            }
        }
    }

    return deduplicate_seeds(std::move(seeds));
}

const loader::ImportedSymbol* find_import_for_address(
    const loader::BinaryImage& image,
    const std::uint64_t address
) {
    for (const auto& imported : image.imports()) {
        if (imported.address == address) {
            return &imported;
        }
    }

    return nullptr;
}

std::uint64_t graph_end_address(const cfg::FunctionGraph& graph) {
    std::uint64_t end_address = graph.entry_address();
    for (const auto& block : graph.blocks()) {
        end_address = std::max(end_address, block.end_address);
    }
    return end_address;
}

bool overlaps_existing_ranges(
    const std::uint64_t start,
    const std::uint64_t end,
    const std::vector<FunctionRange>& accepted_ranges
) {
    for (const auto& range : accepted_ranges) {
        if (start < range.end && end > range.start) {
            return true;
        }
    }
    return false;
}

bool address_in_existing_range(const std::uint64_t address, const std::vector<FunctionRange>& accepted_ranges) {
    for (const auto& range : accepted_ranges) {
        if (address >= range.start && address < range.end) {
            return true;
        }
    }
    return false;
}

bool validate_function_candidate(
    const FunctionSeed& seed,
    const cfg::FunctionGraph& graph,
    const std::vector<FunctionRange>& accepted_ranges
) {
    if (graph.blocks().empty()) {
        return false;
    }

    const auto entry_block_it = std::find_if(
        graph.blocks().begin(),
        graph.blocks().end(),
        [&](const cfg::BasicBlock& block) { return block.start_address == seed.address; }
    );
    if (entry_block_it == graph.blocks().end() || entry_block_it->instructions.empty()) {
        return false;
    }
    const auto* entry_block = &(*entry_block_it);

    if (entry_block->instructions.front().address != seed.address ||
        entry_block->instructions.front().kind == disasm::InstructionKind::DataByte) {
        return false;
    }

    const std::uint64_t end_address = graph_end_address(graph);
    if (end_address <= seed.address) {
        return false;
    }

    if (overlaps_existing_ranges(seed.address, end_address, accepted_ranges)) {
        return false;
    }

    std::size_t instruction_count = 0;
    std::size_t data_byte_count = 0;
    std::size_t terminator_count = 0;
    for (const auto& block : graph.blocks()) {
        for (const auto& instruction : block.instructions) {
            ++instruction_count;
            if (instruction.kind == disasm::InstructionKind::DataByte) {
                ++data_byte_count;
            }
            if (instruction.kind == disasm::InstructionKind::Jump ||
                instruction.kind == disasm::InstructionKind::ConditionalJump ||
                instruction.kind == disasm::InstructionKind::Return ||
                instruction.kind == disasm::InstructionKind::Interrupt) {
                ++terminator_count;
            }
        }
    }

    if (instruction_count == 0 || data_byte_count == instruction_count) {
        return false;
    }

    if (seed.origin == SeedOrigin::Heuristic || seed.origin == SeedOrigin::Signature) {
        const bool strict_heuristic = seed.origin == SeedOrigin::Heuristic;
        if (instruction_count < 2) {
            if (strict_heuristic || terminator_count == 0) {
                return false;
            }
        }
        if ((data_byte_count * 4) > instruction_count) {
            return false;
        }
        if (terminator_count == 0 && graph.direct_call_targets().empty()) {
            return false;
        }
    }

    return true;
}

void deduplicate_xrefs(std::vector<xrefs::CrossReference>& references) {
    std::sort(
        references.begin(),
        references.end(),
        [](const xrefs::CrossReference& lhs, const xrefs::CrossReference& rhs) {
            if (lhs.from_address != rhs.from_address) {
                return lhs.from_address < rhs.from_address;
            }
            if (lhs.to_address != rhs.to_address) {
                return lhs.to_address < rhs.to_address;
            }
            if (lhs.label != rhs.label) {
                return lhs.label < rhs.label;
            }
            return static_cast<int>(lhs.kind) < static_cast<int>(rhs.kind);
        }
    );

    references.erase(
        std::unique(
            references.begin(),
            references.end(),
            [](const xrefs::CrossReference& lhs, const xrefs::CrossReference& rhs) {
                return lhs.kind == rhs.kind &&
                       lhs.from_address == rhs.from_address &&
                       lhs.to_address == rhs.to_address &&
                       lhs.label == rhs.label;
            }
        ),
        references.end()
    );
}

void deduplicate_call_edges(std::vector<CallGraphEdge>& edges) {
    std::sort(
        edges.begin(),
        edges.end(),
        [](const CallGraphEdge& lhs, const CallGraphEdge& rhs) {
            if (lhs.caller_entry != rhs.caller_entry) {
                return lhs.caller_entry < rhs.caller_entry;
            }
            if (lhs.call_site != rhs.call_site) {
                return lhs.call_site < rhs.call_site;
            }
            if (lhs.callee_entry != rhs.callee_entry) {
                return lhs.callee_entry < rhs.callee_entry;
            }
            if (lhs.is_import != rhs.is_import) {
                return lhs.is_import < rhs.is_import;
            }
            return lhs.callee_name < rhs.callee_name;
        }
    );

    edges.erase(
        std::unique(
            edges.begin(),
            edges.end(),
            [](const CallGraphEdge& lhs, const CallGraphEdge& rhs) {
                return lhs.caller_entry == rhs.caller_entry &&
                       lhs.call_site == rhs.call_site &&
                       lhs.callee_entry == rhs.callee_entry &&
                       lhs.is_import == rhs.is_import &&
                       lhs.callee_name == rhs.callee_name;
            }
        ),
        edges.end()
    );
}

std::optional<std::int64_t> constant_of_value(
    const ir::Value& value,
    const std::unordered_map<std::string, std::int64_t>& constants
) {
    if (value.kind == ir::ValueKind::Immediate) {
        return value.immediate;
    }

    if ((value.kind == ir::ValueKind::Register || value.kind == ir::ValueKind::Temporary) && !value.name.empty()) {
        const auto it = constants.find(value.name);
        if (it != constants.end()) {
            return it->second;
        }
    }

    return std::nullopt;
}

std::optional<std::int64_t> evaluate_binary(
    const ir::BinaryOperator operation,
    const std::int64_t lhs,
    const std::int64_t rhs
) {
    switch (operation) {
    case ir::BinaryOperator::Add:
        return lhs + rhs;
    case ir::BinaryOperator::Sub:
        return lhs - rhs;
    case ir::BinaryOperator::And:
        return lhs & rhs;
    case ir::BinaryOperator::Or:
        return lhs | rhs;
    case ir::BinaryOperator::Xor:
        return lhs ^ rhs;
    default:
        return std::nullopt;
    }
}

std::optional<bool> evaluate_branch_condition(const std::string& mnemonic, const KnownCondition& condition) {
    const std::string lowered = lowercase_copy(mnemonic);
    const auto lhs = condition.lhs;
    const auto rhs = condition.rhs;

    if (condition.kind == KnownCondition::Kind::Test) {
        const auto tested = lhs & rhs;
        if (lowered == "je" || lowered == "jz") {
            return tested == 0;
        }
        if (lowered == "jne" || lowered == "jnz") {
            return tested != 0;
        }
    }

    if (lowered == "je" || lowered == "jz") {
        return lhs == rhs;
    }
    if (lowered == "jne" || lowered == "jnz") {
        return lhs != rhs;
    }
    if (lowered == "ja") {
        return static_cast<std::uint64_t>(lhs) > static_cast<std::uint64_t>(rhs);
    }
    if (lowered == "jae" || lowered == "jnb") {
        return static_cast<std::uint64_t>(lhs) >= static_cast<std::uint64_t>(rhs);
    }
    if (lowered == "jb" || lowered == "jc") {
        return static_cast<std::uint64_t>(lhs) < static_cast<std::uint64_t>(rhs);
    }
    if (lowered == "jbe") {
        return static_cast<std::uint64_t>(lhs) <= static_cast<std::uint64_t>(rhs);
    }
    if (lowered == "jg") {
        return lhs > rhs;
    }
    if (lowered == "jge") {
        return lhs >= rhs;
    }
    if (lowered == "jl") {
        return lhs < rhs;
    }
    if (lowered == "jle") {
        return lhs <= rhs;
    }

    return std::nullopt;
}

bool is_ssa_name_value(const ir::Value& value) {
    return (value.kind == ir::ValueKind::Register || value.kind == ir::ValueKind::Temporary) && !value.name.empty();
}

void collect_names_from_value(const ir::Value& value, std::unordered_set<std::string>& out_names) {
    if (is_ssa_name_value(value)) {
        out_names.insert(value.name);
    }

    if (value.kind == ir::ValueKind::MemoryAddress) {
        if (!value.memory.base.empty()) {
            out_names.insert(value.memory.base);
        }
        if (!value.memory.index.empty()) {
            out_names.insert(value.memory.index);
        }
    }
}

bool equivalent_values(const ir::Value& lhs, const ir::Value& rhs) {
    return lhs.kind == rhs.kind &&
           lhs.type == rhs.type &&
           lhs.name == rhs.name &&
           lhs.immediate == rhs.immediate &&
           lhs.memory.segment == rhs.memory.segment &&
           lhs.memory.base == rhs.memory.base &&
           lhs.memory.index == rhs.memory.index &&
           lhs.memory.displacement == rhs.memory.displacement &&
           lhs.memory.scale == rhs.memory.scale;
}

ir::ScalarType merged_copy_type(const ir::ScalarType replacement, const ir::ScalarType original) {
    if (replacement == ir::ScalarType::Unknown) {
        return original;
    }
    if (original == ir::ScalarType::Unknown || original == replacement) {
        return replacement;
    }
    return merge_type(replacement, original);
}

ir::Value resolve_copy_value(
    ir::Value value,
    const std::unordered_map<std::string, ir::Value>& replacements
) {
    std::unordered_set<std::string> visited;
    while (is_ssa_name_value(value)) {
        if (!visited.insert(value.name).second) {
            break;
        }
        const auto replacement_it = replacements.find(value.name);
        if (replacement_it == replacements.end()) {
            break;
        }

        ir::Value replacement = replacement_it->second;
        replacement.type = merged_copy_type(replacement.type, value.type);
        value = std::move(replacement);
    }

    return value;
}

std::size_t rewrite_memory_address(
    ir::MemoryAddress& address,
    const std::unordered_map<std::string, ir::Value>& replacements,
    const loader::Architecture architecture,
    const std::unordered_set<std::string>& protected_families
) {
    std::size_t substitutions = 0;

    auto rewrite_component = [&](std::string& name) {
        if (name.empty()) {
            return;
        }
        if (protected_families.contains(normalize_register_family(name, architecture))) {
            return;
        }

        ir::Value resolved = resolve_copy_value(
            ir::Value{
                .kind = ir::ValueKind::Register,
                .type = ir::ScalarType::Unknown,
                .name = name,
                .memory = {},
            },
            replacements
        );

        if (is_ssa_name_value(resolved) && resolved.name != name) {
            name = resolved.name;
            ++substitutions;
        }
    };

    rewrite_component(address.base);
    rewrite_component(address.index);
    return substitutions;
}

std::unordered_set<std::string> protected_register_families(const loader::Architecture architecture) {
    std::unordered_set<std::string> families{
        stack_pointer_name(architecture),
        frame_pointer_name(architecture),
    };

    const auto return_register = return_register_name(architecture);
    if (!return_register.empty()) {
        families.insert(return_register);
    }

    for (const auto& argument_register : argument_registers(architecture)) {
        families.insert(argument_register);
    }

    return families;
}

bool is_protected_definition(
    const ir::Value& destination,
    const loader::Architecture architecture,
    const std::unordered_set<std::string>& protected_families
) {
    if (destination.kind != ir::ValueKind::Register || destination.name.empty()) {
        return false;
    }

    return protected_families.contains(normalize_register_family(destination.name, architecture));
}

void recompute_ssa_metadata(ssa::Function& function) {
    std::unordered_map<std::uint64_t, std::size_t> block_index_by_address;
    for (std::size_t index = 0; index < function.blocks.size(); ++index) {
        block_index_by_address[function.blocks[index].start_address] = index;
        function.blocks[index].predecessors.clear();
    }

    for (auto& block : function.blocks) {
        std::vector<std::uint64_t> filtered_successors;
        for (const auto successor : block.successors) {
            if (block_index_by_address.contains(successor)) {
                filtered_successors.push_back(successor);
            }
        }
        std::sort(filtered_successors.begin(), filtered_successors.end());
        filtered_successors.erase(std::unique(filtered_successors.begin(), filtered_successors.end()), filtered_successors.end());
        block.successors = std::move(filtered_successors);

        for (const auto successor : block.successors) {
            function.blocks[block_index_by_address.at(successor)].predecessors.push_back(block.start_address);
        }
    }

    for (auto& block : function.blocks) {
        std::sort(block.predecessors.begin(), block.predecessors.end());
        block.predecessors.erase(std::unique(block.predecessors.begin(), block.predecessors.end()), block.predecessors.end());
        for (auto& phi : block.phi_nodes) {
            phi.incoming.erase(
                std::remove_if(
                    phi.incoming.begin(),
                    phi.incoming.end(),
                    [&](const auto& incoming) {
                        return std::find(block.predecessors.begin(), block.predecessors.end(), incoming.first) ==
                               block.predecessors.end();
                    }
                ),
                phi.incoming.end()
            );
        }
    }

    function.immediate_dominators.clear();
    if (function.blocks.empty()) {
        return;
    }

    using AddressSet = std::set<std::uint64_t>;
    AddressSet all_blocks;
    for (const auto& block : function.blocks) {
        all_blocks.insert(block.start_address);
    }

    std::unordered_map<std::uint64_t, AddressSet> dominators;
    for (const auto& block : function.blocks) {
        dominators[block.start_address] =
            block.start_address == function.entry_address ? AddressSet{block.start_address} : all_blocks;
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& block : function.blocks) {
            if (block.start_address == function.entry_address) {
                continue;
            }

            AddressSet next = all_blocks;
            if (block.predecessors.empty()) {
                next.clear();
            } else {
                bool first = true;
                for (const auto predecessor : block.predecessors) {
                    if (first) {
                        next = dominators[predecessor];
                        first = false;
                        continue;
                    }

                    AddressSet intersection;
                    std::set_intersection(
                        next.begin(),
                        next.end(),
                        dominators[predecessor].begin(),
                        dominators[predecessor].end(),
                        std::inserter(intersection, intersection.begin())
                    );
                    next = std::move(intersection);
                }
            }

            next.insert(block.start_address);
            if (dominators[block.start_address] != next) {
                dominators[block.start_address] = std::move(next);
                changed = true;
            }
        }
    }

    for (const auto& block : function.blocks) {
        if (block.start_address == function.entry_address) {
            continue;
        }

        std::optional<std::uint64_t> idom;
        for (const auto candidate : dominators[block.start_address]) {
            if (candidate == block.start_address) {
                continue;
            }

            bool dominated_by_other_candidate = false;
            for (const auto other : dominators[block.start_address]) {
                if (other == block.start_address || other == candidate) {
                    continue;
                }
                if (dominators[other].contains(candidate)) {
                    dominated_by_other_candidate = true;
                    break;
                }
            }

            if (!dominated_by_other_candidate) {
                idom = candidate;
                break;
            }
        }

        if (idom.has_value()) {
            function.immediate_dominators.emplace_back(block.start_address, *idom);
        }
    }

    std::sort(function.immediate_dominators.begin(), function.immediate_dominators.end());
}

std::size_t remove_unreachable_ssa_blocks(ssa::Function& function) {
    std::unordered_map<std::uint64_t, const ssa::BasicBlock*> blocks_by_address;
    for (const auto& block : function.blocks) {
        blocks_by_address.emplace(block.start_address, &block);
    }

    std::vector<std::uint64_t> stack{function.entry_address};
    std::unordered_set<std::uint64_t> reachable;
    while (!stack.empty()) {
        const auto block_start = stack.back();
        stack.pop_back();

        if (!reachable.insert(block_start).second) {
            continue;
        }

        const auto block_it = blocks_by_address.find(block_start);
        if (block_it == blocks_by_address.end()) {
            continue;
        }

        for (const auto successor : block_it->second->successors) {
            stack.push_back(successor);
        }
    }

    const auto before = function.blocks.size();
    function.blocks.erase(
        std::remove_if(
            function.blocks.begin(),
            function.blocks.end(),
            [&](const ssa::BasicBlock& block) { return !reachable.contains(block.start_address); }
        ),
        function.blocks.end()
    );
    recompute_ssa_metadata(function);
    return before - function.blocks.size();
}

SimplificationResult simplify_ssa_with_constants(ssa::Function& function, std::vector<ConstantValue>& out_constants) {
    std::unordered_map<std::string, std::int64_t> constants;
    std::unordered_map<std::string, KnownCondition> conditions;
    std::size_t rewrites_applied = 0;

    bool changed = true;
    while (changed) {
        changed = false;

        for (const auto& block : function.blocks) {
            for (const auto& phi : block.phi_nodes) {
                if (phi.result_name.empty() || phi.incoming.empty()) {
                    continue;
                }

                std::optional<std::int64_t> constant;
                bool valid = true;
                for (const auto& incoming : phi.incoming) {
                    const auto incoming_it = constants.find(incoming.second);
                    if (incoming_it == constants.end()) {
                        valid = false;
                        break;
                    }
                    if (!constant.has_value()) {
                        constant = incoming_it->second;
                        continue;
                    }
                    if (*constant != incoming_it->second) {
                        valid = false;
                        break;
                    }
                }

                if (valid && constant.has_value() && constants[phi.result_name] != *constant) {
                    constants[phi.result_name] = *constant;
                    changed = true;
                }
            }

            for (const auto& instruction : block.instructions) {
                if (!instruction.destination.has_value() || instruction.destination->name.empty()) {
                    continue;
                }

                const auto& destination_name = instruction.destination->name;
                switch (instruction.kind) {
                case ir::InstructionKind::Assign:
                    if (!instruction.inputs.empty()) {
                        if (const auto constant = constant_of_value(instruction.inputs.front(), constants); constant.has_value()) {
                            if (constants[destination_name] != *constant) {
                                constants[destination_name] = *constant;
                                changed = true;
                            }
                        }
                    }
                    break;
                case ir::InstructionKind::Binary:
                    if (instruction.binary_operator.has_value() && instruction.inputs.size() >= 2) {
                        const auto lhs = constant_of_value(instruction.inputs[0], constants);
                        const auto rhs = constant_of_value(instruction.inputs[1], constants);
                        if (lhs.has_value() && rhs.has_value()) {
                            if (const auto value = evaluate_binary(*instruction.binary_operator, *lhs, *rhs);
                                value.has_value() && constants[destination_name] != *value) {
                                constants[destination_name] = *value;
                                changed = true;
                            }
                        }
                    }
                    break;
                case ir::InstructionKind::Compare:
                case ir::InstructionKind::Test:
                    if (instruction.inputs.size() >= 2) {
                        const auto lhs = constant_of_value(instruction.inputs[0], constants);
                        const auto rhs = constant_of_value(instruction.inputs[1], constants);
                        if (lhs.has_value() && rhs.has_value()) {
                            conditions[destination_name] = KnownCondition{
                                .kind =
                                    instruction.kind == ir::InstructionKind::Compare
                                        ? KnownCondition::Kind::Compare
                                        : KnownCondition::Kind::Test,
                                .lhs = *lhs,
                                .rhs = *rhs,
                            };
                        }
                    }
                    break;
                case ir::InstructionKind::Load:
                case ir::InstructionKind::Store:
                case ir::InstructionKind::SetFlags:
                case ir::InstructionKind::Call:
                case ir::InstructionKind::Branch:
                case ir::InstructionKind::CondBranch:
                case ir::InstructionKind::Return:
                case ir::InstructionKind::Nop:
                case ir::InstructionKind::Intrinsic:
                default:
                    break;
                }
            }
        }
    }

    out_constants.clear();
    out_constants.reserve(constants.size());
    for (const auto& [name, value] : constants) {
        if (!name.empty()) {
            out_constants.push_back(ConstantValue{.name = name, .value = value});
        }
    }
    std::sort(
        out_constants.begin(),
        out_constants.end(),
        [](const ConstantValue& lhs, const ConstantValue& rhs) { return lhs.name < rhs.name; }
    );

    for (auto& block : function.blocks) {
        for (auto& instruction : block.instructions) {
            for (auto& input : instruction.inputs) {
                if ((input.kind == ir::ValueKind::Register || input.kind == ir::ValueKind::Temporary) && !input.name.empty()) {
                    const auto constant_it = constants.find(input.name);
                    if (constant_it != constants.end()) {
                        const ir::Value rewritten = make_immediate_value(constant_it->second, input.type);
                        if (!equivalent_values(input, rewritten)) {
                            input = rewritten;
                            ++rewrites_applied;
                        }
                    }
                }
            }

            if (instruction.destination.has_value() &&
                !instruction.destination->name.empty() &&
                constants.contains(instruction.destination->name) &&
                (instruction.kind == ir::InstructionKind::Assign || instruction.kind == ir::InstructionKind::Binary)) {
                const bool changed_kind = instruction.kind != ir::InstructionKind::Assign;
                const bool changed_inputs = instruction.inputs.size() != 1 ||
                                            instruction.inputs.front().kind != ir::ValueKind::Immediate ||
                                            instruction.inputs.front().immediate != constants.at(instruction.destination->name);
                instruction.kind = ir::InstructionKind::Assign;
                instruction.inputs = {
                    make_immediate_value(constants.at(instruction.destination->name), instruction.destination->type)
                };
                instruction.binary_operator.reset();
                instruction.text = "constant folded";
                if (changed_kind || changed_inputs) {
                    ++rewrites_applied;
                }
            }

            if (instruction.kind == ir::InstructionKind::CondBranch) {
                std::optional<bool> branch_result;
                if (!instruction.inputs.empty()) {
                    if (instruction.inputs.front().kind == ir::ValueKind::Immediate) {
                        branch_result = instruction.inputs.front().immediate != 0;
                    } else if (!instruction.inputs.front().name.empty()) {
                        const auto condition_it = conditions.find(instruction.inputs.front().name);
                        if (condition_it != conditions.end()) {
                            branch_result = evaluate_branch_condition(instruction.text, condition_it->second);
                        }
                    }
                }

                if (branch_result.has_value()) {
                    instruction.kind = ir::InstructionKind::Branch;
                    instruction.true_target = *branch_result ? instruction.true_target : instruction.false_target;
                    instruction.false_target.reset();
                    instruction.inputs.clear();
                    instruction.text = "constant-folded branch";
                    ++rewrites_applied;
                }
            }
        }

        if (!block.instructions.empty()) {
            const auto& terminator = block.instructions.back();
            switch (terminator.kind) {
            case ir::InstructionKind::Branch:
                block.successors.clear();
                if (terminator.true_target.has_value()) {
                    block.successors.push_back(*terminator.true_target);
                }
                break;
            case ir::InstructionKind::CondBranch:
                block.successors.clear();
                if (terminator.true_target.has_value()) {
                    block.successors.push_back(*terminator.true_target);
                }
                if (terminator.false_target.has_value()) {
                    block.successors.push_back(*terminator.false_target);
                }
                break;
            case ir::InstructionKind::Return:
                block.successors.clear();
                break;
            default:
                break;
            }
        }
    }

    recompute_ssa_metadata(function);
    return SimplificationResult{
        .unreachable_blocks_removed = remove_unreachable_ssa_blocks(function),
        .rewrites_applied = rewrites_applied,
    };
}

std::size_t propagate_ssa_copies(ssa::Function& function, const loader::Architecture architecture) {
    std::unordered_map<std::string, ir::Value> replacements;
    const auto protected_families = protected_register_families(architecture);

    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) {
            if (instruction.kind != ir::InstructionKind::Assign ||
                !instruction.destination.has_value() ||
                !is_ssa_name_value(*instruction.destination) ||
                instruction.inputs.size() != 1) {
                continue;
            }

            ir::Value replacement = resolve_copy_value(instruction.inputs.front(), replacements);
            replacement.type = merged_copy_type(replacement.type, instruction.destination->type);
            replacements[instruction.destination->name] = std::move(replacement);
        }
    }

    if (replacements.empty()) {
        return 0;
    }

    std::size_t substitutions = 0;
    for (auto& block : function.blocks) {
        for (auto& phi : block.phi_nodes) {
            for (auto& incoming : phi.incoming) {
                ir::Value resolved = resolve_copy_value(
                    ir::Value{
                        .kind = ir::ValueKind::Temporary,
                        .type = ir::ScalarType::Unknown,
                        .name = incoming.second,
                        .memory = {},
                    },
                    replacements
                );
                if (is_ssa_name_value(resolved) && resolved.name != incoming.second) {
                    incoming.second = resolved.name;
                    ++substitutions;
                }
            }
        }

        for (auto& instruction : block.instructions) {
            for (auto& input : instruction.inputs) {
                if (input.kind == ir::ValueKind::MemoryAddress) {
                    substitutions += rewrite_memory_address(input.memory, replacements, architecture, protected_families);
                    continue;
                }

                const ir::Value resolved = resolve_copy_value(input, replacements);
                if (!equivalent_values(input, resolved)) {
                    input = resolved;
                    ++substitutions;
                }
            }

            if (instruction.destination.has_value() && instruction.destination->kind == ir::ValueKind::MemoryAddress) {
                substitutions +=
                    rewrite_memory_address(instruction.destination->memory, replacements, architecture, protected_families);
            }
        }
    }

    return substitutions;
}

bool is_dead_code_candidate(const ir::Instruction& instruction) {
    switch (instruction.kind) {
    case ir::InstructionKind::Assign:
    case ir::InstructionKind::Load:
    case ir::InstructionKind::Binary:
    case ir::InstructionKind::Nop:
        return true;
    case ir::InstructionKind::Compare:
    case ir::InstructionKind::Test:
    case ir::InstructionKind::SetFlags:
    case ir::InstructionKind::Store:
    case ir::InstructionKind::Call:
    case ir::InstructionKind::Branch:
    case ir::InstructionKind::CondBranch:
    case ir::InstructionKind::Return:
    case ir::InstructionKind::Intrinsic:
    default:
        return false;
    }
}

std::size_t eliminate_dead_ssa_instructions(ssa::Function& function, const loader::Architecture architecture) {
    const auto protected_families = protected_register_families(architecture);
    std::size_t removed_total = 0;

    while (true) {
        std::unordered_set<std::string> used_names;
        for (const auto& block : function.blocks) {
            for (const auto& phi : block.phi_nodes) {
                for (const auto& incoming : phi.incoming) {
                    if (!incoming.second.empty()) {
                        used_names.insert(incoming.second);
                    }
                }
            }

            for (const auto& instruction : block.instructions) {
                for (const auto& input : instruction.inputs) {
                    collect_names_from_value(input, used_names);
                }
                if (instruction.destination.has_value() && instruction.destination->kind == ir::ValueKind::MemoryAddress) {
                    collect_names_from_value(*instruction.destination, used_names);
                }
            }
        }

        std::size_t removed_this_round = 0;
        for (auto& block : function.blocks) {
            const auto phi_before = block.phi_nodes.size();
            block.phi_nodes.erase(
                std::remove_if(
                    block.phi_nodes.begin(),
                    block.phi_nodes.end(),
                    [&](const ssa::PhiNode& phi) {
                        if (phi.result_name.empty()) {
                            return false;
                        }

                        const ir::Value destination{
                            .kind = ir::ValueKind::Register,
                            .type = ir::ScalarType::Unknown,
                            .name = phi.result_name,
                            .memory = {},
                        };
                        return !used_names.contains(phi.result_name) &&
                               !is_protected_definition(destination, architecture, protected_families);
                    }
                ),
                block.phi_nodes.end()
            );
            removed_this_round += phi_before - block.phi_nodes.size();

            const auto instruction_before = block.instructions.size();
            block.instructions.erase(
                std::remove_if(
                    block.instructions.begin(),
                    block.instructions.end(),
                    [&](const ir::Instruction& instruction) {
                        if (instruction.kind == ir::InstructionKind::Nop) {
                            return true;
                        }
                        if (!is_dead_code_candidate(instruction) ||
                            !instruction.destination.has_value() ||
                            !is_ssa_name_value(*instruction.destination)) {
                            return false;
                        }

                        return !used_names.contains(instruction.destination->name) &&
                               !is_protected_definition(*instruction.destination, architecture, protected_families);
                    }
                ),
                block.instructions.end()
            );
            removed_this_round += instruction_before - block.instructions.size();
        }

        if (removed_this_round == 0) {
            break;
        }
        removed_total += removed_this_round;
    }

    if (removed_total > 0) {
        recompute_ssa_metadata(function);
    }
    return removed_total;
}

std::string stack_pointer_name(const loader::Architecture architecture) {
    switch (architecture) {
    case loader::Architecture::X86:
        return "esp";
    case loader::Architecture::X86_64:
        return "rsp";
    case loader::Architecture::ARM:
    case loader::Architecture::ARM64:
    case loader::Architecture::RISCV64:
    case loader::Architecture::MIPS64:
        return "sp";
    case loader::Architecture::PPC64:
        return "r1";
    case loader::Architecture::Unknown:
    default:
        return "sp";
    }
}

std::string frame_pointer_name(const loader::Architecture architecture) {
    switch (architecture) {
    case loader::Architecture::X86:
        return "ebp";
    case loader::Architecture::X86_64:
        return "rbp";
    case loader::Architecture::ARM:
        return "fp";
    case loader::Architecture::ARM64:
        return "x29";
    case loader::Architecture::RISCV64:
        return "s0";
    case loader::Architecture::MIPS64:
        return "fp";
    case loader::Architecture::PPC64:
        return "r31";
    case loader::Architecture::Unknown:
    default:
        return "bp";
    }
}

std::string return_register_name(const loader::Architecture architecture) {
    switch (architecture) {
    case loader::Architecture::X86:
        return "eax";
    case loader::Architecture::X86_64:
        return "rax";
    case loader::Architecture::ARM:
        return "r0";
    case loader::Architecture::ARM64:
        return "x0";
    case loader::Architecture::RISCV64:
        return "a0";
    case loader::Architecture::MIPS64:
        return "v0";
    case loader::Architecture::PPC64:
        return "r3";
    case loader::Architecture::Unknown:
    default:
        return {};
    }
}

CallingConvention default_calling_convention(const loader::Architecture architecture) {
    switch (architecture) {
    case loader::Architecture::X86:
        return CallingConvention::Cdecl32;
    case loader::Architecture::X86_64:
        return CallingConvention::SysVAMD64;
    case loader::Architecture::ARM:
        return CallingConvention::AAPCS32;
    case loader::Architecture::ARM64:
        return CallingConvention::AAPCS64;
    case loader::Architecture::RISCV64:
        return CallingConvention::RiscV64SysV;
    case loader::Architecture::MIPS64:
        return CallingConvention::MipsN64;
    case loader::Architecture::PPC64:
        return CallingConvention::Ppc64ElfV2;
    case loader::Architecture::Unknown:
    default:
        return CallingConvention::Unknown;
    }
}

std::vector<std::string> argument_registers(const loader::Architecture architecture) {
    switch (architecture) {
    case loader::Architecture::ARM:
        return {"r0", "r1", "r2", "r3"};
    case loader::Architecture::X86_64:
        return {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
    case loader::Architecture::ARM64:
        return {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
    case loader::Architecture::RISCV64:
        return {"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"};
    case loader::Architecture::MIPS64:
        return {"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"};
    case loader::Architecture::PPC64:
        return {"r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"};
    case loader::Architecture::X86:
    case loader::Architecture::Unknown:
    default:
        return {};
    }
}

FunctionAnalysisSummary build_function_summary(
    const loader::BinaryImage& image,
    const cfg::FunctionGraph& graph,
    const loader::Architecture architecture,
    const ssa::Function& ssa_form,
    const type::FunctionTypes& recovered_types,
    const std::vector<ConstantValue>& constants,
    const std::size_t removed_unreachable_blocks,
    const std::size_t copy_propagations_applied,
    const std::size_t dead_instructions_eliminated
) {
    FunctionAnalysisSummary summary;
    summary.constants = constants;
    summary.unreachable_blocks_removed = graph.unreachable_blocks_removed() + removed_unreachable_blocks;
    summary.copy_propagations_applied = copy_propagations_applied;
    summary.dead_instructions_eliminated = dead_instructions_eliminated;
    summary.cfg_linear_merges = graph.linear_block_merges();
    summary.calling_convention = default_calling_convention(architecture);

    std::unordered_map<std::string, ir::ScalarType> type_by_base;
    for (const auto& variable : recovered_types.variables) {
        const auto name = normalize_register_family(variable.name, architecture);
        type_by_base[name] = merge_type(type_by_base[name], variable.type);
        if (variable.type == ir::ScalarType::Pointer) {
            summary.pointer_variables.push_back(name);
        }
    }

    const auto pointer_width = type_size(ir::ScalarType::Pointer, architecture);
    const auto stack_pointer = stack_pointer_name(architecture);
    const auto frame_pointer = frame_pointer_name(architecture);
    const auto return_register = return_register_name(architecture);
    const auto argument_regs = argument_registers(architecture);

    std::unordered_map<std::string, std::int64_t> stack_offsets;
    stack_offsets[stack_pointer + ".0"] = 0;
    std::unordered_map<std::int64_t, LocalVariable> locals_by_offset;
    std::unordered_map<std::string, ArgumentInfo> arguments_by_location;
    std::unordered_set<std::string> defined_registers;

    auto observe_argument_register = [&](const ir::Value& value) {
        if (value.kind != ir::ValueKind::Register) {
            return;
        }

        const auto name = normalize_register_family(value.name, architecture);
        if (std::find(argument_regs.begin(), argument_regs.end(), name) == argument_regs.end()) {
            return;
        }
        if (defined_registers.contains(name)) {
            return;
        }

        arguments_by_location.try_emplace(
            name,
            ArgumentInfo{
                .name = "arg_" + std::to_string(arguments_by_location.size()),
                .location = name,
                .type = type_by_base.contains(name) ? type_by_base.at(name) : ir::ScalarType::Unknown,
            }
        );
    };

    auto observe_memory = [&](const ir::Value& value, const ir::ScalarType associated_type) {
        if (value.kind != ir::ValueKind::MemoryAddress) {
            return;
        }

        if (!value.memory.base.empty()) {
            summary.pointer_variables.push_back(normalize_register_family(value.memory.base, architecture));
        }
        if (!value.memory.index.empty()) {
            summary.pointer_variables.push_back(normalize_register_family(value.memory.index, architecture));
        }

        const auto base = normalize_register_family(value.memory.base, architecture);
        if (base == frame_pointer && value.memory.displacement < 0) {
            auto& local = locals_by_offset[value.memory.displacement];
            local.stack_offset = value.memory.displacement;
            local.name = "local_" + std::to_string(-value.memory.displacement);
            local.type = merge_type(local.type, associated_type);
            local.size = std::max(local.size, type_size(associated_type, architecture));
        }

        if (summary.calling_convention == CallingConvention::Cdecl32 &&
            base == frame_pointer &&
            value.memory.displacement >= static_cast<std::int64_t>(pointer_width * 2)) {
            const auto slot = static_cast<std::size_t>((value.memory.displacement - static_cast<std::int64_t>(pointer_width * 2)) / pointer_width);
            const std::string location = "[ebp+" + std::to_string(value.memory.displacement) + "]";
            arguments_by_location.try_emplace(
                location,
                ArgumentInfo{
                    .name = "arg_" + std::to_string(slot),
                    .location = location,
                    .type = associated_type,
                }
            );
        }
    };

    for (const auto& block : ssa_form.blocks) {
        for (const auto& instruction : block.instructions) {
            for (const auto& input : instruction.inputs) {
                observe_argument_register(input);
                observe_memory(input, input.type);
            }

            if (instruction.destination.has_value()) {
                const auto& destination = *instruction.destination;
                observe_memory(destination, destination.type);

                if ((destination.kind == ir::ValueKind::Register || destination.kind == ir::ValueKind::Temporary) &&
                    !destination.name.empty()) {
                    const auto destination_base = normalize_register_family(destination.name, architecture);

                    if (destination.kind == ir::ValueKind::Register) {
                        defined_registers.insert(destination_base);
                    }

                    if (instruction.kind == ir::InstructionKind::Assign && instruction.inputs.size() == 1) {
                        const auto& source = instruction.inputs.front();
                        if ((source.kind == ir::ValueKind::Register || source.kind == ir::ValueKind::Temporary) &&
                            !source.name.empty()) {
                            const auto offset_it = stack_offsets.find(source.name);
                            if (offset_it != stack_offsets.end()) {
                                stack_offsets[destination.name] = offset_it->second;
                                if (destination_base == stack_pointer) {
                                    summary.stack_pointer_states.push_back(
                                        StackPointerState{
                                            .address = instruction.address,
                                            .offset = offset_it->second,
                                        }
                                    );
                                    if (offset_it->second < 0) {
                                        summary.stack_frame_size = std::max(summary.stack_frame_size, -offset_it->second);
                                    }
                                }
                                if (destination_base == frame_pointer) {
                                    summary.uses_frame_pointer = true;
                                }
                            }
                        }
                    }

                    if (instruction.kind == ir::InstructionKind::Binary &&
                        instruction.binary_operator.has_value() &&
                        instruction.inputs.size() >= 2 &&
                        (instruction.inputs[0].kind == ir::ValueKind::Register ||
                         instruction.inputs[0].kind == ir::ValueKind::Temporary) &&
                        !instruction.inputs[0].name.empty() &&
                        instruction.inputs[1].kind == ir::ValueKind::Immediate) {
                        const auto offset_it = stack_offsets.find(instruction.inputs[0].name);
                        if (offset_it != stack_offsets.end()) {
                            std::int64_t next_offset = offset_it->second;
                            if (*instruction.binary_operator == ir::BinaryOperator::Add) {
                                next_offset += instruction.inputs[1].immediate;
                            } else if (*instruction.binary_operator == ir::BinaryOperator::Sub) {
                                next_offset -= instruction.inputs[1].immediate;
                            }

                            stack_offsets[destination.name] = next_offset;
                            if (destination_base == stack_pointer) {
                                summary.stack_pointer_states.push_back(
                                    StackPointerState{
                                        .address = instruction.address,
                                        .offset = next_offset,
                                    }
                                );
                                if (next_offset < 0) {
                                    summary.stack_frame_size = std::max(summary.stack_frame_size, -next_offset);
                                }
                            }
                        }
                    }

                    if (!return_register.empty() && destination_base == return_register) {
                        summary.return_value = ReturnInfo{
                            .location = return_register,
                            .type = merge_type(
                                type_by_base.contains(return_register) ? type_by_base.at(return_register) : ir::ScalarType::Unknown,
                                destination.type
                            ),
                        };
                    }
                }
            }
        }
    }

    for (const auto& [offset, local] : locals_by_offset) {
        LocalVariable finalized = local;
        if (finalized.type == ir::ScalarType::Unknown) {
            finalized.type = ir::ScalarType::I64;
        }
        if (finalized.size == 0) {
            finalized.size = type_size(finalized.type, architecture);
        }
        summary.locals.push_back(std::move(finalized));
    }

    std::sort(
        summary.locals.begin(),
        summary.locals.end(),
        [](const LocalVariable& lhs, const LocalVariable& rhs) { return lhs.stack_offset < rhs.stack_offset; }
    );

    for (const auto& [_, argument] : arguments_by_location) {
        summary.arguments.push_back(argument);
    }
    std::sort(
        summary.arguments.begin(),
        summary.arguments.end(),
        [](const ArgumentInfo& lhs, const ArgumentInfo& rhs) { return lhs.location < rhs.location; }
    );

    for (const auto& block : graph.blocks()) {
        for (const auto& instruction : block.instructions) {
            if ((instruction.kind != disasm::InstructionKind::Call &&
                 instruction.kind != disasm::InstructionKind::Jump) ||
                instruction.control_flow_target.has_value()) {
                continue;
            }

            for (const auto reference : instruction.data_references) {
                if (const auto* imported = find_import_for_address(image, reference); imported != nullptr) {
                    summary.indirect_resolutions.push_back(
                        IndirectResolution{
                            .instruction_address = instruction.address,
                            .resolved_target = reference,
                            .label = format_import_name(*imported),
                        }
                    );
                }
            }
        }
    }

    for (const auto& switch_info : graph.switches()) {
        for (const auto& switch_case : switch_info.cases) {
            summary.indirect_resolutions.push_back(
                IndirectResolution{
                    .instruction_address = switch_info.jump_address,
                    .resolved_target = switch_case.target,
                    .label = "case_" + std::to_string(switch_case.value),
                }
            );
        }
        if (switch_info.default_target.has_value()) {
            summary.indirect_resolutions.push_back(
                IndirectResolution{
                    .instruction_address = switch_info.jump_address,
                    .resolved_target = *switch_info.default_target,
                    .label = "default",
                }
            );
        }
    }

    std::sort(summary.pointer_variables.begin(), summary.pointer_variables.end());
    summary.pointer_variables.erase(
        std::unique(summary.pointer_variables.begin(), summary.pointer_variables.end()),
        summary.pointer_variables.end()
    );

    std::sort(
        summary.stack_pointer_states.begin(),
        summary.stack_pointer_states.end(),
        [](const StackPointerState& lhs, const StackPointerState& rhs) { return lhs.address < rhs.address; }
    );

    std::sort(
        summary.indirect_resolutions.begin(),
        summary.indirect_resolutions.end(),
        [](const IndirectResolution& lhs, const IndirectResolution& rhs) {
            if (lhs.instruction_address != rhs.instruction_address) {
                return lhs.instruction_address < rhs.instruction_address;
            }
            if (lhs.resolved_target != rhs.resolved_target) {
                return lhs.resolved_target < rhs.resolved_target;
            }
            return lhs.label < rhs.label;
        }
    );
    summary.indirect_resolutions.erase(
        std::unique(
            summary.indirect_resolutions.begin(),
            summary.indirect_resolutions.end(),
            [](const IndirectResolution& lhs, const IndirectResolution& rhs) {
                return lhs.instruction_address == rhs.instruction_address &&
                       lhs.resolved_target == rhs.resolved_target &&
                       lhs.label == rhs.label;
            }
        ),
        summary.indirect_resolutions.end()
    );

    return summary;
}

std::string basename_for_symbol(std::string value) {
    const std::size_t bang = value.rfind('!');
    if (bang != std::string::npos && bang + 1 < value.size()) {
        value = value.substr(bang + 1);
    }
    const std::size_t scope = value.rfind("::");
    if (scope != std::string::npos && scope + 2 < value.size()) {
        value = value.substr(scope + 2);
    }
    return value;
}

ir::ScalarType scalar_type_from_decl_type(std::string_view decl_type) {
    if (decl_type.empty()) {
        return ir::ScalarType::Unknown;
    }
    if (decl_type.find('*') != std::string_view::npos) {
        return ir::ScalarType::Pointer;
    }
    if (decl_type == "bool") {
        return ir::ScalarType::Bool;
    }
    if (decl_type == "int8_t") {
        return ir::ScalarType::I8;
    }
    if (decl_type == "int16_t") {
        return ir::ScalarType::I16;
    }
    if (decl_type == "int32_t") {
        return ir::ScalarType::I32;
    }
    if (decl_type == "int64_t" || decl_type == "size_t" || decl_type == "ssize_t") {
        return ir::ScalarType::I64;
    }
    if (decl_type == "uintptr_t") {
        return ir::ScalarType::Pointer;
    }
    return ir::ScalarType::Unknown;
}

bool merge_recovered_variable_type(
    type::FunctionTypes& recovered_types,
    const std::string& name,
    const ir::ScalarType incoming_type
) {
    if (name.empty() || incoming_type == ir::ScalarType::Unknown) {
        return false;
    }

    for (auto& variable : recovered_types.variables) {
        if (variable.name != name) {
            continue;
        }
        const auto merged = merge_type(variable.type, incoming_type);
        if (merged == variable.type) {
            return false;
        }
        variable.type = merged;
        return true;
    }

    recovered_types.variables.push_back(
        type::RecoveredVariable{
            .name = name,
            .type = incoming_type,
        }
    );
    return true;
}

bool merge_recovered_variable_family(
    type::FunctionTypes& recovered_types,
    const std::string& family_name,
    const loader::Architecture architecture,
    const ir::ScalarType incoming_type
) {
    if (family_name.empty() || incoming_type == ir::ScalarType::Unknown) {
        return false;
    }

    bool changed = false;
    bool matched = false;
    for (auto& variable : recovered_types.variables) {
        if (normalize_register_family(variable.name, architecture) != family_name) {
            continue;
        }
        matched = true;
        const auto merged = merge_type(variable.type, incoming_type);
        if (merged != variable.type) {
            variable.type = merged;
            changed = true;
        }
    }

    if (!matched) {
        recovered_types.variables.push_back(
            type::RecoveredVariable{
                .name = family_name,
                .type = incoming_type,
            }
        );
        changed = true;
    }
    return changed;
}

bool merge_recovered_struct_alias(
    type::FunctionTypes& recovered_types,
    const type::RecoveredStruct& source,
    const std::string& owner_name
) {
    auto existing_it = std::find_if(
        recovered_types.structs.begin(),
        recovered_types.structs.end(),
        [&](const type::RecoveredStruct& recovered) { return recovered.owner_name == owner_name; }
    );

    if (existing_it == recovered_types.structs.end()) {
        type::RecoveredStruct clone = source;
        clone.owner_name = owner_name;
        recovered_types.structs.push_back(std::move(clone));
        return true;
    }

    bool changed = false;
    existing_it->type_name = source.type_name;
    for (const auto& source_field : source.fields) {
        auto field_it = std::find_if(
            existing_it->fields.begin(),
            existing_it->fields.end(),
            [&](const type::RecoveredStructField& field) { return field.offset == source_field.offset; }
        );
        if (field_it == existing_it->fields.end()) {
            existing_it->fields.push_back(source_field);
            changed = true;
            continue;
        }

        const auto merged_type = merge_type(field_it->type, source_field.type);
        if (merged_type != field_it->type || field_it->size != source_field.size || field_it->name != source_field.name) {
            field_it->type = merged_type;
            field_it->size = std::max(field_it->size, source_field.size);
            if (!source_field.name.empty()) {
                field_it->name = source_field.name;
            }
            changed = true;
        }
    }
    return changed;
}

bool merge_recovered_array_alias(
    type::FunctionTypes& recovered_types,
    const type::RecoveredArray& source,
    const std::string& owner_name
) {
    auto existing_it = std::find_if(
        recovered_types.arrays.begin(),
        recovered_types.arrays.end(),
        [&](const type::RecoveredArray& recovered) { return recovered.owner_name == owner_name; }
    );

    if (existing_it == recovered_types.arrays.end()) {
        type::RecoveredArray clone = source;
        clone.owner_name = owner_name;
        recovered_types.arrays.push_back(std::move(clone));
        return true;
    }

    const auto merged_type = merge_type(existing_it->element_type, source.element_type);
    const bool changed =
        merged_type != existing_it->element_type ||
        existing_it->element_size != source.element_size ||
        existing_it->observed_elements != std::max(existing_it->observed_elements, source.observed_elements) ||
        existing_it->indexed_access != (existing_it->indexed_access || source.indexed_access) ||
        existing_it->type_name != source.type_name;

    existing_it->element_type = merged_type;
    existing_it->element_size = std::max(existing_it->element_size, source.element_size);
    existing_it->observed_elements = std::max(existing_it->observed_elements, source.observed_elements);
    existing_it->indexed_access = existing_it->indexed_access || source.indexed_access;
    existing_it->type_name = source.type_name;
    return changed;
}

bool clone_composites_for_owner(
    type::FunctionTypes& target,
    const type::FunctionTypes& source,
    std::string_view source_owner,
    const std::string& target_owner
) {
    bool changed = false;
    if (const auto* recovered_struct = type::find_struct_prefix(source, source_owner); recovered_struct != nullptr) {
        changed = merge_recovered_struct_alias(target, *recovered_struct, target_owner) || changed;
    }
    if (const auto* recovered_array = type::find_array_prefix(source, source_owner); recovered_array != nullptr) {
        changed = merge_recovered_array_alias(target, *recovered_array, target_owner) || changed;
    }
    return changed;
}

void normalize_recovered_types(type::FunctionTypes& recovered_types) {
    std::sort(
        recovered_types.variables.begin(),
        recovered_types.variables.end(),
        [](const type::RecoveredVariable& lhs, const type::RecoveredVariable& rhs) { return lhs.name < rhs.name; }
    );
    recovered_types.variables.erase(
        std::unique(
            recovered_types.variables.begin(),
            recovered_types.variables.end(),
            [](const type::RecoveredVariable& lhs, const type::RecoveredVariable& rhs) {
                return lhs.name == rhs.name && lhs.type == rhs.type;
            }
        ),
        recovered_types.variables.end()
    );

    for (auto& recovered_struct : recovered_types.structs) {
        std::sort(
            recovered_struct.fields.begin(),
            recovered_struct.fields.end(),
            [](const type::RecoveredStructField& lhs, const type::RecoveredStructField& rhs) {
                return lhs.offset < rhs.offset;
            }
        );
    }

    std::sort(
        recovered_types.structs.begin(),
        recovered_types.structs.end(),
        [](const type::RecoveredStruct& lhs, const type::RecoveredStruct& rhs) {
            return std::tie(lhs.owner_name, lhs.type_name) < std::tie(rhs.owner_name, rhs.type_name);
        }
    );
    recovered_types.structs.erase(
        std::unique(
            recovered_types.structs.begin(),
            recovered_types.structs.end(),
            [](const type::RecoveredStruct& lhs, const type::RecoveredStruct& rhs) {
                return lhs.owner_name == rhs.owner_name && lhs.type_name == rhs.type_name;
            }
        ),
        recovered_types.structs.end()
    );

    std::sort(
        recovered_types.arrays.begin(),
        recovered_types.arrays.end(),
        [](const type::RecoveredArray& lhs, const type::RecoveredArray& rhs) {
            return std::tie(lhs.owner_name, lhs.type_name) < std::tie(rhs.owner_name, rhs.type_name);
        }
    );
    recovered_types.arrays.erase(
        std::unique(
            recovered_types.arrays.begin(),
            recovered_types.arrays.end(),
            [](const type::RecoveredArray& lhs, const type::RecoveredArray& rhs) {
                return lhs.owner_name == rhs.owner_name && lhs.type_name == rhs.type_name;
            }
        ),
        recovered_types.arrays.end()
    );
}

ir::Instruction* find_instruction_by_address(ssa::Function& function, const std::uint64_t address) {
    for (auto& block : function.blocks) {
        for (auto& instruction : block.instructions) {
            if (instruction.address == address) {
                return &instruction;
            }
        }
    }
    return nullptr;
}

decompiler::CallTargetInfo generic_call_target_info(
    const std::string& display_name,
    const bool is_import
) {
    return decompiler::CallTargetInfo{
        .entry_address = std::nullopt,
        .display_name = basename_for_symbol(display_name),
        .return_type = "void",
        .arguments = {},
        .is_import = is_import,
    };
}

std::optional<decompiler::CallTargetInfo> known_import_signature(std::string imported_name) {
    imported_name = basename_for_symbol(std::move(imported_name));

    const auto make_pointer_arg = [](std::string name) {
        return decompiler::CallSignatureArgument{
            .name = std::move(name),
            .owner_name = {},
            .decl_type = "uintptr_t",
            .scalar_type = ir::ScalarType::Pointer,
        };
    };
    const auto make_size_arg = [](std::string name) {
        return decompiler::CallSignatureArgument{
            .name = std::move(name),
            .owner_name = {},
            .decl_type = "size_t",
            .scalar_type = ir::ScalarType::I64,
        };
    };

    if (imported_name == "puts" || imported_name == "strlen") {
        return decompiler::CallTargetInfo{
            .entry_address = std::nullopt,
            .display_name = imported_name,
            .return_type = imported_name == "puts" ? "int32_t" : "size_t",
            .arguments = {
                decompiler::CallSignatureArgument{
                    .name = "s",
                    .owner_name = {},
                    .decl_type = "const char*",
                    .scalar_type = ir::ScalarType::Pointer,
                },
            },
            .is_import = true,
        };
    }
    if (imported_name == "strcmp" || imported_name == "strncmp") {
        std::vector<decompiler::CallSignatureArgument> arguments{
            {.name = "lhs", .owner_name = {}, .decl_type = "const char*", .scalar_type = ir::ScalarType::Pointer},
            {.name = "rhs", .owner_name = {}, .decl_type = "const char*", .scalar_type = ir::ScalarType::Pointer},
        };
        if (imported_name == "strncmp") {
            arguments.push_back(make_size_arg("count"));
        }
        return decompiler::CallTargetInfo{
            .entry_address = std::nullopt,
            .display_name = imported_name,
            .return_type = "int32_t",
            .arguments = std::move(arguments),
            .is_import = true,
        };
    }
    if (imported_name == "memcpy" || imported_name == "memmove") {
        return decompiler::CallTargetInfo{
            .entry_address = std::nullopt,
            .display_name = imported_name,
            .return_type = "uintptr_t",
            .arguments = {make_pointer_arg("dst"), make_pointer_arg("src"), make_size_arg("count")},
            .is_import = true,
        };
    }
    if (imported_name == "memset") {
        return decompiler::CallTargetInfo{
            .entry_address = std::nullopt,
            .display_name = imported_name,
            .return_type = "uintptr_t",
            .arguments = {
                make_pointer_arg("dst"),
                {.name = "value", .owner_name = {}, .decl_type = "int32_t", .scalar_type = ir::ScalarType::I32},
                make_size_arg("count"),
            },
            .is_import = true,
        };
    }
    if (imported_name == "malloc") {
        return decompiler::CallTargetInfo{
            .entry_address = std::nullopt,
            .display_name = imported_name,
            .return_type = "uintptr_t",
            .arguments = {make_size_arg("size")},
            .is_import = true,
        };
    }
    if (imported_name == "free") {
        return decompiler::CallTargetInfo{
            .entry_address = std::nullopt,
            .display_name = imported_name,
            .return_type = "void",
            .arguments = {make_pointer_arg("ptr")},
            .is_import = true,
        };
    }
    if (imported_name == "read" || imported_name == "recv") {
        return decompiler::CallTargetInfo{
            .entry_address = std::nullopt,
            .display_name = imported_name,
            .return_type = "int64_t",
            .arguments = {
                {.name = "fd", .owner_name = {}, .decl_type = "int32_t", .scalar_type = ir::ScalarType::I32},
                make_pointer_arg("buf"),
                make_size_arg("count"),
            },
            .is_import = true,
        };
    }
    if (imported_name == "printf" || imported_name == "scanf" || imported_name == "system") {
        return decompiler::CallTargetInfo{
            .entry_address = std::nullopt,
            .display_name = imported_name,
            .return_type = "int32_t",
            .arguments = {
                {.name = "arg0", .owner_name = {}, .decl_type = "const char*", .scalar_type = ir::ScalarType::Pointer},
            },
            .is_import = true,
        };
    }

    return std::nullopt;
}

decompiler::CallTargetInfo build_function_call_target_info(const DiscoveredFunction& function) {
    decompiler::CallTargetInfo info;
    info.entry_address = function.entry_address;
    info.display_name = function.name;
    info.return_type =
        function.summary.return_value.has_value()
            ? type::render_decl_type_for_prefix(
                  function.recovered_types,
                  function.summary.return_value->location,
                  function.summary.return_value->type
              )
            : "void";

    for (const auto& argument : function.summary.arguments) {
        info.arguments.push_back(
            decompiler::CallSignatureArgument{
                .name = argument.name,
                .owner_name = argument.location,
                .decl_type = type::render_decl_type_for_prefix(
                    function.recovered_types,
                    argument.location,
                    argument.type
                ),
                .scalar_type = argument.type,
            }
        );
    }
    return info;
}

decompiler::ProgramMetadata build_program_metadata(const ProgramAnalysis& analysis) {
    decompiler::ProgramMetadata metadata;

    std::unordered_map<std::uint64_t, decompiler::CallTargetInfo> signatures_by_entry;
    for (const auto& function : analysis.functions) {
        if (!function.analysis_materialized) {
            continue;
        }
        signatures_by_entry.emplace(function.entry_address, build_function_call_target_info(function));
    }

    for (const auto& edge : analysis.call_graph) {
        if (edge.callee_entry.has_value()) {
            const auto signature_it = signatures_by_entry.find(*edge.callee_entry);
            if (signature_it != signatures_by_entry.end()) {
                metadata.call_targets_by_site.emplace(edge.call_site, signature_it->second);
                continue;
            }
        }

        if (edge.is_import) {
            metadata.call_targets_by_site.emplace(
                edge.call_site,
                known_import_signature(edge.callee_name).value_or(generic_call_target_info(edge.callee_name, true))
            );
            continue;
        }

        metadata.call_targets_by_site.emplace(
            edge.call_site,
            generic_call_target_info(edge.callee_name, false)
        );
    }

    return metadata;
}

std::size_t unreachable_delta_for_summary(const DiscoveredFunction& function) {
    if (function.summary.unreachable_blocks_removed >= function.graph.unreachable_blocks_removed()) {
        return function.summary.unreachable_blocks_removed - function.graph.unreachable_blocks_removed();
    }
    return 0;
}

void rebuild_function_summary_only(DiscoveredFunction& function, const loader::BinaryImage& image) {
    function.summary = build_function_summary(
        image,
        function.graph,
        image.architecture(),
        function.ssa_form,
        function.recovered_types,
        function.summary.constants,
        unreachable_delta_for_summary(function),
        function.summary.copy_propagations_applied,
        function.summary.dead_instructions_eliminated
    );
}

bool apply_signature_to_caller(
    DiscoveredFunction& caller,
    const CallGraphEdge& edge,
    const decompiler::CallTargetInfo& callee_info,
    const DiscoveredFunction* materialized_callee,
    const loader::Architecture architecture
) {
    ir::Instruction* instruction = find_instruction_by_address(caller.ssa_form, edge.call_site);
    if (instruction == nullptr || instruction->kind != ir::InstructionKind::Call) {
        return false;
    }

    std::size_t argument_offset = 0;
    if (!instruction->true_target.has_value() && !edge.callee_entry.has_value() && !instruction->inputs.empty()) {
        argument_offset = 1;
    }

    bool changed = false;
    const auto available_inputs =
        instruction->inputs.size() > argument_offset ? instruction->inputs.size() - argument_offset : 0;
    const auto argument_count = std::min<std::size_t>(available_inputs, callee_info.arguments.size());
    for (std::size_t index = 0; index < argument_count; ++index) {
        auto& input = instruction->inputs[argument_offset + index];
        auto scalar_type = callee_info.arguments[index].scalar_type;
        if (scalar_type == ir::ScalarType::Unknown) {
            scalar_type = scalar_type_from_decl_type(callee_info.arguments[index].decl_type);
        }
        if (scalar_type != ir::ScalarType::Unknown) {
            const auto merged = merge_type(input.type, scalar_type);
            if (merged != input.type) {
                input.type = merged;
                changed = true;
            }
        }

        if ((input.kind != ir::ValueKind::Register && input.kind != ir::ValueKind::Temporary) || input.name.empty()) {
            continue;
        }

        changed = merge_recovered_variable_type(caller.recovered_types, input.name, scalar_type) || changed;
        if (materialized_callee != nullptr && !callee_info.arguments[index].owner_name.empty()) {
            changed = clone_composites_for_owner(
                          caller.recovered_types,
                          materialized_callee->recovered_types,
                          callee_info.arguments[index].owner_name,
                          input.name
                      ) ||
                      changed;
        }
    }

    const std::string return_register = return_register_name(architecture);
    const auto return_scalar_type = scalar_type_from_decl_type(callee_info.return_type);
    if (!return_register.empty() && return_scalar_type != ir::ScalarType::Unknown) {
        changed = merge_recovered_variable_family(
                      caller.recovered_types,
                      return_register,
                      architecture,
                      return_scalar_type
                  ) ||
                  changed;
        if (materialized_callee != nullptr && materialized_callee->summary.return_value.has_value()) {
            changed = clone_composites_for_owner(
                          caller.recovered_types,
                          materialized_callee->recovered_types,
                          materialized_callee->summary.return_value->location,
                          return_register
                      ) ||
                      changed;
        }
    }

    if (changed) {
        normalize_recovered_types(caller.recovered_types);
    }
    return changed;
}

void apply_interprocedural_semantics(const loader::BinaryImage& image, ProgramAnalysis& analysis) {
    std::unordered_map<std::uint64_t, std::size_t> function_index_by_entry;
    for (std::size_t index = 0; index < analysis.functions.size(); ++index) {
        if (analysis.functions[index].analysis_materialized) {
            function_index_by_entry.emplace(analysis.functions[index].entry_address, index);
        }
    }
    if (function_index_by_entry.empty()) {
        return;
    }

    for (std::size_t pass = 0; pass < 3; ++pass) {
        std::unordered_set<std::uint64_t> changed_entries;
        const auto metadata = build_program_metadata(analysis);

        for (const auto& edge : analysis.call_graph) {
            const auto caller_index_it = function_index_by_entry.find(edge.caller_entry);
            if (caller_index_it == function_index_by_entry.end()) {
                continue;
            }

            const DiscoveredFunction* materialized_callee = nullptr;
            decompiler::CallTargetInfo callee_info;
            if (edge.callee_entry.has_value()) {
                const auto callee_index_it = function_index_by_entry.find(*edge.callee_entry);
                if (callee_index_it == function_index_by_entry.end()) {
                    continue;
                }
                materialized_callee = &analysis.functions[callee_index_it->second];
                callee_info = build_function_call_target_info(*materialized_callee);
            } else if (edge.is_import) {
                callee_info =
                    known_import_signature(edge.callee_name).value_or(generic_call_target_info(edge.callee_name, true));
            } else {
                callee_info = generic_call_target_info(edge.callee_name, false);
            }

            if (apply_signature_to_caller(
                    analysis.functions[caller_index_it->second],
                    edge,
                    callee_info,
                    materialized_callee,
                    image.architecture()
                )) {
                changed_entries.insert(edge.caller_entry);
            }
        }

        if (changed_entries.empty()) {
            break;
        }

        for (const auto entry_address : changed_entries) {
            const auto function_index_it = function_index_by_entry.find(entry_address);
            if (function_index_it == function_index_by_entry.end()) {
                continue;
            }
            rebuild_function_summary_only(analysis.functions[function_index_it->second], image);
        }
    }

    const auto final_metadata = build_program_metadata(analysis);
    for (auto& function : analysis.functions) {
        if (!function.analysis_materialized) {
            continue;
        }
        function.decompiled = decompiler::Decompiler::decompile(
            function.graph,
            function.ssa_form,
            function.recovered_types,
            &final_metadata
        );
    }
}

DiscoveredFunction make_lazy_shell(const PendingFunction& pending) {
    return DiscoveredFunction{
        .name = pending.name,
        .section_name = pending.section_name,
        .entry_address = pending.entry_address,
        .graph = pending.graph,
        .lifted_ir = {},
        .ssa_form = {},
        .recovered_types = {},
        .decompiled = {},
        .summary = {},
        .analysis_materialized = false,
    };
}

CachedDiscovery discover_program(
    const loader::BinaryImage& image,
    const memory::AddressSpace& address_space
) {
    CachedDiscovery discovery;
    discovery.strings = xrefs::Analyzer::extract_strings(image);
    std::vector<PendingFunction> discovered_functions;

    const auto strong_seeds = collect_strong_seeds(image);
    const auto signature_seeds = collect_signature_seeds(image, address_space);
    const auto heuristic_seeds = collect_heuristic_seeds(image, address_space);
    std::vector<FunctionSeed> pending = strong_seeds;
    std::unordered_set<std::uint64_t> queued;
    for (const auto& seed : strong_seeds) {
        queued.insert(seed.address);
    }

    std::unordered_set<std::uint64_t> analyzed_entries;
    std::vector<FunctionRange> accepted_ranges;

    std::unordered_map<std::uint64_t, std::string> exported_names;
    for (const auto& exported : image.exports()) {
        exported_names.try_emplace(exported.address, exported.name);
    }

    bool signatures_enqueued = false;
    bool heuristics_enqueued = false;
    auto enqueue_seed = [&](const std::uint64_t address, const SeedOrigin origin) {
        if (queued.insert(address).second) {
            pending.push_back(FunctionSeed{.address = address, .origin = origin});
        }
    };

    while (!pending.empty() || !signatures_enqueued || !heuristics_enqueued) {
        if (pending.empty() && !signatures_enqueued) {
            for (const auto& seed : signature_seeds) {
                enqueue_seed(seed.address, SeedOrigin::Signature);
            }
            signatures_enqueued = true;
            continue;
        }

        if (pending.empty() && !heuristics_enqueued) {
            for (const auto& seed : heuristic_seeds) {
                enqueue_seed(seed.address, SeedOrigin::Heuristic);
            }
            heuristics_enqueued = true;
            continue;
        }

        const FunctionSeed seed = pending.back();
        pending.pop_back();

        if (!analyzed_entries.insert(seed.address).second) {
            continue;
        }
        if (address_in_existing_range(seed.address, accepted_ranges)) {
            continue;
        }

        const loader::Section* section = find_executable_section_for_address(image, seed.address);
        if (section == nullptr) {
            continue;
        }

        const std::string function_name =
            exported_names.contains(seed.address) ? exported_names.at(seed.address) : format_function_name(seed.address);
        cfg::FunctionGraph graph = cfg::FunctionGraph::analyze(
            function_name,
            address_space,
            *section,
            seed.address,
            image.architecture()
        );
        if (!validate_function_candidate(seed, graph, accepted_ranges)) {
            continue;
        }

        const std::uint64_t function_end = graph_end_address(graph);
        discovered_functions.push_back(
            PendingFunction{
                .name = function_name,
                .section_name = section->name,
                .entry_address = seed.address,
                .graph = std::move(graph),
            }
        );

        accepted_ranges.push_back(FunctionRange{.start = seed.address, .end = function_end});
        std::sort(
            accepted_ranges.begin(),
            accepted_ranges.end(),
            [](const FunctionRange& lhs, const FunctionRange& rhs) { return lhs.start < rhs.start; }
        );

        for (const auto direct_call_target : discovered_functions.back().graph.direct_call_targets()) {
            if (find_executable_section_for_address(image, direct_call_target) != nullptr) {
                enqueue_seed(direct_call_target, SeedOrigin::CallTarget);
            }
        }
    }

    std::sort(
        discovered_functions.begin(),
        discovered_functions.end(),
        [](const PendingFunction& lhs, const PendingFunction& rhs) {
            return lhs.entry_address < rhs.entry_address;
        }
    );

    std::unordered_map<std::uint64_t, std::string> function_names;
    for (const auto& function : discovered_functions) {
        function_names.emplace(function.entry_address, function.name);
    }

    for (const auto& function : discovered_functions) {
        auto function_xrefs = xrefs::Analyzer::build_cross_references(function.graph, discovery.strings, image.imports());
        for (const auto& switch_info : function.graph.switches()) {
            for (const auto& switch_case : switch_info.cases) {
                function_xrefs.push_back(
                    xrefs::CrossReference{
                        .kind = xrefs::CrossReferenceKind::Jump,
                        .from_address = switch_info.jump_address,
                        .to_address = switch_case.target,
                        .label = "switch case",
                    }
                );
            }
            if (switch_info.default_target.has_value()) {
                function_xrefs.push_back(
                    xrefs::CrossReference{
                        .kind = xrefs::CrossReferenceKind::Jump,
                        .from_address = switch_info.jump_address,
                        .to_address = *switch_info.default_target,
                        .label = "switch default",
                    }
                );
            }
        }
        discovery.xrefs.insert(discovery.xrefs.end(), function_xrefs.begin(), function_xrefs.end());

        for (const auto& block : function.graph.blocks()) {
            for (const auto& instruction : block.instructions) {
                if (instruction.kind != disasm::InstructionKind::Call) {
                    continue;
                }

                if (instruction.control_flow_target.has_value()) {
                    const auto callee_it = function_names.find(*instruction.control_flow_target);
                    discovery.call_graph.push_back(
                        CallGraphEdge{
                            .caller_entry = function.entry_address,
                            .call_site = instruction.address,
                            .callee_entry =
                                callee_it == function_names.end() ? std::optional<std::uint64_t>(*instruction.control_flow_target)
                                                                  : std::optional<std::uint64_t>(callee_it->first),
                            .callee_name =
                                callee_it == function_names.end() ? format_function_name(*instruction.control_flow_target)
                                                                  : callee_it->second,
                            .is_import = false,
                        }
                    );
                    continue;
                }

                for (const auto reference_address : instruction.data_references) {
                    const loader::ImportedSymbol* imported = find_import_for_address(image, reference_address);
                    if (imported == nullptr) {
                        continue;
                    }

                    discovery.call_graph.push_back(
                        CallGraphEdge{
                            .caller_entry = function.entry_address,
                            .call_site = instruction.address,
                            .callee_entry = std::nullopt,
                            .callee_name = format_import_name(*imported),
                            .is_import = true,
                        }
                    );
                }
            }
        }
    }

    deduplicate_xrefs(discovery.xrefs);
    deduplicate_call_edges(discovery.call_graph);
    discovery.functions = std::move(discovered_functions);
    return discovery;
}

DiscoveredFunction finalize_function(
    PendingFunction pending,
    const loader::BinaryImage& image
) {
    ir::Function lifted_ir = ir::Lifter::lift(pending.graph, image.architecture());
    ssa::Function ssa_form = ssa::Builder::build(lifted_ir);
    std::vector<ConstantValue> propagated_constants;
    std::size_t removed_unreachable_blocks = 0;
    std::size_t copy_propagations_applied = 0;
    std::size_t dead_instructions_eliminated = 0;

    auto simplification = simplify_ssa_with_constants(ssa_form, propagated_constants);
    removed_unreachable_blocks += simplification.unreachable_blocks_removed;

    bool changed = true;
    while (changed) {
        changed = false;

        const auto copy_changes = propagate_ssa_copies(ssa_form, image.architecture());
        copy_propagations_applied += copy_changes;
        changed = changed || copy_changes > 0;

        const auto dead_changes = eliminate_dead_ssa_instructions(ssa_form, image.architecture());
        dead_instructions_eliminated += dead_changes;
        changed = changed || dead_changes > 0;

        simplification = simplify_ssa_with_constants(ssa_form, propagated_constants);
        removed_unreachable_blocks += simplification.unreachable_blocks_removed;
        changed = changed || simplification.rewrites_applied > 0 || simplification.unreachable_blocks_removed > 0;
    }

    type::FunctionTypes recovered_types = type::Recoverer::recover(ssa_form);
    FunctionAnalysisSummary summary = build_function_summary(
        image,
        pending.graph,
        image.architecture(),
        ssa_form,
        recovered_types,
        propagated_constants,
        removed_unreachable_blocks,
        copy_propagations_applied,
        dead_instructions_eliminated
    );
    decompiler::DecompiledFunction decompiled =
        decompiler::Decompiler::decompile(pending.graph, ssa_form, recovered_types);

    return DiscoveredFunction{
        .name = std::move(pending.name),
        .section_name = std::move(pending.section_name),
        .entry_address = pending.entry_address,
        .graph = std::move(pending.graph),
        .lifted_ir = std::move(lifted_ir),
        .ssa_form = std::move(ssa_form),
        .recovered_types = std::move(recovered_types),
        .decompiled = std::move(decompiled),
        .summary = std::move(summary),
        .analysis_materialized = true,
    };
}

}  // namespace

bool ProgramAnalysis::materialize_function(const std::uint64_t entry_address) {
    auto function_it = std::find_if(
        functions.begin(),
        functions.end(),
        [&](const DiscoveredFunction& function) { return function.entry_address == entry_address; }
    );
    if (function_it == functions.end()) {
        return false;
    }
    if (function_it->analysis_materialized) {
        return true;
    }
    if (!internal_state) {
        return false;
    }

    auto* state = static_cast<ProgramAnalysisState*>(internal_state.get());
    PendingFunction pending;
    loader::BinaryImage image;
    bool use_cache = true;
    {
        std::scoped_lock lock(state->mutex);
        const auto pending_it = state->pending_functions.find(entry_address);
        if (pending_it == state->pending_functions.end()) {
            return false;
        }
        pending = pending_it->second;
        image = state->image;
        use_cache = state->use_cache;
    }

    const std::string key = function_cache_key(cache_key.empty() ? state->program_cache_key : cache_key, entry_address);
    if (use_cache) {
        if (const auto cached = lookup_function_cache(key); cached.has_value()) {
            *function_it = *cached;
            function_it->analysis_materialized = true;
            ++global_caches().lazy_materializations;
            return true;
        }
    }

    DiscoveredFunction materialized = finalize_function(std::move(pending), image);
    if (use_cache) {
        store_function_cache(key, materialized);
    }
    *function_it = std::move(materialized);
    apply_interprocedural_semantics(image, *this);
    ++global_caches().lazy_materializations;
    return true;
}

void ProgramAnalysis::materialize_all() {
    std::vector<std::uint64_t> pending_entries;
    pending_entries.reserve(functions.size());
    for (const auto& function : functions) {
        if (!function.analysis_materialized) {
            pending_entries.push_back(function.entry_address);
        }
    }
    for (const auto entry_address : pending_entries) {
        (void)materialize_function(entry_address);
    }
    if (internal_state) {
        auto* state = static_cast<ProgramAnalysisState*>(internal_state.get());
        apply_interprocedural_semantics(state->image, *this);
    }
    lazy_materialization = !is_fully_materialized();
}

bool ProgramAnalysis::is_fully_materialized() const noexcept {
    return std::all_of(
        functions.begin(),
        functions.end(),
        [](const DiscoveredFunction& function) { return function.analysis_materialized; }
    );
}

ProgramAnalysis Analyzer::analyze(
    const loader::BinaryImage& image,
    const memory::AddressSpace& address_space,
    const AnalyzeOptions options
) {
    ProgramAnalysis analysis;
    analysis.cache_key = build_program_cache_key(image);

    CachedDiscovery discovery;
    if (options.use_cache) {
        if (const auto cached = lookup_discovery_cache(analysis.cache_key); cached.has_value()) {
            discovery = *cached;
        } else {
            discovery = discover_program(image, address_space);
            store_discovery_cache(analysis.cache_key, discovery);
        }
    } else {
        discovery = discover_program(image, address_space);
    }

    analysis.call_graph = discovery.call_graph;
    analysis.strings = discovery.strings;
    analysis.xrefs = discovery.xrefs;

    if (!options.materialize_functions) {
        analysis.functions.reserve(discovery.functions.size());
        auto state = std::make_shared<ProgramAnalysisState>();
        state->image = image;
        state->address_space = address_space;
        state->program_cache_key = analysis.cache_key;
        state->use_cache = options.use_cache;
        for (const auto& pending_function : discovery.functions) {
            state->pending_functions.emplace(pending_function.entry_address, pending_function);
            analysis.functions.push_back(make_lazy_shell(pending_function));
        }
        analysis.lazy_materialization = true;
        analysis.internal_state = std::static_pointer_cast<void>(state);
        return analysis;
    }

    std::vector<PendingFunction> discovered_functions = discovery.functions;
    analysis.functions.resize(discovered_functions.size());
    const std::size_t hardware_threads = std::max<std::size_t>(1, std::thread::hardware_concurrency());
    const std::size_t requested_threads =
        options.max_worker_threads == 0 ? hardware_threads : std::min(options.max_worker_threads, hardware_threads);
    const std::size_t worker_count = std::min<std::size_t>(
        std::max<std::size_t>(1, requested_threads),
        std::max<std::size_t>(1, discovered_functions.size())
    );
    std::atomic<std::size_t> next_index{0};
    std::vector<std::future<void>> workers;
    workers.reserve(worker_count);

    for (std::size_t worker_index = 0; worker_index < worker_count; ++worker_index) {
        workers.push_back(
            std::async(std::launch::async, [&]() {
                while (true) {
                    const std::size_t index = next_index.fetch_add(1);
                    if (index >= discovered_functions.size()) {
                        break;
                    }

                    const auto entry_address = discovered_functions[index].entry_address;
                    const std::string key = function_cache_key(analysis.cache_key, entry_address);
                    if (options.use_cache) {
                        if (const auto cached = lookup_function_cache(key); cached.has_value()) {
                            analysis.functions[index] = *cached;
                            continue;
                        }
                    }

                    DiscoveredFunction materialized = finalize_function(std::move(discovered_functions[index]), image);
                    if (options.use_cache) {
                        store_function_cache(key, materialized);
                    }
                    analysis.functions[index] = std::move(materialized);
                }
            })
        );
    }
    for (auto& worker : workers) {
        worker.get();
    }

    apply_interprocedural_semantics(image, analysis);

    return analysis;
}

void Analyzer::clear_cache() {
    auto& caches = global_caches();
    std::scoped_lock lock(caches.mutex);
    caches.discovery_cache.clear();
    caches.discovery_order.clear();
    caches.function_cache.clear();
    caches.function_order.clear();
    caches.discovery_hits = 0;
    caches.discovery_misses = 0;
    caches.function_hits = 0;
    caches.function_misses = 0;
    caches.lazy_materializations = 0;
}

AnalysisCacheStats Analyzer::cache_stats() {
    auto& caches = global_caches();
    return AnalysisCacheStats{
        .discovery_hits = caches.discovery_hits.load(),
        .discovery_misses = caches.discovery_misses.load(),
        .function_hits = caches.function_hits.load(),
        .function_misses = caches.function_misses.load(),
        .lazy_materializations = caches.lazy_materializations.load(),
    };
}

std::string_view to_string(const CallingConvention convention) noexcept {
    switch (convention) {
    case CallingConvention::Cdecl32:
        return "cdecl32";
    case CallingConvention::SysVAMD64:
        return "sysv_amd64";
    case CallingConvention::AAPCS32:
        return "aapcs32";
    case CallingConvention::AAPCS64:
        return "aapcs64";
    case CallingConvention::RiscV64SysV:
        return "riscv64_sysv";
    case CallingConvention::MipsN64:
        return "mips_n64";
    case CallingConvention::Ppc64ElfV2:
        return "ppc64_elfv2";
    case CallingConvention::Unknown:
    default:
        return "unknown";
    }
}

}  // namespace zara::analysis
