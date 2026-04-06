#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "zara/loader/binary_image.hpp"

namespace zara::memory {

struct Permissions {
    bool readable = true;
    bool writable = false;
    bool executable = false;
};

struct Segment {
    std::string name;
    std::uint64_t base_address = 0;
    std::vector<std::byte> bytes;
    Permissions permissions;
};

enum class SymbolKind {
    Section,
    Import,
    Export,
    User,
};

struct Symbol {
    std::string name;
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    SymbolKind kind = SymbolKind::User;
};

class AddressSpace {
public:
    [[nodiscard]] bool map_segment(Segment segment);
    [[nodiscard]] bool map_image(const loader::BinaryImage& image);
    [[nodiscard]] bool add_symbol(Symbol symbol);
    [[nodiscard]] std::optional<std::byte> read_byte(std::uint64_t address) const;
    [[nodiscard]] std::vector<std::byte> read_bytes(std::uint64_t address, std::size_t count) const;
    [[nodiscard]] bool write_byte(std::uint64_t address, std::byte value);
    [[nodiscard]] bool write_bytes(std::uint64_t address, std::span<const std::byte> bytes);
    [[nodiscard]] bool patch_bytes(std::uint64_t address, const std::vector<std::byte>& bytes);
    [[nodiscard]] bool fill(std::uint64_t address, std::size_t count, std::byte value);
    [[nodiscard]] std::optional<Permissions> permissions(std::uint64_t address) const;
    [[nodiscard]] std::optional<Symbol> resolve_symbol(std::string_view name) const;
    [[nodiscard]] std::optional<Symbol> symbol_at(std::uint64_t address) const;
    [[nodiscard]] std::optional<Symbol> nearest_symbol(std::uint64_t address) const;
    [[nodiscard]] const std::vector<Segment>& segments() const noexcept;
    [[nodiscard]] const std::vector<Symbol>& symbols() const noexcept;

private:
    [[nodiscard]] const Segment* find_segment(std::uint64_t address) const noexcept;
    [[nodiscard]] Segment* find_segment(std::uint64_t address) noexcept;
    std::vector<Segment> segments_;
    std::vector<Symbol> symbols_;
};

[[nodiscard]] std::string_view to_string(SymbolKind kind) noexcept;

}  // namespace zara::memory
