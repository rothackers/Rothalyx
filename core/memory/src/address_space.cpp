#include "zara/memory/address_space.hpp"

#include <algorithm>
#include <utility>

namespace zara::memory {

namespace {

std::uint64_t segment_end(const Segment& segment) {
    return segment.base_address + static_cast<std::uint64_t>(segment.bytes.size());
}

bool overlaps(const Segment& lhs, const Segment& rhs) {
    return lhs.base_address < segment_end(rhs) && rhs.base_address < segment_end(lhs);
}

int symbol_priority(const SymbolKind kind) {
    switch (kind) {
    case SymbolKind::User:
        return 5;
    case SymbolKind::Export:
        return 4;
    case SymbolKind::Import:
        return 3;
    case SymbolKind::Section:
    default:
        return 1;
    }
}

}  // namespace

bool AddressSpace::map_segment(Segment segment) {
    for (const Segment& existing : segments_) {
        if (overlaps(existing, segment)) {
            return false;
        }
    }

    segments_.push_back(std::move(segment));
    return true;
}

bool AddressSpace::map_image(const loader::BinaryImage& image) {
    bool mapped_any_segment = false;

    for (const loader::Section& section : image.sections()) {
        const bool mapped = map_segment(
            Segment{
                .name = section.name,
                .base_address = section.virtual_address,
                .bytes = section.bytes,
                .permissions =
                    Permissions{
                        .readable = section.readable,
                        .writable = section.writable,
                        .executable = section.executable,
                    },
            }
        );

        if (!mapped) {
            return false;
        }

        mapped_any_segment = true;

        (void)add_symbol(
            Symbol{
                .name = section.name,
                .address = section.virtual_address,
                .size = static_cast<std::uint64_t>(section.bytes.size()),
                .kind = SymbolKind::Section,
            }
        );
    }

    for (const auto& imported : image.imports()) {
        std::string qualified_name = imported.name;
        if (!imported.library.empty()) {
            qualified_name = imported.library + "!" + imported.name;
        }

        (void)add_symbol(
            Symbol{
                .name = qualified_name,
                .address = imported.address,
                .size = 0,
                .kind = SymbolKind::Import,
            }
        );
        if (!imported.name.empty()) {
            (void)add_symbol(
                Symbol{
                    .name = imported.name,
                    .address = imported.address,
                    .size = 0,
                    .kind = SymbolKind::Import,
                }
            );
        }
    }

    for (const auto& exported : image.exports()) {
        (void)add_symbol(
            Symbol{
                .name = exported.name,
                .address = exported.address,
                .size = exported.size,
                .kind = SymbolKind::Export,
            }
        );
    }

    return mapped_any_segment;
}

bool AddressSpace::add_symbol(Symbol symbol) {
    const auto duplicate = std::find_if(
        symbols_.begin(),
        symbols_.end(),
        [&](const Symbol& existing) {
            return existing.name == symbol.name &&
                   existing.address == symbol.address &&
                   existing.kind == symbol.kind;
        }
    );
    if (duplicate != symbols_.end()) {
        return false;
    }

    symbols_.push_back(std::move(symbol));
    std::sort(
        symbols_.begin(),
        symbols_.end(),
        [](const Symbol& lhs, const Symbol& rhs) {
            if (lhs.address != rhs.address) {
                return lhs.address < rhs.address;
            }
            if (lhs.kind != rhs.kind) {
                return symbol_priority(lhs.kind) > symbol_priority(rhs.kind);
            }
            return lhs.name < rhs.name;
        }
    );
    return true;
}

std::optional<std::byte> AddressSpace::read_byte(const std::uint64_t address) const {
    const Segment* segment = find_segment(address);
    if (segment == nullptr) {
        return std::nullopt;
    }

    const auto offset = static_cast<std::size_t>(address - segment->base_address);
    return segment->bytes[offset];
}

std::vector<std::byte> AddressSpace::read_bytes(const std::uint64_t address, const std::size_t count) const {
    const Segment* segment = find_segment(address);
    if (segment == nullptr) {
        return {};
    }

    const auto offset = static_cast<std::size_t>(address - segment->base_address);
    const auto available = segment->bytes.size() - offset;
    const auto actual_count = count < available ? count : available;

    return std::vector<std::byte>(
        segment->bytes.begin() + static_cast<std::ptrdiff_t>(offset),
        segment->bytes.begin() + static_cast<std::ptrdiff_t>(offset + actual_count)
    );
}

bool AddressSpace::write_byte(const std::uint64_t address, const std::byte value) {
    Segment* segment = find_segment(address);
    if (segment == nullptr || !segment->permissions.writable) {
        return false;
    }

    const auto offset = static_cast<std::size_t>(address - segment->base_address);
    segment->bytes[offset] = value;
    return true;
}

bool AddressSpace::write_bytes(const std::uint64_t address, const std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return true;
    }

    Segment* segment = find_segment(address);
    if (segment == nullptr || !segment->permissions.writable) {
        return false;
    }

    const auto offset = static_cast<std::size_t>(address - segment->base_address);
    if (offset > segment->bytes.size() || bytes.size() > segment->bytes.size() - offset) {
        return false;
    }

    std::copy(bytes.begin(), bytes.end(), segment->bytes.begin() + static_cast<std::ptrdiff_t>(offset));
    return true;
}

bool AddressSpace::patch_bytes(const std::uint64_t address, const std::vector<std::byte>& bytes) {
    if (bytes.empty()) {
        return true;
    }

    Segment* segment = find_segment(address);
    if (segment == nullptr) {
        return false;
    }

    const auto offset = static_cast<std::size_t>(address - segment->base_address);
    if (offset > segment->bytes.size() || bytes.size() > segment->bytes.size() - offset) {
        return false;
    }

    std::copy(bytes.begin(), bytes.end(), segment->bytes.begin() + static_cast<std::ptrdiff_t>(offset));
    return true;
}

bool AddressSpace::fill(const std::uint64_t address, const std::size_t count, const std::byte value) {
    if (count == 0) {
        return true;
    }

    Segment* segment = find_segment(address);
    if (segment == nullptr || !segment->permissions.writable) {
        return false;
    }

    const auto offset = static_cast<std::size_t>(address - segment->base_address);
    if (offset > segment->bytes.size() || count > segment->bytes.size() - offset) {
        return false;
    }

    std::fill_n(segment->bytes.begin() + static_cast<std::ptrdiff_t>(offset), static_cast<std::ptrdiff_t>(count), value);
    return true;
}

std::optional<Permissions> AddressSpace::permissions(const std::uint64_t address) const {
    const Segment* segment = find_segment(address);
    if (segment == nullptr) {
        return std::nullopt;
    }
    return segment->permissions;
}

std::optional<Symbol> AddressSpace::resolve_symbol(const std::string_view name) const {
    const auto symbol_it = std::find_if(
        symbols_.begin(),
        symbols_.end(),
        [&](const Symbol& symbol) { return symbol.name == name; }
    );
    if (symbol_it == symbols_.end()) {
        return std::nullopt;
    }
    return *symbol_it;
}

std::optional<Symbol> AddressSpace::symbol_at(const std::uint64_t address) const {
    const auto symbol_it = std::find_if(
        symbols_.begin(),
        symbols_.end(),
        [&](const Symbol& symbol) { return symbol.address == address; }
    );
    if (symbol_it == symbols_.end()) {
        return std::nullopt;
    }
    return *symbol_it;
}

std::optional<Symbol> AddressSpace::nearest_symbol(const std::uint64_t address) const {
    std::optional<Symbol> best;
    for (const auto& symbol : symbols_) {
        if (symbol.address > address) {
            break;
        }
        if (!best.has_value() ||
            symbol.address > best->address ||
            (symbol.address == best->address && symbol_priority(symbol.kind) > symbol_priority(best->kind))) {
            best = symbol;
        }
    }
    return best;
}

const std::vector<Segment>& AddressSpace::segments() const noexcept {
    return segments_;
}

const std::vector<Symbol>& AddressSpace::symbols() const noexcept {
    return symbols_;
}

const Segment* AddressSpace::find_segment(const std::uint64_t address) const noexcept {
    for (const Segment& segment : segments_) {
        if (address >= segment.base_address && address < segment_end(segment)) {
            return &segment;
        }
    }

    return nullptr;
}

Segment* AddressSpace::find_segment(const std::uint64_t address) noexcept {
    for (Segment& segment : segments_) {
        if (address >= segment.base_address && address < segment_end(segment)) {
            return &segment;
        }
    }

    return nullptr;
}

std::string_view to_string(const SymbolKind kind) noexcept {
    switch (kind) {
    case SymbolKind::Section:
        return "section";
    case SymbolKind::Import:
        return "import";
    case SymbolKind::Export:
        return "export";
    case SymbolKind::User:
    default:
        return "user";
    }
}

}  // namespace zara::memory
