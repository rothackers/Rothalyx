#include <array>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string_view>
#include <vector>

#include "zara/loader/binary_image.hpp"

namespace {

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

struct DecodeCase {
    std::string_view name;
    std::uint16_t pointer_format = 0;
    std::uint64_t raw_value = 0;
    bool bind = false;
    std::size_t import_index = 0;
    std::uint16_t next = 0;
    std::uint8_t width = 0;
    std::optional<zara::loader::RelocationEncoding> encoding;
    std::optional<std::uint64_t> target;
    std::uint32_t auxiliary = 0;
    std::vector<std::uint64_t> segment_addresses;
};

std::uint64_t compose_ptr64(
    const std::uint64_t low_target,
    const std::uint8_t high8,
    const std::uint16_t next
) {
    return low_target | (static_cast<std::uint64_t>(high8) << 36U) | (static_cast<std::uint64_t>(next) << 51U);
}

std::uint64_t compose_arm64e_rebase(
    const std::uint64_t low_target,
    const std::uint8_t high8,
    const std::uint16_t next
) {
    return low_target | (static_cast<std::uint64_t>(high8) << 43U) | (static_cast<std::uint64_t>(next) << 51U);
}

bool verify_case(
    const DecodeCase& test_case,
    const std::uint64_t preferred_base
) {
    zara::loader::detail::DecodedMachOChainedFixup decoded;
    std::string error;
    if (!zara::loader::detail::decode_macho_chained_fixup_for_testing(
            test_case.pointer_format,
            test_case.raw_value,
            preferred_base,
            test_case.segment_addresses,
            decoded,
            error
        )) {
        std::cerr << "decode failed for " << test_case.name << ": " << error << '\n';
        return false;
    }

    if (decoded.bind != test_case.bind || decoded.import_index != test_case.import_index ||
        decoded.next != test_case.next || decoded.width != test_case.width) {
        std::cerr << "unexpected decode metadata for " << test_case.name << '\n';
        return false;
    }

    if (!test_case.encoding.has_value()) {
        if (decoded.relocation.has_value()) {
            std::cerr << "expected bind-only decode for " << test_case.name << '\n';
            return false;
        }
        return true;
    }

    if (!decoded.relocation.has_value()) {
        std::cerr << "expected relocation for " << test_case.name << '\n';
        return false;
    }
    if (decoded.relocation->encoding != *test_case.encoding ||
        decoded.relocation->width != test_case.width ||
        decoded.relocation->auxiliary != test_case.auxiliary) {
        std::cerr << "unexpected relocation encoding for " << test_case.name << '\n';
        return false;
    }
    if (test_case.target.has_value() && decoded.relocation->target != *test_case.target) {
        std::cerr << "unexpected relocation target for " << test_case.name << '\n';
        return false;
    }
    return true;
}

}  // namespace

int main() {
    constexpr std::uint64_t kPreferredBase = 0x100000000ULL;
    constexpr std::uint64_t kLow36 = 0x12345ULL;
    constexpr std::uint64_t kLow43 = 0x54321ULL;
    constexpr std::uint64_t kLow34 = 0x3210ULL;
    constexpr std::uint8_t kHigh8 = 0x5A;

    const std::uint64_t composed64 = kLow36 | (static_cast<std::uint64_t>(kHigh8) << 56U);
    const std::uint64_t composedArm64e = kLow43 | (static_cast<std::uint64_t>(kHigh8) << 56U);
    const std::vector<std::uint64_t> segments{0x100000000ULL, 0x200000000ULL, 0x300000000ULL};

    const std::vector<DecodeCase> cases{
        {
            .name = "ptr64-rebase",
            .pointer_format = kDyldChainedPtr64,
            .raw_value = compose_ptr64(kLow36, kHigh8, 3),
            .bind = false,
            .import_index = 0,
            .next = 3,
            .width = 8,
            .encoding = zara::loader::RelocationEncoding::MachOChained64,
            .target = composed64,
            .auxiliary = 0,
            .segment_addresses = {},
        },
        {
            .name = "ptr64-bind",
            .pointer_format = kDyldChainedPtr64,
            .raw_value = (1ULL << 63U) | (static_cast<std::uint64_t>(2) << 51U) | 0x1234ULL,
            .bind = true,
            .import_index = 0x1234ULL,
            .next = 2,
            .width = 8,
            .encoding = std::nullopt,
            .target = std::nullopt,
            .auxiliary = 0,
            .segment_addresses = {},
        },
        {
            .name = "ptr64-offset",
            .pointer_format = kDyldChainedPtr64Offset,
            .raw_value = compose_ptr64(kLow36, kHigh8, 1),
            .bind = false,
            .import_index = 0,
            .next = 1,
            .width = 8,
            .encoding = zara::loader::RelocationEncoding::MachOChained64Offset,
            .target = kPreferredBase + composed64,
            .auxiliary = 0,
            .segment_addresses = {},
        },
        {
            .name = "ptr32-rebase",
            .pointer_format = kDyldChainedPtr32,
            .raw_value = (static_cast<std::uint64_t>(3U) << 26U) | 0x0234567U,
            .bind = false,
            .import_index = 0,
            .next = 3,
            .width = 4,
            .encoding = zara::loader::RelocationEncoding::MachOChained32,
            .target = 0x0234567ULL,
            .auxiliary = 0,
            .segment_addresses = {},
        },
        {
            .name = "ptr32-bind",
            .pointer_format = kDyldChainedPtr32,
            .raw_value = (1ULL << 31U) | (static_cast<std::uint64_t>(4U) << 26U) | 0x3456ULL,
            .bind = true,
            .import_index = 0x3456ULL,
            .next = 4,
            .width = 4,
            .encoding = std::nullopt,
            .target = std::nullopt,
            .auxiliary = 0,
            .segment_addresses = {},
        },
        {
            .name = "ptr32-cache",
            .pointer_format = kDyldChainedPtr32Cache,
            .raw_value = (static_cast<std::uint64_t>(2U) << 30U) | 0x1234567U,
            .bind = false,
            .import_index = 0,
            .next = 2,
            .width = 4,
            .encoding = zara::loader::RelocationEncoding::MachOChained32Cache,
            .target = kPreferredBase + 0x1234567ULL,
            .auxiliary = 0,
            .segment_addresses = {},
        },
        {
            .name = "ptr32-firmware",
            .pointer_format = kDyldChainedPtr32Firmware,
            .raw_value = (static_cast<std::uint64_t>(5U) << 26U) | 0x02ABCDEU,
            .bind = false,
            .import_index = 0,
            .next = 5,
            .width = 4,
            .encoding = zara::loader::RelocationEncoding::MachOChained32Firmware,
            .target = 0x02ABCDEULL,
            .auxiliary = 0,
            .segment_addresses = {},
        },
        {
            .name = "ptr64-kernel-cache",
            .pointer_format = kDyldChainedPtr64KernelCache,
            .raw_value = (static_cast<std::uint64_t>(4) << 51U) | (static_cast<std::uint64_t>(2) << 30U) | 0x1234567ULL,
            .bind = false,
            .import_index = 0,
            .next = 4,
            .width = 8,
            .encoding = zara::loader::RelocationEncoding::MachOChained64KernelCache,
            .target = kPreferredBase + 0x1234567ULL,
            .auxiliary = 2,
            .segment_addresses = {},
        },
        {
            .name = "ptr-x86_64-kernel-cache",
            .pointer_format = kDyldChainedPtrX8664KernelCache,
            .raw_value = (static_cast<std::uint64_t>(7) << 51U) | (static_cast<std::uint64_t>(1) << 30U) | 0x2345678ULL,
            .bind = false,
            .import_index = 0,
            .next = 7,
            .width = 8,
            .encoding = zara::loader::RelocationEncoding::MachOChainedX8664KernelCache,
            .target = kPreferredBase + 0x2345678ULL,
            .auxiliary = 1,
            .segment_addresses = {},
        },
        {
            .name = "arm64e-rebase",
            .pointer_format = kDyldChainedPtrArm64e,
            .raw_value = compose_arm64e_rebase(kLow43, kHigh8, 3),
            .bind = false,
            .import_index = 0,
            .next = 3,
            .width = 8,
            .encoding = zara::loader::RelocationEncoding::MachOChainedArm64e,
            .target = composedArm64e,
            .auxiliary = 0,
            .segment_addresses = {},
        },
        {
            .name = "arm64e-auth",
            .pointer_format = kDyldChainedPtrArm64e,
            .raw_value = (1ULL << 63U) | (static_cast<std::uint64_t>(1) << 51U) | 0x345678ULL,
            .bind = false,
            .import_index = 0,
            .next = 1,
            .width = 8,
            .encoding = zara::loader::RelocationEncoding::MachOChainedArm64e,
            .target = kPreferredBase + 0x345678ULL,
            .auxiliary = 0,
            .segment_addresses = {},
        },
        {
            .name = "arm64e-bind",
            .pointer_format = kDyldChainedPtrArm64e,
            .raw_value = (1ULL << 62U) | (static_cast<std::uint64_t>(2) << 51U) | 0xBEEFULL,
            .bind = true,
            .import_index = 0xBEEFULL,
            .next = 2,
            .width = 8,
            .encoding = std::nullopt,
            .target = std::nullopt,
            .auxiliary = 0,
            .segment_addresses = {},
        },
        {
            .name = "arm64e-offset",
            .pointer_format = kDyldChainedPtrArm64eOffset,
            .raw_value = compose_arm64e_rebase(kLow43, kHigh8, 4),
            .bind = false,
            .import_index = 0,
            .next = 4,
            .width = 8,
            .encoding = zara::loader::RelocationEncoding::MachOChainedArm64eOffset,
            .target = kPreferredBase + composedArm64e,
            .auxiliary = 0,
            .segment_addresses = {},
        },
        {
            .name = "arm64e-userland",
            .pointer_format = kDyldChainedPtrArm64eUserland,
            .raw_value = compose_arm64e_rebase(kLow43, kHigh8, 5),
            .bind = false,
            .import_index = 0,
            .next = 5,
            .width = 8,
            .encoding = zara::loader::RelocationEncoding::MachOChainedArm64eUserland,
            .target = kPreferredBase + composedArm64e,
            .auxiliary = 0,
            .segment_addresses = {},
        },
        {
            .name = "arm64e-firmware",
            .pointer_format = kDyldChainedPtrArm64eFirmware,
            .raw_value = compose_arm64e_rebase(kLow43, kHigh8, 6),
            .bind = false,
            .import_index = 0,
            .next = 6,
            .width = 8,
            .encoding = zara::loader::RelocationEncoding::MachOChainedArm64e,
            .target = composedArm64e,
            .auxiliary = 0,
            .segment_addresses = {},
        },
        {
            .name = "arm64e-userland24-bind",
            .pointer_format = kDyldChainedPtrArm64eUserland24,
            .raw_value = (1ULL << 62U) | (static_cast<std::uint64_t>(3) << 51U) | 0xABCDEULL,
            .bind = true,
            .import_index = 0xABCDEULL,
            .next = 3,
            .width = 8,
            .encoding = std::nullopt,
            .target = std::nullopt,
            .auxiliary = 0,
            .segment_addresses = {},
        },
        {
            .name = "arm64e-shared-cache",
            .pointer_format = kDyldChainedPtrArm64eSharedCache,
            .raw_value = (static_cast<std::uint64_t>(2) << 51U) | kLow34,
            .bind = false,
            .import_index = 0,
            .next = 2,
            .width = 8,
            .encoding = zara::loader::RelocationEncoding::MachOChainedArm64eSharedCache,
            .target = kPreferredBase + kLow34,
            .auxiliary = 0,
            .segment_addresses = {},
        },
        {
            .name = "arm64e-segmented",
            .pointer_format = kDyldChainedPtrArm64eSegmented,
            .raw_value = (static_cast<std::uint64_t>(1) << 51U) | (static_cast<std::uint64_t>(2) << 28U) | 0x1234ULL,
            .bind = false,
            .import_index = 0,
            .next = 1,
            .width = 8,
            .encoding = zara::loader::RelocationEncoding::MachOChainedArm64eSegmented,
            .target = segments[2] + 0x1234ULL,
            .auxiliary = 2,
            .segment_addresses = segments,
        },
    };

    for (const auto& test_case : cases) {
        if (!verify_case(test_case, kPreferredBase)) {
            return 1;
        }
    }

    return 0;
}
