#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "zara/analysis/program_analysis.hpp"
#include "zara/memory/address_space.hpp"

namespace {

std::vector<std::byte> to_bytes(const std::vector<std::uint8_t>& values) {
    return std::vector<std::byte>(
        reinterpret_cast<const std::byte*>(values.data()),
        reinterpret_cast<const std::byte*>(values.data() + values.size())
    );
}

}  // namespace

int main() {
    constexpr std::uint64_t kCodeBase = 0x1000;
    constexpr std::uint64_t kDataBase = 0x1020;

    const std::vector<std::uint8_t> code_bytes{
        0x55,
        0x48, 0x89, 0xE5,
        0x48, 0x8D, 0x3D, 0x15, 0x00, 0x00, 0x00,
        0x74, 0x05,
        0xE8, 0x03, 0x00, 0x00, 0x00,
        0x31, 0xC0,
        0xC3,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3
    };

    const std::array<std::uint8_t, 6> data_bytes{
        0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x00,
    };

    zara::memory::AddressSpace address_space;
    const auto image = zara::loader::BinaryImage::from_components(
        "lazy-cache.bin",
        zara::loader::BinaryFormat::Raw,
        zara::loader::Architecture::X86_64,
        kCodeBase,
        kCodeBase,
        {
            zara::loader::Section{
                .name = ".text",
                .virtual_address = kCodeBase,
                .bytes = to_bytes(code_bytes),
                .readable = true,
                .writable = false,
                .executable = true,
            },
            zara::loader::Section{
                .name = ".rodata",
                .virtual_address = kDataBase,
                .bytes = std::vector<std::byte>(
                    reinterpret_cast<const std::byte*>(data_bytes.data()),
                    reinterpret_cast<const std::byte*>(data_bytes.data() + data_bytes.size())
                ),
                .readable = true,
                .writable = false,
                .executable = false,
            },
        }
    );

    if (!address_space.map_image(image)) {
        std::cerr << "failed to map lazy-cache image\n";
        return 1;
    }

    zara::analysis::Analyzer::clear_cache();
    const auto stats_before = zara::analysis::Analyzer::cache_stats();

    auto lazy_first = zara::analysis::Analyzer::analyze(
        image,
        address_space,
        zara::analysis::AnalyzeOptions{
            .materialize_functions = false,
            .use_cache = true,
        }
    );
    if (!lazy_first.lazy_materialization || lazy_first.functions.empty() || lazy_first.is_fully_materialized()) {
        std::cerr << "lazy analysis did not preserve lightweight function shells\n";
        return 2;
    }

    const auto stats_after_first = zara::analysis::Analyzer::cache_stats();
    if (stats_after_first.discovery_misses <= stats_before.discovery_misses) {
        std::cerr << "expected discovery cache miss on first lazy analysis\n";
        return 3;
    }

    auto lazy_second = zara::analysis::Analyzer::analyze(
        image,
        address_space,
        zara::analysis::AnalyzeOptions{
            .materialize_functions = false,
            .use_cache = true,
        }
    );
    const auto stats_after_second = zara::analysis::Analyzer::cache_stats();
    if (stats_after_second.discovery_hits <= stats_after_first.discovery_hits) {
        std::cerr << "expected discovery cache hit on second lazy analysis\n";
        return 4;
    }

    const auto entry_address = lazy_second.functions.front().entry_address;
    if (!lazy_second.materialize_function(entry_address)) {
        std::cerr << "lazy function materialization failed\n";
        return 5;
    }

    const auto function_it = std::find_if(
        lazy_second.functions.begin(),
        lazy_second.functions.end(),
        [entry_address](const zara::analysis::DiscoveredFunction& function) {
            return function.entry_address == entry_address;
        }
    );
    if (function_it == lazy_second.functions.end() ||
        !function_it->analysis_materialized ||
        function_it->lifted_ir.blocks.empty() ||
        function_it->decompiled.pseudocode.empty()) {
        std::cerr << "materialized function is missing heavy analysis artifacts\n";
        return 6;
    }

    lazy_second.materialize_all();
    if (!lazy_second.is_fully_materialized()) {
        std::cerr << "materialize_all did not complete the remaining lazy functions\n";
        return 10;
    }

    const auto stats_after_materialize = zara::analysis::Analyzer::cache_stats();
    if (stats_after_materialize.function_misses <= stats_after_second.function_misses ||
        stats_after_materialize.lazy_materializations <= stats_after_second.lazy_materializations) {
        std::cerr << "expected a cached function miss followed by lazy materialization work\n";
        return 7;
    }

    auto lazy_third = zara::analysis::Analyzer::analyze(
        image,
        address_space,
        zara::analysis::AnalyzeOptions{
            .materialize_functions = false,
            .use_cache = true,
        }
    );
    if (!lazy_third.materialize_function(entry_address)) {
        std::cerr << "expected cached lazy materialization to succeed\n";
        return 8;
    }

    const auto stats_after_cached_materialize = zara::analysis::Analyzer::cache_stats();
    if (stats_after_cached_materialize.function_hits <= stats_after_materialize.function_hits) {
        std::cerr << "expected function cache hit on repeated lazy materialization\n";
        return 9;
    }

    return 0;
}
