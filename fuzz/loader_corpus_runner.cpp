#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"

namespace {

struct Options {
    std::filesystem::path corpus_root;
    std::size_t repeat_count = 1;
    std::uint64_t rebase_step = 0x100000;
    bool verbose = false;
};

struct Summary {
    std::size_t files_seen = 0;
    std::size_t load_successes = 0;
    std::size_t load_failures = 0;
    std::size_t map_successes = 0;
};

bool parse_positive_size(std::string_view value, std::size_t& out_value) {
    try {
        const auto parsed = std::stoull(std::string(value), nullptr, 10);
        if (parsed == 0) {
            return false;
        }
        out_value = static_cast<std::size_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_u64(std::string_view value, std::uint64_t& out_value) {
    try {
        const int base = value.starts_with("0x") || value.starts_with("0X") ? 16 : 10;
        out_value = std::stoull(std::string(value), nullptr, base);
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_arguments(int argc, char** argv, Options& out_options) {
    if (argc < 2) {
        return false;
    }

    out_options.corpus_root = argv[1];
    for (int index = 2; index < argc; ++index) {
        const std::string_view argument = argv[index];
        if (argument == "--verbose") {
            out_options.verbose = true;
            continue;
        }
        if (argument == "--repeat" && index + 1 < argc) {
            if (!parse_positive_size(argv[++index], out_options.repeat_count)) {
                return false;
            }
            continue;
        }
        if (argument == "--rebase-step" && index + 1 < argc) {
            if (!parse_u64(argv[++index], out_options.rebase_step)) {
                return false;
            }
            continue;
        }
        return false;
    }

    return true;
}

std::vector<std::filesystem::path> collect_files(const std::filesystem::path& root) {
    std::vector<std::filesystem::path> files;
    if (std::filesystem::is_regular_file(root)) {
        files.push_back(root);
        return files;
    }

    if (!std::filesystem::is_directory(root)) {
        return files;
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        if (entry.is_regular_file()) {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());
    return files;
}

void exercise_loaded_image(zara::loader::BinaryImage image, const std::uint64_t rebase_step, Summary& summary) {
    zara::memory::AddressSpace address_space;
    if (address_space.map_image(image)) {
        ++summary.map_successes;
        if (const auto entry = image.entry_point(); entry.has_value()) {
            [[maybe_unused]] const auto initial_bytes = address_space.read_bytes(*entry, 32);
            [[maybe_unused]] const auto initial_symbol = address_space.nearest_symbol(*entry);
        }
    }

    if (rebase_step == 0) {
        return;
    }

    image.apply_rebase(image.base_address() + rebase_step);
    zara::memory::AddressSpace rebased_space;
    if (!rebased_space.map_image(image)) {
        return;
    }

    if (const auto entry = image.entry_point(); entry.has_value()) {
        [[maybe_unused]] const auto rebased_bytes = rebased_space.read_bytes(*entry, 32);
        [[maybe_unused]] const auto rebased_symbol = rebased_space.nearest_symbol(*entry);
    }
}

void print_usage() {
    std::cerr
        << "usage: zara_loader_corpus_runner <corpus-path> [--repeat N] [--rebase-step VALUE] [--verbose]\n"
        << "  corpus-path   file or directory of binary inputs\n"
        << "  --repeat N    iterate the corpus N times (default: 1)\n"
        << "  --rebase-step VALUE  rebase loaded images by VALUE bytes after mapping (default: 0x100000)\n"
        << "  --verbose     print per-file outcomes\n";
}

}  // namespace

int main(int argc, char** argv) {
    Options options;
    if (!parse_arguments(argc, argv, options)) {
        print_usage();
        return 1;
    }

    const auto files = collect_files(options.corpus_root);
    if (files.empty()) {
        std::cerr << "No corpus files found at " << options.corpus_root << '\n';
        return 2;
    }

    const auto started_at = std::chrono::steady_clock::now();
    Summary summary;
    for (std::size_t pass = 0; pass < options.repeat_count; ++pass) {
        for (const auto& file : files) {
            ++summary.files_seen;

            zara::loader::BinaryImage image;
            std::string error;
            try {
                if (!zara::loader::BinaryImage::load_from_file(file, image, error)) {
                    ++summary.load_failures;
                    if (options.verbose) {
                        std::cout << "[loader-fuzz] reject " << file << " :: " << error << '\n';
                    }
                    continue;
                }

                ++summary.load_successes;
                if (options.verbose) {
                    std::cout << "[loader-fuzz] load "
                              << file
                              << " :: format="
                              << zara::loader::to_string(image.format())
                              << " arch="
                              << zara::loader::to_string(image.architecture())
                              << '\n';
                }
                exercise_loaded_image(image, options.rebase_step, summary);
            } catch (const std::exception& error_exception) {
                std::cerr << "Unhandled exception for " << file << ": " << error_exception.what() << '\n';
                return 3;
            } catch (...) {
                std::cerr << "Unhandled non-standard exception for " << file << '\n';
                return 4;
            }
        }
    }

    const auto finished_at = std::chrono::steady_clock::now();
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(finished_at - started_at).count();

    std::cout << "Loader corpus campaign complete\n"
              << "  corpus root: " << options.corpus_root << '\n'
              << "  files discovered: " << files.size() << '\n'
              << "  passes: " << options.repeat_count << '\n'
              << "  file visits: " << summary.files_seen << '\n'
              << "  loads accepted: " << summary.load_successes << '\n'
              << "  loads rejected: " << summary.load_failures << '\n'
              << "  mappings succeeded: " << summary.map_successes << '\n'
              << "  elapsed ms: " << elapsed_ms << '\n';
    return 0;
}
