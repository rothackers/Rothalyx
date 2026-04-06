#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "zara/security/workflow.hpp"

namespace {

struct Options {
    std::filesystem::path corpus_root;
    std::size_t repeat_count = 1;
    bool verbose = false;
};

struct Summary {
    std::size_t files_seen = 0;
    std::size_t parse_successes = 0;
    std::size_t parse_failures = 0;
    std::size_t total_coverage_sites = 0;
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

void print_usage() {
    std::cerr
        << "usage: zara_trace_corpus_runner <corpus-path> [--repeat N] [--verbose]\n"
        << "  corpus-path   file or directory of trace/text inputs\n"
        << "  --repeat N    iterate the corpus N times (default: 1)\n"
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

            zara::security::CrashTrace trace;
            std::string error;
            try {
                if (!zara::security::Workflow::parse_trace_file(file, trace, error)) {
                    ++summary.parse_failures;
                    if (options.verbose) {
                        std::cout << "[trace-fuzz] reject " << file << " :: " << error << '\n';
                    }
                    continue;
                }

                ++summary.parse_successes;
                summary.total_coverage_sites += trace.coverage_addresses.size();
                if (options.verbose) {
                    std::cout << "[trace-fuzz] parse "
                              << file
                              << " :: crash="
                              << (trace.crash_address.has_value() ? "yes" : "no")
                              << " coverage="
                              << trace.coverage_addresses.size()
                              << '\n';
                }
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

    std::cout << "Trace corpus campaign complete\n"
              << "  corpus root: " << options.corpus_root << '\n'
              << "  files discovered: " << files.size() << '\n'
              << "  passes: " << options.repeat_count << '\n'
              << "  file visits: " << summary.files_seen << '\n'
              << "  parses accepted: " << summary.parse_successes << '\n'
              << "  parses rejected: " << summary.parse_failures << '\n'
              << "  total accepted coverage sites: " << summary.total_coverage_sites << '\n'
              << "  elapsed ms: " << elapsed_ms << '\n';
    return 0;
}
