#include <algorithm>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "zara/distributed/batch_runner.hpp"

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: distributed_smoke <fixture-a> <fixture-b>\n";
        return 1;
    }

    const std::filesystem::path fixture_a = argv[1];
    const std::filesystem::path fixture_b = argv[2];

    const auto output_root = std::filesystem::temp_directory_path() / "zara_distributed_smoke";
    std::error_code remove_error;
    std::filesystem::remove_all(output_root, remove_error);

    const std::vector<std::filesystem::path> inputs{fixture_a, fixture_b};
    const auto result = zara::distributed::BatchRunner::analyze(
        inputs,
        output_root,
        zara::distributed::BatchOptions{
            .concurrency = 2,
            .shard_count = 1,
            .shard_index = 0,
            .recursive = false,
        }
    );

    if (result.jobs.size() != 2) {
        std::cerr << "expected two batch jobs, got " << result.jobs.size() << '\n';
        return 2;
    }
    if (result.remote || result.worker_slots != 2 || result.workers.size() != 2) {
        std::cerr << "unexpected local worker summary metadata\n";
        return 3;
    }

    if (result.failure_count != 0) {
        const bool sqlite_missing = std::all_of(
            result.jobs.begin(),
            result.jobs.end(),
            [](const zara::distributed::BatchJobResult& job) {
                return !job.success &&
                       (job.error.find("SQLite3") != std::string::npos ||
                        job.error.find("SQLite") != std::string::npos);
            }
        );
        if (sqlite_missing) {
            return 0;
        }

        std::cerr << "unexpected batch failure\n";
        for (const auto& job : result.jobs) {
            std::cerr << "  " << job.binary_path << ": " << job.error << '\n';
        }
        return 4;
    }

    std::string error;
    if (!zara::distributed::BatchRunner::write_manifest(output_root / "manifest.tsv", result, error)) {
        std::cerr << "manifest write failed: " << error << '\n';
        return 5;
    }
    if (!zara::distributed::BatchRunner::write_summary(output_root / "summary.json", result, error)) {
        std::cerr << "summary write failed: " << error << '\n';
        return 6;
    }
    if (!std::filesystem::exists(output_root / "manifest.tsv")) {
        std::cerr << "manifest missing\n";
        return 7;
    }
    if (!std::filesystem::exists(output_root / "summary.json")) {
        std::cerr << "summary missing\n";
        return 8;
    }

    const auto shard_result = zara::distributed::BatchRunner::analyze(
        inputs,
        output_root / "shard_1",
        zara::distributed::BatchOptions{
            .concurrency = 2,
            .shard_count = 2,
            .shard_index = 1,
            .recursive = false,
        }
    );
    if (shard_result.jobs.size() != 1) {
        std::cerr << "expected one shard job, got " << shard_result.jobs.size() << '\n';
        return 9;
    }

    return 0;
}
