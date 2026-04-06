#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <unistd.h>
#endif

#include "zara/distributed/batch_runner.hpp"

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: distributed_remote_smoke <fixture-a> <fixture-b>\n";
        return 1;
    }

#if !defined(__linux__) && !defined(__APPLE__) && !defined(__unix__)
    std::cerr << "remote distributed smoke is unsupported on this platform\n";
    return 0;
#else
    const std::filesystem::path fixture_a = argv[1];
    const std::filesystem::path fixture_b = argv[2];
    const std::vector<std::filesystem::path> inputs{fixture_a, fixture_b};

    const auto output_root = std::filesystem::temp_directory_path() / "zara_distributed_remote_smoke";
    std::error_code remove_error;
    std::filesystem::remove_all(output_root, remove_error);
    const std::string shared_secret = "zara-remote-test-secret";

    const std::uint16_t port = static_cast<std::uint16_t>(39000 + (getpid() % 1000));

    zara::distributed::BatchResult controller_result;
    std::string controller_error;
    bool controller_ok = false;
    std::thread controller(
        [&]() {
            controller_ok = zara::distributed::BatchRunner::analyze_remote(
                inputs,
                output_root,
                zara::distributed::RemoteOptions{
                    .host = "127.0.0.1",
                    .port = port,
                    .expected_workers = 2,
                    .accept_timeout_ms = 10000,
                    .max_jobs_per_worker = 1,
                    .shared_secret = shared_secret,
                    .allowed_platforms = {"linux"},
                },
                controller_result,
                controller_error
            );
        }
    );

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    std::string worker_error_a;
    std::string worker_error_b;
    bool worker_ok_a = false;
    bool worker_ok_b = false;
    std::thread worker_a(
        [&]() {
            worker_ok_a = zara::distributed::BatchRunner::run_remote_worker(
                output_root / "worker_a",
                zara::distributed::RemoteOptions{
                    .host = "127.0.0.1",
                    .port = port,
                    .shared_secret = shared_secret,
                },
                worker_error_a
            );
        }
    );
    std::thread worker_b(
        [&]() {
            worker_ok_b = zara::distributed::BatchRunner::run_remote_worker(
                output_root / "worker_b",
                zara::distributed::RemoteOptions{
                    .host = "127.0.0.1",
                    .port = port,
                    .shared_secret = shared_secret,
                },
                worker_error_b
            );
        }
    );

    worker_a.join();
    worker_b.join();
    controller.join();

    if (!controller_ok) {
        std::cerr << "remote controller failed: " << controller_error << '\n';
        return 2;
    }
    if (!worker_ok_a) {
        std::cerr << "worker A failed: " << worker_error_a << '\n';
        return 3;
    }
    if (!worker_ok_b) {
        std::cerr << "worker B failed: " << worker_error_b << '\n';
        return 4;
    }

    if (controller_result.jobs.size() != 2 || controller_result.failure_count != 0) {
        std::cerr << "unexpected remote batch result size/failures\n";
        return 5;
    }
    if (!controller_result.remote || controller_result.worker_slots != 2 || controller_result.workers.size() != 2) {
        std::cerr << "unexpected remote worker summary metadata\n";
        return 6;
    }
    if (controller_result.protocol_version != "zara-batch/2") {
        std::cerr << "unexpected remote protocol version\n";
        return 7;
    }
    if (controller_result.events.size() < 4) {
        std::cerr << "expected controller/worker event stream\n";
        return 8;
    }
    for (const auto& worker : controller_result.workers) {
        if (worker.platform != "linux" || worker.assigned_jobs != 1 || worker.last_event.empty() || worker.status.empty()) {
            std::cerr << "unexpected worker observability/policy fields\n";
            return 9;
        }
    }
    const auto has_ready_event = std::any_of(
        controller_result.events.begin(),
        controller_result.events.end(),
        [](const zara::distributed::BatchEvent& event) { return event.kind == "worker-ready"; }
    );
    const auto has_dispatch_event = std::any_of(
        controller_result.events.begin(),
        controller_result.events.end(),
        [](const zara::distributed::BatchEvent& event) {
            return event.kind == "job-dispatched" || event.kind == "job-finished" || event.kind == "worker-detached";
        }
    );
    if (!has_ready_event || !has_dispatch_event) {
        std::cerr << "expected readiness and job lifecycle events in remote summary\n";
        return 10;
    }

    std::string manifest_error;
    if (!zara::distributed::BatchRunner::write_manifest(output_root / "remote-manifest.tsv", controller_result, manifest_error)) {
        std::cerr << "remote manifest write failed: " << manifest_error << '\n';
        return 11;
    }
    if (!zara::distributed::BatchRunner::write_summary(output_root / "remote-summary.json", controller_result, manifest_error)) {
        std::cerr << "remote summary write failed: " << manifest_error << '\n';
        return 12;
    }

    if (!std::filesystem::exists(output_root / "remote-manifest.tsv")) {
        std::cerr << "remote manifest missing\n";
        return 13;
    }
    if (!std::filesystem::exists(output_root / "remote-summary.json")) {
        std::cerr << "remote summary missing\n";
        return 14;
    }

    return 0;
#endif
}
