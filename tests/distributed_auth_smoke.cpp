#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <unistd.h>
#endif

#include "zara/distributed/batch_runner.hpp"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: distributed_auth_smoke <fixture>\n";
        return 1;
    }

#if !defined(__linux__) && !defined(__APPLE__) && !defined(__unix__)
    std::cerr << "distributed auth smoke is unsupported on this platform\n";
    return 0;
#else
    const std::filesystem::path fixture = argv[1];
    const auto output_root = std::filesystem::temp_directory_path() / "zara_distributed_auth_smoke";
    std::error_code remove_error;
    std::filesystem::remove_all(output_root, remove_error);

    const std::uint16_t port = static_cast<std::uint16_t>(41000 + (getpid() % 1000));
    const std::string good_secret = "zara-auth-good";
    const std::string bad_secret = "zara-auth-bad";

    zara::distributed::BatchResult controller_result;
    std::string controller_error;
    bool controller_ok = false;
    std::thread controller(
        [&]() {
            controller_ok = zara::distributed::BatchRunner::analyze_remote(
                {fixture},
                output_root / "controller",
                zara::distributed::RemoteOptions{
                    .host = "127.0.0.1",
                    .port = port,
                    .expected_workers = 1,
                    .accept_timeout_ms = 2000,
                    .read_timeout_ms = 2000,
                    .shared_secret = good_secret,
                    .allowed_platforms = {"linux"},
                },
                controller_result,
                controller_error
            );
        }
    );

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    std::string worker_error;
    const bool worker_ok = zara::distributed::BatchRunner::run_remote_worker(
        output_root / "worker",
        zara::distributed::RemoteOptions{
            .host = "127.0.0.1",
            .port = port,
            .shared_secret = bad_secret,
        },
        worker_error
    );

    controller.join();

    if (controller_ok) {
        std::cerr << "expected controller auth failure\n";
        return 2;
    }
    if (controller_error.find("authentication failed") == std::string::npos) {
        std::cerr << "unexpected controller auth error: " << controller_error << '\n';
        return 3;
    }
    if (worker_ok) {
        std::cerr << "expected worker auth failure\n";
        return 4;
    }

    return 0;
#endif
}
