#include <chrono>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "zara/distributed/batch_runner.hpp"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: distributed_protocol_abuse_smoke <fixture>\n";
        return 1;
    }

#if !defined(__linux__) && !defined(__APPLE__) && !defined(__unix__)
    std::cerr << "distributed protocol abuse smoke is unsupported on this platform\n";
    return 0;
#else
    const std::filesystem::path fixture = argv[1];
    const auto output_root = std::filesystem::temp_directory_path() / "zara_distributed_protocol_abuse";
    std::error_code remove_error;
    std::filesystem::remove_all(output_root, remove_error);

    const std::uint16_t port = static_cast<std::uint16_t>(43000 + (getpid() % 1000));
    const std::string shared_secret = "zara-abuse-secret";

    zara::distributed::BatchResult controller_result;
    std::string controller_error;
    bool controller_ok = false;
    std::thread controller(
        [&]() {
            controller_ok = zara::distributed::BatchRunner::analyze_remote(
                {fixture},
                output_root,
                zara::distributed::RemoteOptions{
                    .host = "127.0.0.1",
                    .port = port,
                    .expected_workers = 1,
                    .accept_timeout_ms = 2000,
                    .read_timeout_ms = 2000,
                    .max_message_bytes = 64,
                    .shared_secret = shared_secret,
                },
                controller_result,
                controller_error
            );
        }
    );

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        std::cerr << "socket creation failed\n";
        controller.join();
        return 2;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1 ||
        connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        std::cerr << "socket connect failed: " << std::strerror(errno) << '\n';
        close(fd);
        controller.join();
        return 3;
    }

    const std::string oversized_line(256, 'A');
    const std::string payload = oversized_line + '\n';
    if (write(fd, payload.data(), payload.size()) < 0) {
        std::cerr << "socket write failed: " << std::strerror(errno) << '\n';
        close(fd);
        controller.join();
        return 4;
    }
    close(fd);
    controller.join();

    if (controller_ok) {
        std::cerr << "expected protocol abuse rejection\n";
        return 5;
    }
    if (controller_error.find("protocol limit") == std::string::npos &&
        controller_error.find("invalid") == std::string::npos) {
        std::cerr << "unexpected controller error: " << controller_error << '\n';
        return 6;
    }

    return 0;
#endif
}
