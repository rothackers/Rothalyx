#include <filesystem>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "zara/scripting/python_engine.hpp"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: scripting_concurrency_smoke <fixture-binary>\n";
        return 1;
    }

    const std::filesystem::path fixture = std::filesystem::absolute(argv[1]);
    constexpr std::size_t kThreadCount = 4;

    std::mutex error_mutex;
    std::vector<std::string> errors;
    std::vector<std::thread> threads;
    threads.reserve(kThreadCount);

    for (std::size_t index = 0; index < kThreadCount; ++index) {
        threads.emplace_back(
            [&, index]() {
                zara::scripting::PythonEngine engine;
                if (!engine.is_available()) {
                    return;
                }

                std::string error;
                const std::string script =
                    "import zara\n"
                    "summary = zara.analyze_binary(r'" + fixture.string() + "')\n"
                    "assert summary['function_count'] >= 1\n"
                    "functions = zara.list_functions(r'" + fixture.string() + "')\n"
                    "assert len(functions) >= 1\n";
                if (!engine.execute_string(script, error)) {
                    std::lock_guard lock(error_mutex);
                    errors.push_back("thread " + std::to_string(index) + ": " + error);
                }
            }
        );
    }

    for (auto& thread : threads) {
        thread.join();
    }

    if (!errors.empty()) {
        std::cerr << errors.front() << '\n';
        return 2;
    }

    return 0;
}
