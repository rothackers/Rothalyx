#include <atomic>
#include <chrono>
#include <string_view>
#include <thread>

namespace {

volatile int g_counter = 0;
std::atomic<bool> g_running = true;

[[gnu::noinline]] int work(const int value) {
    g_counter += value;
    return g_counter + 1;
}

void worker_loop() {
    while (g_running.load()) {
        work(2);
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
}

}  // namespace

int main(const int argc, char** argv) {
    if (argc > 1 && std::string_view(argv[1]) == "loop") {
        std::thread worker(worker_loop);
        for (int index = 0; index < 200; ++index) {
            work(index);
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
        g_running.store(false);
        worker.join();
        return g_counter;
    }

    const int result = work(1);
    return result == 0 ? 1 : 0;
}
