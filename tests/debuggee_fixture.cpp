#include <chrono>
#include <string_view>
#include <thread>

namespace {

volatile int g_counter = 0;

[[gnu::noinline]] int work(const int value) {
    g_counter += value;
    return g_counter + 1;
}

}  // namespace

int main(const int argc, char** argv) {
    if (argc > 1 && std::string_view(argv[1]) == "loop") {
        for (int index = 0; index < 50; ++index) {
            work(index);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return g_counter;
    }

    const int result = work(1);
    return result == 0 ? 1 : 0;
}
