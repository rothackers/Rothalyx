#include <algorithm>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zara/debugger/session.hpp"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: zara_debugger_threads_smoke <debuggee>\n";
        return 1;
    }

    const std::filesystem::path debuggee_path(argv[1]);
    const pid_t child = fork();
    if (child < 0) {
        std::cerr << "fork failed\n";
        return 2;
    }

    if (child == 0) {
        execl(debuggee_path.c_str(), debuggee_path.c_str(), "loop", nullptr);
        _exit(127);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    const auto debugger = zara::debugger::DebugSession::create_native();
    if (!debugger->is_supported()) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        std::cerr << "debugger backend is unavailable\n";
        return 3;
    }

    std::string error;
    zara::debugger::StopEvent event;
    if (!debugger->attach(child, event, error)) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        std::cerr << "attach failed: " << error << '\n';
        return 4;
    }

    std::vector<zara::debugger::ThreadInfo> threads;
    if (!debugger->list_threads(threads, error)) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        std::cerr << "list_threads failed: " << error << '\n';
        return 5;
    }

    if (threads.size() < 2) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        std::cerr << "expected at least two attached threads\n";
        return 6;
    }

    const auto current_thread = debugger->current_thread_id();
    auto selected_it = std::find_if(
        threads.begin(),
        threads.end(),
        [current_thread](const auto& thread) { return thread.thread_id != current_thread; }
    );
    if (selected_it == threads.end()) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        std::cerr << "failed to find a non-current thread\n";
        return 7;
    }

    if (!debugger->select_thread(selected_it->thread_id, error)) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        std::cerr << "select_thread failed: " << error << '\n';
        return 8;
    }

    zara::debugger::RegisterState registers;
    if (!debugger->read_registers(registers, error)) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        std::cerr << "read_registers on selected thread failed: " << error << '\n';
        return 9;
    }

    if (registers.rip == 0) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        std::cerr << "expected a non-zero instruction pointer on the selected thread\n";
        return 10;
    }

    if (!debugger->detach(error)) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        std::cerr << "detach failed: " << error << '\n';
        return 11;
    }

    kill(child, SIGTERM);
    int status = 0;
    waitpid(child, &status, 0);
    return 0;
}
