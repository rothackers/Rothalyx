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
        std::cerr << "usage: zara_debugger_attach_smoke <debuggee>\n";
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

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

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

    if (event.reason != zara::debugger::StopReason::Attach) {
        std::cerr << "expected attach stop, got " << zara::debugger::to_string(event.reason) << '\n';
        return 5;
    }

    zara::debugger::RegisterState registers;
    if (!debugger->read_registers(registers, error)) {
        std::cerr << "read_registers failed: " << error << '\n';
        return 6;
    }

    if (registers.rip == 0) {
        std::cerr << "expected a non-zero instruction pointer after attach\n";
        return 7;
    }

    if (!debugger->detach(error)) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        std::cerr << "detach failed: " << error << '\n';
        return 8;
    }

    kill(child, SIGTERM);
    int status = 0;
    waitpid(child, &status, 0);
    return 0;
}
