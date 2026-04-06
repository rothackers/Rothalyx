#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "zara/debugger/session.hpp"
#include "zara/loader/binary_image.hpp"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: zara_debugger_launch_smoke <debuggee>\n";
        return 1;
    }

    const std::filesystem::path debuggee_path(argv[1]);

    zara::loader::BinaryImage image;
    std::string error;
    if (!zara::loader::BinaryImage::load_from_file(debuggee_path, image, error)) {
        std::cerr << "load failed: " << error << '\n';
        return 2;
    }

    if (!image.entry_point().has_value()) {
        std::cerr << "debuggee is missing an entry point\n";
        return 3;
    }

    const auto debugger = zara::debugger::DebugSession::create_native();
    if (!debugger->is_supported()) {
        std::cerr << "debugger backend is unavailable\n";
        return 4;
    }

    zara::debugger::StopEvent event;
    if (!debugger->launch(debuggee_path, {}, event, error)) {
        std::cerr << "launch failed: " << error << '\n';
        return 5;
    }

    if (event.reason != zara::debugger::StopReason::Launch) {
        std::cerr << "expected launch stop, got " << zara::debugger::to_string(event.reason) << '\n';
        return 6;
    }

    if (!debugger->set_breakpoint(*image.entry_point(), error)) {
        std::cerr << "set_breakpoint failed: " << error << '\n';
        return 7;
    }

    if (!debugger->continue_execution(event, error)) {
        std::cerr << "continue failed: " << error << '\n';
        return 8;
    }

    if (event.reason != zara::debugger::StopReason::Breakpoint ||
        !event.address.has_value() ||
        *event.address != *image.entry_point()) {
        std::cerr << "expected breakpoint at entry point\n";
        return 9;
    }

    zara::debugger::RegisterState registers;
    if (!debugger->read_registers(registers, error)) {
        std::cerr << "read_registers failed: " << error << '\n';
        return 10;
    }

    if (registers.rip != *image.entry_point()) {
        std::cerr << "expected RIP at entry breakpoint, got 0x" << std::hex << registers.rip << '\n';
        return 11;
    }

    std::vector<std::byte> memory;
    if (!debugger->read_memory(*image.entry_point(), 1, memory, error)) {
        std::cerr << "read_memory failed: " << error << '\n';
        return 12;
    }

    if (memory.empty()) {
        std::cerr << "expected to read entry-point memory\n";
        return 13;
    }

    if (!debugger->single_step(event, error)) {
        std::cerr << "single_step failed: " << error << '\n';
        return 14;
    }

    if (event.reason != zara::debugger::StopReason::SingleStep) {
        std::cerr << "expected single-step stop, got " << zara::debugger::to_string(event.reason) << '\n';
        return 15;
    }

    if (!debugger->read_registers(registers, error)) {
        std::cerr << "read_registers after single-step failed: " << error << '\n';
        return 16;
    }

    if (registers.rip == *image.entry_point()) {
        std::cerr << "expected RIP to advance after single-step\n";
        return 17;
    }

    if (!debugger->remove_breakpoint(*image.entry_point(), error)) {
        std::cerr << "remove_breakpoint failed: " << error << '\n';
        return 18;
    }

    while (true) {
        if (!debugger->continue_execution(event, error)) {
            std::cerr << "continue to exit failed: " << error << '\n';
            return 19;
        }

        if (event.reason == zara::debugger::StopReason::Exited) {
            break;
        }

        if (event.reason == zara::debugger::StopReason::Signal ||
            event.reason == zara::debugger::StopReason::SingleStep) {
            continue;
        }

        std::cerr << "unexpected terminal stop: " << zara::debugger::to_string(event.reason) << '\n';
        return 20;
    }

    if (event.exit_code != 0) {
        std::cerr << "expected debuggee exit code 0, got " << event.exit_code << '\n';
        return 21;
    }

    return 0;
}
