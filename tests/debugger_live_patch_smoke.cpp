#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <vector>

#include "zara/debugger/session.hpp"
#include "zara/loader/binary_image.hpp"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: zara_debugger_live_patch_smoke <debuggee>\n";
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

    if (!debugger->set_breakpoint(*image.entry_point(), error)) {
        std::cerr << "set_breakpoint failed: " << error << '\n';
        return 6;
    }

    if (!debugger->continue_execution(event, error)) {
        std::cerr << "continue failed: " << error << '\n';
        return 7;
    }

    if (event.reason != zara::debugger::StopReason::Breakpoint ||
        !event.address.has_value() ||
        *event.address != *image.entry_point()) {
        std::cerr << "expected entry breakpoint before patching\n";
        return 8;
    }

    zara::debugger::RegisterState registers;
    if (!debugger->read_registers(registers, error)) {
        std::cerr << "read_registers failed: " << error << '\n';
        return 9;
    }

    std::vector<std::byte> original;
    if (!debugger->read_memory(registers.rsp, 8, original, error) || original.size() != 8) {
        std::cerr << "read_memory failed at stack pointer: " << error << '\n';
        return 10;
    }

    const std::array<std::byte, 8> patch_bytes{
        std::byte{0x41},
        std::byte{0x42},
        std::byte{0x43},
        std::byte{0x44},
        std::byte{0x45},
        std::byte{0x46},
        std::byte{0x47},
        std::byte{0x48},
    };
    if (!debugger->write_memory(registers.rsp, patch_bytes, error)) {
        std::cerr << "write_memory failed: " << error << '\n';
        return 11;
    }

    std::vector<std::byte> observed;
    if (!debugger->read_memory(registers.rsp, patch_bytes.size(), observed, error)) {
        std::cerr << "read_memory after patch failed: " << error << '\n';
        return 12;
    }

    if (!std::equal(patch_bytes.begin(), patch_bytes.end(), observed.begin(), observed.end())) {
        std::cerr << "patched bytes were not observed in runtime memory\n";
        return 13;
    }

    if (!debugger->write_memory(registers.rsp, original, error)) {
        std::cerr << "restoring original stack bytes failed: " << error << '\n';
        return 14;
    }

    std::vector<std::byte> restored;
    if (!debugger->read_memory(registers.rsp, original.size(), restored, error)) {
        std::cerr << "read_memory after restore failed: " << error << '\n';
        return 15;
    }
    if (restored != original) {
        std::cerr << "stack bytes did not restore cleanly after patch\n";
        return 16;
    }

    if (!debugger->remove_breakpoint(*image.entry_point(), error)) {
        std::cerr << "remove_breakpoint failed: " << error << '\n';
        return 17;
    }

    while (true) {
        if (!debugger->continue_execution(event, error)) {
            std::cerr << "continue to exit failed: " << error << '\n';
            return 18;
        }

        if (event.reason == zara::debugger::StopReason::Exited) {
            break;
        }
        if (event.reason == zara::debugger::StopReason::Signal ||
            event.reason == zara::debugger::StopReason::SingleStep) {
            continue;
        }

        std::cerr << "unexpected stop after patch validation: " << zara::debugger::to_string(event.reason) << '\n';
        return 19;
    }

    return 0;
}
