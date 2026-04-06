#include <algorithm>
#include <iostream>
#include <string_view>

#include "zara/debugger/session.hpp"

int main() {
    const auto shapes = zara::debugger::DebugSession::target_shapes();
    if (shapes.size() != 3) {
        std::cerr << "expected three debugger target shapes\n";
        return 1;
    }

    const auto has_windows = std::any_of(
        shapes.begin(),
        shapes.end(),
        [](const zara::debugger::TargetShape& shape) {
            return shape.platform == zara::debugger::TargetPlatform::Windows &&
                   shape.backend == zara::debugger::BackendKind::WindowsDbgEng;
        }
    );
    const auto has_linux = std::any_of(
        shapes.begin(),
        shapes.end(),
        [](const zara::debugger::TargetShape& shape) {
            return shape.platform == zara::debugger::TargetPlatform::Linux &&
                   shape.backend == zara::debugger::BackendKind::LinuxPtrace &&
                   shape.implemented;
        }
    );
    const auto has_macos = std::any_of(
        shapes.begin(),
        shapes.end(),
        [](const zara::debugger::TargetShape& shape) {
            return shape.platform == zara::debugger::TargetPlatform::MacOS &&
                   shape.backend == zara::debugger::BackendKind::MacOSLldb;
        }
    );

    if (!has_windows || !has_linux || !has_macos) {
        std::cerr << "missing debugger target shape descriptors\n";
        return 2;
    }

    const auto selected_count = static_cast<int>(std::count_if(
        shapes.begin(),
        shapes.end(),
        [](const zara::debugger::TargetShape& shape) { return shape.selected_on_host; }
    ));
    if (selected_count != 1) {
        std::cerr << "expected exactly one host-selected debugger target shape\n";
        return 3;
    }

    const auto native = zara::debugger::DebugSession::create_native();
    if (!native) {
        std::cerr << "failed to create native debugger session\n";
        return 4;
    }

#if defined(__linux__)
    if (native->backend_name() != std::string_view("linux-ptrace") || !native->is_supported()) {
        std::cerr << "unexpected linux debugger backend\n";
        return 5;
    }
#elif defined(_WIN32)
    if (native->backend_name() != std::string_view("windows-dbgeng") || !native->is_supported()) {
        std::cerr << "unexpected windows debugger backend name\n";
        return 6;
    }
#elif defined(__APPLE__)
    if (native->backend_name() != std::string_view("macos-lldb") || !native->is_supported()) {
        std::cerr << "unexpected macos debugger backend name\n";
        return 7;
    }
#endif

    return 0;
}
