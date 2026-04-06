#include <filesystem>
#include <iostream>
#include <string>

#include "zara/analysis/program_analysis.hpp"
#include "zara/debugger/session.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: zara_debugger_integration_smoke <debuggee>\n";
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

    zara::memory::AddressSpace address_space;
    if (!address_space.map_image(image)) {
        std::cerr << "failed to map debuggee image\n";
        return 4;
    }
    const auto analysis = zara::analysis::Analyzer::analyze(image, address_space);

    const auto debugger = zara::debugger::DebugSession::create_native();
    if (!debugger->is_supported()) {
        std::cerr << "debugger backend is unavailable\n";
        return 5;
    }

    zara::debugger::StopEvent event;
    if (!debugger->launch(debuggee_path, {}, event, error)) {
        std::cerr << "launch failed: " << error << '\n';
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

    zara::debugger::RuntimeSnapshot snapshot;
    if (!zara::debugger::capture_runtime_snapshot(*debugger, image, analysis, event, snapshot, error)) {
        std::cerr << "runtime snapshot failed: " << error << '\n';
        return 9;
    }

    std::string ignore_error;
    (void)debugger->terminate(ignore_error);

    if (snapshot.registers.rip != *image.entry_point()) {
        std::cerr << "expected snapshot RIP at entry point\n";
        return 10;
    }
    if (snapshot.instruction_bytes.empty()) {
        std::cerr << "expected instruction bytes in runtime snapshot\n";
        return 11;
    }
    if (!snapshot.location.has_value()) {
        std::cerr << "expected static/runtime correlated location\n";
        return 12;
    }
    if (snapshot.location->function_entry != *image.entry_point()) {
        std::cerr << "runtime snapshot resolved wrong function\n";
        return 13;
    }
    if (snapshot.location->mnemonic.empty() || snapshot.location->pseudocode_excerpt.empty()) {
        std::cerr << "runtime snapshot is missing instruction or pseudocode context\n";
        return 14;
    }

    return 0;
}
