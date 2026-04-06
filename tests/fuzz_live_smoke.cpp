#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>

#include "zara/security/workflow.hpp"

int main() {
    const auto temp_root = std::filesystem::temp_directory_path() / "zara_fuzz_live_smoke";
    std::error_code remove_error;
    std::filesystem::remove_all(temp_root, remove_error);
    std::filesystem::create_directories(temp_root);

    const auto script_path = temp_root / "synthetic_fuzzer.sh";
    {
        std::ofstream script(script_path);
        script << "#!/bin/sh\n";
        script << "echo '#1 INITED cov: 8 ft: 8 corp: 1/1b exec/s: 0'\n";
        script << "echo 'execs_done=42 paths_total=6 cycles_done=1'\n";
        script << "echo '==ERROR: AddressSanitizer: heap-buffer-overflow'\n";
        script << "exit 0\n";
    }
    std::filesystem::permissions(
        script_path,
        std::filesystem::perms::owner_exec | std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::add,
        remove_error
    );

    std::size_t callback_count = 0;
    zara::security::LiveFuzzResult result;
    std::string error;
    if (!zara::security::Workflow::run_live_fuzz_tool(
            script_path.string(),
            zara::security::LiveFuzzOptions{
                .working_directory = temp_root,
                .engine_hint = "afl libfuzzer",
                .max_output_lines = 32,
                .max_line_bytes = 4096,
                .on_event = [&](const zara::security::FuzzProgressEvent&) { ++callback_count; },
            },
            result,
            error
        )) {
        std::cerr << "run_live_fuzz_tool failed: " << error << '\n';
        return 1;
    }

    if (result.exit_code != 0) {
        std::cerr << "expected zero exit code, got " << result.exit_code << '\n';
        return 2;
    }
    if (result.output_lines.size() != 3 || result.events.size() != 3 || callback_count != 3) {
        std::cerr << "expected three live fuzz lines/events\n";
        return 3;
    }

    const auto has_libfuzzer = std::any_of(
        result.events.begin(),
        result.events.end(),
        [](const zara::security::FuzzProgressEvent& event) {
            return event.kind == "libfuzzer-progress" && event.coverage.has_value() && *event.coverage == 8;
        }
    );
    const auto has_afl = std::any_of(
        result.events.begin(),
        result.events.end(),
        [](const zara::security::FuzzProgressEvent& event) {
            return event.kind == "afl-progress" && event.executions.has_value() && *event.executions == 42;
        }
    );
    if (!has_libfuzzer || !has_afl || !result.crash_detected) {
        std::cerr << "expected parsed libFuzzer/AFL progress and crash detection\n";
        return 4;
    }

    std::filesystem::remove_all(temp_root, remove_error);
    return 0;
}
