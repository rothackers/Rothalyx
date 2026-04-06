#include <filesystem>
#include <iostream>
#include <string>

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <unistd.h>
#endif

#include "zara/scripting/python_engine.hpp"

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: zara_distributed_scripting_smoke <binary-a> <binary-b>\n";
        return 1;
    }

#if !defined(__linux__) && !defined(__APPLE__) && !defined(__unix__)
    std::cerr << "distributed scripting smoke is unsupported on this platform\n";
    return 0;
#else
    const std::filesystem::path binary_a = std::filesystem::absolute(argv[1]);
    const std::filesystem::path binary_b = std::filesystem::absolute(argv[2]);
    const auto temp_root = std::filesystem::temp_directory_path() / "zara_distributed_scripting_smoke";
    const auto input_root = temp_root / "inputs";
    const auto controller_output = temp_root / "controller";
    const auto worker_output = temp_root / "worker";
    const std::string shared_secret = "zara-scripting-remote-secret";

    std::error_code filesystem_error;
    std::filesystem::remove_all(temp_root, filesystem_error);
    std::filesystem::create_directories(input_root, filesystem_error);
    std::filesystem::copy_file(binary_a, input_root / "fixture_a.bin", std::filesystem::copy_options::overwrite_existing, filesystem_error);
    std::filesystem::copy_file(binary_b, input_root / "fixture_b.bin", std::filesystem::copy_options::overwrite_existing, filesystem_error);

    zara::scripting::PythonEngine engine;
    if (!engine.is_available()) {
        std::cerr << "embedded python is unavailable\n";
        return 2;
    }

    std::string error;
    if (!engine.set_argv({"distributed_scripting_smoke"}, error)) {
        std::cerr << "set_argv failed: " << error << '\n';
        return 3;
    }

    const unsigned int port = 40000u + static_cast<unsigned int>(getpid() % 1000);
    const std::string script =
        "from pathlib import Path\n"
        "import threading\n"
        "import time\n"
        "import zara\n"
        "inputs = zara.discover_inputs(r'" + input_root.string() + "', recursive=False)\n"
        "assert len(inputs) == 2\n"
        "controller_output = Path(r'" + controller_output.string() + "')\n"
        "worker_output = Path(r'" + worker_output.string() + "')\n"
        "holder = {}\n"
        "errors = []\n"
        "def controller():\n"
        "    try:\n"
        "        holder['result'] = zara.run_remote_batch(inputs, str(controller_output), port=" + std::to_string(port) + ", shared_secret='" + shared_secret + "', expected_workers=1, write_reports=True)\n"
        "    except Exception as exc:\n"
        "        errors.append(str(exc))\n"
        "thread = threading.Thread(target=controller)\n"
        "thread.start()\n"
        "time.sleep(0.2)\n"
        "worker = zara.run_remote_worker(str(worker_output), port=" + std::to_string(port) + ", shared_secret='" + shared_secret + "')\n"
        "thread.join()\n"
        "assert not errors, errors\n"
        "assert holder['result']['remote'] is True\n"
        "assert holder['result']['success_count'] == 2\n"
        "assert len(holder['result']['workers']) == 1\n"
        "assert worker['status'] == 'completed'\n"
        "assert (controller_output / 'manifest.tsv').exists()\n"
        "assert (controller_output / 'summary.json').exists()\n";

    if (!engine.execute_string(script, error)) {
        std::cerr << "script execution failed: " << error << '\n';
        return 4;
    }

    return 0;
#endif
}
