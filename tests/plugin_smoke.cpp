#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>

#include "zara/plugins/manager.hpp"

namespace {

std::optional<std::string> read_text_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        return std::nullopt;
    }

    std::ostringstream stream;
    stream << input.rdbuf();
    return stream.str();
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: zara_plugin_smoke <plugins-dir> <binary>\n";
        return 1;
    }

    const std::filesystem::path plugins_dir = std::filesystem::absolute(argv[1]);
    const std::filesystem::path binary_path = std::filesystem::absolute(argv[2]);
    const std::filesystem::path output_path = std::filesystem::temp_directory_path() / "zara_plugin_smoke.txt";
    std::filesystem::remove(output_path);

    if (setenv("ZARA_PLUGIN_OUT", output_path.string().c_str(), 1) != 0) {
        std::cerr << "failed to set plugin output environment variable\n";
        return 2;
    }

    zara::plugins::PluginManager manager;
    if (!manager.is_available()) {
        std::cerr << "plugin manager is unavailable\n";
        return 3;
    }

    std::string error;
    if (!manager.load_all(plugins_dir, error)) {
        std::cerr << "load_all failed: " << error << '\n';
        return 4;
    }

    if (manager.loaded_plugins().size() != 1 || manager.loaded_plugins().front().name != "Echo Plugin") {
        std::cerr << "expected exactly one discovered plugin\n";
        return 5;
    }
    if (manager.loaded_plugins().front().version != "1.0.0") {
        std::cerr << "expected plugin version metadata\n";
        return 9;
    }
    if (!manager.loaded_plugins().front().sandboxed) {
        std::cerr << "expected sandboxed plugin metadata\n";
        return 11;
    }

    if (!manager.run_analysis_hooks(binary_path, error)) {
        std::cerr << "run_analysis_hooks failed: " << error << '\n';
        return 6;
    }

    const auto content = read_text_file(output_path);
    if (!content.has_value()) {
        std::cerr << "plugin output file was not created\n";
        return 7;
    }

    if (content->rfind("elf|", 0) != 0) {
        std::cerr << "unexpected plugin output: " << *content << '\n';
        return 8;
    }
    if (content->find("|program=") == std::string::npos ||
        content->find("|ai=") == std::string::npos ||
        content->find("|security=") == std::string::npos ||
        content->find("|functions=") == std::string::npos) {
        std::cerr << "expected richer plugin hook output: " << *content << '\n';
        return 10;
    }

    return 0;
}
