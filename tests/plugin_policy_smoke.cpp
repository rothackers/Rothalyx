#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

#include "zara/plugins/manager.hpp"

namespace {

std::filesystem::path stage_plugin_fixture(const std::filesystem::path& plugin_directory, const std::string& suffix) {
    const auto root = std::filesystem::temp_directory_path() / ("zara_plugin_policy_" + suffix);
    std::error_code error;
    std::filesystem::remove_all(root, error);
    std::filesystem::create_directories(root, error);
    std::filesystem::copy(
        plugin_directory,
        root / plugin_directory.filename(),
        std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing,
        error
    );
    return root;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: zara_plugin_policy_smoke <denied-fixtures> <unsandboxed-fixtures>\n";
        return 1;
    }

    zara::plugins::PluginManager manager;
    if (!manager.is_available()) {
        std::cerr << "plugin manager is unavailable\n";
        return 2;
    }

    std::string error;
    const auto denied_root = stage_plugin_fixture(std::filesystem::absolute(argv[1]), "denied");
    if (manager.load_all(denied_root, error)) {
        std::cerr << "expected denied allow_imports fixture to fail\n";
        return 3;
    }
    if (error.find("rejects allow_imports entry") == std::string::npos) {
        std::cerr << "unexpected denied-allowlist error: " << error << '\n';
        return 4;
    }

    unsetenv("ZARA_ENABLE_UNSANDBOXED_PLUGINS");
    error.clear();
    const auto unsandboxed_root = stage_plugin_fixture(std::filesystem::absolute(argv[2]), "unsandboxed");
    if (manager.load_all(unsandboxed_root, error)) {
        std::cerr << "expected unsandboxed fixture to fail in production mode\n";
        return 5;
    }
    if (error.find("disabled by default") == std::string::npos) {
        std::cerr << "unexpected unsandboxed policy error: " << error << '\n';
        return 6;
    }

    return 0;
}
