#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

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
        std::cerr << "usage: zara_plugin_marketplace_smoke <marketplace-root> <binary>\n";
        return 1;
    }

    const std::filesystem::path marketplace_root = std::filesystem::absolute(argv[1]);
    const std::filesystem::path binary_path = std::filesystem::absolute(argv[2]);
    const std::filesystem::path install_root = std::filesystem::temp_directory_path() / "zara_marketplace_plugins";
    const std::filesystem::path output_path = std::filesystem::temp_directory_path() / "zara_marketplace_plugin.txt";
    std::filesystem::remove_all(install_root);
    std::filesystem::remove(output_path);

    if (setenv("ZARA_PLUGIN_OUT", output_path.string().c_str(), 1) != 0) {
        std::cerr << "failed to set plugin output environment variable\n";
        return 2;
    }

    zara::plugins::PluginManager manager;
    std::vector<zara::plugins::MarketplacePlugin> marketplace_plugins;
    std::string error;
    if (!manager.discover_marketplace(marketplace_root, marketplace_plugins, error)) {
        std::cerr << "discover_marketplace failed: " << error << '\n';
        return 3;
    }
    if (marketplace_plugins.size() != 1 || marketplace_plugins.front().name != "Marketplace Echo") {
        std::cerr << "expected one marketplace plugin entry\n";
        return 4;
    }

    if (!manager.install_from_marketplace(marketplace_root, "Marketplace Echo", install_root, error)) {
        std::cerr << "install_from_marketplace failed: " << error << '\n';
        return 5;
    }

    if (!manager.load_all(install_root, error)) {
        std::cerr << "load_all failed after install: " << error << '\n';
        return 6;
    }
    if (manager.loaded_plugins().empty() || manager.loaded_plugins().front().name != "Marketplace Echo") {
        std::cerr << "expected installed plugin to be loadable\n";
        return 7;
    }
    if (!manager.run_analysis_hooks(binary_path, error)) {
        std::cerr << "run_analysis_hooks failed: " << error << '\n';
        return 8;
    }

    const auto content = read_text_file(output_path);
    if (!content.has_value() || content->find("marketplace:") != 0) {
        std::cerr << "unexpected marketplace plugin output\n";
        return 9;
    }

    return 0;
}
