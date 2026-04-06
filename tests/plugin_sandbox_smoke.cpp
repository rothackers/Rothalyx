#include <filesystem>
#include <iostream>
#include <string>

#include "zara/plugins/manager.hpp"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: zara_plugin_sandbox_smoke <plugins-dir>\n";
        return 1;
    }

    zara::plugins::PluginManager manager;
    if (!manager.is_available()) {
        std::cerr << "plugin manager is unavailable\n";
        return 2;
    }

    std::string error;
    if (manager.load_all(std::filesystem::absolute(argv[1]), error)) {
        std::cerr << "expected sandboxed plugin load to fail\n";
        return 3;
    }

    if (error.find("blocked by the Zara plugin sandbox") == std::string::npos) {
        std::cerr << "unexpected sandbox error: " << error << '\n';
        return 4;
    }

    return 0;
}
