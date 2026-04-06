#pragma once

#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "zara/scripting/python_engine.hpp"

namespace zara::plugins {

struct PluginDescriptor {
    std::string name;
    std::string version = "1.0.0";
    std::string api_version = "1";
    std::string description;
    std::string module_name;
    std::filesystem::path root_path;
    std::filesystem::path entry_script;
    std::vector<std::string> capabilities;
    std::vector<std::string> declared_hooks;
    bool sandboxed = false;
    std::size_t timeout_ms = 5000;
    std::vector<std::string> allowed_imports;
    std::vector<std::string> allowed_env;
};

struct MarketplacePlugin {
    std::string name;
    std::string version = "1.0.0";
    std::string api_version = "1";
    std::string description;
    std::filesystem::path root_path;
    std::filesystem::path package_path;
    std::filesystem::path entry_script;
    std::vector<std::string> capabilities;
    std::vector<std::string> declared_hooks;
    bool sandboxed = false;
};

class PluginManager {
public:
    PluginManager();
    ~PluginManager();

    [[nodiscard]] bool is_available() const noexcept;
    [[nodiscard]] bool discover(
        const std::filesystem::path& plugins_directory,
        std::vector<PluginDescriptor>& out_plugins,
        std::string& out_error
    ) const;
    [[nodiscard]] bool load_all(const std::filesystem::path& plugins_directory, std::string& out_error);
    [[nodiscard]] bool run_analysis_hooks(const std::filesystem::path& binary_path, std::string& out_error);
    [[nodiscard]] bool discover_marketplace(
        const std::filesystem::path& marketplace_root,
        std::vector<MarketplacePlugin>& out_plugins,
        std::string& out_error
    ) const;
    [[nodiscard]] bool install_from_marketplace(
        const std::filesystem::path& marketplace_root,
        const std::string& plugin_name,
        const std::filesystem::path& destination_root,
        std::string& out_error
    ) const;
    [[nodiscard]] const std::vector<PluginDescriptor>& loaded_plugins() const noexcept;

private:
    struct SandboxRuntime {
        std::string module_name;
        std::filesystem::path entry_script;
        std::size_t timeout_ms = 5000;
        int process_id = -1;
        int output_fd = -1;
        std::FILE* input_stream = nullptr;
    };

    [[nodiscard]] bool start_sandbox(const PluginDescriptor& plugin, std::string& out_error);
    [[nodiscard]] bool stop_sandbox(SandboxRuntime& runtime, std::string& out_error);
    void stop_all_sandboxes() noexcept;
    [[nodiscard]] bool send_sandbox_hook(
        const PluginDescriptor& plugin,
        const std::string& hook_name,
        const std::string& payload_json,
        std::string& out_error
    );
    [[nodiscard]] bool run_hook_script(const std::string& script, const std::string& failure_context, std::string& out_error);
    [[nodiscard]] SandboxRuntime* find_sandbox(const std::string& module_name) noexcept;

    scripting::PythonEngine engine_;
    std::vector<PluginDescriptor> loaded_plugins_;
    std::vector<SandboxRuntime> sandboxes_;
};

}  // namespace zara::plugins
