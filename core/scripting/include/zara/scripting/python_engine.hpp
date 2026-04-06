#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace zara::scripting {

class PythonEngine {
public:
    PythonEngine();
    ~PythonEngine();

    PythonEngine(const PythonEngine&) = delete;
    PythonEngine& operator=(const PythonEngine&) = delete;

    [[nodiscard]] bool is_available() const noexcept;
    [[nodiscard]] bool set_argv(const std::vector<std::string>& arguments, std::string& out_error);
    [[nodiscard]] bool execute_string(const std::string& source, std::string& out_error);
    [[nodiscard]] bool execute_file(const std::filesystem::path& path, std::string& out_error);
    [[nodiscard]] bool run_repl(std::string& out_error);

private:
    bool available_ = false;
    bool initialized_here_ = false;
};

}  // namespace zara::scripting
