#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "zara/analysis/program_analysis.hpp"
#include "zara/loader/binary_image.hpp"

namespace zara::debugger {

using ProcessId = int;

enum class TargetPlatform {
    Unknown,
    Windows,
    Linux,
    MacOS,
};

enum class BackendKind {
    Unsupported,
    LinuxPtrace,
    WindowsDbgEng,
    MacOSLldb,
};

enum class StopReason {
    None,
    Launch,
    Attach,
    Breakpoint,
    SingleStep,
    Signal,
    Exited,
    Terminated,
    Detached,
    Error,
};

struct StopEvent {
    StopReason reason = StopReason::None;
    ProcessId process_id = -1;
    ProcessId thread_id = -1;
    std::optional<std::uint64_t> address;
    int signal = 0;
    int exit_code = 0;
    std::string message;
};

struct RegisterState {
    std::uint64_t rip = 0;
    std::uint64_t rsp = 0;
    std::uint64_t rbp = 0;
    std::uint64_t rax = 0;
    std::uint64_t rbx = 0;
    std::uint64_t rcx = 0;
    std::uint64_t rdx = 0;
    std::uint64_t rsi = 0;
    std::uint64_t rdi = 0;
    std::uint64_t r8 = 0;
    std::uint64_t r9 = 0;
    std::uint64_t r10 = 0;
    std::uint64_t r11 = 0;
    std::uint64_t r12 = 0;
    std::uint64_t r13 = 0;
    std::uint64_t r14 = 0;
    std::uint64_t r15 = 0;
    std::uint64_t eflags = 0;
};

struct StaticLocation {
    std::string function_name;
    std::uint64_t function_entry = 0;
    std::uint64_t block_start = 0;
    std::uint64_t instruction_address = 0;
    std::string mnemonic;
    std::string operands;
    std::string pseudocode_excerpt;
};

struct RuntimeSnapshot {
    StopEvent stop;
    RegisterState registers;
    std::vector<std::byte> instruction_bytes;
    std::optional<StaticLocation> location;
};

struct TargetShape {
    TargetPlatform platform = TargetPlatform::Unknown;
    BackendKind backend = BackendKind::Unsupported;
    bool selected_on_host = false;
    bool implemented = false;
    std::vector<std::string> capabilities;
    std::string note;
};

struct ThreadInfo {
    ProcessId thread_id = -1;
    bool selected = false;
    bool stopped = false;
    std::optional<std::uint64_t> instruction_pointer;
    std::string state;
};

class DebugSession {
public:
    virtual ~DebugSession() = default;

    [[nodiscard]] virtual std::string_view backend_name() const noexcept = 0;
    [[nodiscard]] virtual bool is_supported() const noexcept = 0;
    [[nodiscard]] virtual bool is_active() const noexcept = 0;
    [[nodiscard]] virtual ProcessId process_id() const noexcept = 0;
    [[nodiscard]] virtual ProcessId current_thread_id() const noexcept = 0;

    [[nodiscard]] virtual bool launch(
        const std::filesystem::path& path,
        const std::vector<std::string>& arguments,
        StopEvent& out_event,
        std::string& out_error
    ) = 0;
    [[nodiscard]] virtual bool attach(
        ProcessId process_id,
        StopEvent& out_event,
        std::string& out_error
    ) = 0;
    [[nodiscard]] virtual bool continue_execution(StopEvent& out_event, std::string& out_error) = 0;
    [[nodiscard]] virtual bool single_step(StopEvent& out_event, std::string& out_error) = 0;
    [[nodiscard]] virtual bool list_threads(std::vector<ThreadInfo>& out_threads, std::string& out_error) const = 0;
    [[nodiscard]] virtual bool select_thread(ProcessId thread_id, std::string& out_error) = 0;
    [[nodiscard]] virtual bool read_registers(RegisterState& out_registers, std::string& out_error) const = 0;
    [[nodiscard]] virtual bool write_registers(const RegisterState& registers, std::string& out_error) = 0;
    [[nodiscard]] virtual bool read_memory(
        std::uint64_t address,
        std::size_t count,
        std::vector<std::byte>& out_bytes,
        std::string& out_error
    ) const = 0;
    [[nodiscard]] virtual bool write_memory(
        std::uint64_t address,
        std::span<const std::byte> bytes,
        std::string& out_error
    ) = 0;
    [[nodiscard]] virtual bool set_breakpoint(std::uint64_t address, std::string& out_error) = 0;
    [[nodiscard]] virtual bool remove_breakpoint(std::uint64_t address, std::string& out_error) = 0;
    [[nodiscard]] virtual bool detach(std::string& out_error) = 0;
    [[nodiscard]] virtual bool terminate(std::string& out_error) = 0;

    [[nodiscard]] static std::unique_ptr<DebugSession> create_native();
    [[nodiscard]] static std::vector<TargetShape> target_shapes();
};

[[nodiscard]] bool capture_runtime_snapshot(
    DebugSession& session,
    const loader::BinaryImage& image,
    const analysis::ProgramAnalysis& analysis,
    const StopEvent& stop,
    RuntimeSnapshot& out_snapshot,
    std::string& out_error
);

[[nodiscard]] std::string_view to_string(TargetPlatform platform) noexcept;
[[nodiscard]] std::string_view to_string(BackendKind backend) noexcept;
[[nodiscard]] std::string_view to_string(StopReason reason) noexcept;

}  // namespace zara::debugger
