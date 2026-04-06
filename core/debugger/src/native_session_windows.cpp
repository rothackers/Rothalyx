#include "zara/debugger/session.hpp"

#if defined(_WIN32)

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace zara::debugger {

namespace {

constexpr std::uint8_t kBreakpointOpcode = 0xCC;
constexpr DWORD kThreadAccessMask =
    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME;

std::string win_error_message(const std::string_view prefix) {
    const DWORD code = GetLastError();
    LPSTR buffer = nullptr;
    const DWORD length = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&buffer),
        0,
        nullptr
    );

    std::string message(prefix);
    message += ": ";
    if (length == 0 || buffer == nullptr) {
        message += "Win32 error ";
        message += std::to_string(code);
        return message;
    }

    message.append(buffer, buffer + length);
    while (!message.empty() && (message.back() == '\r' || message.back() == '\n' || message.back() == ' ')) {
        message.pop_back();
    }
    LocalFree(buffer);
    return message;
}

std::wstring utf8_to_wide(const std::string& value) {
    if (value.empty()) {
        return {};
    }

    const int wide_length = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    if (wide_length <= 1) {
        return std::wstring(value.begin(), value.end());
    }

    std::wstring wide(static_cast<std::size_t>(wide_length - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, wide.data(), wide_length);
    return wide;
}

std::wstring quote_argument(const std::wstring& value) {
    if (value.find_first_of(L" \t\"") == std::wstring::npos) {
        return value;
    }

    std::wstring quoted;
    quoted.push_back(L'"');
    std::size_t slash_count = 0;
    for (const wchar_t ch : value) {
        if (ch == L'\\') {
            ++slash_count;
            continue;
        }
        if (ch == L'"') {
            quoted.append(slash_count * 2 + 1, L'\\');
            quoted.push_back(L'"');
            slash_count = 0;
            continue;
        }
        if (slash_count > 0) {
            quoted.append(slash_count, L'\\');
            slash_count = 0;
        }
        quoted.push_back(ch);
    }
    if (slash_count > 0) {
        quoted.append(slash_count * 2, L'\\');
    }
    quoted.push_back(L'"');
    return quoted;
}

std::wstring build_command_line(const std::filesystem::path& path, const std::vector<std::string>& arguments) {
    std::wstring command_line = quote_argument(path.wstring());
    for (const auto& argument : arguments) {
        command_line.push_back(L' ');
        command_line += quote_argument(utf8_to_wide(argument));
    }
    return command_line;
}

void close_handle_if_valid(HANDLE& handle) {
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
    }
    handle = nullptr;
}

struct BreakpointState {
    std::uint64_t address = 0;
    std::uint8_t original_byte = 0;
    bool enabled = false;
};

class WindowsDbgSession final : public DebugSession {
public:
    ~WindowsDbgSession() override {
        std::string ignore_error;
        if (is_active()) {
            if (launch_owned_) {
                (void)terminate(ignore_error);
            } else {
                (void)detach(ignore_error);
            }
        }
        close_all_handles();
    }

    [[nodiscard]] std::string_view backend_name() const noexcept override {
        return "windows-dbgeng";
    }

    [[nodiscard]] bool is_supported() const noexcept override {
        return true;
    }

    [[nodiscard]] bool is_active() const noexcept override {
        return active_;
    }

    [[nodiscard]] ProcessId process_id() const noexcept override {
        return leader_process_id_;
    }

    [[nodiscard]] ProcessId current_thread_id() const noexcept override {
        return current_thread_id_;
    }

    [[nodiscard]] bool launch(
        const std::filesystem::path& path,
        const std::vector<std::string>& arguments,
        StopEvent& out_event,
        std::string& out_error
    ) override {
        out_error.clear();
        out_event = {};

        if (active_) {
            out_error = "A debug session is already active.";
            return false;
        }

        std::wstring command_line = build_command_line(path, arguments);
        std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
        mutable_command.push_back(L'\0');

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process_info{};
        const DWORD creation_flags = DEBUG_ONLY_THIS_PROCESS;
        if (!CreateProcessW(
                path.wstring().c_str(),
                mutable_command.data(),
                nullptr,
                nullptr,
                FALSE,
                creation_flags,
                nullptr,
                nullptr,
                &startup,
                &process_info
            )) {
            out_error = win_error_message("CreateProcessW failed");
            return false;
        }

        process_handle_ = process_info.hProcess;
        thread_handles_[static_cast<ProcessId>(process_info.dwThreadId)] = process_info.hThread;
        leader_process_id_ = static_cast<ProcessId>(process_info.dwProcessId);
        current_thread_id_ = static_cast<ProcessId>(process_info.dwThreadId);
        active_ = true;
        launch_owned_ = true;
        ignore_initial_breakpoint_ = true;
        breakpoints_.clear();
        pending_breakpoint_.reset();
        debug_event_pending_ = false;
        stopped_threads_.clear();
        stopped_threads_.insert(current_thread_id_);
        DebugSetProcessKillOnExit(FALSE);

        if (!wait_for_event(WaitMode::Launch, out_event, out_error)) {
            cleanup_after_failure();
            return false;
        }

        if (out_event.reason != StopReason::Launch) {
            out_error = "Process did not stop in a debuggable launch state.";
            cleanup_after_failure();
            return false;
        }

        return true;
    }

    [[nodiscard]] bool attach(
        const ProcessId process_id,
        StopEvent& out_event,
        std::string& out_error
    ) override {
        out_error.clear();
        out_event = {};

        if (active_) {
            out_error = "A debug session is already active.";
            return false;
        }

        if (!DebugActiveProcess(static_cast<DWORD>(process_id))) {
            out_error = win_error_message("DebugActiveProcess failed");
            return false;
        }
        DebugSetProcessKillOnExit(FALSE);

        process_handle_ = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_TERMINATE,
            FALSE,
            static_cast<DWORD>(process_id)
        );
        if (process_handle_ == nullptr) {
            DebugActiveProcessStop(static_cast<DWORD>(process_id));
            out_error = win_error_message("OpenProcess failed");
            return false;
        }

        leader_process_id_ = process_id;
        current_thread_id_ = process_id;
        active_ = true;
        launch_owned_ = false;
        ignore_initial_breakpoint_ = false;
        breakpoints_.clear();
        pending_breakpoint_.reset();
        debug_event_pending_ = false;
        stopped_threads_.clear();

        if (!wait_for_event(WaitMode::Attach, out_event, out_error)) {
            cleanup_after_failure();
            return false;
        }

        if (out_event.reason != StopReason::Attach) {
            out_error = "Process did not stop in an attachable state.";
            cleanup_after_failure();
            return false;
        }

        return true;
    }

    [[nodiscard]] bool continue_execution(StopEvent& out_event, std::string& out_error) override {
        out_error.clear();
        out_event = {};

        if (!active_) {
            out_error = "No active debug session.";
            return false;
        }

        if (pending_breakpoint_.has_value()) {
            StopEvent stepped;
            if (!step_over_pending_breakpoint(stepped, out_error)) {
                return false;
            }
        }

        if (!continue_last_event(pending_continue_status_, out_error)) {
            return false;
        }
        return wait_for_event(WaitMode::Continue, out_event, out_error);
    }

    [[nodiscard]] bool single_step(StopEvent& out_event, std::string& out_error) override {
        out_error.clear();
        out_event = {};

        if (!active_) {
            out_error = "No active debug session.";
            return false;
        }

        if (pending_breakpoint_.has_value()) {
            return step_over_pending_breakpoint(out_event, out_error);
        }

        if (!set_trap_flag(current_thread_id_, true, out_error)) {
            return false;
        }

        if (!continue_last_event(DBG_CONTINUE, out_error)) {
            return false;
        }
        return wait_for_event(WaitMode::SingleStep, out_event, out_error);
    }

    [[nodiscard]] bool list_threads(std::vector<ThreadInfo>& out_threads, std::string& out_error) const override {
        out_error.clear();
        out_threads.clear();

        if (!active_) {
            out_error = "No active debug session.";
            return false;
        }

        std::set<ProcessId> thread_ids;
        for (const auto& [thread_id, _] : thread_handles_) {
            thread_ids.insert(thread_id);
        }

        for (const auto thread_id : thread_ids) {
            ThreadInfo info;
            info.thread_id = thread_id;
            info.selected = thread_id == current_thread_id_;
            info.stopped = stopped_threads_.contains(thread_id);
            info.state = info.stopped ? "stopped" : "running";

            RegisterState registers;
            std::string ignore_error;
            if (read_registers_for_thread(thread_id, registers, ignore_error)) {
                info.instruction_pointer = registers.rip;
            }
            out_threads.push_back(std::move(info));
        }
        return true;
    }

    [[nodiscard]] bool select_thread(const ProcessId thread_id, std::string& out_error) override {
        out_error.clear();
        if (!active_) {
            out_error = "No active debug session.";
            return false;
        }

        if (!ensure_thread_handle(thread_id, out_error)) {
            return false;
        }
        current_thread_id_ = thread_id;
        return true;
    }

    [[nodiscard]] bool read_registers(RegisterState& out_registers, std::string& out_error) const override {
        out_error.clear();
        out_registers = {};
        if (!active_) {
            out_error = "No active debug session.";
            return false;
        }
        return read_registers_for_thread(current_thread_id_, out_registers, out_error);
    }

    [[nodiscard]] bool write_registers(const RegisterState& registers, std::string& out_error) override {
        out_error.clear();
        if (!active_) {
            out_error = "No active debug session.";
            return false;
        }
        return write_registers_for_thread(current_thread_id_, registers, out_error);
    }

    [[nodiscard]] bool read_memory(
        const std::uint64_t address,
        const std::size_t count,
        std::vector<std::byte>& out_bytes,
        std::string& out_error
    ) const override {
        out_error.clear();
        out_bytes.clear();

        if (!active_ || process_handle_ == nullptr) {
            out_error = "No active debug session.";
            return false;
        }

        out_bytes.resize(count);
        SIZE_T bytes_read = 0;
        if (!ReadProcessMemory(
                process_handle_,
                reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
                out_bytes.data(),
                count,
                &bytes_read
            )) {
            out_error = win_error_message("ReadProcessMemory failed");
            out_bytes.clear();
            return false;
        }

        out_bytes.resize(static_cast<std::size_t>(bytes_read));
        return bytes_read == count;
    }

    [[nodiscard]] bool write_memory(
        const std::uint64_t address,
        const std::span<const std::byte> bytes,
        std::string& out_error
    ) override {
        out_error.clear();
        if (!active_ || process_handle_ == nullptr) {
            out_error = "No active debug session.";
            return false;
        }
        if (bytes.empty()) {
            return true;
        }

        SIZE_T bytes_written = 0;
        if (!WriteProcessMemory(
                process_handle_,
                reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(address)),
                bytes.data(),
                bytes.size(),
                &bytes_written
            )) {
            out_error = win_error_message("WriteProcessMemory failed");
            return false;
        }

        FlushInstructionCache(
            process_handle_,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
            bytes.size()
        );
        return bytes_written == bytes.size();
    }

    [[nodiscard]] bool set_breakpoint(const std::uint64_t address, std::string& out_error) override {
        out_error.clear();
        if (!active_) {
            out_error = "No active debug session.";
            return false;
        }

        auto existing = breakpoints_.find(address);
        if (existing != breakpoints_.end() && existing->second.enabled) {
            return true;
        }

        std::vector<std::byte> bytes;
        if (!read_memory(address, 1, bytes, out_error) || bytes.empty()) {
            return false;
        }
        if (!write_memory(address, std::array<std::byte, 1>{std::byte{kBreakpointOpcode}}, out_error)) {
            return false;
        }

        breakpoints_[address] = BreakpointState{
            .address = address,
            .original_byte = static_cast<std::uint8_t>(std::to_integer<unsigned int>(bytes.front())),
            .enabled = true,
        };
        return true;
    }

    [[nodiscard]] bool remove_breakpoint(const std::uint64_t address, std::string& out_error) override {
        out_error.clear();
        if (!active_) {
            out_error = "No active debug session.";
            return false;
        }

        auto breakpoint_it = breakpoints_.find(address);
        if (breakpoint_it == breakpoints_.end()) {
            return true;
        }

        if (breakpoint_it->second.enabled) {
            const std::array<std::byte, 1> original{
                static_cast<std::byte>(breakpoint_it->second.original_byte),
            };
            if (!write_memory(address, original, out_error)) {
                return false;
            }
        }

        breakpoints_.erase(breakpoint_it);
        if (pending_breakpoint_.has_value() && pending_breakpoint_->address == address) {
            pending_breakpoint_.reset();
        }
        return true;
    }

    [[nodiscard]] bool detach(std::string& out_error) override {
        out_error.clear();
        if (!active_) {
            return true;
        }

        if (!restore_all_breakpoints(out_error)) {
            return false;
        }

        if (debug_event_pending_) {
            if (!continue_last_event(DBG_CONTINUE, out_error)) {
                return false;
            }
        }

        if (!DebugActiveProcessStop(static_cast<DWORD>(leader_process_id_))) {
            out_error = win_error_message("DebugActiveProcessStop failed");
            return false;
        }

        reset_state();
        return true;
    }

    [[nodiscard]] bool terminate(std::string& out_error) override {
        out_error.clear();
        if (!active_) {
            return true;
        }

        if (debug_event_pending_) {
            std::string continue_error;
            (void)continue_last_event(DBG_CONTINUE, continue_error);
        }

        if (process_handle_ != nullptr && !TerminateProcess(process_handle_, 0)) {
            out_error = win_error_message("TerminateProcess failed");
            return false;
        }

        DEBUG_EVENT event{};
        while (WaitForDebugEvent(&event, 2000)) {
            const bool is_exit =
                event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT &&
                static_cast<ProcessId>(event.dwProcessId) == leader_process_id_;
            ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
            if (is_exit) {
                break;
            }
        }

        reset_state();
        return true;
    }

private:
    struct PendingBreakpoint {
        ProcessId thread_id = -1;
        std::uint64_t address = 0;
    };

    enum class WaitMode {
        Launch,
        Attach,
        Continue,
        SingleStep,
    };

    [[nodiscard]] HANDLE thread_handle(const ProcessId thread_id) const {
        const auto it = thread_handles_.find(thread_id);
        return it == thread_handles_.end() ? nullptr : it->second;
    }

    [[nodiscard]] bool ensure_thread_handle(const ProcessId thread_id, std::string& out_error) {
        if (thread_handle(thread_id) != nullptr) {
            return true;
        }

        HANDLE handle = OpenThread(kThreadAccessMask, FALSE, static_cast<DWORD>(thread_id));
        if (handle == nullptr) {
            out_error = win_error_message("OpenThread failed");
            return false;
        }

        thread_handles_[thread_id] = handle;
        return true;
    }

    [[nodiscard]] bool read_registers_for_thread(
        const ProcessId thread_id,
        RegisterState& out_registers,
        std::string& out_error
    ) const {
        out_error.clear();
        out_registers = {};

        HANDLE handle = thread_handle(thread_id);
        if (handle == nullptr) {
            out_error = "No thread is selected.";
            return false;
        }

        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (!GetThreadContext(handle, &context)) {
            out_error = win_error_message("GetThreadContext failed");
            return false;
        }

        out_registers = RegisterState{
            .rip = context.Rip,
            .rsp = context.Rsp,
            .rbp = context.Rbp,
            .rax = context.Rax,
            .rbx = context.Rbx,
            .rcx = context.Rcx,
            .rdx = context.Rdx,
            .rsi = context.Rsi,
            .rdi = context.Rdi,
            .r8 = context.R8,
            .r9 = context.R9,
            .r10 = context.R10,
            .r11 = context.R11,
            .r12 = context.R12,
            .r13 = context.R13,
            .r14 = context.R14,
            .r15 = context.R15,
            .eflags = context.EFlags,
        };
        return true;
    }

    [[nodiscard]] bool write_registers_for_thread(
        const ProcessId thread_id,
        const RegisterState& registers,
        std::string& out_error
    ) {
        out_error.clear();

        HANDLE handle = thread_handle(thread_id);
        if (handle == nullptr) {
            out_error = "No thread is selected.";
            return false;
        }

        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (!GetThreadContext(handle, &context)) {
            out_error = win_error_message("GetThreadContext failed");
            return false;
        }

        context.Rip = registers.rip;
        context.Rsp = registers.rsp;
        context.Rbp = registers.rbp;
        context.Rax = registers.rax;
        context.Rbx = registers.rbx;
        context.Rcx = registers.rcx;
        context.Rdx = registers.rdx;
        context.Rsi = registers.rsi;
        context.Rdi = registers.rdi;
        context.R8 = registers.r8;
        context.R9 = registers.r9;
        context.R10 = registers.r10;
        context.R11 = registers.r11;
        context.R12 = registers.r12;
        context.R13 = registers.r13;
        context.R14 = registers.r14;
        context.R15 = registers.r15;
        context.EFlags = static_cast<DWORD>(registers.eflags);

        if (!SetThreadContext(handle, &context)) {
            out_error = win_error_message("SetThreadContext failed");
            return false;
        }
        return true;
    }

    [[nodiscard]] bool set_trap_flag(const ProcessId thread_id, const bool enabled, std::string& out_error) {
        RegisterState registers;
        if (!read_registers_for_thread(thread_id, registers, out_error)) {
            return false;
        }
        if (enabled) {
            registers.eflags |= 0x100U;
        } else {
            registers.eflags &= ~0x100U;
        }
        return write_registers_for_thread(thread_id, registers, out_error);
    }

    [[nodiscard]] bool wait_for_event(
        const WaitMode mode,
        StopEvent& out_event,
        std::string& out_error
    ) {
        out_error.clear();
        out_event = {};

        DEBUG_EVENT debug_event{};
        while (WaitForDebugEvent(&debug_event, INFINITE)) {
            out_event.process_id = static_cast<ProcessId>(debug_event.dwProcessId);
            out_event.thread_id = static_cast<ProcessId>(debug_event.dwThreadId);
            current_thread_id_ = out_event.thread_id;
            stopped_threads_.clear();
            for (const auto& [thread_id, _] : thread_handles_) {
                stopped_threads_.insert(thread_id);
            }

            if (debug_event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
                handle_create_process_event(debug_event);
                if (mode == WaitMode::Launch) {
                    stash_pending_event(debug_event, DBG_CONTINUE);
                    out_event.reason = StopReason::Launch;
                    out_event.message = "Process created under debugger.";
                    return true;
                }
                if (!continue_debug_event(debug_event, DBG_CONTINUE, out_error)) {
                    return false;
                }
                continue;
            }

            if (debug_event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
                handle_create_thread_event(debug_event);
                if (!continue_debug_event(debug_event, DBG_CONTINUE, out_error)) {
                    return false;
                }
                continue;
            }

            if (debug_event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
                handle_exit_thread_event(debug_event);
                if (!continue_debug_event(debug_event, DBG_CONTINUE, out_error)) {
                    return false;
                }
                continue;
            }

            if (debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                out_event.reason = StopReason::Exited;
                out_event.exit_code = static_cast<int>(debug_event.u.ExitProcess.dwExitCode);
                close_all_handles();
                active_ = false;
                leader_process_id_ = -1;
                current_thread_id_ = -1;
                pending_breakpoint_.reset();
                debug_event_pending_ = false;
                return true;
            }

            if (debug_event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
                HANDLE file = debug_event.u.LoadDll.hFile;
                close_handle_if_valid(file);
                if (!continue_debug_event(debug_event, DBG_CONTINUE, out_error)) {
                    return false;
                }
                continue;
            }

            if (debug_event.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT ||
                debug_event.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT) {
                if (!continue_debug_event(debug_event, DBG_CONTINUE, out_error)) {
                    return false;
                }
                continue;
            }

            if (debug_event.dwDebugEventCode == RIP_EVENT) {
                stash_pending_event(debug_event, DBG_CONTINUE);
                out_event.reason = StopReason::Error;
                out_event.message = "Windows RIP event reported a debugger transport failure.";
                return true;
            }

            if (debug_event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT) {
                if (!continue_debug_event(debug_event, DBG_CONTINUE, out_error)) {
                    return false;
                }
                continue;
            }

            const auto& exception = debug_event.u.Exception;
            const DWORD code = exception.ExceptionRecord.ExceptionCode;
            const std::uint64_t exception_address =
                static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(exception.ExceptionRecord.ExceptionAddress));

            if (mode == WaitMode::Attach && code == EXCEPTION_BREAKPOINT) {
                stash_pending_event(debug_event, DBG_CONTINUE);
                out_event.reason = StopReason::Attach;
                out_event.address = exception_address;
                out_event.message = "Attached to running process.";
                return true;
            }

            if (ignore_initial_breakpoint_ && code == EXCEPTION_BREAKPOINT) {
                ignore_initial_breakpoint_ = false;
                if (!continue_debug_event(debug_event, DBG_CONTINUE, out_error)) {
                    return false;
                }
                continue;
            }

            if (code == EXCEPTION_SINGLE_STEP) {
                stash_pending_event(debug_event, DBG_CONTINUE);
                out_event.reason = StopReason::SingleStep;
                RegisterState registers;
                std::string ignore_error;
                if (read_registers(registers, ignore_error)) {
                    out_event.address = registers.rip;
                }
                return true;
            }

            if (code == EXCEPTION_BREAKPOINT) {
                auto breakpoint_it = breakpoints_.find(exception_address);
                if (breakpoint_it != breakpoints_.end() && breakpoint_it->second.enabled) {
                    const std::array<std::byte, 1> restore{
                        static_cast<std::byte>(breakpoint_it->second.original_byte),
                    };
                    if (!write_memory(exception_address, restore, out_error)) {
                        return false;
                    }
                    breakpoint_it->second.enabled = false;

                    RegisterState registers;
                    if (!read_registers_for_thread(out_event.thread_id, registers, out_error)) {
                        return false;
                    }
                    registers.rip = exception_address;
                    if (!write_registers_for_thread(out_event.thread_id, registers, out_error)) {
                        return false;
                    }

                    pending_breakpoint_ = PendingBreakpoint{
                        .thread_id = out_event.thread_id,
                        .address = exception_address,
                    };
                    stash_pending_event(debug_event, DBG_CONTINUE);
                    out_event.reason = StopReason::Breakpoint;
                    out_event.address = exception_address;
                    return true;
                }

                stash_pending_event(debug_event, DBG_CONTINUE);
                out_event.reason = StopReason::Signal;
                out_event.signal = static_cast<int>(code);
                out_event.address = exception_address;
                out_event.message = "Received a breakpoint trap outside the managed breakpoint table.";
                return true;
            }

            stash_pending_event(debug_event, DBG_EXCEPTION_NOT_HANDLED);
            out_event.reason = StopReason::Signal;
            out_event.signal = static_cast<int>(code);
            out_event.address = exception_address;
            out_event.message = "Received a first-chance Windows exception.";
            return true;
        }

        out_error = win_error_message("WaitForDebugEvent failed");
        return false;
    }

    void handle_create_process_event(const DEBUG_EVENT& debug_event) {
        const auto& event = debug_event.u.CreateProcessInfo;
        if (process_handle_ == nullptr) {
            process_handle_ = event.hProcess;
        } else {
            HANDLE duplicate = event.hProcess;
            if (duplicate != process_handle_) {
                close_handle_if_valid(duplicate);
            }
        }

        HANDLE thread_handle = event.hThread;
        auto& slot = thread_handles_[static_cast<ProcessId>(debug_event.dwThreadId)];
        if (slot == nullptr) {
            slot = thread_handle;
        } else if (slot != thread_handle) {
            close_handle_if_valid(thread_handle);
        }

        HANDLE file_handle = event.hFile;
        close_handle_if_valid(file_handle);
    }

    void handle_create_thread_event(const DEBUG_EVENT& debug_event) {
        HANDLE thread_handle = debug_event.u.CreateThread.hThread;
        auto& slot = thread_handles_[static_cast<ProcessId>(debug_event.dwThreadId)];
        if (slot == nullptr) {
            slot = thread_handle;
        } else if (slot != thread_handle) {
            close_handle_if_valid(thread_handle);
        }
    }

    void handle_exit_thread_event(const DEBUG_EVENT& debug_event) {
        const ProcessId thread_id = static_cast<ProcessId>(debug_event.dwThreadId);
        auto it = thread_handles_.find(thread_id);
        if (it != thread_handles_.end()) {
            close_handle_if_valid(it->second);
            thread_handles_.erase(it);
        }
        stopped_threads_.erase(thread_id);
        if (current_thread_id_ == thread_id && !thread_handles_.empty()) {
            current_thread_id_ = thread_handles_.begin()->first;
        }
    }

    void stash_pending_event(const DEBUG_EVENT& debug_event, const DWORD continue_status) {
        debug_event_pending_ = true;
        pending_continue_process_id_ = debug_event.dwProcessId;
        pending_continue_thread_id_ = debug_event.dwThreadId;
        pending_continue_status_ = continue_status;
    }

    [[nodiscard]] bool continue_debug_event(
        const DEBUG_EVENT& debug_event,
        const DWORD continue_status,
        std::string& out_error
    ) {
        if (!ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)) {
            out_error = win_error_message("ContinueDebugEvent failed");
            return false;
        }
        return true;
    }

    [[nodiscard]] bool continue_last_event(const DWORD continue_status, std::string& out_error) {
        if (!debug_event_pending_) {
            out_error = "No stopped debug event is available to resume.";
            return false;
        }

        if (!ContinueDebugEvent(pending_continue_process_id_, pending_continue_thread_id_, continue_status)) {
            out_error = win_error_message("ContinueDebugEvent failed");
            return false;
        }

        debug_event_pending_ = false;
        return true;
    }

    [[nodiscard]] bool step_over_pending_breakpoint(StopEvent& out_event, std::string& out_error) {
        out_error.clear();
        out_event = {};

        if (!pending_breakpoint_.has_value()) {
            out_error = "No pending breakpoint state exists.";
            return false;
        }

        current_thread_id_ = pending_breakpoint_->thread_id;
        if (!set_trap_flag(current_thread_id_, true, out_error)) {
            return false;
        }

        if (!continue_last_event(DBG_CONTINUE, out_error)) {
            return false;
        }

        if (!wait_for_event(WaitMode::SingleStep, out_event, out_error)) {
            return false;
        }

        const auto breakpoint_address = pending_breakpoint_->address;
        const auto it = breakpoints_.find(breakpoint_address);
        if (it != breakpoints_.end()) {
            const std::array<std::byte, 1> trap{std::byte{kBreakpointOpcode}};
            if (!write_memory(breakpoint_address, trap, out_error)) {
                return false;
            }
            it->second.enabled = true;
        }
        pending_breakpoint_.reset();
        return true;
    }

    [[nodiscard]] bool restore_all_breakpoints(std::string& out_error) {
        std::vector<std::uint64_t> addresses;
        addresses.reserve(breakpoints_.size());
        for (const auto& [address, _] : breakpoints_) {
            addresses.push_back(address);
        }

        for (const auto address : addresses) {
            if (!remove_breakpoint(address, out_error)) {
                return false;
            }
        }
        return true;
    }

    void cleanup_after_failure() {
        if (process_handle_ != nullptr) {
            TerminateProcess(process_handle_, 1);
        }
        close_all_handles();
        reset_state();
    }

    void close_all_handles() {
        for (auto& [_, handle] : thread_handles_) {
            close_handle_if_valid(handle);
        }
        thread_handles_.clear();
        close_handle_if_valid(process_handle_);
    }

    void reset_state() {
        active_ = false;
        launch_owned_ = false;
        leader_process_id_ = -1;
        current_thread_id_ = -1;
        ignore_initial_breakpoint_ = false;
        pending_breakpoint_.reset();
        breakpoints_.clear();
        stopped_threads_.clear();
        debug_event_pending_ = false;
        pending_continue_process_id_ = 0;
        pending_continue_thread_id_ = 0;
        pending_continue_status_ = DBG_CONTINUE;
        close_all_handles();
    }

    HANDLE process_handle_ = nullptr;
    ProcessId leader_process_id_ = -1;
    ProcessId current_thread_id_ = -1;
    bool active_ = false;
    bool launch_owned_ = false;
    bool ignore_initial_breakpoint_ = false;
    bool debug_event_pending_ = false;
    DWORD pending_continue_process_id_ = 0;
    DWORD pending_continue_thread_id_ = 0;
    DWORD pending_continue_status_ = DBG_CONTINUE;
    std::unordered_map<ProcessId, HANDLE> thread_handles_;
    std::set<ProcessId> stopped_threads_;
    std::unordered_map<std::uint64_t, BreakpointState> breakpoints_;
    std::optional<PendingBreakpoint> pending_breakpoint_;
};

}  // namespace

std::unique_ptr<DebugSession> create_windows_debug_session() {
    return std::make_unique<WindowsDbgSession>();
}

}  // namespace zara::debugger

#endif
