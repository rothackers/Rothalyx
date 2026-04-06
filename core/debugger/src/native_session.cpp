#include "zara/debugger/session.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fstream>
#include <set>
#include <unordered_map>
#include <utility>

#if defined(__linux__)
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace zara::debugger {

#if defined(_WIN32)
std::unique_ptr<DebugSession> create_windows_debug_session();
#elif defined(__APPLE__)
std::unique_ptr<DebugSession> create_macos_debug_session();
#endif

namespace {

constexpr std::uint8_t kBreakpointOpcode = 0xCC;

std::string system_error_message(const std::string_view prefix) {
    return std::string(prefix) + ": " + std::strerror(errno);
}

#if defined(__linux__)
struct BreakpointState {
    std::uint64_t address = 0;
    std::uint8_t original_byte = 0;
    bool enabled = false;
};

class LinuxPtraceSession final : public DebugSession {
public:
    ~LinuxPtraceSession() override {
        std::string ignore_error;
        if (is_active()) {
            if (launch_owned_) {
                (void)terminate(ignore_error);
            } else {
                (void)detach(ignore_error);
            }
        }
    }

    [[nodiscard]] std::string_view backend_name() const noexcept override {
        return "linux-ptrace";
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

        const pid_t child = fork();
        if (child < 0) {
            out_error = system_error_message("fork failed");
            return false;
        }

        if (child == 0) {
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) {
                _exit(127);
            }

            std::vector<char*> argv;
            argv.reserve(arguments.size() + 2);
            argv.push_back(const_cast<char*>(path.c_str()));
            for (const auto& argument : arguments) {
                argv.push_back(const_cast<char*>(argument.c_str()));
            }
            argv.push_back(nullptr);

            execv(path.c_str(), argv.data());
            _exit(127);
        }

        leader_process_id_ = child;
        current_thread_id_ = child;
        launch_owned_ = true;
        active_ = true;
        breakpoints_.clear();
        pending_breakpoint_.reset();
        threads_.clear();
        stopped_threads_.clear();
        threads_.insert(child);

        if (!wait_for_event(WaitMode::Launch, out_event, out_error)) {
            cleanup_after_failure();
            return false;
        }

        if (out_event.reason != StopReason::Launch) {
            out_error = "Process did not stop in a debuggable launch state.";
            cleanup_after_failure();
            return false;
        }

        if (!set_ptrace_options(child, out_error)) {
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

        if (ptrace(PTRACE_ATTACH, process_id, nullptr, nullptr) != 0) {
            out_error = system_error_message("ptrace attach failed");
            return false;
        }

        leader_process_id_ = process_id;
        current_thread_id_ = process_id;
        active_ = true;
        launch_owned_ = false;
        breakpoints_.clear();
        pending_breakpoint_.reset();
        threads_.clear();
        stopped_threads_.clear();
        threads_.insert(process_id);

        if (!wait_for_event(WaitMode::Attach, out_event, out_error)) {
            cleanup_after_failure();
            return false;
        }

        if (out_event.reason != StopReason::Attach) {
            out_error = "Process did not stop in an attachable state.";
            cleanup_after_failure();
            return false;
        }

        if (!set_ptrace_options(process_id, out_error)) {
            cleanup_after_failure();
            return false;
        }

        for (const auto tid : enumerate_threads()) {
            if (tid == process_id) {
                continue;
            }
            if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) != 0) {
                out_error = system_error_message("ptrace attach thread failed");
                cleanup_after_failure();
                return false;
            }

            int status = 0;
            if (!wait_for_specific_thread(tid, status, out_error)) {
                cleanup_after_failure();
                return false;
            }

            threads_.insert(tid);
            stopped_threads_.insert(tid);
            if (!set_ptrace_options(tid, out_error)) {
                cleanup_after_failure();
                return false;
            }
        }

        out_event.message += " Threads=" + std::to_string(threads_.size()) + ".";
        return true;
    }

    [[nodiscard]] bool continue_execution(StopEvent& out_event, std::string& out_error) override {
        out_error.clear();
        out_event = {};

        if (!active_) {
            out_error = "No active debug session.";
            return false;
        }

        if (!prepare_resume(out_error)) {
            return false;
        }

        if (!resume_all_threads(PTRACE_CONT, out_error)) {
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

        if (ptrace(PTRACE_SINGLESTEP, current_thread_id_, nullptr, nullptr) != 0) {
            out_error = system_error_message("ptrace single-step failed");
            return false;
        }
        stopped_threads_.erase(current_thread_id_);

        return wait_for_event(WaitMode::SingleStep, out_event, out_error);
    }

    [[nodiscard]] bool list_threads(std::vector<ThreadInfo>& out_threads, std::string& out_error) const override {
        out_error.clear();
        out_threads.clear();

        if (!active_) {
            out_error = "No active debug session.";
            return false;
        }

        std::set<ProcessId> known_threads = threads_;
        for (const auto tid : enumerate_threads()) {
            known_threads.insert(tid);
        }

        for (const auto tid : known_threads) {
            ThreadInfo info;
            info.thread_id = tid;
            info.selected = tid == current_thread_id_;
            info.stopped = stopped_threads_.contains(tid);
            info.state = thread_state_label(tid);

            RegisterState registers;
            std::string ignore_error;
            if (read_registers_for_thread(tid, registers, ignore_error)) {
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

        if (!threads_.contains(thread_id)) {
            const auto proc_threads = enumerate_threads();
            if (std::find(proc_threads.begin(), proc_threads.end(), thread_id) == proc_threads.end()) {
                out_error = "The selected thread is not part of the active process.";
                return false;
            }
            threads_.insert(thread_id);
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

        if (!active_) {
            out_error = "No active debug session.";
            return false;
        }

        if (count == 0) {
            return true;
        }

        constexpr std::size_t kWordSize = sizeof(long);
        const std::uint64_t aligned_start = address & ~static_cast<std::uint64_t>(kWordSize - 1);
        const std::uint64_t aligned_end =
            (address + count + kWordSize - 1) & ~static_cast<std::uint64_t>(kWordSize - 1);

        std::vector<std::byte> scratch;
        scratch.reserve(static_cast<std::size_t>(aligned_end - aligned_start));

        for (std::uint64_t cursor = aligned_start; cursor < aligned_end; cursor += kWordSize) {
            errno = 0;
            const long word = ptrace(PTRACE_PEEKDATA, leader_process_id_, reinterpret_cast<void*>(cursor), nullptr);
            if (errno != 0) {
                out_error = system_error_message("ptrace peekdata failed");
                return false;
            }

            const auto* bytes = reinterpret_cast<const std::byte*>(&word);
            scratch.insert(scratch.end(), bytes, bytes + kWordSize);
        }

        const std::size_t start_offset = static_cast<std::size_t>(address - aligned_start);
        out_bytes.assign(scratch.begin() + static_cast<std::ptrdiff_t>(start_offset),
                         scratch.begin() + static_cast<std::ptrdiff_t>(start_offset + count));
        return true;
    }

    [[nodiscard]] bool write_memory(
        const std::uint64_t address,
        const std::span<const std::byte> bytes,
        std::string& out_error
    ) override {
        out_error.clear();

        if (!active_) {
            out_error = "No active debug session.";
            return false;
        }

        if (bytes.empty()) {
            return true;
        }

        constexpr std::size_t kWordSize = sizeof(long);
        const std::uint64_t aligned_start = address & ~static_cast<std::uint64_t>(kWordSize - 1);
        const std::uint64_t aligned_end =
            (address + bytes.size() + kWordSize - 1) & ~static_cast<std::uint64_t>(kWordSize - 1);

        std::vector<std::byte> scratch;
        if (!read_memory(aligned_start, static_cast<std::size_t>(aligned_end - aligned_start), scratch, out_error)) {
            return false;
        }

        const std::size_t start_offset = static_cast<std::size_t>(address - aligned_start);
        std::copy(bytes.begin(), bytes.end(), scratch.begin() + static_cast<std::ptrdiff_t>(start_offset));

        for (std::uint64_t cursor = aligned_start; cursor < aligned_end; cursor += kWordSize) {
            long word = 0;
            std::memcpy(
                &word,
                scratch.data() + static_cast<std::ptrdiff_t>(cursor - aligned_start),
                kWordSize
            );
            if (ptrace(PTRACE_POKEDATA, leader_process_id_, reinterpret_cast<void*>(cursor), word) != 0) {
                out_error = system_error_message("ptrace pokedata failed");
                return false;
            }
        }

        return true;
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

        std::vector<std::byte> original_byte;
        if (!read_memory(address, 1, original_byte, out_error)) {
            return false;
        }

        if (!write_memory(address, std::array<std::byte, 1>{std::byte{kBreakpointOpcode}}, out_error)) {
            return false;
        }

        breakpoints_[address] =
            BreakpointState{
                .address = address,
                .original_byte = static_cast<std::uint8_t>(std::to_integer<unsigned int>(original_byte.front())),
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
            if (!write_memory(
                    address,
                    std::array<std::byte, 1>{static_cast<std::byte>(breakpoint_it->second.original_byte)},
                    out_error
                )) {
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

        for (const auto tid : threads_) {
            if (ptrace(PTRACE_DETACH, tid, nullptr, nullptr) != 0 && errno != ESRCH) {
                out_error = system_error_message("ptrace detach failed");
                return false;
            }
        }

        reset_state();
        return true;
    }

    [[nodiscard]] bool terminate(std::string& out_error) override {
        out_error.clear();

        if (!active_) {
            return true;
        }

        kill(leader_process_id_, SIGKILL);
        int status = 0;
        while (waitpid(-1, &status, __WALL) > 0) {
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

    [[nodiscard]] std::vector<ProcessId> enumerate_threads() const {
        std::vector<ProcessId> thread_ids;
        if (leader_process_id_ <= 0) {
            return thread_ids;
        }

        const auto task_dir = std::filesystem::path("/proc") / std::to_string(leader_process_id_) / "task";
        std::error_code error;
        for (const auto& entry : std::filesystem::directory_iterator(task_dir, error)) {
            if (error) {
                break;
            }
            try {
                thread_ids.push_back(std::stoi(entry.path().filename().string()));
            } catch (...) {
            }
        }
        std::sort(thread_ids.begin(), thread_ids.end());
        return thread_ids;
    }

    [[nodiscard]] std::string thread_state_label(const ProcessId thread_id) const {
        if (stopped_threads_.contains(thread_id)) {
            return "stopped";
        }

        const auto status_path =
            std::filesystem::path("/proc") / std::to_string(leader_process_id_) / "task" / std::to_string(thread_id) / "status";
        std::ifstream stream(status_path);
        if (!stream) {
            return "unknown";
        }

        std::string line;
        while (std::getline(stream, line)) {
            if (line.rfind("State:", 0) == 0) {
                const auto tab = line.find('\t');
                return tab == std::string::npos ? line.substr(6) : line.substr(tab + 1);
            }
        }
        return "unknown";
    }

    [[nodiscard]] bool read_registers_for_thread(
        const ProcessId thread_id,
        RegisterState& out_registers,
        std::string& out_error
    ) const {
        out_error.clear();
        out_registers = {};

        if (thread_id <= 0) {
            out_error = "No thread is selected.";
            return false;
        }

        user_regs_struct raw{};
        if (ptrace(PTRACE_GETREGS, thread_id, nullptr, &raw) != 0) {
            out_error = system_error_message("ptrace getregs failed");
            return false;
        }

        out_registers =
            RegisterState{
                .rip = raw.rip,
                .rsp = raw.rsp,
                .rbp = raw.rbp,
                .rax = raw.rax,
                .rbx = raw.rbx,
                .rcx = raw.rcx,
                .rdx = raw.rdx,
                .rsi = raw.rsi,
                .rdi = raw.rdi,
                .r8 = raw.r8,
                .r9 = raw.r9,
                .r10 = raw.r10,
                .r11 = raw.r11,
                .r12 = raw.r12,
                .r13 = raw.r13,
                .r14 = raw.r14,
                .r15 = raw.r15,
                .eflags = raw.eflags,
            };
        return true;
    }

    [[nodiscard]] bool write_registers_for_thread(
        const ProcessId thread_id,
        const RegisterState& registers,
        std::string& out_error
    ) {
        out_error.clear();

        if (thread_id <= 0) {
            out_error = "No thread is selected.";
            return false;
        }

        user_regs_struct raw{};
        if (ptrace(PTRACE_GETREGS, thread_id, nullptr, &raw) != 0) {
            out_error = system_error_message("ptrace getregs failed");
            return false;
        }

        raw.rip = registers.rip;
        raw.rsp = registers.rsp;
        raw.rbp = registers.rbp;
        raw.rax = registers.rax;
        raw.rbx = registers.rbx;
        raw.rcx = registers.rcx;
        raw.rdx = registers.rdx;
        raw.rsi = registers.rsi;
        raw.rdi = registers.rdi;
        raw.r8 = registers.r8;
        raw.r9 = registers.r9;
        raw.r10 = registers.r10;
        raw.r11 = registers.r11;
        raw.r12 = registers.r12;
        raw.r13 = registers.r13;
        raw.r14 = registers.r14;
        raw.r15 = registers.r15;
        raw.eflags = registers.eflags;

        if (ptrace(PTRACE_SETREGS, thread_id, nullptr, &raw) != 0) {
            out_error = system_error_message("ptrace setregs failed");
            return false;
        }

        return true;
    }

    [[nodiscard]] bool set_ptrace_options(const ProcessId thread_id, std::string& out_error) {
        if (ptrace(PTRACE_SETOPTIONS, thread_id, nullptr, PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE) != 0) {
            out_error = system_error_message("ptrace setoptions failed");
            return false;
        }
        return true;
    }

    [[nodiscard]] bool wait_for_specific_thread(const ProcessId thread_id, int& out_status, std::string& out_error) {
        out_error.clear();
        out_status = 0;
        if (waitpid(thread_id, &out_status, __WALL) < 0) {
            out_error = system_error_message("waitpid failed");
            return false;
        }
        return true;
    }

    void cleanup_after_failure() {
        if (active_ && launch_owned_ && leader_process_id_ > 0) {
            kill(leader_process_id_, SIGKILL);
            int status = 0;
            while (waitpid(-1, &status, __WALL) > 0) {
            }
        }

        reset_state();
    }

    [[nodiscard]] bool wait_for_event(
        const WaitMode mode,
        StopEvent& out_event,
        std::string& out_error
    ) {
        out_error.clear();
        out_event = {};

        int status = 0;
        const pid_t thread_id = waitpid(-1, &status, __WALL);
        if (thread_id < 0) {
            out_error = system_error_message("waitpid failed");
            return false;
        }

        current_thread_id_ = thread_id;
        out_event.process_id = leader_process_id_;
        out_event.thread_id = thread_id;
        if (WIFEXITED(status)) {
            threads_.erase(thread_id);
            stopped_threads_.erase(thread_id);
            if (thread_id == leader_process_id_ || threads_.empty()) {
                out_event.reason = StopReason::Exited;
                out_event.exit_code = WEXITSTATUS(status);
                reset_state();
            } else {
                out_event.reason = StopReason::Signal;
                out_event.exit_code = WEXITSTATUS(status);
                out_event.message = "Thread exited.";
            }
            return true;
        }

        if (WIFSIGNALED(status)) {
            threads_.erase(thread_id);
            stopped_threads_.erase(thread_id);
            if (thread_id == leader_process_id_ || threads_.empty()) {
                out_event.reason = StopReason::Terminated;
                out_event.signal = WTERMSIG(status);
                reset_state();
            } else {
                out_event.reason = StopReason::Signal;
                out_event.signal = WTERMSIG(status);
                out_event.message = "Thread terminated.";
            }
            return true;
        }

        if (!WIFSTOPPED(status)) {
            out_error = "waitpid returned an unsupported status.";
            return false;
        }

        stopped_threads_.insert(thread_id);
        const int signal = WSTOPSIG(status);
        out_event.signal = signal;

        if (mode == WaitMode::Launch) {
            out_event.reason = StopReason::Launch;
            out_event.message = "Process stopped after exec.";
            return true;
        }

        if (mode == WaitMode::Attach) {
            out_event.reason = StopReason::Attach;
            out_event.message = "Attached to running process.";
            return true;
        }

        const unsigned event_code = static_cast<unsigned>(status >> 16U);
        if (event_code == PTRACE_EVENT_CLONE) {
            unsigned long new_thread = 0;
            if (ptrace(PTRACE_GETEVENTMSG, thread_id, nullptr, &new_thread) == 0 && new_thread > 0U) {
                threads_.insert(static_cast<ProcessId>(new_thread));
                int clone_status = 0;
                if (!wait_for_specific_thread(static_cast<ProcessId>(new_thread), clone_status, out_error)) {
                    return false;
                }
                stopped_threads_.insert(static_cast<ProcessId>(new_thread));
                if (!set_ptrace_options(static_cast<ProcessId>(new_thread), out_error)) {
                    return false;
                }
                out_event.message = "Thread created: " + std::to_string(new_thread) + ".";
            }
        }

        if (signal == SIGTRAP) {
            RegisterState registers;
            if (!read_registers(registers, out_error)) {
                return false;
            }

            if (mode == WaitMode::SingleStep) {
                out_event.reason = StopReason::SingleStep;
                out_event.address = registers.rip;
                return true;
            }

            if (registers.rip > 0) {
                const std::uint64_t breakpoint_address = registers.rip - 1;
                const auto breakpoint_it = breakpoints_.find(breakpoint_address);
                if (breakpoint_it != breakpoints_.end() && breakpoint_it->second.enabled) {
                    if (!write_memory(
                            breakpoint_address,
                            std::array<std::byte, 1>{static_cast<std::byte>(breakpoint_it->second.original_byte)},
                            out_error
                        )) {
                        return false;
                    }

                    breakpoint_it->second.enabled = false;
                    registers.rip = breakpoint_address;
                    if (!write_registers(registers, out_error)) {
                        return false;
                    }

                    pending_breakpoint_ =
                        PendingBreakpoint{
                            .thread_id = thread_id,
                            .address = breakpoint_address,
                        };
                    out_event.reason = StopReason::Breakpoint;
                    out_event.address = breakpoint_address;
                    return true;
                }
            }

            out_event.reason = StopReason::Signal;
            out_event.address = registers.rip;
            if (out_event.message.empty()) {
                out_event.message = "Received SIGTRAP.";
            }
            return true;
        }

        RegisterState registers;
        if (read_registers(registers, out_error)) {
            out_event.address = registers.rip;
        } else {
            out_error.clear();
        }

        out_event.reason = StopReason::Signal;
        if (out_event.message.empty()) {
            out_event.message = "Process stopped by signal.";
        }
        return true;
    }

    [[nodiscard]] bool step_over_pending_breakpoint(StopEvent& out_event, std::string& out_error) {
        if (!pending_breakpoint_.has_value()) {
            return true;
        }

        current_thread_id_ = pending_breakpoint_->thread_id;
        if (ptrace(PTRACE_SINGLESTEP, current_thread_id_, nullptr, nullptr) != 0) {
            out_error = system_error_message("ptrace single-step failed while stepping over breakpoint");
            return false;
        }
        stopped_threads_.erase(current_thread_id_);

        if (!wait_for_event(WaitMode::SingleStep, out_event, out_error)) {
            return false;
        }

        const std::uint64_t breakpoint_address = pending_breakpoint_->address;
        const auto breakpoint_it = breakpoints_.find(breakpoint_address);
        if (breakpoint_it != breakpoints_.end()) {
            if (!write_memory(
                    breakpoint_address,
                    std::array<std::byte, 1>{std::byte{kBreakpointOpcode}},
                    out_error
                )) {
                return false;
            }
            breakpoint_it->second.enabled = true;
        }

        pending_breakpoint_.reset();
        return true;
    }

    [[nodiscard]] bool prepare_resume(std::string& out_error) {
        if (!pending_breakpoint_.has_value()) {
            return true;
        }

        StopEvent single_step_event;
        if (!step_over_pending_breakpoint(single_step_event, out_error)) {
            return false;
        }

        return true;
    }

    [[nodiscard]] bool resume_all_threads(const __ptrace_request request, std::string& out_error) {
        for (const auto tid : threads_) {
            if (ptrace(request, tid, nullptr, nullptr) != 0 && errno != ESRCH) {
                out_error = request == PTRACE_CONT ? system_error_message("ptrace continue failed")
                                                   : system_error_message("ptrace request failed");
                return false;
            }
            stopped_threads_.erase(tid);
        }
        return true;
    }

    [[nodiscard]] bool restore_all_breakpoints(std::string& out_error) {
        if (pending_breakpoint_.has_value()) {
            pending_breakpoint_.reset();
        }

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

    void reset_state() {
        active_ = false;
        leader_process_id_ = -1;
        current_thread_id_ = -1;
        launch_owned_ = false;
        threads_.clear();
        stopped_threads_.clear();
        breakpoints_.clear();
        pending_breakpoint_.reset();
    }

    ProcessId leader_process_id_ = -1;
    ProcessId current_thread_id_ = -1;
    bool active_ = false;
    bool launch_owned_ = false;
    std::set<ProcessId> threads_;
    std::set<ProcessId> stopped_threads_;
    std::unordered_map<std::uint64_t, BreakpointState> breakpoints_;
    std::optional<PendingBreakpoint> pending_breakpoint_;
};
#endif

class UnavailableDebugSession final : public DebugSession {
public:
    UnavailableDebugSession(std::string backend_name, std::string unavailable_reason)
        : backend_name_(std::move(backend_name)),
          unavailable_reason_(std::move(unavailable_reason)) {}

    [[nodiscard]] std::string_view backend_name() const noexcept override {
        return backend_name_;
    }

    [[nodiscard]] bool is_supported() const noexcept override {
        return false;
    }

    [[nodiscard]] bool is_active() const noexcept override {
        return false;
    }

    [[nodiscard]] ProcessId process_id() const noexcept override {
        return -1;
    }

    [[nodiscard]] ProcessId current_thread_id() const noexcept override {
        return -1;
    }

    [[nodiscard]] bool launch(
        const std::filesystem::path&,
        const std::vector<std::string>&,
        StopEvent&,
        std::string& out_error
    ) override {
        out_error = unavailable_reason_;
        return false;
    }

    [[nodiscard]] bool attach(ProcessId, StopEvent&, std::string& out_error) override {
        out_error = unavailable_reason_;
        return false;
    }

    [[nodiscard]] bool continue_execution(StopEvent&, std::string& out_error) override {
        out_error = unavailable_reason_;
        return false;
    }

    [[nodiscard]] bool single_step(StopEvent&, std::string& out_error) override {
        out_error = unavailable_reason_;
        return false;
    }

    [[nodiscard]] bool list_threads(std::vector<ThreadInfo>&, std::string& out_error) const override {
        out_error = unavailable_reason_;
        return false;
    }

    [[nodiscard]] bool select_thread(ProcessId, std::string& out_error) override {
        out_error = unavailable_reason_;
        return false;
    }

    [[nodiscard]] bool read_registers(RegisterState&, std::string& out_error) const override {
        out_error = unavailable_reason_;
        return false;
    }

    [[nodiscard]] bool write_registers(const RegisterState&, std::string& out_error) override {
        out_error = unavailable_reason_;
        return false;
    }

    [[nodiscard]] bool read_memory(
        std::uint64_t,
        std::size_t,
        std::vector<std::byte>&,
        std::string& out_error
    ) const override {
        out_error = unavailable_reason_;
        return false;
    }

    [[nodiscard]] bool write_memory(std::uint64_t, std::span<const std::byte>, std::string& out_error) override {
        out_error = unavailable_reason_;
        return false;
    }

    [[nodiscard]] bool set_breakpoint(std::uint64_t, std::string& out_error) override {
        out_error = unavailable_reason_;
        return false;
    }

    [[nodiscard]] bool remove_breakpoint(std::uint64_t, std::string& out_error) override {
        out_error = unavailable_reason_;
        return false;
    }

    [[nodiscard]] bool detach(std::string& out_error) override {
        out_error = unavailable_reason_;
        return false;
    }

    [[nodiscard]] bool terminate(std::string& out_error) override {
        out_error = unavailable_reason_;
        return false;
    }

private:
    std::string backend_name_;
    std::string unavailable_reason_;
};

}  // namespace

std::unique_ptr<DebugSession> DebugSession::create_native() {
#if defined(__linux__)
    return std::make_unique<LinuxPtraceSession>();
#elif defined(_WIN32)
    return create_windows_debug_session();
#elif defined(__APPLE__)
    return create_macos_debug_session();
#else
    return std::make_unique<UnavailableDebugSession>(
        "unsupported",
        "Native debugger backend is unavailable on this platform."
    );
#endif
}

std::vector<TargetShape> DebugSession::target_shapes() {
    const bool host_is_linux =
#if defined(__linux__)
        true;
#else
        false;
#endif
    const bool host_is_windows =
#if defined(_WIN32)
        true;
#else
        false;
#endif
    const bool host_is_macos =
#if defined(__APPLE__)
        true;
#else
        false;
#endif

    return {
        TargetShape{
            .platform = TargetPlatform::Windows,
            .backend = BackendKind::WindowsDbgEng,
            .selected_on_host = host_is_windows,
            .implemented = true,
            .capabilities = {"launch", "attach", "breakpoints", "registers", "memory", "threads", "runtime-static-correlation"},
            .note = "Windows target shape is backed by a WinAPI debug loop implementation.",
        },
        TargetShape{
            .platform = TargetPlatform::Linux,
            .backend = BackendKind::LinuxPtrace,
            .selected_on_host = host_is_linux,
            .implemented = true,
            .capabilities = {"launch", "attach", "breakpoints", "registers", "memory", "threads", "runtime-static-correlation"},
            .note = "Linux target shape is backed by the ptrace implementation in this repository.",
        },
        TargetShape{
            .platform = TargetPlatform::MacOS,
            .backend = BackendKind::MacOSLldb,
            .selected_on_host = host_is_macos,
            .implemented = true,
            .capabilities = {"launch", "attach", "breakpoints", "registers", "memory", "threads", "runtime-static-correlation"},
            .note = "macOS target shape is backed by a native ptrace/Mach session implementation.",
        },
    };
}

std::string_view to_string(const TargetPlatform platform) noexcept {
    switch (platform) {
    case TargetPlatform::Windows:
        return "windows";
    case TargetPlatform::Linux:
        return "linux";
    case TargetPlatform::MacOS:
        return "macos";
    case TargetPlatform::Unknown:
    default:
        return "unknown";
    }
}

std::string_view to_string(const BackendKind backend) noexcept {
    switch (backend) {
    case BackendKind::LinuxPtrace:
        return "linux-ptrace";
    case BackendKind::WindowsDbgEng:
        return "windows-dbgeng";
    case BackendKind::MacOSLldb:
        return "macos-lldb";
    case BackendKind::Unsupported:
    default:
        return "unsupported";
    }
}

std::string_view to_string(const StopReason reason) noexcept {
    switch (reason) {
    case StopReason::Launch:
        return "launch";
    case StopReason::Attach:
        return "attach";
    case StopReason::Breakpoint:
        return "breakpoint";
    case StopReason::SingleStep:
        return "single_step";
    case StopReason::Signal:
        return "signal";
    case StopReason::Exited:
        return "exited";
    case StopReason::Terminated:
        return "terminated";
    case StopReason::Detached:
        return "detached";
    case StopReason::Error:
        return "error";
    case StopReason::None:
    default:
        return "none";
    }
}

}  // namespace zara::debugger
