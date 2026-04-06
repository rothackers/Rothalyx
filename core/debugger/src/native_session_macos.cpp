#include "zara/debugger/session.hpp"

#if defined(__APPLE__)

#include <mach/error.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#if defined(__x86_64__)
#include <mach/i386/thread_status.h>
#elif defined(__arm64__) || defined(__aarch64__)
#include <mach/arm/thread_status.h>
#endif

#include <array>
#include <cerrno>
#include <csignal>
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

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace zara::debugger {

namespace {

std::string system_error_message(const std::string_view prefix) {
    return std::string(prefix) + ": " + std::strerror(errno);
}

std::string mach_error_message(const std::string_view prefix, const kern_return_t code) {
    return std::string(prefix) + ": " + mach_error_string(code);
}

constexpr std::size_t architecture_breakpoint_size() {
#if defined(__x86_64__)
    return 1;
#else
    return 4;
#endif
}

std::vector<std::byte> architecture_breakpoint_bytes() {
#if defined(__x86_64__)
    return {std::byte{0xCC}};
#else
    return {std::byte{0x00}, std::byte{0x00}, std::byte{0x20}, std::byte{0xD4}};
#endif
}

struct BreakpointState {
    std::uint64_t address = 0;
    std::vector<std::byte> original_bytes;
    bool enabled = false;
};

class MacOSDebugSession final : public DebugSession {
public:
    ~MacOSDebugSession() override {
        std::string ignore_error;
        if (is_active()) {
            if (launch_owned_) {
                (void)terminate(ignore_error);
            } else {
                (void)detach(ignore_error);
            }
        }
        release_ports();
    }

    [[nodiscard]] std::string_view backend_name() const noexcept override {
        return "macos-lldb";
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
            if (ptrace(PT_TRACE_ME, 0, nullptr, 0) != 0) {
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
        active_ = true;
        launch_owned_ = true;
        breakpoints_.clear();
        pending_breakpoint_.reset();

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

        if (ptrace(PT_ATTACH, process_id, nullptr, 0) != 0) {
            out_error = system_error_message("ptrace attach failed");
            return false;
        }

        leader_process_id_ = process_id;
        current_thread_id_ = process_id;
        active_ = true;
        launch_owned_ = false;
        breakpoints_.clear();
        pending_breakpoint_.reset();

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

        if (!resume_process(PT_CONTINUE, out_error)) {
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

        if (!resume_process(PT_STEP, out_error)) {
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

        if (!refresh_threads(out_error)) {
            return false;
        }

        for (const auto& [thread_id, port] : thread_ports_) {
            (void)port;
            ThreadInfo info;
            info.thread_id = thread_id;
            info.selected = thread_id == current_thread_id_;
            info.stopped = stopped_;
            info.state = stopped_ ? "stopped" : "running";

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
        if (!refresh_threads(out_error)) {
            return false;
        }
        if (!thread_ports_.contains(thread_id)) {
            out_error = "The selected thread is not part of the active process.";
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

        if (!active_ || task_ == MACH_PORT_NULL) {
            out_error = "No active debug session.";
            return false;
        }
        if (count == 0) {
            return true;
        }

        out_bytes.resize(count);
        mach_vm_size_t bytes_read = 0;
        const auto result = mach_vm_read_overwrite(
            task_,
            static_cast<mach_vm_address_t>(address),
            static_cast<mach_vm_size_t>(count),
            reinterpret_cast<mach_vm_address_t>(out_bytes.data()),
            &bytes_read
        );
        if (result != KERN_SUCCESS) {
            out_error = mach_error_message("mach_vm_read_overwrite failed", result);
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

        if (!active_ || task_ == MACH_PORT_NULL) {
            out_error = "No active debug session.";
            return false;
        }
        if (bytes.empty()) {
            return true;
        }

        const auto result = mach_vm_write(
            task_,
            static_cast<mach_vm_address_t>(address),
            reinterpret_cast<vm_offset_t>(const_cast<std::byte*>(bytes.data())),
            static_cast<mach_msg_type_number_t>(bytes.size())
        );
        if (result != KERN_SUCCESS) {
            out_error = mach_error_message("mach_vm_write failed", result);
            return false;
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

        std::vector<std::byte> original_bytes;
        const auto breakpoint_size = architecture_breakpoint_size();
        if (!read_memory(address, breakpoint_size, original_bytes, out_error) ||
            original_bytes.size() != breakpoint_size) {
            return false;
        }

        const auto trap = architecture_breakpoint_bytes();
        if (!write_memory(address, trap, out_error)) {
            return false;
        }

        breakpoints_[address] = BreakpointState{
            .address = address,
            .original_bytes = std::move(original_bytes),
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
            if (!write_memory(address, breakpoint_it->second.original_bytes, out_error)) {
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

        if (ptrace(PT_DETACH, leader_process_id_, reinterpret_cast<caddr_t>(1), 0) != 0) {
            out_error = system_error_message("ptrace detach failed");
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

        kill(leader_process_id_, SIGKILL);
        int status = 0;
        while (waitpid(leader_process_id_, &status, 0) > 0) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
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

    [[nodiscard]] thread_act_t current_thread_port(std::string& out_error) const {
        if (current_thread_id_ <= 0) {
            out_error = "No thread is selected.";
            return MACH_PORT_NULL;
        }

        const auto it = thread_ports_.find(current_thread_id_);
        if (it == thread_ports_.end()) {
            out_error = "The selected thread no longer exists.";
            return MACH_PORT_NULL;
        }

        return it->second;
    }

    [[nodiscard]] bool refresh_task_port(std::string& out_error) {
        out_error.clear();

        if (leader_process_id_ <= 0) {
            out_error = "No active debug session.";
            return false;
        }

        if (task_ != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), task_);
            task_ = MACH_PORT_NULL;
        }

        const auto result = task_for_pid(mach_task_self(), leader_process_id_, &task_);
        if (result != KERN_SUCCESS) {
            out_error = mach_error_message("task_for_pid failed", result);
            return false;
        }

        return true;
    }

    [[nodiscard]] bool refresh_threads(std::string& out_error) const {
        out_error.clear();

        if (task_ == MACH_PORT_NULL) {
            out_error = "Task port is unavailable.";
            return false;
        }

        thread_act_array_t threads = nullptr;
        mach_msg_type_number_t thread_count = 0;
        const auto result = task_threads(task_, &threads, &thread_count);
        if (result != KERN_SUCCESS) {
            out_error = mach_error_message("task_threads failed", result);
            return false;
        }

        std::unordered_map<ProcessId, thread_act_t> refreshed;
        refreshed.reserve(static_cast<std::size_t>(thread_count));
        for (mach_msg_type_number_t index = 0; index < thread_count; ++index) {
            const auto thread = threads[index];
            refreshed[static_cast<ProcessId>(thread)] = thread;
        }

        if (threads != nullptr) {
            vm_deallocate(
                mach_task_self(),
                reinterpret_cast<vm_address_t>(threads),
                static_cast<vm_size_t>(thread_count * sizeof(thread_act_t))
            );
        }

        for (const auto& [thread_id, port] : thread_ports_) {
            if (!refreshed.contains(thread_id)) {
                mach_port_deallocate(mach_task_self(), port);
            }
        }

        thread_ports_ = std::move(refreshed);
        if (!thread_ports_.empty() && !thread_ports_.contains(current_thread_id_)) {
            current_thread_id_ = thread_ports_.begin()->first;
        }
        return true;
    }

    [[nodiscard]] bool read_registers_for_thread(
        const ProcessId thread_id,
        RegisterState& out_registers,
        std::string& out_error
    ) const {
        out_error.clear();
        out_registers = {};

        const auto it = thread_ports_.find(thread_id);
        if (it == thread_ports_.end()) {
            out_error = "No thread is selected.";
            return false;
        }

#if defined(__x86_64__)
        x86_thread_state64_t state{};
        mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
        const auto result = thread_get_state(
            it->second,
            x86_THREAD_STATE64,
            reinterpret_cast<thread_state_t>(&state),
            &count
        );
        if (result != KERN_SUCCESS) {
            out_error = mach_error_message("thread_get_state failed", result);
            return false;
        }

        out_registers = RegisterState{
            .rip = state.__rip,
            .rsp = state.__rsp,
            .rbp = state.__rbp,
            .rax = state.__rax,
            .rbx = state.__rbx,
            .rcx = state.__rcx,
            .rdx = state.__rdx,
            .rsi = state.__rsi,
            .rdi = state.__rdi,
            .r8 = state.__r8,
            .r9 = state.__r9,
            .r10 = state.__r10,
            .r11 = state.__r11,
            .r12 = state.__r12,
            .r13 = state.__r13,
            .r14 = state.__r14,
            .r15 = state.__r15,
            .eflags = state.__rflags,
        };
#elif defined(__arm64__) || defined(__aarch64__)
        arm_thread_state64_t state{};
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        const auto result = thread_get_state(
            it->second,
            ARM_THREAD_STATE64,
            reinterpret_cast<thread_state_t>(&state),
            &count
        );
        if (result != KERN_SUCCESS) {
            out_error = mach_error_message("thread_get_state failed", result);
            return false;
        }

        out_registers = RegisterState{
            .rip = state.__pc,
            .rsp = state.__sp,
            .rbp = state.__fp,
            .rax = state.__x[0],
            .rbx = state.__x[1],
            .rcx = state.__x[2],
            .rdx = state.__x[3],
            .rsi = state.__x[4],
            .rdi = state.__x[5],
            .r8 = state.__x[6],
            .r9 = state.__x[7],
            .r10 = state.__x[8],
            .r11 = state.__x[9],
            .r12 = state.__x[10],
            .r13 = state.__x[11],
            .r14 = state.__x[12],
            .r15 = state.__x[13],
            .eflags = state.__cpsr,
        };
#else
        out_error = "Unsupported macOS debugger architecture.";
        return false;
#endif
        return true;
    }

    [[nodiscard]] bool write_registers_for_thread(
        const ProcessId thread_id,
        const RegisterState& registers,
        std::string& out_error
    ) {
        out_error.clear();

        const auto it = thread_ports_.find(thread_id);
        if (it == thread_ports_.end()) {
            out_error = "No thread is selected.";
            return false;
        }

#if defined(__x86_64__)
        x86_thread_state64_t state{};
        mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
        auto result = thread_get_state(
            it->second,
            x86_THREAD_STATE64,
            reinterpret_cast<thread_state_t>(&state),
            &count
        );
        if (result != KERN_SUCCESS) {
            out_error = mach_error_message("thread_get_state failed", result);
            return false;
        }

        state.__rip = registers.rip;
        state.__rsp = registers.rsp;
        state.__rbp = registers.rbp;
        state.__rax = registers.rax;
        state.__rbx = registers.rbx;
        state.__rcx = registers.rcx;
        state.__rdx = registers.rdx;
        state.__rsi = registers.rsi;
        state.__rdi = registers.rdi;
        state.__r8 = registers.r8;
        state.__r9 = registers.r9;
        state.__r10 = registers.r10;
        state.__r11 = registers.r11;
        state.__r12 = registers.r12;
        state.__r13 = registers.r13;
        state.__r14 = registers.r14;
        state.__r15 = registers.r15;
        state.__rflags = registers.eflags;
        result = thread_set_state(
            it->second,
            x86_THREAD_STATE64,
            reinterpret_cast<thread_state_t>(&state),
            x86_THREAD_STATE64_COUNT
        );
#elif defined(__arm64__) || defined(__aarch64__)
        arm_thread_state64_t state{};
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        auto result = thread_get_state(
            it->second,
            ARM_THREAD_STATE64,
            reinterpret_cast<thread_state_t>(&state),
            &count
        );
        if (result != KERN_SUCCESS) {
            out_error = mach_error_message("thread_get_state failed", result);
            return false;
        }

        state.__pc = registers.rip;
        state.__sp = registers.rsp;
        state.__fp = registers.rbp;
        state.__x[0] = registers.rax;
        state.__x[1] = registers.rbx;
        state.__x[2] = registers.rcx;
        state.__x[3] = registers.rdx;
        state.__x[4] = registers.rsi;
        state.__x[5] = registers.rdi;
        state.__x[6] = registers.r8;
        state.__x[7] = registers.r9;
        state.__x[8] = registers.r10;
        state.__x[9] = registers.r11;
        state.__x[10] = registers.r12;
        state.__x[11] = registers.r13;
        state.__x[12] = registers.r14;
        state.__x[13] = registers.r15;
        state.__cpsr = static_cast<decltype(state.__cpsr)>(registers.eflags);
        result = thread_set_state(
            it->second,
            ARM_THREAD_STATE64,
            reinterpret_cast<thread_state_t>(&state),
            ARM_THREAD_STATE64_COUNT
        );
#else
        out_error = "Unsupported macOS debugger architecture.";
        return false;
#endif

        if (result != KERN_SUCCESS) {
            out_error = mach_error_message("thread_set_state failed", result);
            return false;
        }
        return true;
    }

    [[nodiscard]] bool wait_for_event(
        const WaitMode mode,
        StopEvent& out_event,
        std::string& out_error
    ) {
        out_error.clear();
        out_event = {};

        int status = 0;
        const pid_t waited = waitpid(leader_process_id_, &status, 0);
        if (waited < 0) {
            out_error = system_error_message("waitpid failed");
            return false;
        }

        out_event.process_id = leader_process_id_;

        if (WIFEXITED(status)) {
            out_event.reason = StopReason::Exited;
            out_event.exit_code = WEXITSTATUS(status);
            reset_state();
            return true;
        }

        if (WIFSIGNALED(status)) {
            out_event.reason = StopReason::Terminated;
            out_event.signal = WTERMSIG(status);
            reset_state();
            return true;
        }

        if (!WIFSTOPPED(status)) {
            out_error = "waitpid returned an unsupported status.";
            return false;
        }

        stopped_ = true;
        out_event.signal = WSTOPSIG(status);

        if (!refresh_task_port(out_error) || !refresh_threads(out_error)) {
            return false;
        }
        out_event.thread_id = current_thread_id_;

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

        RegisterState registers;
        if (!read_registers(registers, out_error)) {
            return false;
        }

        if (mode == WaitMode::SingleStep && out_event.signal == SIGTRAP) {
            out_event.reason = StopReason::SingleStep;
            out_event.address = registers.rip;
            return true;
        }

        if (out_event.signal == SIGTRAP) {
            const auto breakpoint_address = resolve_breakpoint_address(registers.rip);
            const auto it = breakpoints_.find(breakpoint_address);
            if (it != breakpoints_.end() && it->second.enabled) {
                if (!write_memory(breakpoint_address, it->second.original_bytes, out_error)) {
                    return false;
                }

                auto restored = registers;
                restored.rip = breakpoint_address;
                if (!write_registers(restored, out_error)) {
                    return false;
                }

                it->second.enabled = false;
                pending_breakpoint_ = PendingBreakpoint{
                    .thread_id = current_thread_id_,
                    .address = breakpoint_address,
                };
                out_event.reason = StopReason::Breakpoint;
                out_event.address = breakpoint_address;
                return true;
            }

            out_event.reason = StopReason::Signal;
            out_event.address = registers.rip;
            out_event.message = "Received SIGTRAP outside the managed breakpoint table.";
            return true;
        }

        out_event.reason = StopReason::Signal;
        out_event.address = registers.rip;
        out_event.message = "Process stopped by signal.";
        return true;
    }

    [[nodiscard]] std::uint64_t resolve_breakpoint_address(const std::uint64_t instruction_pointer) const {
        const auto breakpoint_size = static_cast<std::uint64_t>(architecture_breakpoint_size());
        if (breakpoints_.contains(instruction_pointer)) {
            return instruction_pointer;
        }
        if (instruction_pointer >= breakpoint_size && breakpoints_.contains(instruction_pointer - breakpoint_size)) {
            return instruction_pointer - breakpoint_size;
        }
        return instruction_pointer;
    }

    [[nodiscard]] bool resume_process(const int request, std::string& out_error) {
        if (ptrace(request, leader_process_id_, reinterpret_cast<caddr_t>(1), 0) != 0) {
            out_error =
                request == PT_STEP ? system_error_message("ptrace single-step failed")
                                   : system_error_message("ptrace continue failed");
            return false;
        }
        stopped_ = false;
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
        if (!resume_process(PT_STEP, out_error)) {
            return false;
        }

        if (!wait_for_event(WaitMode::SingleStep, out_event, out_error)) {
            return false;
        }

        const auto breakpoint_address = pending_breakpoint_->address;
        const auto it = breakpoints_.find(breakpoint_address);
        if (it != breakpoints_.end()) {
            const auto trap = architecture_breakpoint_bytes();
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
        if (active_ && leader_process_id_ > 0 && launch_owned_) {
            kill(leader_process_id_, SIGKILL);
            int status = 0;
            while (waitpid(leader_process_id_, &status, 0) > 0) {
                if (WIFEXITED(status) || WIFSIGNALED(status)) {
                    break;
                }
            }
        }
        reset_state();
    }

    void release_ports() const {
        for (const auto& [_, port] : thread_ports_) {
            mach_port_deallocate(mach_task_self(), port);
        }
        if (task_ != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), task_);
        }
    }

    void reset_state() {
        release_ports();
        task_ = MACH_PORT_NULL;
        thread_ports_.clear();
        active_ = false;
        stopped_ = false;
        launch_owned_ = false;
        leader_process_id_ = -1;
        current_thread_id_ = -1;
        pending_breakpoint_.reset();
        breakpoints_.clear();
    }

    mutable mach_port_t task_ = MACH_PORT_NULL;
    mutable std::unordered_map<ProcessId, thread_act_t> thread_ports_;
    ProcessId leader_process_id_ = -1;
    mutable ProcessId current_thread_id_ = -1;
    bool active_ = false;
    bool stopped_ = false;
    bool launch_owned_ = false;
    std::unordered_map<std::uint64_t, BreakpointState> breakpoints_;
    std::optional<PendingBreakpoint> pending_breakpoint_;
};

}  // namespace

std::unique_ptr<DebugSession> create_macos_debug_session() {
    return std::make_unique<MacOSDebugSession>();
}

}  // namespace zara::debugger

#endif
