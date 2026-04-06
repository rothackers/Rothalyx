#include <iostream>

#include "zara/disasm/disassembler.hpp"

namespace {

bool verify_descriptor(
    const zara::loader::Architecture architecture,
    const std::string_view name,
    const std::size_t pointer_size,
    const std::size_t alignment,
    const std::string_view stack_pointer,
    const std::string_view frame_pointer,
    const std::string_view link_register
) {
    const auto* descriptor = zara::disasm::describe_architecture(architecture);
    if (descriptor == nullptr) {
        return false;
    }

    return descriptor->architecture == architecture &&
           descriptor->name == name &&
           descriptor->pointer_size == pointer_size &&
           descriptor->instruction_alignment == alignment &&
           descriptor->stack_pointer == stack_pointer &&
           descriptor->frame_pointer == frame_pointer &&
           descriptor->link_register == link_register;
}

}  // namespace

int main() {
    if (!verify_descriptor(zara::loader::Architecture::Unknown, "unknown", 0, 1, "", "", "")) {
        std::cerr << "unknown architecture descriptor mismatch\n";
        return 1;
    }

    if (!verify_descriptor(zara::loader::Architecture::X86, "x86", 4, 1, "esp", "ebp", "")) {
        std::cerr << "x86 architecture descriptor mismatch\n";
        return 2;
    }

    if (!verify_descriptor(zara::loader::Architecture::X86_64, "x86_64", 8, 1, "rsp", "rbp", "")) {
        std::cerr << "x86_64 architecture descriptor mismatch\n";
        return 3;
    }

    if (!verify_descriptor(zara::loader::Architecture::ARM, "arm", 4, 4, "sp", "fp", "lr")) {
        std::cerr << "arm architecture descriptor mismatch\n";
        return 4;
    }

    if (!verify_descriptor(zara::loader::Architecture::ARM64, "arm64", 8, 4, "sp", "x29", "x30")) {
        std::cerr << "arm64 architecture descriptor mismatch\n";
        return 5;
    }

    if (!verify_descriptor(zara::loader::Architecture::RISCV64, "riscv64", 8, 2, "sp", "s0", "ra")) {
        std::cerr << "riscv64 architecture descriptor mismatch\n";
        return 6;
    }

    if (!verify_descriptor(zara::loader::Architecture::MIPS64, "mips64", 8, 4, "sp", "fp", "ra")) {
        std::cerr << "mips64 architecture descriptor mismatch\n";
        return 7;
    }

    if (!verify_descriptor(zara::loader::Architecture::PPC64, "ppc64", 8, 4, "r1", "r31", "lr")) {
        std::cerr << "ppc64 architecture descriptor mismatch\n";
        return 8;
    }

    return 0;
}
