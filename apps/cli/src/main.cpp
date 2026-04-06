#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "zara/ai/assistant.hpp"
#include "zara/analysis/program_analysis.hpp"
#include "zara/cfg/function_graph.hpp"
#include "zara/database/project_store.hpp"
#include "zara/decompiler/decompiler.hpp"
#include "zara/debugger/session.hpp"
#include "zara/diff/engine.hpp"
#include "zara/distributed/batch_runner.hpp"
#include "zara/ir/lifter.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"
#include "zara/plugins/manager.hpp"
#include "zara/security/workflow.hpp"
#include "zara/scripting/python_engine.hpp"
#include "zara/ssa/builder.hpp"
#include "zara/type/recovery.hpp"

namespace {

struct LoadedProgram {
    zara::loader::BinaryImage image;
    zara::memory::AddressSpace address_space;
    zara::analysis::ProgramAnalysis analysis;
};

std::string format_address(const std::uint64_t value) {
    std::ostringstream stream;
    stream << "0x" << std::hex << std::uppercase << value;
    return stream.str();
}

std::string format_bytes(const std::vector<std::byte>& bytes) {
    std::ostringstream stream;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index > 0) {
            stream << ' ';
        }
        stream << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
               << static_cast<unsigned int>(std::to_integer<unsigned int>(bytes[index]));
    }
    return stream.str();
}

bool patch_overlaps_breakpoints(
    const std::uint64_t address,
    const std::size_t size,
    const std::set<std::uint64_t>& breakpoints
) {
    if (size == 0) {
        return false;
    }

    const auto end = address + static_cast<std::uint64_t>(size);
    for (const auto breakpoint : breakpoints) {
        if (breakpoint >= address && breakpoint < end) {
            return true;
        }
    }
    return false;
}

void print_registers(const zara::debugger::RegisterState& registers) {
    std::cout
        << "Registers\n"
        << "  RIP " << format_address(registers.rip) << '\n'
        << "  RSP " << format_address(registers.rsp) << '\n'
        << "  RBP " << format_address(registers.rbp) << '\n'
        << "  RAX " << format_address(registers.rax) << '\n'
        << "  RBX " << format_address(registers.rbx) << '\n'
        << "  RCX " << format_address(registers.rcx) << '\n'
        << "  RDX " << format_address(registers.rdx) << '\n'
        << "  RSI " << format_address(registers.rsi) << '\n'
        << "  RDI " << format_address(registers.rdi) << '\n';
}

void print_stop_event(const zara::debugger::StopEvent& event) {
    std::cout << "Stop: " << zara::debugger::to_string(event.reason);
    if (event.address.has_value()) {
        std::cout << "  @" << format_address(*event.address);
    }
    if (event.signal != 0) {
        std::cout << "  signal=" << event.signal;
    }
    if (event.reason == zara::debugger::StopReason::Exited) {
        std::cout << "  exit=" << event.exit_code;
    }
    if (!event.message.empty()) {
        std::cout << "  " << event.message;
    }
    std::cout << '\n';
}

void print_runtime_snapshot(const zara::debugger::RuntimeSnapshot& snapshot) {
    std::cout << "Runtime snapshot\n";
    std::cout << "  RIP " << format_address(snapshot.registers.rip) << '\n';
    if (!snapshot.instruction_bytes.empty()) {
        std::cout << "  Bytes " << format_bytes(snapshot.instruction_bytes) << '\n';
    }
    if (snapshot.location.has_value()) {
        std::cout
            << "  Function "
            << snapshot.location->function_name
            << "  "
            << format_address(snapshot.location->function_entry)
            << '\n';
        std::cout
            << "  Block    "
            << format_address(snapshot.location->block_start)
            << "  "
            << snapshot.location->mnemonic
            << ' '
            << snapshot.location->operands
            << '\n';
        if (!snapshot.location->pseudocode_excerpt.empty()) {
            std::cout << "  Pseudocode\n";
            std::istringstream excerpt(snapshot.location->pseudocode_excerpt);
            std::string line;
            while (std::getline(excerpt, line)) {
                std::cout << "    " << line << '\n';
            }
        }
    }
}

std::optional<LoadedProgram> load_program(const std::filesystem::path& binary_path, std::string& out_error) {
    out_error.clear();

    LoadedProgram program;
    if (!zara::loader::BinaryImage::load_from_file(binary_path, program.image, out_error)) {
        return std::nullopt;
    }

    if (!program.address_space.map_image(program.image)) {
        out_error = "Failed to map image into address space.";
        return std::nullopt;
    }

    program.analysis = zara::analysis::Analyzer::analyze(program.image, program.address_space);
    return program;
}

bool persist_project_if_needed(
    const std::filesystem::path& project_path,
    const LoadedProgram& loaded,
    const zara::ai::AssistantOptions* assistant_options,
    const bool allow_cache,
    bool& out_cache_hit,
    std::string& out_error
) {
    out_cache_hit = false;
    zara::database::ProjectStore project_store(project_path);
    if (allow_cache) {
        if (const auto cached = project_store.find_cached_analysis_run(loaded.image, out_error); cached.has_value()) {
            out_cache_hit = true;
            out_error.clear();
            return true;
        }
    }

    return project_store.save_program_analysis(loaded.image, loaded.analysis, assistant_options, out_error);
}

std::string trim(std::string value) {
    const auto first = std::find_if_not(
        value.begin(),
        value.end(),
        [](const unsigned char character) { return std::isspace(character) != 0; }
    );
    const auto last = std::find_if_not(
        value.rbegin(),
        value.rend(),
        [](const unsigned char character) { return std::isspace(character) != 0; }
    ).base();
    if (first >= last) {
        return {};
    }
    return std::string(first, last);
}

std::vector<std::string> split_words(const std::string& line) {
    std::istringstream stream(line);
    std::vector<std::string> words;
    std::string word;
    while (stream >> word) {
        words.push_back(word);
    }
    return words;
}

bool parse_u64(std::string_view token, std::uint64_t& out_value) {
    if (token.empty()) {
        return false;
    }

    std::size_t parsed = 0;
    const int base = token.starts_with("0x") || token.starts_with("0X") ? 16 : 10;
    try {
        out_value = std::stoull(std::string(token), &parsed, base);
        return parsed == token.size();
    } catch (...) {
        return false;
    }
}

bool parse_hex_byte(std::string_view token, std::byte& out_value) {
    if (token.size() != 2 || !std::isxdigit(static_cast<unsigned char>(token[0])) ||
        !std::isxdigit(static_cast<unsigned char>(token[1]))) {
        return false;
    }

    const auto high = static_cast<unsigned int>(std::isdigit(static_cast<unsigned char>(token[0]))
                                                    ? token[0] - '0'
                                                    : std::toupper(static_cast<unsigned char>(token[0])) - 'A' + 10);
    const auto low = static_cast<unsigned int>(std::isdigit(static_cast<unsigned char>(token[1]))
                                                   ? token[1] - '0'
                                                   : std::toupper(static_cast<unsigned char>(token[1])) - 'A' + 10);
    out_value = static_cast<std::byte>((high << 4U) | low);
    return true;
}

std::optional<std::uint64_t> find_function_entry_by_name(
    const zara::analysis::ProgramAnalysis& analysis,
    std::string_view name
) {
    const auto function_it = std::find_if(
        analysis.functions.begin(),
        analysis.functions.end(),
        [&](const zara::analysis::DiscoveredFunction& function) { return function.name == name; }
    );
    if (function_it == analysis.functions.end()) {
        return std::nullopt;
    }
    return function_it->entry_address;
}

std::optional<std::uint64_t> resolve_debug_address(
    std::string_view token,
    const std::optional<LoadedProgram>& loaded_program,
    const std::optional<zara::debugger::RegisterState>& registers
) {
    if (token == "rip" && registers.has_value()) {
        return registers->rip;
    }
    if (token == "rsp" && registers.has_value()) {
        return registers->rsp;
    }
    if (token == "rbp" && registers.has_value()) {
        return registers->rbp;
    }
    if (token == "entry" && loaded_program.has_value() && loaded_program->image.entry_point().has_value()) {
        return *loaded_program->image.entry_point();
    }

    std::uint64_t numeric = 0;
    if (parse_u64(token, numeric)) {
        return numeric;
    }

    if (loaded_program.has_value()) {
        if (const auto symbol = loaded_program->address_space.resolve_symbol(token); symbol.has_value()) {
            return symbol->address;
        }
        if (const auto function_entry = find_function_entry_by_name(loaded_program->analysis, token);
            function_entry.has_value()) {
            return *function_entry;
        }
    }

    return std::nullopt;
}

void print_vulnerability_patterns(const zara::security::ExploitReport& report, const std::size_t max_count) {
    if (report.patterns.empty()) {
        return;
    }

    std::cout << "\nVulnerability patterns\n";
    for (std::size_t index = 0; index < std::min<std::size_t>(report.patterns.size(), max_count); ++index) {
        const auto& pattern = report.patterns[index];
        std::cout
            << "  ["
            << zara::security::to_string(pattern.severity)
            << "] "
            << pattern.function_name
            << "  "
            << pattern.title
            << '\n';
        std::cout << "    " << pattern.detail << '\n';
        for (const auto& note : pattern.poc_notes) {
            std::cout << "    - " << note << '\n';
        }
    }
}

void print_poc_targets(const zara::security::ExploitReport& report, const std::size_t max_count) {
    if (report.poc_targets.empty()) {
        return;
    }

    std::cout << "\nPoC targets\n";
    for (std::size_t index = 0; index < std::min<std::size_t>(report.poc_targets.size(), max_count); ++index) {
        const auto& target = report.poc_targets[index];
        std::cout
            << "  "
            << target.role
            << "  "
            << target.function_name
            << "  "
            << format_address(target.function_entry)
            << '\n';
        for (const auto& note : target.notes) {
            std::cout << "    - " << note << '\n';
        }
    }
}

void print_stack_visualizations(const zara::security::ExploitReport& report, const std::size_t max_count) {
    if (report.stack_visualizations.empty()) {
        return;
    }

    std::cout << "\nStack visualizations\n";
    for (std::size_t index = 0; index < std::min<std::size_t>(report.stack_visualizations.size(), max_count); ++index) {
        std::istringstream stream(report.stack_visualizations[index].rendered);
        std::string line;
        while (std::getline(stream, line)) {
            std::cout << "  " << line << '\n';
        }
    }
}

void print_mutation_hooks(const zara::security::FuzzingReport& report, const std::size_t max_count) {
    if (report.mutation_hooks.empty()) {
        return;
    }

    std::cout << "\nMutation hooks\n";
    for (std::size_t index = 0; index < std::min<std::size_t>(report.mutation_hooks.size(), max_count); ++index) {
        const auto& hook = report.mutation_hooks[index];
        std::cout << "  " << hook.function_name << "  [" << hook.kind << "]  " << hook.label << '\n';
        std::cout << "    " << hook.detail << '\n';
        if (!hook.sample.empty()) {
            std::cout << "    sample: " << hook.sample << '\n';
        }
    }
}

void print_harness_artifacts(const zara::security::FuzzingReport& report) {
    if (report.harness_artifacts.empty()) {
        return;
    }

    std::cout << "\nHarness artifacts\n";
    for (const auto& artifact : report.harness_artifacts) {
        std::cout << "  " << artifact.engine << "  " << artifact.filename << '\n';
    }
}

void print_debug_target_shapes() {
    std::cout << "Debugger target shapes\n";
    for (const auto& shape : zara::debugger::DebugSession::target_shapes()) {
        std::cout
            << "  "
            << zara::debugger::to_string(shape.platform)
            << "  "
            << zara::debugger::to_string(shape.backend)
            << "  implemented="
            << (shape.implemented ? "yes" : "no");
        if (shape.selected_on_host) {
            std::cout << "  [host]";
        }
        std::cout << '\n';
        if (!shape.note.empty()) {
            std::cout << "    " << shape.note << '\n';
        }
    }
}

void print_batch_summary(const zara::distributed::BatchResult& result) {
    std::cout << "  worker-slots " << result.worker_slots << '\n';
    std::cout << "  mode         " << (result.remote ? "remote-controller" : "local") << '\n';
    std::cout << "  protocol     " << result.protocol_version << '\n';
    std::cout << "  totals       funcs=" << result.total_function_count << " calls=" << result.total_call_count
              << " imports=" << result.total_import_count << " exports=" << result.total_export_count
              << " xrefs=" << result.total_xref_count << " strings=" << result.total_string_count << '\n';

    if (!result.workers.empty()) {
        std::cout << "\nWorkers\n";
        for (const auto& worker : result.workers) {
            std::cout
                << "  "
                << worker.worker_id
                << "  "
                << worker.host
                << "  "
                << worker.platform
                << "  status="
                << worker.status
                << "  assigned="
                << worker.assigned_jobs
                << "  jobs="
                << worker.completed_jobs
                << "  ok="
                << worker.success_count
                << "  fail="
                << worker.failure_count
                << '\n';
            if (!worker.last_event.empty()) {
                std::cout << "    last-event: " << worker.last_event << '\n';
            }
            if (!worker.last_error.empty()) {
                std::cout << "    last-error: " << worker.last_error << '\n';
            }
        }
    }

    if (!result.events.empty()) {
        std::cout << "\nEvents\n";
        for (std::size_t index = 0; index < std::min<std::size_t>(result.events.size(), 24); ++index) {
            const auto& event = result.events[index];
            std::cout << "  #" << event.sequence << "  " << event.worker_id << "  " << event.kind;
            if (!event.detail.empty()) {
                std::cout << "  " << event.detail;
            }
            std::cout << '\n';
        }
    }
}

bool print_current_snapshot(
    zara::debugger::DebugSession& debugger,
    const std::optional<LoadedProgram>& loaded_program,
    const zara::debugger::StopEvent& event,
    std::optional<zara::debugger::RegisterState>& out_registers,
    std::string& out_error
) {
    zara::debugger::RegisterState registers;
    if (!debugger.read_registers(registers, out_error)) {
        return false;
    }

    out_registers = registers;
    print_registers(registers);

    if (!loaded_program.has_value()) {
        return true;
    }

    zara::debugger::RuntimeSnapshot snapshot;
    if (!zara::debugger::capture_runtime_snapshot(
            debugger,
            loaded_program->image,
            loaded_program->analysis,
            event,
            snapshot,
            out_error
        )) {
        return false;
    }

    print_runtime_snapshot(snapshot);
    return true;
}

void print_ai_preview(const std::vector<zara::ai::FunctionInsight>& insights, const std::size_t max_count) {
    if (insights.empty()) {
        return;
    }

    std::cout << "\nAI insight preview\n";
    for (std::size_t index = 0; index < std::min<std::size_t>(insights.size(), max_count); ++index) {
        const auto& insight = insights[index];
        std::cout
            << "  "
            << format_address(insight.entry_address)
            << "  "
            << insight.current_name
            << " -> "
            << insight.suggested_name
            << '\n';
        std::cout << "    " << insight.summary << '\n';
        for (const auto& hint : insight.hints) {
            std::cout << "    - " << hint << '\n';
        }
    }
}

void print_ai_metadata(const zara::ai::AssistantRunMetadata& metadata) {
    std::cout << "AI backend: " << metadata.backend << '\n';
    if (!metadata.model.empty()) {
        std::cout << "AI model:   " << metadata.model << '\n';
    }
    if (!metadata.credential_fingerprint.empty()) {
        std::cout << "AI cred:    " << metadata.credential_fingerprint << '\n';
    }
    for (const auto& warning : metadata.warnings) {
        std::cout << "AI note:    " << warning << '\n';
    }
}

void print_security_preview(
    const zara::security::ExploitReport& report,
    const std::size_t max_findings,
    const std::size_t max_gadgets
) {
    if (max_findings > 0 && !report.findings.empty()) {
        std::cout << "\nSecurity findings\n";
        for (std::size_t index = 0; index < std::min<std::size_t>(report.findings.size(), max_findings); ++index) {
            const auto& finding = report.findings[index];
            std::cout
                << "  ["
                << zara::security::to_string(finding.severity)
                << "] "
                << finding.function_name
                << "  "
                << finding.title
                << '\n';
            std::cout << "    " << finding.detail << '\n';
        }
    }

    if (max_gadgets > 0 && !report.gadgets.empty()) {
        std::cout << "\nROP gadget preview\n";
        for (std::size_t index = 0; index < std::min<std::size_t>(report.gadgets.size(), max_gadgets); ++index) {
            const auto& gadget = report.gadgets[index];
            std::cout
                << "  "
                << format_address(gadget.address)
                << "  "
                << gadget.sequence
                << "  ["
                << gadget.function_name
                << "]\n";
        }
    }
}

void print_usage() {
    std::cerr
        << "Usage:\n"
        << "  zara_cli <binary-path> [project-db-path]\n"
        << "  zara_cli ai <binary-path> [project-db-path]\n"
        << "  zara_cli ai-model <binary-path> [project-db-path]\n"
        << "  zara_cli exploit <binary-path> [project-db-path]\n"
        << "  zara_cli fuzz-map <binary-path> <trace-path> [harness-output-dir]\n"
        << "  zara_cli fuzz-live <binary-path> <bundle-output-dir> <tool-command...>\n"
        << "  zara_cli batch <input-path> <output-dir> [concurrency] [shard-count] [shard-index]\n"
        << "  zara_cli batch-controller <input-path> <output-dir> <port> <workers> [max-jobs-per-worker]\n"
        << "  zara_cli batch-worker <host> <port> <output-dir>\n"
        << "    remote batch modes require ZARA_BATCH_SHARED_SECRET or an explicit shared_secret in scripting\n"
        << "    optional TLS env: ZARA_BATCH_USE_TLS=1 ZARA_BATCH_TLS_CERT=<pem> ZARA_BATCH_TLS_KEY=<pem> ZARA_BATCH_TLS_CA=<pem>\n"
        << "  zara_cli debug-targets\n"
        << "  zara_cli debug <binary-path> [args...]\n"
        << "  zara_cli debug-attach <pid>\n"
        << "  zara_cli debug-shell <binary-path> [--script <commands.txt>] [args...]\n"
        << "  zara_cli script --repl [args...]\n"
        << "  zara_cli script <script-path> [args...]\n"
        << "  zara_cli script -c <code> [args...]\n"
        << "  zara_cli plugins <plugins-dir> <binary-path>\n"
        << "  zara_cli plugins-marketplace list <marketplace-root>\n"
        << "  zara_cli plugins-marketplace install <marketplace-root> <plugin-name> <destination-root>\n"
        << "  zara_cli diff <before-binary> <after-binary>\n";
}

int run_analysis_mode(const std::filesystem::path& binary_path, const std::filesystem::path& project_path) {
    std::string error;
    auto loaded = load_program(binary_path, error);
    if (!loaded.has_value()) {
        std::cerr << "Load failed: " << error << '\n';
        return 1;
    }

    const auto ai_insights = zara::ai::Assistant::analyze_program(loaded->analysis, loaded->image.entry_point());
    const auto security_report = zara::security::Workflow::analyze_exploit_surface(binary_path, loaded->analysis, 32);

    std::cout << "Loaded: " << loaded->image.source_path() << '\n';
    std::cout << "Format: " << zara::loader::to_string(loaded->image.format()) << '\n';
    std::cout << "Arch:   " << zara::loader::to_string(loaded->image.architecture()) << '\n';
    std::cout << "Base:   " << format_address(loaded->image.base_address()) << '\n';
    if (loaded->image.entry_point().has_value()) {
        std::cout << "Entry:  " << format_address(*loaded->image.entry_point()) << '\n';
    }
    std::cout << "Size:   " << loaded->image.raw_image().size() << " bytes\n";
    std::cout << "Funcs:  " << loaded->analysis.functions.size() << '\n';
    std::cout << "Calls:  " << loaded->analysis.call_graph.size() << '\n';
    std::cout << "Xrefs:  " << loaded->analysis.xrefs.size() << '\n';
    std::cout << "Imports:" << loaded->image.imports().size() << '\n';
    std::cout << "Exports:" << loaded->image.exports().size() << '\n';
    std::cout << "Strings:" << loaded->analysis.strings.size() << '\n';
    std::cout << "AI:     " << ai_insights.size() << '\n';
    std::cout << "Risks:  " << security_report.findings.size() << '\n';
    std::cout << "Gadgets:" << security_report.gadgets.size() << '\n';
    std::cout << "Sections\n";
    for (const auto& section : loaded->image.sections()) {
        std::cout
            << "  "
            << std::setw(12)
            << std::left
            << section.name
            << format_address(section.virtual_address)
            << "  size="
            << section.bytes.size()
            << "  perms="
            << (section.readable ? 'r' : '-')
            << (section.writable ? 'w' : '-')
            << (section.executable ? 'x' : '-')
            << '\n';
    }

    if (!loaded->analysis.functions.empty()) {
        std::cout << "\nFunctions preview\n";
        for (std::size_t function_index = 0; function_index < std::min<std::size_t>(loaded->analysis.functions.size(), 16); ++function_index) {
            const auto& function = loaded->analysis.functions[function_index];
            std::size_t instruction_count = 0;
            for (const auto& block : function.graph.blocks()) {
                instruction_count += block.instructions.size();
            }
            std::cout
                << "  "
                << function.name
                << "  "
                << format_address(function.entry_address)
                << "  section="
                << function.section_name
                << "  blocks="
                << function.graph.blocks().size()
                << "  instrs="
                << instruction_count
                << '\n';
        }

        const auto& first_function = loaded->analysis.functions.front();
        if (!first_function.graph.blocks().empty()) {
            std::cout << "\nFirst function blocks\n";
            for (const auto& block : first_function.graph.blocks()) {
                std::cout
                    << "  "
                    << format_address(block.start_address)
                    << " -> "
                    << format_address(block.end_address)
                    << "  successors=";

                if (block.successors.empty()) {
                    std::cout << "-";
                } else {
                    for (std::size_t successor_index = 0; successor_index < block.successors.size(); ++successor_index) {
                        if (successor_index > 0) {
                            std::cout << ", ";
                        }
                        std::cout << format_address(block.successors[successor_index]);
                    }
                }
                std::cout << '\n';
            }

            std::cout << "\nDisassembly preview\n";
            std::size_t emitted = 0;
            for (const auto& block : first_function.graph.blocks()) {
                for (const auto& instruction : block.instructions) {
                    std::cout
                        << "  "
                        << std::setw(10)
                        << std::left
                        << format_address(instruction.address)
                        << instruction.mnemonic
                        << ' '
                        << instruction.operands
                        << '\n';
                    ++emitted;
                    if (emitted >= 32) {
                        break;
                    }
                }

                if (emitted >= 32) {
                    break;
                }
            }
        }

        if (!first_function.lifted_ir.blocks.empty()) {
            std::cout << "\nIR preview\n";
            std::size_t emitted = 0;
            for (const auto& block : first_function.lifted_ir.blocks) {
                std::cout << "  block " << format_address(block.start_address) << '\n';
                for (const auto& instruction : block.instructions) {
                    std::cout << "    " << zara::ir::format_instruction(instruction) << '\n';
                    ++emitted;
                    if (emitted >= 24) {
                        break;
                    }
                }
                if (emitted >= 24) {
                    break;
                }
            }
        }

        if (!first_function.ssa_form.blocks.empty()) {
            std::cout << "\nSSA preview\n";
            std::size_t emitted = 0;
            for (const auto& block : first_function.ssa_form.blocks) {
                std::cout << "  block " << format_address(block.start_address) << '\n';
                for (const auto& phi : block.phi_nodes) {
                    std::cout << "    " << zara::ssa::format_phi(phi) << '\n';
                }
                for (const auto& instruction : block.instructions) {
                    std::cout << "    " << zara::ir::format_instruction(instruction) << '\n';
                    ++emitted;
                    if (emitted >= 24) {
                        break;
                    }
                }
                if (emitted >= 24) {
                    break;
                }
            }
        }

        if (!first_function.recovered_types.variables.empty()) {
            std::cout << "\nRecovered types\n";
            for (std::size_t index = 0; index < std::min<std::size_t>(first_function.recovered_types.variables.size(), 16); ++index) {
                const auto& variable = first_function.recovered_types.variables[index];
                std::cout << "  " << variable.name << " : " << zara::ir::to_string(variable.type) << '\n';
            }
        }

        if (!first_function.decompiled.pseudocode.empty()) {
            std::cout << "\nDecompiler preview\n";
            std::istringstream stream(first_function.decompiled.pseudocode);
            std::string line;
            std::size_t emitted = 0;
            while (std::getline(stream, line) && emitted < 24) {
                std::cout << "  " << line << '\n';
                ++emitted;
            }
        }
    }

    if (!loaded->analysis.call_graph.empty()) {
        std::cout << "\nCall graph preview\n";
        for (std::size_t index = 0; index < std::min<std::size_t>(loaded->analysis.call_graph.size(), 16); ++index) {
            const auto& edge = loaded->analysis.call_graph[index];
            std::cout
                << "  "
                << format_address(edge.caller_entry)
                << " @ "
                << format_address(edge.call_site)
                << " -> ";
            if (edge.callee_entry.has_value()) {
                std::cout << format_address(*edge.callee_entry);
            } else {
                std::cout << "<import>";
            }
            if (!edge.callee_name.empty()) {
                std::cout << "  " << edge.callee_name;
            }
            std::cout << '\n';
        }
    }

    if (!loaded->analysis.xrefs.empty()) {
        std::cout << "\nCross references\n";
        for (std::size_t index = 0; index < std::min<std::size_t>(loaded->analysis.xrefs.size(), 16); ++index) {
            const auto& xref = loaded->analysis.xrefs[index];
            std::cout
                << "  "
                << format_address(xref.from_address)
                << " -> "
                << format_address(xref.to_address)
                << "  "
                << zara::xrefs::to_string(xref.kind);
            if (!xref.label.empty()) {
                std::cout << "  " << xref.label;
            }
            std::cout << '\n';
        }
    }

    if (!loaded->image.imports().empty()) {
        std::cout << "\nImports preview\n";
        for (std::size_t index = 0; index < std::min<std::size_t>(loaded->image.imports().size(), 16); ++index) {
            const auto& imported = loaded->image.imports()[index];
            std::cout
                << "  "
                << format_address(imported.address)
                << "  "
                << (imported.library.empty() ? imported.name : imported.library + "!" + imported.name)
                << '\n';
        }
    }

    if (!loaded->image.exports().empty()) {
        std::cout << "\nExports preview\n";
        for (std::size_t index = 0; index < std::min<std::size_t>(loaded->image.exports().size(), 16); ++index) {
            const auto& exported = loaded->image.exports()[index];
            std::cout
                << "  "
                << format_address(exported.address)
                << "  "
                << exported.name
                << "  size="
                << exported.size
                << '\n';
        }
    }

    if (!loaded->analysis.strings.empty()) {
        std::cout << "\nStrings preview\n";
        for (std::size_t index = 0; index < std::min<std::size_t>(loaded->analysis.strings.size(), 8); ++index) {
            const auto& extracted = loaded->analysis.strings[index];
            std::cout
                << "  "
                << format_address(extracted.start_address)
                << "  "
                << extracted.value
                << '\n';
        }
    }

    print_ai_preview(ai_insights, 8);
    print_security_preview(security_report, 8, 8);

    bool cache_hit = false;
    if (persist_project_if_needed(project_path, *loaded, nullptr, true, cache_hit, error)) {
        std::cout << '\n'
                  << (cache_hit ? "Reused cached project analysis at " : "Saved analysis summary to ")
                  << project_path << '\n';
    } else {
        std::cout << "\nProject database skipped: " << error << '\n';
    }

    return 0;
}

int run_ai_mode(
    const std::filesystem::path& binary_path,
    const std::optional<std::filesystem::path>& project_path,
    const bool model_backed
) {
    std::string error;
    auto loaded = load_program(binary_path, error);
    if (!loaded.has_value()) {
        std::cerr << "Load failed: " << error << '\n';
        return 1;
    }

    zara::ai::AssistantRunMetadata ai_metadata;
    const auto assistant_options =
        model_backed ? zara::ai::Assistant::options_from_environment() : zara::ai::AssistantOptions{};
    const auto insights =
        model_backed ? zara::ai::Assistant::analyze_program(
                           loaded->analysis,
                           loaded->image.entry_point(),
                           assistant_options,
                           &ai_metadata
                       )
                     : zara::ai::Assistant::analyze_program(loaded->analysis, loaded->image.entry_point());
    if (!model_backed) {
        ai_metadata.backend = "heuristic";
    }

    std::cout << "AI insights for " << binary_path << '\n';
    std::cout << "  functions " << loaded->analysis.functions.size() << '\n';
    std::cout << "  insights  " << insights.size() << '\n';
    print_ai_metadata(ai_metadata);
    print_ai_preview(insights, 24);

    if (project_path.has_value()) {
        const auto* options_ptr = model_backed ? &assistant_options : nullptr;
        bool cache_hit = false;
        if (persist_project_if_needed(*project_path, *loaded, options_ptr, !model_backed, cache_hit, error)) {
            std::cout << '\n'
                      << (cache_hit ? "Reused cached project analysis at " : "Saved analysis summary to ")
                      << *project_path << '\n';
        } else {
            std::cout << "\nProject database skipped: " << error << '\n';
        }
    }

    return 0;
}

int run_exploit_mode(
    const std::filesystem::path& binary_path,
    const std::optional<std::filesystem::path>& project_path
) {
    std::string error;
    auto loaded = load_program(binary_path, error);
    if (!loaded.has_value()) {
        std::cerr << "Load failed: " << error << '\n';
        return 1;
    }

    const auto report = zara::security::Workflow::analyze_exploit_surface(binary_path, loaded->analysis);
    std::cout << "Exploit surface for " << binary_path << '\n';
    std::cout << "  findings " << report.findings.size() << '\n';
    std::cout << "  gadgets  " << report.gadgets.size() << '\n';
    std::cout << "  patterns " << report.patterns.size() << '\n';
    std::cout << "  targets  " << report.poc_targets.size() << '\n';
    print_security_preview(report, 24, 24);
    print_vulnerability_patterns(report, 16);
    print_poc_targets(report, 16);
    print_stack_visualizations(report, 8);

    if (!report.poc_scaffold.empty()) {
        std::cout << "\nPoC scaffold\n" << report.poc_scaffold;
    }

    if (project_path.has_value()) {
        bool cache_hit = false;
        if (persist_project_if_needed(*project_path, *loaded, nullptr, true, cache_hit, error)) {
            std::cout << '\n'
                      << (cache_hit ? "Reused cached project analysis at " : "Saved analysis summary to ")
                      << *project_path << '\n';
        } else {
            std::cout << "\nProject database skipped: " << error << '\n';
        }
    }

    return 0;
}

int run_fuzz_mode(
    const std::filesystem::path& binary_path,
    const std::filesystem::path& trace_path,
    const std::optional<std::filesystem::path>& harness_output_directory
) {
    std::string error;
    auto loaded = load_program(binary_path, error);
    if (!loaded.has_value()) {
        std::cerr << "Load failed: " << error << '\n';
        return 1;
    }

    zara::security::CrashTrace trace;
    if (!zara::security::Workflow::parse_trace_file(trace_path, trace, error)) {
        std::cerr << "Trace parse failed: " << error << '\n';
        return 1;
    }

    const auto report = zara::security::Workflow::analyze_fuzzing_surface(binary_path, loaded->analysis, trace);
    std::cout << "Fuzz/crash mapping for " << binary_path << '\n';
    if (!trace.input_label.empty()) {
        std::cout << "  input    " << trace.input_label << '\n';
    }
    std::cout << "  coverage " << trace.coverage_addresses.size() << '\n';
    if (trace.crash_address.has_value()) {
        std::cout << "  crash    " << format_address(*trace.crash_address) << '\n';
    }
    std::cout << '\n' << report.crash_summary << '\n';

    if (!report.covered_functions.empty()) {
        std::cout << "\nCovered functions\n";
        for (std::size_t index = 0; index < std::min<std::size_t>(report.covered_functions.size(), 24); ++index) {
            const auto& function = report.covered_functions[index];
            std::cout
                << "  "
                << function.function_name
                << "  "
                << format_address(function.function_entry)
                << "  hits="
                << function.hit_count
                << '/'
                << function.instruction_count
                << "  ratio="
                << std::fixed
                << std::setprecision(2)
                << (function.coverage_ratio * 100.0)
                << "%";
            if (function.contains_crash_address) {
                std::cout << "  [crash]";
            }
            std::cout << '\n';
        }
    }

    if (!report.crash_hints.empty()) {
        std::cout << "\nCrash hints\n";
        for (const auto& hint : report.crash_hints) {
            std::cout
                << "  ["
                << zara::security::to_string(hint.severity)
                << "] "
                << hint.function_name
                << "  "
                << hint.title
                << '\n';
            std::cout << "    " << hint.detail << '\n';
        }
    }

    print_mutation_hooks(report, 24);
    print_harness_artifacts(report);

    if (harness_output_directory.has_value()) {
        std::vector<std::filesystem::path> written_paths;
        if (!zara::security::Workflow::write_harness_bundle(
                *harness_output_directory,
                report,
                &written_paths,
                error
            )) {
            std::cerr << "Harness bundle write failed: " << error << '\n';
            return 1;
        }

        std::cout << "\nWrote harness bundle to " << *harness_output_directory << '\n';
        for (const auto& path : written_paths) {
            std::cout << "  " << path << '\n';
        }
    }

    return 0;
}

int run_fuzz_live_mode(
    const std::filesystem::path& binary_path,
    const std::filesystem::path& harness_output_directory,
    const std::string& tool_command
) {
    std::string error;
    auto loaded = load_program(binary_path, error);
    if (!loaded.has_value()) {
        std::cerr << "Load failed: " << error << '\n';
        return 1;
    }

    zara::security::CrashTrace trace;
    trace.input_label = "live-feedback";
    const auto report = zara::security::Workflow::analyze_fuzzing_surface(binary_path, loaded->analysis, trace);
    std::vector<std::filesystem::path> written_paths;
    if (!zara::security::Workflow::write_harness_bundle(
            harness_output_directory,
            report,
            &written_paths,
            error
        )) {
        std::cerr << "Harness bundle write failed: " << error << '\n';
        return 1;
    }

    std::cout << "Live fuzz execution\n";
    std::cout << "  bundle     " << harness_output_directory << '\n';
    std::cout << "  command    " << tool_command << "\n\n";

    zara::security::LiveFuzzResult result;
    if (!zara::security::Workflow::run_live_fuzz_tool(
            tool_command,
            zara::security::LiveFuzzOptions{
                .working_directory = harness_output_directory,
                .engine_hint = tool_command,
                .max_output_lines = 4096,
                .max_line_bytes = 16384,
                .on_event =
                    [](const zara::security::FuzzProgressEvent& event) {
                        std::cout << "[fuzz] " << event.kind;
                        if (event.executions.has_value()) {
                            std::cout << "  exec=" << *event.executions;
                        }
                        if (event.coverage.has_value()) {
                            std::cout << "  cov=" << *event.coverage;
                        }
                        if (event.corpus_size.has_value()) {
                            std::cout << "  corpus=" << *event.corpus_size;
                        }
                        if (!event.source_line.empty()) {
                            std::cout << "  " << event.source_line;
                        }
                        std::cout << '\n';
                    },
            },
            result,
            error
        )) {
        std::cerr << "Live fuzz execution failed: " << error << '\n';
        return 1;
    }

    std::cout << "\nLive fuzz summary\n";
    std::cout << "  exit-code  " << result.exit_code << '\n';
    std::cout << "  events     " << result.events.size() << '\n';
    std::cout << "  crash      " << (result.crash_detected ? "yes" : "no") << '\n';
    return result.exit_code == 0 ? 0 : 1;
}

int run_batch_mode(
    const std::filesystem::path& input_path,
    const std::filesystem::path& output_directory,
    const std::size_t concurrency,
    const std::size_t shard_count,
    const std::size_t shard_index
) {
    const auto inputs = zara::distributed::BatchRunner::discover_inputs(input_path);
    if (inputs.empty()) {
        std::cerr << "No candidate binaries found under " << input_path << '\n';
        return 1;
    }

    const auto result = zara::distributed::BatchRunner::analyze(
        inputs,
        output_directory,
        zara::distributed::BatchOptions{
            .concurrency = concurrency,
            .shard_count = shard_count,
            .shard_index = shard_index,
            .recursive = true,
        }
    );

    std::string error;
    const auto manifest_path = output_directory / "manifest.tsv";
    const auto summary_path = output_directory / "summary.json";
    if (!zara::distributed::BatchRunner::write_manifest(manifest_path, result, error)) {
        std::cerr << "Manifest write failed: " << error << '\n';
        return 1;
    }
    if (!zara::distributed::BatchRunner::write_summary(summary_path, result, error)) {
        std::cerr << "Summary write failed: " << error << '\n';
        return 1;
    }

    std::cout << "Batch analysis\n";
    std::cout << "  discovered " << inputs.size() << '\n';
    std::cout << "  success    " << result.success_count << '\n';
    std::cout << "  failure    " << result.failure_count << '\n';
    std::cout << "  manifest   " << manifest_path << '\n';
    std::cout << "  summary    " << summary_path << '\n';
    print_batch_summary(result);

    std::cout << "\nJobs\n";
    for (std::size_t index = 0; index < std::min<std::size_t>(result.jobs.size(), 24); ++index) {
        const auto& job = result.jobs[index];
        std::cout << "  " << (job.success ? "ok   " : "fail ") << job.binary_path;
        if (job.success) {
            std::cout
                << "  funcs=" << job.function_count
                << "  calls=" << job.call_count
                << "  db=" << job.project_db_path;
        } else if (!job.error.empty()) {
            std::cout << "  " << job.error;
        }
        std::cout << '\n';
    }

    return result.failure_count == 0 ? 0 : 1;
}

int run_batch_controller_mode(
    const std::filesystem::path& input_path,
    const std::filesystem::path& output_directory,
    const std::uint16_t port,
    const std::size_t worker_count,
    const std::size_t max_jobs_per_worker
) {
    const auto inputs = zara::distributed::BatchRunner::discover_inputs(input_path);
    if (inputs.empty()) {
        std::cerr << "No candidate binaries found under " << input_path << '\n';
        return 1;
    }

    zara::distributed::BatchResult result;
    std::string error;
    if (!zara::distributed::BatchRunner::analyze_remote(
            inputs,
            output_directory,
            zara::distributed::RemoteOptions{
                .host = "127.0.0.1",
                .port = port,
                .expected_workers = worker_count,
                .protocol_version = "zara-batch/2",
                .accept_timeout_ms = 10000,
                .read_timeout_ms = 10000,
                .max_message_bytes = 64u * 1024u,
                .max_jobs_per_worker = max_jobs_per_worker,
                .heartbeat_interval_ms = 1000,
                .heartbeat_timeout_ms = 5000,
                .shared_secret = "",
                .allowed_platforms = {},
                .use_tls = false,
                .require_tls_for_remote = true,
                .tls_insecure_skip_verify = false,
                .tls_certificate = {},
                .tls_private_key = {},
                .tls_ca_certificate = {},
            },
            result,
            error
        )) {
        std::cerr << "Remote controller failed: " << error << '\n';
        return 1;
    }

    const auto manifest_path = output_directory / "manifest.tsv";
    const auto summary_path = output_directory / "summary.json";
    if (!zara::distributed::BatchRunner::write_manifest(manifest_path, result, error)) {
        std::cerr << "Manifest write failed: " << error << '\n';
        return 1;
    }
    if (!zara::distributed::BatchRunner::write_summary(summary_path, result, error)) {
        std::cerr << "Summary write failed: " << error << '\n';
        return 1;
    }

    std::cout << "Remote batch analysis\n";
    std::cout << "  discovered " << inputs.size() << '\n';
    std::cout << "  workers    " << worker_count << '\n';
    if (max_jobs_per_worker > 0) {
        std::cout << "  max-jobs   " << max_jobs_per_worker << '\n';
    }
    std::cout << "  success    " << result.success_count << '\n';
    std::cout << "  failure    " << result.failure_count << '\n';
    std::cout << "  manifest   " << manifest_path << '\n';
    std::cout << "  summary    " << summary_path << '\n';
    print_batch_summary(result);
    return result.failure_count == 0 ? 0 : 1;
}

int run_batch_worker_mode(
    const std::string& host,
    const std::uint16_t port,
    const std::filesystem::path& output_directory
) {
    std::string error;
    if (!zara::distributed::BatchRunner::run_remote_worker(
            output_directory,
            zara::distributed::RemoteOptions{
                .host = host,
                .port = port,
                .expected_workers = 1,
                .protocol_version = "zara-batch/2",
                .accept_timeout_ms = 10000,
                .read_timeout_ms = 10000,
                .max_message_bytes = 64u * 1024u,
                .max_jobs_per_worker = 0,
                .heartbeat_interval_ms = 1000,
                .heartbeat_timeout_ms = 5000,
                .shared_secret = "",
                .allowed_platforms = {},
                .use_tls = false,
                .require_tls_for_remote = true,
                .tls_insecure_skip_verify = false,
                .tls_certificate = {},
                .tls_private_key = {},
                .tls_ca_certificate = {},
            },
            error
        )) {
        std::cerr << "Remote worker failed: " << error << '\n';
        return 1;
    }

    std::cout << "Remote worker completed.\n";
    return 0;
}

int run_debug_targets_mode() {
    print_debug_target_shapes();
    return 0;
}

int run_debug_shell_mode(
    const std::filesystem::path& binary_path,
    const std::vector<std::string>& arguments,
    const std::optional<std::filesystem::path>& script_path
) {
    auto debugger = zara::debugger::DebugSession::create_native();
    if (!debugger->is_supported()) {
        std::cerr << "Debugger backend is unavailable on this platform.\n";
        print_debug_target_shapes();
        return 1;
    }

    std::string error;
    std::optional<LoadedProgram> loaded_program = load_program(binary_path, error);
    if (!loaded_program.has_value()) {
        std::cout << "Static analysis context skipped: " << error << '\n';
        error.clear();
    }
    const auto exploit_report = loaded_program.has_value()
                                    ? std::optional<zara::security::ExploitReport>(
                                          zara::security::Workflow::analyze_exploit_surface(binary_path, loaded_program->analysis)
                                      )
                                    : std::nullopt;

    zara::debugger::StopEvent event;
    if (!debugger->launch(binary_path, arguments, event, error)) {
        std::cerr << "Launch failed: " << error << '\n';
        return 1;
    }

    std::cout << "Debugger backend: " << debugger->backend_name() << '\n';
    std::cout << "Process: " << debugger->process_id() << '\n';
    print_stop_event(event);
    if (loaded_program.has_value() && loaded_program->image.entry_point().has_value()) {
        std::cout << "Entry: " << format_address(*loaded_program->image.entry_point()) << '\n';
    }

    std::ifstream script_stream;
    std::istream* input = &std::cin;
    const bool scripted = script_path.has_value();
    if (scripted) {
        script_stream.open(*script_path);
        if (!script_stream) {
            std::cerr << "Failed to open debug shell script " << *script_path << '\n';
            std::string ignore_error;
            (void)debugger->terminate(ignore_error);
            return 1;
        }
        input = &script_stream;
    }

    auto print_help = []() {
        std::cout
            << "Commands\n"
            << "  help                    Show this command list\n"
            << "  regs                    Read registers\n"
            << "  snapshot|where          Capture static/runtime snapshot at the current stop\n"
            << "  break <addr|symbol>     Set a breakpoint\n"
            << "  delete <addr|symbol>    Remove a breakpoint\n"
            << "  continue|c              Resume execution\n"
            << "  step|s                  Single-step one instruction\n"
            << "  threads                 List traced threads\n"
            << "  thread <tid>            Select the active thread\n"
            << "  mem <addr|symbol> <n>   Read memory bytes\n"
            << "  patch <addr> <HH...>    Patch runtime memory with hex bytes\n"
            << "  findings                Show exploit findings\n"
            << "  gadgets                 Show ROP gadgets\n"
            << "  patterns                Show vulnerability patterns\n"
            << "  targets                 Show PoC targets\n"
            << "  stackviz                Show exploit-oriented stack visualizations\n"
            << "  scaffold [path]         Print or write the PoC scaffold\n"
            << "  shapes                  Show debugger target shapes\n"
            << "  quit|q                  Terminate the launched process and exit\n";
    };

    std::optional<zara::debugger::RegisterState> registers;
    if (!print_current_snapshot(*debugger, loaded_program, event, registers, error)) {
        std::cout << "Initial snapshot skipped: " << error << '\n';
        error.clear();
    }

    print_help();

    std::set<std::uint64_t> active_breakpoints;
    std::string line;
    while (true) {
        if (!scripted) {
            std::cout << "zara(debug)> " << std::flush;
        }
        if (!std::getline(*input, line)) {
            break;
        }

        line = trim(std::move(line));
        if (line.empty() || line.starts_with('#')) {
            continue;
        }
        if (scripted) {
            std::cout << "zara(debug)> " << line << '\n';
        }

        const auto words = split_words(line);
        const std::string_view command(words.front());

        if (command == "help") {
            print_help();
            continue;
        }

        if (command == "regs") {
            if (!print_current_snapshot(*debugger, std::nullopt, event, registers, error)) {
                std::cout << "Register read failed: " << error << '\n';
                error.clear();
            }
            continue;
        }

        if (command == "snapshot" || command == "where") {
            if (!print_current_snapshot(*debugger, loaded_program, event, registers, error)) {
                std::cout << "Snapshot failed: " << error << '\n';
                error.clear();
            }
            continue;
        }

        if (command == "break" || command == "delete") {
            if (words.size() != 2) {
                std::cout << "Usage: " << command << " <addr|symbol>\n";
                continue;
            }

            const auto address = resolve_debug_address(words[1], loaded_program, registers);
            if (!address.has_value()) {
                std::cout << "Could not resolve address `" << words[1] << "`.\n";
                continue;
            }

            const bool ok =
                command == "break" ? debugger->set_breakpoint(*address, error) : debugger->remove_breakpoint(*address, error);
            if (!ok) {
                std::cout << (command == "break" ? "Breakpoint set failed: " : "Breakpoint removal failed: ") << error
                          << '\n';
                error.clear();
                continue;
            }

            std::cout << (command == "break" ? "Breakpoint set at " : "Breakpoint removed at ")
                      << format_address(*address) << '\n';
            if (command == "break") {
                active_breakpoints.insert(*address);
            } else {
                active_breakpoints.erase(*address);
            }
            continue;
        }

        if (command == "continue" || command == "c" || command == "step" || command == "s") {
            const bool ok =
                (command == "continue" || command == "c") ? debugger->continue_execution(event, error)
                                                          : debugger->single_step(event, error);
            if (!ok) {
                std::cout << (command == "continue" || command == "c" ? "Continue failed: " : "Single-step failed: ")
                          << error << '\n';
                error.clear();
                continue;
            }

            print_stop_event(event);
            if (event.reason == zara::debugger::StopReason::Exited ||
                event.reason == zara::debugger::StopReason::Terminated) {
                return 0;
            }

            if (!print_current_snapshot(*debugger, loaded_program, event, registers, error)) {
                std::cout << "Snapshot failed: " << error << '\n';
                error.clear();
            }
            continue;
        }

        if (command == "threads") {
            std::vector<zara::debugger::ThreadInfo> threads;
            if (!debugger->list_threads(threads, error)) {
                std::cout << "Thread list failed: " << error << '\n';
                error.clear();
                continue;
            }

            std::cout << "Threads\n";
            for (const auto& thread : threads) {
                std::cout << "  " << thread.thread_id
                          << (thread.selected ? " *" : "  ")
                          << "  " << thread.state;
                if (thread.instruction_pointer.has_value()) {
                    std::cout << "  @" << format_address(*thread.instruction_pointer);
                }
                std::cout << '\n';
            }
            continue;
        }

        if (command == "thread") {
            if (words.size() != 2) {
                std::cout << "Usage: thread <tid>\n";
                continue;
            }

            std::uint64_t raw_tid = 0;
            if (!parse_u64(words[1], raw_tid)) {
                std::cout << "Invalid thread id.\n";
                continue;
            }

            if (!debugger->select_thread(static_cast<zara::debugger::ProcessId>(raw_tid), error)) {
                std::cout << "Thread selection failed: " << error << '\n';
                error.clear();
                continue;
            }

            std::cout << "Selected thread " << raw_tid << '\n';
            if (!print_current_snapshot(*debugger, loaded_program, event, registers, error)) {
                std::cout << "Snapshot failed: " << error << '\n';
                error.clear();
            }
            continue;
        }

        if (command == "mem") {
            if (words.size() != 3) {
                std::cout << "Usage: mem <addr|symbol> <count>\n";
                continue;
            }

            const auto address = resolve_debug_address(words[1], loaded_program, registers);
            std::uint64_t count = 0;
            if (!address.has_value() || !parse_u64(words[2], count)) {
                std::cout << "Invalid mem arguments.\n";
                continue;
            }

            std::vector<std::byte> bytes;
            if (!debugger->read_memory(*address, static_cast<std::size_t>(count), bytes, error)) {
                std::cout << "Memory read failed: " << error << '\n';
                error.clear();
                continue;
            }

            std::cout << format_address(*address) << "  " << format_bytes(bytes) << '\n';
            continue;
        }

        if (command == "patch") {
            if (words.size() < 3) {
                std::cout << "Usage: patch <addr|symbol> <HH...>\n";
                continue;
            }

            const auto address = resolve_debug_address(words[1], loaded_program, registers);
            if (!address.has_value()) {
                std::cout << "Could not resolve address `" << words[1] << "`.\n";
                continue;
            }

            std::vector<std::byte> patch_bytes;
            bool parsed_all_bytes = true;
            for (std::size_t index = 2; index < words.size(); ++index) {
                std::byte value{};
                if (!parse_hex_byte(words[index], value)) {
                    parsed_all_bytes = false;
                    break;
                }
                patch_bytes.push_back(value);
            }

            if (!parsed_all_bytes) {
                std::cout << "Patch bytes must be two-digit hex tokens.\n";
                continue;
            }

            if (patch_overlaps_breakpoints(*address, patch_bytes.size(), active_breakpoints)) {
                std::cout << "Memory patch failed: remove any breakpoint that overlaps the patch range first.\n";
                continue;
            }

            if (!debugger->write_memory(*address, patch_bytes, error)) {
                std::cout << "Memory patch failed: " << error << '\n';
                error.clear();
                continue;
            }

            std::cout << "Patched " << patch_bytes.size() << " byte(s) at " << format_address(*address) << '\n';
            continue;
        }

        if (command == "findings") {
            if (!exploit_report.has_value()) {
                std::cout << "Exploit findings are unavailable without static analysis context.\n";
                continue;
            }
            print_security_preview(*exploit_report, 32, 0);
            continue;
        }

        if (command == "gadgets") {
            if (!exploit_report.has_value()) {
                std::cout << "Gadgets are unavailable without static analysis context.\n";
                continue;
            }
            std::cout << "\nROP gadgets\n";
            for (std::size_t index = 0; index < std::min<std::size_t>(exploit_report->gadgets.size(), 32); ++index) {
                const auto& gadget = exploit_report->gadgets[index];
                std::cout << "  " << format_address(gadget.address) << "  " << gadget.sequence << "  ["
                          << gadget.function_name << "]\n";
            }
            continue;
        }

        if (command == "patterns") {
            if (!exploit_report.has_value()) {
                std::cout << "Patterns are unavailable without static analysis context.\n";
                continue;
            }
            print_vulnerability_patterns(*exploit_report, 24);
            continue;
        }

        if (command == "targets") {
            if (!exploit_report.has_value()) {
                std::cout << "PoC targets are unavailable without static analysis context.\n";
                continue;
            }
            print_poc_targets(*exploit_report, 24);
            continue;
        }

        if (command == "stackviz") {
            if (!exploit_report.has_value()) {
                std::cout << "Stack visualizations are unavailable without static analysis context.\n";
                continue;
            }
            print_stack_visualizations(*exploit_report, 12);
            continue;
        }

        if (command == "scaffold") {
            if (!exploit_report.has_value()) {
                std::cout << "PoC scaffold is unavailable without static analysis context.\n";
                continue;
            }

            if (words.size() == 1) {
                std::cout << exploit_report->poc_scaffold;
                continue;
            }

            std::ofstream stream(words[1]);
            if (!stream) {
                std::cout << "Failed to write scaffold to " << words[1] << '\n';
                continue;
            }
            stream << exploit_report->poc_scaffold;
            std::cout << "Wrote scaffold to " << words[1] << '\n';
            continue;
        }

        if (command == "shapes") {
            print_debug_target_shapes();
            continue;
        }

        if (command == "quit" || command == "q") {
            std::string ignore_error;
            (void)debugger->terminate(ignore_error);
            return 0;
        }

        std::cout << "Unknown command `" << command << "`. Use `help`.\n";
    }

    std::string ignore_error;
    (void)debugger->terminate(ignore_error);
    return 0;
}

int run_debug_mode(const std::filesystem::path& binary_path, const std::vector<std::string>& arguments) {
    auto debugger = zara::debugger::DebugSession::create_native();
    if (!debugger->is_supported()) {
        std::cerr << "Debugger backend is unavailable on this platform.\n";
        return 1;
    }

    std::string error;
    zara::debugger::StopEvent event;
    if (!debugger->launch(binary_path, arguments, event, error)) {
        std::cerr << "Launch failed: " << error << '\n';
        return 1;
    }

    std::cout << "Debugger backend: " << debugger->backend_name() << '\n';
    std::cout << "Process: " << debugger->process_id() << '\n';
    print_stop_event(event);

    zara::debugger::RegisterState registers;
    if (debugger->read_registers(registers, error)) {
        print_registers(registers);
    } else {
        std::cout << "Register read skipped: " << error << '\n';
        error.clear();
    }

    auto loaded_program = load_program(binary_path, error);
    const bool loaded_image = loaded_program.has_value();
    zara::loader::BinaryImage image;
    if (loaded_image) {
        image = loaded_program->image;
    }
    error.clear();

    bool breakpoint_set = false;
    std::uint64_t breakpoint_address = 0;
    if (loaded_image && image.entry_point().has_value()) {
        breakpoint_address = *image.entry_point();
        if (debugger->set_breakpoint(breakpoint_address, error)) {
            breakpoint_set = true;
            std::cout << "Breakpoint set at entry " << format_address(breakpoint_address) << '\n';
        } else {
            std::cout << "Breakpoint skipped: " << error << '\n';
            error.clear();
        }
    }

    if (breakpoint_set) {
        for (int attempts = 0; attempts < 8; ++attempts) {
            if (!debugger->continue_execution(event, error)) {
                std::cerr << "Continue failed: " << error << '\n';
                return 1;
            }

            print_stop_event(event);
            if (event.reason == zara::debugger::StopReason::Breakpoint &&
                event.address.has_value() &&
                *event.address == breakpoint_address) {
                break;
            }

            if (event.reason == zara::debugger::StopReason::Exited ||
                event.reason == zara::debugger::StopReason::Terminated) {
                return 0;
            }
        }

        if (debugger->read_registers(registers, error)) {
            print_registers(registers);
        } else {
            std::cout << "Register read skipped: " << error << '\n';
            error.clear();
        }

        if (loaded_program.has_value()) {
            zara::debugger::RuntimeSnapshot snapshot;
            if (zara::debugger::capture_runtime_snapshot(
                    *debugger,
                    loaded_program->image,
                    loaded_program->analysis,
                    event,
                    snapshot,
                    error
                )) {
                print_runtime_snapshot(snapshot);
            } else {
                std::cout << "Runtime correlation skipped: " << error << '\n';
                error.clear();
            }
        }

        std::vector<std::byte> bytes;
        if (debugger->read_memory(breakpoint_address, 16, bytes, error)) {
            std::cout << "Memory @" << format_address(breakpoint_address) << "  " << format_bytes(bytes) << '\n';
        } else {
            std::cout << "Memory read skipped: " << error << '\n';
            error.clear();
        }

        if (debugger->single_step(event, error)) {
            print_stop_event(event);
            if (debugger->read_registers(registers, error)) {
                print_registers(registers);
            } else {
                error.clear();
            }
        } else {
            std::cout << "Single-step skipped: " << error << '\n';
            error.clear();
        }

        if (!debugger->remove_breakpoint(breakpoint_address, error)) {
            std::cout << "Breakpoint removal skipped: " << error << '\n';
            error.clear();
        }
    }

    for (int attempts = 0; attempts < 64; ++attempts) {
        if (!debugger->continue_execution(event, error)) {
            std::cerr << "Continue failed: " << error << '\n';
            return 1;
        }

        print_stop_event(event);
        if (event.reason == zara::debugger::StopReason::Exited ||
            event.reason == zara::debugger::StopReason::Terminated) {
            return 0;
        }
    }

    std::cerr << "Debugger run exceeded stop budget.\n";
    debugger->terminate(error);
    return 1;
}

int run_debug_attach_mode(const zara::debugger::ProcessId process_id) {
    auto debugger = zara::debugger::DebugSession::create_native();
    if (!debugger->is_supported()) {
        std::cerr << "Debugger backend is unavailable on this platform.\n";
        return 1;
    }

    std::string error;
    zara::debugger::StopEvent event;
    if (!debugger->attach(process_id, event, error)) {
        std::cerr << "Attach failed: " << error << '\n';
        return 1;
    }

    std::cout << "Debugger backend: " << debugger->backend_name() << '\n';
    print_stop_event(event);

    zara::debugger::RegisterState registers;
    if (debugger->read_registers(registers, error)) {
        print_registers(registers);
    }

    if (!debugger->detach(error)) {
        std::cerr << "Detach failed: " << error << '\n';
        return 1;
    }

    std::cout << "Detached from process " << process_id << '\n';
    return 0;
}

int run_plugins_marketplace_mode(const int argc, char** argv) {
    if (argc < 4) {
        print_usage();
        return 1;
    }

    zara::plugins::PluginManager manager;
    std::string error;
    const std::string_view action(argv[2]);
    if (action == "list") {
        std::vector<zara::plugins::MarketplacePlugin> plugins;
        if (!manager.discover_marketplace(argv[3], plugins, error)) {
            std::cerr << "Marketplace discovery failed: " << error << '\n';
            return 1;
        }

        std::cout << "Marketplace plugins\n";
        for (const auto& plugin : plugins) {
            std::cout
                << "  "
                << plugin.name
                << "  "
                << plugin.version
                << "  "
                << plugin.package_path
                << '\n';
        }
        return 0;
    }

    if (action == "install") {
        if (argc < 6) {
            print_usage();
            return 1;
        }
        if (!manager.install_from_marketplace(argv[3], argv[4], argv[5], error)) {
            std::cerr << "Marketplace install failed: " << error << '\n';
            return 1;
        }
        std::cout << "Installed " << argv[4] << " into " << argv[5] << '\n';
        return 0;
    }

    print_usage();
    return 1;
}

int run_script_mode(const int argc, char** argv) {
    if (argc < 3) {
        print_usage();
        return 1;
    }

    zara::scripting::PythonEngine engine;
    if (!engine.is_available()) {
        std::cerr << "Embedded Python is unavailable in this build.\n";
        return 1;
    }

    std::string error;
    std::vector<std::string> argv_values;
    if (std::string_view(argv[2]) == "--repl") {
        argv_values.emplace_back("zara-repl");
        for (int index = 3; index < argc; ++index) {
            argv_values.emplace_back(argv[index]);
        }

        if (!engine.set_argv(argv_values, error)) {
            std::cerr << "Failed to set script argv: " << error << '\n';
            return 1;
        }

        if (!engine.run_repl(error)) {
            std::cerr << "REPL execution failed: " << error << '\n';
            return 1;
        }
        return 0;
    }

    if (std::string_view(argv[2]) == "-c") {
        if (argc < 4) {
            print_usage();
            return 1;
        }

        for (int index = 2; index < argc; ++index) {
            argv_values.emplace_back(argv[index]);
        }

        if (!engine.set_argv(argv_values, error)) {
            std::cerr << "Failed to set script argv: " << error << '\n';
            return 1;
        }

        if (!engine.execute_string(argv[3], error)) {
            std::cerr << "Script execution failed: " << error << '\n';
            return 1;
        }
        return 0;
    }

    for (int index = 2; index < argc; ++index) {
        argv_values.emplace_back(argv[index]);
    }

    if (!engine.set_argv(argv_values, error)) {
        std::cerr << "Failed to set script argv: " << error << '\n';
        return 1;
    }

    if (!engine.execute_file(argv[2], error)) {
        std::cerr << "Script execution failed: " << error << '\n';
        return 1;
    }
    return 0;
}

int run_plugins_mode(const std::filesystem::path& plugins_directory, const std::filesystem::path& binary_path) {
    zara::plugins::PluginManager manager;
    if (!manager.is_available()) {
        std::cerr << "Plugin runtime is unavailable in this build.\n";
        return 1;
    }

    std::string error;
    if (!manager.load_all(plugins_directory, error)) {
        std::cerr << "Plugin load failed: " << error << '\n';
        return 1;
    }

    std::cout << "Loaded plugins: " << manager.loaded_plugins().size() << '\n';
    for (const auto& plugin : manager.loaded_plugins()) {
        std::cout << "  " << plugin.name << "  " << plugin.entry_script << '\n';
    }

    if (!manager.run_analysis_hooks(binary_path, error)) {
        std::cerr << "Plugin hook execution failed: " << error << '\n';
        return 1;
    }

    std::cout << "Plugin hooks completed for " << binary_path << '\n';
    return 0;
}

int run_diff_mode(const std::filesystem::path& before_path, const std::filesystem::path& after_path) {
    std::string error;

    zara::loader::BinaryImage before_image;
    if (!zara::loader::BinaryImage::load_from_file(before_path, before_image, error)) {
        std::cerr << "Failed to load before binary: " << error << '\n';
        return 1;
    }

    zara::memory::AddressSpace before_address_space;
    if (!before_address_space.map_image(before_image)) {
        std::cerr << "Failed to map before image into address space.\n";
        return 1;
    }

    zara::loader::BinaryImage after_image;
    if (!zara::loader::BinaryImage::load_from_file(after_path, after_image, error)) {
        std::cerr << "Failed to load after binary: " << error << '\n';
        return 1;
    }

    zara::memory::AddressSpace after_address_space;
    if (!after_address_space.map_image(after_image)) {
        std::cerr << "Failed to map after image into address space.\n";
        return 1;
    }

    const auto before_analysis = zara::analysis::Analyzer::analyze(before_image, before_address_space);
    const auto after_analysis = zara::analysis::Analyzer::analyze(after_image, after_address_space);
    const auto diff = zara::diff::Engine::diff(before_analysis, after_analysis);

    std::cout << "Diff summary\n";
    std::cout << "  unchanged " << diff.unchanged_count << '\n';
    std::cout << "  modified  " << diff.modified_count << '\n';
    std::cout << "  added     " << diff.added_count << '\n';
    std::cout << "  removed   " << diff.removed_count << '\n';

    std::cout << "\nFunction changes\n";
    for (std::size_t index = 0; index < std::min<std::size_t>(diff.changes.size(), 24); ++index) {
        const auto& change = diff.changes[index];
        std::cout << "  " << zara::diff::to_string(change.kind) << "  ";
        if (!change.old_name.empty()) {
            std::cout << change.old_name << "@" << format_address(change.old_entry);
        } else {
            std::cout << "-";
        }
        std::cout << " -> ";
        if (!change.new_name.empty()) {
            std::cout << change.new_name << "@" << format_address(change.new_entry);
        } else {
            std::cout << "-";
        }
        if (change.kind == zara::diff::ChangeKind::Unchanged ||
            change.kind == zara::diff::ChangeKind::Modified) {
            std::cout << "  sim=" << std::fixed << std::setprecision(3) << change.similarity;
        }
        std::cout << '\n';
    }

    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    if (std::string_view(argv[1]) == "ai") {
        if (argc < 3 || argc > 4) {
            print_usage();
            return 1;
        }
        return run_ai_mode(argv[2], argc == 4 ? std::optional<std::filesystem::path>(argv[3]) : std::nullopt, false);
    }

    if (std::string_view(argv[1]) == "ai-model") {
        if (argc < 3 || argc > 4) {
            print_usage();
            return 1;
        }
        return run_ai_mode(argv[2], argc == 4 ? std::optional<std::filesystem::path>(argv[3]) : std::nullopt, true);
    }

    if (std::string_view(argv[1]) == "exploit") {
        if (argc < 3 || argc > 4) {
            print_usage();
            return 1;
        }
        return run_exploit_mode(
            argv[2],
            argc == 4 ? std::optional<std::filesystem::path>(argv[3]) : std::nullopt
        );
    }

    if (std::string_view(argv[1]) == "fuzz-map") {
        if (argc < 4 || argc > 5) {
            print_usage();
            return 1;
        }
        return run_fuzz_mode(argv[2], argv[3], argc == 5 ? std::optional<std::filesystem::path>(argv[4]) : std::nullopt);
    }

    if (std::string_view(argv[1]) == "fuzz-live") {
        if (argc < 5) {
            print_usage();
            return 1;
        }
        std::ostringstream command;
        for (int index = 4; index < argc; ++index) {
            if (index > 4) {
                command << ' ';
            }
            command << argv[index];
        }
        return run_fuzz_live_mode(argv[2], argv[3], command.str());
    }

    if (std::string_view(argv[1]) == "batch") {
        if (argc < 4 || argc > 7) {
            print_usage();
            return 1;
        }

        const std::size_t concurrency = argc >= 5 ? static_cast<std::size_t>(std::stoull(argv[4])) : 0;
        const std::size_t shard_count = argc >= 6 ? static_cast<std::size_t>(std::stoull(argv[5])) : 1;
        const std::size_t shard_index = argc >= 7 ? static_cast<std::size_t>(std::stoull(argv[6])) : 0;
        return run_batch_mode(argv[2], argv[3], concurrency, shard_count, shard_index);
    }

    if (std::string_view(argv[1]) == "batch-controller") {
        if (argc != 6 && argc != 7) {
            print_usage();
            return 1;
        }
        return run_batch_controller_mode(
            argv[2],
            argv[3],
            static_cast<std::uint16_t>(std::stoul(argv[4])),
            static_cast<std::size_t>(std::stoull(argv[5])),
            argc == 7 ? static_cast<std::size_t>(std::stoull(argv[6])) : 0
        );
    }

    if (std::string_view(argv[1]) == "batch-worker") {
        if (argc != 5) {
            print_usage();
            return 1;
        }
        return run_batch_worker_mode(argv[2], static_cast<std::uint16_t>(std::stoul(argv[3])), argv[4]);
    }

    if (std::string_view(argv[1]) == "debug-targets") {
        if (argc != 2) {
            print_usage();
            return 1;
        }
        return run_debug_targets_mode();
    }

    if (std::string_view(argv[1]) == "debug") {
        if (argc < 3) {
            print_usage();
            return 1;
        }

        std::vector<std::string> arguments;
        for (int index = 3; index < argc; ++index) {
            arguments.emplace_back(argv[index]);
        }
        return run_debug_mode(argv[2], arguments);
    }

    if (std::string_view(argv[1]) == "debug-shell") {
        if (argc < 3) {
            print_usage();
            return 1;
        }

        std::optional<std::filesystem::path> script_path;
        std::vector<std::string> arguments;
        for (int index = 3; index < argc; ++index) {
            if (std::string_view(argv[index]) == "--script") {
                if (index + 1 >= argc) {
                    print_usage();
                    return 1;
                }
                script_path = argv[index + 1];
                ++index;
                continue;
            }
            arguments.emplace_back(argv[index]);
        }
        return run_debug_shell_mode(argv[2], arguments, script_path);
    }

    if (std::string_view(argv[1]) == "debug-attach") {
        if (argc != 3) {
            print_usage();
            return 1;
        }

        return run_debug_attach_mode(static_cast<zara::debugger::ProcessId>(std::stoi(argv[2])));
    }

    if (std::string_view(argv[1]) == "script") {
        return run_script_mode(argc, argv);
    }

    if (std::string_view(argv[1]) == "plugins") {
        if (argc != 4) {
            print_usage();
            return 1;
        }
        return run_plugins_mode(argv[2], argv[3]);
    }

    if (std::string_view(argv[1]) == "plugins-marketplace") {
        return run_plugins_marketplace_mode(argc, argv);
    }

    if (std::string_view(argv[1]) == "diff") {
        if (argc != 4) {
            print_usage();
            return 1;
        }
        return run_diff_mode(argv[2], argv[3]);
    }

    const std::filesystem::path binary_path = argv[1];
    const std::filesystem::path project_path = argc >= 3 ? argv[2] : "zara_project.sqlite";
    return run_analysis_mode(binary_path, project_path);
}
