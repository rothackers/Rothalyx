#include "zara/scripting/python_engine.hpp"

#if defined(ZARA_HAS_PYTHON)
#include <Python.h>
#endif

#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "zara/ai/assistant.hpp"
#include "zara/analysis/program_analysis.hpp"
#include "zara/debugger/session.hpp"
#include "zara/diff/engine.hpp"
#include "zara/distributed/batch_runner.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"
#include "zara/security/workflow.hpp"

namespace zara::scripting {

namespace {

#if defined(ZARA_HAS_PYTHON)
struct CachedAnalysis {
    loader::BinaryImage image;
    analysis::ProgramAnalysis program;
};

std::unordered_map<std::string, CachedAnalysis>& analysis_cache() {
    static std::unordered_map<std::string, CachedAnalysis> cache;
    return cache;
}

std::shared_mutex& analysis_cache_mutex() {
    static std::shared_mutex mutex;
    return mutex;
}

std::recursive_mutex& python_runtime_mutex() {
    static std::recursive_mutex mutex;
    return mutex;
}

std::size_t& python_runtime_refcount() {
    static std::size_t refcount = 0;
    return refcount;
}

class PythonGilGuard {
public:
    PythonGilGuard() {
        state_ = PyGILState_Ensure();
    }

    ~PythonGilGuard() {
        PyGILState_Release(state_);
    }

private:
    PyGILState_STATE state_{};
};

std::string fetch_python_error() {
    if (!PyErr_Occurred()) {
        return "Python execution failed.";
    }

    PyObject* exception_type = nullptr;
    PyObject* exception_value = nullptr;
    PyObject* exception_traceback = nullptr;
    PyErr_Fetch(&exception_type, &exception_value, &exception_traceback);
    PyErr_NormalizeException(&exception_type, &exception_value, &exception_traceback);

    std::string message = "Python execution failed.";
    if (exception_value != nullptr) {
        PyObject* value_string = PyObject_Str(exception_value);
        if (value_string != nullptr) {
            const char* utf8 = PyUnicode_AsUTF8(value_string);
            if (utf8 != nullptr) {
                message = utf8;
            }
            Py_DECREF(value_string);
        }
    }

    Py_XDECREF(exception_type);
    Py_XDECREF(exception_value);
    Py_XDECREF(exception_traceback);
    return message;
}

bool load_analysis_bundle(const std::filesystem::path& path, CachedAnalysis*& out_bundle, std::string& out_error) {
    out_error.clear();

    const std::string cache_key = std::filesystem::absolute(path).string();
    {
        std::shared_lock lock(analysis_cache_mutex());
        const auto cache_it = analysis_cache().find(cache_key);
        if (cache_it != analysis_cache().end()) {
            out_bundle = &cache_it->second;
            return true;
        }
    }

    loader::BinaryImage image;
    if (!loader::BinaryImage::load_from_file(path, image, out_error)) {
        return false;
    }

    memory::AddressSpace address_space;
    if (!address_space.map_image(image)) {
        out_error = "Failed to map image into address space.";
        return false;
    }

    analysis::ProgramAnalysis program = analysis::Analyzer::analyze(image, address_space);
    CachedAnalysis bundle{
        .image = std::move(image),
        .program = std::move(program),
    };
    {
        std::unique_lock lock(analysis_cache_mutex());
        const auto cache_it = analysis_cache().find(cache_key);
        if (cache_it != analysis_cache().end()) {
            out_bundle = &cache_it->second;
            return true;
        }
        auto [inserted_it, _] = analysis_cache().emplace(cache_key, std::move(bundle));
        out_bundle = &inserted_it->second;
    }
    return true;
}

const analysis::DiscoveredFunction* find_function(
    const CachedAnalysis& bundle,
    const std::optional<std::uint64_t> entry_address
) {
    if (entry_address.has_value()) {
        for (const auto& function : bundle.program.functions) {
            if (function.entry_address == *entry_address) {
                return &function;
            }
        }
        return nullptr;
    }

    if (bundle.program.functions.empty()) {
        return nullptr;
    }
    return &bundle.program.functions.front();
}

bool set_dict_item(PyObject* dict, const char* key, PyObject* value) {
    if (value == nullptr) {
        return false;
    }
    const int result = PyDict_SetItemString(dict, key, value);
    Py_DECREF(value);
    return result == 0;
}

bool append_list_item(PyObject* list, PyObject* value) {
    if (value == nullptr) {
        return false;
    }
    const int result = PyList_Append(list, value);
    Py_DECREF(value);
    return result == 0;
}

PyObject* py_none() {
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject* py_nullable_address(const std::optional<std::uint64_t> value) {
    if (!value.has_value()) {
        return py_none();
    }
    return PyLong_FromUnsignedLongLong(*value);
}

std::string_view instruction_kind_to_string(const disasm::InstructionKind kind) noexcept {
    switch (kind) {
    case disasm::InstructionKind::DataByte:
        return "data_byte";
    case disasm::InstructionKind::Instruction:
        return "instruction";
    case disasm::InstructionKind::Call:
        return "call";
    case disasm::InstructionKind::Jump:
        return "jump";
    case disasm::InstructionKind::ConditionalJump:
        return "conditional_jump";
    case disasm::InstructionKind::Return:
        return "return";
    case disasm::InstructionKind::Interrupt:
        return "interrupt";
    case disasm::InstructionKind::Unknown:
    default:
        return "unknown";
    }
}

PyObject* build_summary_dict(const CachedAnalysis& bundle) {
    PyObject* summary = PyDict_New();
    if (summary == nullptr) {
        return nullptr;
    }

    if (!set_dict_item(summary, "path", PyUnicode_FromString(bundle.image.source_path().string().c_str())) ||
        !set_dict_item(summary, "format", PyUnicode_FromString(loader::to_string(bundle.image.format()).data())) ||
        !set_dict_item(summary, "architecture", PyUnicode_FromString(loader::to_string(bundle.image.architecture()).data())) ||
        !set_dict_item(summary, "base_address", PyLong_FromUnsignedLongLong(bundle.image.base_address())) ||
        !set_dict_item(summary, "entry_point", py_nullable_address(bundle.image.entry_point())) ||
        !set_dict_item(summary, "function_count", PyLong_FromSize_t(bundle.program.functions.size())) ||
        !set_dict_item(summary, "call_count", PyLong_FromSize_t(bundle.program.call_graph.size())) ||
        !set_dict_item(summary, "xref_count", PyLong_FromSize_t(bundle.program.xrefs.size())) ||
        !set_dict_item(summary, "string_count", PyLong_FromSize_t(bundle.program.strings.size())) ||
        !set_dict_item(summary, "import_count", PyLong_FromSize_t(bundle.image.imports().size())) ||
        !set_dict_item(summary, "export_count", PyLong_FromSize_t(bundle.image.exports().size()))) {
        Py_DECREF(summary);
        return nullptr;
    }

    return summary;
}

PyObject* build_function_summary_dict(const analysis::DiscoveredFunction& function);
PyObject* build_ir_blocks_list(const ir::Function& function);
PyObject* build_ssa_blocks_list(const ssa::Function& function);
PyObject* build_runtime_snapshot_dict(const debugger::RuntimeSnapshot& snapshot);

PyObject* build_batch_job_dict(const distributed::BatchJobResult& job) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    const bool ok =
        set_dict_item(item, "binary_path", PyUnicode_FromString(job.binary_path.string().c_str())) &&
        set_dict_item(item, "project_db", PyUnicode_FromString(job.project_db_path.string().c_str())) &&
        set_dict_item(item, "status", PyUnicode_FromString(job.success ? "ok" : "error")) &&
        set_dict_item(item, "functions", PyLong_FromSize_t(job.function_count)) &&
        set_dict_item(item, "calls", PyLong_FromSize_t(job.call_count)) &&
        set_dict_item(item, "imports", PyLong_FromSize_t(job.import_count)) &&
        set_dict_item(item, "exports", PyLong_FromSize_t(job.export_count)) &&
        set_dict_item(item, "xrefs", PyLong_FromSize_t(job.xref_count)) &&
        set_dict_item(item, "strings", PyLong_FromSize_t(job.string_count)) &&
        set_dict_item(item, "error", PyUnicode_FromString(job.error.c_str()));
    if (!ok) {
        Py_DECREF(item);
        return nullptr;
    }

    return item;
}

PyObject* build_batch_worker_dict(const distributed::BatchWorkerSummary& worker) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    const bool ok =
        set_dict_item(item, "worker_id", PyUnicode_FromString(worker.worker_id.c_str())) &&
        set_dict_item(item, "host", PyUnicode_FromString(worker.host.c_str())) &&
        set_dict_item(item, "platform", PyUnicode_FromString(worker.platform.c_str())) &&
        set_dict_item(item, "assigned_jobs", PyLong_FromSize_t(worker.assigned_jobs)) &&
        set_dict_item(item, "completed_jobs", PyLong_FromSize_t(worker.completed_jobs)) &&
        set_dict_item(item, "success_count", PyLong_FromSize_t(worker.success_count)) &&
        set_dict_item(item, "failure_count", PyLong_FromSize_t(worker.failure_count)) &&
        set_dict_item(item, "status", PyUnicode_FromString(worker.status.c_str())) &&
        set_dict_item(item, "last_event", PyUnicode_FromString(worker.last_event.c_str())) &&
        set_dict_item(item, "last_error", PyUnicode_FromString(worker.last_error.c_str()));
    if (!ok) {
        Py_DECREF(item);
        return nullptr;
    }

    return item;
}

PyObject* build_batch_event_dict(const distributed::BatchEvent& event) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    const bool ok =
        set_dict_item(item, "sequence", PyLong_FromSize_t(event.sequence)) &&
        set_dict_item(item, "worker_id", PyUnicode_FromString(event.worker_id.c_str())) &&
        set_dict_item(item, "kind", PyUnicode_FromString(event.kind.c_str())) &&
        set_dict_item(item, "detail", PyUnicode_FromString(event.detail.c_str()));
    if (!ok) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_batch_result_dict(const distributed::BatchResult& result) {
    PyObject* item = PyDict_New();
    PyObject* totals = PyDict_New();
    PyObject* jobs = PyList_New(0);
    PyObject* workers = PyList_New(0);
    PyObject* events = PyList_New(0);
    if (item == nullptr || totals == nullptr || jobs == nullptr || workers == nullptr || events == nullptr) {
        Py_XDECREF(item);
        Py_XDECREF(totals);
        Py_XDECREF(jobs);
        Py_XDECREF(workers);
        Py_XDECREF(events);
        return nullptr;
    }

    for (const auto& job : result.jobs) {
        if (!append_list_item(jobs, build_batch_job_dict(job))) {
            Py_DECREF(item);
            Py_DECREF(totals);
            Py_DECREF(jobs);
            Py_DECREF(workers);
            Py_DECREF(events);
            return nullptr;
        }
    }

    for (const auto& worker : result.workers) {
        if (!append_list_item(workers, build_batch_worker_dict(worker))) {
            Py_DECREF(item);
            Py_DECREF(totals);
            Py_DECREF(jobs);
            Py_DECREF(workers);
            Py_DECREF(events);
            return nullptr;
        }
    }

    for (const auto& event : result.events) {
        if (!append_list_item(events, build_batch_event_dict(event))) {
            Py_DECREF(item);
            Py_DECREF(totals);
            Py_DECREF(jobs);
            Py_DECREF(workers);
            Py_DECREF(events);
            return nullptr;
        }
    }

    if (!set_dict_item(totals, "functions", PyLong_FromSize_t(result.total_function_count)) ||
        !set_dict_item(totals, "calls", PyLong_FromSize_t(result.total_call_count)) ||
        !set_dict_item(totals, "imports", PyLong_FromSize_t(result.total_import_count)) ||
        !set_dict_item(totals, "exports", PyLong_FromSize_t(result.total_export_count)) ||
        !set_dict_item(totals, "xrefs", PyLong_FromSize_t(result.total_xref_count)) ||
        !set_dict_item(totals, "strings", PyLong_FromSize_t(result.total_string_count))) {
        Py_DECREF(item);
        Py_DECREF(totals);
        Py_DECREF(jobs);
        Py_DECREF(workers);
        Py_DECREF(events);
        return nullptr;
    }

    const bool ok =
        set_dict_item(item, "remote", PyBool_FromLong(result.remote ? 1 : 0)) &&
        set_dict_item(item, "protocol_version", PyUnicode_FromString(result.protocol_version.c_str())) &&
        set_dict_item(item, "worker_slots", PyLong_FromSize_t(result.worker_slots)) &&
        set_dict_item(item, "success_count", PyLong_FromSize_t(result.success_count)) &&
        set_dict_item(item, "failure_count", PyLong_FromSize_t(result.failure_count)) &&
        set_dict_item(item, "totals", totals) &&
        set_dict_item(item, "workers", workers) &&
        set_dict_item(item, "events", events) &&
        set_dict_item(item, "jobs", jobs);
    if (!ok) {
        Py_DECREF(item);
        return nullptr;
    }

    return item;
}

bool parse_input_paths(
    PyObject* value,
    const bool recursive,
    std::vector<std::filesystem::path>& out_inputs,
    std::string& out_error
) {
    out_inputs.clear();
    out_error.clear();

    if (value == nullptr) {
        out_error = "inputs is required.";
        return false;
    }

    if (PyUnicode_Check(value)) {
        const char* raw_path = PyUnicode_AsUTF8(value);
        if (raw_path == nullptr) {
            out_error = "inputs path must be UTF-8.";
            return false;
        }

        const std::filesystem::path input_path = raw_path;
        if (std::filesystem::is_directory(input_path)) {
            out_inputs = distributed::BatchRunner::discover_inputs(input_path, recursive);
        } else {
            out_inputs.push_back(input_path);
        }
        return true;
    }

    if (!PySequence_Check(value)) {
        out_error = "inputs must be a path string or a sequence of path strings.";
        return false;
    }

    const Py_ssize_t size = PySequence_Size(value);
    if (size < 0) {
        out_error = fetch_python_error();
        return false;
    }

    out_inputs.reserve(static_cast<std::size_t>(size));
    for (Py_ssize_t index = 0; index < size; ++index) {
        PyObject* item = PySequence_GetItem(value, index);
        if (item == nullptr) {
            out_error = fetch_python_error();
            return false;
        }

        if (!PyUnicode_Check(item)) {
            Py_DECREF(item);
            out_error = "inputs sequence must contain only path strings.";
            return false;
        }

        const char* raw_path = PyUnicode_AsUTF8(item);
        if (raw_path == nullptr) {
            Py_DECREF(item);
            out_error = "inputs path must be UTF-8.";
            return false;
        }

        out_inputs.emplace_back(raw_path);
        Py_DECREF(item);
    }

    return true;
}

bool write_batch_reports(const std::filesystem::path& output_directory, const distributed::BatchResult& result, std::string& out_error) {
    const auto manifest_path = output_directory / "manifest.tsv";
    const auto summary_path = output_directory / "summary.json";
    return distributed::BatchRunner::write_manifest(manifest_path, result, out_error) &&
           distributed::BatchRunner::write_summary(summary_path, result, out_error);
}

PyObject* build_instruction_dict(const disasm::Instruction& instruction) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    PyObject* data_references = PyList_New(0);
    if (data_references == nullptr) {
        Py_DECREF(item);
        return nullptr;
    }
    for (const auto reference : instruction.data_references) {
        if (!append_list_item(data_references, PyLong_FromUnsignedLongLong(reference))) {
            Py_DECREF(data_references);
            Py_DECREF(item);
            return nullptr;
        }
    }

    const bool ok =
        set_dict_item(item, "address", PyLong_FromUnsignedLongLong(instruction.address)) &&
        set_dict_item(item, "size", PyLong_FromUnsignedLong(instruction.size)) &&
        set_dict_item(item, "kind", PyUnicode_FromString(instruction_kind_to_string(instruction.kind).data())) &&
        set_dict_item(item, "mnemonic", PyUnicode_FromString(instruction.mnemonic.c_str())) &&
        set_dict_item(item, "operands", PyUnicode_FromString(instruction.operands.c_str())) &&
        set_dict_item(item, "control_flow_target", py_nullable_address(instruction.control_flow_target)) &&
        set_dict_item(item, "data_references", data_references);

    if (!ok) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_function_overview_dict(const analysis::DiscoveredFunction& function) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    std::size_t instruction_count = 0;
    for (const auto& block : function.graph.blocks()) {
        instruction_count += block.instructions.size();
    }

    if (!set_dict_item(item, "name", PyUnicode_FromString(function.name.c_str())) ||
        !set_dict_item(item, "entry", PyLong_FromUnsignedLongLong(function.entry_address)) ||
        !set_dict_item(item, "section", PyUnicode_FromString(function.section_name.c_str())) ||
        !set_dict_item(item, "blocks", PyLong_FromSize_t(function.graph.blocks().size())) ||
        !set_dict_item(item, "instructions", PyLong_FromSize_t(instruction_count))) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_function_detail_dict(const CachedAnalysis& bundle, const analysis::DiscoveredFunction& function) {
    PyObject* item = build_function_overview_dict(function);
    if (item == nullptr) {
        return nullptr;
    }

    PyObject* basic_blocks = PyList_New(0);
    PyObject* instructions = PyList_New(0);
    PyObject* outgoing_calls = PyList_New(0);
    PyObject* xrefs = PyList_New(0);
    PyObject* variables = PyList_New(0);
    if (basic_blocks == nullptr || instructions == nullptr || outgoing_calls == nullptr || xrefs == nullptr || variables == nullptr) {
        Py_XDECREF(basic_blocks);
        Py_XDECREF(instructions);
        Py_XDECREF(outgoing_calls);
        Py_XDECREF(xrefs);
        Py_XDECREF(variables);
        Py_DECREF(item);
        return nullptr;
    }

    std::unordered_set<std::uint64_t> instruction_addresses;
    for (const auto& block : function.graph.blocks()) {
        PyObject* block_item = PyDict_New();
        if (block_item == nullptr) {
            Py_DECREF(basic_blocks);
            Py_DECREF(instructions);
            Py_DECREF(outgoing_calls);
            Py_DECREF(xrefs);
            Py_DECREF(variables);
            Py_DECREF(item);
            return nullptr;
        }

        PyObject* successors = PyList_New(0);
        if (successors == nullptr) {
            Py_DECREF(block_item);
            Py_DECREF(basic_blocks);
            Py_DECREF(instructions);
            Py_DECREF(outgoing_calls);
            Py_DECREF(xrefs);
            Py_DECREF(variables);
            Py_DECREF(item);
            return nullptr;
        }
        for (const auto successor : block.successors) {
            if (!append_list_item(successors, PyLong_FromUnsignedLongLong(successor))) {
                Py_DECREF(successors);
                Py_DECREF(block_item);
                Py_DECREF(basic_blocks);
                Py_DECREF(instructions);
                Py_DECREF(outgoing_calls);
                Py_DECREF(xrefs);
                Py_DECREF(variables);
                Py_DECREF(item);
                return nullptr;
            }
        }

        if (!set_dict_item(block_item, "start", PyLong_FromUnsignedLongLong(block.start_address)) ||
            !set_dict_item(block_item, "end", PyLong_FromUnsignedLongLong(block.end_address)) ||
            !set_dict_item(block_item, "successors", successors)) {
            Py_DECREF(block_item);
            Py_DECREF(basic_blocks);
            Py_DECREF(instructions);
            Py_DECREF(outgoing_calls);
            Py_DECREF(xrefs);
            Py_DECREF(variables);
            Py_DECREF(item);
            return nullptr;
        }

        if (!append_list_item(basic_blocks, block_item)) {
            Py_DECREF(basic_blocks);
            Py_DECREF(instructions);
            Py_DECREF(outgoing_calls);
            Py_DECREF(xrefs);
            Py_DECREF(variables);
            Py_DECREF(item);
            return nullptr;
        }

        for (const auto& instruction : block.instructions) {
            instruction_addresses.insert(instruction.address);
            if (!append_list_item(instructions, build_instruction_dict(instruction))) {
                Py_DECREF(basic_blocks);
                Py_DECREF(instructions);
                Py_DECREF(outgoing_calls);
                Py_DECREF(xrefs);
                Py_DECREF(variables);
                Py_DECREF(item);
                return nullptr;
            }
        }
    }

    for (const auto& edge : bundle.program.call_graph) {
        if (edge.caller_entry != function.entry_address) {
            continue;
        }

        PyObject* edge_item = PyDict_New();
        if (edge_item == nullptr) {
            Py_DECREF(basic_blocks);
            Py_DECREF(instructions);
            Py_DECREF(outgoing_calls);
            Py_DECREF(xrefs);
            Py_DECREF(variables);
            Py_DECREF(item);
            return nullptr;
        }

        if (!set_dict_item(edge_item, "call_site", PyLong_FromUnsignedLongLong(edge.call_site)) ||
            !set_dict_item(edge_item, "callee_entry", py_nullable_address(edge.callee_entry)) ||
            !set_dict_item(edge_item, "callee_name", PyUnicode_FromString(edge.callee_name.c_str())) ||
            !set_dict_item(edge_item, "is_import", PyBool_FromLong(edge.is_import ? 1 : 0)) ||
            !append_list_item(outgoing_calls, edge_item)) {
            Py_DECREF(basic_blocks);
            Py_DECREF(instructions);
            Py_DECREF(outgoing_calls);
            Py_DECREF(xrefs);
            Py_DECREF(variables);
            Py_DECREF(item);
            return nullptr;
        }
    }

    for (const auto& xref : bundle.program.xrefs) {
        if (!instruction_addresses.contains(xref.from_address)) {
            continue;
        }

        PyObject* xref_item = PyDict_New();
        if (xref_item == nullptr) {
            Py_DECREF(basic_blocks);
            Py_DECREF(instructions);
            Py_DECREF(outgoing_calls);
            Py_DECREF(xrefs);
            Py_DECREF(variables);
            Py_DECREF(item);
            return nullptr;
        }

        if (!set_dict_item(xref_item, "kind", PyUnicode_FromString(zara::xrefs::to_string(xref.kind).data())) ||
            !set_dict_item(xref_item, "from", PyLong_FromUnsignedLongLong(xref.from_address)) ||
            !set_dict_item(xref_item, "to", PyLong_FromUnsignedLongLong(xref.to_address)) ||
            !set_dict_item(xref_item, "label", PyUnicode_FromString(xref.label.c_str())) ||
            !append_list_item(xrefs, xref_item)) {
            Py_DECREF(basic_blocks);
            Py_DECREF(instructions);
            Py_DECREF(outgoing_calls);
            Py_DECREF(xrefs);
            Py_DECREF(variables);
            Py_DECREF(item);
            return nullptr;
        }
    }

    for (const auto& variable : function.recovered_types.variables) {
        PyObject* variable_item = PyDict_New();
        if (variable_item == nullptr) {
            Py_DECREF(basic_blocks);
            Py_DECREF(instructions);
            Py_DECREF(outgoing_calls);
            Py_DECREF(xrefs);
            Py_DECREF(variables);
            Py_DECREF(item);
            return nullptr;
        }

        if (!set_dict_item(variable_item, "name", PyUnicode_FromString(variable.name.c_str())) ||
            !set_dict_item(variable_item, "type", PyUnicode_FromString(ir::to_string(variable.type).data())) ||
            !append_list_item(variables, variable_item)) {
            Py_DECREF(basic_blocks);
            Py_DECREF(instructions);
            Py_DECREF(outgoing_calls);
            Py_DECREF(xrefs);
            Py_DECREF(variables);
            Py_DECREF(item);
            return nullptr;
        }
    }

    PyObject* summary = build_function_summary_dict(function);
    PyObject* ir_blocks = build_ir_blocks_list(function.lifted_ir);
    PyObject* ssa_blocks = build_ssa_blocks_list(function.ssa_form);
    if (summary == nullptr || ir_blocks == nullptr || ssa_blocks == nullptr) {
        Py_XDECREF(summary);
        Py_XDECREF(ir_blocks);
        Py_XDECREF(ssa_blocks);
        Py_DECREF(item);
        return nullptr;
    }

    if (!set_dict_item(item, "pseudocode", PyUnicode_FromString(function.decompiled.pseudocode.c_str())) ||
        !set_dict_item(item, "basic_blocks", basic_blocks) ||
        !set_dict_item(item, "instructions_detail", instructions) ||
        !set_dict_item(item, "outgoing_calls", outgoing_calls) ||
        !set_dict_item(item, "xrefs", xrefs) ||
        !set_dict_item(item, "variables", variables) ||
        !set_dict_item(item, "summary", summary) ||
        !set_dict_item(item, "ir_blocks", ir_blocks) ||
        !set_dict_item(item, "ssa_blocks", ssa_blocks)) {
        Py_DECREF(item);
        return nullptr;
    }

    return item;
}

PyObject* build_constant_dict(const analysis::ConstantValue& constant) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }
    if (!set_dict_item(item, "name", PyUnicode_FromString(constant.name.c_str())) ||
        !set_dict_item(item, "value", PyLong_FromLongLong(constant.value))) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_local_dict(const analysis::LocalVariable& local) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }
    if (!set_dict_item(item, "name", PyUnicode_FromString(local.name.c_str())) ||
        !set_dict_item(item, "stack_offset", PyLong_FromLongLong(local.stack_offset)) ||
        !set_dict_item(item, "size", PyLong_FromUnsignedLongLong(local.size)) ||
        !set_dict_item(item, "type", PyUnicode_FromString(ir::to_string(local.type).data()))) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_argument_dict(const analysis::ArgumentInfo& argument) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }
    if (!set_dict_item(item, "name", PyUnicode_FromString(argument.name.c_str())) ||
        !set_dict_item(item, "location", PyUnicode_FromString(argument.location.c_str())) ||
        !set_dict_item(item, "type", PyUnicode_FromString(ir::to_string(argument.type).data()))) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_indirect_resolution_dict(const analysis::IndirectResolution& resolution) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }
    if (!set_dict_item(item, "instruction_address", PyLong_FromUnsignedLongLong(resolution.instruction_address)) ||
        !set_dict_item(item, "resolved_target", py_nullable_address(resolution.resolved_target)) ||
        !set_dict_item(item, "label", PyUnicode_FromString(resolution.label.c_str()))) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_loop_dict(const cfg::LoopInfo& loop) {
    PyObject* item = PyDict_New();
    PyObject* latches = PyList_New(0);
    PyObject* body = PyList_New(0);
    if (item == nullptr || latches == nullptr || body == nullptr) {
        Py_XDECREF(item);
        Py_XDECREF(latches);
        Py_XDECREF(body);
        return nullptr;
    }

    for (const auto address : loop.latch_blocks) {
        if (!append_list_item(latches, PyLong_FromUnsignedLongLong(address))) {
            Py_DECREF(item);
            Py_DECREF(latches);
            Py_DECREF(body);
            return nullptr;
        }
    }
    for (const auto address : loop.body_blocks) {
        if (!append_list_item(body, PyLong_FromUnsignedLongLong(address))) {
            Py_DECREF(item);
            Py_DECREF(latches);
            Py_DECREF(body);
            return nullptr;
        }
    }

    if (!set_dict_item(item, "header", PyLong_FromUnsignedLongLong(loop.header_address)) ||
        !set_dict_item(item, "latches", latches) ||
        !set_dict_item(item, "body", body)) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_switch_dict(const cfg::SwitchInfo& switch_info) {
    PyObject* item = PyDict_New();
    PyObject* cases = PyList_New(0);
    if (item == nullptr || cases == nullptr) {
        Py_XDECREF(item);
        Py_XDECREF(cases);
        return nullptr;
    }

    for (const auto& switch_case : switch_info.cases) {
        PyObject* case_item = PyDict_New();
        if (case_item == nullptr) {
            Py_DECREF(item);
            Py_DECREF(cases);
            return nullptr;
        }
        if (!set_dict_item(case_item, "value", PyLong_FromLongLong(switch_case.value)) ||
            !set_dict_item(case_item, "target", PyLong_FromUnsignedLongLong(switch_case.target)) ||
            !append_list_item(cases, case_item)) {
            Py_DECREF(item);
            Py_DECREF(cases);
            return nullptr;
        }
    }

    if (!set_dict_item(item, "dispatch_block", PyLong_FromUnsignedLongLong(switch_info.dispatch_block)) ||
        !set_dict_item(item, "jump_address", PyLong_FromUnsignedLongLong(switch_info.jump_address)) ||
        !set_dict_item(item, "table_address", PyLong_FromUnsignedLongLong(switch_info.table_address)) ||
        !set_dict_item(item, "default_target", py_nullable_address(switch_info.default_target)) ||
        !set_dict_item(item, "cases", cases)) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_ir_instruction_dict(const ir::Instruction& instruction) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }
    if (!set_dict_item(item, "address", PyLong_FromUnsignedLongLong(instruction.address)) ||
        !set_dict_item(item, "kind", PyUnicode_FromString(ir::to_string(instruction.kind).data())) ||
        !set_dict_item(item, "text", PyUnicode_FromString(ir::format_instruction(instruction).c_str()))) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_ir_blocks_list(const ir::Function& function) {
    PyObject* blocks = PyList_New(0);
    if (blocks == nullptr) {
        return nullptr;
    }

    for (const auto& block : function.blocks) {
        PyObject* block_item = PyDict_New();
        PyObject* instructions = PyList_New(0);
        PyObject* successors = PyList_New(0);
        if (block_item == nullptr || instructions == nullptr || successors == nullptr) {
            Py_XDECREF(block_item);
            Py_XDECREF(instructions);
            Py_XDECREF(successors);
            Py_DECREF(blocks);
            return nullptr;
        }

        for (const auto successor : block.successors) {
            if (!append_list_item(successors, PyLong_FromUnsignedLongLong(successor))) {
                Py_DECREF(block_item);
                Py_DECREF(instructions);
                Py_DECREF(successors);
                Py_DECREF(blocks);
                return nullptr;
            }
        }
        for (const auto& instruction : block.instructions) {
            if (!append_list_item(instructions, build_ir_instruction_dict(instruction))) {
                Py_DECREF(block_item);
                Py_DECREF(instructions);
                Py_DECREF(successors);
                Py_DECREF(blocks);
                return nullptr;
            }
        }

        if (!set_dict_item(block_item, "start", PyLong_FromUnsignedLongLong(block.start_address)) ||
            !set_dict_item(block_item, "successors", successors) ||
            !set_dict_item(block_item, "instructions", instructions) ||
            !append_list_item(blocks, block_item)) {
            Py_DECREF(blocks);
            return nullptr;
        }
    }

    return blocks;
}

PyObject* build_ssa_blocks_list(const ssa::Function& function) {
    PyObject* blocks = PyList_New(0);
    if (blocks == nullptr) {
        return nullptr;
    }

    for (const auto& block : function.blocks) {
        PyObject* block_item = PyDict_New();
        PyObject* phis = PyList_New(0);
        PyObject* instructions = PyList_New(0);
        PyObject* predecessors = PyList_New(0);
        PyObject* successors = PyList_New(0);
        if (block_item == nullptr || phis == nullptr || instructions == nullptr || predecessors == nullptr || successors == nullptr) {
            Py_XDECREF(block_item);
            Py_XDECREF(phis);
            Py_XDECREF(instructions);
            Py_XDECREF(predecessors);
            Py_XDECREF(successors);
            Py_DECREF(blocks);
            return nullptr;
        }

        for (const auto predecessor : block.predecessors) {
            if (!append_list_item(predecessors, PyLong_FromUnsignedLongLong(predecessor))) {
                Py_DECREF(blocks);
                return nullptr;
            }
        }
        for (const auto successor : block.successors) {
            if (!append_list_item(successors, PyLong_FromUnsignedLongLong(successor))) {
                Py_DECREF(blocks);
                return nullptr;
            }
        }
        for (const auto& phi : block.phi_nodes) {
            if (!append_list_item(phis, PyUnicode_FromString(ssa::format_phi(phi).c_str()))) {
                Py_DECREF(blocks);
                return nullptr;
            }
        }
        for (const auto& instruction : block.instructions) {
            if (!append_list_item(instructions, build_ir_instruction_dict(instruction))) {
                Py_DECREF(blocks);
                return nullptr;
            }
        }

        if (!set_dict_item(block_item, "start", PyLong_FromUnsignedLongLong(block.start_address)) ||
            !set_dict_item(block_item, "phis", phis) ||
            !set_dict_item(block_item, "instructions", instructions) ||
            !set_dict_item(block_item, "predecessors", predecessors) ||
            !set_dict_item(block_item, "successors", successors) ||
            !append_list_item(blocks, block_item)) {
            Py_DECREF(blocks);
            return nullptr;
        }
    }

    return blocks;
}

PyObject* build_function_summary_dict(const analysis::DiscoveredFunction& function) {
    PyObject* item = PyDict_New();
    PyObject* constants = PyList_New(0);
    PyObject* stack_states = PyList_New(0);
    PyObject* locals = PyList_New(0);
    PyObject* arguments = PyList_New(0);
    PyObject* pointers = PyList_New(0);
    PyObject* indirect = PyList_New(0);
    PyObject* loops = PyList_New(0);
    PyObject* switches = PyList_New(0);
    if (item == nullptr || constants == nullptr || stack_states == nullptr || locals == nullptr || arguments == nullptr ||
        pointers == nullptr || indirect == nullptr || loops == nullptr || switches == nullptr) {
        Py_XDECREF(item);
        Py_XDECREF(constants);
        Py_XDECREF(stack_states);
        Py_XDECREF(locals);
        Py_XDECREF(arguments);
        Py_XDECREF(pointers);
        Py_XDECREF(indirect);
        Py_XDECREF(loops);
        Py_XDECREF(switches);
        return nullptr;
    }

    for (const auto& constant : function.summary.constants) {
        if (!append_list_item(constants, build_constant_dict(constant))) {
            Py_DECREF(item);
            return nullptr;
        }
    }
    for (const auto& state : function.summary.stack_pointer_states) {
        PyObject* state_item = PyDict_New();
        if (state_item == nullptr ||
            !set_dict_item(state_item, "address", PyLong_FromUnsignedLongLong(state.address)) ||
            !set_dict_item(state_item, "offset", PyLong_FromLongLong(state.offset)) ||
            !append_list_item(stack_states, state_item)) {
            Py_XDECREF(state_item);
            Py_DECREF(item);
            return nullptr;
        }
    }
    for (const auto& local : function.summary.locals) {
        if (!append_list_item(locals, build_local_dict(local))) {
            Py_DECREF(item);
            return nullptr;
        }
    }
    for (const auto& argument : function.summary.arguments) {
        if (!append_list_item(arguments, build_argument_dict(argument))) {
            Py_DECREF(item);
            return nullptr;
        }
    }
    for (const auto& pointer : function.summary.pointer_variables) {
        if (!append_list_item(pointers, PyUnicode_FromString(pointer.c_str()))) {
            Py_DECREF(item);
            return nullptr;
        }
    }
    for (const auto& resolution : function.summary.indirect_resolutions) {
        if (!append_list_item(indirect, build_indirect_resolution_dict(resolution))) {
            Py_DECREF(item);
            return nullptr;
        }
    }
    for (const auto& loop : function.graph.loops()) {
        if (!append_list_item(loops, build_loop_dict(loop))) {
            Py_DECREF(item);
            return nullptr;
        }
    }
    for (const auto& switch_info : function.graph.switches()) {
        if (!append_list_item(switches, build_switch_dict(switch_info))) {
            Py_DECREF(item);
            return nullptr;
        }
    }

    PyObject* return_value = py_none();
    if (function.summary.return_value.has_value()) {
        PyObject* return_item = PyDict_New();
        if (return_item == nullptr ||
            !set_dict_item(return_item, "location", PyUnicode_FromString(function.summary.return_value->location.c_str())) ||
            !set_dict_item(return_item, "type", PyUnicode_FromString(ir::to_string(function.summary.return_value->type).data()))) {
            Py_XDECREF(return_item);
            Py_DECREF(item);
            Py_DECREF(return_value);
            return nullptr;
        }
        Py_DECREF(return_value);
        return_value = return_item;
    }

    if (!set_dict_item(item, "constants", constants) ||
        !set_dict_item(item, "unreachable_blocks_removed", PyLong_FromSize_t(function.summary.unreachable_blocks_removed)) ||
        !set_dict_item(item, "copy_propagations_applied", PyLong_FromSize_t(function.summary.copy_propagations_applied)) ||
        !set_dict_item(item, "dead_instructions_eliminated", PyLong_FromSize_t(function.summary.dead_instructions_eliminated)) ||
        !set_dict_item(item, "cfg_linear_merges", PyLong_FromSize_t(function.summary.cfg_linear_merges)) ||
        !set_dict_item(item, "stack_pointer_states", stack_states) ||
        !set_dict_item(item, "stack_frame_size", PyLong_FromLongLong(function.summary.stack_frame_size)) ||
        !set_dict_item(item, "uses_frame_pointer", PyBool_FromLong(function.summary.uses_frame_pointer ? 1 : 0)) ||
        !set_dict_item(item, "locals", locals) ||
        !set_dict_item(item, "pointer_variables", pointers) ||
        !set_dict_item(item, "calling_convention", PyUnicode_FromString(analysis::to_string(function.summary.calling_convention).data())) ||
        !set_dict_item(item, "arguments", arguments) ||
        !set_dict_item(item, "return_value", return_value) ||
        !set_dict_item(item, "indirect_resolutions", indirect) ||
        !set_dict_item(item, "loops", loops) ||
        !set_dict_item(item, "switches", switches)) {
        Py_DECREF(item);
        return nullptr;
    }

    return item;
}

PyObject* build_runtime_snapshot_dict(const debugger::RuntimeSnapshot& snapshot) {
    PyObject* item = PyDict_New();
    PyObject* bytes = PyList_New(0);
    if (item == nullptr || bytes == nullptr) {
        Py_XDECREF(item);
        Py_XDECREF(bytes);
        return nullptr;
    }

    for (const auto byte : snapshot.instruction_bytes) {
        if (!append_list_item(bytes, PyLong_FromUnsignedLong(std::to_integer<unsigned int>(byte)))) {
            Py_DECREF(item);
            Py_DECREF(bytes);
            return nullptr;
        }
    }

    PyObject* registers = PyDict_New();
    if (registers == nullptr) {
        Py_DECREF(item);
        Py_DECREF(bytes);
        return nullptr;
    }
    const bool registers_ok =
        set_dict_item(registers, "rip", PyLong_FromUnsignedLongLong(snapshot.registers.rip)) &&
        set_dict_item(registers, "rsp", PyLong_FromUnsignedLongLong(snapshot.registers.rsp)) &&
        set_dict_item(registers, "rbp", PyLong_FromUnsignedLongLong(snapshot.registers.rbp)) &&
        set_dict_item(registers, "rax", PyLong_FromUnsignedLongLong(snapshot.registers.rax)) &&
        set_dict_item(registers, "rdi", PyLong_FromUnsignedLongLong(snapshot.registers.rdi)) &&
        set_dict_item(registers, "rsi", PyLong_FromUnsignedLongLong(snapshot.registers.rsi));
    if (!registers_ok) {
        Py_DECREF(item);
        Py_DECREF(bytes);
        Py_DECREF(registers);
        return nullptr;
    }

    PyObject* location = py_none();
    if (snapshot.location.has_value()) {
        PyObject* location_item = PyDict_New();
        if (location_item == nullptr ||
            !set_dict_item(location_item, "function_name", PyUnicode_FromString(snapshot.location->function_name.c_str())) ||
            !set_dict_item(location_item, "function_entry", PyLong_FromUnsignedLongLong(snapshot.location->function_entry)) ||
            !set_dict_item(location_item, "block_start", PyLong_FromUnsignedLongLong(snapshot.location->block_start)) ||
            !set_dict_item(location_item, "instruction_address", PyLong_FromUnsignedLongLong(snapshot.location->instruction_address)) ||
            !set_dict_item(location_item, "mnemonic", PyUnicode_FromString(snapshot.location->mnemonic.c_str())) ||
            !set_dict_item(location_item, "operands", PyUnicode_FromString(snapshot.location->operands.c_str())) ||
            !set_dict_item(location_item, "pseudocode_excerpt", PyUnicode_FromString(snapshot.location->pseudocode_excerpt.c_str()))) {
            Py_XDECREF(location_item);
            Py_DECREF(item);
            Py_DECREF(bytes);
            Py_DECREF(registers);
            Py_DECREF(location);
            return nullptr;
        }
        Py_DECREF(location);
        location = location_item;
    }

    if (!set_dict_item(item, "stop_reason", PyUnicode_FromString(debugger::to_string(snapshot.stop.reason).data())) ||
        !set_dict_item(item, "stop_address", py_nullable_address(snapshot.stop.address)) ||
        !set_dict_item(item, "registers", registers) ||
        !set_dict_item(item, "instruction_bytes", bytes) ||
        !set_dict_item(item, "location", location)) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_import_dict(const loader::ImportedSymbol& imported) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    if (!set_dict_item(item, "library", PyUnicode_FromString(imported.library.c_str())) ||
        !set_dict_item(item, "name", PyUnicode_FromString(imported.name.c_str())) ||
        !set_dict_item(item, "address", PyLong_FromUnsignedLongLong(imported.address))) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_export_dict(const loader::ExportedSymbol& exported) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    if (!set_dict_item(item, "name", PyUnicode_FromString(exported.name.c_str())) ||
        !set_dict_item(item, "address", PyLong_FromUnsignedLongLong(exported.address)) ||
        !set_dict_item(item, "size", PyLong_FromUnsignedLongLong(exported.size))) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_string_dict(const xrefs::ExtractedString& extracted) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    if (!set_dict_item(item, "start", PyLong_FromUnsignedLongLong(extracted.start_address)) ||
        !set_dict_item(item, "end", PyLong_FromUnsignedLongLong(extracted.end_address)) ||
        !set_dict_item(item, "value", PyUnicode_FromString(extracted.value.c_str()))) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_xref_dict(const xrefs::CrossReference& reference) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    if (!set_dict_item(item, "kind", PyUnicode_FromString(xrefs::to_string(reference.kind).data())) ||
        !set_dict_item(item, "from", PyLong_FromUnsignedLongLong(reference.from_address)) ||
        !set_dict_item(item, "to", PyLong_FromUnsignedLongLong(reference.to_address)) ||
        !set_dict_item(item, "label", PyUnicode_FromString(reference.label.c_str()))) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_call_edge_dict(const analysis::CallGraphEdge& edge) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    if (!set_dict_item(item, "caller_entry", PyLong_FromUnsignedLongLong(edge.caller_entry)) ||
        !set_dict_item(item, "call_site", PyLong_FromUnsignedLongLong(edge.call_site)) ||
        !set_dict_item(item, "callee_entry", py_nullable_address(edge.callee_entry)) ||
        !set_dict_item(item, "callee_name", PyUnicode_FromString(edge.callee_name.c_str())) ||
        !set_dict_item(item, "is_import", PyBool_FromLong(edge.is_import ? 1 : 0))) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_ai_insight_dict(const ai::FunctionInsight& insight) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    PyObject* hints = PyList_New(0);
    PyObject* patterns = PyList_New(0);
    PyObject* vulnerability_hints = PyList_New(0);
    if (hints == nullptr || patterns == nullptr || vulnerability_hints == nullptr) {
        Py_DECREF(item);
        Py_XDECREF(hints);
        Py_XDECREF(patterns);
        Py_XDECREF(vulnerability_hints);
        return nullptr;
    }
    for (const auto& hint : insight.hints) {
        if (!append_list_item(hints, PyUnicode_FromString(hint.c_str()))) {
            Py_DECREF(hints);
            Py_DECREF(patterns);
            Py_DECREF(vulnerability_hints);
            Py_DECREF(item);
            return nullptr;
        }
    }
    for (const auto& pattern : insight.patterns) {
        PyObject* pattern_item = PyDict_New();
        if (pattern_item == nullptr ||
            !set_dict_item(pattern_item, "category", PyUnicode_FromString(pattern.category.c_str())) ||
            !set_dict_item(pattern_item, "label", PyUnicode_FromString(pattern.label.c_str())) ||
            !set_dict_item(pattern_item, "confidence", PyUnicode_FromString(pattern.confidence.c_str())) ||
            !set_dict_item(pattern_item, "detail", PyUnicode_FromString(pattern.detail.c_str())) ||
            !append_list_item(patterns, pattern_item)) {
            Py_XDECREF(pattern_item);
            Py_DECREF(hints);
            Py_DECREF(patterns);
            Py_DECREF(vulnerability_hints);
            Py_DECREF(item);
            return nullptr;
        }
    }
    for (const auto& vulnerability_hint : insight.vulnerability_hints) {
        PyObject* hint_item = PyDict_New();
        if (hint_item == nullptr ||
            !set_dict_item(hint_item, "severity", PyUnicode_FromString(vulnerability_hint.severity.c_str())) ||
            !set_dict_item(hint_item, "title", PyUnicode_FromString(vulnerability_hint.title.c_str())) ||
            !set_dict_item(hint_item, "detail", PyUnicode_FromString(vulnerability_hint.detail.c_str())) ||
            !append_list_item(vulnerability_hints, hint_item)) {
            Py_XDECREF(hint_item);
            Py_DECREF(hints);
            Py_DECREF(patterns);
            Py_DECREF(vulnerability_hints);
            Py_DECREF(item);
            return nullptr;
        }
    }

    if (!set_dict_item(item, "entry", PyLong_FromUnsignedLongLong(insight.entry_address)) ||
        !set_dict_item(item, "current_name", PyUnicode_FromString(insight.current_name.c_str())) ||
        !set_dict_item(item, "suggested_name", PyUnicode_FromString(insight.suggested_name.c_str())) ||
        !set_dict_item(item, "summary", PyUnicode_FromString(insight.summary.c_str())) ||
        !set_dict_item(item, "hints", hints) ||
        !set_dict_item(item, "patterns", patterns) ||
        !set_dict_item(item, "vulnerability_hints", vulnerability_hints)) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_security_finding_dict(const security::RiskFinding& finding) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    if (!set_dict_item(item, "category", PyUnicode_FromString(finding.category.c_str())) ||
        !set_dict_item(item, "severity", PyUnicode_FromString(security::to_string(finding.severity).data())) ||
        !set_dict_item(item, "function_entry", PyLong_FromUnsignedLongLong(finding.function_entry)) ||
        !set_dict_item(item, "function_name", PyUnicode_FromString(finding.function_name.c_str())) ||
        !set_dict_item(item, "title", PyUnicode_FromString(finding.title.c_str())) ||
        !set_dict_item(item, "detail", PyUnicode_FromString(finding.detail.c_str()))) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_gadget_dict(const security::Gadget& gadget) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    if (!set_dict_item(item, "function_entry", PyLong_FromUnsignedLongLong(gadget.function_entry)) ||
        !set_dict_item(item, "function_name", PyUnicode_FromString(gadget.function_name.c_str())) ||
        !set_dict_item(item, "address", PyLong_FromUnsignedLongLong(gadget.address)) ||
        !set_dict_item(item, "sequence", PyUnicode_FromString(gadget.sequence.c_str())) ||
        !set_dict_item(item, "instruction_count", PyLong_FromSize_t(gadget.instruction_count))) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_vulnerability_pattern_dict(const security::VulnerabilityPattern& pattern) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    PyObject* poc_notes = PyList_New(0);
    if (poc_notes == nullptr) {
        Py_DECREF(item);
        return nullptr;
    }
    for (const auto& note : pattern.poc_notes) {
        if (!append_list_item(poc_notes, PyUnicode_FromString(note.c_str()))) {
            Py_DECREF(poc_notes);
            Py_DECREF(item);
            return nullptr;
        }
    }

    if (!set_dict_item(item, "category", PyUnicode_FromString(pattern.category.c_str())) ||
        !set_dict_item(item, "severity", PyUnicode_FromString(security::to_string(pattern.severity).data())) ||
        !set_dict_item(item, "function_entry", PyLong_FromUnsignedLongLong(pattern.function_entry)) ||
        !set_dict_item(item, "function_name", PyUnicode_FromString(pattern.function_name.c_str())) ||
        !set_dict_item(item, "title", PyUnicode_FromString(pattern.title.c_str())) ||
        !set_dict_item(item, "detail", PyUnicode_FromString(pattern.detail.c_str())) ||
        !set_dict_item(item, "poc_notes", poc_notes)) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_poc_target_dict(const security::PocScaffoldTarget& target) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    PyObject* notes = PyList_New(0);
    if (notes == nullptr) {
        Py_DECREF(item);
        return nullptr;
    }
    for (const auto& note : target.notes) {
        if (!append_list_item(notes, PyUnicode_FromString(note.c_str()))) {
            Py_DECREF(notes);
            Py_DECREF(item);
            return nullptr;
        }
    }

    if (!set_dict_item(item, "role", PyUnicode_FromString(target.role.c_str())) ||
        !set_dict_item(item, "function_entry", PyLong_FromUnsignedLongLong(target.function_entry)) ||
        !set_dict_item(item, "function_name", PyUnicode_FromString(target.function_name.c_str())) ||
        !set_dict_item(item, "notes", notes)) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_security_report_dict(const security::ExploitReport& report, const int max_findings, const int max_gadgets) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    PyObject* findings = PyList_New(0);
    PyObject* patterns = PyList_New(0);
    PyObject* poc_targets = PyList_New(0);
    PyObject* gadgets = PyList_New(0);
    if (findings == nullptr || patterns == nullptr || poc_targets == nullptr || gadgets == nullptr) {
        Py_XDECREF(findings);
        Py_XDECREF(patterns);
        Py_XDECREF(poc_targets);
        Py_XDECREF(gadgets);
        Py_DECREF(item);
        return nullptr;
    }

    const std::size_t findings_limit =
        max_findings <= 0 ? report.findings.size() : std::min<std::size_t>(report.findings.size(), max_findings);
    for (std::size_t index = 0; index < findings_limit; ++index) {
        if (!append_list_item(findings, build_security_finding_dict(report.findings[index]))) {
            Py_DECREF(findings);
            Py_DECREF(patterns);
            Py_DECREF(poc_targets);
            Py_DECREF(gadgets);
            Py_DECREF(item);
            return nullptr;
        }
    }

    for (const auto& pattern : report.patterns) {
        if (!append_list_item(patterns, build_vulnerability_pattern_dict(pattern))) {
            Py_DECREF(findings);
            Py_DECREF(patterns);
            Py_DECREF(poc_targets);
            Py_DECREF(gadgets);
            Py_DECREF(item);
            return nullptr;
        }
    }

    for (const auto& target : report.poc_targets) {
        if (!append_list_item(poc_targets, build_poc_target_dict(target))) {
            Py_DECREF(findings);
            Py_DECREF(patterns);
            Py_DECREF(poc_targets);
            Py_DECREF(gadgets);
            Py_DECREF(item);
            return nullptr;
        }
    }

    const std::size_t gadgets_limit =
        max_gadgets <= 0 ? report.gadgets.size() : std::min<std::size_t>(report.gadgets.size(), max_gadgets);
    for (std::size_t index = 0; index < gadgets_limit; ++index) {
        if (!append_list_item(gadgets, build_gadget_dict(report.gadgets[index]))) {
            Py_DECREF(findings);
            Py_DECREF(patterns);
            Py_DECREF(poc_targets);
            Py_DECREF(gadgets);
            Py_DECREF(item);
            return nullptr;
        }
    }

    if (!set_dict_item(item, "findings", findings) ||
        !set_dict_item(item, "patterns", patterns) ||
        !set_dict_item(item, "poc_targets", poc_targets) ||
        !set_dict_item(item, "gadgets", gadgets) ||
        !set_dict_item(item, "poc_scaffold", PyUnicode_FromString(report.poc_scaffold.c_str()))) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* build_diff_result_dict(const diff::Result& result) {
    PyObject* item = PyDict_New();
    if (item == nullptr) {
        return nullptr;
    }

    PyObject* changes = PyList_New(0);
    if (changes == nullptr) {
        Py_DECREF(item);
        return nullptr;
    }

    for (const auto& change : result.changes) {
        PyObject* change_item = PyDict_New();
        if (change_item == nullptr) {
            Py_DECREF(changes);
            Py_DECREF(item);
            return nullptr;
        }

        if (!set_dict_item(change_item, "kind", PyUnicode_FromString(diff::to_string(change.kind).data())) ||
            !set_dict_item(change_item, "old_name", PyUnicode_FromString(change.old_name.c_str())) ||
            !set_dict_item(change_item, "new_name", PyUnicode_FromString(change.new_name.c_str())) ||
            !set_dict_item(change_item, "old_entry", PyLong_FromUnsignedLongLong(change.old_entry)) ||
            !set_dict_item(change_item, "new_entry", PyLong_FromUnsignedLongLong(change.new_entry)) ||
            !set_dict_item(change_item, "similarity", PyFloat_FromDouble(change.similarity)) ||
            !append_list_item(changes, change_item)) {
            Py_DECREF(changes);
            Py_DECREF(item);
            return nullptr;
        }
    }

    if (!set_dict_item(item, "unchanged_count", PyLong_FromSize_t(result.unchanged_count)) ||
        !set_dict_item(item, "modified_count", PyLong_FromSize_t(result.modified_count)) ||
        !set_dict_item(item, "added_count", PyLong_FromSize_t(result.added_count)) ||
        !set_dict_item(item, "removed_count", PyLong_FromSize_t(result.removed_count)) ||
        !set_dict_item(item, "changes", changes)) {
        Py_DECREF(item);
        return nullptr;
    }
    return item;
}

PyObject* py_analyze_binary(PyObject*, PyObject* args) {
    const char* raw_path = nullptr;
    if (!PyArg_ParseTuple(args, "s", &raw_path)) {
        return nullptr;
    }

    CachedAnalysis* bundle = nullptr;
    std::string error;
    if (!load_analysis_bundle(raw_path, bundle, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    return build_summary_dict(*bundle);
}

PyObject* py_list_functions(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* raw_path = nullptr;
    int limit = 32;
    static const char* keywords[] = {"path", "limit", nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|i", const_cast<char**>(keywords), &raw_path, &limit)) {
        return nullptr;
    }

    CachedAnalysis* bundle = nullptr;
    std::string error;
    if (!load_analysis_bundle(raw_path, bundle, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    const std::size_t actual_limit =
        limit <= 0 ? bundle->program.functions.size() : std::min<std::size_t>(bundle->program.functions.size(), limit);
    PyObject* list = PyList_New(0);
    if (list == nullptr) {
        return nullptr;
    }

    for (std::size_t index = 0; index < actual_limit; ++index) {
        if (!append_list_item(list, build_function_overview_dict(bundle->program.functions[index]))) {
            Py_DECREF(list);
            return nullptr;
        }
    }
    return list;
}

PyObject* py_get_function(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* raw_path = nullptr;
    unsigned long long entry_address = 0;
    const int has_entry =
        PyTuple_Size(args) > 1 || (kwargs != nullptr && PyDict_GetItemString(kwargs, "entry") != nullptr);
    static const char* keywords[] = {"path", "entry", nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|K", const_cast<char**>(keywords), &raw_path, &entry_address)) {
        return nullptr;
    }

    CachedAnalysis* bundle = nullptr;
    std::string error;
    if (!load_analysis_bundle(raw_path, bundle, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    const auto* function = find_function(*bundle, has_entry != 0 ? std::optional<std::uint64_t>(entry_address) : std::nullopt);
    if (function == nullptr) {
        PyErr_SetString(PyExc_KeyError, "Requested function entry was not found.");
        return nullptr;
    }

    return build_function_detail_dict(*bundle, *function);
}

template <typename Item, typename Builder>
PyObject* build_list(const std::vector<Item>& items, const int limit, Builder&& builder) {
    const std::size_t actual_limit = limit <= 0 ? items.size() : std::min<std::size_t>(items.size(), limit);
    PyObject* list = PyList_New(0);
    if (list == nullptr) {
        return nullptr;
    }

    for (std::size_t index = 0; index < actual_limit; ++index) {
        if (!append_list_item(list, builder(items[index]))) {
            Py_DECREF(list);
            return nullptr;
        }
    }

    return list;
}

PyObject* py_list_imports(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* raw_path = nullptr;
    int limit = 64;
    static const char* keywords[] = {"path", "limit", nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|i", const_cast<char**>(keywords), &raw_path, &limit)) {
        return nullptr;
    }

    CachedAnalysis* bundle = nullptr;
    std::string error;
    if (!load_analysis_bundle(raw_path, bundle, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    return build_list(bundle->image.imports(), limit, [](const loader::ImportedSymbol& imported) {
        return build_import_dict(imported);
    });
}

PyObject* py_list_exports(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* raw_path = nullptr;
    int limit = 64;
    static const char* keywords[] = {"path", "limit", nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|i", const_cast<char**>(keywords), &raw_path, &limit)) {
        return nullptr;
    }

    CachedAnalysis* bundle = nullptr;
    std::string error;
    if (!load_analysis_bundle(raw_path, bundle, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    return build_list(bundle->image.exports(), limit, [](const loader::ExportedSymbol& exported) {
        return build_export_dict(exported);
    });
}

PyObject* py_list_strings(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* raw_path = nullptr;
    int limit = 64;
    static const char* keywords[] = {"path", "limit", nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|i", const_cast<char**>(keywords), &raw_path, &limit)) {
        return nullptr;
    }

    CachedAnalysis* bundle = nullptr;
    std::string error;
    if (!load_analysis_bundle(raw_path, bundle, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    return build_list(bundle->program.strings, limit, [](const xrefs::ExtractedString& extracted) {
        return build_string_dict(extracted);
    });
}

PyObject* py_list_xrefs(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* raw_path = nullptr;
    int limit = 128;
    static const char* keywords[] = {"path", "limit", nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|i", const_cast<char**>(keywords), &raw_path, &limit)) {
        return nullptr;
    }

    CachedAnalysis* bundle = nullptr;
    std::string error;
    if (!load_analysis_bundle(raw_path, bundle, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    return build_list(bundle->program.xrefs, limit, [](const xrefs::CrossReference& reference) {
        return build_xref_dict(reference);
    });
}

PyObject* py_list_call_graph(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* raw_path = nullptr;
    int limit = 128;
    static const char* keywords[] = {"path", "limit", nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|i", const_cast<char**>(keywords), &raw_path, &limit)) {
        return nullptr;
    }

    CachedAnalysis* bundle = nullptr;
    std::string error;
    if (!load_analysis_bundle(raw_path, bundle, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    return build_list(bundle->program.call_graph, limit, [](const analysis::CallGraphEdge& edge) {
        return build_call_edge_dict(edge);
    });
}

PyObject* py_get_ai_insights(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* raw_path = nullptr;
    int limit = 32;
    static const char* keywords[] = {"path", "limit", nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|i", const_cast<char**>(keywords), &raw_path, &limit)) {
        return nullptr;
    }

    CachedAnalysis* bundle = nullptr;
    std::string error;
    if (!load_analysis_bundle(raw_path, bundle, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    const auto insights = ai::Assistant::analyze_program(bundle->program, bundle->image.entry_point());
    return build_list(insights, limit, [](const ai::FunctionInsight& insight) {
        return build_ai_insight_dict(insight);
    });
}

PyObject* py_get_security_report(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* raw_path = nullptr;
    int max_findings = 32;
    int max_gadgets = 32;
    static const char* keywords[] = {"path", "max_findings", "max_gadgets", nullptr};
    if (!PyArg_ParseTupleAndKeywords(
            args,
            kwargs,
            "s|ii",
            const_cast<char**>(keywords),
            &raw_path,
            &max_findings,
            &max_gadgets
        )) {
        return nullptr;
    }

    CachedAnalysis* bundle = nullptr;
    std::string error;
    if (!load_analysis_bundle(raw_path, bundle, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    security::ExploitReport report = security::Workflow::analyze_exploit_surface(raw_path, bundle->program);
    return build_security_report_dict(report, max_findings, max_gadgets);
}

PyObject* py_decompile_function(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* raw_path = nullptr;
    unsigned long long entry_address = 0;
    const int has_entry =
        PyTuple_Size(args) > 1 || (kwargs != nullptr && PyDict_GetItemString(kwargs, "entry") != nullptr);
    static const char* keywords[] = {"path", "entry", nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|K", const_cast<char**>(keywords), &raw_path, &entry_address)) {
        return nullptr;
    }

    CachedAnalysis* bundle = nullptr;
    std::string error;
    if (!load_analysis_bundle(raw_path, bundle, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    const auto* function = find_function(*bundle, has_entry != 0 ? std::optional<std::uint64_t>(entry_address) : std::nullopt);
    if (function == nullptr) {
        PyErr_SetString(PyExc_KeyError, "Requested function entry was not found.");
        return nullptr;
    }

    return PyUnicode_FromString(function->decompiled.pseudocode.c_str());
}

PyObject* py_get_function_summary(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* raw_path = nullptr;
    unsigned long long entry_address = 0;
    const int has_entry =
        PyTuple_Size(args) > 1 || (kwargs != nullptr && PyDict_GetItemString(kwargs, "entry") != nullptr);
    static const char* keywords[] = {"path", "entry", nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|K", const_cast<char**>(keywords), &raw_path, &entry_address)) {
        return nullptr;
    }

    CachedAnalysis* bundle = nullptr;
    std::string error;
    if (!load_analysis_bundle(raw_path, bundle, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    const auto* function = find_function(*bundle, has_entry != 0 ? std::optional<std::uint64_t>(entry_address) : std::nullopt);
    if (function == nullptr) {
        PyErr_SetString(PyExc_KeyError, "Requested function entry was not found.");
        return nullptr;
    }
    return build_function_summary_dict(*function);
}

PyObject* py_get_function_ir(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* raw_path = nullptr;
    unsigned long long entry_address = 0;
    const int has_entry =
        PyTuple_Size(args) > 1 || (kwargs != nullptr && PyDict_GetItemString(kwargs, "entry") != nullptr);
    static const char* keywords[] = {"path", "entry", nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|K", const_cast<char**>(keywords), &raw_path, &entry_address)) {
        return nullptr;
    }

    CachedAnalysis* bundle = nullptr;
    std::string error;
    if (!load_analysis_bundle(raw_path, bundle, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    const auto* function = find_function(*bundle, has_entry != 0 ? std::optional<std::uint64_t>(entry_address) : std::nullopt);
    if (function == nullptr) {
        PyErr_SetString(PyExc_KeyError, "Requested function entry was not found.");
        return nullptr;
    }
    return build_ir_blocks_list(function->lifted_ir);
}

PyObject* py_get_function_ssa(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* raw_path = nullptr;
    unsigned long long entry_address = 0;
    const int has_entry =
        PyTuple_Size(args) > 1 || (kwargs != nullptr && PyDict_GetItemString(kwargs, "entry") != nullptr);
    static const char* keywords[] = {"path", "entry", nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|K", const_cast<char**>(keywords), &raw_path, &entry_address)) {
        return nullptr;
    }

    CachedAnalysis* bundle = nullptr;
    std::string error;
    if (!load_analysis_bundle(raw_path, bundle, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    const auto* function = find_function(*bundle, has_entry != 0 ? std::optional<std::uint64_t>(entry_address) : std::nullopt);
    if (function == nullptr) {
        PyErr_SetString(PyExc_KeyError, "Requested function entry was not found.");
        return nullptr;
    }
    return build_ssa_blocks_list(function->ssa_form);
}

PyObject* py_capture_entry_snapshot(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* raw_path = nullptr;
    static const char* keywords[] = {"path", nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", const_cast<char**>(keywords), &raw_path)) {
        return nullptr;
    }

    CachedAnalysis* bundle = nullptr;
    std::string error;
    if (!load_analysis_bundle(raw_path, bundle, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }
    if (!bundle->image.entry_point().has_value()) {
        PyErr_SetString(PyExc_RuntimeError, "Binary does not expose an entry point.");
        return nullptr;
    }

    auto debugger = debugger::DebugSession::create_native();
    if (!debugger->is_supported()) {
        PyErr_SetString(PyExc_RuntimeError, "Native debugger backend is unavailable.");
        return nullptr;
    }

    debugger::StopEvent event;
    if (!debugger->launch(bundle->image.source_path(), {}, event, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    if (!debugger->set_breakpoint(*bundle->image.entry_point(), error)) {
        std::string ignore_error;
        (void)debugger->terminate(ignore_error);
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }
    if (!debugger->continue_execution(event, error)) {
        std::string ignore_error;
        (void)debugger->terminate(ignore_error);
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    debugger::RuntimeSnapshot snapshot;
    if (!debugger::capture_runtime_snapshot(*debugger, bundle->image, bundle->program, event, snapshot, error)) {
        std::string ignore_error;
        (void)debugger->terminate(ignore_error);
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    std::string ignore_error;
    (void)debugger->terminate(ignore_error);
    return build_runtime_snapshot_dict(snapshot);
}

PyObject* py_diff_binaries(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* before_path = nullptr;
    const char* after_path = nullptr;
    static const char* keywords[] = {"before_path", "after_path", nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ss", const_cast<char**>(keywords), &before_path, &after_path)) {
        return nullptr;
    }

    CachedAnalysis* before_bundle = nullptr;
    CachedAnalysis* after_bundle = nullptr;
    std::string error;
    if (!load_analysis_bundle(before_path, before_bundle, error) ||
        !load_analysis_bundle(after_path, after_bundle, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    return build_diff_result_dict(diff::Engine::diff(before_bundle->program, after_bundle->program));
}

PyObject* py_discover_inputs(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* raw_input_path = nullptr;
    int recursive = 1;
    static const char* keywords[] = {"input_path", "recursive", nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|p", const_cast<char**>(keywords), &raw_input_path, &recursive)) {
        return nullptr;
    }

    const auto inputs = distributed::BatchRunner::discover_inputs(raw_input_path, recursive != 0);
    PyObject* list = PyList_New(0);
    if (list == nullptr) {
        return nullptr;
    }

    for (const auto& input : inputs) {
        if (!append_list_item(list, PyUnicode_FromString(input.string().c_str()))) {
            Py_DECREF(list);
            return nullptr;
        }
    }

    return list;
}

PyObject* py_run_batch(PyObject*, PyObject* args, PyObject* kwargs) {
    PyObject* raw_inputs = nullptr;
    const char* raw_output_dir = nullptr;
    unsigned long long concurrency = 0;
    unsigned long long shard_count = 1;
    unsigned long long shard_index = 0;
    int recursive = 1;
    int write_reports = 1;
    static const char* keywords[] = {
        "inputs",
        "output_dir",
        "concurrency",
        "shard_count",
        "shard_index",
        "recursive",
        "write_reports",
        nullptr,
    };
    if (!PyArg_ParseTupleAndKeywords(
            args,
            kwargs,
            "Os|KKKpp",
            const_cast<char**>(keywords),
            &raw_inputs,
            &raw_output_dir,
            &concurrency,
            &shard_count,
            &shard_index,
            &recursive,
            &write_reports
        )) {
        return nullptr;
    }

    std::vector<std::filesystem::path> inputs;
    std::string error;
    if (!parse_input_paths(raw_inputs, recursive != 0, inputs, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    distributed::BatchResult result;
    Py_BEGIN_ALLOW_THREADS
    result = distributed::BatchRunner::analyze(
        inputs,
        raw_output_dir,
        distributed::BatchOptions{
            .concurrency = static_cast<std::size_t>(concurrency),
            .shard_count = static_cast<std::size_t>(shard_count),
            .shard_index = static_cast<std::size_t>(shard_index),
            .recursive = recursive != 0,
        }
    );
    Py_END_ALLOW_THREADS

    if (write_reports != 0 && !write_batch_reports(raw_output_dir, result, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    return build_batch_result_dict(result);
}

PyObject* py_run_remote_batch(PyObject*, PyObject* args, PyObject* kwargs) {
    PyObject* raw_inputs = nullptr;
    const char* raw_output_dir = nullptr;
    const char* raw_host = "127.0.0.1";
    const char* raw_shared_secret = "";
    unsigned int port = 0;
    unsigned long long expected_workers = 1;
    unsigned long long timeout_ms = 10000;
    int recursive = 1;
    int write_reports = 1;
    static const char* keywords[] = {
        "inputs",
        "output_dir",
        "host",
        "shared_secret",
        "port",
        "expected_workers",
        "timeout_ms",
        "recursive",
        "write_reports",
        nullptr,
    };
    if (!PyArg_ParseTupleAndKeywords(
            args,
            kwargs,
            "Os|ssIKKpp",
            const_cast<char**>(keywords),
            &raw_inputs,
            &raw_output_dir,
            &raw_host,
            &raw_shared_secret,
            &port,
            &expected_workers,
            &timeout_ms,
            &recursive,
            &write_reports
        )) {
        return nullptr;
    }

    std::vector<std::filesystem::path> inputs;
    std::string error;
    if (!parse_input_paths(raw_inputs, recursive != 0, inputs, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    distributed::BatchResult result;
    bool ok = false;
    Py_BEGIN_ALLOW_THREADS
    ok = distributed::BatchRunner::analyze_remote(
        inputs,
        raw_output_dir,
        distributed::RemoteOptions{
            .host = raw_host,
            .port = static_cast<std::uint16_t>(port),
            .expected_workers = static_cast<std::size_t>(expected_workers),
            .accept_timeout_ms = static_cast<std::size_t>(timeout_ms),
            .shared_secret = raw_shared_secret,
        },
        result,
        error
    );
    Py_END_ALLOW_THREADS

    if (!ok) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    if (write_reports != 0 && !write_batch_reports(raw_output_dir, result, error)) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    return build_batch_result_dict(result);
}

PyObject* py_run_remote_worker(PyObject*, PyObject* args, PyObject* kwargs) {
    const char* raw_output_dir = nullptr;
    const char* raw_host = "127.0.0.1";
    const char* raw_shared_secret = "";
    unsigned int port = 0;
    static const char* keywords[] = {"output_dir", "host", "shared_secret", "port", nullptr};
    if (!PyArg_ParseTupleAndKeywords(
            args,
            kwargs,
            "s|ssI",
            const_cast<char**>(keywords),
            &raw_output_dir,
            &raw_host,
            &raw_shared_secret,
            &port
        )) {
        return nullptr;
    }

    std::string error;
    bool ok = false;
    Py_BEGIN_ALLOW_THREADS
    ok = distributed::BatchRunner::run_remote_worker(
        raw_output_dir,
        distributed::RemoteOptions{
            .host = raw_host,
            .port = static_cast<std::uint16_t>(port),
            .shared_secret = raw_shared_secret,
        },
        error
    );
    Py_END_ALLOW_THREADS

    if (!ok) {
        PyErr_SetString(PyExc_RuntimeError, error.c_str());
        return nullptr;
    }

    PyObject* result = PyDict_New();
    if (result == nullptr) {
        return nullptr;
    }

    if (!set_dict_item(result, "status", PyUnicode_FromString("completed")) ||
        !set_dict_item(result, "host", PyUnicode_FromString(raw_host)) ||
        !set_dict_item(result, "port", PyLong_FromUnsignedLong(port)) ||
        !set_dict_item(result, "output_dir", PyUnicode_FromString(raw_output_dir))) {
        Py_DECREF(result);
        return nullptr;
    }

    return result;
}

PyObject* py_clear_cache(PyObject*, PyObject*) {
    std::unique_lock lock(analysis_cache_mutex());
    analysis_cache().clear();
    Py_RETURN_NONE;
}

PyMethodDef zara_methods[] = {
    {"analyze_binary", py_analyze_binary, METH_VARARGS, "Analyze a binary and return a summary dictionary."},
    {"list_functions", reinterpret_cast<PyCFunction>(py_list_functions), METH_VARARGS | METH_KEYWORDS, "List discovered functions."},
    {"get_function", reinterpret_cast<PyCFunction>(py_get_function), METH_VARARGS | METH_KEYWORDS, "Return detailed function information."},
    {"list_imports", reinterpret_cast<PyCFunction>(py_list_imports), METH_VARARGS | METH_KEYWORDS, "List imported symbols."},
    {"list_exports", reinterpret_cast<PyCFunction>(py_list_exports), METH_VARARGS | METH_KEYWORDS, "List exported symbols."},
    {"list_strings", reinterpret_cast<PyCFunction>(py_list_strings), METH_VARARGS | METH_KEYWORDS, "List extracted strings."},
    {"list_xrefs", reinterpret_cast<PyCFunction>(py_list_xrefs), METH_VARARGS | METH_KEYWORDS, "List cross references."},
    {"list_call_graph", reinterpret_cast<PyCFunction>(py_list_call_graph), METH_VARARGS | METH_KEYWORDS, "List call graph edges."},
    {"get_ai_insights", reinterpret_cast<PyCFunction>(py_get_ai_insights), METH_VARARGS | METH_KEYWORDS, "Return AI-assisted function insights."},
    {"get_security_report", reinterpret_cast<PyCFunction>(py_get_security_report), METH_VARARGS | METH_KEYWORDS, "Return security findings and gadgets."},
    {"get_function_summary", reinterpret_cast<PyCFunction>(py_get_function_summary), METH_VARARGS | METH_KEYWORDS, "Return the recovered analysis summary for a function."},
    {"get_function_ir", reinterpret_cast<PyCFunction>(py_get_function_ir), METH_VARARGS | METH_KEYWORDS, "Return lifted IR blocks for a function."},
    {"get_function_ssa", reinterpret_cast<PyCFunction>(py_get_function_ssa), METH_VARARGS | METH_KEYWORDS, "Return SSA blocks for a function."},
    {"capture_entry_snapshot", reinterpret_cast<PyCFunction>(py_capture_entry_snapshot), METH_VARARGS | METH_KEYWORDS, "Launch a binary and capture a static/runtime-correlated snapshot at entry."},
    {"decompile_function", reinterpret_cast<PyCFunction>(py_decompile_function), METH_VARARGS | METH_KEYWORDS, "Return C-like pseudocode for a function."},
    {"diff_binaries", reinterpret_cast<PyCFunction>(py_diff_binaries), METH_VARARGS | METH_KEYWORDS, "Diff two analyzed binaries."},
    {"discover_inputs", reinterpret_cast<PyCFunction>(py_discover_inputs), METH_VARARGS | METH_KEYWORDS, "Discover candidate binaries in a directory tree."},
    {"run_batch", reinterpret_cast<PyCFunction>(py_run_batch), METH_VARARGS | METH_KEYWORDS, "Run local batch analysis and return the aggregate result."},
    {"run_remote_batch", reinterpret_cast<PyCFunction>(py_run_remote_batch), METH_VARARGS | METH_KEYWORDS, "Run remote controller batch analysis and return the aggregate result."},
    {"run_remote_worker", reinterpret_cast<PyCFunction>(py_run_remote_worker), METH_VARARGS | METH_KEYWORDS, "Run a remote batch worker until the controller finishes dispatching jobs."},
    {"clear_cache", py_clear_cache, METH_NOARGS, "Clear the embedded analysis cache."},
    {nullptr, nullptr, 0, nullptr},
};

PyModuleDef zara_module = {
    PyModuleDef_HEAD_INIT,
    "zara",
    "Zara embedded reverse-engineering API.",
    -1,
    zara_methods,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
};

PyObject* PyInit_zara() {
    return PyModule_Create(&zara_module);
}
#endif

}  // namespace

PythonEngine::PythonEngine() {
#if defined(ZARA_HAS_PYTHON)
    std::scoped_lock lock(python_runtime_mutex());
    if (python_runtime_refcount() == 0) {
        if (!Py_IsInitialized()) {
            PyImport_AppendInittab("zara", &PyInit_zara);
            Py_Initialize();
            initialized_here_ = true;
        }
    }
    ++python_runtime_refcount();
    available_ = Py_IsInitialized() != 0;
#else
    available_ = false;
#endif
}

PythonEngine::~PythonEngine() {
#if defined(ZARA_HAS_PYTHON)
    std::scoped_lock lock(python_runtime_mutex());
    if (python_runtime_refcount() > 0) {
        --python_runtime_refcount();
    }
    if (initialized_here_ && python_runtime_refcount() == 0 && Py_IsInitialized()) {
        Py_Finalize();
    }
#endif
}

bool PythonEngine::is_available() const noexcept {
    return available_;
}

bool PythonEngine::set_argv(const std::vector<std::string>& arguments, std::string& out_error) {
    out_error.clear();

#if defined(ZARA_HAS_PYTHON)
    if (!available_) {
        out_error = "Embedded Python is unavailable.";
        return false;
    }
    std::scoped_lock lock(python_runtime_mutex());
    PythonGilGuard gil;

    PyObject* sys_module = PyImport_ImportModule("sys");
    if (sys_module == nullptr) {
        out_error = fetch_python_error();
        return false;
    }

    PyObject* argv_list = PyList_New(static_cast<Py_ssize_t>(arguments.size()));
    if (argv_list == nullptr) {
        Py_DECREF(sys_module);
        out_error = fetch_python_error();
        return false;
    }

    for (std::size_t index = 0; index < arguments.size(); ++index) {
        PyObject* item = PyUnicode_FromString(arguments[index].c_str());
        if (item == nullptr) {
            Py_DECREF(argv_list);
            Py_DECREF(sys_module);
            out_error = fetch_python_error();
            return false;
        }
        PyList_SET_ITEM(argv_list, static_cast<Py_ssize_t>(index), item);
    }

    if (PyObject_SetAttrString(sys_module, "argv", argv_list) != 0) {
        Py_DECREF(argv_list);
        Py_DECREF(sys_module);
        out_error = fetch_python_error();
        return false;
    }

    Py_DECREF(argv_list);
    Py_DECREF(sys_module);
    return true;
#else
    (void)arguments;
    out_error = "Embedded Python support was not enabled at build time.";
    return false;
#endif
}

bool PythonEngine::execute_string(const std::string& source, std::string& out_error) {
    out_error.clear();

#if defined(ZARA_HAS_PYTHON)
    if (!available_) {
        out_error = "Embedded Python is unavailable.";
        return false;
    }
    std::scoped_lock lock(python_runtime_mutex());
    PythonGilGuard gil;

    if (PyRun_SimpleString(source.c_str()) != 0) {
        out_error = fetch_python_error();
        return false;
    }
    return true;
#else
    (void)source;
    out_error = "Embedded Python support was not enabled at build time.";
    return false;
#endif
}

bool PythonEngine::execute_file(const std::filesystem::path& path, std::string& out_error) {
    out_error.clear();

#if defined(ZARA_HAS_PYTHON)
    if (!available_) {
        out_error = "Embedded Python is unavailable.";
        return false;
    }
    std::scoped_lock lock(python_runtime_mutex());
    PythonGilGuard gil;

    FILE* file = std::fopen(path.string().c_str(), "r");
    if (file == nullptr) {
        out_error = "Failed to open script file.";
        return false;
    }

    const int result = PyRun_SimpleFileEx(file, path.string().c_str(), 1);
    if (result != 0) {
        out_error = fetch_python_error();
        return false;
    }
    return true;
#else
    (void)path;
    out_error = "Embedded Python support was not enabled at build time.";
    return false;
#endif
}

bool PythonEngine::run_repl(std::string& out_error) {
    out_error.clear();

#if defined(ZARA_HAS_PYTHON)
    if (!available_) {
        out_error = "Embedded Python is unavailable.";
        return false;
    }
    std::scoped_lock lock(python_runtime_mutex());
    PythonGilGuard gil;

    PyObject* main_module = PyImport_AddModule("__main__");
    if (main_module == nullptr) {
        out_error = fetch_python_error();
        return false;
    }
    (void)main_module;

    if (PyRun_InteractiveLoop(stdin, "<zara-repl>") != 0) {
        out_error = fetch_python_error();
        return false;
    }
    return true;
#else
    out_error = "Embedded Python support was not enabled at build time.";
    return false;
#endif
}

}  // namespace zara::scripting
