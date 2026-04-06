#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace zara::distributed {

struct BatchOptions {
    std::size_t concurrency = 0;
    std::size_t shard_count = 1;
    std::size_t shard_index = 0;
    bool recursive = true;
};

struct BatchJobResult {
    std::filesystem::path binary_path;
    std::filesystem::path project_db_path;
    bool success = false;
    std::string error;
    std::size_t function_count = 0;
    std::size_t call_count = 0;
    std::size_t import_count = 0;
    std::size_t export_count = 0;
    std::size_t xref_count = 0;
    std::size_t string_count = 0;
};

struct BatchWorkerSummary {
    std::string worker_id;
    std::string host;
    std::string platform;
    std::size_t assigned_jobs = 0;
    std::size_t completed_jobs = 0;
    std::size_t success_count = 0;
    std::size_t failure_count = 0;
    std::string status;
    std::string last_event;
    std::string last_error;
};

struct BatchEvent {
    std::size_t sequence = 0;
    std::string worker_id;
    std::string kind;
    std::string detail;
};

struct BatchResult {
    std::vector<BatchJobResult> jobs;
    std::size_t success_count = 0;
    std::size_t failure_count = 0;
    std::size_t total_function_count = 0;
    std::size_t total_call_count = 0;
    std::size_t total_import_count = 0;
    std::size_t total_export_count = 0;
    std::size_t total_xref_count = 0;
    std::size_t total_string_count = 0;
    bool remote = false;
    std::size_t worker_slots = 0;
    std::string protocol_version = "zara-batch/2";
    std::vector<BatchWorkerSummary> workers;
    std::vector<BatchEvent> events;
};

struct RemoteOptions {
    std::string host = "127.0.0.1";
    std::uint16_t port = 0;
    std::size_t expected_workers = 1;
    std::string protocol_version = "zara-batch/2";
    std::size_t accept_timeout_ms = 10000;
    std::size_t read_timeout_ms = 10000;
    std::size_t max_message_bytes = 64u * 1024u;
    std::size_t max_jobs_per_worker = 0;
    std::size_t heartbeat_interval_ms = 1000;
    std::size_t heartbeat_timeout_ms = 5000;
    std::string shared_secret;
    std::vector<std::string> allowed_platforms;
    bool use_tls = false;
    bool require_tls_for_remote = true;
    bool tls_insecure_skip_verify = false;
    std::filesystem::path tls_certificate;
    std::filesystem::path tls_private_key;
    std::filesystem::path tls_ca_certificate;
};

class BatchRunner {
public:
    [[nodiscard]] static std::vector<std::filesystem::path> discover_inputs(
        const std::filesystem::path& input_path,
        bool recursive = true
    );

    [[nodiscard]] static BatchResult analyze(
        const std::vector<std::filesystem::path>& inputs,
        const std::filesystem::path& output_directory,
        const BatchOptions& options = {}
    );

    [[nodiscard]] static bool write_manifest(
        const std::filesystem::path& manifest_path,
        const BatchResult& result,
        std::string& out_error
    );

    [[nodiscard]] static bool write_summary(
        const std::filesystem::path& summary_path,
        const BatchResult& result,
        std::string& out_error
    );

    [[nodiscard]] static bool analyze_remote(
        const std::vector<std::filesystem::path>& inputs,
        const std::filesystem::path& output_directory,
        const RemoteOptions& remote_options,
        BatchResult& out_result,
        std::string& out_error
    );

    [[nodiscard]] static bool run_remote_worker(
        const std::filesystem::path& output_directory,
        const RemoteOptions& remote_options,
        std::string& out_error
    );
};

}  // namespace zara::distributed
