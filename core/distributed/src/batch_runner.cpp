#include "zara/distributed/batch_runner.hpp"

#include <algorithm>
#include <atomic>
#include <array>
#include <cctype>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <mutex>
#include <optional>
#include <random>
#include <span>
#include <sstream>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <arpa/inet.h>
#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#if defined(ZARA_HAS_OPENSSL)
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

#include "zara/analysis/program_analysis.hpp"
#include "zara/database/project_store.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"

namespace zara::distributed {

namespace {

struct WorkerConnection {
    int fd = -1;
    bool awaiting_result = false;
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
    std::chrono::steady_clock::time_point last_activity = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point last_heartbeat = std::chrono::steady_clock::now();
#if defined(ZARA_HAS_OPENSSL)
    SSL* tls = nullptr;
#endif
};

struct WorkerHello {
    std::string host;
    std::string platform;
    std::string worker_id;
    std::string protocol_version;
    std::string worker_nonce;
    std::string auth_token;
};

struct WorkerPolicy {
    std::string protocol_version;
    std::size_t max_jobs_per_worker = 0;
    std::size_t read_timeout_ms = 0;
    std::size_t max_message_bytes = 0;
    std::size_t heartbeat_interval_ms = 0;
    std::string controller_nonce;
    std::string auth_token;
};

#if defined(ZARA_HAS_OPENSSL)
struct TlsContext {
    SSL_CTX* handle = nullptr;
    bool server = false;
};
#endif

struct TransportConnection {
    int fd = -1;
#if defined(ZARA_HAS_OPENSSL)
    SSL* tls = nullptr;
#endif
};

std::optional<std::string> environment_string(const char* name) {
    if (const char* value = std::getenv(name); value != nullptr && *value != '\0') {
        return std::string(value);
    }
    return std::nullopt;
}

std::optional<bool> environment_bool(const char* name) {
    const auto value = environment_string(name);
    if (!value.has_value()) {
        return std::nullopt;
    }

    std::string lowered = *value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](const unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (lowered == "1" || lowered == "true" || lowered == "yes" || lowered == "on") {
        return true;
    }
    if (lowered == "0" || lowered == "false" || lowered == "no" || lowered == "off") {
        return false;
    }
    return std::nullopt;
}

std::optional<std::size_t> environment_size(const char* name) {
    const auto value = environment_string(name);
    if (!value.has_value()) {
        return std::nullopt;
    }
    try {
        return static_cast<std::size_t>(std::stoull(*value));
    } catch (...) {
        return std::nullopt;
    }
}

std::string resolve_shared_secret(std::string configured_secret) {
    if (!configured_secret.empty()) {
        return configured_secret;
    }
    if (const auto env_secret = environment_string("ZARA_BATCH_SHARED_SECRET"); env_secret.has_value()) {
        return *env_secret;
    }
    return {};
}

RemoteOptions resolve_remote_options(RemoteOptions options) {
    if (!options.use_tls) {
        if (const auto env = environment_bool("ZARA_BATCH_USE_TLS"); env.has_value()) {
            options.use_tls = *env;
        }
    }
    if (const auto env = environment_bool("ZARA_BATCH_TLS_REQUIRE_REMOTE"); env.has_value()) {
        options.require_tls_for_remote = *env;
    }
    if (!options.tls_insecure_skip_verify) {
        if (const auto env = environment_bool("ZARA_BATCH_TLS_INSECURE_SKIP_VERIFY"); env.has_value()) {
            options.tls_insecure_skip_verify = *env;
        }
    }
    if (options.tls_certificate.empty()) {
        if (const auto env = environment_string("ZARA_BATCH_TLS_CERT"); env.has_value()) {
            options.tls_certificate = *env;
        }
    }
    if (options.tls_private_key.empty()) {
        if (const auto env = environment_string("ZARA_BATCH_TLS_KEY"); env.has_value()) {
            options.tls_private_key = *env;
        }
    }
    if (options.tls_ca_certificate.empty()) {
        if (const auto env = environment_string("ZARA_BATCH_TLS_CA"); env.has_value()) {
            options.tls_ca_certificate = *env;
        }
    }
    if (options.heartbeat_timeout_ms == 5000) {
        if (const auto env = environment_size("ZARA_BATCH_HEARTBEAT_TIMEOUT_MS"); env.has_value()) {
            options.heartbeat_timeout_ms = *env;
        }
    }
    return options;
}

std::uint32_t rotr32(const std::uint32_t value, const unsigned shift) {
    return (value >> shift) | (value << (32U - shift));
}

std::array<std::byte, 32> sha256_bytes(std::span<const std::byte> input) {
    static constexpr std::uint32_t kInitialState[8] = {
        0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
        0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
    };
    static constexpr std::uint32_t kRoundConstants[64] = {
        0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u, 0x3956C25Bu, 0x59F111F1u, 0x923F82A4u, 0xAB1C5ED5u,
        0xD807AA98u, 0x12835B01u, 0x243185BEu, 0x550C7DC3u, 0x72BE5D74u, 0x80DEB1FEu, 0x9BDC06A7u, 0xC19BF174u,
        0xE49B69C1u, 0xEFBE4786u, 0x0FC19DC6u, 0x240CA1CCu, 0x2DE92C6Fu, 0x4A7484AAu, 0x5CB0A9DCu, 0x76F988DAu,
        0x983E5152u, 0xA831C66Du, 0xB00327C8u, 0xBF597FC7u, 0xC6E00BF3u, 0xD5A79147u, 0x06CA6351u, 0x14292967u,
        0x27B70A85u, 0x2E1B2138u, 0x4D2C6DFCu, 0x53380D13u, 0x650A7354u, 0x766A0ABBu, 0x81C2C92Eu, 0x92722C85u,
        0xA2BFE8A1u, 0xA81A664Bu, 0xC24B8B70u, 0xC76C51A3u, 0xD192E819u, 0xD6990624u, 0xF40E3585u, 0x106AA070u,
        0x19A4C116u, 0x1E376C08u, 0x2748774Cu, 0x34B0BCB5u, 0x391C0CB3u, 0x4ED8AA4Au, 0x5B9CCA4Fu, 0x682E6FF3u,
        0x748F82EEu, 0x78A5636Fu, 0x84C87814u, 0x8CC70208u, 0x90BEFFFau, 0xA4506CEBu, 0xBEF9A3F7u, 0xC67178F2u,
    };

    std::vector<std::byte> padded(input.begin(), input.end());
    const std::uint64_t bit_length = static_cast<std::uint64_t>(input.size()) * 8ULL;
    padded.push_back(std::byte{0x80});
    while ((padded.size() % 64U) != 56U) {
        padded.push_back(std::byte{0x00});
    }
    for (int shift = 56; shift >= 0; shift -= 8) {
        padded.push_back(static_cast<std::byte>((bit_length >> shift) & 0xFFu));
    }

    std::uint32_t state[8];
    std::copy(std::begin(kInitialState), std::end(kInitialState), state);

    for (std::size_t offset = 0; offset < padded.size(); offset += 64U) {
        std::uint32_t words[64]{};
        for (std::size_t index = 0; index < 16; ++index) {
            const std::size_t base = offset + index * 4U;
            words[index] =
                (static_cast<std::uint32_t>(std::to_integer<unsigned char>(padded[base])) << 24U) |
                (static_cast<std::uint32_t>(std::to_integer<unsigned char>(padded[base + 1U])) << 16U) |
                (static_cast<std::uint32_t>(std::to_integer<unsigned char>(padded[base + 2U])) << 8U) |
                static_cast<std::uint32_t>(std::to_integer<unsigned char>(padded[base + 3U]));
        }
        for (std::size_t index = 16; index < 64; ++index) {
            const std::uint32_t s0 = rotr32(words[index - 15U], 7U) ^ rotr32(words[index - 15U], 18U) ^ (words[index - 15U] >> 3U);
            const std::uint32_t s1 = rotr32(words[index - 2U], 17U) ^ rotr32(words[index - 2U], 19U) ^ (words[index - 2U] >> 10U);
            words[index] = words[index - 16U] + s0 + words[index - 7U] + s1;
        }

        std::uint32_t a = state[0];
        std::uint32_t b = state[1];
        std::uint32_t c = state[2];
        std::uint32_t d = state[3];
        std::uint32_t e = state[4];
        std::uint32_t f = state[5];
        std::uint32_t g = state[6];
        std::uint32_t h = state[7];

        for (std::size_t index = 0; index < 64; ++index) {
            const std::uint32_t sigma1 = rotr32(e, 6U) ^ rotr32(e, 11U) ^ rotr32(e, 25U);
            const std::uint32_t choose = (e & f) ^ (~e & g);
            const std::uint32_t temp1 = h + sigma1 + choose + kRoundConstants[index] + words[index];
            const std::uint32_t sigma0 = rotr32(a, 2U) ^ rotr32(a, 13U) ^ rotr32(a, 22U);
            const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temp2 = sigma0 + majority;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    std::array<std::byte, 32> output{};
    for (std::size_t index = 0; index < 8; ++index) {
        output[index * 4U] = static_cast<std::byte>((state[index] >> 24U) & 0xFFu);
        output[index * 4U + 1U] = static_cast<std::byte>((state[index] >> 16U) & 0xFFu);
        output[index * 4U + 2U] = static_cast<std::byte>((state[index] >> 8U) & 0xFFu);
        output[index * 4U + 3U] = static_cast<std::byte>(state[index] & 0xFFu);
    }
    return output;
}

std::string bytes_to_hex(std::span<const std::byte> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string output;
    output.resize(bytes.size() * 2U);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        const auto value = std::to_integer<unsigned char>(bytes[index]);
        output[index * 2U] = kHex[(value >> 4U) & 0x0Fu];
        output[index * 2U + 1U] = kHex[value & 0x0Fu];
    }
    return output;
}

std::string hmac_sha256_hex(std::string_view secret, std::string_view message) {
    constexpr std::size_t kBlockSize = 64;
    std::array<std::byte, kBlockSize> key_block{};
    if (secret.size() > kBlockSize) {
        const auto hashed = sha256_bytes(
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(secret.data()), secret.size())
        );
        std::copy(hashed.begin(), hashed.end(), key_block.begin());
    } else {
        std::copy_n(reinterpret_cast<const std::byte*>(secret.data()), secret.size(), key_block.begin());
    }

    std::array<std::byte, kBlockSize> outer_pad{};
    std::array<std::byte, kBlockSize> inner_pad{};
    for (std::size_t index = 0; index < kBlockSize; ++index) {
        outer_pad[index] = key_block[index] ^ std::byte{0x5c};
        inner_pad[index] = key_block[index] ^ std::byte{0x36};
    }

    std::vector<std::byte> inner(inner_pad.begin(), inner_pad.end());
    inner.insert(
        inner.end(),
        reinterpret_cast<const std::byte*>(message.data()),
        reinterpret_cast<const std::byte*>(message.data()) + message.size()
    );
    const auto inner_hash = sha256_bytes(inner);

    std::vector<std::byte> outer(outer_pad.begin(), outer_pad.end());
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    const auto outer_hash = sha256_bytes(outer);
    return bytes_to_hex(outer_hash);
}

std::string random_nonce() {
    std::array<std::byte, 16> bytes{};
    std::random_device device;
    for (auto& value : bytes) {
        value = static_cast<std::byte>(device() & 0xFFu);
    }
    return bytes_to_hex(bytes);
}

std::string build_hello_token(const WorkerHello& hello, std::string_view shared_secret) {
    std::ostringstream stream;
    stream << "HELLO|" << hello.host << '|' << hello.platform << '|' << hello.worker_id << '|'
           << hello.protocol_version << '|' << hello.worker_nonce;
    return hmac_sha256_hex(shared_secret, stream.str());
}

std::string build_policy_token(
    const WorkerPolicy& policy,
    std::string_view worker_nonce,
    std::string_view shared_secret
) {
    std::ostringstream stream;
    stream << "POLICY|" << policy.protocol_version << '|' << policy.max_jobs_per_worker << '|'
           << policy.read_timeout_ms << '|' << policy.max_message_bytes << '|'
           << policy.heartbeat_interval_ms << '|' << policy.controller_nonce << '|' << worker_nonce;
    return hmac_sha256_hex(shared_secret, stream.str());
}

std::string sanitize_filename(std::string value) {
    for (char& character : value) {
        const bool keep =
            (character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9') ||
            character == '-' ||
            character == '_' ||
            character == '.';
        if (!keep) {
            character = '_';
        }
    }
    return value;
}

std::uint64_t fnv1a(std::string_view value) {
    std::uint64_t hash = 14695981039346656037ull;
    for (const unsigned char character : value) {
        hash ^= character;
        hash *= 1099511628211ull;
    }
    return hash;
}

std::string current_platform_name() {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#elif defined(__linux__)
    return "linux";
#else
    return "unknown";
#endif
}

bool is_loopback_host(const std::string_view host) {
    return host == "127.0.0.1" || host == "localhost" || host == "::1";
}

bool tls_required_for_options(const RemoteOptions& options) {
    return options.require_tls_for_remote && !is_loopback_host(options.host);
}

bool tls_enabled_for_options(const RemoteOptions& options) {
    return options.use_tls || tls_required_for_options(options);
}

std::size_t recommended_analysis_threads() {
    const std::size_t hardware_threads = std::max<std::size_t>(1, std::thread::hardware_concurrency());
    return std::min<std::size_t>(4, hardware_threads);
}

std::filesystem::path make_project_db_path(
    const std::filesystem::path& output_directory,
    const std::filesystem::path& binary_path
) {
    const std::string filename = sanitize_filename(binary_path.filename().string());
    const std::uint64_t digest = fnv1a(binary_path.string());
    std::ostringstream stream;
    stream << filename << '-' << std::hex << std::uppercase << digest << ".sqlite";
    return output_directory / stream.str();
}

bool has_candidate_extension(const std::filesystem::path& path) {
    const std::string extension = path.extension().string();
    return extension == ".exe" ||
           extension == ".dll" ||
           extension == ".so" ||
           extension == ".dylib" ||
           extension == ".bin" ||
           extension == ".o";
}

bool is_candidate_binary(const std::filesystem::directory_entry& entry) {
    if (!entry.is_regular_file()) {
        return false;
    }

    std::error_code error;
    const auto permissions = entry.status(error).permissions();
    if (!error) {
        const auto executable_bits =
            std::filesystem::perms::owner_exec |
            std::filesystem::perms::group_exec |
            std::filesystem::perms::others_exec;
        if ((permissions & executable_bits) != std::filesystem::perms::none) {
            return true;
        }
    }

    return has_candidate_extension(entry.path());
}

BatchJobResult analyze_one(
    const std::filesystem::path& binary_path,
    const std::filesystem::path& output_directory
) {
    BatchJobResult result;
    result.binary_path = binary_path;
    result.project_db_path = make_project_db_path(output_directory, binary_path);

    std::string error;
    loader::BinaryImage image;
    if (!loader::BinaryImage::load_from_file(binary_path, image, error)) {
        result.error = error;
        return result;
    }

    memory::AddressSpace address_space;
    if (!address_space.map_image(image)) {
        result.error = "Failed to map image into address space.";
        return result;
    }

    const auto program_analysis =
        analysis::Analyzer::analyze(
            image,
            address_space,
            analysis::AnalyzeOptions{
                .materialize_functions = true,
                .use_cache = true,
                .max_worker_threads = recommended_analysis_threads(),
            }
        );
    database::ProjectStore store(result.project_db_path);
    if (!store.save_program_analysis(image, program_analysis, error)) {
        result.error = error;
        return result;
    }

    result.success = true;
    result.function_count = program_analysis.functions.size();
    result.call_count = program_analysis.call_graph.size();
    result.import_count = image.imports().size();
    result.export_count = image.exports().size();
    result.xref_count = program_analysis.xrefs.size();
    result.string_count = program_analysis.strings.size();
    return result;
}

void finalize_result(BatchResult& result) {
    std::sort(
        result.jobs.begin(),
        result.jobs.end(),
        [](const BatchJobResult& lhs, const BatchJobResult& rhs) {
            return lhs.binary_path < rhs.binary_path;
        }
    );

    result.success_count = 0;
    result.failure_count = 0;
    result.total_function_count = 0;
    result.total_call_count = 0;
    result.total_import_count = 0;
    result.total_export_count = 0;
    result.total_xref_count = 0;
    result.total_string_count = 0;
    for (const auto& job : result.jobs) {
        if (job.success) {
            ++result.success_count;
        } else {
            ++result.failure_count;
        }
        result.total_function_count += job.function_count;
        result.total_call_count += job.call_count;
        result.total_import_count += job.import_count;
        result.total_export_count += job.export_count;
        result.total_xref_count += job.xref_count;
        result.total_string_count += job.string_count;
    }
}

std::string escape_field(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);
    for (const char character : value) {
        switch (character) {
        case '%':
            escaped += "%25";
            break;
        case '\t':
            escaped += "%09";
            break;
        case '\n':
            escaped += "%0A";
            break;
        case '\r':
            escaped += "%0D";
            break;
        default:
            escaped.push_back(character);
            break;
        }
    }
    return escaped;
}

std::string escape_json(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);
    for (const char character : value) {
        switch (character) {
        case '\\':
            escaped += "\\\\";
            break;
        case '"':
            escaped += "\\\"";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            escaped.push_back(character);
            break;
        }
    }
    return escaped;
}

std::string unescape_field(std::string_view value) {
    std::string decoded;
    decoded.reserve(value.size());
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (value[index] == '%' && index + 2 < value.size()) {
            const std::string_view token = value.substr(index, 3);
            if (token == "%25") {
                decoded.push_back('%');
                index += 2;
                continue;
            }
            if (token == "%09") {
                decoded.push_back('\t');
                index += 2;
                continue;
            }
            if (token == "%0A") {
                decoded.push_back('\n');
                index += 2;
                continue;
            }
            if (token == "%0D") {
                decoded.push_back('\r');
                index += 2;
                continue;
            }
        }
        decoded.push_back(value[index]);
    }
    return decoded;
}

std::vector<std::string_view> split_fields(const std::string_view line) {
    std::vector<std::string_view> fields;
    std::size_t cursor = 0;
    while (cursor <= line.size()) {
        const auto separator = line.find('\t', cursor);
        if (separator == std::string_view::npos) {
            fields.push_back(line.substr(cursor));
            break;
        }
        fields.push_back(line.substr(cursor, separator - cursor));
        cursor = separator + 1;
    }
    return fields;
}

std::string encode_job_message(const std::filesystem::path& binary_path) {
    return "JOB\t" + escape_field(binary_path.string()) + '\n';
}

std::string encode_hello_message(const WorkerHello& hello) {
    return "HELLO\t" + escape_field(hello.host) + '\t' + escape_field(hello.platform) + '\t' +
           escape_field(hello.worker_id) + '\t' + escape_field(hello.protocol_version) + '\t' +
           escape_field(hello.worker_nonce) + '\t' + escape_field(hello.auth_token) + '\n';
}

std::string encode_result_message(const BatchJobResult& result) {
    std::ostringstream stream;
    stream << "RESULT\t"
           << escape_field(result.binary_path.string()) << '\t'
           << escape_field(result.project_db_path.string()) << '\t'
           << (result.success ? "ok" : "error") << '\t'
           << result.function_count << '\t'
           << result.call_count << '\t'
           << result.import_count << '\t'
           << result.export_count << '\t'
           << result.xref_count << '\t'
           << result.string_count << '\t'
           << escape_field(result.error)
           << '\n';
    return stream.str();
}

std::string encode_policy_message(const WorkerPolicy& policy) {
    std::ostringstream stream;
    stream << "POLICY\t"
           << escape_field(policy.protocol_version) << '\t'
           << policy.max_jobs_per_worker << '\t'
           << policy.read_timeout_ms << '\t'
           << policy.max_message_bytes << '\t'
           << policy.heartbeat_interval_ms << '\t'
           << escape_field(policy.controller_nonce) << '\t'
           << escape_field(policy.auth_token) << '\n';
    return stream.str();
}

std::string encode_event_message(std::string_view kind, std::string_view detail) {
    return "EVENT\t" + escape_field(kind) + '\t' + escape_field(detail) + '\n';
}

bool decode_job_message(const std::string_view line, std::filesystem::path& out_binary_path) {
    const auto fields = split_fields(line);
    if (fields.size() != 2 || fields[0] != "JOB") {
        return false;
    }

    out_binary_path = unescape_field(fields[1]);
    return true;
}

bool decode_hello_message(const std::string_view line, WorkerHello& out_hello) {
    const auto fields = split_fields(line);
    if (fields.size() != 7 || fields[0] != "HELLO") {
        return false;
    }

    out_hello.host = unescape_field(fields[1]);
    out_hello.platform = unescape_field(fields[2]);
    out_hello.worker_id = unescape_field(fields[3]);
    out_hello.protocol_version = unescape_field(fields[4]);
    out_hello.worker_nonce = unescape_field(fields[5]);
    out_hello.auth_token = unescape_field(fields[6]);
    return true;
}

bool parse_size_field(const std::string_view field, std::size_t& out_value) {
    try {
        const auto parsed = std::stoull(std::string(field));
        if (parsed > static_cast<unsigned long long>((std::numeric_limits<std::size_t>::max)())) {
            return false;
        }
        out_value = static_cast<std::size_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

bool decode_result_message(const std::string_view line, BatchJobResult& out_result) {
    const auto fields = split_fields(line);
    if (fields.size() != 11 || fields[0] != "RESULT") {
        return false;
    }

    out_result.binary_path = unescape_field(fields[1]);
    out_result.project_db_path = unescape_field(fields[2]);
    out_result.success = fields[3] == "ok";
    if (!parse_size_field(fields[4], out_result.function_count) ||
        !parse_size_field(fields[5], out_result.call_count) ||
        !parse_size_field(fields[6], out_result.import_count) ||
        !parse_size_field(fields[7], out_result.export_count) ||
        !parse_size_field(fields[8], out_result.xref_count) ||
        !parse_size_field(fields[9], out_result.string_count)) {
        return false;
    }
    out_result.error = unescape_field(fields[10]);
    return true;
}

bool decode_policy_message(const std::string_view line, WorkerPolicy& out_policy) {
    const auto fields = split_fields(line);
    if (fields.size() != 8 || fields[0] != "POLICY") {
        return false;
    }

    out_policy.protocol_version = unescape_field(fields[1]);
    if (!parse_size_field(fields[2], out_policy.max_jobs_per_worker) ||
        !parse_size_field(fields[3], out_policy.read_timeout_ms) ||
        !parse_size_field(fields[4], out_policy.max_message_bytes) ||
        !parse_size_field(fields[5], out_policy.heartbeat_interval_ms)) {
        return false;
    }
    out_policy.controller_nonce = unescape_field(fields[6]);
    out_policy.auth_token = unescape_field(fields[7]);
    return true;
}

bool decode_event_message(
    const std::string_view line,
    std::string& out_kind,
    std::string& out_detail
) {
    const auto fields = split_fields(line);
    if (fields.size() != 3 || fields[0] != "EVENT") {
        return false;
    }

    out_kind = unescape_field(fields[1]);
    out_detail = unescape_field(fields[2]);
    return true;
}

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
std::string socket_error_message(const std::string_view prefix) {
    return std::string(prefix) + ": " + std::strerror(errno);
}

std::string tls_error_message(const std::string_view prefix) {
#if defined(ZARA_HAS_OPENSSL)
    const unsigned long code = ERR_get_error();
    if (code == 0) {
        return std::string(prefix) + ": unknown TLS error";
    }

    std::array<char, 256> buffer{};
    ERR_error_string_n(code, buffer.data(), buffer.size());
    return std::string(prefix) + ": " + buffer.data();
#else
    return std::string(prefix) + ": TLS support is unavailable";
#endif
}

#if defined(ZARA_HAS_OPENSSL)
void destroy_tls_context(TlsContext& context) {
    if (context.handle != nullptr) {
        SSL_CTX_free(context.handle);
        context.handle = nullptr;
    }
}

bool configure_tls_minimums(SSL_CTX* context, std::string& out_error) {
    if (context == nullptr) {
        out_error = "TLS context is not initialized.";
        return false;
    }
    if (SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION) != 1) {
        out_error = tls_error_message("failed to configure TLS minimum version");
        return false;
    }
    SSL_CTX_set_options(context, SSL_OP_NO_COMPRESSION);
    return true;
}

bool create_server_tls_context(const RemoteOptions& options, TlsContext& out_context, std::string& out_error) {
    out_context = {};
    if (!tls_enabled_for_options(options)) {
        return true;
    }

    if (options.tls_certificate.empty() || options.tls_private_key.empty()) {
        out_error = "TLS-enabled controller requires certificate and private key paths.";
        return false;
    }

    SSL_CTX* context = SSL_CTX_new(TLS_server_method());
    if (context == nullptr) {
        out_error = tls_error_message("failed to create TLS server context");
        return false;
    }

    out_context.handle = context;
    out_context.server = true;
    if (!configure_tls_minimums(context, out_error)) {
        destroy_tls_context(out_context);
        return false;
    }
    if (SSL_CTX_use_certificate_file(context, options.tls_certificate.string().c_str(), SSL_FILETYPE_PEM) != 1) {
        out_error = tls_error_message("failed to load TLS certificate");
        destroy_tls_context(out_context);
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(context, options.tls_private_key.string().c_str(), SSL_FILETYPE_PEM) != 1) {
        out_error = tls_error_message("failed to load TLS private key");
        destroy_tls_context(out_context);
        return false;
    }
    if (SSL_CTX_check_private_key(context) != 1) {
        out_error = tls_error_message("TLS certificate/private key mismatch");
        destroy_tls_context(out_context);
        return false;
    }
    return true;
}

bool create_client_tls_context(const RemoteOptions& options, TlsContext& out_context, std::string& out_error) {
    out_context = {};
    if (!tls_enabled_for_options(options)) {
        return true;
    }

    SSL_CTX* context = SSL_CTX_new(TLS_client_method());
    if (context == nullptr) {
        out_error = tls_error_message("failed to create TLS client context");
        return false;
    }

    out_context.handle = context;
    out_context.server = false;
    if (!configure_tls_minimums(context, out_error)) {
        destroy_tls_context(out_context);
        return false;
    }

    if (options.tls_insecure_skip_verify) {
        SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nullptr);
        return true;
    }

    if (options.tls_ca_certificate.empty()) {
        out_error = "TLS-enabled worker requires a CA certificate unless insecure verification is explicitly enabled.";
        destroy_tls_context(out_context);
        return false;
    }

    if (SSL_CTX_load_verify_locations(context, options.tls_ca_certificate.string().c_str(), nullptr) != 1) {
        out_error = tls_error_message("failed to load TLS CA certificate");
        destroy_tls_context(out_context);
        return false;
    }
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, nullptr);
    return true;
}

bool configure_tls_peer_host(SSL* ssl, const std::string& host, std::string& out_error) {
    if (ssl == nullptr) {
        out_error = "TLS session is not initialized.";
        return false;
    }
    X509_VERIFY_PARAM* verify = SSL_get0_param(ssl);
    if (verify == nullptr) {
        out_error = "Failed to initialize TLS peer verification parameters.";
        return false;
    }

    if (is_loopback_host(host) || std::count(host.begin(), host.end(), '.') == 3) {
        if (X509_VERIFY_PARAM_set1_ip_asc(verify, host.c_str()) != 1) {
            out_error = tls_error_message("failed to configure TLS peer IP verification");
            return false;
        }
        return true;
    }

    if (X509_VERIFY_PARAM_set1_host(verify, host.c_str(), 0) != 1) {
        out_error = tls_error_message("failed to configure TLS peer hostname verification");
        return false;
    }
    return true;
}

bool attach_server_tls(TlsContext& context, TransportConnection& connection, std::string& out_error) {
    if (context.handle == nullptr) {
        return true;
    }

    SSL* ssl = SSL_new(context.handle);
    if (ssl == nullptr) {
        out_error = tls_error_message("failed to allocate TLS server session");
        return false;
    }
    if (SSL_set_fd(ssl, connection.fd) != 1) {
        out_error = tls_error_message("failed to bind TLS server session to socket");
        SSL_free(ssl);
        return false;
    }
    if (SSL_accept(ssl) != 1) {
        out_error = tls_error_message("TLS server handshake failed");
        SSL_free(ssl);
        return false;
    }
    connection.tls = ssl;
    return true;
}

bool attach_client_tls(
    TlsContext& context,
    const std::string& host,
    const RemoteOptions& options,
    TransportConnection& connection,
    std::string& out_error
) {
    if (context.handle == nullptr) {
        return true;
    }

    SSL* ssl = SSL_new(context.handle);
    if (ssl == nullptr) {
        out_error = tls_error_message("failed to allocate TLS client session");
        return false;
    }
    if (!options.tls_insecure_skip_verify && !configure_tls_peer_host(ssl, host, out_error)) {
        SSL_free(ssl);
        return false;
    }
    if (SSL_set_fd(ssl, connection.fd) != 1) {
        out_error = tls_error_message("failed to bind TLS client session to socket");
        SSL_free(ssl);
        return false;
    }
    if (SSL_connect(ssl) != 1) {
        out_error = tls_error_message("TLS client handshake failed");
        SSL_free(ssl);
        return false;
    }
    connection.tls = ssl;
    return true;
}
#endif

void close_transport_connection(TransportConnection& connection) {
#if defined(ZARA_HAS_OPENSSL)
    if (connection.tls != nullptr) {
        (void)SSL_shutdown(connection.tls);
        SSL_free(connection.tls);
        connection.tls = nullptr;
    }
#endif
    if (connection.fd >= 0) {
        close(connection.fd);
        connection.fd = -1;
    }
}

bool write_line(const TransportConnection& connection, const std::string& line, std::string& out_error) {
    out_error.clear();

    std::size_t written = 0;
    while (written < line.size()) {
        long result = 0;
#if defined(ZARA_HAS_OPENSSL)
        if (connection.tls != nullptr) {
            result = SSL_write(
                connection.tls,
                line.data() + static_cast<std::ptrdiff_t>(written),
                static_cast<int>(line.size() - written)
            );
            if (result <= 0) {
                out_error = tls_error_message("TLS write failed");
                return false;
            }
        } else
#endif
        {
            result = ::write(
                connection.fd,
                line.data() + static_cast<std::ptrdiff_t>(written),
                line.size() - written
            );
            if (result < 0) {
                out_error = socket_error_message("socket write failed");
                return false;
            }
        }
        written += static_cast<std::size_t>(result);
    }
    return true;
}

bool read_line(
    const TransportConnection& connection,
    const int timeout_ms,
    const std::size_t max_message_bytes,
    std::string& out_line,
    std::string& out_error
) {
    out_error.clear();
    out_line.clear();

    if (timeout_ms > 0) {
        pollfd descriptor{
            .fd = connection.fd,
            .events = POLLIN,
            .revents = 0,
        };
        const int poll_result = poll(&descriptor, 1, timeout_ms);
        if (poll_result < 0) {
            out_error = socket_error_message("socket poll failed");
            return false;
        }
        if (poll_result == 0) {
            out_error = "socket read timed out";
            return false;
        }
    }

    char character = '\0';
    while (true) {
        long result = 0;
#if defined(ZARA_HAS_OPENSSL)
        if (connection.tls != nullptr) {
            result = SSL_read(connection.tls, &character, 1);
            if (result <= 0) {
                out_error = tls_error_message("TLS read failed");
                return false;
            }
        } else
#endif
        {
            result = ::read(connection.fd, &character, 1);
            if (result < 0) {
                out_error = socket_error_message("socket read failed");
                return false;
            }
        }
        if (result == 0) {
            out_error = "peer closed the connection";
            return false;
        }
        if (character == '\n') {
            return true;
        }
        if (out_line.size() >= max_message_bytes) {
            out_error = "socket message exceeds the configured protocol limit";
            return false;
        }
        out_line.push_back(character);
    }
}

int create_server_socket(const std::string& host, const std::uint16_t port, std::string& out_error) {
    out_error.clear();

    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        out_error = socket_error_message("socket creation failed");
        return -1;
    }

    const int reuse = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1) {
        out_error = "unsupported remote host address";
        close(fd);
        return -1;
    }

    if (bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        out_error = socket_error_message("socket bind failed");
        close(fd);
        return -1;
    }

    if (listen(fd, SOMAXCONN) != 0) {
        out_error = socket_error_message("socket listen failed");
        close(fd);
        return -1;
    }

    return fd;
}

int connect_socket(const std::string& host, const std::uint16_t port, std::string& out_error) {
    out_error.clear();

    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        out_error = socket_error_message("socket creation failed");
        return -1;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1) {
        out_error = "unsupported remote host address";
        close(fd);
        return -1;
    }

    if (connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        out_error = socket_error_message("socket connect failed");
        close(fd);
        return -1;
    }

    return fd;
}

void close_connection(WorkerConnection& connection) {
    TransportConnection transport{
        .fd = connection.fd,
#if defined(ZARA_HAS_OPENSSL)
        .tls = connection.tls,
#endif
    };
    close_transport_connection(transport);
    connection.fd = transport.fd;
#if defined(ZARA_HAS_OPENSSL)
    connection.tls = transport.tls;
#endif
    connection.awaiting_result = false;
}
#endif

void append_batch_event(
    BatchResult& result,
    const WorkerConnection& worker,
    std::string kind,
    std::string detail
) {
    result.events.push_back(
        BatchEvent{
            .sequence = result.events.size(),
            .worker_id = worker.worker_id,
            .kind = std::move(kind),
            .detail = std::move(detail),
        }
    );
}

}  // namespace

std::vector<std::filesystem::path> BatchRunner::discover_inputs(
    const std::filesystem::path& input_path,
    const bool recursive
) {
    std::vector<std::filesystem::path> inputs;
    std::error_code error;
    if (!std::filesystem::exists(input_path, error)) {
        return inputs;
    }

    if (std::filesystem::is_regular_file(input_path, error)) {
        inputs.push_back(input_path);
        return inputs;
    }

    if (!std::filesystem::is_directory(input_path, error)) {
        return inputs;
    }

    if (recursive) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(input_path)) {
            if (is_candidate_binary(entry)) {
                inputs.push_back(entry.path());
            }
        }
    } else {
        for (const auto& entry : std::filesystem::directory_iterator(input_path)) {
            if (is_candidate_binary(entry)) {
                inputs.push_back(entry.path());
            }
        }
    }

    std::sort(inputs.begin(), inputs.end());
    return inputs;
}

BatchResult BatchRunner::analyze(
    const std::vector<std::filesystem::path>& inputs,
    const std::filesystem::path& output_directory,
    const BatchOptions& options
) {
    BatchResult result;
    result.remote = false;
    if (inputs.empty()) {
        return result;
    }

    std::filesystem::create_directories(output_directory);

    std::vector<std::filesystem::path> selected_inputs;
    selected_inputs.reserve(inputs.size());
    const std::size_t shard_count = (std::max<std::size_t>)(1, options.shard_count);
    const std::size_t shard_index = (std::min)(options.shard_index, shard_count - 1);
    for (std::size_t index = 0; index < inputs.size(); ++index) {
        if ((index % shard_count) == shard_index) {
            selected_inputs.push_back(inputs[index]);
        }
    }

    if (selected_inputs.empty()) {
        return result;
    }

    const std::size_t hardware_threads =
        (std::max<std::size_t>)(1, static_cast<std::size_t>(std::thread::hardware_concurrency()));
    const std::size_t requested_concurrency =
        options.concurrency == 0 ? hardware_threads : options.concurrency;
    const std::size_t safe_concurrency_cap = (std::max<std::size_t>)(1, hardware_threads * 2);
    const std::size_t concurrency =
        (std::max<std::size_t>)(1, (std::min)(requested_concurrency, selected_inputs.size()));
    const std::size_t bounded_concurrency = (std::min)(concurrency, safe_concurrency_cap);
    result.worker_slots = bounded_concurrency;
    result.workers.resize(bounded_concurrency);
    for (std::size_t worker_index = 0; worker_index < bounded_concurrency; ++worker_index) {
        result.workers[worker_index] =
            BatchWorkerSummary{
                .worker_id = "local-" + std::to_string(worker_index + 1),
                .host = "localhost",
                .platform = current_platform_name(),
                .assigned_jobs = 0,
                .completed_jobs = 0,
                .success_count = 0,
                .failure_count = 0,
                .status = "idle",
                .last_event = "initialized",
                .last_error = {},
            };
    }

    std::atomic<std::size_t> next_index = 0;
    std::mutex jobs_mutex;
    std::vector<std::thread> workers;
    workers.reserve(bounded_concurrency);

    for (std::size_t worker_index = 0; worker_index < bounded_concurrency; ++worker_index) {
        workers.emplace_back(
            [&, worker_index]() {
                while (true) {
                    const std::size_t index = next_index.fetch_add(1);
                    if (index >= selected_inputs.size()) {
                        break;
                    }

                    BatchJobResult job_result = analyze_one(selected_inputs[index], output_directory);
                    std::scoped_lock lock(jobs_mutex);
                    result.workers[worker_index].assigned_jobs += 1;
                    result.jobs.push_back(std::move(job_result));
                    result.workers[worker_index].completed_jobs += 1;
                    if (result.jobs.back().success) {
                        result.workers[worker_index].success_count += 1;
                        result.workers[worker_index].status = "completed";
                        result.workers[worker_index].last_event = "job finished";
                    } else {
                        result.workers[worker_index].failure_count += 1;
                        result.workers[worker_index].status = "error";
                        result.workers[worker_index].last_event = "job failed";
                        result.workers[worker_index].last_error = result.jobs.back().error;
                    }
                }
            }
        );
    }

    for (auto& worker : workers) {
        worker.join();
    }

    finalize_result(result);
    return result;
}

bool BatchRunner::write_manifest(
    const std::filesystem::path& manifest_path,
    const BatchResult& result,
    std::string& out_error
) {
    out_error.clear();
    std::filesystem::create_directories(manifest_path.parent_path());

    std::ofstream stream(manifest_path);
    if (!stream) {
        out_error = "Failed to open manifest for writing.";
        return false;
    }

    stream << "binary_path\tproject_db\tstatus\tfunctions\tcalls\timports\texports\txrefs\tstrings\terror\n";
    for (const auto& job : result.jobs) {
        stream << job.binary_path.string() << '\t'
               << job.project_db_path.string() << '\t'
               << (job.success ? "ok" : "error") << '\t'
               << job.function_count << '\t'
               << job.call_count << '\t'
               << job.import_count << '\t'
               << job.export_count << '\t'
               << job.xref_count << '\t'
               << job.string_count << '\t'
               << job.error << '\n';
    }

    return true;
}

bool BatchRunner::write_summary(
    const std::filesystem::path& summary_path,
    const BatchResult& result,
    std::string& out_error
) {
    out_error.clear();
    std::filesystem::create_directories(summary_path.parent_path());

    std::ofstream stream(summary_path);
    if (!stream) {
        out_error = "Failed to open batch summary for writing.";
        return false;
    }

    stream << "{\n";
    stream << "  \"remote\": " << (result.remote ? "true" : "false") << ",\n";
    stream << "  \"protocol_version\": \"" << escape_json(result.protocol_version) << "\",\n";
    stream << "  \"worker_slots\": " << result.worker_slots << ",\n";
    stream << "  \"success_count\": " << result.success_count << ",\n";
    stream << "  \"failure_count\": " << result.failure_count << ",\n";
    stream << "  \"totals\": {\n";
    stream << "    \"functions\": " << result.total_function_count << ",\n";
    stream << "    \"calls\": " << result.total_call_count << ",\n";
    stream << "    \"imports\": " << result.total_import_count << ",\n";
    stream << "    \"exports\": " << result.total_export_count << ",\n";
    stream << "    \"xrefs\": " << result.total_xref_count << ",\n";
    stream << "    \"strings\": " << result.total_string_count << "\n";
    stream << "  },\n";
    stream << "  \"workers\": [\n";
    for (std::size_t index = 0; index < result.workers.size(); ++index) {
        const auto& worker = result.workers[index];
        stream << "    {\n";
        stream << "      \"worker_id\": \"" << escape_json(worker.worker_id) << "\",\n";
        stream << "      \"host\": \"" << escape_json(worker.host) << "\",\n";
        stream << "      \"platform\": \"" << escape_json(worker.platform) << "\",\n";
        stream << "      \"assigned_jobs\": " << worker.assigned_jobs << ",\n";
        stream << "      \"completed_jobs\": " << worker.completed_jobs << ",\n";
        stream << "      \"success_count\": " << worker.success_count << ",\n";
        stream << "      \"failure_count\": " << worker.failure_count << ",\n";
        stream << "      \"status\": \"" << escape_json(worker.status) << "\",\n";
        stream << "      \"last_event\": \"" << escape_json(worker.last_event) << "\",\n";
        stream << "      \"last_error\": \"" << escape_json(worker.last_error) << "\"\n";
        stream << "    }";
        if (index + 1 != result.workers.size()) {
            stream << ',';
        }
        stream << '\n';
    }
    stream << "  ],\n";
    stream << "  \"events\": [\n";
    for (std::size_t index = 0; index < result.events.size(); ++index) {
        const auto& event = result.events[index];
        stream << "    {\n";
        stream << "      \"sequence\": " << event.sequence << ",\n";
        stream << "      \"worker_id\": \"" << escape_json(event.worker_id) << "\",\n";
        stream << "      \"kind\": \"" << escape_json(event.kind) << "\",\n";
        stream << "      \"detail\": \"" << escape_json(event.detail) << "\"\n";
        stream << "    }";
        if (index + 1 != result.events.size()) {
            stream << ',';
        }
        stream << '\n';
    }
    stream << "  ],\n";
    stream << "  \"jobs\": [\n";
    for (std::size_t index = 0; index < result.jobs.size(); ++index) {
        const auto& job = result.jobs[index];
        stream << "    {\n";
        stream << "      \"binary_path\": \"" << escape_json(job.binary_path.string()) << "\",\n";
        stream << "      \"project_db\": \"" << escape_json(job.project_db_path.string()) << "\",\n";
        stream << "      \"status\": \"" << (job.success ? "ok" : "error") << "\",\n";
        stream << "      \"functions\": " << job.function_count << ",\n";
        stream << "      \"calls\": " << job.call_count << ",\n";
        stream << "      \"imports\": " << job.import_count << ",\n";
        stream << "      \"exports\": " << job.export_count << ",\n";
        stream << "      \"xrefs\": " << job.xref_count << ",\n";
        stream << "      \"strings\": " << job.string_count << ",\n";
        stream << "      \"error\": \"" << escape_json(job.error) << "\"\n";
        stream << "    }";
        if (index + 1 != result.jobs.size()) {
            stream << ',';
        }
        stream << '\n';
    }
    stream << "  ]\n";
    stream << "}\n";
    return true;
}

bool BatchRunner::analyze_remote(
    const std::vector<std::filesystem::path>& inputs,
    const std::filesystem::path& output_directory,
    const RemoteOptions& configured_remote_options,
    BatchResult& out_result,
    std::string& out_error
) {
    out_result = {};
    out_error.clear();
    const RemoteOptions remote_options = resolve_remote_options(configured_remote_options);

    if (inputs.empty()) {
        return true;
    }

    if (remote_options.port == 0) {
        out_error = "Remote controller port must be non-zero.";
        return false;
    }
    if (remote_options.protocol_version.empty()) {
        out_error = "Remote controller protocol version must not be empty.";
        return false;
    }
    if (remote_options.max_message_bytes == 0) {
        out_error = "Remote controller message budget must be non-zero.";
        return false;
    }
    if (remote_options.heartbeat_interval_ms == 0) {
        out_error = "Remote controller heartbeat interval must be non-zero.";
        return false;
    }
    if (remote_options.heartbeat_timeout_ms == 0) {
        out_error = "Remote controller heartbeat timeout must be non-zero.";
        return false;
    }
    if (remote_options.heartbeat_timeout_ms < remote_options.heartbeat_interval_ms) {
        out_error = "Remote controller heartbeat timeout must be greater than or equal to the heartbeat interval.";
        return false;
    }

    const std::string shared_secret = resolve_shared_secret(remote_options.shared_secret);
    if (shared_secret.empty()) {
        out_error = "Remote controller requires a non-empty shared secret.";
        return false;
    }
    if (tls_enabled_for_options(remote_options)) {
#if !defined(ZARA_HAS_OPENSSL)
        out_error = "Remote controller TLS was requested but Zara was built without OpenSSL support.";
        return false;
#endif
    }

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    std::signal(SIGPIPE, SIG_IGN);
    std::filesystem::create_directories(output_directory);
    out_result.remote = true;
    out_result.worker_slots = remote_options.expected_workers;
    out_result.protocol_version = remote_options.protocol_version;

    const int listener = create_server_socket(remote_options.host, remote_options.port, out_error);
    if (listener < 0) {
        return false;
    }

    auto close_listener = [&]() {
        close(listener);
    };

#if defined(ZARA_HAS_OPENSSL)
    TlsContext tls_context;
    if (!create_server_tls_context(remote_options, tls_context, out_error)) {
        close_listener();
        return false;
    }
    auto destroy_tls = [&]() {
        destroy_tls_context(tls_context);
    };
#endif

    std::vector<WorkerConnection> workers;
    workers.reserve(remote_options.expected_workers);
    std::unordered_set<std::string> seen_worker_nonces;

    while (workers.size() < remote_options.expected_workers) {
        pollfd descriptor{
            .fd = listener,
            .events = POLLIN,
            .revents = 0,
        };
        const int poll_result = poll(&descriptor, 1, static_cast<int>(remote_options.accept_timeout_ms));
        if (poll_result < 0) {
            out_error = socket_error_message("controller accept poll failed");
            close_listener();
            return false;
        }
        if (poll_result == 0) {
            out_error = "Timed out waiting for remote workers to connect.";
            close_listener();
            return false;
        }

        const int worker_fd = accept(listener, nullptr, nullptr);
        if (worker_fd < 0) {
            out_error = socket_error_message("controller accept failed");
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            close_listener();
            return false;
        }

        TransportConnection transport{
            .fd = worker_fd,
#if defined(ZARA_HAS_OPENSSL)
            .tls = nullptr,
#endif
        };
#if defined(ZARA_HAS_OPENSSL)
        if (!attach_server_tls(tls_context, transport, out_error)) {
            close_transport_connection(transport);
            destroy_tls();
            close_listener();
            return false;
        }
#endif

        std::string hello_line;
        std::string read_error;
        if (!read_line(
                transport,
                static_cast<int>(remote_options.read_timeout_ms),
                remote_options.max_message_bytes,
                hello_line,
                read_error
            )) {
            out_error = read_error;
            close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            close_listener();
            return false;
        }

        WorkerHello hello;
        if (!decode_hello_message(hello_line, hello)) {
            out_error = "Remote worker handshake is invalid.";
            close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            close_listener();
            return false;
        }
        if (hello.auth_token != build_hello_token(hello, shared_secret)) {
            out_error = "Remote worker authentication failed.";
            close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            close_listener();
            return false;
        }
        if (!seen_worker_nonces.insert(hello.worker_nonce).second) {
            out_error = "Remote worker authentication failed: replayed nonce.";
            close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            close_listener();
            return false;
        }

        workers.push_back(
            WorkerConnection{
                .fd = transport.fd,
                .awaiting_result = false,
                .worker_id = std::move(hello.worker_id),
                .host = std::move(hello.host),
                .platform = std::move(hello.platform),
                .assigned_jobs = 0,
                .completed_jobs = 0,
                .success_count = 0,
                .failure_count = 0,
                .status = "connected",
                .last_event = "handshake completed",
                .last_error = {},
                .last_activity = std::chrono::steady_clock::now(),
                .last_heartbeat = std::chrono::steady_clock::now(),
#if defined(ZARA_HAS_OPENSSL)
                .tls = transport.tls,
#endif
            }
        );
        if (hello.protocol_version != remote_options.protocol_version) {
            out_error = "Remote worker protocol version does not match the controller policy.";
            close_connection(workers.back());
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            close_listener();
            return false;
        }
        if (!remote_options.allowed_platforms.empty() &&
            std::find(
                remote_options.allowed_platforms.begin(),
                remote_options.allowed_platforms.end(),
                workers.back().platform
            ) == remote_options.allowed_platforms.end()) {
            out_error = "Remote worker platform is not allowed by the controller policy.";
            close_connection(workers.back());
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            close_listener();
            return false;
        }
        append_batch_event(out_result, workers.back(), "worker-connected", workers.back().host + " (" + workers.back().platform + ")");

        std::string write_error;
        WorkerPolicy policy{
            .protocol_version = remote_options.protocol_version,
            .max_jobs_per_worker = remote_options.max_jobs_per_worker,
            .read_timeout_ms = remote_options.read_timeout_ms,
            .max_message_bytes = remote_options.max_message_bytes,
            .heartbeat_interval_ms = remote_options.heartbeat_interval_ms,
            .controller_nonce = random_nonce(),
            .auth_token = {},
        };
        policy.auth_token = build_policy_token(policy, hello.worker_nonce, shared_secret);
        if (!write_line(
                TransportConnection{
                    .fd = workers.back().fd,
#if defined(ZARA_HAS_OPENSSL)
                    .tls = workers.back().tls,
#endif
                },
                encode_policy_message(policy),
                write_error
            )) {
            out_error = write_error;
            close_connection(workers.back());
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            close_listener();
            return false;
        }
    }

    std::size_t next_job_index = 0;
    auto dispatch_job = [&](WorkerConnection& worker) -> bool {
        TransportConnection transport{
            .fd = worker.fd,
#if defined(ZARA_HAS_OPENSSL)
            .tls = worker.tls,
#endif
        };
        if (remote_options.max_jobs_per_worker > 0 && worker.assigned_jobs >= remote_options.max_jobs_per_worker) {
            std::string write_error;
            const bool wrote_done = write_line(transport, "DONE\n", write_error);
            worker.status = "quota-reached";
            worker.last_event = "policy quota reached";
            close_connection(worker);
            if (!wrote_done) {
                out_error = write_error;
                return false;
            }
            append_batch_event(out_result, worker, "worker-detached", worker.last_event);
            return true;
        }
        if (next_job_index >= inputs.size()) {
            std::string write_error;
            const bool wrote_done = write_line(transport, "DONE\n", write_error);
            worker.status = "completed";
            worker.last_event = "controller finished dispatch";
            close_connection(worker);
            if (!wrote_done) {
                out_error = write_error;
                return false;
            }
            append_batch_event(out_result, worker, "worker-detached", worker.last_event);
            return true;
        }

        std::string write_error;
        if (!write_line(transport, encode_job_message(inputs[next_job_index]), write_error)) {
            out_error = write_error;
            return false;
        }
        worker.awaiting_result = true;
        worker.assigned_jobs += 1;
        worker.status = "running";
        worker.last_event = "dispatched " + inputs[next_job_index].filename().string();
        worker.last_activity = std::chrono::steady_clock::now();
        append_batch_event(out_result, worker, "job-dispatched", worker.last_event);
        ++next_job_index;
        return true;
    };

    for (auto& worker : workers) {
        if (!dispatch_job(worker)) {
            for (auto& connection : workers) {
                close_connection(connection);
            }
            close_listener();
            return false;
        }
    }

    while (out_result.jobs.size() < inputs.size()) {
        const auto now = std::chrono::steady_clock::now();
        for (auto& worker : workers) {
            if (!worker.awaiting_result || worker.fd < 0) {
                continue;
            }
            const auto quiet_for =
                std::chrono::duration_cast<std::chrono::milliseconds>(now - worker.last_activity).count();
            if (quiet_for > static_cast<long long>(remote_options.heartbeat_timeout_ms)) {
                out_error = "Remote worker heartbeat timed out.";
                worker.status = "timeout";
                worker.last_error = out_error;
                append_batch_event(out_result, worker, "worker-timeout", out_error);
                for (auto& connection : workers) {
                    close_connection(connection);
                }
#if defined(ZARA_HAS_OPENSSL)
                destroy_tls();
#endif
                close_listener();
                return false;
            }
        }

        std::vector<pollfd> descriptors;
        std::vector<std::size_t> indices;
        for (std::size_t index = 0; index < workers.size(); ++index) {
            if (workers[index].fd >= 0 && workers[index].awaiting_result) {
                descriptors.push_back(
                    pollfd{
                        .fd = workers[index].fd,
                        .events = POLLIN,
                        .revents = 0,
                    }
                );
                indices.push_back(index);
            }
        }

        if (descriptors.empty()) {
            out_error = "Remote controller lost all active workers before completing jobs.";
            for (auto& worker : workers) {
                close_connection(worker);
            }
            close_listener();
            return false;
        }

        const int poll_result = poll(descriptors.data(), descriptors.size(), static_cast<int>(remote_options.read_timeout_ms));
        if (poll_result < 0) {
            out_error = socket_error_message("controller worker poll failed");
            for (auto& worker : workers) {
                close_connection(worker);
            }
            close_listener();
            return false;
        }
        if (poll_result == 0) {
            out_error = "Timed out waiting for remote worker results.";
            for (auto& worker : workers) {
                close_connection(worker);
            }
            close_listener();
            return false;
        }

        for (std::size_t descriptor_index = 0; descriptor_index < descriptors.size(); ++descriptor_index) {
            if ((descriptors[descriptor_index].revents & POLLIN) == 0) {
                continue;
            }

            WorkerConnection& worker = workers[indices[descriptor_index]];
            TransportConnection transport{
                .fd = worker.fd,
#if defined(ZARA_HAS_OPENSSL)
                .tls = worker.tls,
#endif
            };
            std::string line;
            std::string read_error;
            if (!read_line(
                    transport,
                    static_cast<int>(remote_options.read_timeout_ms),
                    remote_options.max_message_bytes,
                    line,
                    read_error
                )) {
                out_error = read_error;
                for (auto& connection : workers) {
                    close_connection(connection);
                }
#if defined(ZARA_HAS_OPENSSL)
                destroy_tls();
#endif
                close_listener();
                return false;
            }
            worker.last_activity = std::chrono::steady_clock::now();

            std::string event_kind;
            std::string event_detail;
            if (decode_event_message(line, event_kind, event_detail)) {
                worker.last_event = event_detail;
                worker.status = event_kind;
                if (event_kind == "worker-heartbeat") {
                    worker.last_heartbeat = worker.last_activity;
                }
                append_batch_event(out_result, worker, std::move(event_kind), std::move(event_detail));
                continue;
            }

            BatchJobResult job_result;
            if (!decode_result_message(line, job_result)) {
                out_error = "Remote worker returned an invalid result message.";
                for (auto& connection : workers) {
                    close_connection(connection);
                }
#if defined(ZARA_HAS_OPENSSL)
                destroy_tls();
#endif
                close_listener();
                return false;
            }

            worker.awaiting_result = false;
            worker.completed_jobs += 1;
            if (job_result.success) {
                worker.success_count += 1;
                worker.status = "idle";
                worker.last_event = "job finished";
            } else {
                worker.failure_count += 1;
                worker.status = "error";
                worker.last_error = job_result.error;
                worker.last_event = "job failed";
            }
            out_result.jobs.push_back(std::move(job_result));
            append_batch_event(out_result, worker, worker.status, worker.last_event);
            if (!dispatch_job(worker)) {
                for (auto& connection : workers) {
                    close_connection(connection);
                }
                close_listener();
                return false;
            }
        }
    }

    for (auto& worker : workers) {
        out_result.workers.push_back(
            BatchWorkerSummary{
                .worker_id = worker.worker_id,
                .host = worker.host,
                .platform = worker.platform,
                .assigned_jobs = worker.assigned_jobs,
                .completed_jobs = worker.completed_jobs,
                .success_count = worker.success_count,
                .failure_count = worker.failure_count,
                .status = worker.status,
                .last_event = worker.last_event,
                .last_error = worker.last_error,
            }
        );
        close_connection(worker);
    }
#if defined(ZARA_HAS_OPENSSL)
    destroy_tls();
#endif
    close_listener();
    finalize_result(out_result);
    return true;
#else
    (void)inputs;
    (void)output_directory;
    (void)remote_options;
    out_error = "Remote controller/worker execution is unavailable on this platform.";
    return false;
#endif
}

bool BatchRunner::run_remote_worker(
    const std::filesystem::path& output_directory,
    const RemoteOptions& configured_remote_options,
    std::string& out_error
) {
    out_error.clear();
    const RemoteOptions remote_options = resolve_remote_options(configured_remote_options);

    if (remote_options.port == 0) {
        out_error = "Remote worker port must be non-zero.";
        return false;
    }
    const std::string shared_secret = resolve_shared_secret(remote_options.shared_secret);
    if (shared_secret.empty()) {
        out_error = "Remote worker requires a non-empty shared secret.";
        return false;
    }
    if (tls_enabled_for_options(remote_options)) {
#if !defined(ZARA_HAS_OPENSSL)
        out_error = "Remote worker TLS was requested but Zara was built without OpenSSL support.";
        return false;
#endif
    }

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    std::signal(SIGPIPE, SIG_IGN);
    std::filesystem::create_directories(output_directory);

    const int connection = connect_socket(remote_options.host, remote_options.port, out_error);
    if (connection < 0) {
        return false;
    }
    TransportConnection transport{
        .fd = connection,
#if defined(ZARA_HAS_OPENSSL)
        .tls = nullptr,
#endif
    };

#if defined(ZARA_HAS_OPENSSL)
    TlsContext tls_context;
    if (!create_client_tls_context(remote_options, tls_context, out_error)) {
        close_transport_connection(transport);
        return false;
    }
    auto destroy_tls = [&]() {
        destroy_tls_context(tls_context);
    };
    if (!attach_client_tls(tls_context, remote_options.host, remote_options, transport, out_error)) {
        close_transport_connection(transport);
        destroy_tls();
        return false;
    }
#endif

    char hostname_buffer[256] = {};
    if (gethostname(hostname_buffer, sizeof(hostname_buffer)) != 0) {
        std::strncpy(hostname_buffer, "localhost", sizeof(hostname_buffer) - 1);
    }
    const WorkerHello hello{
        .host = hostname_buffer,
        .platform = current_platform_name(),
        .worker_id = current_platform_name() + "-" + std::to_string(static_cast<unsigned long long>(::getpid())),
        .protocol_version = remote_options.protocol_version.empty() ? "zara-batch/2" : remote_options.protocol_version,
        .worker_nonce = random_nonce(),
        .auth_token = {},
    };
    WorkerHello authenticated_hello = hello;
    authenticated_hello.auth_token = build_hello_token(authenticated_hello, shared_secret);
    if (!write_line(transport, encode_hello_message(authenticated_hello), out_error)) {
        close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
        destroy_tls();
#endif
        return false;
    }

    WorkerPolicy policy;
    {
        std::string policy_line;
        if (!read_line(transport, 30000, 64u * 1024u, policy_line, out_error)) {
            close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            return false;
        }
        if (!decode_policy_message(policy_line, policy)) {
            out_error = "Remote controller sent an invalid policy message.";
            close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            return false;
        }
        if (policy.protocol_version != authenticated_hello.protocol_version) {
            out_error = "Remote controller protocol version does not match the worker implementation.";
            close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            return false;
        }
        if (policy.auth_token != build_policy_token(policy, authenticated_hello.worker_nonce, shared_secret)) {
            out_error = "Remote controller authentication failed.";
            close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            return false;
        }
    }

    std::size_t completed_jobs = 0;
    if (!write_line(transport, encode_event_message("worker-ready", "worker connected"), out_error)) {
        close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
        destroy_tls();
#endif
        return false;
    }

    while (true) {
        std::string line;
        if (!read_line(
                transport,
                static_cast<int>(policy.read_timeout_ms == 0 ? 30000 : policy.read_timeout_ms),
                policy.max_message_bytes == 0 ? 64u * 1024u : policy.max_message_bytes,
                line,
                out_error
            )) {
            close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            return false;
        }

        if (line == "DONE") {
            close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            return true;
        }

        std::filesystem::path binary_path;
        if (!decode_job_message(line, binary_path)) {
            out_error = "Remote controller sent an invalid job message.";
            close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            return false;
        }

        if (!write_line(transport, encode_event_message("job-started", binary_path.filename().string()), out_error)) {
            close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            return false;
        }

        std::mutex write_mutex;
        std::atomic<bool> heartbeat_running = true;
        std::atomic<bool> heartbeat_failed = false;
        std::string heartbeat_error;
        std::thread heartbeat_thread(
            [&]() {
                if (policy.heartbeat_interval_ms == 0) {
                    return;
                }
                while (heartbeat_running.load()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(policy.heartbeat_interval_ms));
                    if (!heartbeat_running.load()) {
                        break;
                    }
                    std::lock_guard lock(write_mutex);
                    if (!write_line(transport, encode_event_message("worker-heartbeat", binary_path.filename().string()), heartbeat_error)) {
                        heartbeat_failed = true;
                        heartbeat_running = false;
                        break;
                    }
                }
            }
        );

        const BatchJobResult result = analyze_one(binary_path, output_directory);
        heartbeat_running = false;
        if (heartbeat_thread.joinable()) {
            heartbeat_thread.join();
        }
        if (heartbeat_failed.load()) {
            out_error = heartbeat_error.empty() ? "Remote worker heartbeat failed." : heartbeat_error;
            close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            return false;
        }

        ++completed_jobs;
        {
            std::lock_guard lock(write_mutex);
            if (!write_line(transport, encode_result_message(result), out_error)) {
                close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
                destroy_tls();
#endif
                return false;
            }
        }
        const std::string result_detail =
            binary_path.filename().string() + (result.success ? " ok" : " error");
        if (!write_line(transport, encode_event_message("job-finished", result_detail), out_error)) {
            close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
            destroy_tls();
#endif
            return false;
        }
        if (policy.max_jobs_per_worker > 0 && completed_jobs >= policy.max_jobs_per_worker) {
            if (!write_line(transport, encode_event_message("worker-quota", "worker reached max_jobs_per_worker"), out_error)) {
                close_transport_connection(transport);
#if defined(ZARA_HAS_OPENSSL)
                destroy_tls();
#endif
                return false;
            }
        }
    }
#else
    (void)output_directory;
    (void)remote_options;
    out_error = "Remote controller/worker execution is unavailable on this platform.";
    return false;
#endif
}

}  // namespace zara::distributed
