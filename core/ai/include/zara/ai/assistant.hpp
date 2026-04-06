#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "zara/analysis/program_analysis.hpp"

namespace zara::ai {

struct PatternDetection {
    std::string category;
    std::string label;
    std::string confidence;
    std::string detail;
};

struct VulnerabilityHint {
    std::string severity;
    std::string title;
    std::string detail;
};

struct FunctionInsight {
    std::uint64_t entry_address = 0;
    std::string current_name;
    std::string suggested_name;
    std::string summary;
    std::vector<std::string> hints;
    std::vector<PatternDetection> patterns;
    std::vector<VulnerabilityHint> vulnerability_hints;
};

enum class AssistantBackend {
    Heuristic,
    OpenAI,
    Anthropic,
    Gemini,
    OpenAICompatible,
    LocalLLM,
    Auto,
};

struct OpenAIOptions {
    std::string api_key;
    std::string model = "gpt-5-mini";
    std::string base_url = "https://api.openai.com/v1/responses";
    std::string organization;
    std::string project;
    std::size_t max_functions = 12;
    long timeout_ms = 30000;
};

struct AnthropicOptions {
    std::string api_key;
    std::string model;
    std::string base_url = "https://api.anthropic.com/v1/messages";
    std::size_t max_functions = 12;
    long timeout_ms = 30000;
    std::string api_version = "2023-06-01";
};

struct GeminiOptions {
    std::string api_key;
    std::string model;
    std::string base_url = "https://generativelanguage.googleapis.com/v1beta/models";
    std::size_t max_functions = 12;
    long timeout_ms = 30000;
};

struct CompatibleModelOptions {
    std::string api_key;
    std::string model;
    std::string base_url = "http://127.0.0.1:11434/v1/chat/completions";
    std::size_t max_functions = 12;
    long timeout_ms = 30000;
};

struct AssistantOptions {
    AssistantBackend backend = AssistantBackend::Heuristic;
    std::optional<OpenAIOptions> openai;
    std::optional<AnthropicOptions> anthropic;
    std::optional<GeminiOptions> gemini;
    std::optional<CompatibleModelOptions> compatible;
    bool fallback_to_heuristics = true;
};

struct AssistantRunMetadata {
    std::string backend = "heuristic";
    std::string model;
    std::string credential_fingerprint;
    bool used_remote_model = false;
    std::vector<std::string> warnings;
};

class ModelTransport {
public:
    virtual ~ModelTransport() = default;

    [[nodiscard]] virtual bool create_response(
        const std::string& request_json,
        const AssistantOptions& options,
        std::string& out_response_json,
        std::string& out_error
    ) = 0;
};

class Assistant {
public:
    [[nodiscard]] static std::vector<FunctionInsight> analyze_program(
        const analysis::ProgramAnalysis& program,
        std::optional<std::uint64_t> entry_point = std::nullopt
    );

    [[nodiscard]] static std::vector<FunctionInsight> analyze_program(
        const analysis::ProgramAnalysis& program,
        std::optional<std::uint64_t> entry_point,
        const AssistantOptions& options,
        AssistantRunMetadata* out_metadata = nullptr,
        ModelTransport* transport = nullptr
    );

    [[nodiscard]] static AssistantOptions options_from_environment();
};

[[nodiscard]] std::string_view to_string(AssistantBackend backend) noexcept;

}  // namespace zara::ai
