#include <cstdlib>
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "zara/ai/assistant.hpp"

namespace {

class FakeModelTransport final : public zara::ai::ModelTransport {
public:
    [[nodiscard]] bool create_response(
        const std::string&,
        const zara::ai::AssistantOptions& options,
        std::string& out_response_json,
        std::string& out_error
    ) override {
        out_error.clear();
        switch (options.backend) {
        case zara::ai::AssistantBackend::Anthropic:
            out_response_json =
                R"({"content":[{"type":"text","text":"{\"functions\":[{\"entry_address\":\"0x2000\",\"suggested_name\":\"claude_auth_gate\",\"summary\":\"Anthropic-backed summary.\",\"hints\":[\"Anthropic hint.\"],\"patterns\":[{\"category\":\"comparison\",\"label\":\"anthropic authentication gate\",\"confidence\":\"high\",\"detail\":\"Anthropic detected validation logic.\"}],\"vulnerability_hints\":[{\"severity\":\"medium\",\"title\":\"Anthropic format-string exposure\",\"detail\":\"Review user-controlled formatting.\"}]}]}"}]})";
            break;
        case zara::ai::AssistantBackend::Gemini:
            out_response_json =
                R"({"candidates":[{"content":{"parts":[{"text":"{\"functions\":[{\"entry_address\":\"0x2000\",\"suggested_name\":\"gemini_auth_gate\",\"summary\":\"Gemini-backed summary.\",\"hints\":[\"Gemini hint.\"],\"patterns\":[{\"category\":\"comparison\",\"label\":\"gemini authentication gate\",\"confidence\":\"high\",\"detail\":\"Gemini detected validation logic.\"}],\"vulnerability_hints\":[{\"severity\":\"medium\",\"title\":\"Gemini format-string exposure\",\"detail\":\"Review user-controlled formatting.\"}]}]}"}]}}]})";
            break;
        case zara::ai::AssistantBackend::OpenAICompatible:
        case zara::ai::AssistantBackend::LocalLLM:
            out_response_json =
                R"({"choices":[{"message":{"content":"{\"functions\":[{\"entry_address\":\"0x2000\",\"suggested_name\":\"compatible_auth_gate\",\"summary\":\"Compatible model summary.\",\"hints\":[\"Compatible hint.\"],\"patterns\":[{\"category\":\"comparison\",\"label\":\"compatible authentication gate\",\"confidence\":\"high\",\"detail\":\"Compatible model detected validation logic.\"}],\"vulnerability_hints\":[{\"severity\":\"medium\",\"title\":\"Compatible format-string exposure\",\"detail\":\"Review user-controlled formatting.\"}]}]}"}}]})";
            break;
        case zara::ai::AssistantBackend::OpenAI:
        case zara::ai::AssistantBackend::Auto:
        case zara::ai::AssistantBackend::Heuristic:
        default:
            out_response_json =
                R"({"output_text":"{\"functions\":[{\"entry_address\":\"0x2000\",\"suggested_name\":\"auth_gate\",\"summary\":\"Validates a credential-like input before allowing execution.\",\"hints\":[\"Compares strings that look like credential material.\"],\"patterns\":[{\"category\":\"comparison\",\"label\":\"authentication gate\",\"confidence\":\"high\",\"detail\":\"String comparison imports and password-like strings indicate validation logic.\"}],\"vulnerability_hints\":[{\"severity\":\"medium\",\"title\":\"Format-string exposure\",\"detail\":\"User-controlled formatting path should be reviewed.\"}]}]}"})";
            break;
        }
        return true;
    }
};

zara::disasm::Instruction make_instruction(
    const std::uint64_t address,
    const std::string& mnemonic,
    const zara::disasm::InstructionKind kind = zara::disasm::InstructionKind::Instruction
) {
    return zara::disasm::Instruction{
        .address = address,
        .size = 1,
        .kind = kind,
        .bytes = {0x90},
        .mnemonic = mnemonic,
        .operands = {},
        .decoded_operands = {},
        .control_flow_target = std::nullopt,
        .data_references = {},
    };
}

zara::analysis::DiscoveredFunction make_function(
    const std::string& name,
    const std::uint64_t entry,
    std::vector<zara::disasm::Instruction> instructions
) {
    return zara::analysis::DiscoveredFunction{
        .name = name,
        .section_name = ".text",
        .entry_address = entry,
        .graph = zara::cfg::FunctionGraph::from_linear(name, std::move(instructions)),
        .lifted_ir = {},
        .ssa_form = {},
        .recovered_types = {},
        .decompiled = {},
        .summary = {},
        .analysis_materialized = true,
    };
}

}  // namespace

int main() {
    zara::analysis::ProgramAnalysis program{
        .functions =
            {
                make_function(
                    "sub_00001000",
                    0x1000,
                    {
                        make_instruction(0x1000, "call", zara::disasm::InstructionKind::Call),
                        make_instruction(0x1001, "ret", zara::disasm::InstructionKind::Return),
                    }
                ),
                make_function(
                    "sub_00002000",
                    0x2000,
                    {
                        make_instruction(0x2000, "call", zara::disasm::InstructionKind::Call),
                        make_instruction(0x2001, "call", zara::disasm::InstructionKind::Call),
                        make_instruction(0x2002, "ret", zara::disasm::InstructionKind::Return),
                    }
                ),
            },
        .call_graph =
            {
                zara::analysis::CallGraphEdge{
                    .caller_entry = 0x1000,
                    .call_site = 0x1000,
                    .callee_entry = std::nullopt,
                    .callee_name = "libc.so.6!__libc_start_main",
                    .is_import = true,
                },
                zara::analysis::CallGraphEdge{
                    .caller_entry = 0x2000,
                    .call_site = 0x2000,
                    .callee_entry = std::nullopt,
                    .callee_name = "strlen",
                    .is_import = true,
                },
                zara::analysis::CallGraphEdge{
                    .caller_entry = 0x2000,
                    .call_site = 0x2001,
                    .callee_entry = std::nullopt,
                    .callee_name = "memcmp",
                    .is_import = true,
                },
            },
        .strings = {},
        .xrefs =
            {
                zara::xrefs::CrossReference{
                    .kind = zara::xrefs::CrossReferenceKind::String,
                    .from_address = 0x2000,
                    .to_address = 0x3000,
                    .label = "password check",
                },
            },
        .lazy_materialization = false,
        .cache_key = {},
        .internal_state = {},
    };

    zara::ai::AssistantOptions options;
    options.backend = zara::ai::AssistantBackend::OpenAI;
    options.openai = zara::ai::OpenAIOptions{
        .api_key = "test-key",
        .model = "gpt-5-mini",
        .base_url = "https://example.invalid/v1/responses",
        .organization = {},
        .project = {},
        .max_functions = 1,
        .timeout_ms = 1000,
    };

    FakeModelTransport transport;
    zara::ai::AssistantRunMetadata metadata;
    const auto insights = zara::ai::Assistant::analyze_program(program, 0x1000, options, &metadata, &transport);
    if (insights.size() != 2) {
        std::cerr << "expected 2 insights, got " << insights.size() << '\n';
        return 1;
    }

    if (metadata.backend != "openai" || metadata.model != "gpt-5-mini" || !metadata.used_remote_model) {
        std::cerr << "expected openai metadata\n";
        return 2;
    }
    if (metadata.credential_fingerprint.empty()) {
        std::cerr << "expected credential fingerprint metadata\n";
        return 8;
    }

    const auto entry_it = std::find_if(
        insights.begin(),
        insights.end(),
        [](const zara::ai::FunctionInsight& insight) { return insight.entry_address == 0x1000; }
    );
    if (entry_it == insights.end() || entry_it->suggested_name != "entry_startup") {
        std::cerr << "expected heuristic fallback for entry point\n";
        return 3;
    }

    const auto compare_it = std::find_if(
        insights.begin(),
        insights.end(),
        [](const zara::ai::FunctionInsight& insight) { return insight.entry_address == 0x2000; }
    );
    if (compare_it == insights.end()) {
        std::cerr << "missing modeled function insight\n";
        return 4;
    }

    if (compare_it->suggested_name != "auth_gate" ||
        compare_it->summary.find("credential-like input") == std::string::npos) {
        std::cerr << "expected modeled rename/summary\n";
        return 5;
    }

    if (compare_it->patterns.empty() || compare_it->patterns.front().label != "authentication gate") {
        std::cerr << "expected modeled pattern\n";
        return 6;
    }

    if (compare_it->vulnerability_hints.empty() ||
        compare_it->vulnerability_hints.front().title != "Format-string exposure") {
        std::cerr << "expected modeled vulnerability hint\n";
        return 7;
    }

    if (setenv("ZARA_AI_BACKEND", "openai", 1) != 0 || setenv("ZARA_OPENAI_API_KEY", "env-secret", 1) != 0) {
        std::cerr << "failed to configure AI environment\n";
        return 9;
    }
    const auto env_options = zara::ai::Assistant::options_from_environment();
    if (!env_options.openai.has_value() || !env_options.openai->api_key.empty()) {
        std::cerr << "expected environment-derived options to scrub the raw API key\n";
        return 10;
    }

    zara::ai::AssistantOptions anthropic_options;
    anthropic_options.backend = zara::ai::AssistantBackend::Anthropic;
    anthropic_options.anthropic = zara::ai::AnthropicOptions{
        .api_key = "anthropic-secret",
        .model = "claude-sonnet-4-20250514",
        .base_url = "https://api.anthropic.com/v1/messages",
        .max_functions = 1,
        .timeout_ms = 1000,
        .api_version = "2023-06-01",
    };
    const auto anthropic_insights =
        zara::ai::Assistant::analyze_program(program, 0x1000, anthropic_options, nullptr, &transport);
    const auto anthropic_it = std::find_if(
        anthropic_insights.begin(),
        anthropic_insights.end(),
        [](const zara::ai::FunctionInsight& insight) { return insight.entry_address == 0x2000; }
    );
    if (anthropic_it == anthropic_insights.end() || anthropic_it->suggested_name != "claude_auth_gate") {
        std::cerr << "expected anthropic insight mapping\n";
        return 11;
    }

    zara::ai::AssistantOptions gemini_options;
    gemini_options.backend = zara::ai::AssistantBackend::Gemini;
    gemini_options.gemini = zara::ai::GeminiOptions{
        .api_key = "gemini-secret",
        .model = "gemini-2.5-pro",
        .base_url = "https://generativelanguage.googleapis.com/v1beta/models",
        .max_functions = 1,
        .timeout_ms = 1000,
    };
    const auto gemini_insights = zara::ai::Assistant::analyze_program(program, 0x1000, gemini_options, nullptr, &transport);
    const auto gemini_it = std::find_if(
        gemini_insights.begin(),
        gemini_insights.end(),
        [](const zara::ai::FunctionInsight& insight) { return insight.entry_address == 0x2000; }
    );
    if (gemini_it == gemini_insights.end() || gemini_it->suggested_name != "gemini_auth_gate") {
        std::cerr << "expected gemini insight mapping\n";
        return 12;
    }

    zara::ai::AssistantOptions compatible_options;
    compatible_options.backend = zara::ai::AssistantBackend::LocalLLM;
    compatible_options.compatible = zara::ai::CompatibleModelOptions{
        .api_key = {},
        .model = "llama3.1",
        .base_url = "http://127.0.0.1:11434/v1/chat/completions",
        .max_functions = 1,
        .timeout_ms = 1000,
    };
    zara::ai::AssistantRunMetadata compatible_metadata;
    const auto compatible_insights =
        zara::ai::Assistant::analyze_program(program, 0x1000, compatible_options, &compatible_metadata, &transport);
    const auto compatible_it = std::find_if(
        compatible_insights.begin(),
        compatible_insights.end(),
        [](const zara::ai::FunctionInsight& insight) { return insight.entry_address == 0x2000; }
    );
    if (compatible_it == compatible_insights.end() || compatible_it->suggested_name != "compatible_auth_gate") {
        std::cerr << "expected compatible insight mapping\n";
        return 13;
    }
    if (compatible_metadata.backend != "local_llm" || compatible_metadata.used_remote_model) {
        std::cerr << "expected local llm metadata\n";
        return 14;
    }

    return 0;
}
