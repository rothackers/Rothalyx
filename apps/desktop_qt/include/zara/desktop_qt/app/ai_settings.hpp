#pragma once

#include <QSettings>
#include <QString>

#include "zara/ai/assistant.hpp"

namespace zara::desktop_qt::app {

enum class AiProviderProfile {
    Heuristic,
    OpenAI,
    Anthropic,
    Gemini,
    OpenAICompatible,
    LocalLLM,
};

struct AiSettings {
    AiProviderProfile provider = AiProviderProfile::Heuristic;
    QString model;
    QString endpoint;
    QString organization;
    QString project;
    bool fallback_to_heuristics = true;
    int max_functions_per_run = 12;
    int timeout_ms = 30000;
    int max_remote_requests_per_day = 25;
};

[[nodiscard]] AiSettings load_ai_settings(QSettings& settings);
void save_ai_settings(QSettings& settings, const AiSettings& config);

[[nodiscard]] QString provider_key(AiProviderProfile provider);
[[nodiscard]] QString provider_display_name(AiProviderProfile provider);
[[nodiscard]] QString provider_help_text(AiProviderProfile provider);
[[nodiscard]] QString provider_default_model(AiProviderProfile provider);
[[nodiscard]] QString provider_default_endpoint(AiProviderProfile provider);
[[nodiscard]] bool provider_requires_api_key(AiProviderProfile provider);
[[nodiscard]] bool provider_uses_remote_billing(AiProviderProfile provider);
[[nodiscard]] QString provider_secret_account(AiProviderProfile provider);

[[nodiscard]] ai::AssistantOptions build_assistant_options(const AiSettings& config, const QString& api_key);

[[nodiscard]] bool ai_request_allowed(QSettings& settings, const AiSettings& config, QString& out_message);
void record_ai_request_usage(QSettings& settings, const AiSettings& config);

}  // namespace zara::desktop_qt::app
