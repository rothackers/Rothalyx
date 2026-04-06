#include "zara/desktop_qt/app/ai_settings.hpp"

#include <algorithm>

#include <QDate>

namespace zara::desktop_qt::app {

namespace {

constexpr const char* kAiProviderKey = "ai/provider";
constexpr const char* kAiModelKey = "ai/model";
constexpr const char* kAiEndpointKey = "ai/endpoint";
constexpr const char* kAiOrganizationKey = "ai/organization";
constexpr const char* kAiProjectKey = "ai/project";
constexpr const char* kAiFallbackKey = "ai/fallback_to_heuristics";
constexpr const char* kAiMaxFunctionsKey = "ai/max_functions_per_run";
constexpr const char* kAiTimeoutKey = "ai/timeout_ms";
constexpr const char* kAiMaxRequestsPerDayKey = "ai/max_remote_requests_per_day";
constexpr const char* kAiUsageDayKey = "ai/usage/day_key";
constexpr const char* kAiUsageDayCountKey = "ai/usage/day_count";

AiProviderProfile provider_from_key(const QString& key) {
    if (key == "openai") {
        return AiProviderProfile::OpenAI;
    }
    if (key == "anthropic") {
        return AiProviderProfile::Anthropic;
    }
    if (key == "gemini") {
        return AiProviderProfile::Gemini;
    }
    if (key == "openai_compatible") {
        return AiProviderProfile::OpenAICompatible;
    }
    if (key == "local_llm") {
        return AiProviderProfile::LocalLLM;
    }
    return AiProviderProfile::Heuristic;
}

}  // namespace

AiSettings load_ai_settings(QSettings& settings) {
    const auto provider = provider_from_key(settings.value(kAiProviderKey, "heuristic").toString());
    AiSettings config;
    config.provider = provider;
    config.model = settings.value(kAiModelKey, provider_default_model(provider)).toString();
    config.endpoint = settings.value(kAiEndpointKey, provider_default_endpoint(provider)).toString();
    config.organization = settings.value(kAiOrganizationKey).toString();
    config.project = settings.value(kAiProjectKey).toString();
    config.fallback_to_heuristics = settings.value(kAiFallbackKey, true).toBool();
    config.max_functions_per_run = settings.value(kAiMaxFunctionsKey, 12).toInt();
    config.timeout_ms = settings.value(kAiTimeoutKey, 30000).toInt();
    config.max_remote_requests_per_day = settings.value(kAiMaxRequestsPerDayKey, 25).toInt();
    return config;
}

void save_ai_settings(QSettings& settings, const AiSettings& config) {
    settings.setValue(kAiProviderKey, provider_key(config.provider));
    settings.setValue(kAiModelKey, config.model.trimmed());
    settings.setValue(kAiEndpointKey, config.endpoint.trimmed());
    settings.setValue(kAiOrganizationKey, config.organization.trimmed());
    settings.setValue(kAiProjectKey, config.project.trimmed());
    settings.setValue(kAiFallbackKey, config.fallback_to_heuristics);
    settings.setValue(kAiMaxFunctionsKey, config.max_functions_per_run);
    settings.setValue(kAiTimeoutKey, config.timeout_ms);
    settings.setValue(kAiMaxRequestsPerDayKey, config.max_remote_requests_per_day);
}

QString provider_key(const AiProviderProfile provider) {
    switch (provider) {
    case AiProviderProfile::OpenAI:
        return "openai";
    case AiProviderProfile::Anthropic:
        return "anthropic";
    case AiProviderProfile::Gemini:
        return "gemini";
    case AiProviderProfile::OpenAICompatible:
        return "openai_compatible";
    case AiProviderProfile::LocalLLM:
        return "local_llm";
    case AiProviderProfile::Heuristic:
    default:
        return "heuristic";
    }
}

QString provider_display_name(const AiProviderProfile provider) {
    switch (provider) {
    case AiProviderProfile::OpenAI:
        return "OpenAI";
    case AiProviderProfile::Anthropic:
        return "Anthropic";
    case AiProviderProfile::Gemini:
        return "Gemini";
    case AiProviderProfile::OpenAICompatible:
        return "OpenAI-Compatible";
    case AiProviderProfile::LocalLLM:
        return "Local LLM";
    case AiProviderProfile::Heuristic:
    default:
        return "Heuristic Only";
    }
}

QString provider_help_text(const AiProviderProfile provider) {
    switch (provider) {
    case AiProviderProfile::OpenAI:
        return "Uses the OpenAI Responses API. Best fit when you want hosted model analysis with strict JSON output.";
    case AiProviderProfile::Anthropic:
        return "Uses the Anthropic Messages API. Good fit if your team standardizes on Claude.";
    case AiProviderProfile::Gemini:
        return "Uses the Gemini generateContent API. Useful when your team prefers Google's hosted models.";
    case AiProviderProfile::OpenAICompatible:
        return "Uses a chat-completions style endpoint. Suitable for gateways and compatible hosted providers.";
    case AiProviderProfile::LocalLLM:
        return "Uses a local OpenAI-compatible endpoint such as Ollama or LM Studio. No hosted billing required.";
    case AiProviderProfile::Heuristic:
    default:
        return "Keeps Zara on local heuristic analysis only. No external model requests are made.";
    }
}

QString provider_default_model(const AiProviderProfile provider) {
    switch (provider) {
    case AiProviderProfile::OpenAI:
        return "gpt-5-mini";
    case AiProviderProfile::Anthropic:
        return "claude-sonnet-4-20250514";
    case AiProviderProfile::Gemini:
        return "gemini-2.5-pro";
    case AiProviderProfile::OpenAICompatible:
        return "gpt-4o-mini";
    case AiProviderProfile::LocalLLM:
        return "llama3.1";
    case AiProviderProfile::Heuristic:
    default:
        return {};
    }
}

QString provider_default_endpoint(const AiProviderProfile provider) {
    switch (provider) {
    case AiProviderProfile::OpenAI:
        return "https://api.openai.com/v1/responses";
    case AiProviderProfile::Anthropic:
        return "https://api.anthropic.com/v1/messages";
    case AiProviderProfile::Gemini:
        return "https://generativelanguage.googleapis.com/v1beta/models";
    case AiProviderProfile::OpenAICompatible:
        return "https://your-provider.example/v1/chat/completions";
    case AiProviderProfile::LocalLLM:
        return "http://127.0.0.1:11434/v1/chat/completions";
    case AiProviderProfile::Heuristic:
    default:
        return {};
    }
}

bool provider_requires_api_key(const AiProviderProfile provider) {
    return provider == AiProviderProfile::OpenAI || provider == AiProviderProfile::Anthropic ||
           provider == AiProviderProfile::Gemini || provider == AiProviderProfile::OpenAICompatible;
}

bool provider_uses_remote_billing(const AiProviderProfile provider) {
    return provider == AiProviderProfile::OpenAI || provider == AiProviderProfile::Anthropic ||
           provider == AiProviderProfile::Gemini || provider == AiProviderProfile::OpenAICompatible;
}

QString provider_secret_account(const AiProviderProfile provider) {
    return "ai/" + provider_key(provider);
}

ai::AssistantOptions build_assistant_options(const AiSettings& config, const QString& api_key) {
    ai::AssistantOptions options;
    options.fallback_to_heuristics = config.fallback_to_heuristics;

    const auto model = config.model.trimmed().toStdString();
    const auto endpoint = config.endpoint.trimmed().toStdString();
    const auto secret = api_key.toStdString();

    switch (config.provider) {
    case AiProviderProfile::OpenAI: {
        options.backend = ai::AssistantBackend::OpenAI;
        options.openai = ai::OpenAIOptions{
            .api_key = secret,
            .model = model.empty() ? provider_default_model(config.provider).toStdString() : model,
            .base_url = endpoint.empty() ? provider_default_endpoint(config.provider).toStdString() : endpoint,
            .organization = config.organization.trimmed().toStdString(),
            .project = config.project.trimmed().toStdString(),
            .max_functions = static_cast<std::size_t>(std::max(1, config.max_functions_per_run)),
            .timeout_ms = std::max(1000, config.timeout_ms),
        };
        break;
    }
    case AiProviderProfile::Anthropic: {
        options.backend = ai::AssistantBackend::Anthropic;
        options.anthropic = ai::AnthropicOptions{
            .api_key = secret,
            .model = model.empty() ? provider_default_model(config.provider).toStdString() : model,
            .base_url = endpoint.empty() ? provider_default_endpoint(config.provider).toStdString() : endpoint,
            .max_functions = static_cast<std::size_t>(std::max(1, config.max_functions_per_run)),
            .timeout_ms = std::max(1000, config.timeout_ms),
            .api_version = "2023-06-01",
        };
        break;
    }
    case AiProviderProfile::Gemini: {
        options.backend = ai::AssistantBackend::Gemini;
        options.gemini = ai::GeminiOptions{
            .api_key = secret,
            .model = model.empty() ? provider_default_model(config.provider).toStdString() : model,
            .base_url = endpoint.empty() ? provider_default_endpoint(config.provider).toStdString() : endpoint,
            .max_functions = static_cast<std::size_t>(std::max(1, config.max_functions_per_run)),
            .timeout_ms = std::max(1000, config.timeout_ms),
        };
        break;
    }
    case AiProviderProfile::OpenAICompatible: {
        options.backend = ai::AssistantBackend::OpenAICompatible;
        options.compatible = ai::CompatibleModelOptions{
            .api_key = secret,
            .model = model.empty() ? provider_default_model(config.provider).toStdString() : model,
            .base_url = endpoint.empty() ? provider_default_endpoint(config.provider).toStdString() : endpoint,
            .max_functions = static_cast<std::size_t>(std::max(1, config.max_functions_per_run)),
            .timeout_ms = std::max(1000, config.timeout_ms),
        };
        break;
    }
    case AiProviderProfile::LocalLLM: {
        options.backend = ai::AssistantBackend::LocalLLM;
        options.compatible = ai::CompatibleModelOptions{
            .api_key = secret,
            .model = model.empty() ? provider_default_model(config.provider).toStdString() : model,
            .base_url = endpoint.empty() ? provider_default_endpoint(config.provider).toStdString() : endpoint,
            .max_functions = static_cast<std::size_t>(std::max(1, config.max_functions_per_run)),
            .timeout_ms = std::max(1000, config.timeout_ms),
        };
        break;
    }
    case AiProviderProfile::Heuristic:
    default:
        options.backend = ai::AssistantBackend::Heuristic;
        break;
    }

    return options;
}

bool ai_request_allowed(QSettings& settings, const AiSettings& config, QString& out_message) {
    out_message.clear();
    if (!provider_uses_remote_billing(config.provider) || config.max_remote_requests_per_day <= 0) {
        return true;
    }

    const QString current_day = QDate::currentDate().toString(Qt::ISODate);
    const QString stored_day = settings.value(kAiUsageDayKey).toString();
    int day_count = settings.value(kAiUsageDayCountKey, 0).toInt();
    if (stored_day != current_day) {
        day_count = 0;
    }

    if (day_count >= config.max_remote_requests_per_day) {
        out_message =
            QString("The configured daily AI request cap has been reached for %1. Increase the cap in Settings > AI or wait until tomorrow.")
                .arg(provider_display_name(config.provider));
        return false;
    }
    return true;
}

void record_ai_request_usage(QSettings& settings, const AiSettings& config) {
    if (!provider_uses_remote_billing(config.provider)) {
        return;
    }

    const QString current_day = QDate::currentDate().toString(Qt::ISODate);
    const QString stored_day = settings.value(kAiUsageDayKey).toString();
    int day_count = settings.value(kAiUsageDayCountKey, 0).toInt();
    if (stored_day != current_day) {
        day_count = 0;
    }
    settings.setValue(kAiUsageDayKey, current_day);
    settings.setValue(kAiUsageDayCountKey, day_count + 1);
}

}  // namespace zara::desktop_qt::app
