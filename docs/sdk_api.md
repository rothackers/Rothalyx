# SDK API

Zara exposes a versioned C ABI for external tooling in:

- `core/sdk/include/zara/sdk/api.h`

The ABI is intentionally C-shaped so it can be consumed from Python, Rust, Go, or other FFI targets without leaking internal C++ types into the public surface.

## Version Constants

The public header exports:

- `ZARA_SDK_VERSION_MAJOR`
- `ZARA_SDK_VERSION_MINOR`
- `ZARA_SDK_VERSION_PATCH`
- `ZARA_SDK_ABI_VERSION`
- `ZARA_SDK_PLUGIN_API_VERSION`

## What the SDK Covers

The current SDK can:

- analyze a binary into a persisted project database
- open a project database
- read the latest analysis run overview
- enumerate persisted functions
- enumerate persisted AI insights

## Analyze a Binary

```c
zara_sdk_status_t zara_sdk_analyze_binary(
    const char* binary_path,
    const char* project_db_path,
    const zara_ai_options_t* ai_options,
    char* error_buffer,
    size_t error_buffer_size
);
```

Pass `NULL` for `ai_options` to use local heuristic analysis only.

## Open and Inspect a Project

```c
zara_project_t* project = NULL;
zara_sdk_open_project("sample.sqlite", &project, error, sizeof(error));
zara_sdk_get_latest_run(project, &run, error, sizeof(error));
zara_sdk_get_function_count(project, run.run_id, &count, error, sizeof(error));
zara_sdk_get_function_at(project, run.run_id, 0, &function, error, sizeof(error));
zara_sdk_get_ai_insight_count(project, run.run_id, &count, error, sizeof(error));
zara_sdk_get_ai_insight_at(project, run.run_id, 0, &insight, error, sizeof(error));
zara_sdk_close_project(project);
```

## Lifetime Rules

Strings returned inside SDK result structs are owned by the project handle. They remain valid until:

- the next SDK call that refreshes the same cached collection
- or `zara_sdk_close_project()`

## AI Options

`zara_ai_options_t` supports:

- `backend`
- `api_key`
- `model`
- `base_url`
- `organization`
- `project`
- `max_model_functions`
- `timeout_ms`

Current backend values cover:

- `heuristic`
- `openai`
- `anthropic`
- `gemini`
- `openai_compatible`
- `local_llm`
- `auto`
