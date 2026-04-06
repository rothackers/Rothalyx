#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZARA_SDK_VERSION_MAJOR 1
#define ZARA_SDK_VERSION_MINOR 0
#define ZARA_SDK_VERSION_PATCH 0
#define ZARA_SDK_ABI_VERSION 1
#define ZARA_SDK_PLUGIN_API_VERSION "1"

typedef enum zara_sdk_status_t {
    ZARA_SDK_STATUS_OK = 0,
    ZARA_SDK_STATUS_INVALID_ARGUMENT = 1,
    ZARA_SDK_STATUS_NOT_FOUND = 2,
    ZARA_SDK_STATUS_UNSUPPORTED = 3,
    ZARA_SDK_STATUS_ERROR = 4
} zara_sdk_status_t;

typedef struct zara_project zara_project_t;

typedef struct zara_ai_options_t {
    const char* backend;
    const char* api_key;
    const char* model;
    const char* base_url;
    const char* organization;
    const char* project;
    size_t max_model_functions;
    long timeout_ms;
} zara_ai_options_t;

typedef struct zara_run_overview_t {
    int run_id;
    const char* binary_path;
    const char* binary_format;
    const char* architecture;
    uint64_t base_address;
    int has_entry_point;
    uint64_t entry_point;
    int section_count;
    int function_count;
    int import_count;
    int export_count;
    int xref_count;
    int string_count;
    const char* ai_backend;
    const char* ai_model;
    const char* poc_scaffold;
} zara_run_overview_t;

typedef struct zara_function_record_t {
    const char* name;
    const char* section_name;
    uint64_t entry_address;
    uint64_t start_address;
    uint64_t end_address;
    int block_count;
    int instruction_count;
    const char* decompiled_pseudocode;
    const char* analysis_summary;
} zara_function_record_t;

typedef struct zara_ai_insight_record_t {
    uint64_t function_entry;
    const char* current_name;
    const char* suggested_name;
    const char* summary;
    const char* hints;
    const char* patterns;
    const char* vulnerability_hints;
} zara_ai_insight_record_t;

const char* zara_sdk_version_string(void);
uint32_t zara_sdk_abi_version(void);
const char* zara_sdk_supported_plugin_api_version(void);
const char* zara_sdk_status_string(zara_sdk_status_t status);

zara_sdk_status_t zara_sdk_analyze_binary(
    const char* binary_path,
    const char* project_db_path,
    const zara_ai_options_t* ai_options,
    char* error_buffer,
    size_t error_buffer_size
);

zara_sdk_status_t zara_sdk_open_project(
    const char* project_db_path,
    zara_project_t** out_project,
    char* error_buffer,
    size_t error_buffer_size
);

void zara_sdk_close_project(zara_project_t* project);

zara_sdk_status_t zara_sdk_get_latest_run(
    zara_project_t* project,
    zara_run_overview_t* out_run,
    char* error_buffer,
    size_t error_buffer_size
);

zara_sdk_status_t zara_sdk_get_function_count(
    zara_project_t* project,
    int run_id,
    size_t* out_count,
    char* error_buffer,
    size_t error_buffer_size
);

zara_sdk_status_t zara_sdk_get_function_at(
    zara_project_t* project,
    int run_id,
    size_t index,
    zara_function_record_t* out_function,
    char* error_buffer,
    size_t error_buffer_size
);

zara_sdk_status_t zara_sdk_get_ai_insight_count(
    zara_project_t* project,
    int run_id,
    size_t* out_count,
    char* error_buffer,
    size_t error_buffer_size
);

zara_sdk_status_t zara_sdk_get_ai_insight_at(
    zara_project_t* project,
    int run_id,
    size_t index,
    zara_ai_insight_record_t* out_insight,
    char* error_buffer,
    size_t error_buffer_size
);

#ifdef __cplusplus
}
#endif
