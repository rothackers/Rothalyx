add_executable(
    zara_core_smoke
    core_smoke.cpp
)

target_link_libraries(
    zara_core_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_disasm
)

if(MSVC)
    target_compile_options(zara_core_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_core_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_core_raw_fixture
    COMMAND zara_core_smoke ${CMAKE_SOURCE_DIR}/tests/fixtures/sample.bin
)

add_executable(
    zara_safe_parsing_smoke
    safe_parsing_smoke.cpp
)

target_link_libraries(
    zara_safe_parsing_smoke
    PRIVATE
        zara_loader
)

if(MSVC)
    target_compile_options(zara_safe_parsing_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_safe_parsing_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_safe_parsing_fixture
    COMMAND zara_safe_parsing_smoke $<TARGET_FILE:zara_debuggee_fixture>
)

add_executable(
    zara_loader_adversarial_smoke
    loader_adversarial_smoke.cpp
)

target_link_libraries(
    zara_loader_adversarial_smoke
    PRIVATE
        zara_loader
)

if(MSVC)
    target_compile_options(zara_loader_adversarial_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_loader_adversarial_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_loader_adversarial_synthetic
    COMMAND zara_loader_adversarial_smoke
)

add_executable(
    zara_memory_smoke
    memory_smoke.cpp
)

target_link_libraries(
    zara_memory_smoke
    PRIVATE
        zara_memory
)

if(MSVC)
    target_compile_options(zara_memory_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_memory_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_memory_synthetic
    COMMAND zara_memory_smoke
)

add_executable(
    zara_native_analysis_smoke
    native_analysis_smoke.cpp
    ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/app/analysis_runner.cpp
    ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/app/workspace_controller.cpp
    ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/persistence/project_repository.cpp
)

target_include_directories(
    zara_native_analysis_smoke
    PRIVATE
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/include
)

target_link_libraries(
    zara_native_analysis_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_analysis
        zara_database
)

if(TARGET SQLite3::SQLite3)
    target_link_libraries(zara_native_analysis_smoke PRIVATE SQLite3::SQLite3)
elseif(TARGET SQLite::SQLite3)
    target_link_libraries(zara_native_analysis_smoke PRIVATE SQLite::SQLite3)
endif()
if(MSVC)
    target_compile_options(zara_native_analysis_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_native_analysis_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_native_analysis_persistence
    COMMAND zara_native_analysis_smoke $<TARGET_FILE:zara_debuggee_fixture>
)

if(TARGET zara_desktop_qt)
    find_package(Qt6 COMPONENTS Widgets QUIET)
    add_executable(
        zara_ui_flow_highlight_smoke
        ui_flow_highlight_smoke.cpp
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/app/ai_settings.cpp
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/app/analysis_runner.cpp
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/app/secret_store.cpp
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/app/workspace_controller.cpp
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/persistence/project_repository.cpp
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/ui/graph_view.cpp
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/ui/main_window.cpp
    )

    target_include_directories(
        zara_ui_flow_highlight_smoke
        PRIVATE
            ${CMAKE_SOURCE_DIR}/apps/desktop_qt/include
    )

    target_link_libraries(
        zara_ui_flow_highlight_smoke
        PRIVATE
            Qt6::Widgets
            zara_loader
            zara_memory
            zara_analysis
            zara_database
            zara_debugger
    )

    if(TARGET SQLite3::SQLite3)
        target_link_libraries(zara_ui_flow_highlight_smoke PRIVATE SQLite3::SQLite3)
    elseif(TARGET SQLite::SQLite3)
        target_link_libraries(zara_ui_flow_highlight_smoke PRIVATE SQLite::SQLite3)
    endif()
    if(WIN32)
        target_link_libraries(zara_ui_flow_highlight_smoke PRIVATE Advapi32)
    endif()

    if(MSVC)
        target_compile_options(zara_ui_flow_highlight_smoke PRIVATE /W4 /permissive-)
    else()
        target_compile_options(zara_ui_flow_highlight_smoke PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(
        NAME zara_ui_flow_highlight_synthetic
        COMMAND zara_ui_flow_highlight_smoke
    )

    add_executable(
        zara_ui_debugger_polish_smoke
        ui_debugger_polish_smoke.cpp
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/app/ai_settings.cpp
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/app/analysis_runner.cpp
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/app/secret_store.cpp
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/app/workspace_controller.cpp
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/persistence/project_repository.cpp
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/ui/graph_view.cpp
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/ui/main_window.cpp
    )

    target_include_directories(
        zara_ui_debugger_polish_smoke
        PRIVATE
            ${CMAKE_SOURCE_DIR}/apps/desktop_qt/include
    )

    target_link_libraries(
        zara_ui_debugger_polish_smoke
        PRIVATE
            Qt6::Widgets
            zara_loader
            zara_memory
            zara_analysis
            zara_database
            zara_debugger
    )

    if(TARGET SQLite3::SQLite3)
        target_link_libraries(zara_ui_debugger_polish_smoke PRIVATE SQLite3::SQLite3)
    elseif(TARGET SQLite::SQLite3)
        target_link_libraries(zara_ui_debugger_polish_smoke PRIVATE SQLite::SQLite3)
    endif()
    if(WIN32)
        target_link_libraries(zara_ui_debugger_polish_smoke PRIVATE Advapi32)
    endif()

    if(MSVC)
        target_compile_options(zara_ui_debugger_polish_smoke PRIVATE /W4 /permissive-)
    else()
        target_compile_options(zara_ui_debugger_polish_smoke PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(
        NAME zara_ui_debugger_polish_synthetic
        COMMAND zara_ui_debugger_polish_smoke
    )
endif()

add_executable(
    zara_architecture_smoke
    architecture_smoke.cpp
)

target_link_libraries(
    zara_architecture_smoke
    PRIVATE
        zara_disasm
)

if(MSVC)
    target_compile_options(zara_architecture_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_architecture_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_architecture_synthetic
    COMMAND zara_architecture_smoke
)

add_executable(
    zara_mips_ppc_loader_smoke
    mips_ppc_loader_smoke.cpp
)

target_link_libraries(
    zara_mips_ppc_loader_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_disasm
        zara_analysis
)

if(MSVC)
    target_compile_options(zara_mips_ppc_loader_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_mips_ppc_loader_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_mips_ppc_loader_synthetic
    COMMAND zara_mips_ppc_loader_smoke
)

add_executable(
    zara_riscv_loader_smoke
    riscv_loader_smoke.cpp
)

target_link_libraries(
    zara_riscv_loader_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_disasm
        zara_analysis
)

if(MSVC)
    target_compile_options(zara_riscv_loader_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_riscv_loader_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_riscv_loader_synthetic
    COMMAND zara_riscv_loader_smoke
)

add_executable(
    zara_arm_pe_loader_smoke
    arm_pe_loader_smoke.cpp
)

target_link_libraries(
    zara_arm_pe_loader_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_disasm
        zara_analysis
)

if(MSVC)
    target_compile_options(zara_arm_pe_loader_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_arm_pe_loader_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_arm_pe_loader_synthetic
    COMMAND zara_arm_pe_loader_smoke
)

add_executable(
    zara_debuggee_fixture
    debuggee_fixture.cpp
)

if(MSVC)
    target_compile_options(zara_debuggee_fixture PRIVATE /W4 /permissive- /Od)
else()
    target_compile_options(zara_debuggee_fixture PRIVATE -Wall -Wextra -Wpedantic -O0)
    target_link_options(zara_debuggee_fixture PRIVATE -no-pie)
    target_compile_options(zara_debuggee_fixture PRIVATE -fno-pie)
endif()

add_executable(
    zara_threaded_debuggee_fixture
    threaded_debuggee_fixture.cpp
)

if(MSVC)
    target_compile_options(zara_threaded_debuggee_fixture PRIVATE /W4 /permissive- /Od)
else()
    target_compile_options(zara_threaded_debuggee_fixture PRIVATE -Wall -Wextra -Wpedantic -O0)
    target_link_options(zara_threaded_debuggee_fixture PRIVATE -no-pie)
    target_compile_options(zara_threaded_debuggee_fixture PRIVATE -fno-pie)
endif()

add_executable(
    zara_debugger_launch_smoke
    debugger_launch_smoke.cpp
)

target_link_libraries(
    zara_debugger_launch_smoke
    PRIVATE
        zara_loader
        zara_debugger
)

if(MSVC)
    target_compile_options(zara_debugger_launch_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_debugger_launch_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(
    zara_debugger_live_patch_smoke
    debugger_live_patch_smoke.cpp
)

target_link_libraries(
    zara_debugger_live_patch_smoke
    PRIVATE
        zara_loader
        zara_debugger
)

if(MSVC)
    target_compile_options(zara_debugger_live_patch_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_debugger_live_patch_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(
    zara_debugger_attach_smoke
    debugger_attach_smoke.cpp
)

target_link_libraries(
    zara_debugger_attach_smoke
    PRIVATE
        zara_debugger
)

if(MSVC)
    target_compile_options(zara_debugger_attach_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_debugger_attach_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(
    zara_debugger_target_shape_smoke
    debugger_target_shape_smoke.cpp
)

target_link_libraries(
    zara_debugger_target_shape_smoke
    PRIVATE
        zara_debugger
)

if(MSVC)
    target_compile_options(zara_debugger_target_shape_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_debugger_target_shape_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_debugger_target_shapes
    COMMAND zara_debugger_target_shape_smoke
)

if(UNIX OR WIN32)
    add_test(
        NAME zara_debugger_launch_synthetic
        COMMAND zara_debugger_launch_smoke $<TARGET_FILE:zara_debuggee_fixture>
    )

    add_test(
        NAME zara_debugger_live_patch_synthetic
        COMMAND zara_debugger_live_patch_smoke $<TARGET_FILE:zara_debuggee_fixture>
    )

    add_executable(
        zara_debugger_integration_smoke
        debugger_integration_smoke.cpp
    )

    target_link_libraries(
        zara_debugger_integration_smoke
        PRIVATE
            zara_loader
            zara_memory
            zara_analysis
            zara_debugger
    )

    if(MSVC)
        target_compile_options(zara_debugger_integration_smoke PRIVATE /W4 /permissive-)
    else()
        target_compile_options(zara_debugger_integration_smoke PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(
        NAME zara_debugger_integration_synthetic
        COMMAND zara_debugger_integration_smoke $<TARGET_FILE:zara_debuggee_fixture>
    )
endif()

if(UNIX)
    add_test(
        NAME zara_debugger_attach_synthetic
        COMMAND zara_debugger_attach_smoke $<TARGET_FILE:zara_debuggee_fixture>
    )

    add_executable(
        zara_debugger_threads_smoke
        debugger_threads_smoke.cpp
    )

    target_link_libraries(
        zara_debugger_threads_smoke
        PRIVATE
            zara_debugger
    )

    if(MSVC)
        target_compile_options(zara_debugger_threads_smoke PRIVATE /W4 /permissive-)
    else()
        target_compile_options(zara_debugger_threads_smoke PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(
        NAME zara_debugger_threads_synthetic
        COMMAND zara_debugger_threads_smoke $<TARGET_FILE:zara_threaded_debuggee_fixture>
    )

    if(TARGET zara_cli)
        add_test(
            NAME zara_debugger_shell_scripted
            COMMAND
                $<TARGET_FILE:zara_cli>
                debug-shell
                $<TARGET_FILE:zara_debuggee_fixture>
                --script
                ${CMAKE_SOURCE_DIR}/tests/fixtures/debug_shell_commands.txt
        )
    endif()
endif()

if(TARGET zara_scripting)
    add_executable(
        zara_scripting_smoke
        scripting_smoke.cpp
    )

    target_link_libraries(
        zara_scripting_smoke
        PRIVATE
            zara_scripting
    )

    if(MSVC)
        target_compile_options(zara_scripting_smoke PRIVATE /W4 /permissive-)
    else()
        target_compile_options(zara_scripting_smoke PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(
        NAME zara_scripting_synthetic
        COMMAND zara_scripting_smoke $<TARGET_FILE:zara_debuggee_fixture>
    )

    add_executable(
        zara_scripting_concurrency_smoke
        scripting_concurrency_smoke.cpp
    )

    target_link_libraries(
        zara_scripting_concurrency_smoke
        PRIVATE
            zara_scripting
    )

    if(MSVC)
        target_compile_options(zara_scripting_concurrency_smoke PRIVATE /W4 /permissive-)
    else()
        target_compile_options(zara_scripting_concurrency_smoke PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(
        NAME zara_scripting_concurrency_synthetic
        COMMAND zara_scripting_concurrency_smoke $<TARGET_FILE:zara_debuggee_fixture>
    )

    if(UNIX)
        add_executable(
            zara_distributed_scripting_smoke
            distributed_scripting_smoke.cpp
        )

        target_link_libraries(
            zara_distributed_scripting_smoke
            PRIVATE
                zara_scripting
        )

        if(MSVC)
            target_compile_options(zara_distributed_scripting_smoke PRIVATE /W4 /permissive-)
        else()
            target_compile_options(zara_distributed_scripting_smoke PRIVATE -Wall -Wextra -Wpedantic)
        endif()

        add_test(
            NAME zara_distributed_scripting_python
            COMMAND zara_distributed_scripting_smoke $<TARGET_FILE:zara_debuggee_fixture> $<TARGET_FILE:zara_debuggee_fixture>
        )
    endif()

add_executable(
        zara_plugin_smoke
        plugin_smoke.cpp
)

    target_link_libraries(
        zara_plugin_smoke
        PRIVATE
            zara_plugins
    )

    if(MSVC)
        target_compile_options(zara_plugin_smoke PRIVATE /W4 /permissive-)
    else()
        target_compile_options(zara_plugin_smoke PRIVATE -Wall -Wextra -Wpedantic)
    endif()

add_test(
        NAME zara_plugin_synthetic
        COMMAND
            zara_plugin_smoke
            ${CMAKE_SOURCE_DIR}/tests/plugin_fixtures
            $<TARGET_FILE:zara_debuggee_fixture>
)

add_executable(
        zara_plugin_sandbox_smoke
        plugin_sandbox_smoke.cpp
)
target_link_libraries(
        zara_plugin_sandbox_smoke
        PRIVATE
            zara_plugins
)
if(MSVC)
        target_compile_options(zara_plugin_sandbox_smoke PRIVATE /W4 /permissive-)
else()
        target_compile_options(zara_plugin_sandbox_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
        NAME zara_plugin_sandbox_synthetic
        COMMAND
            zara_plugin_sandbox_smoke
            ${CMAKE_SOURCE_DIR}/tests/plugin_sandbox_fixtures
)

add_executable(
        zara_plugin_policy_smoke
        plugin_policy_smoke.cpp
)
target_link_libraries(
        zara_plugin_policy_smoke
        PRIVATE
            zara_plugins
)
if(MSVC)
        target_compile_options(zara_plugin_policy_smoke PRIVATE /W4 /permissive-)
else()
        target_compile_options(zara_plugin_policy_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
        NAME zara_plugin_policy_synthetic
        COMMAND
            zara_plugin_policy_smoke
            ${CMAKE_SOURCE_DIR}/tests/plugin_policy_fixtures/denied_allowlist
            ${CMAKE_SOURCE_DIR}/tests/plugin_policy_fixtures/unsandboxed_plugin
)

add_executable(
        zara_plugin_marketplace_smoke
        plugin_marketplace_smoke.cpp
)
    target_link_libraries(
        zara_plugin_marketplace_smoke
        PRIVATE
            zara_plugins
    )
    if(MSVC)
        target_compile_options(zara_plugin_marketplace_smoke PRIVATE /W4 /permissive-)
    else()
        target_compile_options(zara_plugin_marketplace_smoke PRIVATE -Wall -Wextra -Wpedantic)
    endif()

add_test(
        NAME zara_plugin_marketplace_synthetic
        COMMAND
            zara_plugin_marketplace_smoke
            ${CMAKE_SOURCE_DIR}/tests/plugin_marketplace_fixtures
            $<TARGET_FILE:zara_debuggee_fixture>
)
endif()

if(UNIX AND EXISTS "/bin/ls")
    add_test(
        NAME zara_core_system_elf
        COMMAND zara_core_smoke /bin/ls
    )
endif()

add_executable(
    zara_analysis_smoke
    analysis_smoke.cpp
)

target_link_libraries(
    zara_analysis_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_disasm
        zara_cfg
        zara_xrefs
)

if(MSVC)
    target_compile_options(zara_analysis_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_analysis_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_analysis_synthetic
    COMMAND zara_analysis_smoke
)

add_executable(
    zara_cfg_advanced_smoke
    cfg_advanced_smoke.cpp
)

target_link_libraries(
    zara_cfg_advanced_smoke
    PRIVATE
        zara_cfg
        zara_memory
)

if(MSVC)
    target_compile_options(zara_cfg_advanced_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_cfg_advanced_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_cfg_advanced_synthetic
    COMMAND zara_cfg_advanced_smoke
)

add_executable(
    zara_program_smoke
    program_smoke.cpp
)

target_link_libraries(
    zara_program_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_cfg
        zara_xrefs
        zara_analysis
)

if(MSVC)
    target_compile_options(zara_program_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_program_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_program_synthetic
    COMMAND zara_program_smoke
)

add_executable(
    zara_analysis_engine_smoke
    analysis_engine_smoke.cpp
)

target_link_libraries(
    zara_analysis_engine_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_analysis
)

if(MSVC)
    target_compile_options(zara_analysis_engine_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_analysis_engine_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_analysis_engine_synthetic
    COMMAND zara_analysis_engine_smoke
)

add_executable(
    zara_optimizer_smoke
    optimizer_smoke.cpp
)

target_link_libraries(
    zara_optimizer_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_analysis
        zara_ssa
)

if(MSVC)
    target_compile_options(zara_optimizer_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_optimizer_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_optimizer_synthetic
    COMMAND zara_optimizer_smoke
)

add_executable(
    zara_function_discovery_smoke
    function_discovery_smoke.cpp
)

target_link_libraries(
    zara_function_discovery_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_analysis
)

if(MSVC)
    target_compile_options(zara_function_discovery_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_function_discovery_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_function_discovery_synthetic
    COMMAND zara_function_discovery_smoke
)

add_executable(
    zara_signature_detection_smoke
    signature_detection_smoke.cpp
)

target_link_libraries(
    zara_signature_detection_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_analysis
)

if(MSVC)
    target_compile_options(zara_signature_detection_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_signature_detection_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_signature_detection_synthetic
    COMMAND zara_signature_detection_smoke
)

add_executable(
    zara_ir_smoke
    ir_smoke.cpp
)

target_link_libraries(
    zara_ir_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_cfg
        zara_xrefs
        zara_ir
        zara_analysis
)

if(MSVC)
    target_compile_options(zara_ir_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_ir_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_ir_synthetic
    COMMAND zara_ir_smoke
)

add_executable(
    zara_ssa_smoke
    ssa_smoke.cpp
)

target_link_libraries(
    zara_ssa_smoke
    PRIVATE
        zara_ir
        zara_ssa
)

if(MSVC)
    target_compile_options(zara_ssa_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_ssa_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_ssa_synthetic
    COMMAND zara_ssa_smoke
)

add_executable(
    zara_type_smoke
    type_smoke.cpp
)

target_link_libraries(
    zara_type_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_cfg
        zara_xrefs
        zara_ir
        zara_ssa
        zara_type
        zara_analysis
)

if(MSVC)
    target_compile_options(zara_type_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_type_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_type_synthetic
    COMMAND zara_type_smoke
)

add_executable(
    zara_composite_type_smoke
    composite_type_smoke.cpp
)

target_link_libraries(
    zara_composite_type_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_cfg
        zara_xrefs
        zara_ir
        zara_ssa
        zara_type
        zara_analysis
)

if(MSVC)
    target_compile_options(zara_composite_type_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_composite_type_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_composite_type_synthetic
    COMMAND zara_composite_type_smoke
)

add_executable(
    zara_lazy_cache_smoke
    lazy_cache_smoke.cpp
)

target_link_libraries(
    zara_lazy_cache_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_cfg
        zara_xrefs
        zara_ir
        zara_ssa
        zara_type
        zara_decompiler
        zara_analysis
)

if(MSVC)
    target_compile_options(zara_lazy_cache_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_lazy_cache_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_lazy_cache_synthetic
    COMMAND zara_lazy_cache_smoke
)

add_executable(
    zara_decompiler_smoke
    decompiler_smoke.cpp
)

target_link_libraries(
    zara_decompiler_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_cfg
        zara_xrefs
        zara_ir
        zara_ssa
        zara_type
        zara_decompiler
        zara_analysis
)

if(MSVC)
    target_compile_options(zara_decompiler_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_decompiler_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_decompiler_synthetic
    COMMAND zara_decompiler_smoke
)

add_executable(
    zara_decompiler_structured_smoke
    decompiler_structured_smoke.cpp
)

target_link_libraries(
    zara_decompiler_structured_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_cfg
        zara_xrefs
        zara_ir
        zara_ssa
        zara_type
        zara_decompiler
        zara_analysis
)

if(MSVC)
    target_compile_options(zara_decompiler_structured_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_decompiler_structured_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_decompiler_structured_synthetic
    COMMAND zara_decompiler_structured_smoke
)

add_executable(
    zara_decompiler_maturity_smoke
    decompiler_maturity_smoke.cpp
)

target_link_libraries(
    zara_decompiler_maturity_smoke
    PRIVATE
        zara_cfg
        zara_ir
        zara_ssa
        zara_type
        zara_decompiler
)

if(MSVC)
    target_compile_options(zara_decompiler_maturity_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_decompiler_maturity_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_decompiler_maturity_synthetic
    COMMAND zara_decompiler_maturity_smoke
)

add_executable(
    zara_interprocedural_semantics_smoke
    interprocedural_semantics_smoke.cpp
)

target_link_libraries(
    zara_interprocedural_semantics_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_analysis
        zara_type
        zara_decompiler
)

if(MSVC)
    target_compile_options(zara_interprocedural_semantics_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_interprocedural_semantics_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_interprocedural_semantics_synthetic
    COMMAND zara_interprocedural_semantics_smoke
)

add_executable(
    zara_ai_smoke
    ai_smoke.cpp
)

target_link_libraries(
    zara_ai_smoke
    PRIVATE
        zara_ai
)

if(MSVC)
    target_compile_options(zara_ai_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_ai_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_ai_synthetic
    COMMAND zara_ai_smoke
)

add_executable(
    zara_ai_model_smoke
    ai_model_smoke.cpp
)

target_link_libraries(
    zara_ai_model_smoke
    PRIVATE
        zara_ai
)

if(MSVC)
    target_compile_options(zara_ai_model_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_ai_model_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_ai_model_synthetic
    COMMAND zara_ai_model_smoke
)

add_executable(
    zara_security_smoke
    security_smoke.cpp
)

target_link_libraries(
    zara_security_smoke
    PRIVATE
        zara_security
)

if(MSVC)
    target_compile_options(zara_security_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_security_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_security_synthetic
    COMMAND zara_security_smoke
)

add_executable(
    zara_fuzz_live_smoke
    fuzz_live_smoke.cpp
)

target_link_libraries(
    zara_fuzz_live_smoke
    PRIVATE
        zara_security
)

if(MSVC)
    target_compile_options(zara_fuzz_live_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_fuzz_live_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_fuzz_live_synthetic
    COMMAND zara_fuzz_live_smoke
)

add_executable(
    zara_database_persistence_smoke
    database_persistence_smoke.cpp
)

target_link_libraries(
    zara_database_persistence_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_analysis
        zara_database
)

if(MSVC)
    target_compile_options(zara_database_persistence_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_database_persistence_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_database_persistence_synthetic
    COMMAND zara_database_persistence_smoke $<TARGET_FILE:zara_debuggee_fixture>
)

add_executable(
    zara_sdk_smoke
    sdk_smoke.cpp
)

target_link_libraries(
    zara_sdk_smoke
    PRIVATE
        zara_sdk
)

if(MSVC)
    target_compile_options(zara_sdk_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_sdk_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_sdk_public_api
    COMMAND zara_sdk_smoke $<TARGET_FILE:zara_debuggee_fixture>
)

add_executable(
    zara_project_workflow_smoke
    project_workflow_smoke.cpp
    ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/persistence/project_repository.cpp
)

target_include_directories(
    zara_project_workflow_smoke
    PRIVATE
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/include
)

target_link_libraries(
    zara_project_workflow_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_analysis
        zara_database
        zara_security
)

if(TARGET SQLite3::SQLite3)
    target_link_libraries(zara_project_workflow_smoke PRIVATE SQLite3::SQLite3)
elseif(TARGET SQLite::SQLite3)
    target_link_libraries(zara_project_workflow_smoke PRIVATE SQLite::SQLite3)
endif()

if(MSVC)
    target_compile_options(zara_project_workflow_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_project_workflow_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_project_workflow_synthetic
    COMMAND zara_project_workflow_smoke $<TARGET_FILE:zara_debuggee_fixture>
)

add_executable(
    zara_distributed_smoke
    distributed_smoke.cpp
)

target_link_libraries(
    zara_distributed_smoke
    PRIVATE
        zara_distributed
)

if(MSVC)
    target_compile_options(zara_distributed_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_distributed_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_distributed_synthetic
    COMMAND
        zara_distributed_smoke
        ${CMAKE_SOURCE_DIR}/tests/fixtures/sample.bin
        $<TARGET_FILE:zara_debuggee_fixture>
)

add_executable(
    zara_distributed_remote_smoke
    distributed_remote_smoke.cpp
)

target_link_libraries(
    zara_distributed_remote_smoke
    PRIVATE
        zara_distributed
)

if(MSVC)
    target_compile_options(zara_distributed_remote_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_distributed_remote_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_distributed_remote_synthetic
    COMMAND
        zara_distributed_remote_smoke
        ${CMAKE_SOURCE_DIR}/tests/fixtures/sample.bin
        $<TARGET_FILE:zara_debuggee_fixture>
)

add_executable(
    zara_distributed_auth_smoke
    distributed_auth_smoke.cpp
)

target_link_libraries(
    zara_distributed_auth_smoke
    PRIVATE
        zara_distributed
)

if(MSVC)
    target_compile_options(zara_distributed_auth_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_distributed_auth_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_distributed_auth_synthetic
    COMMAND
        zara_distributed_auth_smoke
        ${CMAKE_SOURCE_DIR}/tests/fixtures/sample.bin
)

add_executable(
    zara_distributed_tls_smoke
    distributed_tls_smoke.cpp
)

target_link_libraries(
    zara_distributed_tls_smoke
    PRIVATE
        zara_distributed
)

if(MSVC)
    target_compile_options(zara_distributed_tls_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_distributed_tls_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_distributed_tls_synthetic
    COMMAND
        zara_distributed_tls_smoke
        ${CMAKE_SOURCE_DIR}/tests/fixtures/sample.bin
)

add_executable(
    zara_distributed_protocol_abuse_smoke
    distributed_protocol_abuse_smoke.cpp
)

target_link_libraries(
    zara_distributed_protocol_abuse_smoke
    PRIVATE
        zara_distributed
)

if(MSVC)
    target_compile_options(zara_distributed_protocol_abuse_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_distributed_protocol_abuse_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_distributed_protocol_abuse_synthetic
    COMMAND
        zara_distributed_protocol_abuse_smoke
        ${CMAKE_SOURCE_DIR}/tests/fixtures/sample.bin
)

add_executable(
    zara_diff_smoke
    diff_smoke.cpp
)

target_link_libraries(
    zara_diff_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_cfg
        zara_xrefs
        zara_ir
        zara_ssa
        zara_type
        zara_decompiler
        zara_analysis
        zara_diff
)

if(MSVC)
    target_compile_options(zara_diff_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_diff_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_diff_synthetic
    COMMAND zara_diff_smoke
)

add_executable(
    zara_pe_loader_smoke
    pe_loader_smoke.cpp
)

target_link_libraries(
    zara_pe_loader_smoke
    PRIVATE
        zara_loader
)

if(MSVC)
    target_compile_options(zara_pe_loader_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_pe_loader_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_pe_loader_synthetic
    COMMAND zara_pe_loader_smoke
)

add_executable(
    zara_pe_rebase_smoke
    pe_rebase_smoke.cpp
)

target_link_libraries(
    zara_pe_rebase_smoke
    PRIVATE
        zara_loader
)

if(MSVC)
    target_compile_options(zara_pe_rebase_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_pe_rebase_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_pe_rebase_synthetic
    COMMAND zara_pe_rebase_smoke
)

add_executable(
    zara_macho_loader_smoke
    macho_loader_smoke.cpp
)

target_link_libraries(
    zara_macho_loader_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_disasm
)

if(MSVC)
    target_compile_options(zara_macho_loader_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_macho_loader_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_macho_loader_synthetic
    COMMAND zara_macho_loader_smoke
)

add_executable(
    zara_macho_chained_fixups_smoke
    macho_chained_fixups_smoke.cpp
)

target_link_libraries(
    zara_macho_chained_fixups_smoke
    PRIVATE
        zara_loader
        zara_memory
)

if(MSVC)
    target_compile_options(zara_macho_chained_fixups_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_macho_chained_fixups_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_macho_chained_fixups_synthetic
    COMMAND zara_macho_chained_fixups_smoke
)

add_executable(
    zara_macho_chained_fixups_matrix_smoke
    macho_chained_fixups_matrix_smoke.cpp
)

target_link_libraries(
    zara_macho_chained_fixups_matrix_smoke
    PRIVATE
        zara_loader
)

if(MSVC)
    target_compile_options(zara_macho_chained_fixups_matrix_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_macho_chained_fixups_matrix_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME zara_macho_chained_fixups_matrix_synthetic
    COMMAND zara_macho_chained_fixups_matrix_smoke
)

add_executable(
    zara_import_smoke
    import_smoke.cpp
)

target_link_libraries(
    zara_import_smoke
    PRIVATE
        zara_loader
        zara_memory
        zara_cfg
        zara_xrefs
        zara_analysis
)

if(MSVC)
    target_compile_options(zara_import_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_import_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(UNIX AND EXISTS "/bin/ls")
    add_test(
        NAME zara_import_system_elf
        COMMAND zara_import_smoke /bin/ls
    )
endif()
