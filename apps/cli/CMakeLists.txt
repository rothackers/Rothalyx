add_executable(
    zara_cli
    src/main.cpp
)

target_link_libraries(
    zara_cli
    PRIVATE
        zara_loader
        zara_memory
        zara_disasm
        zara_cfg
        zara_xrefs
        zara_debugger
        zara_scripting
        zara_plugins
        zara_diff
        zara_ai
        zara_security
        zara_distributed
        zara_database
)

if(MSVC)
    target_compile_options(zara_cli PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_cli PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(BUILD_TESTING)
    add_test(
        NAME zara_cli_smoke
        COMMAND
            zara_cli
            ${CMAKE_SOURCE_DIR}/tests/fixtures/sample.bin
            ${CMAKE_BINARY_DIR}/zara_cli_smoke.sqlite
    )
endif()

install(
    TARGETS
        zara_cli
    RUNTIME DESTINATION
        ${CMAKE_INSTALL_BINDIR}
)
