find_package(SQLite3 QUIET)
find_package(unofficial-sqlite3 CONFIG QUIET)
find_package(Python3 COMPONENTS Development QUIET)
find_package(PkgConfig QUIET)
find_package(Threads QUIET)
find_package(CURL QUIET)
find_package(OpenSSL QUIET)
find_package(capstone CONFIG QUIET)

if(PkgConfig_FOUND)
    pkg_check_modules(CAPSTONE QUIET capstone)
endif()

find_path(
    ZARA_CAPSTONE_INCLUDE_DIR
    NAMES capstone/capstone.h capstone.h
    HINTS ${CAPSTONE_INCLUDE_DIRS}
    PATH_SUFFIXES include
)

find_library(
    ZARA_CAPSTONE_LIBRARY
    NAMES capstone
    HINTS ${CAPSTONE_LIBRARY_DIRS}
    PATH_SUFFIXES lib
)

if(SQLite3_FOUND OR TARGET SQLite3::SQLite3 OR TARGET SQLite::SQLite3 OR TARGET unofficial::sqlite3::sqlite3)
    if(NOT TARGET zara_sqlite_dep)
        add_library(zara_sqlite_dep INTERFACE)
    endif()

    if(TARGET SQLite3::SQLite3)
        target_link_libraries(zara_sqlite_dep INTERFACE SQLite3::SQLite3)
    elseif(TARGET SQLite::SQLite3)
        target_link_libraries(zara_sqlite_dep INTERFACE SQLite::SQLite3)
    elseif(TARGET unofficial::sqlite3::sqlite3)
        target_link_libraries(zara_sqlite_dep INTERFACE unofficial::sqlite3::sqlite3)
    endif()
endif()

if(TARGET capstone::capstone OR TARGET Capstone::Capstone OR CAPSTONE_FOUND)
    if(NOT TARGET zara_capstone_dep)
        add_library(zara_capstone_dep INTERFACE)
    endif()

    if(TARGET capstone::capstone)
        target_link_libraries(zara_capstone_dep INTERFACE capstone::capstone)
    elseif(TARGET Capstone::Capstone)
        target_link_libraries(zara_capstone_dep INTERFACE Capstone::Capstone)
    elseif(CAPSTONE_FOUND)
        set(zara_capstone_include_dirs "")
        foreach(include_dir IN LISTS CAPSTONE_INCLUDE_DIRS)
            if(EXISTS "${include_dir}/capstone.h")
                get_filename_component(include_parent "${include_dir}" DIRECTORY)
                list(APPEND zara_capstone_include_dirs "${include_parent}")
            else()
                list(APPEND zara_capstone_include_dirs "${include_dir}")
            endif()
        endforeach()

        if(NOT zara_capstone_include_dirs AND ZARA_CAPSTONE_INCLUDE_DIR)
            list(APPEND zara_capstone_include_dirs "${ZARA_CAPSTONE_INCLUDE_DIR}")
        endif()

        list(REMOVE_DUPLICATES zara_capstone_include_dirs)
        if(zara_capstone_include_dirs)
            target_include_directories(zara_capstone_dep INTERFACE ${zara_capstone_include_dirs})
        endif()

        if(CAPSTONE_LIBRARY_DIRS)
            target_link_directories(zara_capstone_dep INTERFACE ${CAPSTONE_LIBRARY_DIRS})
        endif()

        if(CAPSTONE_LINK_LIBRARIES)
            target_link_libraries(zara_capstone_dep INTERFACE ${CAPSTONE_LINK_LIBRARIES})
        elseif(CAPSTONE_LIBRARIES)
            target_link_libraries(zara_capstone_dep INTERFACE ${CAPSTONE_LIBRARIES})
        elseif(ZARA_CAPSTONE_LIBRARY)
            target_link_libraries(zara_capstone_dep INTERFACE ${ZARA_CAPSTONE_LIBRARY})
        endif()
    endif()
elseif(ZARA_CAPSTONE_INCLUDE_DIR AND ZARA_CAPSTONE_LIBRARY)
    add_library(zara_capstone_dep INTERFACE)
    target_include_directories(zara_capstone_dep INTERFACE "${ZARA_CAPSTONE_INCLUDE_DIR}")
    target_link_libraries(zara_capstone_dep INTERFACE "${ZARA_CAPSTONE_LIBRARY}")
endif()

function(zara_apply_defaults target_name)
    target_compile_features(${target_name} PUBLIC cxx_std_20)

    if(WIN32)
        target_compile_definitions(${target_name} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    endif()

    if(MSVC)
        target_compile_options(${target_name} PRIVATE /W4 /permissive-)
    else()
        target_compile_options(${target_name} PRIVATE -Wall -Wextra -Wpedantic)
        if(ZARA_ENABLE_SANITIZERS)
            target_compile_options(${target_name} PRIVATE -fno-omit-frame-pointer -fsanitize=address,undefined)
            target_link_options(${target_name} PRIVATE -fsanitize=address,undefined)
        endif()
    endif()
endfunction()

add_library(
    zara_loader STATIC
    loader/src/binary_image.cpp
)
target_include_directories(
    zara_loader
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/loader/include
)
zara_apply_defaults(zara_loader)

add_library(
    zara_memory STATIC
    memory/src/address_space.cpp
)
target_include_directories(
    zara_memory
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/memory/include
)
target_link_libraries(zara_memory PUBLIC zara_loader)
zara_apply_defaults(zara_memory)

add_library(
    zara_debugger STATIC
    debugger/src/native_session.cpp
    debugger/src/integration.cpp
)
if(WIN32)
    target_sources(
        zara_debugger
        PRIVATE
            debugger/src/native_session_windows.cpp
    )
elseif(APPLE)
    target_sources(
        zara_debugger
        PRIVATE
            debugger/src/native_session_macos.cpp
    )
endif()
target_include_directories(
    zara_debugger
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/debugger/include
)
zara_apply_defaults(zara_debugger)

add_library(
    zara_scripting STATIC
    scripting/src/python_engine.cpp
)
target_include_directories(
    zara_scripting
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/scripting/include
)
if(Python3_Development_FOUND)
    target_compile_definitions(zara_scripting PRIVATE ZARA_HAS_PYTHON=1)
    target_link_libraries(zara_scripting PRIVATE Python3::Python)
endif()
zara_apply_defaults(zara_scripting)

add_library(
    zara_plugins STATIC
    plugins/src/manager.cpp
)
target_include_directories(
    zara_plugins
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/plugins/include
)
target_compile_definitions(
    zara_plugins
    PRIVATE
        ZARA_PLUGIN_HOST_SCRIPT_SOURCE="${CMAKE_CURRENT_SOURCE_DIR}/plugins/runtime/plugin_host.py"
        ZARA_PLUGIN_HOST_SCRIPT_INSTALL="${CMAKE_INSTALL_FULL_DATADIR}/zara/plugin_host.py"
)
zara_apply_defaults(zara_plugins)

add_library(
    zara_diff STATIC
    diff/src/engine.cpp
)
target_include_directories(
    zara_diff
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/diff/include
)
zara_apply_defaults(zara_diff)

add_library(
    zara_ai STATIC
    ai/src/assistant.cpp
)
target_include_directories(
    zara_ai
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/ai/include
)
if(CURL_FOUND)
    target_compile_definitions(zara_ai PRIVATE ZARA_HAS_CURL=1)
    target_link_libraries(zara_ai PRIVATE CURL::libcurl)
endif()
zara_apply_defaults(zara_ai)

add_library(
    zara_sdk STATIC
    sdk/src/api.cpp
)
target_include_directories(
    zara_sdk
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/sdk/include
)
target_link_libraries(zara_sdk PUBLIC zara_loader zara_memory zara_analysis zara_database zara_ai)
if(TARGET zara_sqlite_dep)
    target_compile_definitions(zara_sdk PRIVATE ZARA_HAS_SQLITE=1)
    target_link_libraries(zara_sdk PRIVATE zara_sqlite_dep)
endif()
zara_apply_defaults(zara_sdk)

add_library(
    zara_security STATIC
    security/src/workflow.cpp
)
target_include_directories(
    zara_security
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/security/include
)
zara_apply_defaults(zara_security)

add_library(
    zara_distributed STATIC
    distributed/src/batch_runner.cpp
)
target_include_directories(
    zara_distributed
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/distributed/include
)
if(OpenSSL_FOUND)
    target_compile_definitions(zara_distributed PRIVATE ZARA_HAS_OPENSSL=1)
    target_link_libraries(zara_distributed PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
zara_apply_defaults(zara_distributed)

add_library(
    zara_disasm STATIC
    disasm/src/disassembler.cpp
)
target_include_directories(
    zara_disasm
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/disasm/include
)
target_link_libraries(zara_disasm PUBLIC zara_memory)
if(TARGET zara_capstone_dep)
    target_compile_definitions(zara_disasm PRIVATE ZARA_HAS_CAPSTONE=1)
    target_link_libraries(zara_disasm PRIVATE zara_capstone_dep)
endif()
zara_apply_defaults(zara_disasm)

add_library(
    zara_cfg STATIC
    cfg/src/function_graph.cpp
)
target_include_directories(
    zara_cfg
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/cfg/include
)
target_link_libraries(zara_cfg PUBLIC zara_disasm)
zara_apply_defaults(zara_cfg)

add_library(
    zara_xrefs STATIC
    xrefs/src/analysis.cpp
)
target_include_directories(
    zara_xrefs
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/xrefs/include
)
target_link_libraries(zara_xrefs PUBLIC zara_cfg zara_loader)
zara_apply_defaults(zara_xrefs)

add_library(
    zara_ir STATIC
    ir/src/lifter.cpp
)
target_include_directories(
    zara_ir
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/ir/include
)
target_link_libraries(zara_ir PUBLIC zara_cfg zara_disasm)
zara_apply_defaults(zara_ir)

add_library(
    zara_ssa STATIC
    ssa/src/builder.cpp
)
target_include_directories(
    zara_ssa
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/ssa/include
)
target_link_libraries(zara_ssa PUBLIC zara_ir)
zara_apply_defaults(zara_ssa)

add_library(
    zara_type STATIC
    type/src/recovery.cpp
)
target_include_directories(
    zara_type
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/type/include
)
target_link_libraries(zara_type PUBLIC zara_ssa zara_ir)
zara_apply_defaults(zara_type)

add_library(
    zara_decompiler STATIC
    decompiler/src/decompiler.cpp
)
target_include_directories(
    zara_decompiler
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/decompiler/include
)
zara_apply_defaults(zara_decompiler)

add_library(
    zara_analysis STATIC
    analysis/src/program_analysis.cpp
)
target_include_directories(
    zara_analysis
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/analysis/include
)
target_link_libraries(zara_analysis PUBLIC zara_xrefs zara_memory zara_ir zara_ssa zara_type zara_decompiler)
if(Threads_FOUND)
    target_link_libraries(zara_analysis PRIVATE Threads::Threads)
endif()
zara_apply_defaults(zara_analysis)

target_link_libraries(zara_debugger PUBLIC zara_loader zara_analysis)
target_link_libraries(zara_decompiler PUBLIC zara_cfg zara_ssa zara_type zara_ir)
target_link_libraries(zara_scripting PUBLIC zara_analysis zara_ai zara_security zara_diff zara_debugger zara_distributed)
target_link_libraries(zara_plugins PUBLIC zara_scripting)
target_link_libraries(zara_diff PUBLIC zara_analysis)
target_link_libraries(zara_ai PUBLIC zara_analysis)
target_link_libraries(zara_security PUBLIC zara_analysis)

add_library(
    zara_database STATIC
    database/src/project_store.cpp
)
target_include_directories(
    zara_database
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/database/include
)
target_link_libraries(zara_database PUBLIC zara_loader zara_cfg zara_analysis zara_ai zara_security)
if(TARGET zara_sqlite_dep)
    target_compile_definitions(zara_database PRIVATE ZARA_HAS_SQLITE=1)
    target_link_libraries(zara_database PRIVATE zara_sqlite_dep)
endif()
zara_apply_defaults(zara_database)

target_link_libraries(zara_distributed PUBLIC zara_analysis zara_database)
if(Threads_FOUND)
    target_link_libraries(zara_distributed PRIVATE Threads::Threads)
endif()

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/plugins/runtime/plugin_host.py
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/zara
)
