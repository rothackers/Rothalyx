cmake_minimum_required(VERSION 3.26)

project(
    Zara
    VERSION 1.0.0
    DESCRIPTION "Native reverse engineering framework for binary analysis, decompilation, and debugging"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(ZARA_BUILD_CLI "Build the CLI tooling" ON)
option(ZARA_BUILD_DESKTOP_QT "Build the native Qt Widgets desktop shell" ON)
option(ZARA_BUILD_FUZZING "Build fuzzing harnesses" OFF)
option(ZARA_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer on supported toolchains" OFF)

include(CTest)
include(GNUInstallDirs)

add_subdirectory(core)

if(ZARA_BUILD_FUZZING)
    add_subdirectory(fuzz)
endif()

if(ZARA_BUILD_CLI)
    add_subdirectory(apps/cli)
endif()

if(ZARA_BUILD_DESKTOP_QT)
    add_subdirectory(apps/desktop_qt)
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ZaraPackaging.cmake)
