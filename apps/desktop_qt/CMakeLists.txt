find_package(Qt6 COMPONENTS Widgets QUIET)

if(NOT Qt6_FOUND)
    message(STATUS "Skipping native desktop shell: Qt6 Widgets was not found.")
    return()
endif()

if(NOT TARGET zara_sqlite_dep)
    message(STATUS "Skipping native desktop shell: SQLite dependency was not found.")
    return()
endif()

add_executable(
    zara_desktop_qt
    src/main.cpp
    src/app/ai_settings.cpp
    src/app/analysis_runner.cpp
    src/app/secret_store.cpp
    src/app/workspace_controller.cpp
    src/persistence/project_repository.cpp
    src/ui/graph_view.cpp
    src/ui/main_window.cpp
)

qt_add_resources(
    zara_desktop_qt
    desktop_qt_resources
    PREFIX
        "/"
    BASE
        ${CMAKE_CURRENT_SOURCE_DIR}/resources
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/zara-re-platform.png
)

target_include_directories(
    zara_desktop_qt
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(
    zara_desktop_qt
    PRIVATE
        Qt6::Widgets
        zara_loader
        zara_memory
        zara_analysis
        zara_database
        zara_debugger
        zara_sqlite_dep
)

if(MSVC)
    target_compile_options(zara_desktop_qt PRIVATE /W4 /permissive-)
else()
    target_compile_options(zara_desktop_qt PRIVATE -Wall -Wextra -Wpedantic)
endif()

set_target_properties(
    zara_desktop_qt
    PROPERTIES
        WIN32_EXECUTABLE TRUE
        MACOSX_BUNDLE TRUE
)

if(WIN32)
    target_link_libraries(zara_desktop_qt PRIVATE Advapi32)
    target_sources(
        zara_desktop_qt
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/resources/zara_desktop_qt.rc
    )
endif()

if(APPLE)
    target_sources(
        zara_desktop_qt
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/resources/zara-re-platform.icns
    )
    set_source_files_properties(
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/zara-re-platform.icns
        PROPERTIES
            MACOSX_PACKAGE_LOCATION Resources
    )
    set_target_properties(
        zara_desktop_qt
        PROPERTIES
            MACOSX_BUNDLE_ICON_FILE zara-re-platform.icns
    )
endif()

install(
    TARGETS
        zara_desktop_qt
    RUNTIME DESTINATION
        ${CMAKE_INSTALL_BINDIR}
    BUNDLE DESTINATION
        .
)

if((WIN32 OR APPLE) AND COMMAND qt_generate_deploy_app_script)
    qt_generate_deploy_app_script(
        TARGET zara_desktop_qt
        OUTPUT_SCRIPT zara_desktop_qt_deploy_script
        NO_UNSUPPORTED_PLATFORM_ERROR
    )
    install(SCRIPT ${zara_desktop_qt_deploy_script})
endif()

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/zara-re-platform.desktop
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/applications
)

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/zara-re-platform-512.png
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/icons/hicolor/512x512/apps
    RENAME
        zara-re-platform.png
)

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/zara-re-platform.svg
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps
)
