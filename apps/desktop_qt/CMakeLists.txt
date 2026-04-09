find_package(Qt6 COMPONENTS Widgets QUIET)

if(NOT Qt6_FOUND)
    message(STATUS "Skipping native desktop shell: Qt6 Widgets was not found.")
    return()
endif()

if(NOT TARGET rothalyx_sqlite_dep)
    message(STATUS "Skipping native desktop shell: SQLite dependency was not found.")
    return()
endif()

add_executable(
    rothalyx_desktop_qt
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
    rothalyx_desktop_qt
    desktop_qt_resources
    PREFIX
        "/"
    BASE
        ${CMAKE_CURRENT_SOURCE_DIR}/resources
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/rothalyx-re-framework.png
)

target_include_directories(
    rothalyx_desktop_qt
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(
    rothalyx_desktop_qt
    PRIVATE
        Qt6::Widgets
        rothalyx_loader
        rothalyx_memory
        rothalyx_analysis
        rothalyx_database
        rothalyx_debugger
        rothalyx_sqlite_dep
)

if(MSVC)
    target_compile_options(rothalyx_desktop_qt PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_desktop_qt PRIVATE -Wall -Wextra -Wpedantic)
endif()

set_target_properties(
    rothalyx_desktop_qt
    PROPERTIES
        WIN32_EXECUTABLE TRUE
        MACOSX_BUNDLE TRUE
)

if(WIN32)
    target_link_libraries(rothalyx_desktop_qt PRIVATE Advapi32)
    target_sources(
        rothalyx_desktop_qt
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/resources/rothalyx_desktop_qt.rc
    )
endif()

if(APPLE)
    target_sources(
        rothalyx_desktop_qt
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/resources/rothalyx-re-framework.icns
    )
    set_source_files_properties(
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/rothalyx-re-framework.icns
        PROPERTIES
            MACOSX_PACKAGE_LOCATION Resources
    )
    set_target_properties(
        rothalyx_desktop_qt
        PROPERTIES
            MACOSX_BUNDLE_ICON_FILE rothalyx-re-framework.icns
    )
endif()

install(
    TARGETS
        rothalyx_desktop_qt
    RUNTIME DESTINATION
        ${CMAKE_INSTALL_BINDIR}
    BUNDLE DESTINATION
        .
)

if((WIN32 OR APPLE) AND COMMAND qt_generate_deploy_app_script)
    qt_generate_deploy_app_script(
        TARGET rothalyx_desktop_qt
        OUTPUT_SCRIPT rothalyx_desktop_qt_deploy_script
        NO_UNSUPPORTED_PLATFORM_ERROR
    )
    install(SCRIPT ${rothalyx_desktop_qt_deploy_script})
endif()

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/rothalyx-re-framework.desktop
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/applications
)

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/rothalyx-re-framework-512.png
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/icons/hicolor/512x512/apps
    RENAME
        rothalyx-re-framework.png
)

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/rothalyx-re-framework.svg
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps
)
