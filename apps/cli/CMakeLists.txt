add_executable(
    rothalyx_cli
    src/main.cpp
)

target_link_libraries(
    rothalyx_cli
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_disasm
        rothalyx_cfg
        rothalyx_xrefs
        rothalyx_debugger
        rothalyx_scripting
        rothalyx_plugins
        rothalyx_diff
        rothalyx_ai
        rothalyx_security
        rothalyx_distributed
        rothalyx_database
)

if(MSVC)
    target_compile_options(rothalyx_cli PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_cli PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(BUILD_TESTING)
    add_test(
        NAME rothalyx_cli_smoke
        COMMAND
            rothalyx_cli
            ${CMAKE_SOURCE_DIR}/tests/fixtures/sample.bin
            ${CMAKE_BINARY_DIR}/rothalyx_cli_smoke.sqlite
    )
endif()

install(
    TARGETS
        rothalyx_cli
    RUNTIME DESTINATION
        ${CMAKE_INSTALL_BINDIR}
)
