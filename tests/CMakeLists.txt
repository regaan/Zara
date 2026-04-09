add_executable(
    rothalyx_core_smoke
    core_smoke.cpp
)

target_link_libraries(
    rothalyx_core_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_disasm
)

if(MSVC)
    target_compile_options(rothalyx_core_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_core_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_core_raw_fixture
    COMMAND rothalyx_core_smoke ${CMAKE_SOURCE_DIR}/tests/fixtures/sample.bin
)

add_executable(
    rothalyx_safe_parsing_smoke
    safe_parsing_smoke.cpp
)

target_link_libraries(
    rothalyx_safe_parsing_smoke
    PRIVATE
        rothalyx_loader
)

if(MSVC)
    target_compile_options(rothalyx_safe_parsing_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_safe_parsing_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_safe_parsing_fixture
    COMMAND rothalyx_safe_parsing_smoke $<TARGET_FILE:rothalyx_debuggee_fixture>
)

add_executable(
    rothalyx_loader_adversarial_smoke
    loader_adversarial_smoke.cpp
)

target_link_libraries(
    rothalyx_loader_adversarial_smoke
    PRIVATE
        rothalyx_loader
)

if(MSVC)
    target_compile_options(rothalyx_loader_adversarial_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_loader_adversarial_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_loader_adversarial_synthetic
    COMMAND rothalyx_loader_adversarial_smoke
)

add_executable(
    rothalyx_memory_smoke
    memory_smoke.cpp
)

target_link_libraries(
    rothalyx_memory_smoke
    PRIVATE
        rothalyx_memory
)

if(MSVC)
    target_compile_options(rothalyx_memory_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_memory_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_memory_synthetic
    COMMAND rothalyx_memory_smoke
)

add_executable(
    rothalyx_native_analysis_smoke
    native_analysis_smoke.cpp
    ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/app/analysis_runner.cpp
    ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/app/workspace_controller.cpp
    ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/persistence/project_repository.cpp
)

target_include_directories(
    rothalyx_native_analysis_smoke
    PRIVATE
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/include
)

target_link_libraries(
    rothalyx_native_analysis_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_analysis
        rothalyx_database
)

if(TARGET SQLite3::SQLite3)
    target_link_libraries(rothalyx_native_analysis_smoke PRIVATE SQLite3::SQLite3)
elseif(TARGET SQLite::SQLite3)
    target_link_libraries(rothalyx_native_analysis_smoke PRIVATE SQLite::SQLite3)
endif()
if(MSVC)
    target_compile_options(rothalyx_native_analysis_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_native_analysis_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_native_analysis_persistence
    COMMAND rothalyx_native_analysis_smoke $<TARGET_FILE:rothalyx_debuggee_fixture>
)

if(TARGET rothalyx_desktop_qt)
    find_package(Qt6 COMPONENTS Widgets QUIET)
    add_executable(
        rothalyx_ui_flow_highlight_smoke
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
        rothalyx_ui_flow_highlight_smoke
        PRIVATE
            ${CMAKE_SOURCE_DIR}/apps/desktop_qt/include
    )

    target_link_libraries(
        rothalyx_ui_flow_highlight_smoke
        PRIVATE
            Qt6::Widgets
            rothalyx_loader
            rothalyx_memory
            rothalyx_analysis
            rothalyx_database
            rothalyx_debugger
    )

    if(TARGET SQLite3::SQLite3)
        target_link_libraries(rothalyx_ui_flow_highlight_smoke PRIVATE SQLite3::SQLite3)
    elseif(TARGET SQLite::SQLite3)
        target_link_libraries(rothalyx_ui_flow_highlight_smoke PRIVATE SQLite::SQLite3)
    endif()
    if(WIN32)
        target_link_libraries(rothalyx_ui_flow_highlight_smoke PRIVATE Advapi32)
    endif()

    if(MSVC)
        target_compile_options(rothalyx_ui_flow_highlight_smoke PRIVATE /W4 /permissive-)
    else()
        target_compile_options(rothalyx_ui_flow_highlight_smoke PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(
        NAME rothalyx_ui_flow_highlight_synthetic
        COMMAND rothalyx_ui_flow_highlight_smoke
    )

    add_executable(
        rothalyx_ui_debugger_polish_smoke
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
        rothalyx_ui_debugger_polish_smoke
        PRIVATE
            ${CMAKE_SOURCE_DIR}/apps/desktop_qt/include
    )

    target_link_libraries(
        rothalyx_ui_debugger_polish_smoke
        PRIVATE
            Qt6::Widgets
            rothalyx_loader
            rothalyx_memory
            rothalyx_analysis
            rothalyx_database
            rothalyx_debugger
    )

    if(TARGET SQLite3::SQLite3)
        target_link_libraries(rothalyx_ui_debugger_polish_smoke PRIVATE SQLite3::SQLite3)
    elseif(TARGET SQLite::SQLite3)
        target_link_libraries(rothalyx_ui_debugger_polish_smoke PRIVATE SQLite::SQLite3)
    endif()
    if(WIN32)
        target_link_libraries(rothalyx_ui_debugger_polish_smoke PRIVATE Advapi32)
    endif()

    if(MSVC)
        target_compile_options(rothalyx_ui_debugger_polish_smoke PRIVATE /W4 /permissive-)
    else()
        target_compile_options(rothalyx_ui_debugger_polish_smoke PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(
        NAME rothalyx_ui_debugger_polish_synthetic
        COMMAND rothalyx_ui_debugger_polish_smoke
    )
endif()

add_executable(
    rothalyx_architecture_smoke
    architecture_smoke.cpp
)

target_link_libraries(
    rothalyx_architecture_smoke
    PRIVATE
        rothalyx_disasm
)

if(MSVC)
    target_compile_options(rothalyx_architecture_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_architecture_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_architecture_synthetic
    COMMAND rothalyx_architecture_smoke
)

add_executable(
    rothalyx_mips_ppc_loader_smoke
    mips_ppc_loader_smoke.cpp
)

target_link_libraries(
    rothalyx_mips_ppc_loader_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_disasm
        rothalyx_analysis
)

if(MSVC)
    target_compile_options(rothalyx_mips_ppc_loader_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_mips_ppc_loader_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_mips_ppc_loader_synthetic
    COMMAND rothalyx_mips_ppc_loader_smoke
)

add_executable(
    rothalyx_riscv_loader_smoke
    riscv_loader_smoke.cpp
)

target_link_libraries(
    rothalyx_riscv_loader_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_disasm
        rothalyx_analysis
)

if(MSVC)
    target_compile_options(rothalyx_riscv_loader_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_riscv_loader_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_riscv_loader_synthetic
    COMMAND rothalyx_riscv_loader_smoke
)

add_executable(
    rothalyx_arm_pe_loader_smoke
    arm_pe_loader_smoke.cpp
)

target_link_libraries(
    rothalyx_arm_pe_loader_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_disasm
        rothalyx_analysis
)

if(MSVC)
    target_compile_options(rothalyx_arm_pe_loader_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_arm_pe_loader_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_arm_pe_loader_synthetic
    COMMAND rothalyx_arm_pe_loader_smoke
)

add_executable(
    rothalyx_debuggee_fixture
    debuggee_fixture.cpp
)

if(MSVC)
    target_compile_options(rothalyx_debuggee_fixture PRIVATE /W4 /permissive- /Od)
else()
    target_compile_options(rothalyx_debuggee_fixture PRIVATE -Wall -Wextra -Wpedantic -O0)
    target_link_options(rothalyx_debuggee_fixture PRIVATE -no-pie)
    target_compile_options(rothalyx_debuggee_fixture PRIVATE -fno-pie)
endif()

add_executable(
    rothalyx_threaded_debuggee_fixture
    threaded_debuggee_fixture.cpp
)

if(MSVC)
    target_compile_options(rothalyx_threaded_debuggee_fixture PRIVATE /W4 /permissive- /Od)
else()
    target_compile_options(rothalyx_threaded_debuggee_fixture PRIVATE -Wall -Wextra -Wpedantic -O0)
    target_link_options(rothalyx_threaded_debuggee_fixture PRIVATE -no-pie)
    target_compile_options(rothalyx_threaded_debuggee_fixture PRIVATE -fno-pie)
endif()

add_executable(
    rothalyx_debugger_launch_smoke
    debugger_launch_smoke.cpp
)

target_link_libraries(
    rothalyx_debugger_launch_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_debugger
)

if(MSVC)
    target_compile_options(rothalyx_debugger_launch_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_debugger_launch_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(
    rothalyx_debugger_live_patch_smoke
    debugger_live_patch_smoke.cpp
)

target_link_libraries(
    rothalyx_debugger_live_patch_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_debugger
)

if(MSVC)
    target_compile_options(rothalyx_debugger_live_patch_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_debugger_live_patch_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(
    rothalyx_debugger_attach_smoke
    debugger_attach_smoke.cpp
)

target_link_libraries(
    rothalyx_debugger_attach_smoke
    PRIVATE
        rothalyx_debugger
)

if(MSVC)
    target_compile_options(rothalyx_debugger_attach_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_debugger_attach_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(
    rothalyx_debugger_target_shape_smoke
    debugger_target_shape_smoke.cpp
)

target_link_libraries(
    rothalyx_debugger_target_shape_smoke
    PRIVATE
        rothalyx_debugger
)

if(MSVC)
    target_compile_options(rothalyx_debugger_target_shape_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_debugger_target_shape_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_debugger_target_shapes
    COMMAND rothalyx_debugger_target_shape_smoke
)

if(UNIX OR WIN32)
    add_test(
        NAME rothalyx_debugger_launch_synthetic
        COMMAND rothalyx_debugger_launch_smoke $<TARGET_FILE:rothalyx_debuggee_fixture>
    )

    add_test(
        NAME rothalyx_debugger_live_patch_synthetic
        COMMAND rothalyx_debugger_live_patch_smoke $<TARGET_FILE:rothalyx_debuggee_fixture>
    )

    add_executable(
        rothalyx_debugger_integration_smoke
        debugger_integration_smoke.cpp
    )

    target_link_libraries(
        rothalyx_debugger_integration_smoke
        PRIVATE
            rothalyx_loader
            rothalyx_memory
            rothalyx_analysis
            rothalyx_debugger
    )

    if(MSVC)
        target_compile_options(rothalyx_debugger_integration_smoke PRIVATE /W4 /permissive-)
    else()
        target_compile_options(rothalyx_debugger_integration_smoke PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(
        NAME rothalyx_debugger_integration_synthetic
        COMMAND rothalyx_debugger_integration_smoke $<TARGET_FILE:rothalyx_debuggee_fixture>
    )
endif()

if(UNIX)
    add_test(
        NAME rothalyx_debugger_attach_synthetic
        COMMAND rothalyx_debugger_attach_smoke $<TARGET_FILE:rothalyx_debuggee_fixture>
    )

    add_executable(
        rothalyx_debugger_threads_smoke
        debugger_threads_smoke.cpp
    )

    target_link_libraries(
        rothalyx_debugger_threads_smoke
        PRIVATE
            rothalyx_debugger
    )

    if(MSVC)
        target_compile_options(rothalyx_debugger_threads_smoke PRIVATE /W4 /permissive-)
    else()
        target_compile_options(rothalyx_debugger_threads_smoke PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(
        NAME rothalyx_debugger_threads_synthetic
        COMMAND rothalyx_debugger_threads_smoke $<TARGET_FILE:rothalyx_threaded_debuggee_fixture>
    )

    if(TARGET rothalyx_cli)
        add_test(
            NAME rothalyx_debugger_shell_scripted
            COMMAND
                $<TARGET_FILE:rothalyx_cli>
                debug-shell
                $<TARGET_FILE:rothalyx_debuggee_fixture>
                --script
                ${CMAKE_SOURCE_DIR}/tests/fixtures/debug_shell_commands.txt
        )
    endif()
endif()

if(TARGET rothalyx_scripting)
    add_executable(
        rothalyx_scripting_smoke
        scripting_smoke.cpp
    )

    target_link_libraries(
        rothalyx_scripting_smoke
        PRIVATE
            rothalyx_scripting
    )

    if(MSVC)
        target_compile_options(rothalyx_scripting_smoke PRIVATE /W4 /permissive-)
    else()
        target_compile_options(rothalyx_scripting_smoke PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(
        NAME rothalyx_scripting_synthetic
        COMMAND rothalyx_scripting_smoke $<TARGET_FILE:rothalyx_debuggee_fixture>
    )

    add_executable(
        rothalyx_scripting_concurrency_smoke
        scripting_concurrency_smoke.cpp
    )

    target_link_libraries(
        rothalyx_scripting_concurrency_smoke
        PRIVATE
            rothalyx_scripting
    )

    if(MSVC)
        target_compile_options(rothalyx_scripting_concurrency_smoke PRIVATE /W4 /permissive-)
    else()
        target_compile_options(rothalyx_scripting_concurrency_smoke PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(
        NAME rothalyx_scripting_concurrency_synthetic
        COMMAND rothalyx_scripting_concurrency_smoke $<TARGET_FILE:rothalyx_debuggee_fixture>
    )

    if(UNIX)
        add_executable(
            rothalyx_distributed_scripting_smoke
            distributed_scripting_smoke.cpp
        )

        target_link_libraries(
            rothalyx_distributed_scripting_smoke
            PRIVATE
                rothalyx_scripting
        )

        if(MSVC)
            target_compile_options(rothalyx_distributed_scripting_smoke PRIVATE /W4 /permissive-)
        else()
            target_compile_options(rothalyx_distributed_scripting_smoke PRIVATE -Wall -Wextra -Wpedantic)
        endif()

        add_test(
            NAME rothalyx_distributed_scripting_python
            COMMAND rothalyx_distributed_scripting_smoke $<TARGET_FILE:rothalyx_debuggee_fixture> $<TARGET_FILE:rothalyx_debuggee_fixture>
        )
    endif()

add_executable(
        rothalyx_plugin_smoke
        plugin_smoke.cpp
)

    target_link_libraries(
        rothalyx_plugin_smoke
        PRIVATE
            rothalyx_plugins
    )

    if(MSVC)
        target_compile_options(rothalyx_plugin_smoke PRIVATE /W4 /permissive-)
    else()
        target_compile_options(rothalyx_plugin_smoke PRIVATE -Wall -Wextra -Wpedantic)
    endif()

add_test(
        NAME rothalyx_plugin_synthetic
        COMMAND
            rothalyx_plugin_smoke
            ${CMAKE_SOURCE_DIR}/tests/plugin_fixtures
            $<TARGET_FILE:rothalyx_debuggee_fixture>
)

add_executable(
        rothalyx_plugin_sandbox_smoke
        plugin_sandbox_smoke.cpp
)
target_link_libraries(
        rothalyx_plugin_sandbox_smoke
        PRIVATE
            rothalyx_plugins
)
if(MSVC)
        target_compile_options(rothalyx_plugin_sandbox_smoke PRIVATE /W4 /permissive-)
else()
        target_compile_options(rothalyx_plugin_sandbox_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
        NAME rothalyx_plugin_sandbox_synthetic
        COMMAND
            rothalyx_plugin_sandbox_smoke
            ${CMAKE_SOURCE_DIR}/tests/plugin_sandbox_fixtures
)

add_executable(
        rothalyx_plugin_policy_smoke
        plugin_policy_smoke.cpp
)
target_link_libraries(
        rothalyx_plugin_policy_smoke
        PRIVATE
            rothalyx_plugins
)
if(MSVC)
        target_compile_options(rothalyx_plugin_policy_smoke PRIVATE /W4 /permissive-)
else()
        target_compile_options(rothalyx_plugin_policy_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
        NAME rothalyx_plugin_policy_synthetic
        COMMAND
            rothalyx_plugin_policy_smoke
            ${CMAKE_SOURCE_DIR}/tests/plugin_policy_fixtures/denied_allowlist
            ${CMAKE_SOURCE_DIR}/tests/plugin_policy_fixtures/unsandboxed_plugin
)

add_executable(
        rothalyx_plugin_marketplace_smoke
        plugin_marketplace_smoke.cpp
)
    target_link_libraries(
        rothalyx_plugin_marketplace_smoke
        PRIVATE
            rothalyx_plugins
    )
    if(MSVC)
        target_compile_options(rothalyx_plugin_marketplace_smoke PRIVATE /W4 /permissive-)
    else()
        target_compile_options(rothalyx_plugin_marketplace_smoke PRIVATE -Wall -Wextra -Wpedantic)
    endif()

add_test(
        NAME rothalyx_plugin_marketplace_synthetic
        COMMAND
            rothalyx_plugin_marketplace_smoke
            ${CMAKE_SOURCE_DIR}/tests/plugin_marketplace_fixtures
            $<TARGET_FILE:rothalyx_debuggee_fixture>
)
endif()

if(UNIX AND EXISTS "/bin/ls")
    add_test(
        NAME rothalyx_core_system_elf
        COMMAND rothalyx_core_smoke /bin/ls
    )
endif()

add_executable(
    rothalyx_analysis_smoke
    analysis_smoke.cpp
)

target_link_libraries(
    rothalyx_analysis_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_disasm
        rothalyx_cfg
        rothalyx_xrefs
)

if(MSVC)
    target_compile_options(rothalyx_analysis_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_analysis_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_analysis_synthetic
    COMMAND rothalyx_analysis_smoke
)

add_executable(
    rothalyx_cfg_advanced_smoke
    cfg_advanced_smoke.cpp
)

target_link_libraries(
    rothalyx_cfg_advanced_smoke
    PRIVATE
        rothalyx_cfg
        rothalyx_memory
)

if(MSVC)
    target_compile_options(rothalyx_cfg_advanced_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_cfg_advanced_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_cfg_advanced_synthetic
    COMMAND rothalyx_cfg_advanced_smoke
)

add_executable(
    rothalyx_program_smoke
    program_smoke.cpp
)

target_link_libraries(
    rothalyx_program_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_cfg
        rothalyx_xrefs
        rothalyx_analysis
)

if(MSVC)
    target_compile_options(rothalyx_program_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_program_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_program_synthetic
    COMMAND rothalyx_program_smoke
)

add_executable(
    rothalyx_analysis_engine_smoke
    analysis_engine_smoke.cpp
)

target_link_libraries(
    rothalyx_analysis_engine_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_analysis
)

if(MSVC)
    target_compile_options(rothalyx_analysis_engine_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_analysis_engine_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_analysis_engine_synthetic
    COMMAND rothalyx_analysis_engine_smoke
)

add_executable(
    rothalyx_optimizer_smoke
    optimizer_smoke.cpp
)

target_link_libraries(
    rothalyx_optimizer_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_analysis
        rothalyx_ssa
)

if(MSVC)
    target_compile_options(rothalyx_optimizer_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_optimizer_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_optimizer_synthetic
    COMMAND rothalyx_optimizer_smoke
)

add_executable(
    rothalyx_function_discovery_smoke
    function_discovery_smoke.cpp
)

target_link_libraries(
    rothalyx_function_discovery_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_analysis
)

if(MSVC)
    target_compile_options(rothalyx_function_discovery_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_function_discovery_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_function_discovery_synthetic
    COMMAND rothalyx_function_discovery_smoke
)

add_executable(
    rothalyx_signature_detection_smoke
    signature_detection_smoke.cpp
)

target_link_libraries(
    rothalyx_signature_detection_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_analysis
)

if(MSVC)
    target_compile_options(rothalyx_signature_detection_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_signature_detection_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_signature_detection_synthetic
    COMMAND rothalyx_signature_detection_smoke
)

add_executable(
    rothalyx_ir_smoke
    ir_smoke.cpp
)

target_link_libraries(
    rothalyx_ir_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_cfg
        rothalyx_xrefs
        rothalyx_ir
        rothalyx_analysis
)

if(MSVC)
    target_compile_options(rothalyx_ir_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_ir_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_ir_synthetic
    COMMAND rothalyx_ir_smoke
)

add_executable(
    rothalyx_ssa_smoke
    ssa_smoke.cpp
)

target_link_libraries(
    rothalyx_ssa_smoke
    PRIVATE
        rothalyx_ir
        rothalyx_ssa
)

if(MSVC)
    target_compile_options(rothalyx_ssa_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_ssa_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_ssa_synthetic
    COMMAND rothalyx_ssa_smoke
)

add_executable(
    rothalyx_type_smoke
    type_smoke.cpp
)

target_link_libraries(
    rothalyx_type_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_cfg
        rothalyx_xrefs
        rothalyx_ir
        rothalyx_ssa
        rothalyx_type
        rothalyx_analysis
)

if(MSVC)
    target_compile_options(rothalyx_type_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_type_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_type_synthetic
    COMMAND rothalyx_type_smoke
)

add_executable(
    rothalyx_composite_type_smoke
    composite_type_smoke.cpp
)

target_link_libraries(
    rothalyx_composite_type_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_cfg
        rothalyx_xrefs
        rothalyx_ir
        rothalyx_ssa
        rothalyx_type
        rothalyx_analysis
)

if(MSVC)
    target_compile_options(rothalyx_composite_type_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_composite_type_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_composite_type_synthetic
    COMMAND rothalyx_composite_type_smoke
)

add_executable(
    rothalyx_lazy_cache_smoke
    lazy_cache_smoke.cpp
)

target_link_libraries(
    rothalyx_lazy_cache_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_cfg
        rothalyx_xrefs
        rothalyx_ir
        rothalyx_ssa
        rothalyx_type
        rothalyx_decompiler
        rothalyx_analysis
)

if(MSVC)
    target_compile_options(rothalyx_lazy_cache_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_lazy_cache_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_lazy_cache_synthetic
    COMMAND rothalyx_lazy_cache_smoke
)

add_executable(
    rothalyx_decompiler_smoke
    decompiler_smoke.cpp
)

target_link_libraries(
    rothalyx_decompiler_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_cfg
        rothalyx_xrefs
        rothalyx_ir
        rothalyx_ssa
        rothalyx_type
        rothalyx_decompiler
        rothalyx_analysis
)

if(MSVC)
    target_compile_options(rothalyx_decompiler_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_decompiler_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_decompiler_synthetic
    COMMAND rothalyx_decompiler_smoke
)

add_executable(
    rothalyx_decompiler_structured_smoke
    decompiler_structured_smoke.cpp
)

target_link_libraries(
    rothalyx_decompiler_structured_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_cfg
        rothalyx_xrefs
        rothalyx_ir
        rothalyx_ssa
        rothalyx_type
        rothalyx_decompiler
        rothalyx_analysis
)

if(MSVC)
    target_compile_options(rothalyx_decompiler_structured_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_decompiler_structured_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_decompiler_structured_synthetic
    COMMAND rothalyx_decompiler_structured_smoke
)

add_executable(
    rothalyx_decompiler_maturity_smoke
    decompiler_maturity_smoke.cpp
)

target_link_libraries(
    rothalyx_decompiler_maturity_smoke
    PRIVATE
        rothalyx_cfg
        rothalyx_ir
        rothalyx_ssa
        rothalyx_type
        rothalyx_decompiler
)

if(MSVC)
    target_compile_options(rothalyx_decompiler_maturity_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_decompiler_maturity_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_decompiler_maturity_synthetic
    COMMAND rothalyx_decompiler_maturity_smoke
)

add_executable(
    rothalyx_interprocedural_semantics_smoke
    interprocedural_semantics_smoke.cpp
)

target_link_libraries(
    rothalyx_interprocedural_semantics_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_analysis
        rothalyx_type
        rothalyx_decompiler
)

if(MSVC)
    target_compile_options(rothalyx_interprocedural_semantics_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_interprocedural_semantics_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_interprocedural_semantics_synthetic
    COMMAND rothalyx_interprocedural_semantics_smoke
)

add_executable(
    rothalyx_ai_smoke
    ai_smoke.cpp
)

target_link_libraries(
    rothalyx_ai_smoke
    PRIVATE
        rothalyx_ai
)

if(MSVC)
    target_compile_options(rothalyx_ai_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_ai_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_ai_synthetic
    COMMAND rothalyx_ai_smoke
)

add_executable(
    rothalyx_ai_model_smoke
    ai_model_smoke.cpp
)

target_link_libraries(
    rothalyx_ai_model_smoke
    PRIVATE
        rothalyx_ai
)

if(MSVC)
    target_compile_options(rothalyx_ai_model_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_ai_model_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_ai_model_synthetic
    COMMAND rothalyx_ai_model_smoke
)

add_executable(
    rothalyx_security_smoke
    security_smoke.cpp
)

target_link_libraries(
    rothalyx_security_smoke
    PRIVATE
        rothalyx_security
)

if(MSVC)
    target_compile_options(rothalyx_security_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_security_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_security_synthetic
    COMMAND rothalyx_security_smoke
)

add_executable(
    rothalyx_fuzz_live_smoke
    fuzz_live_smoke.cpp
)

target_link_libraries(
    rothalyx_fuzz_live_smoke
    PRIVATE
        rothalyx_security
)

if(MSVC)
    target_compile_options(rothalyx_fuzz_live_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_fuzz_live_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_fuzz_live_synthetic
    COMMAND rothalyx_fuzz_live_smoke
)

add_executable(
    rothalyx_database_persistence_smoke
    database_persistence_smoke.cpp
)

target_link_libraries(
    rothalyx_database_persistence_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_analysis
        rothalyx_database
)

if(MSVC)
    target_compile_options(rothalyx_database_persistence_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_database_persistence_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_database_persistence_synthetic
    COMMAND rothalyx_database_persistence_smoke $<TARGET_FILE:rothalyx_debuggee_fixture>
)

add_executable(
    rothalyx_sdk_smoke
    sdk_smoke.cpp
)

target_link_libraries(
    rothalyx_sdk_smoke
    PRIVATE
        rothalyx_sdk
)

if(MSVC)
    target_compile_options(rothalyx_sdk_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_sdk_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_sdk_public_api
    COMMAND rothalyx_sdk_smoke $<TARGET_FILE:rothalyx_debuggee_fixture>
)

add_executable(
    rothalyx_project_workflow_smoke
    project_workflow_smoke.cpp
    ${CMAKE_SOURCE_DIR}/apps/desktop_qt/src/persistence/project_repository.cpp
)

target_include_directories(
    rothalyx_project_workflow_smoke
    PRIVATE
        ${CMAKE_SOURCE_DIR}/apps/desktop_qt/include
)

target_link_libraries(
    rothalyx_project_workflow_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_analysis
        rothalyx_database
        rothalyx_security
)

if(TARGET SQLite3::SQLite3)
    target_link_libraries(rothalyx_project_workflow_smoke PRIVATE SQLite3::SQLite3)
elseif(TARGET SQLite::SQLite3)
    target_link_libraries(rothalyx_project_workflow_smoke PRIVATE SQLite::SQLite3)
endif()

if(MSVC)
    target_compile_options(rothalyx_project_workflow_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_project_workflow_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_project_workflow_synthetic
    COMMAND rothalyx_project_workflow_smoke $<TARGET_FILE:rothalyx_debuggee_fixture>
)

add_executable(
    rothalyx_distributed_smoke
    distributed_smoke.cpp
)

target_link_libraries(
    rothalyx_distributed_smoke
    PRIVATE
        rothalyx_distributed
)

if(MSVC)
    target_compile_options(rothalyx_distributed_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_distributed_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_distributed_synthetic
    COMMAND
        rothalyx_distributed_smoke
        ${CMAKE_SOURCE_DIR}/tests/fixtures/sample.bin
        $<TARGET_FILE:rothalyx_debuggee_fixture>
)

add_executable(
    rothalyx_distributed_remote_smoke
    distributed_remote_smoke.cpp
)

target_link_libraries(
    rothalyx_distributed_remote_smoke
    PRIVATE
        rothalyx_distributed
)

if(MSVC)
    target_compile_options(rothalyx_distributed_remote_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_distributed_remote_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_distributed_remote_synthetic
    COMMAND
        rothalyx_distributed_remote_smoke
        ${CMAKE_SOURCE_DIR}/tests/fixtures/sample.bin
        $<TARGET_FILE:rothalyx_debuggee_fixture>
)

add_executable(
    rothalyx_distributed_auth_smoke
    distributed_auth_smoke.cpp
)

target_link_libraries(
    rothalyx_distributed_auth_smoke
    PRIVATE
        rothalyx_distributed
)

if(MSVC)
    target_compile_options(rothalyx_distributed_auth_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_distributed_auth_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_distributed_auth_synthetic
    COMMAND
        rothalyx_distributed_auth_smoke
        ${CMAKE_SOURCE_DIR}/tests/fixtures/sample.bin
)

add_executable(
    rothalyx_distributed_tls_smoke
    distributed_tls_smoke.cpp
)

target_link_libraries(
    rothalyx_distributed_tls_smoke
    PRIVATE
        rothalyx_distributed
)

if(MSVC)
    target_compile_options(rothalyx_distributed_tls_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_distributed_tls_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_distributed_tls_synthetic
    COMMAND
        rothalyx_distributed_tls_smoke
        ${CMAKE_SOURCE_DIR}/tests/fixtures/sample.bin
)

add_executable(
    rothalyx_distributed_protocol_abuse_smoke
    distributed_protocol_abuse_smoke.cpp
)

target_link_libraries(
    rothalyx_distributed_protocol_abuse_smoke
    PRIVATE
        rothalyx_distributed
)

if(MSVC)
    target_compile_options(rothalyx_distributed_protocol_abuse_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_distributed_protocol_abuse_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_distributed_protocol_abuse_synthetic
    COMMAND
        rothalyx_distributed_protocol_abuse_smoke
        ${CMAKE_SOURCE_DIR}/tests/fixtures/sample.bin
)

add_executable(
    rothalyx_diff_smoke
    diff_smoke.cpp
)

target_link_libraries(
    rothalyx_diff_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_cfg
        rothalyx_xrefs
        rothalyx_ir
        rothalyx_ssa
        rothalyx_type
        rothalyx_decompiler
        rothalyx_analysis
        rothalyx_diff
)

if(MSVC)
    target_compile_options(rothalyx_diff_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_diff_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_diff_synthetic
    COMMAND rothalyx_diff_smoke
)

add_executable(
    rothalyx_pe_loader_smoke
    pe_loader_smoke.cpp
)

target_link_libraries(
    rothalyx_pe_loader_smoke
    PRIVATE
        rothalyx_loader
)

if(MSVC)
    target_compile_options(rothalyx_pe_loader_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_pe_loader_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_pe_loader_synthetic
    COMMAND rothalyx_pe_loader_smoke
)

add_executable(
    rothalyx_pe_rebase_smoke
    pe_rebase_smoke.cpp
)

target_link_libraries(
    rothalyx_pe_rebase_smoke
    PRIVATE
        rothalyx_loader
)

if(MSVC)
    target_compile_options(rothalyx_pe_rebase_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_pe_rebase_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_pe_rebase_synthetic
    COMMAND rothalyx_pe_rebase_smoke
)

add_executable(
    rothalyx_macho_loader_smoke
    macho_loader_smoke.cpp
)

target_link_libraries(
    rothalyx_macho_loader_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_disasm
)

if(MSVC)
    target_compile_options(rothalyx_macho_loader_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_macho_loader_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_macho_loader_synthetic
    COMMAND rothalyx_macho_loader_smoke
)

add_executable(
    rothalyx_macho_chained_fixups_smoke
    macho_chained_fixups_smoke.cpp
)

target_link_libraries(
    rothalyx_macho_chained_fixups_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
)

if(MSVC)
    target_compile_options(rothalyx_macho_chained_fixups_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_macho_chained_fixups_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_macho_chained_fixups_synthetic
    COMMAND rothalyx_macho_chained_fixups_smoke
)

add_executable(
    rothalyx_macho_chained_fixups_matrix_smoke
    macho_chained_fixups_matrix_smoke.cpp
)

target_link_libraries(
    rothalyx_macho_chained_fixups_matrix_smoke
    PRIVATE
        rothalyx_loader
)

if(MSVC)
    target_compile_options(rothalyx_macho_chained_fixups_matrix_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_macho_chained_fixups_matrix_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(
    NAME rothalyx_macho_chained_fixups_matrix_synthetic
    COMMAND rothalyx_macho_chained_fixups_matrix_smoke
)

add_executable(
    rothalyx_import_smoke
    import_smoke.cpp
)

target_link_libraries(
    rothalyx_import_smoke
    PRIVATE
        rothalyx_loader
        rothalyx_memory
        rothalyx_cfg
        rothalyx_xrefs
        rothalyx_analysis
)

if(MSVC)
    target_compile_options(rothalyx_import_smoke PRIVATE /W4 /permissive-)
else()
    target_compile_options(rothalyx_import_smoke PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(UNIX AND EXISTS "/bin/ls")
    add_test(
        NAME rothalyx_import_system_elf
        COMMAND rothalyx_import_smoke /bin/ls
    )
endif()
