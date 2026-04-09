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
    ROTHALYX_CAPSTONE_INCLUDE_DIR
    NAMES capstone/capstone.h capstone.h
    HINTS ${CAPSTONE_INCLUDE_DIRS}
    PATH_SUFFIXES include
)

find_library(
    ROTHALYX_CAPSTONE_LIBRARY
    NAMES capstone
    HINTS ${CAPSTONE_LIBRARY_DIRS}
    PATH_SUFFIXES lib
)

if(SQLite3_FOUND OR TARGET SQLite3::SQLite3 OR TARGET SQLite::SQLite3 OR TARGET unofficial::sqlite3::sqlite3)
    if(NOT TARGET rothalyx_sqlite_dep)
        add_library(rothalyx_sqlite_dep INTERFACE)
    endif()

    if(TARGET SQLite3::SQLite3)
        target_link_libraries(rothalyx_sqlite_dep INTERFACE SQLite3::SQLite3)
    elseif(TARGET SQLite::SQLite3)
        target_link_libraries(rothalyx_sqlite_dep INTERFACE SQLite::SQLite3)
    elseif(TARGET unofficial::sqlite3::sqlite3)
        target_link_libraries(rothalyx_sqlite_dep INTERFACE unofficial::sqlite3::sqlite3)
    endif()
endif()

if(TARGET capstone::capstone OR TARGET Capstone::Capstone OR CAPSTONE_FOUND)
    if(NOT TARGET rothalyx_capstone_dep)
        add_library(rothalyx_capstone_dep INTERFACE)
    endif()

    if(TARGET capstone::capstone)
        target_link_libraries(rothalyx_capstone_dep INTERFACE capstone::capstone)
    elseif(TARGET Capstone::Capstone)
        target_link_libraries(rothalyx_capstone_dep INTERFACE Capstone::Capstone)
    elseif(CAPSTONE_FOUND)
        set(rothalyx_capstone_include_dirs "")
        foreach(include_dir IN LISTS CAPSTONE_INCLUDE_DIRS)
            if(EXISTS "${include_dir}/capstone.h")
                get_filename_component(include_parent "${include_dir}" DIRECTORY)
                list(APPEND rothalyx_capstone_include_dirs "${include_parent}")
            else()
                list(APPEND rothalyx_capstone_include_dirs "${include_dir}")
            endif()
        endforeach()

        if(NOT rothalyx_capstone_include_dirs AND ROTHALYX_CAPSTONE_INCLUDE_DIR)
            list(APPEND rothalyx_capstone_include_dirs "${ROTHALYX_CAPSTONE_INCLUDE_DIR}")
        endif()

        list(REMOVE_DUPLICATES rothalyx_capstone_include_dirs)
        if(rothalyx_capstone_include_dirs)
            target_include_directories(rothalyx_capstone_dep INTERFACE ${rothalyx_capstone_include_dirs})
        endif()

        if(CAPSTONE_LIBRARY_DIRS)
            target_link_directories(rothalyx_capstone_dep INTERFACE ${CAPSTONE_LIBRARY_DIRS})
        endif()

        if(CAPSTONE_LINK_LIBRARIES)
            target_link_libraries(rothalyx_capstone_dep INTERFACE ${CAPSTONE_LINK_LIBRARIES})
        elseif(CAPSTONE_LIBRARIES)
            target_link_libraries(rothalyx_capstone_dep INTERFACE ${CAPSTONE_LIBRARIES})
        elseif(ROTHALYX_CAPSTONE_LIBRARY)
            target_link_libraries(rothalyx_capstone_dep INTERFACE ${ROTHALYX_CAPSTONE_LIBRARY})
        endif()
    endif()
elseif(ROTHALYX_CAPSTONE_INCLUDE_DIR AND ROTHALYX_CAPSTONE_LIBRARY)
    add_library(rothalyx_capstone_dep INTERFACE)
    target_include_directories(rothalyx_capstone_dep INTERFACE "${ROTHALYX_CAPSTONE_INCLUDE_DIR}")
    target_link_libraries(rothalyx_capstone_dep INTERFACE "${ROTHALYX_CAPSTONE_LIBRARY}")
endif()

function(rothalyx_apply_defaults target_name)
    target_compile_features(${target_name} PUBLIC cxx_std_20)

    if(WIN32)
        target_compile_definitions(${target_name} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    endif()

    if(MSVC)
        target_compile_options(${target_name} PRIVATE /W4 /permissive-)
    else()
        target_compile_options(${target_name} PRIVATE -Wall -Wextra -Wpedantic)
        if(ROTHALYX_ENABLE_SANITIZERS)
            target_compile_options(${target_name} PRIVATE -fno-omit-frame-pointer -fsanitize=address,undefined)
            target_link_options(${target_name} PRIVATE -fsanitize=address,undefined)
        endif()
    endif()
endfunction()

add_library(
    rothalyx_loader STATIC
    loader/src/binary_image.cpp
)
target_include_directories(
    rothalyx_loader
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/loader/include
)
rothalyx_apply_defaults(rothalyx_loader)

add_library(
    rothalyx_memory STATIC
    memory/src/address_space.cpp
)
target_include_directories(
    rothalyx_memory
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/memory/include
)
target_link_libraries(rothalyx_memory PUBLIC rothalyx_loader)
rothalyx_apply_defaults(rothalyx_memory)

add_library(
    rothalyx_debugger STATIC
    debugger/src/native_session.cpp
    debugger/src/integration.cpp
)
if(WIN32)
    target_sources(
        rothalyx_debugger
        PRIVATE
            debugger/src/native_session_windows.cpp
    )
elseif(APPLE)
    target_sources(
        rothalyx_debugger
        PRIVATE
            debugger/src/native_session_macos.cpp
    )
endif()
target_include_directories(
    rothalyx_debugger
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/debugger/include
)
rothalyx_apply_defaults(rothalyx_debugger)

add_library(
    rothalyx_scripting STATIC
    scripting/src/python_engine.cpp
)
target_include_directories(
    rothalyx_scripting
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/scripting/include
)
if(Python3_Development_FOUND)
    target_compile_definitions(rothalyx_scripting PRIVATE ROTHALYX_HAS_PYTHON=1)
    target_link_libraries(rothalyx_scripting PRIVATE Python3::Python)
endif()
rothalyx_apply_defaults(rothalyx_scripting)

add_library(
    rothalyx_plugins STATIC
    plugins/src/manager.cpp
)
target_include_directories(
    rothalyx_plugins
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/plugins/include
)
target_compile_definitions(
    rothalyx_plugins
    PRIVATE
        ROTHALYX_PLUGIN_HOST_SCRIPT_SOURCE="${CMAKE_CURRENT_SOURCE_DIR}/plugins/runtime/plugin_host.py"
        ROTHALYX_PLUGIN_HOST_SCRIPT_INSTALL="${CMAKE_INSTALL_FULL_DATADIR}/rothalyx/plugin_host.py"
)
rothalyx_apply_defaults(rothalyx_plugins)

add_library(
    rothalyx_diff STATIC
    diff/src/engine.cpp
)
target_include_directories(
    rothalyx_diff
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/diff/include
)
rothalyx_apply_defaults(rothalyx_diff)

add_library(
    rothalyx_ai STATIC
    ai/src/assistant.cpp
)
target_include_directories(
    rothalyx_ai
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/ai/include
)
if(CURL_FOUND)
    target_compile_definitions(rothalyx_ai PRIVATE ROTHALYX_HAS_CURL=1)
    target_link_libraries(rothalyx_ai PRIVATE CURL::libcurl)
endif()
rothalyx_apply_defaults(rothalyx_ai)

add_library(
    rothalyx_sdk STATIC
    sdk/src/api.cpp
)
target_include_directories(
    rothalyx_sdk
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/sdk/include
)
target_link_libraries(rothalyx_sdk PUBLIC rothalyx_loader rothalyx_memory rothalyx_analysis rothalyx_database rothalyx_ai)
if(TARGET rothalyx_sqlite_dep)
    target_compile_definitions(rothalyx_sdk PRIVATE ROTHALYX_HAS_SQLITE=1)
    target_link_libraries(rothalyx_sdk PRIVATE rothalyx_sqlite_dep)
endif()
rothalyx_apply_defaults(rothalyx_sdk)

add_library(
    rothalyx_security STATIC
    security/src/workflow.cpp
)
target_include_directories(
    rothalyx_security
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/security/include
)
rothalyx_apply_defaults(rothalyx_security)

add_library(
    rothalyx_distributed STATIC
    distributed/src/batch_runner.cpp
)
target_include_directories(
    rothalyx_distributed
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/distributed/include
)
if(OpenSSL_FOUND)
    target_compile_definitions(rothalyx_distributed PRIVATE ROTHALYX_HAS_OPENSSL=1)
    target_link_libraries(rothalyx_distributed PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
rothalyx_apply_defaults(rothalyx_distributed)

add_library(
    rothalyx_disasm STATIC
    disasm/src/disassembler.cpp
)
target_include_directories(
    rothalyx_disasm
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/disasm/include
)
target_link_libraries(rothalyx_disasm PUBLIC rothalyx_memory)
if(TARGET rothalyx_capstone_dep)
    target_compile_definitions(rothalyx_disasm PRIVATE ROTHALYX_HAS_CAPSTONE=1)
    target_link_libraries(rothalyx_disasm PRIVATE rothalyx_capstone_dep)
endif()
rothalyx_apply_defaults(rothalyx_disasm)

add_library(
    rothalyx_cfg STATIC
    cfg/src/function_graph.cpp
)
target_include_directories(
    rothalyx_cfg
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/cfg/include
)
target_link_libraries(rothalyx_cfg PUBLIC rothalyx_disasm)
rothalyx_apply_defaults(rothalyx_cfg)

add_library(
    rothalyx_xrefs STATIC
    xrefs/src/analysis.cpp
)
target_include_directories(
    rothalyx_xrefs
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/xrefs/include
)
target_link_libraries(rothalyx_xrefs PUBLIC rothalyx_cfg rothalyx_loader)
rothalyx_apply_defaults(rothalyx_xrefs)

add_library(
    rothalyx_ir STATIC
    ir/src/lifter.cpp
)
target_include_directories(
    rothalyx_ir
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/ir/include
)
target_link_libraries(rothalyx_ir PUBLIC rothalyx_cfg rothalyx_disasm)
rothalyx_apply_defaults(rothalyx_ir)

add_library(
    rothalyx_ssa STATIC
    ssa/src/builder.cpp
)
target_include_directories(
    rothalyx_ssa
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/ssa/include
)
target_link_libraries(rothalyx_ssa PUBLIC rothalyx_ir)
rothalyx_apply_defaults(rothalyx_ssa)

add_library(
    rothalyx_type STATIC
    type/src/recovery.cpp
)
target_include_directories(
    rothalyx_type
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/type/include
)
target_link_libraries(rothalyx_type PUBLIC rothalyx_ssa rothalyx_ir)
rothalyx_apply_defaults(rothalyx_type)

add_library(
    rothalyx_decompiler STATIC
    decompiler/src/decompiler.cpp
)
target_include_directories(
    rothalyx_decompiler
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/decompiler/include
)
rothalyx_apply_defaults(rothalyx_decompiler)

add_library(
    rothalyx_analysis STATIC
    analysis/src/program_analysis.cpp
)
target_include_directories(
    rothalyx_analysis
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/analysis/include
)
target_link_libraries(rothalyx_analysis PUBLIC rothalyx_xrefs rothalyx_memory rothalyx_ir rothalyx_ssa rothalyx_type rothalyx_decompiler)
if(Threads_FOUND)
    target_link_libraries(rothalyx_analysis PRIVATE Threads::Threads)
endif()
rothalyx_apply_defaults(rothalyx_analysis)

target_link_libraries(rothalyx_debugger PUBLIC rothalyx_loader rothalyx_analysis)
target_link_libraries(rothalyx_decompiler PUBLIC rothalyx_cfg rothalyx_ssa rothalyx_type rothalyx_ir)
target_link_libraries(rothalyx_scripting PUBLIC rothalyx_analysis rothalyx_ai rothalyx_security rothalyx_diff rothalyx_debugger rothalyx_distributed)
target_link_libraries(rothalyx_plugins PUBLIC rothalyx_scripting)
target_link_libraries(rothalyx_diff PUBLIC rothalyx_analysis)
target_link_libraries(rothalyx_ai PUBLIC rothalyx_analysis)
target_link_libraries(rothalyx_security PUBLIC rothalyx_analysis)

add_library(
    rothalyx_database STATIC
    database/src/project_store.cpp
)
target_include_directories(
    rothalyx_database
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/database/include
)
target_link_libraries(rothalyx_database PUBLIC rothalyx_loader rothalyx_cfg rothalyx_analysis rothalyx_ai rothalyx_security)
if(TARGET rothalyx_sqlite_dep)
    target_compile_definitions(rothalyx_database PRIVATE ROTHALYX_HAS_SQLITE=1)
    target_link_libraries(rothalyx_database PRIVATE rothalyx_sqlite_dep)
endif()
rothalyx_apply_defaults(rothalyx_database)

target_link_libraries(rothalyx_distributed PUBLIC rothalyx_analysis rothalyx_database)
if(Threads_FOUND)
    target_link_libraries(rothalyx_distributed PRIVATE Threads::Threads)
endif()

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/plugins/runtime/plugin_host.py
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/rothalyx
)
