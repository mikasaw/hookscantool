cmake_minimum_required(VERSION 3.20)
project(hookscantool VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# --- Generated version header/resource (single source of truth:
#     the project() VERSION above) ---
set(HOOKSCAN_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.h.in"
    "${HOOKSCAN_GENERATED_DIR}/version.h"
)
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.rc.in"
    "${HOOKSCAN_GENERATED_DIR}/version.rc"
)

# --- Local dependencies (pre-downloaded in deps/) ---
# Copy Zycore into Zydis' expected submodule path
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/deps/zycore/" DESTINATION "${CMAKE_CURRENT_SOURCE_DIR}/deps/zydis-4.0.0/dependencies/zycore/")

set(ZYAN_SYSTEM_ZYCORE OFF CACHE BOOL "" FORCE)
set(ZYDIS_MINIMAL_MODE OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN OFF CACHE BOOL "" FORCE)
add_subdirectory(deps/zydis-4.0.0)

set(IMGUI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/deps/imgui-1.91.8")

# --- Engine library (no GUI dependency) ---
add_library(hookscan_engine STATIC
    src/engine/pe_parser.c
    src/engine/process.c
    src/engine/iat_scanner.c
    src/engine/eat_scanner.c
    src/engine/inline_scanner.c
    src/engine/chain_tracer.c
    src/engine/restore.c
    src/engine/wow64.c
    src/engine/module_scorer.c
    src/engine/sigcheck.c
    src/engine/engine.c
)
target_include_directories(hookscan_engine PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/engine
)
target_include_directories(hookscan_engine PRIVATE
    "${HOOKSCAN_GENERATED_DIR}"
)
target_link_libraries(hookscan_engine PRIVATE Zydis psapi bcrypt)

# --- CLI tool ---
add_executable(hookscan_cli
    src/cli/main.c
    src/cli/args.c
    "${HOOKSCAN_GENERATED_DIR}/version.rc"
)
target_include_directories(hookscan_cli PRIVATE
    "${HOOKSCAN_GENERATED_DIR}"
)
target_link_libraries(hookscan_cli PRIVATE hookscan_engine Zydis psapi)

# --- Dear ImGui library (compiled from source) ---
add_library(imgui STATIC
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp
)
target_include_directories(imgui PUBLIC
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
)
target_compile_definitions(imgui PUBLIC IMGUI_DEFINE_MATH_OPERATORS)

# --- GUI executable ---
add_executable(hookscantool WIN32
    src/gui/main.cpp
    src/gui/ui_process_tree.cpp
    src/gui/ui_hook_list.cpp
    src/gui/ui_chain_view.cpp
    src/gui/ui_restore.cpp
    src/gui/ui_module_list.cpp
    "${HOOKSCAN_GENERATED_DIR}/version.rc"
)
target_link_libraries(hookscantool PRIVATE
    hookscan_engine
    Zydis
    imgui
    d3d11
    dxgi
    d3dcompiler
    dwmapi
    comdlg32
    psapi
)
target_include_directories(hookscantool PRIVATE
    "${HOOKSCAN_GENERATED_DIR}"
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
)

# --- Compiler-specific settings ---
if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    target_compile_options(hookscan_engine PRIVATE /W4 /wd4819 /wd4152)
    target_compile_options(hookscan_cli PRIVATE /W4 /wd4819 /wd4152)
    target_compile_options(hookscantool PRIVATE /W4 /wd4819 /wd4152)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_compile_options(hookscan_engine PRIVATE /O2)
        target_compile_options(hookscan_cli PRIVATE /O2)
        target_compile_options(hookscantool PRIVATE /O2)
    endif()
elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    target_compile_options(hookscan_engine PRIVATE -Wall -Wextra)
    target_compile_options(hookscan_cli PRIVATE -Wall -Wextra)
    target_compile_options(hookscantool PRIVATE -Wall -Wextra)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_compile_options(hookscan_engine PRIVATE -O2 -fomit-frame-pointer)
        target_compile_options(hookscan_cli PRIVATE -O2 -fomit-frame-pointer)
        target_compile_options(hookscantool PRIVATE -O2 -fomit-frame-pointer)
    endif()
endif()

# --- E2E fixture (opt-in): a target process + DLL that hooks itself ---
option(HOOKSCAN_BUILD_E2E "Build end-to-end test fixture" OFF)
if(HOOKSCAN_BUILD_E2E)
    add_executable(e2e_target test/e2e/target_app.c)
    add_library(e2e_hook SHARED test/e2e/hook_dll.c)
    set_target_properties(e2e_hook PROPERTIES OUTPUT_NAME hook_dll)
    if(MSVC)
        target_compile_options(e2e_target PRIVATE /W4 /wd4819 /wd4152)
        target_compile_options(e2e_hook PRIVATE /W4 /wd4819 /wd4152)
    endif()
endif()

# --- Test targets ---
option(HOOKSCAN_BUILD_TESTS "Build unit tests" OFF)

if(HOOKSCAN_BUILD_TESTS)
    # Compile engine with test exports enabled
    target_compile_definitions(hookscan_engine PRIVATE HOOKSCAN_TESTING)

    add_executable(hookscan_test
        test/test_runner.c
        test/test_pe_parser.c
        test/test_module_scorer.c
        test/test_inline_matcher.c
        test/test_cli_args.c
        test/test_json_writer.c
        test/test_eat_match.c
        test/test_sigcheck.c
        src/cli/args.c
    )
    target_include_directories(hookscan_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/test
        ${CMAKE_CURRENT_SOURCE_DIR}/src/engine
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cli
    )
    target_compile_definitions(hookscan_test PRIVATE HOOKSCAN_TESTING)
    target_link_libraries(hookscan_test PRIVATE
        hookscan_engine
        Zydis
        psapi
    )
    if(MSVC)
        target_compile_options(hookscan_test PRIVATE /W4 /wd4819 /wd4152)
    elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        target_compile_options(hookscan_test PRIVATE -Wall -Wextra)
    endif()
endif()