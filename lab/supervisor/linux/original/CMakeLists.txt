cmake_minimum_required(VERSION 3.20)
project(GateBouncerLinuxOriginal LANGUAGES CXX)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(gatebouncer-linux-original linux_original_guest.cpp)
    add_executable(gatebouncer-capture linux_original_guest.cpp)
    target_compile_definitions(gatebouncer-capture PRIVATE GB_CAPTURE_ONLY)
    foreach(target gatebouncer-linux-original gatebouncer-capture)
        target_compile_features(${target} PRIVATE cxx_std_17)
        target_compile_options(${target} PRIVATE -Wall -Wextra)
    endforeach()
elseif(WIN32)
    # Los ELF provienen del artifact de fuente propia revisada. El build lee sus bytes reales.
    set(GB_ORIGINAL_GUEST_ARTIFACT_DIR "" CACHE PATH "Directory containing the two original Linux executables")
    foreach(leaf gatebouncer-linux-original gatebouncer-capture)
        if(NOT EXISTS "${GB_ORIGINAL_GUEST_ARTIFACT_DIR}/${leaf}")
            message(FATAL_ERROR "Both original Linux executables are required")
        endif()
    endforeach()
    file(SHA256 "${GB_ORIGINAL_GUEST_ARTIFACT_DIR}/gatebouncer-linux-original" GB_GUEST_HASH)
    file(SHA256 "${GB_ORIGINAL_GUEST_ARTIFACT_DIR}/gatebouncer-capture" GB_CAPTURE_HASH)
    add_library(original_native STATIC
        ../../../../common/token_ii_win.cpp ../../../../common/protected_file_win.cpp
        ../../../../common/wire_v1.cpp ../../../../common/wire_ii.cpp ../../../../common/wire_iv.cpp)
    target_compile_features(original_native PUBLIC cxx_std_17)
    target_compile_definitions(original_native PUBLIC UNICODE _UNICODE _WIN32_WINNT=0x0A00)
    target_link_libraries(original_native PUBLIC advapi32 bcrypt user32)
    add_executable(gatebouncer-linux-proxy WIN32 linux_original_proxy.cpp)
    target_link_libraries(gatebouncer-linux-proxy PRIVATE original_native shell32)
    # Este paso de build sólo pinnea la imagen Proxy propia recién compilada; nunca la ejecuta.
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/WriteProxyPin.cmake"
        "file(SHA256 \"\${PROXY}\" hash)\nfile(WRITE \"\${OUTPUT}\" \"#pragma once\\n#define GB_ORIGINAL_GUEST_SHA256 \\\"${GB_GUEST_HASH}\\\"\\n#define GB_ORIGINAL_CAPTURE_SHA256 \\\"${GB_CAPTURE_HASH}\\\"\\n#define GB_ORIGINAL_PROXY_SHA256 \\\"\${hash}\\\"\\n\")\n")
    add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/OriginalGuestPins.hpp"
        COMMAND "${CMAKE_COMMAND}" "-DPROXY=$<TARGET_FILE:gatebouncer-linux-proxy>"
            "-DOUTPUT=${CMAKE_CURRENT_BINARY_DIR}/OriginalGuestPins.hpp" -P "${CMAKE_CURRENT_BINARY_DIR}/WriteProxyPin.cmake"
        DEPENDS gatebouncer-linux-proxy VERBATIM)
    add_executable(gatebouncer-linux-original-host linux_original_host.cpp OwnHostLinuxOriginal.cpp OwnCloudSeed.cpp
        ../OwnMemorySshCredential.cpp ../../../../common/pipe_ii_win.cpp ../../../../controller/deployment_win.cpp
        "${CMAKE_CURRENT_BINARY_DIR}/OriginalGuestPins.hpp")
    target_include_directories(gatebouncer-linux-original-host PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
    target_compile_definitions(gatebouncer-linux-original-host PRIVATE GB_ORIGINAL_HOST_ONLY)
    target_link_libraries(gatebouncer-linux-original-host PRIVATE original_native wintrust crypt32)
    if(MINGW)
        target_link_options(gatebouncer-linux-original-host PRIVATE -municode -static)
        target_link_options(gatebouncer-linux-proxy PRIVATE -municode -static)
    endif()
else()
    message(FATAL_ERROR "A Linux or Windows toolchain is required")
endif()
