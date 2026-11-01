cmake_minimum_required(VERSION 3.24)
project(GateBouncerEngine LANGUAGES CXX)
# Motor de firewall sin driver (WFP en modo usuario). MSVC + Windows SDK, sin Qt.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT WIN32 OR NOT MSVC)
  message(FATAL_ERROR "El motor requiere MSVC y Windows SDK.")
endif()
add_compile_definitions(UNICODE _UNICODE _WIN32_WINNT=0x0A00 WIN32_LEAN_AND_MEAN)
add_compile_options(/W4 /permissive- /utf-8 /EHsc)

add_library(gatebouncer_engine_core STATIC wfp_engine.cpp)
target_link_libraries(gatebouncer_engine_core PUBLIC fwpuclnt ws2_32 advapi32)

add_executable(GateBouncerEngineSelfTest selftest_main.cpp)
target_link_libraries(GateBouncerEngineSelfTest PRIVATE gatebouncer_engine_core)

add_executable(GateBouncerEngine engine_main.cpp firewall_core.cpp pipe_server.cpp)
target_link_libraries(GateBouncerEngine PRIVATE gatebouncer_engine_core)
