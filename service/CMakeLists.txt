cmake_minimum_required(VERSION 3.24)
project(GateBouncerService LANGUAGES CXX RC)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT WIN32 OR NOT MSVC)
  message(FATAL_ERROR "El servicio requiere MSVC y Windows SDK; no se enlaza dentro de QtMinGW.")
endif()
find_package(Qt6 6.8.2 REQUIRED COMPONENTS Core)
qt_standard_project_setup(REQUIRES 6.8)
# Mismas unidades fuente del importador original, recompiladas para este ABI.
# No enlazar el archive QtMinGW ni incluir GUI, stores o catálogos del caller.
qt_add_library(gatebouncer_qname_source STATIC
  ../src/data/contracts.cpp
  ../src/data/qnamexmlreader.cpp
  ../src/data/netlimiterxmlprofile.cpp)
target_link_libraries(gatebouncer_qname_source PUBLIC Qt6::Core)
target_include_directories(gatebouncer_qname_source PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/..")
target_compile_options(gatebouncer_qname_source PRIVATE /W4 /permissive- /utf-8 /guard:cf)
target_compile_definitions(gatebouncer_qname_source PRIVATE UNICODE _UNICODE _WIN32_WINNT=0x0A00)
add_library(gatebouncer_wire STATIC ../common/wire_v1.cpp ../common/wire_ii.cpp ../common/wire_iv.cpp ../common/review_open.cpp)
add_library(gatebouncer_decisions STATIC decisions_ii.cpp observations_ii.cpp)
add_subdirectory(windows/allapps/native)
target_sources(gatebouncer_allapps_native PRIVATE windows/allapps/native/NativeRecipe.cpp windows/allapps/native/NativeCatalog.cpp)
target_link_libraries(gatebouncer_allapps_native PUBLIC bcrypt)
target_link_libraries(gatebouncer_decisions PUBLIC gatebouncer_wire)
add_library(gatebouncer_policy STATIC policy.cpp)
target_link_libraries(gatebouncer_policy PUBLIC gatebouncer_wire bcrypt advapi32)
add_library(gatebouncer_native_ii STATIC ../common/protected_file_win.cpp ../common/token_ii_win.cpp ../common/pipe_ii_win.cpp ../common/client_ii_win.cpp ../controller/deployment_win.cpp journal_ii_store.cpp snapshot_iii.cpp snapshot_iv.cpp store_iv.cpp coordinator_iii.cpp journal_iii.cpp directional_specs.cpp profile_ii.cpp collector_ii.cpp effects_projection_ii.cpp effects_ii.cpp runtime_ii.cpp engine_resource_iv.cpp catalog_plan_iv.cpp)
target_link_libraries(gatebouncer_native_ii PUBLIC gatebouncer_decisions gatebouncer_policy gatebouncer_allapps_native bcrypt advapi32 wtsapi32 fwpuclnt)
target_sources(gatebouncer_native_ii PRIVATE principal_producer_vii.cpp)
target_sources(gatebouncer_native_ii PRIVATE principal_source_capture_vii.cpp)
target_sources(gatebouncer_native_ii PRIVATE scopes_v.cpp scoped_runtime_v.cpp)
target_sources(gatebouncer_native_ii PRIVATE ../controller/deployment_prepare_win.cpp)
target_sources(gatebouncer_native_ii PRIVATE maintenance_iv.cpp ../controller/deployment_maintenance_win.cpp)
target_link_libraries(gatebouncer_native_ii PRIVATE onecore gatebouncer_qname_source)
qt_add_executable(GateBouncerService main.cpp pipe_transport.cpp wfp_backend.cpp)
target_link_libraries(GateBouncerService PRIVATE gatebouncer_policy gatebouncer_native_ii fwpuclnt shell32 ws2_32)
foreach(target gatebouncer_wire gatebouncer_policy gatebouncer_decisions gatebouncer_native_ii GateBouncerService)
  target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /guard:cf)
  target_compile_definitions(${target} PRIVATE UNICODE _UNICODE _WIN32_WINNT=0x0A00)
endforeach()
target_link_options(GateBouncerService PRIVATE /guard:cf /DYNAMICBASE /NXCOMPAT)
target_link_options(GateBouncerService PRIVATE /DEPENDENTLOADFLAG:0xA00
  "/MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/../controller/deployment_ordinary.manifest")
# El loader propio debe cargar la QtCore MSVC inventariada antes del parser.
# La QtCore MinGW del directorio GUI no es compatible con este servicio.
target_link_libraries(GateBouncerService PRIVATE delayimp)
target_link_options(GateBouncerService PRIVATE
  "/DELAYLOAD:Qt6Core$<$<CONFIG:Debug>:d>.dll")
add_executable(GateBouncer WIN32 ../controller/deployment_ordinary_bootstrap.cpp ../resources/app.rc)
target_include_directories(GateBouncer PRIVATE ../resources)
target_link_libraries(GateBouncer PRIVATE gatebouncer_native_ii shell32)
target_compile_definitions(GateBouncer PRIVATE UNICODE _UNICODE _WIN32_WINNT=0x0A00)
target_compile_options(GateBouncer PRIVATE /W4 /permissive- /utf-8 /guard:cf)
target_link_options(GateBouncer PRIVATE /guard:cf /DYNAMICBASE /NXCOMPAT /DEPENDENTLOADFLAG:0x800
  "/MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/../controller/deployment_ordinary.manifest")
# QtCore MSVC compartida usa CRT dinámico. La misma selección debe alcanzar
# todos los objetos de esta clausura, incluidos los compartidos con bootstrap.
set_property(TARGET gatebouncer_qname_source gatebouncer_wire gatebouncer_decisions
  gatebouncer_policy gatebouncer_appidentity gatebouncer_allapps gatebouncer_allapps_native
  gatebouncer_native_ii GateBouncerService GateBouncer
  PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
set(GATEBOUNCER_OFFLINE_TEST_SOURCE "" CACHE PATH "Fuente externa exclusiva de QA offline")
if(GATEBOUNCER_OFFLINE_TEST_SOURCE)
  add_executable(GateBouncerOfflineTests "${GATEBOUNCER_OFFLINE_TEST_SOURCE}")
  target_link_libraries(GateBouncerOfflineTests PRIVATE gatebouncer_policy)
  target_include_directories(GateBouncerOfflineTests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/..")
  target_compile_options(GateBouncerOfflineTests PRIVATE /W4 /permissive- /utf-8)
  set_property(TARGET GateBouncerOfflineTests PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()
if(GATEBOUNCER_DECISIONS_TEST_SOURCE)
  add_executable(GateBouncerDecisionsTests "${GATEBOUNCER_DECISIONS_TEST_SOURCE}" ../controller/review_state.cpp)
  target_link_libraries(GateBouncerDecisionsTests PRIVATE gatebouncer_decisions gatebouncer_native_ii)
  target_include_directories(GateBouncerDecisionsTests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/..")
  set_property(TARGET GateBouncerDecisionsTests PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()
