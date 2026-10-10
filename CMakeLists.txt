cmake_minimum_required(VERSION 3.21)
project(LGA_GateBouncer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOGEN_PARALLEL 1)
find_package(Qt6 6.8 REQUIRED COMPONENTS Widgets)
qt_standard_project_setup(REQUIRES 6.8)
add_subdirectory(src/data)
add_subdirectory(src/assistance)
add_subdirectory(src/localfacts)
add_subdirectory(src/lifecycle)
qt_add_library(gatebouncer_wire STATIC common/wire_v1.cpp common/wire_ii.cpp common/wire_iv.cpp common/review_open.cpp)
target_include_directories(gatebouncer_wire PUBLIC common)
qt_add_library(gatebouncer_service_view_ui STATIC
    src/engine/DecisionViewClient.cpp src/engine/DecisionViewClient.h
    src/engine/OrdinaryDecisionClient.cpp src/engine/OrdinaryDecisionClient.h
    controller/ordinary_qt.cpp controller/ordinary_qt.h
    controller/session_qt.cpp controller/session_qt.h
)
target_link_libraries(gatebouncer_service_view_ui PUBLIC Qt6::Core gatebouncer_native_ii gatebouncer_data)
target_include_directories(gatebouncer_service_view_ui PUBLIC src common controller)
if(DEFINED ENV{GATEBOUNCER_ORDINARY_HEADER_DIR})
    target_include_directories(gatebouncer_service_view_ui PRIVATE "$ENV{GATEBOUNCER_ORDINARY_HEADER_DIR}")
endif()
target_compile_definitions(gatebouncer_service_view_ui PRIVATE UNICODE _UNICODE NOMINMAX)
target_compile_options(gatebouncer_service_view_ui PRIVATE -Wall -Wextra -Wpedantic)

qt_add_library(GateBouncerGuiStage SHARED
    src/main.cpp
    controller/deployment_ordinary_stage.cpp
    src/bootstrap.cpp
    src/bootstrap.h
    src/simulation.cpp
    src/simulation.h
    src/mainwindow.cpp
    src/mainwindow.h
    src/productcontroller.cpp
    src/productcontroller.h
    src/engine/EngineViewClient.cpp
    src/engine/EngineViewClient.h
    src/engine/ReviewGateway.cpp
    src/engine/ReviewGateway.h
    resources/app.rc
)
set_source_files_properties(src/main.cpp PROPERTIES COMPILE_DEFINITIONS "main=GateBouncerGuiMain")
target_link_libraries(GateBouncerGuiStage PRIVATE Qt6::Widgets gatebouncer_data gatebouncer_assistance gatebouncer_assistance_ui gatebouncer_general_live gatebouncer_service_view_ui gatebouncer_wire gatebouncer_lifecycle advapi32)
target_include_directories(GateBouncerGuiStage PRIVATE src common)
target_compile_options(GateBouncerGuiStage PRIVATE -Wall -Wextra -Wpedantic)
qt_add_resources(GateBouncerGuiStage "gatebouncer_assets"
    PREFIX "/gatebouncer"
    FILES
        resources/fonts/Inter-Regular.ttf
        resources/fonts/Inter-Medium.ttf
        resources/fonts/Inter-SemiBold.ttf
        resources/icons/LGA_GateBouncer.png
        resources/icons/tray/tray_16.png
        resources/icons/tray/tray_20.png
        resources/icons/tray/tray_24.png
        resources/icons/tray/tray_32.png
        resources/icons/tray/tray_40.png
        resources/icons/tray/tray_48.png
)

# El observador externo reutiliza el binario real; no forma parte del producto.
if(GATEBOUNCER_OBSERVER_SOURCE)
    get_target_property(observer_sources GateBouncerGuiStage SOURCES)
    list(FILTER observer_sources EXCLUDE REGEX "deployment_ordinary_stage.cpp")
    qt_add_executable(GateBouncerObserver WIN32 ${observer_sources}
        controller/deployment_observer_main.cpp "${GATEBOUNCER_OBSERVER_SOURCE}")
    target_compile_definitions(GateBouncerObserver PRIVATE GATEBOUNCER_OBSERVER)
    target_include_directories(GateBouncerObserver PRIVATE src common)
    target_link_libraries(GateBouncerObserver PRIVATE Qt6::Widgets gatebouncer_data gatebouncer_assistance
        gatebouncer_assistance_ui gatebouncer_general_live gatebouncer_service_view_ui gatebouncer_wire
        gatebouncer_lifecycle gatebouncer_native_ii advapi32 shell32 fwpuclnt)
endif()

# Componentes de decisiones: no habilitan endpoints ni ejecución elevada.
qt_add_library(gatebouncer_review STATIC controller/review_state.cpp controller/review_state.h)
target_include_directories(gatebouncer_review PUBLIC controller common)
target_link_libraries(gatebouncer_review PUBLIC gatebouncer_wire)
qt_add_library(gatebouncer_decisions STATIC service/decisions_ii.cpp service/decisions_ii.h service/observations_ii.cpp service/observations_ii.h)
target_include_directories(gatebouncer_decisions PUBLIC service common)
target_link_libraries(gatebouncer_decisions PUBLIC gatebouncer_wire)
add_library(gatebouncer_native_ii STATIC common/protected_file_win.cpp common/token_ii_win.cpp common/pipe_ii_win.cpp common/client_ii_win.cpp service/journal_ii_store.cpp service/policy.cpp service/snapshot_iii.cpp service/snapshot_iv.cpp service/store_iv.cpp service/coordinator_iii.cpp service/journal_iii.cpp service/directional_specs.cpp service/effects_projection_ii.cpp controller/deployment_win.cpp)
target_include_directories(gatebouncer_native_ii PUBLIC common service)
target_compile_definitions(gatebouncer_native_ii PRIVATE UNICODE _UNICODE _WIN32_WINNT=0x0A00)
target_compile_options(gatebouncer_native_ii PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(gatebouncer_native_ii PUBLIC gatebouncer_decisions bcrypt advapi32 wtsapi32)
target_link_libraries(gatebouncer_localfacts PRIVATE gatebouncer_native_ii)
add_executable(GateBouncerDecisionBootstrap WIN32 controller/bootstrap_main.cpp)
set_target_properties(GateBouncerDecisionBootstrap PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
target_link_libraries(GateBouncerDecisionBootstrap PRIVATE gatebouncer_native_ii)
target_link_options(GateBouncerDecisionBootstrap PRIVATE -static -static-libgcc -static-libstdc++)
qt_add_library(GateBouncerDecisionStage SHARED controller/review_window.cpp controller/review_window.h controller/session_qt.cpp controller/session_qt.h controller/review_ingress.cpp controller/review_ingress.h)
target_link_libraries(GateBouncerDecisionStage PRIVATE Qt6::Widgets gatebouncer_review gatebouncer_native_ii)
target_compile_options(GateBouncerDecisionStage PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(GateBouncerDecisionStage PRIVATE UNICODE _UNICODE _WIN32_WINNT=0x0A00)
set_target_properties(GateBouncerDecisionStage PROPERTIES PREFIX "")
target_link_libraries(GateBouncerGuiStage PRIVATE gatebouncer_native_ii shell32 fwpuclnt)
qt_add_executable(GateBouncerAssistant WIN32 src/assistance/broker/BrokerMain.cpp)
target_link_libraries(GateBouncerAssistant PRIVATE gatebouncer_general_live)
target_compile_options(GateBouncerAssistant PRIVATE -Wall -Wextra -Wpedantic)
foreach(target gatebouncer_wire gatebouncer_review gatebouncer_decisions)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
endforeach()
if(GATEBOUNCER_DECISIONS_TEST_SOURCE)
    qt_add_executable(GateBouncerDecisionsTests "${GATEBOUNCER_DECISIONS_TEST_SOURCE}")
    target_link_libraries(GateBouncerDecisionsTests PRIVATE gatebouncer_review gatebouncer_decisions gatebouncer_native_ii)
    target_include_directories(GateBouncerDecisionsTests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
endif()
if(GATEBOUNCER_REVIEW_TEST_SOURCE)
    find_package(Qt6 6.8 REQUIRED COMPONENTS Test)
    qt_add_executable(GateBouncerReviewTests "${GATEBOUNCER_REVIEW_TEST_SOURCE}" controller/review_window.cpp controller/review_window.h controller/session_qt.cpp controller/session_qt.h controller/review_ingress.cpp controller/review_ingress.h src/engine/DecisionViewClient.cpp src/engine/DecisionViewClient.h)
    target_link_libraries(GateBouncerReviewTests PRIVATE Qt6::Widgets Qt6::Test gatebouncer_review gatebouncer_native_ii)
    target_include_directories(GateBouncerReviewTests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
endif()

set_target_properties(GateBouncerGuiStage PROPERTIES PREFIX "" AUTOMOC ON)
