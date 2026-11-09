cmake_minimum_required(VERSION 3.21)
# La versión del producto (centésimos, como las demás apps LGA): fuente única. instalador.bat se la pasa al .iss.
project(LGA_GateBouncer VERSION 1.02 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOGEN_PARALLEL 1)
find_package(Qt6 6.8 REQUIRED COMPONENTS Widgets Network)
qt_standard_project_setup(REQUIRES 6.8)
add_compile_definitions(GATEBOUNCER_VERSION="${PROJECT_VERSION}")
# Auto-update de las apps LGA: libs/lgaupdate es la copia idéntica de LGA_Base_QT_C_Py (ver su README).
add_subdirectory(libs/lgaupdate)
# Idioma de la interfaz (inglés o español): la tabla y I18n::tr, para la ventana, el aviso y la bandeja.
qt_add_library(gatebouncer_i18n STATIC src/i18n.cpp src/i18n.h src/i18n_es.cpp)
target_include_directories(gatebouncer_i18n PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(gatebouncer_i18n PUBLIC Qt6::Core)
target_compile_options(gatebouncer_i18n PRIVATE -Wall -Wextra -Wpedantic)
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

# Explicaciones con IA de las apps bloqueadas (key propia del usuario, NVIDIA).
qt_add_library(gatebouncer_explain STATIC
    src/explain/KeyStore.cpp
    src/explain/KeyStore.h
    src/explain/Explainer.cpp
    src/explain/Explainer.h
    src/explain/KnownApps.cpp
    src/explain/KnownApps.h
)
target_include_directories(gatebouncer_explain PUBLIC src)
target_link_libraries(gatebouncer_explain PUBLIC Qt6::Core Qt6::Network PRIVATE winhttp crypt32 version advapi32 shell32 ole32)
target_compile_options(gatebouncer_explain PRIVATE -Wall -Wextra -Wpedantic)
qt_add_executable(GateBouncerExplainProbe src/explain/probe_main.cpp)
target_link_libraries(GateBouncerExplainProbe PRIVATE gatebouncer_explain)

qt_add_library(GateBouncerGuiStage SHARED
    src/main.cpp
    controller/deployment_ordinary_stage.cpp
    src/bootstrap.cpp
    src/bootstrap.h
    src/simulation.cpp
    src/simulation.h
    src/mainwindow.cpp
    src/mainwindow.h
    src/accesstoast.cpp
    src/accesstoast.h
    src/appicon.cpp
    src/appicon.h
    src/customtooltip.cpp
    src/customtooltip.h
    src/foldertrust.cpp
    src/foldertrust.h
    engine/folder_rule.cpp
    engine/folder_rule.h
    src/toggleswitch.cpp
    src/toggleswitch.h
    src/theme.h
    src/palette.cpp
    src/palette.h
    src/productcontroller.cpp
    src/productcontroller.h
    src/engine/EngineViewClient.cpp
    src/engine/EngineViewClient.h
    src/engine/ReviewGateway.cpp
    src/engine/ReviewGateway.h
    src/engine/FirewallClient.cpp
    src/engine/FirewallClient.h
    src/engine/NetLimiterRules.cpp
    src/engine/NetLimiterRules.h
    resources/app.rc
)
set_source_files_properties(src/main.cpp PROPERTIES COMPILE_DEFINITIONS "main=GateBouncerGuiMain")
target_link_libraries(GateBouncerGuiStage PRIVATE Qt6::Widgets Qt6::Network gatebouncer_explain gatebouncer_data gatebouncer_assistance gatebouncer_assistance_ui gatebouncer_general_live gatebouncer_service_view_ui gatebouncer_wire gatebouncer_lifecycle gatebouncer_i18n advapi32)
# engine/: la validación de las reglas por carpeta es la misma del motor (folder_rule.cpp, Win32 sin Qt).
target_include_directories(GateBouncerGuiStage PRIVATE src common engine)
target_compile_options(GateBouncerGuiStage PRIVATE -Wall -Wextra -Wpedantic)
qt_add_resources(GateBouncerGuiStage "gatebouncer_assets"
    PREFIX "/gatebouncer"
    FILES
        resources/fonts/Inter-Regular.ttf
        resources/fonts/Inter-Medium.ttf
        resources/fonts/Inter-SemiBold.ttf
        resources/fonts/BricolageGrotesque-SemiBold.ttf
        resources/fonts/BricolageGrotesque-Bold.ttf
        resources/fonts/BricolageGrotesque-ExtraBold.ttf
        resources/translations/qtbase_es.qm
        resources/icons/LGA_GateBouncer.png
        resources/icons/tray/tray_16.png
        resources/icons/tray/tray_20.png
        resources/icons/tray/tray_24.png
        resources/icons/tray/tray_32.png
        resources/icons/tray/tray_40.png
        resources/icons/tray/tray_48.png
        # Paletas de Settings (palette.cpp: presetIds).
        resources/palettes/default-1.json
        resources/palettes/default-2.json
        resources/palettes/alto-contraste.json
        resources/palettes/grafito-ambar.json
        resources/palettes/niebla.json
        resources/palettes/pizarra-turquesa.json
)

# El observador externo reutiliza el binario real; no forma parte del producto.
if(GATEBOUNCER_OBSERVER_SOURCE)
    get_target_property(observer_sources GateBouncerGuiStage SOURCES)
    list(FILTER observer_sources EXCLUDE REGEX "deployment_ordinary_stage.cpp")
    qt_add_executable(GateBouncerObserver WIN32 ${observer_sources}
        controller/deployment_observer_main.cpp "${GATEBOUNCER_OBSERVER_SOURCE}")
    target_compile_definitions(GateBouncerObserver PRIVATE GATEBOUNCER_OBSERVER)
    target_include_directories(GateBouncerObserver PRIVATE src common engine)
    target_link_libraries(GateBouncerObserver PRIVATE Qt6::Widgets Qt6::Network gatebouncer_data gatebouncer_assistance
        gatebouncer_assistance_ui gatebouncer_general_live gatebouncer_service_view_ui gatebouncer_wire
        gatebouncer_lifecycle gatebouncer_i18n gatebouncer_native_ii advapi32 shell32 fwpuclnt)
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

if(GATEBOUNCER_TOAST_TEST_SOURCE)
    find_package(Qt6 6.8 REQUIRED COMPONENTS Test)
    qt_add_executable(GateBouncerToastTests "${GATEBOUNCER_TOAST_TEST_SOURCE}" src/accesstoast.cpp src/accesstoast.h
        src/appicon.cpp src/appicon.h src/engine/FirewallClient.cpp src/engine/FirewallClient.h
        src/customtooltip.cpp src/customtooltip.h src/foldertrust.cpp src/foldertrust.h engine/folder_rule.cpp
        src/palette.cpp src/palette.h)
    target_include_directories(GateBouncerToastTests PRIVATE src engine)
    target_link_libraries(GateBouncerToastTests PRIVATE Qt6::Widgets Qt6::Network Qt6::Test gatebouncer_explain
        gatebouncer_i18n)
endif()

set_target_properties(GateBouncerGuiStage PROPERTIES PREFIX "" AUTOMOC ON)

# GateBouncer.exe común: la misma interfaz sin el lanzador de la instalación protegida.
get_target_property(gatebouncer_app_sources GateBouncerGuiStage SOURCES)
list(FILTER gatebouncer_app_sources EXCLUDE REGEX "deployment_ordinary_stage.cpp|src/main.cpp")
qt_add_executable(GateBouncer WIN32 ${gatebouncer_app_sources} src/app_main.cpp src/firewallwindow.cpp src/firewallwindow.h
    src/rulestransfer.cpp src/rulestransfer.h
    src/platform/WindowFrame.h src/platform/WindowFrameWin.cpp src/uiscale.cpp src/uiscale.h
    # Editor de paletas, sólo con GATEBOUNCER_PALETTE_EDITOR=1 (desarrollo).
    src/dev/paletteeditor.cpp src/dev/paletteeditor.h src/dev/LgaColorPickerDialog.cpp src/dev/LgaColorPickerDialog.h)
target_include_directories(GateBouncer PRIVATE src common engine)
target_link_libraries(GateBouncer PRIVATE Qt6::Widgets Qt6::Network gatebouncer_explain gatebouncer_data gatebouncer_assistance
    gatebouncer_assistance_ui gatebouncer_general_live gatebouncer_service_view_ui gatebouncer_wire
    gatebouncer_lifecycle gatebouncer_i18n gatebouncer_native_ii LGAUpdate advapi32 shell32 fwpuclnt dwmapi)
target_compile_options(GateBouncer PRIVATE -Wall -Wextra -Wpedantic)
qt_add_resources(GateBouncer "gatebouncer_app_assets"
    PREFIX "/gatebouncer"
    FILES
        resources/catalog/known_apps.json
        resources/fonts/Inter-Regular.ttf
        resources/fonts/Inter-Medium.ttf
        resources/fonts/Inter-SemiBold.ttf
        resources/fonts/BricolageGrotesque-SemiBold.ttf
        resources/fonts/BricolageGrotesque-Bold.ttf
        resources/fonts/BricolageGrotesque-ExtraBold.ttf
        resources/translations/qtbase_es.qm
        resources/icons/LGA_GateBouncer.png
        resources/icons/tray/tray_16.png
        resources/icons/tray/tray_20.png
        resources/icons/tray/tray_24.png
        resources/icons/tray/tray_32.png
        resources/icons/tray/tray_40.png
        resources/icons/tray/tray_48.png
        # Paletas de Settings (palette.cpp: presetIds).
        resources/palettes/default-1.json
        resources/palettes/default-2.json
        resources/palettes/alto-contraste.json
        resources/palettes/grafito-ambar.json
        resources/palettes/niebla.json
        resources/palettes/pizarra-turquesa.json
)
