cmake_minimum_required(VERSION 3.21)
project(LGA_GateBouncer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(Qt6 6.8 REQUIRED COMPONENTS Widgets)
qt_standard_project_setup(REQUIRES 6.8)
add_subdirectory(src/data)
add_subdirectory(src/assistance)

qt_add_executable(GateBouncer WIN32
    src/main.cpp
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
    common/wire_v1.cpp
    common/wire_v1.h
    resources/app.rc
)
target_link_libraries(GateBouncer PRIVATE Qt6::Widgets gatebouncer_data gatebouncer_assistance advapi32)
target_include_directories(GateBouncer PRIVATE src common)
target_compile_options(GateBouncer PRIVATE -Wall -Wextra -Wpedantic)
qt_add_resources(GateBouncer "gatebouncer_assets"
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
    target_sources(GateBouncer PRIVATE "${GATEBOUNCER_OBSERVER_SOURCE}")
    target_compile_definitions(GateBouncer PRIVATE GATEBOUNCER_OBSERVER)
endif()
