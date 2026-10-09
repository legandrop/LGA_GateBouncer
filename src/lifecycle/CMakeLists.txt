qt_add_library(gatebouncer_lifecycle STATIC
    LifecycleController.cpp
    LifecycleController.h
    StartupPreference.cpp
    StartupPreference.h
    NativeStartup.cpp
)
target_link_libraries(gatebouncer_lifecycle PUBLIC Qt6::Widgets)
if(WIN32)
    target_link_libraries(gatebouncer_lifecycle PRIVATE advapi32)
endif()
target_include_directories(gatebouncer_lifecycle PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/..")
target_compile_options(gatebouncer_lifecycle PRIVATE -Wall -Wextra -Wpedantic)
