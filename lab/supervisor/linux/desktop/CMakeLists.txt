cmake_minimum_required(VERSION 3.20)
project(GateBouncerPrivateDesktop LANGUAGES CXX)
if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "Windows MSVC SDK required")
endif()
add_library(GateBouncerGuestResources STATIC
    PrivateDesktopOwner.cpp ../WindowsNativeOwnedLaunchContext.cpp ../LinuxSshCreator.cpp
    ../OwnMemorySshCredential.cpp
    ../helper/OwnedSuspendedProcess.cpp ../helper/OwnedHelperContainer.cpp
    ../helper/OwnedHelperLaunchAdapter.cpp ../guestbroker/GuestNoJobObserver.cpp
    ../guestbroker/FixedGuestBrokerSource.cpp ../../files/RetainedFile.cpp
    ../../conversion/P3OwnedConversionFileSeal.cpp ../guestbroker/GuestBrokerBoundary.cpp
    ../../../../common/pipe_ii_win.cpp ../../../../common/token_ii_win.cpp
    ../../../../common/protected_file_win.cpp ../../../../common/wire_v1.cpp
    ../../../../common/wire_ii.cpp ../../../../common/wire_iv.cpp
    ../../../../controller/deployment_win.cpp)
target_compile_features(GateBouncerGuestResources PUBLIC cxx_std_17)
# Windows 10 / Server 2016: PowerShell Direct y BCryptHash del digest común propio.
# Los consumidores del broker heredan ese mínimo junto a sus dependencias reales.
target_compile_definitions(GateBouncerGuestResources PUBLIC UNICODE _UNICODE _WIN32_WINNT=0x0A00)
target_compile_options(GateBouncerGuestResources PRIVATE /W4 /WX /utf-8)
target_link_libraries(GateBouncerGuestResources PUBLIC User32 Advapi32 Bcrypt Netapi32)
add_executable(desktop_worker desktop_worker.cpp)
target_compile_options(desktop_worker PRIVATE /W4 /WX /utf-8)
target_link_libraries(desktop_worker PRIVATE GateBouncerGuestResources)
add_executable(guest_broker ../guestbroker/guest_broker.cpp)
target_compile_options(guest_broker PRIVATE /W4 /WX /utf-8)
target_link_libraries(guest_broker PRIVATE GateBouncerGuestResources)
add_library(guest_native_controller SHARED ../guestbroker/GuestBrokerBoundary.cpp)
target_compile_features(guest_native_controller PRIVATE cxx_std_17)
target_compile_definitions(guest_native_controller PRIVATE GB_GUEST_NATIVE_EXPORTS)
target_compile_options(guest_native_controller PRIVATE /W4 /WX /utf-8)
target_link_libraries(guest_native_controller PRIVATE GateBouncerGuestResources)
set_property(TARGET GateBouncerGuestResources desktop_worker guest_broker guest_native_controller
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
