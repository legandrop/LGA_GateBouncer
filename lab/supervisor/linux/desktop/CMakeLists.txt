cmake_minimum_required(VERSION 3.20)
project(GateBouncerPrivateDesktop LANGUAGES CXX)
if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "Windows MSVC SDK required")
endif()
add_library(GateBouncerGuestResources STATIC
    PrivateDesktopOwner.cpp ../WindowsNativeOwnedLaunchContext.cpp ../LinuxSshCreator.cpp
    ../helper/OwnedSuspendedProcess.cpp ../helper/OwnedHelperContainer.cpp
    ../helper/OwnedHelperLaunchAdapter.cpp ../guestbroker/GuestNoJobObserver.cpp
    ../guestbroker/FixedGuestBrokerSource.cpp ../../files/RetainedFile.cpp
    ../../conversion/P3OwnedConversionFileSeal.cpp)
target_compile_features(GateBouncerGuestResources PUBLIC cxx_std_17)
target_compile_definitions(GateBouncerGuestResources PUBLIC UNICODE _UNICODE _WIN32_WINNT=0x0601)
target_compile_options(GateBouncerGuestResources PRIVATE /W4 /WX /utf-8)
target_link_libraries(GateBouncerGuestResources PUBLIC User32 Advapi32 Bcrypt)
add_executable(desktop_worker desktop_worker.cpp)
target_compile_options(desktop_worker PRIVATE /W4 /WX /utf-8)
target_link_libraries(desktop_worker PRIVATE GateBouncerGuestResources)
