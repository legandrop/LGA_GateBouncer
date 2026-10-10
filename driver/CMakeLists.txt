cmake_minimum_required(VERSION 3.24)
project(GateBouncerClassifier LANGUAGES C)
# El target nativo no hereda imports usermode ni selección de CRT /MD o /MT.
set(CMAKE_C_STANDARD_LIBRARIES "")
set(CMAKE_MSVC_RUNTIME_LIBRARY "")
if(NOT WIN32 OR NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "El clasificador WDM requiere MSVC x64 y WDK.")
endif()
set(GATEBOUNCER_WDK_ROOT "" CACHE PATH "Raíz portable WDK que contiene Include y Lib")
set(GATEBOUNCER_WDK_VERSION "10.0.26100.0" CACHE STRING "Versión de headers/libs WDK")
set(GATEBOUNCER_SDK_ROOT "" CACHE PATH "Raíz del Windows SDK con Include")
if(NOT EXISTS "${GATEBOUNCER_WDK_ROOT}/Include/${GATEBOUNCER_WDK_VERSION}/km/fwpsk.h")
  message(FATAL_ERROR "Faltan headers km del WDK explícito.")
endif()
add_executable(GateBouncerClassifier classifier.c)
set_target_properties(GateBouncerClassifier PROPERTIES PREFIX "" SUFFIX ".sys")
target_include_directories(GateBouncerClassifier PRIVATE
  "${GATEBOUNCER_WDK_ROOT}/Include/${GATEBOUNCER_WDK_VERSION}/km"
  "${GATEBOUNCER_WDK_ROOT}/Include/${GATEBOUNCER_WDK_VERSION}/km/crt"
  "${GATEBOUNCER_SDK_ROOT}/Include/${GATEBOUNCER_WDK_VERSION}/shared")
target_compile_definitions(GateBouncerClassifier PRIVATE _AMD64_ AMD64 _WIN64
  UNICODE _UNICODE _WIN32_WINNT=0x0A00 NTDDI_VERSION=0x0A00000B)
target_compile_options(GateBouncerClassifier PRIVATE /W4 /WX /GS /kernel /Zl /utf-8)
target_link_directories(GateBouncerClassifier PRIVATE
  "${GATEBOUNCER_WDK_ROOT}/Lib/${GATEBOUNCER_WDK_VERSION}/km/x64")
target_link_libraries(GateBouncerClassifier PRIVATE ntoskrnl hal fwpkclnt wdmsec BufferOverflowFastFailK)
# El wrapper WDK inicializa la cookie antes de entrar al DriverEntry propio.
target_link_options(GateBouncerClassifier PRIVATE /DRIVER /SUBSYSTEM:NATIVE /ENTRY:GsDriverEntry
  /NODEFAULTLIB /INCREMENTAL:NO /MANIFEST:NO /DYNAMICBASE /NXCOMPAT)
