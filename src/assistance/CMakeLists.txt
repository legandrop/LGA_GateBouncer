qt_add_library(gatebouncer_assistance STATIC
    ExplanationContracts.cpp
    ExplanationContracts.h
    ExplanationCoordinator.cpp
    ExplanationCoordinator.h
    MockExplanationTransport.cpp
    MockExplanationTransport.h
)
target_link_libraries(gatebouncer_assistance PUBLIC Qt6::Core)
target_include_directories(gatebouncer_assistance PUBLIC ..)
target_compile_options(gatebouncer_assistance PRIVATE -Wall -Wextra -Wpedantic)
# El vault sintetico no se compila ni se enlaza en el producto.
