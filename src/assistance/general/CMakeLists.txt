qt_add_library(gatebouncer_general STATIC
    GeneralContracts.h GeneralContracts.cpp
    GeneralPayload.h GeneralPayload.cpp
    GeneralCoordinator.h GeneralCoordinator.cpp
    GeneralRuntime.h GeneralRuntime.cpp
    GeneralRuntimeState.h
    GeneralJobRegistry.h GeneralJobRegistry.cpp
    PresentationContext.h PresentationContext.cpp
    PendingPresentationContext.h PendingPresentationContext.cpp
    QtSearchAdapter.h QtSearchAdapter.cpp
    GeneralWire.h GeneralWire.cpp
    InferenceEncoding.h InferenceEncoding.cpp
    GeneralChannel.h GeneralClient.h GeneralClient.cpp
    GeneralServer.h GeneralServer.cpp
)
target_link_libraries(gatebouncer_general
    PUBLIC Qt6::Core
    PRIVATE gatebouncer_retrieval gatebouncer_websearch gatebouncer_configuration
)
target_include_directories(gatebouncer_general PUBLIC ..)
target_compile_features(gatebouncer_general PUBLIC cxx_std_17)
target_compile_options(gatebouncer_general PRIVATE -Wall -Wextra -Wpedantic)

# El integrador provee configuración y transporte; este target nunca los activa.
qt_add_library(gatebouncer_general_broker STATIC
    GeneralBrokerRuntime.cpp GeneralModelTransport.h GeneralModelTransport.cpp
    GeneralFactory.h GeneralFactory.cpp GeneralDisclosures.h GeneralDisclosures.cpp
)
target_link_libraries(gatebouncer_general_broker PUBLIC gatebouncer_general PRIVATE gatebouncer_configuration Qt6::Core)
target_compile_features(gatebouncer_general_broker PUBLIC cxx_std_17)
target_compile_options(gatebouncer_general_broker PRIVATE -Wall -Wextra -Wpedantic)
