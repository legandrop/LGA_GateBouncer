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

qt_add_library(gatebouncer_general_live STATIC
    WinHttpExplanationTransport.cpp WinHttpExplanationTransport.h WinHttpCompatibility.h
    broker/BrokerPipe.cpp broker/BrokerPipe.h
    broker/BrokerPrimitives.cpp broker/BrokerPrimitives.h
    broker/BrokerWire.cpp broker/BrokerWire.h
    broker/BrokerVault.cpp broker/BrokerVault.h
    broker/BrokerLauncher.cpp broker/BrokerLauncher.h
    broker/AssistantBrokerRuntime.cpp broker/AssistantBrokerRuntime.h
    broker/GeneralBrokerHost.cpp broker/GeneralBrokerHost.h
    configuration/ConfigurationContracts.cpp configuration/ConfigurationContracts.h
    configuration/ConfigurationCodec.cpp configuration/ConfigurationCodec.h
    configuration/ConfigurationController.cpp configuration/ConfigurationController.h
    configuration/ConfigurationAuthority.h
    configuration/ConfigurationPolicy.cpp configuration/ConfigurationPolicy.h
    configuration/WindowsConfigurationStore.cpp configuration/WindowsConfigurationStore.h
    configuration/ProviderEntitlementVerifier.cpp configuration/ProviderEntitlementVerifier.h
    configuration/ProviderEntitlementInternal.h
    general/GeneralContracts.cpp general/GeneralContracts.h
    general/GeneralPayload.cpp general/GeneralPayload.h
    general/GeneralCoordinator.cpp general/GeneralCoordinator.h
    general/GeneralRuntime.cpp general/GeneralRuntime.h general/GeneralRuntimeState.h
    general/GeneralBrokerRuntime.cpp general/GeneralModelTransport.cpp general/GeneralModelTransport.h
    general/GeneralJobRegistry.cpp general/GeneralJobRegistry.h
    general/GeneralFactory.cpp general/GeneralFactory.h
    general/GeneralDisclosures.cpp general/GeneralDisclosures.h
    general/PresentationContext.cpp general/PresentationContext.h
    general/PendingPresentationContext.cpp general/PendingPresentationContext.h
    general/ObservationReader.cpp general/ObservationReader.h
    general/QtSearchAdapter.cpp general/QtSearchAdapter.h
    general/GeneralWire.cpp general/GeneralWire.h
    general/InferenceEncoding.cpp general/InferenceEncoding.h
    general/GeneralChannel.h general/GeneralClient.cpp general/GeneralClient.h
    general/GeneralServer.cpp general/GeneralServer.h
    grounded_bridge/FixedUltraProfile.cpp grounded_bridge/FixedUltraProfile.h
    grounded_bridge/NvidiaEnvelope.cpp grounded_bridge/NvidiaEnvelope.h
    grounded_bridge/GroundedBrokerRuntime.cpp grounded_bridge/GroundedBrokerRuntime.h
    retrieval/Catalog.cpp retrieval/Catalog.h retrieval/Contracts.cpp retrieval/Contracts.h
    retrieval/Coordinator.cpp retrieval/Coordinator.h
    retrieval/GroundedParser.cpp retrieval/GroundedParser.h
    retrieval/GroundedPayload.cpp retrieval/GroundedPayload.h
    retrieval/ProviderAdapters.cpp retrieval/ProviderAdapters.h
    retrieval/ProviderPolicy.cpp retrieval/ProviderPolicy.h
    retrieval/SourceNormalizer.cpp retrieval/SourceNormalizer.h
    retrieval/StrictJson.cpp retrieval/StrictJson.h
    ../websearch/WebSearch.cpp ../websearch/WebSearch.h ../websearch/WinHttpTransport.cpp
)
# La composición comparte Store, Authority y Vault; no objetos de ABI anteriores.
target_link_libraries(gatebouncer_general_live PUBLIC gatebouncer_assistance Qt6::Core PRIVATE
    gatebouncer_native_ii gatebouncer_localfacts gatebouncer_wire winhttp bcrypt crypt32 advapi32 shell32 ole32)
target_include_directories(gatebouncer_general_live PUBLIC .. .)
target_compile_features(gatebouncer_general_live PUBLIC cxx_std_17)
target_compile_definitions(gatebouncer_general_live PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_compile_options(gatebouncer_general_live PRIVATE -Wall -Wextra -Wpedantic)

qt_add_library(gatebouncer_assistance_ui STATIC
    ui/GeneralSession.cpp ui/GeneralSession.h
    ui/SettingsWidget.cpp ui/SettingsWidget.h
    ui/ExplanationWidget.cpp ui/ExplanationWidget.h
    ui/GeneralConnection.cpp ui/GeneralConnection.h
    ui/ObservationSelection.h
)
target_link_libraries(gatebouncer_assistance_ui PUBLIC gatebouncer_general_live Qt6::Widgets PRIVATE gatebouncer_service_view_ui)
target_include_directories(gatebouncer_assistance_ui PUBLIC .. .)
target_compile_definitions(gatebouncer_assistance_ui PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_compile_options(gatebouncer_assistance_ui PRIVATE -Wall -Wextra -Wpedantic)
