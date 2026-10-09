qt_add_library(gatebouncer_retrieval STATIC
    Contracts.cpp Contracts.h Catalog.cpp Catalog.h ProviderPolicy.cpp ProviderPolicy.h
    StrictJson.cpp StrictJson.h SourceNormalizer.cpp SourceNormalizer.h
    GroundedPayload.cpp GroundedPayload.h GroundedParser.cpp GroundedParser.h
    Coordinator.cpp Coordinator.h ProviderAdapters.cpp ProviderAdapters.h
    ../broker/BrokerPrimitives.cpp
)
target_link_libraries(gatebouncer_retrieval PUBLIC gatebouncer_assistance Qt6::Core PRIVATE winhttp advapi32 bcrypt)
target_include_directories(gatebouncer_retrieval PUBLIC ../..)
target_compile_features(gatebouncer_retrieval PUBLIC cxx_std_17)
target_compile_definitions(gatebouncer_retrieval PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_compile_options(gatebouncer_retrieval PRIVATE -Wall -Wextra -Wpedantic)
