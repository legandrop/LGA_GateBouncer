qt_add_library(gatebouncer_websearch STATIC
    WebSearch.h
    WebSearch.cpp
    WinHttpTransport.cpp
)
target_link_libraries(gatebouncer_websearch PUBLIC Qt6::Core)
target_include_directories(gatebouncer_websearch PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/..")
if(WIN32)
    target_link_libraries(gatebouncer_websearch PRIVATE winhttp)
endif()
