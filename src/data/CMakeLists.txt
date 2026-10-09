qt_add_library(gatebouncer_data STATIC
    contracts.cpp contracts.h
    netlimiterimport.cpp netlimiterimport.h
    activityhistory.cpp activityhistory.h
    reviewstore.cpp reviewstore.h
    ../platform/ProcessCatalog.cpp ../platform/ProcessCatalog.h
)
target_link_libraries(gatebouncer_data PUBLIC Qt6::Core)
target_include_directories(gatebouncer_data PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_compile_features(gatebouncer_data PUBLIC cxx_std_17)
target_compile_options(gatebouncer_data PRIVATE -Wall -Wextra -Wpedantic)
