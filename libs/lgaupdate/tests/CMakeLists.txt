# Banco de pruebas de los reintentos de red de lgaupdate (`LgaNetRetry.h`). Solo se construye con
# -DLGAUPDATE_BUILD_TESTS=ON (ver ../CMakeLists.txt): las apps copian `libs/lgaupdate` y no lo
# compilan.
#
# Es un exe de CONSOLA con QApplication (el servicio necesita widgets: el dialogo de progreso de
# la descarga) que corre contra un servidor HTTP propio en 127.0.0.1. Nunca sale a la red y nunca
# instala nada. Se corre SOLO con el runner de QA de la Base (`tools/qa/run_headless.ps1`), que le
# pone la plataforma offscreen y el Qt en el PATH.
add_executable(lgaupdate_retry_tests TestLgaNetRetry.cpp)

set_target_properties(lgaupdate_retry_tests PROPERTIES
    AUTOMOC ON
    WIN32_EXECUTABLE OFF
    # Un nivel abajo del CMakeCache.txt: el runner busca el cache hasta dos niveles arriba del exe
    # para saber contra que Qt se compilo.
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lgaupdate_tests"
)

target_link_libraries(lgaupdate_retry_tests PRIVATE
    LGAUpdate
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
)

if(WIN32 AND NOT MSVC)
    # El runtime de MinGW del compilador usado, junto al exe: el que trae <Qt>\bin (que el runner
    # pone en el PATH) es mas viejo, y con el el exe no resuelve sus importaciones.
    get_filename_component(LGAUPDATE_TESTS_MINGW_BIN "${CMAKE_CXX_COMPILER}" DIRECTORY)
    foreach(runtime_dll libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll)
        if(EXISTS "${LGAUPDATE_TESTS_MINGW_BIN}/${runtime_dll}")
            add_custom_command(TARGET lgaupdate_retry_tests POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                        "${LGAUPDATE_TESTS_MINGW_BIN}/${runtime_dll}"
                        "$<TARGET_FILE_DIR:lgaupdate_retry_tests>/${runtime_dll}"
                VERBATIM)
        endif()
    endforeach()
endif()
