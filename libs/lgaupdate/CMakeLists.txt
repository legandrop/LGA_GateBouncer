# Auto-update de las apps LGA como biblioteca interna: red, disco, validacion y helpers.
# Incluye las notas para el usuario (LgaWhatsNew): bajarlas, verificarlas y armarlas en HTML.
# La app aporta su identidad, repositorio publico, caminos de cierre/configuracion y el
# presentador de carteles (`LgaUpdateConfig::presentDialog`): la biblioteca no incluye nada
# de la app.
#
# Pieza canonica de LGA_Base_QT_C_Py: se copia IDENTICA a `libs/lgaupdate` de cada app (ver
# README.md). No se edita en la app.
add_library(LGAUpdate STATIC
    src/LgaUpdateDialog.cpp
    src/LgaUpdateService.cpp
    src/LgaVersionCompare.cpp
    src/LgaWhatsNew.cpp
    include/lgaupdate/LgaNetRetry.h
    include/lgaupdate/LgaUpdateDialog.h
    include/lgaupdate/LgaUpdateService.h
    include/lgaupdate/LgaVersionCompare.h
    include/lgaupdate/LgaWhatsNew.h
)

# AUTOMOC propio: no depende de lo que haya fijado la app que la incluye.
set_target_properties(LGAUpdate PROPERTIES AUTOMOC ON)

target_include_directories(LGAUpdate
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(LGAUpdate
    PUBLIC
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::Network
)

# Banco de pruebas de los reintentos de red (`tests/`, servidor HTTP propio en 127.0.0.1).
# Apagado por defecto: las apps copian esta carpeta tal cual y no lo compilan. Se prende al
# configurar con -DLGAUPDATE_BUILD_TESTS=ON; como se corre esta en el README.md de esta carpeta.
option(LGAUPDATE_BUILD_TESTS "Compilar el banco de pruebas de lgaupdate (tests/)" OFF)
if(LGAUPDATE_BUILD_TESTS)
    add_subdirectory(tests)
endif()
