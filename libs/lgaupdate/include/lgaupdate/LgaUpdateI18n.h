#pragma once

#include <QString>

/**
 * Textos del updater en ingles o en castellano, segun `LgaUpdateConfig::language`.
 *
 * Los textos de la biblioteca son `tr()` en ingles. Con "es", `setLanguage()` instala un
 * `QTranslator` propio que contesta SOLO los contextos de la biblioteca (`LgaUpdateService` y
 * `LgaWhatsNew`) con la tabla de `src/LgaUpdateI18n.cpp`; para cualquier otro contexto no
 * contesta nada y la app sigue con sus traductores. Sin `.qm` ni `lrelease`: la tabla vive en el
 * codigo y viaja con la copia de la biblioteca.
 *
 * Lo llama el constructor de `LgaUpdateService`: la app solo fija `language`. Las notas de cada
 * version no pasan por aca: vienen escritas en el WhatsNew.md del producto, y en las apps
 * bilingues `LgaWhatsNew::displayText()` elige su `text_en` cuando `language()` es "en".
 *
 * `tests/check_i18n.ps1` confronta la tabla con los `tr()` de `src/`: un texto nuevo sin
 * traduccion sale en ingles, nunca vacio.
 */
namespace LgaUpdateI18n {

/// "es" (sin distinguir mayusculas) pasa al castellano; cualquier otro valor, al ingles.
void setLanguage(const QString &code);
/// "es" o "en".
QString language();
/// La traduccion de un texto de la biblioteca en el idioma actual, o el mismo texto si no hay.
QString translate(const char *context, const char *english);

} // namespace LgaUpdateI18n
