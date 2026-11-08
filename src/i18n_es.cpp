#include "i18n.h"

// Tabla inglés -> español de la interfaz (ver i18n.h). La clave es el texto en inglés EXACTO del código, con sus
// placeholders; la traducción conserva los mismos %1, %2. "contexto|texto" es la clave de I18n::trc.
// Lo que no está acá queda en inglés a propósito: el nombre de la app, Allow / Block como nombres de regla en los
// datos del motor, unidades y lo que viene del sistema.
// Estilo, como Mighty Tools: infinitivo o impersonal, nunca vos ni tú.
// tools\qa\check_i18n.ps1 confronta esta tabla con los I18n::tr / trc del código.

#define E(en, es) {QStringLiteral(en), QStringLiteral(es)}

namespace Gate::I18n {

const QHash<QString, QString> &spanishTable() {
    static const QHash<QString, QString> table = {
        // ---------- Settings: App
        E("App", "App"),
        E("Could not restart the window. The change applies the next time it opens.",
          "No se pudo reiniciar la ventana. El cambio se aplica la próxima vez que se abra."),
        E("Check for updates at startup", "Buscar actualizaciones al iniciar"),
        E("Installed version: v%1", "Versión instalada: v%1"),
        E("Check now", "Buscar ahora"),
        E("Updates are off in this copy.", "Esta copia no se actualiza."),
        E("This copy is not the installed one: it does not update itself.",
          "Esta copia no es la instalada: no se actualiza sola."),
        E("Language", "Idioma"),
        E("Zoom", "Zoom"),
        E("%1%", "%1 %"),
        E("%1 is the default. Changing the zoom or the language restarts the window.",
          "%1 es el normal. Cambiar el zoom o el idioma reinicia la ventana."),
        E("Only %1 fits on this screen.", "En esta pantalla solo entra el %1."),
        E("Up to %1 fits on this screen.", "En esta pantalla entra hasta el %1."),
    };
    return table;
}

} // namespace Gate::I18n
