#include "lgaupdate/LgaUpdateI18n.h"

#include <QCoreApplication>
#include <QHash>
#include <QPointer>
#include <QTranslator>

// Tabla ingles -> castellano de los textos de la biblioteca. La clave es "<contexto>|<texto en
// ingles EXACTO del tr()>", con sus placeholders, saltos de linea y marcas `&`; la traduccion
// conserva los mismos %1, %2 y el mismo HTML. `tests/check_i18n.ps1` confronta las claves con el
// codigo.
//
// Estilo de las apps LGA en castellano: infinitivo o impersonal, nunca vos ni tu ("Guardar el
// trabajo", "Volver a probar"). Las letras de los atajos (U, R, S, C, O) no cambian: las fija el
// codigo, asi que cada boton conserva su letra dentro de la palabra.
// Los nombres de app, versiones, rutas y detalles tecnicos (httpStatus, url...) no se traducen.

namespace {

#define E(context, en, es) {QStringLiteral(context "|" en), QStringLiteral(es)}

const QHash<QString, QString> &spanishTable()
{
    static const QHash<QString, QString> table = {
        // ---------- Carteles del chequeo
        E("LgaUpdateService", "Updates", "Actualizaciones"),
        E("LgaUpdateService", "An update operation is already in progress.",
          "Ya hay una actualización en curso."),
        E("LgaUpdateService", "Update Check Failed", "Error al buscar actualizaciones"),
        E("LgaUpdateService", "Could not check for updates. Please try again later.",
          "No se pudieron buscar actualizaciones. Volver a probar más tarde."),
        E("LgaUpdateService",
          "This version is too old to read the update list.\nReinstall %1 from a newer installer.",
          "Esta versión es demasiado vieja para leer la lista de actualizaciones.\n"
          "Reinstalar %1 con un instalador más nuevo."),
        E("LgaUpdateService", "The update manifest could not be read safely.",
          "No se pudo leer de forma segura la lista de actualizaciones."),
        E("LgaUpdateService", "No installable update was found.",
          "No se encontró ninguna actualización instalable."),
        E("LgaUpdateService", "Release %1 does not contain an installable asset for %2.",
          "La versión %1 no trae un instalador para %2."),
        E("LgaUpdateService", "You are running the latest version.",
          "Ya se está usando la última versión."),
        E("LgaUpdateService", "The published update is missing valid integrity information.",
          "La actualización publicada no trae una verificación de integridad válida."),

        // ---------- Cartel de version nueva
        E("LgaUpdateService", "Update Available", "Actualización disponible"),
        E("LgaUpdateService",
          "A new version of %1 is available: %2.<br><br>You are currently running version %3.<br><br>%4",
          "Hay una versión nueva de %1: %2.<br><br>La versión en uso es la %3.<br><br>%4"),
        E("LgaUpdateService", "Save your work and close every other %1 window before updating.",
          "Guardar el trabajo y cerrar las demás ventanas de %1 antes de actualizar."),
        E("LgaUpdateService",
          "<b>U</b> Update now · <b>R</b> Remind me later · <b>S</b> Skip this version<br>"
          "<b>Enter</b> / <b>Esc</b> / <b>C</b> Cancel",
          "<b>U</b> Actualizar ahora · <b>R</b> Recordar más tarde · <b>S</b> Saltear esta versión<br>"
          "<b>Enter</b> / <b>Esc</b> / <b>C</b> Cancelar"),
        E("LgaUpdateService", "&Update now", "Act&ualizar ahora"),
        E("LgaUpdateService", "&Remind me later", "&Recordar más tarde"),
        E("LgaUpdateService", "&Skip this version", "&Saltear esta versión"),
        E("LgaUpdateService", "&Cancel", "&Cancelar"),
        E("LgaUpdateService", "Update Postponed", "Actualización postergada"),
        E("LgaUpdateService", "<b>Enter</b> / <b>Esc</b> / <b>O</b> OK",
          "<b>Enter</b> / <b>Esc</b> / <b>O</b> OK"),
        E("LgaUpdateService", "&OK", "&OK"),

        // ---------- Novedades
        E("LgaUpdateService", "What's New", "Novedades"),
        E("LgaUpdateService", "%1 was updated to version %2.", "%1 se actualizó a la versión %2."),
        E("LgaUpdateService", "Release notes of %1. You are running version %2.",
          "Novedades de %1. La versión en uso es la %2."),
        E("LgaUpdateService", "There are no release notes for %1 yet.",
          "Todavía no hay novedades de %1."),
        E("LgaUpdateService",
          "The release notes could not be loaded.\nCheck your connection and try again.",
          "No se pudieron cargar las novedades.\nRevisar la conexión y volver a probar."),
        E("LgaWhatsNew", "New", "Nuevo"),
        E("LgaWhatsNew", "Improved", "Mejorado"),
        E("LgaWhatsNew", "Fixed", "Corregido"),

        // ---------- Descarga
        E("LgaUpdateService", "Update Failed", "Error de actualización"),
        E("LgaUpdateService", "The update cache directory could not be created.",
          "No se pudo crear la carpeta donde se descarga la actualización."),
        E("LgaUpdateService", "The update installer could not be saved.",
          "No se pudo guardar el instalador de la actualización."),
        E("LgaUpdateService", "Downloading %1 %2...", "Descargando %1 %2..."),
        E("LgaUpdateService", "Cancel", "Cancelar"),
        E("LgaUpdateService", "Downloading Update", "Descargando actualización"),
        E("LgaUpdateService", "Connection problem. Retrying (attempt %1 of %2)...",
          "Problema de conexión. Reintentando (intento %1 de %2)..."),
        E("LgaUpdateService", "There is not enough free disk space to download the update.",
          "No hay espacio libre suficiente en el disco para descargar la actualización."),
        E("LgaUpdateService", "The update installer could not be saved to disk.",
          "No se pudo guardar en el disco el instalador de la actualización."),
        E("LgaUpdateService", "The downloaded update failed integrity verification.",
          "La actualización descargada no pasó la verificación de integridad."),
        E("LgaUpdateService", "The server rejected the update download.",
          "El servidor rechazó la descarga de la actualización."),
        E("LgaUpdateService", "The interrupted download could not be resumed safely.",
          "No se pudo retomar de forma segura la descarga interrumpida."),
        E("LgaUpdateService", "The update installer could not be downloaded.",
          "No se pudo descargar el instalador de la actualización."),
        E("LgaUpdateService", "The update installer could not be launched.",
          "No se pudo iniciar el instalador de la actualización."),

        // ---------- Helper (Windows y macOS)
        E("LgaUpdateService", "Could not prepare update helper script.",
          "No se pudo preparar el script de actualización."),
        E("LgaUpdateService", "Could not launch update helper process.",
          "No se pudo iniciar el proceso de actualización."),
        E("LgaUpdateService", "Could not resolve the %1 app bundle for update.",
          "No se encontró el paquete de %1 para actualizarlo."),
        E("LgaUpdateService",
          "%1 could not update automatically because this location is not writable:\n%2\n\n"
          "Please install the new macOS release manually and run:\nsudo xattr -cr /Applications/%3",
          "%1 no se pudo actualizar automáticamente porque no se puede escribir en esta ubicación:\n%2\n\n"
          "Instalar a mano la versión nueva para macOS y ejecutar:\nsudo xattr -cr /Applications/%3"),
        E("LgaUpdateService", "Could not prepare macOS update helper script.",
          "No se pudo preparar el script de actualización de macOS."),
        E("LgaUpdateService", "Could not launch macOS update helper process.",
          "No se pudo iniciar el proceso de actualización de macOS."),
        E("LgaUpdateService", "Could not launch installer process.", "No se pudo iniciar el instalador."),
        E("LgaUpdateService", "%1 Update", "Actualización de %1"),
        E("LgaUpdateService",
          "The update was postponed because another %1 window is still open. Save your work, close "
          "every %1 window, and try again.",
          "La actualización se postergó porque sigue abierta otra ventana de %1. Guardar el trabajo, "
          "cerrar todas las ventanas de %1 y volver a probar."),
        E("LgaUpdateService",
          "The update was postponed because %1 is still finishing work in the background. Try again "
          "in a moment.",
          "La actualización se postergó porque %1 todavía está terminando un trabajo en segundo "
          "plano. Volver a probar en un momento."),
        E("LgaUpdateService",
          "The update could not finish. %1 was restored; details were saved in the update log.",
          "La actualización no pudo terminar. %1 quedó como estaba; el detalle se guardó en el log "
          "de actualizaciones."),
    };
    return table;
}

#undef E

// Contesta solo las claves de la tabla. Un texto que no esta devuelve un QString NULO: Qt pasa
// al traductor siguiente y, si ninguno contesta, muestra el ingles.
class SpanishTranslator final : public QTranslator
{
public:
    using QTranslator::QTranslator;

    bool isEmpty() const override { return false; }

    QString translate(const char *context, const char *sourceText, const char *disambiguation,
                      int n) const override
    {
        Q_UNUSED(disambiguation);
        Q_UNUSED(n);
        if (!context || !sourceText) {
            return {};
        }
        return spanishTable().value(QString::fromUtf8(context) + QLatin1Char('|')
                                    + QString::fromUtf8(sourceText));
    }
};

bool g_spanish = false;

} // namespace

namespace LgaUpdateI18n {

void setLanguage(const QString &code)
{
    // "es", "es_AR", "es-ES"...: vale el idioma, sin la region (QLocale().name() da "es_AR").
    const QString lang = code.trimmed().section(QLatin1Char('_'), 0, 0).section(QLatin1Char('-'), 0, 0);
    g_spanish = lang.compare(QLatin1String("es"), Qt::CaseInsensitive) == 0;
    QCoreApplication *app = QCoreApplication::instance();
    if (!app) {
        return;
    }
    static QPointer<SpanishTranslator> translator;
    if (g_spanish) {
        if (!translator) {
            translator = new SpanishTranslator(app);
        }
        // Instalarlo de nuevo lo deja primero en la lista: gana sobre los de la app, que para
        // estos contextos no tienen nada.
        QCoreApplication::installTranslator(translator);
    } else if (translator) {
        QCoreApplication::removeTranslator(translator);
    }
}

QString language()
{
    return g_spanish ? QStringLiteral("es") : QStringLiteral("en");
}

QString translate(const char *context, const char *english)
{
    return QCoreApplication::translate(context, english);
}

} // namespace LgaUpdateI18n
