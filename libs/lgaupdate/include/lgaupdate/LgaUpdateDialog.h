#pragma once

#include <QList>
#include <QString>
#include <Qt>

#include <functional>

class QWidget;

/**
 * Lo que el updater necesita mostrar en un cartel, sin decir como se dibuja.
 *
 * Cada app LGA tiene su propio cartel modal (el `Dialogs` de la Base, el `ConfirmDialog` de
 * Theta Explorer, los carteles del Shot Player): la biblioteca arma esta descripcion y la app
 * la dibuja con el suyo, via `LgaUpdateConfig::presentDialog`. Asi la biblioteca no incluye
 * ningun header de la app y es la MISMA copia en todas.
 *
 * Los textos llegan listos y traducidos con `tr()` del servicio. `messageHtml` y `notesHtml`
 * son rich text; `details` es texto plano (status HTTP, URL, cuerpo de la respuesta) y va
 * colapsado y seleccionable, porque es lo que el usuario copia cuando algo falla.
 */
struct LgaUpdateDialogSpec {
    /// Que cartel es. Un presentador que arma cada uno a su manera decide por esto.
    enum class Kind {
        /// "Update Available": las cuatro decisiones, con las notas de la version ofrecida.
        UpdatePrompt,
        /// "What's New": las notas despues de instalar o el historial completo de Help.
        WhatsNew,
        /// Un desenlace informativo: ya estas al dia, fallo el chequeo, fallo la descarga...
        Result,
    };

    /// Que significa cada boton. El servicio decide por el rol, no por la posicion.
    enum class Role { Update, Snooze, Skip, Cancel, Ok };

    struct Button {
        Role role = Role::Ok;
        /// Con `&` para el mnemonico: "&Update now".
        QString text;
        /// La accion principal del cartel ("Update now", "OK"): estilo de accion.
        bool primary = false;
        /// Tecla que lo aprieta sin modificadores; `Qt::Key_unknown` = ninguna.
        Qt::Key shortcut = Qt::Key_unknown;
    };

    Kind kind = Kind::Result;
    /// Glyph sugerido ("download", "refresh"). La app puede ignorarlo.
    QString iconName;
    /**
     * La version de la que habla el cartel, sin `v`: la ofrecida en `UpdatePrompt`, la instalada
     * en el "What's New" de despues de instalar; vacia en el resto. Ya esta dentro de
     * `messageHtml`; existe para el presentador que arma su propio texto (FileManagerS3 y
     * PipeSync conservan "<App> <version> is available.").
     */
    QString version;
    QString title;
    QString messageHtml;
    /// Notas de version, para una caja con scroll. Vacio = sin notas.
    QString notesHtml;
    QString details;
    /// Fila que dice que hace cada tecla, con las teclas en `<b>`. Opcional para la app.
    QString hintHtml;
    /// Desenlace de error (para el icono o el color del cartel).
    bool warning = false;
    /// En el orden en que se muestran, de izquierda a derecha.
    QList<Button> buttons;
    /// El que responde a Enter.
    int defaultIndex = -1;
    /// Lo que vale Esc o cerrar la ventana.
    int escapeIndex = -1;
};

/**
 * Muestra `spec` como cartel MODAL sobre `parent` y devuelve el indice del boton elegido, o
 * `spec.escapeIndex` si se cerro con Esc o la X. `parent` puede ser null.
 */
using LgaUpdateDialogPresenter =
    std::function<int(QWidget *parent, const LgaUpdateDialogSpec &spec)>;

namespace LgaUpdateDialog {

/// Indice del primer boton con `role`, o -1.
int indexOf(const LgaUpdateDialogSpec &spec, LgaUpdateDialogSpec::Role role);

/**
 * Cartel de respaldo con `QMessageBox`, para una app que todavia no paso su presentador. Es
 * funcional pero no lleva el aspecto de ninguna app: toda app LGA pasa el suyo.
 */
int presentFallback(QWidget *parent, const LgaUpdateDialogSpec &spec);

} // namespace LgaUpdateDialog
