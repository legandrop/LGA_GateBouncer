#pragma once

#include <QColor>
#include <QDialog>
#include <QList>
#include <QVector>

class QLabel;
class QLineEdit;
class QPushButton;
class QWidget;

namespace LgaColorPickerInternal {
class SwatchWidget;
}

/**
 * Picker de color LGA (modal): presets + recientes, cuadrado SV plegable + barras de
 * hue/sat/val, campo hex editable y reset al lado del hex. Emite colorChanged en cada
 * drag/click de swatch; alpha siempre 255. El reset vuelve al color de fabrica de esa
 * categoria (defaultColor) sin cerrar el dialogo.
 *
 * Esta es la version de REFERENCIA LGA: nacio como copia del picker de clips del Shot
 * Player, divergio, y hoy es el componente compartido canonico. El Shot Player
 * (LGA_MediaTools/apps/player) ya lleva una COPIA de esta version: los cambios van
 * primero aca y se re-copian, como con CustomTooltip y Dialogs.
 *
 * El dialogo NO persiste nada por su cuenta: los presets traen una paleta por defecto
 * baked-in, pero los recientes los administra el llamador (setRecentColors antes de
 * exec(), recentColors()/selectedColor() despues) via el storage que corresponda
 * (QSettings en FileManagerS3).
 */
class LgaColorPickerDialog : public QDialog
{
    Q_OBJECT

public:
    explicit LgaColorPickerDialog(const QColor &initial,
                                  const QColor &defaultColor,
                                  QWidget *parent = nullptr);
    // Destruido abierto, el campo hex pierde el foco despues del destructor: se corta antes (fix de la Base/DayTrace).
    ~LgaColorPickerDialog() override;

    QColor selectedColor() const;

    /// Reemplaza la paleta de presets (por defecto ya trae 8 colores baked-in).
    void setPresetColors(const QList<QColor> &colors);
    /// Recorta a 8. El dialogo solo los MUESTRA: la persistencia es responsabilidad del llamador.
    void setRecentColors(const QList<QColor> &colors);
    QList<QColor> recentColors() const;

signals:
    void colorChanged(const QColor &color);

private:
    void setColorInternal(const QColor &color, bool emitSignal);
    /// Reposiciona hue/sat/val y repinta SV+barras: usado al saltar a un color arbitrario
    /// (swatch de preset/reciente, reset, o commit del campo hex).
    void jumpToColor(const QColor &color);
    void updatePreviewUi();
    void rebuildSvCache();
    void rebuildHueCache();
    void rebuildSatCache();
    void rebuildValCache();
    /// Repinta cuadrado SV + las tres barras (cada rebuild*Cache decide si regenera o no).
    void updateAllBars();
    /// Escribe #RRGGBB en el campo hex sin condicion de foco (usado al confirmar tipeo).
    void refreshHexEditDisplay();
    /// returnPressed / editingFinished del campo hex: parsea y aplica, o revierte si invalido.
    void commitHexEdit();

    /// Arma una fila "TAG" + 8 swatches (usado para presets y recientes). Guarda los
    /// punteros en `outSwatches` para poder refrescar color/tooltip/seleccion despues.
    /// Nombre "outSwatches" y no "slots": Qt define `slots` como macro (Q_SLOTS) cuando
    /// no se compila con QT_NO_KEYWORDS, y colisiona con un parametro de ese nombre.
    QWidget *buildSwatchRow(const QString &tag,
                            QVector<LgaColorPickerInternal::SwatchWidget *> &outSwatches);
    void refreshPresetSwatches();
    void refreshRecentSwatches();
    /// Marca con borde violeta el swatch (preset o reciente) que matchea m_color; el resto
    /// vuelve al borde plano. Se llama desde updatePreviewUi().
    void refreshSwatchSelectionHighlight();
    void toggleCustomSection();
    /// Recalcula sizeHint() con el estado actual (plegado/expandido) y vuelve a fijar el
    /// tamano del dialogo: setFixedSize() del constructor deja el alto congelado, asi que
    /// hay que soltarlo antes de volver a medir.
    void refreshFixedSize();

    QColor m_color;
    QColor m_defaultColor;
    qreal m_hue = 0.0; // 0..1
    qreal m_sat = 0.0; // 0..1
    qreal m_val = 1.0; // 0..1

    QList<QColor> m_presetColors;
    QList<QColor> m_recentColors;
    QVector<LgaColorPickerInternal::SwatchWidget *> m_presetSwatches;
    QVector<LgaColorPickerInternal::SwatchWidget *> m_recentSwatches;

    bool m_customExpanded = true;
    QWidget *m_customContent = nullptr;
    QLabel *m_customChevron = nullptr;

    QWidget *m_svSquare = nullptr;
    QWidget *m_hueBar = nullptr;
    QWidget *m_satBar = nullptr;
    QWidget *m_valBar = nullptr;
    QWidget *m_swatch = nullptr;
    QLineEdit *m_hexEdit = nullptr;
    // El usuario esta TIPEANDO en el campo hex. No alcanza con `m_hexEdit->hasFocus()`: el
    // campo es el primer widget enfocable del dialogo, asi que arranca con el foco puesto
    // sin que nadie haya escrito nada. Se prende con `textEdited` (que Qt emite SOLO ante
    // ediciones del usuario, no ante un `setText()` programatico) y se apaga al commitear.
    bool m_hexUserEditing = false;
    QPushButton *m_resetButton = nullptr;

    QImage m_svCache;
    QImage m_hueCache;
    QImage m_satCache;
    QImage m_valCache;
    qreal m_svCacheDpr = 0.0;
    qreal m_hueCacheDpr = 0.0;
    qreal m_satCacheDpr = 0.0;
    qreal m_valCacheDpr = 0.0;
    int m_svCacheHueBucket = -1;
    // La barra de sat depende de hue+val; la de val depende de hue+sat (ver rebuild*Cache).
    int m_satCacheHueBucket = -1;
    int m_satCacheValBucket = -1;
    int m_valCacheHueBucket = -1;
    int m_valCacheSatBucket = -1;
};
