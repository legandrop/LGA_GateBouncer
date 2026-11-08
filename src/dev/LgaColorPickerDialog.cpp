#include "dev/LgaColorPickerDialog.h"

// Copia del picker de la Base (C:Portablega_base_qt_c_pysrcImponentsgacolorpickerdialog.cpp) para el
// editor de paletas de desarrollo. los cambios van primero en la base y se re-copian. ajustes de gatebouncer: tooltips
// con el globo propio (customtooltip, nunca el nativo) y el destructor que corta el campo hex (como en daytrace).
#include "customtooltip.h"

#include <QFont>
#include <QGraphicsDropShadowEffect>
#include <QHBoxLayout>
#include <QIcon>
#include <QImage>
#include <QLabel>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPainter>
#include <QPixmap>
#include <QPushButton>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QPainterPath>
#include <QVBoxLayout>
#include <QtMath>

#include <functional>
#include <utility>

namespace {

constexpr int kSvWidth = 240;
constexpr int kSvHeight = 140;
constexpr int kBarWidth = 240;
// Alto VISUAL de la barra de gradiente. El widget en si es mas alto (kBarWidgetH): el
// marcador sobresale 3px arriba y abajo, y ese sobrante necesita su propio espacio de
// pintura porque QPainter clipea al rect del widget.
constexpr int kBarVisualH = 11;
constexpr int kBarMarkerOverflow = 3;
constexpr int kBarWidgetH = kBarVisualH + kBarMarkerOverflow * 2;
constexpr int kSwatchSize = 26;
constexpr int kSwatchGap = 6;
constexpr int kSwatchesPerRow = 8;
constexpr int kHexSwatchSize = 30;
constexpr int kResetButtonSize = 30;

constexpr auto kBg = "#1E1E1E";
constexpr auto kText = "#E0E0E0";
constexpr auto kTagColor = "#6E6E74";
constexpr auto kSeparatorColor = "#2A2A2A";
constexpr auto kSwatchSelectedBorder = "#774DCB";

// Look de los QLineEdit de Settings (src/features/settings/components/settingstab.cpp,
// constantes kSettingsInputBackground/kSettingsInputBorder/kSettingsInputText), copiado
// literal aca porque este dialogo es otra unidad de compilacion y no comparte ese namespace
// anonimo. El texto sube a #C8C8C8 (mas claro que el gris original) para que se lea al
// lado del swatch/reset de 30x30, que quedan mas prominentes que en la version anterior.
constexpr auto kHexBg = "#1B1B1B";
constexpr auto kHexBorder = "#3A3A3A";
constexpr auto kHexText = "#C8C8C8";

constexpr auto kResetBg = "#262626";
constexpr auto kResetBorder = "#3A3A3A";

// Tokens del pie (Cancel/OK) COPIADOS de FM_DialogStyle.h (filemanagers3_core) en vez de
// incluirlo: este picker es la version de referencia LGA que va a moverse a
// LGA_Base_QT_C_Py, y FM_DialogStyle trae bastante mas que estos ocho valores (paleta de
// paths, popover de "Calculate size", icono de FM_Dialogs) atado a FileManagerS3/PipeSync.
// Si el token de FM_DialogStyle cambia, actualizar tambien aca.
constexpr auto kButtonBackground = "#3A3A3A";
constexpr auto kButtonBackgroundHover = "#454545";
constexpr auto kButtonBackgroundPressed = "#2F2F2F";
constexpr auto kButtonTextColor = "#E6E6E6";
constexpr auto kPlainBorderColor = "#4A4A4A";
constexpr auto kMarkedBorderColor = "#3B316A";
const QColor kGlowColor(QStringLiteral("#4C3078"));
constexpr int kGlowBlurRadius = 16;
constexpr int kButtonPaddingV = 6;
constexpr int kButtonPaddingH = 18;
constexpr int kButtonBorderRadius = 4;
constexpr int kButtonSpacing = 8;

QColor colorFromHsvNorm(qreal h, qreal s, qreal v)
{
    QColor c;
    c.setHsvF(qBound(0.0, h, 1.0), qBound(0.0, s, 1.0), qBound(0.0, v, 1.0), 1.0);
    c.setAlpha(255);
    return c;
}

// La flecha circular del reset, dibujada con QPainter en lugar de rasterizar el SVG de la Base: GateBouncer no lleva
// Qt6Svg.dll en el paquete. Mismo trazo que el SVG de la Base (arco de radio 9 centrado en 12,12 y la punta en 3,4-3,9-8,9).
QPixmap renderResetIcon(const QSize &logicalSize, qreal dpr)
{
    QPixmap pixmap(logicalSize * qMax(1.0, dpr));
    pixmap.fill(Qt::transparent);
    pixmap.setDevicePixelRatio(qMax(1.0, dpr));
    QPainter p(&pixmap);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.scale(logicalSize.width() / 24.0, logicalSize.height() / 24.0);
    p.setPen(QPen(QColor("#B2B2B2"), 1.8, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    QPainterPath arc;
    arc.arcMoveTo(QRectF(3, 3, 18, 18), 180);
    arc.arcTo(QRectF(3, 3, 18, 18), 180, 311.8);
    p.drawPath(arc);
    p.drawPolyline(QPolygonF({QPointF(3, 4), QPointF(3, 9), QPointF(8, 9)}));
    return pixmap;
}

// Marcador de las barras H/S/V: rectangulo redondeado blanco de 3px, sobresaliendo
// kBarMarkerOverflow px arriba y abajo de la franja visual del gradiente, con un halo
// oscuro detras que hace de sombra (equivalente al box-shadow del mockup).
void paintBarMarker(QPainter &p, qreal x, qreal visualH, qreal overflow)
{
    p.setRenderHint(QPainter::Antialiasing, true);
    const QRectF outer(x - 2.0, 0.0, 4.0, visualH + overflow * 2.0);
    const QRectF inner(x - 1.5, 0.5, 3.0, visualH + overflow * 2.0 - 1.0);
    p.setPen(Qt::NoPen);
    p.setBrush(QColor(0, 0, 0, 153));
    p.drawRoundedRect(outer, 2.5, 2.5);
    p.setBrush(Qt::white);
    p.drawRoundedRect(inner, 2.0, 2.0);
}

// Pone el texto en 10px con letter-spacing: Qt Style Sheets no soporta text-transform ni
// letter-spacing, asi que el look de los labels "PRESETS"/"RECENT"/"CUSTOM" (mayuscula +
// tracking) se resuelve en C++ y no en QSS. El color si sale del QSS del dialogo.
void applyTagFont(QLabel *label)
{
    QFont f = label->font();
    f.setPixelSize(10);
    f.setLetterSpacing(QFont::AbsoluteSpacing, 0.8);
    label->setFont(f);
}

class SvSquareWidget : public QWidget
{
public:
    using PressFn = std::function<void(const QPointF &)>;

    explicit SvSquareWidget(QWidget *parent = nullptr)
        : QWidget(parent)
    {
        setFixedSize(kSvWidth, kSvHeight);
        setMouseTracking(true);
        setCursor(Qt::CrossCursor);
    }

    void setPaintFn(std::function<void(QPainter &, const QRect &)> fn) { m_paint = std::move(fn); }
    void setPressFn(PressFn fn) { m_press = std::move(fn); }

protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        if (m_paint) {
            m_paint(p, rect());
        }
    }

    void mousePressEvent(QMouseEvent *event) override
    {
        if (event->button() == Qt::LeftButton && m_press) {
            m_press(event->position());
        }
    }

    void mouseMoveEvent(QMouseEvent *event) override
    {
        if ((event->buttons() & Qt::LeftButton) && m_press) {
            m_press(event->position());
        }
    }

private:
    std::function<void(QPainter &, const QRect &)> m_paint;
    PressFn m_press;
};

// Barra horizontal generica de gradiente (hue, sat o val): el gradiente y el press/drag
// salen de afuera via setPaintFn/setPressFn, la clase no sabe de que componente se trata.
// El widget es mas alto que la franja visual del gradiente (ver kBarWidgetH) para dejarle
// espacio al marcador, que sobresale por arriba y por abajo.
class GradientBarWidget : public QWidget
{
public:
    using PressFn = std::function<void(const QPointF &)>;

    explicit GradientBarWidget(QWidget *parent = nullptr)
        : QWidget(parent)
    {
        setFixedSize(kBarWidth, kBarWidgetH);
        setCursor(Qt::PointingHandCursor);
    }

    void setPaintFn(std::function<void(QPainter &, const QRect &)> fn) { m_paint = std::move(fn); }
    void setPressFn(PressFn fn) { m_press = std::move(fn); }

protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        if (m_paint) {
            m_paint(p, rect());
        }
    }

    void mousePressEvent(QMouseEvent *event) override
    {
        if (event->button() == Qt::LeftButton && m_press) {
            m_press(event->position());
        }
    }

    void mouseMoveEvent(QMouseEvent *event) override
    {
        if ((event->buttons() & Qt::LeftButton) && m_press) {
            m_press(event->position());
        }
    }

private:
    std::function<void(QPainter &, const QRect &)> m_paint;
    PressFn m_press;
};

// Fila generica clickeable (header "CUSTOM"): sin senales propias, solo un callback, mismo
// criterio que el resto de los widgets internos del archivo (std::function en vez de moc).
class ClickableRow : public QWidget
{
public:
    using ClickFn = std::function<void()>;

    explicit ClickableRow(QWidget *parent = nullptr)
        : QWidget(parent)
    {
        setCursor(Qt::PointingHandCursor);
    }

    void setClickFn(ClickFn fn) { m_click = std::move(fn); }

protected:
    void mousePressEvent(QMouseEvent *event) override
    {
        if (event->button() == Qt::LeftButton && m_click) {
            m_click();
        }
    }

private:
    ClickFn m_click;
};

} // namespace

// SwatchWidget vive en el namespace declarado por el header (LgaColorPickerInternal), asi
// LgaColorPickerDialog.h puede guardar QVector<SwatchWidget*> sin conocer la clase entera.
namespace LgaColorPickerInternal {

class SwatchWidget : public QWidget
{
public:
    using ClickFn = std::function<void()>;

    explicit SwatchWidget(QWidget *parent = nullptr)
        : QWidget(parent)
    {
        setFixedSize(kSwatchSize, kSwatchSize);
    }

    void setColor(const QColor &color)
    {
        m_color = color;
        CustomTooltip::instance()->setToolTip(this, color.isValid() ? color.name(QColor::HexRgb).toUpper() : QString());
        update();
    }
    QColor color() const { return m_color; }

    void setEmpty(bool empty)
    {
        m_empty = empty;
        setCursor(empty ? Qt::ArrowCursor : Qt::PointingHandCursor);
        if (empty) {
            CustomTooltip::instance()->setToolTip(this, QString());
        }
        update();
    }
    bool isEmpty() const { return m_empty; }

    void setSelected(bool selected)
    {
        if (m_selected == selected) {
            return;
        }
        m_selected = selected;
        update();
    }

    void setClickFn(ClickFn fn) { m_click = std::move(fn); }

protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF r(0.5, 0.5, width() - 1.0, height() - 1.0);

        if (m_empty) {
            // Slot de reciente sin usar todavia: no clickeable, borde punteado.
            p.setBrush(QColor(QStringLiteral("#1B1B1B")));
            QPen pen(QColor(QStringLiteral("#3A3A3A")));
            pen.setStyle(Qt::DashLine);
            pen.setWidthF(1.0);
            p.setPen(pen);
            p.drawRoundedRect(r, 4, 4);
            return;
        }

        p.setBrush(m_color);
        if (m_selected) {
            p.setPen(QPen(QColor(QLatin1String(kSwatchSelectedBorder)), 2.0));
        } else {
            p.setPen(QPen(QColor(255, 255, 255, 26), 1.0));
        }
        p.drawRoundedRect(r, 4, 4);
    }

    void mousePressEvent(QMouseEvent *event) override
    {
        if (!m_empty && event->button() == Qt::LeftButton && m_click) {
            m_click();
        }
    }

private:
    QColor m_color;
    bool m_empty = false;
    bool m_selected = false;
    ClickFn m_click;
};

} // namespace LgaColorPickerInternal

using LgaColorPickerInternal::SwatchWidget;

LgaColorPickerDialog::~LgaColorPickerDialog()
{
    if (m_hexEdit) {
        m_hexEdit->disconnect(this);
    }
}

LgaColorPickerDialog::LgaColorPickerDialog(const QColor &initial,
                                           const QColor &defaultColor,
                                           QWidget *parent)
    : QDialog(parent)
{
    setObjectName(QStringLiteral("lgaColorPickerDialog"));
    setWindowTitle(QStringLiteral("Select clip color"));
    setModal(true);
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);

    QColor start = initial.isValid() ? initial : QColor(QStringLiteral("#3A3A3A"));
    start.setAlpha(255);
    m_color = start;
    m_hue = start.hsvHueF();
    if (m_hue < 0.0) {
        m_hue = 0.0; // achromatic
    }
    m_sat = start.hsvSaturationF();
    m_val = start.valueF();

    m_defaultColor = defaultColor.isValid() ? defaultColor : start;
    m_defaultColor.setAlpha(255);

    // Paleta baked-in: 8 tonos que cubren el espectro sin repetir el violeta de marca mas
    // de una vez. setPresetColors() la reemplaza si el llamador quiere otra.
    m_presetColors = {
        QColor(QStringLiteral("#2E5A8E")), QColor(QStringLiteral("#443A91")),
        QColor(QStringLiteral("#774DCB")), QColor(QStringLiteral("#2E8E7A")),
        QColor(QStringLiteral("#4A7A2E")), QColor(QStringLiteral("#8E7A2E")),
        QColor(QStringLiteral("#8E4A2E")), QColor(QStringLiteral("#8E2E5A")),
    };

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(18, 16, 18, 18);
    root->setSpacing(12);

    root->addWidget(buildSwatchRow(QStringLiteral("PRESETS"), m_presetSwatches));
    refreshPresetSwatches();

    root->addWidget(buildSwatchRow(QStringLiteral("RECENT"), m_recentSwatches));
    refreshRecentSwatches();

    auto *separator = new QWidget(this);
    separator->setFixedHeight(1);
    separator->setStyleSheet(QStringLiteral("background-color: %1;").arg(QLatin1String(kSeparatorColor)));
    root->addWidget(separator);

    // ---------------------------------------------------------------- seccion "Custom"
    // objectName "lgaColorPickerRow" en TODOS los QWidget contenedores de aca en mas
    // (customSection, m_customContent, barsContainer, hexRow, footer): sin eso heredan el
    // fondo #161616 de la regla global "QWidget { background-color: ... }" del tema oscuro
    // de la app y se ve como un rectangulo mas oscuro flotando sobre el fondo del dialogo.
    auto *customSection = new QWidget(this);
    customSection->setObjectName(QStringLiteral("lgaColorPickerRow"));
    auto *customSectionLayout = new QVBoxLayout(customSection);
    customSectionLayout->setContentsMargins(0, 0, 0, 0);
    customSectionLayout->setSpacing(9);

    auto *header = new ClickableRow(customSection);
    header->setObjectName(QStringLiteral("lgaColorPickerRow"));
    auto *headerLayout = new QHBoxLayout(header);
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(6);
    m_customChevron = new QLabel(QStringLiteral("▾"), header); // ▾ = triangulo abajo (expandido)
    m_customChevron->setObjectName(QStringLiteral("lgaColorPickerChevron"));
    headerLayout->addWidget(m_customChevron);
    auto *customLabel = new QLabel(QStringLiteral("CUSTOM"), header);
    customLabel->setObjectName(QStringLiteral("lgaColorPickerTag"));
    applyTagFont(customLabel);
    headerLayout->addWidget(customLabel);
    headerLayout->addStretch(1);
    header->setClickFn([this]() { toggleCustomSection(); });
    customSectionLayout->addWidget(header);

    // Todo lo de abajo del header vive en m_customContent: es lo que se oculta al plegar.
    m_customContent = new QWidget(customSection);
    m_customContent->setObjectName(QStringLiteral("lgaColorPickerRow"));
    auto *contentLayout = new QVBoxLayout(m_customContent);
    contentLayout->setContentsMargins(0, 0, 0, 0);
    contentLayout->setSpacing(9);

    auto *sv = new SvSquareWidget(m_customContent);
    m_svSquare = sv;
    sv->setPaintFn([this](QPainter &p, const QRect &r) {
        rebuildSvCache();
        p.setRenderHint(QPainter::SmoothPixmapTransform, false);
        p.drawImage(r, m_svCache);

        // Anillo del cursor SV.
        const qreal x = m_sat * (r.width() - 1);
        const qreal y = (1.0 - m_val) * (r.height() - 1);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setPen(QPen(Qt::white, 2.0));
        p.setBrush(Qt::NoBrush);
        p.drawEllipse(QPointF(x, y), 6.0, 6.0);
        p.setPen(QPen(QColor(0, 0, 0, 140), 1.0));
        p.drawEllipse(QPointF(x, y), 7.0, 7.0);
    });
    sv->setPressFn([this](const QPointF &pos) {
        const qreal w = qMax(1, m_svSquare->width() - 1);
        const qreal h = qMax(1, m_svSquare->height() - 1);
        m_sat = qBound(0.0, pos.x() / w, 1.0);
        m_val = qBound(0.0, 1.0 - (pos.y() / h), 1.0);
        setColorInternal(colorFromHsvNorm(m_hue, m_sat, m_val), true);
        updateAllBars();
    });
    contentLayout->addWidget(sv, 0, Qt::AlignHCenter);

    auto *barsContainer = new QWidget(m_customContent);
    barsContainer->setObjectName(QStringLiteral("lgaColorPickerRow"));
    auto *barsLayout = new QVBoxLayout(barsContainer);
    barsLayout->setContentsMargins(0, 0, 0, 0);
    // Spacing 0 y NO 6: cada GradientBarWidget ya reserva kBarMarkerOverflow (3px) de
    // margen transparente arriba y abajo para el marcador que sobresale, asi que dos
    // barras consecutivas quedan a 3+3=6px de distancia entre sus franjas de gradiente
    // VISIBLES sin que el layout sume nada mas encima.
    barsLayout->setSpacing(0);

    auto *hue = new GradientBarWidget(m_customContent);
    m_hueBar = hue;
    hue->setPaintFn([this](QPainter &p, const QRect &r) {
        rebuildHueCache();
        p.fillRect(r, QColor(QLatin1String(kBg)));
        const QRect barRect(r.x(), r.y() + kBarMarkerOverflow, r.width(), kBarVisualH);
        p.drawImage(barRect, m_hueCache);

        const qreal x = m_hue * (barRect.width() - 1);
        paintBarMarker(p, x, kBarVisualH, kBarMarkerOverflow);
    });
    hue->setPressFn([this](const QPointF &pos) {
        const qreal w = qMax(1, m_hueBar->width() - 1);
        m_hue = qBound(0.0, pos.x() / w, 1.0);
        setColorInternal(colorFromHsvNorm(m_hue, m_sat, m_val), true);
        updateAllBars();
    });
    barsLayout->addWidget(hue);

    auto *sat = new GradientBarWidget(m_customContent);
    m_satBar = sat;
    sat->setPaintFn([this](QPainter &p, const QRect &r) {
        rebuildSatCache();
        p.fillRect(r, QColor(QLatin1String(kBg)));
        const QRect barRect(r.x(), r.y() + kBarMarkerOverflow, r.width(), kBarVisualH);
        p.drawImage(barRect, m_satCache);

        const qreal x = m_sat * (barRect.width() - 1);
        paintBarMarker(p, x, kBarVisualH, kBarMarkerOverflow);
    });
    sat->setPressFn([this](const QPointF &pos) {
        const qreal w = qMax(1, m_satBar->width() - 1);
        m_sat = qBound(0.0, pos.x() / w, 1.0);
        setColorInternal(colorFromHsvNorm(m_hue, m_sat, m_val), true);
        updateAllBars();
    });
    barsLayout->addWidget(sat);

    auto *val = new GradientBarWidget(m_customContent);
    m_valBar = val;
    val->setPaintFn([this](QPainter &p, const QRect &r) {
        rebuildValCache();
        p.fillRect(r, QColor(QLatin1String(kBg)));
        const QRect barRect(r.x(), r.y() + kBarMarkerOverflow, r.width(), kBarVisualH);
        p.drawImage(barRect, m_valCache);

        const qreal x = m_val * (barRect.width() - 1);
        paintBarMarker(p, x, kBarVisualH, kBarMarkerOverflow);
    });
    val->setPressFn([this](const QPointF &pos) {
        const qreal w = qMax(1, m_valBar->width() - 1);
        m_val = qBound(0.0, pos.x() / w, 1.0);
        setColorInternal(colorFromHsvNorm(m_hue, m_sat, m_val), true);
        updateAllBars();
    });
    barsLayout->addWidget(val);

    contentLayout->addWidget(barsContainer, 0, Qt::AlignHCenter);

    auto *hexRow = new QWidget(m_customContent);
    hexRow->setObjectName(QStringLiteral("lgaColorPickerRow"));
    hexRow->setFixedWidth(kSvWidth); // mismo ancho que el cuadrado SV/las barras, centrado abajo
    auto *hexRowLayout = new QHBoxLayout(hexRow);
    hexRowLayout->setContentsMargins(0, 0, 0, 0);
    hexRowLayout->setSpacing(8);

    m_swatch = new QWidget(hexRow);
    m_swatch->setFixedSize(kHexSwatchSize, kHexSwatchSize);
    m_swatch->setObjectName(QStringLiteral("lgaColorPickerSwatch"));
    hexRowLayout->addWidget(m_swatch);

    m_hexEdit = new QLineEdit(hexRow);
    m_hexEdit->setObjectName(QStringLiteral("lgaColorPickerHex"));
    m_hexEdit->setValidator(new QRegularExpressionValidator(
        QRegularExpression(QStringLiteral("^#?[0-9A-Fa-f]{0,6}$")), m_hexEdit));
    // `textEdited` (NO `textChanged`) es la unica senal que distingue una edicion del usuario
    // de un `setText()` nuestro: es lo que marca que el campo manda sobre el color.
    connect(m_hexEdit, &QLineEdit::textEdited, this, [this]() { m_hexUserEditing = true; });
    connect(m_hexEdit, &QLineEdit::returnPressed, this, &LgaColorPickerDialog::commitHexEdit);
    connect(m_hexEdit, &QLineEdit::editingFinished, this, &LgaColorPickerDialog::commitHexEdit);
    hexRowLayout->addWidget(m_hexEdit, 1);

    m_resetButton = new QPushButton(hexRow);
    m_resetButton->setObjectName(QStringLiteral("lgaColorPickerReset"));
    m_resetButton->setFixedSize(kResetButtonSize, kResetButtonSize);
    m_resetButton->setCursor(Qt::PointingHandCursor);
    m_resetButton->setAutoDefault(false);
    CustomTooltip::instance()->setToolTip(m_resetButton, QStringLiteral("Reset to default"));
    const qreal iconDpr = m_resetButton->devicePixelRatioF();
    const QPixmap resetPixmap = renderResetIcon(QSize(15, 15), iconDpr);
    m_resetButton->setIcon(QIcon(resetPixmap));
    m_resetButton->setIconSize(QSize(15, 15));
    connect(m_resetButton, &QPushButton::clicked, this, [this]() { jumpToColor(m_defaultColor); });
    hexRowLayout->addWidget(m_resetButton);

    contentLayout->addWidget(hexRow, 0, Qt::AlignHCenter);

    customSectionLayout->addWidget(m_customContent);
    root->addWidget(customSection);

    // ---------------------------------------------------------------------------- pie
    // QHBoxLayout propio, NO QDialogButtonBox: en Windows el box reordena a "OK | Cancel"
    // y el diseno pide "Cancel | OK" con OK ultimo y marcado (mismo patron que
    // src/ui/dialogs/FM_Dialogs.cpp). Se usan QPushButton simples en vez de FM_DialogButton
    // (que tambien vive en filemanagers3_core) para no atar este componente -destinado a
    // LGA_Base_QT_C_Py- a su logica de subrayado de mnemonico, que aca no hace falta.
    auto *footer = new QWidget(this);
    footer->setObjectName(QStringLiteral("lgaColorPickerRow"));
    auto *footerLayout = new QHBoxLayout(footer);
    footerLayout->setContentsMargins(0, 6, 0, 0);
    footerLayout->setSpacing(kButtonSpacing);
    footerLayout->addStretch(1);

    auto *cancelBtn = new QPushButton(QStringLiteral("Cancel"), footer);
    cancelBtn->setObjectName(QStringLiteral("lgaColorPickerCancel"));
    cancelBtn->setAutoDefault(false);
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
    footerLayout->addWidget(cancelBtn);

    auto *okBtn = new QPushButton(QStringLiteral("OK"), footer);
    okBtn->setObjectName(QStringLiteral("lgaColorPickerOk"));
    okBtn->setDefault(true);
    okBtn->setAutoDefault(true);
    connect(okBtn, &QPushButton::clicked, this, &QDialog::accept);
    footerLayout->addWidget(okBtn);

    // Glow del boton marcado: mismo patron que DialogButtonNavFilter en FM_Dialogs.cpp
    // (QGraphicsDropShadowEffect siempre montado, blur/color de los tokens copiados arriba).
    auto *glow = new QGraphicsDropShadowEffect(okBtn);
    glow->setBlurRadius(kGlowBlurRadius);
    glow->setColor(kGlowColor);
    glow->setOffset(0, 0);
    okBtn->setGraphicsEffect(glow);

    root->addWidget(footer);

    // Chrome scoped por objectName (tokens DialogStyle LGA + los del pie copiados arriba).
    setStyleSheet(
        QStringLiteral("QDialog#lgaColorPickerDialog {"
                       "  background-color: %1;"
                       "  color: %2;"
                       "}")
            .arg(QLatin1String(kBg), QLatin1String(kText))
        + QStringLiteral("QDialog#lgaColorPickerDialog QWidget#lgaColorPickerRow {"
                         "  background: transparent;"
                         "}")
        + QStringLiteral("QDialog#lgaColorPickerDialog QLabel#lgaColorPickerTag,"
                         "QDialog#lgaColorPickerDialog QLabel#lgaColorPickerChevron {"
                         "  color: %1;"
                         "}")
              .arg(QLatin1String(kTagColor))
        + QStringLiteral("QDialog#lgaColorPickerDialog QLineEdit#lgaColorPickerHex {"
                         "  color: %1;"
                         "  background-color: %2;"
                         "  border: 1px solid %3;"
                         "  border-radius: 3px;"
                         "  padding: 6px 10px;"
                         "  font-size: 13px;"
                         "  font-weight: 600;"
                         "  letter-spacing: 1px;"
                         "}")
              .arg(QLatin1String(kHexText), QLatin1String(kHexBg), QLatin1String(kHexBorder))
        + QStringLiteral("QDialog#lgaColorPickerDialog QPushButton#lgaColorPickerReset {"
                         "  background-color: %1;"
                         "  border: 1px solid %2;"
                         "  border-radius: 4px;"
                         "}")
              .arg(QLatin1String(kResetBg), QLatin1String(kResetBorder))
        + QStringLiteral("QDialog#lgaColorPickerDialog QPushButton#lgaColorPickerCancel,"
                         "QDialog#lgaColorPickerDialog QPushButton#lgaColorPickerOk {"
                         "  background-color: %1;"
                         "  color: %2;"
                         "  border: 1px solid %3;"
                         "  border-radius: %4px;"
                         "  padding: %5px %6px;"
                         "  min-width: 64px;"
                         "}")
              .arg(QLatin1String(kButtonBackground), QLatin1String(kButtonTextColor),
                   QLatin1String(kPlainBorderColor))
              .arg(kButtonBorderRadius)
              .arg(kButtonPaddingV)
              .arg(kButtonPaddingH)
        + QStringLiteral("QDialog#lgaColorPickerDialog QPushButton#lgaColorPickerCancel:hover,"
                         "QDialog#lgaColorPickerDialog QPushButton#lgaColorPickerOk:hover {"
                         "  background-color: %1;"
                         "}")
              .arg(QLatin1String(kButtonBackgroundHover))
        + QStringLiteral("QDialog#lgaColorPickerDialog QPushButton#lgaColorPickerCancel:pressed,"
                         "QDialog#lgaColorPickerDialog QPushButton#lgaColorPickerOk:pressed {"
                         "  background-color: %1;"
                         "}")
              .arg(QLatin1String(kButtonBackgroundPressed))
        + QStringLiteral("QDialog#lgaColorPickerDialog QPushButton#lgaColorPickerOk {"
                         "  border: 1px solid %1;"
                         "}")
              .arg(QLatin1String(kMarkedBorderColor)));

    updatePreviewUi();
    adjustSize();
    setFixedSize(sizeHint());
}

QColor LgaColorPickerDialog::selectedColor() const
{
    return m_color;
}

void LgaColorPickerDialog::setPresetColors(const QList<QColor> &colors)
{
    m_presetColors = colors.mid(0, kSwatchesPerRow);
    refreshPresetSwatches();
}

void LgaColorPickerDialog::setRecentColors(const QList<QColor> &colors)
{
    m_recentColors = colors.mid(0, kSwatchesPerRow);
    refreshRecentSwatches();
}

QList<QColor> LgaColorPickerDialog::recentColors() const
{
    return m_recentColors;
}

QWidget *LgaColorPickerDialog::buildSwatchRow(const QString &tag, QVector<SwatchWidget *> &outSwatches)
{
    auto *container = new QWidget(this);
    container->setObjectName(QStringLiteral("lgaColorPickerRow"));
    auto *layout = new QVBoxLayout(container);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(7);

    auto *label = new QLabel(tag, container);
    label->setObjectName(QStringLiteral("lgaColorPickerTag"));
    applyTagFont(label);
    layout->addWidget(label);

    auto *grid = new QWidget(container);
    grid->setObjectName(QStringLiteral("lgaColorPickerRow"));
    auto *gridLayout = new QHBoxLayout(grid);
    gridLayout->setContentsMargins(0, 0, 0, 0);
    gridLayout->setSpacing(kSwatchGap);

    outSwatches.clear();
    outSwatches.reserve(kSwatchesPerRow);
    for (int i = 0; i < kSwatchesPerRow; ++i) {
        auto *swatch = new SwatchWidget(grid);
        gridLayout->addWidget(swatch);
        outSwatches.append(swatch);
    }
    layout->addWidget(grid);

    return container;
}

void LgaColorPickerDialog::refreshPresetSwatches()
{
    for (int i = 0; i < m_presetSwatches.size(); ++i) {
        SwatchWidget *swatch = m_presetSwatches.at(i);
        if (!swatch) {
            continue;
        }
        if (i < m_presetColors.size() && m_presetColors.at(i).isValid()) {
            const QColor c = m_presetColors.at(i);
            swatch->setEmpty(false);
            swatch->setColor(c);
            swatch->setClickFn([this, c]() { jumpToColor(c); });
        } else {
            swatch->setEmpty(true);
            swatch->setClickFn(nullptr);
        }
    }
    refreshSwatchSelectionHighlight();
}

void LgaColorPickerDialog::refreshRecentSwatches()
{
    for (int i = 0; i < m_recentSwatches.size(); ++i) {
        SwatchWidget *swatch = m_recentSwatches.at(i);
        if (!swatch) {
            continue;
        }
        if (i < m_recentColors.size() && m_recentColors.at(i).isValid()) {
            const QColor c = m_recentColors.at(i);
            swatch->setEmpty(false);
            swatch->setColor(c);
            swatch->setClickFn([this, c]() { jumpToColor(c); });
        } else {
            swatch->setEmpty(true);
            swatch->setClickFn(nullptr);
        }
    }
    refreshSwatchSelectionHighlight();
}

void LgaColorPickerDialog::refreshSwatchSelectionHighlight()
{
    const QString currentHex = m_color.name(QColor::HexRgb);
    auto matches = [&currentHex](const QColor &c) {
        return c.isValid() && c.name(QColor::HexRgb).compare(currentHex, Qt::CaseInsensitive) == 0;
    };
    for (SwatchWidget *swatch : m_presetSwatches) {
        if (swatch && !swatch->isEmpty()) {
            swatch->setSelected(matches(swatch->color()));
        }
    }
    for (SwatchWidget *swatch : m_recentSwatches) {
        if (swatch && !swatch->isEmpty()) {
            swatch->setSelected(matches(swatch->color()));
        }
    }
}

void LgaColorPickerDialog::toggleCustomSection()
{
    m_customExpanded = !m_customExpanded;
    if (m_customContent) {
        m_customContent->setVisible(m_customExpanded);
    }
    if (m_customChevron) {
        // ▾ = triangulo abajo (expandido), ▸ = triangulo derecha (plegado).
        m_customChevron->setText(m_customExpanded ? QStringLiteral("▾") : QStringLiteral("▸"));
    }
    refreshFixedSize();
}

void LgaColorPickerDialog::refreshFixedSize()
{
    // El constructor termina con setFixedSize(sizeHint()), asi que el dialogo no se puede
    // volver a medir sin soltar antes el tamano fijo (si no, adjustSize()/sizeHint() no
    // tienen efecto porque min==max ya esta clavado al valor viejo).
    setMinimumSize(0, 0);
    setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX);
    if (layout()) {
        layout()->activate();
    }
    adjustSize();
    setFixedSize(sizeHint());
}

void LgaColorPickerDialog::setColorInternal(const QColor &color, bool emitSignal)
{
    QColor c = color;
    c.setAlpha(255);
    if (m_color == c && !emitSignal) {
        return;
    }
    m_color = c;
    updatePreviewUi();
    if (emitSignal) {
        emit colorChanged(m_color);
    }
}

void LgaColorPickerDialog::jumpToColor(const QColor &color)
{
    QColor target = color;
    target.setAlpha(255);
    m_hue = target.hsvHueF();
    if (m_hue < 0.0) {
        m_hue = 0.0; // gris puro: hue indefinido, se ancla en rojo
    }
    m_sat = target.hsvSaturationF();
    m_val = target.valueF();
    setColorInternal(target, true);
    updateAllBars();
}

void LgaColorPickerDialog::updatePreviewUi()
{
    // Solo se saltea el refresco si el usuario ESTA TIPEANDO, no si el campo tiene el foco:
    // el campo arranca enfocado (es el primer widget enfocable del dialogo), asi que con
    // `hasFocus()` el texto se quedaba clavado en el color inicial durante todo el arrastre.
    if (m_hexEdit && !m_hexUserEditing) {
        refreshHexEditDisplay();
    }
    if (m_swatch) {
        const QString hex = m_color.name(QColor::HexRgb).toUpper();
        m_swatch->setStyleSheet(
            QStringLiteral(
                "QWidget#lgaColorPickerSwatch {"
                "  background-color: %1;"
                "  border: 1px solid %2;"
                "  border-radius: 4px;"
                "}")
                .arg(hex, QLatin1String(kPlainBorderColor)));
    }
    refreshSwatchSelectionHighlight();
}

void LgaColorPickerDialog::refreshHexEditDisplay()
{
    if (!m_hexEdit) {
        return;
    }
    const QString hex = m_color.name(QColor::HexRgb).toUpper();
    if (m_hexEdit->text() != hex) {
        m_hexEdit->setText(hex);
    }
}

void LgaColorPickerDialog::commitHexEdit()
{
    if (!m_hexEdit) {
        return;
    }
    // Si el usuario nunca tipeo, no hay nada que commitear: el campo es un REFLEJO del color,
    // no su fuente. `editingFinished` tambien se dispara al cerrar el dialogo (el campo pierde
    // el foco), y sin esta guarda ese cierre reaplicaba el texto viejo y pisaba lo elegido.
    if (!m_hexUserEditing) {
        refreshHexEditDisplay();
        return;
    }
    m_hexUserEditing = false;
    QString text = m_hexEdit->text().trimmed();
    if (!text.startsWith(QLatin1Char('#'))) {
        text.prepend(QLatin1Char('#'));
    }
    const QString digits = text.mid(1);
    const QColor parsed(text);
    if (digits.size() == 6 && parsed.isValid()) {
        QColor c = parsed;
        c.setAlpha(255);
        jumpToColor(c);
    }
    // Invalido, o valido pero igual al actual: de cualquier forma dejamos el texto en
    // el formato canonico (#RRGGBB en mayusculas) del color vigente.
    refreshHexEditDisplay();
}

void LgaColorPickerDialog::updateAllBars()
{
    if (m_svSquare) {
        m_svSquare->update();
    }
    if (m_hueBar) {
        m_hueBar->update();
    }
    if (m_satBar) {
        m_satBar->update();
    }
    if (m_valBar) {
        m_valBar->update();
    }
}

void LgaColorPickerDialog::rebuildSvCache()
{
    if (!m_svSquare) {
        return;
    }
    const qreal dpr = m_svSquare->devicePixelRatioF();
    const int hueBucket = qRound(m_hue * 360.0);
    const int pw = qMax(1, qRound(m_svSquare->width() * dpr));
    const int ph = qMax(1, qRound(m_svSquare->height() * dpr));
    if (m_svCache.width() == pw && m_svCache.height() == ph && qFuzzyCompare(m_svCacheDpr, dpr)
        && m_svCacheHueBucket == hueBucket) {
        return;
    }

    m_svCache = QImage(pw, ph, QImage::Format_RGB32);
    m_svCache.setDevicePixelRatio(dpr);
    for (int y = 0; y < ph; ++y) {
        const qreal v = 1.0 - (static_cast<qreal>(y) / qMax(1, ph - 1));
        auto *line = reinterpret_cast<QRgb *>(m_svCache.scanLine(y));
        for (int x = 0; x < pw; ++x) {
            const qreal s = static_cast<qreal>(x) / qMax(1, pw - 1);
            line[x] = colorFromHsvNorm(m_hue, s, v).rgb();
        }
    }
    m_svCacheDpr = dpr;
    m_svCacheHueBucket = hueBucket;
}

void LgaColorPickerDialog::rebuildHueCache()
{
    if (!m_hueBar) {
        return;
    }
    const qreal dpr = m_hueBar->devicePixelRatioF();
    const int pw = qMax(1, qRound(m_hueBar->width() * dpr));
    const int ph = qMax(1, qRound(kBarVisualH * dpr));
    if (m_hueCache.width() == pw && m_hueCache.height() == ph && qFuzzyCompare(m_hueCacheDpr, dpr)) {
        return;
    }

    m_hueCache = QImage(pw, ph, QImage::Format_RGB32);
    m_hueCache.setDevicePixelRatio(dpr);
    for (int x = 0; x < pw; ++x) {
        const qreal h = static_cast<qreal>(x) / qMax(1, pw - 1);
        const QRgb rgb = colorFromHsvNorm(h, 1.0, 1.0).rgb();
        for (int y = 0; y < ph; ++y) {
            reinterpret_cast<QRgb *>(m_hueCache.scanLine(y))[x] = rgb;
        }
    }
    m_hueCacheDpr = dpr;
}

void LgaColorPickerDialog::rebuildSatCache()
{
    if (!m_satBar) {
        return;
    }
    const qreal dpr = m_satBar->devicePixelRatioF();
    // La barra de sat pinta S=0..1 con H y V actuales, asi que su cache depende de los dos.
    const int hueBucket = qRound(m_hue * 360.0);
    const int valBucket = qRound(m_val * 255.0);
    const int pw = qMax(1, qRound(m_satBar->width() * dpr));
    const int ph = qMax(1, qRound(kBarVisualH * dpr));
    if (m_satCache.width() == pw && m_satCache.height() == ph && qFuzzyCompare(m_satCacheDpr, dpr)
        && m_satCacheHueBucket == hueBucket && m_satCacheValBucket == valBucket) {
        return;
    }

    m_satCache = QImage(pw, ph, QImage::Format_RGB32);
    m_satCache.setDevicePixelRatio(dpr);
    for (int x = 0; x < pw; ++x) {
        const qreal s = static_cast<qreal>(x) / qMax(1, pw - 1);
        const QRgb rgb = colorFromHsvNorm(m_hue, s, m_val).rgb();
        for (int y = 0; y < ph; ++y) {
            reinterpret_cast<QRgb *>(m_satCache.scanLine(y))[x] = rgb;
        }
    }
    m_satCacheDpr = dpr;
    m_satCacheHueBucket = hueBucket;
    m_satCacheValBucket = valBucket;
}

void LgaColorPickerDialog::rebuildValCache()
{
    if (!m_valBar) {
        return;
    }
    const qreal dpr = m_valBar->devicePixelRatioF();
    // La barra de val pinta V=0..1 con H y S actuales, asi que su cache depende de los dos.
    const int hueBucket = qRound(m_hue * 360.0);
    const int satBucket = qRound(m_sat * 255.0);
    const int pw = qMax(1, qRound(m_valBar->width() * dpr));
    const int ph = qMax(1, qRound(kBarVisualH * dpr));
    if (m_valCache.width() == pw && m_valCache.height() == ph && qFuzzyCompare(m_valCacheDpr, dpr)
        && m_valCacheHueBucket == hueBucket && m_valCacheSatBucket == satBucket) {
        return;
    }

    m_valCache = QImage(pw, ph, QImage::Format_RGB32);
    m_valCache.setDevicePixelRatio(dpr);
    for (int x = 0; x < pw; ++x) {
        const qreal v = static_cast<qreal>(x) / qMax(1, pw - 1);
        const QRgb rgb = colorFromHsvNorm(m_hue, m_sat, v).rgb();
        for (int y = 0; y < ph; ++y) {
            reinterpret_cast<QRgb *>(m_valCache.scanLine(y))[x] = rgb;
        }
    }
    m_valCacheDpr = dpr;
    m_valCacheHueBucket = hueBucket;
    m_valCacheSatBucket = satBucket;
}
