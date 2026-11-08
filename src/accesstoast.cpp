#include "accesstoast.h"
#include "appicon.h"
#include "customtooltip.h"
#include "engine/FirewallClient.h"
#include "foldertrust.h"
#include "explain/Explainer.h"
#include "explain/KnownApps.h"
#include "theme.h"
#include <QAbstractItemView>
#include <QComboBox>
#include <QDateTime>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QApplication>
#include <QFileInfo>
#include <QGridLayout>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QScreen>
#include <QSettings>
#include <QSignalBlocker>
#include <QStandardPaths>
#include <QStyle>
#include <QStyledItemDelegate>
#include <QTimer>
#include <QVBoxLayout>
#include <QWheelEvent>
#include <utility>

namespace Gate {
namespace {
// Medidas de la maqueta «Pliego» (2026-11-07): aviso de 368 px con borde de 1 px y 16 px de margen interior, de modo
// que el contenido mide 334 px como en la maqueta.
constexpr int Width = 368; // ancho inicial y mínimo
constexpr int MaxWidth = 760;
constexpr int Margin = 15;
constexpr int Edge = 6;          // franja de los bordes izquierdo y derecho que ensancha
constexpr int Pad = 17;          // borde de 1 px + 16 px de margen lateral
constexpr int Gap = 12;          // separación entre bloques
constexpr int CardInsetX = 12;   // relleno interior de la tarjeta de la explicación
constexpr int CardInsetY = 11;
constexpr int IconSize = 36;     // caja del ícono del programa
constexpr int IconGlyph = 24;    // el mismo tamaño que la caja de 36 de la ventana
constexpr int IconGap = 12;
constexpr int KeyColumn = 76;    // columna de rótulos de la grilla de datos
constexpr int ColumnGap = 8;
constexpr int NoteInsetX = 10;   // relleno de los recuadros de aviso
constexpr int NoteInsetY = 8;
constexpr int ChipHeight = 28;   // desplegables de la regla
constexpr int ChipGap = 6;
constexpr int DecisionWidth = 72; // Block y Allow
// Estados de hover de la maqueta que todavía no tienen token en theme.h.
constexpr char ButtonHover[] = "#34343C";
constexpr char ButtonHoverBorder[] = "#4A4A55";
constexpr char BlockHover[] = "#4A2326";
constexpr char BlockHoverBorder[] = "#8A3A3E";
constexpr char PickHoverBorder[] = "#44444E";

// Rol de un texto corto para el desplegable cuando el texto entero no entra («Any destination (whole app)»).
constexpr int ShortTextRole = Qt::UserRole + 1;

QSettings store() { return QSettings(QSettings::NativeFormat, QSettings::UserScope, "LGA", "GateBouncer"); }

// shortcut: registro temporal de los desplegables del aviso (una elección que no queda); se quita al cerrar ese error.
void trace(const QString &line) {
    QFile f(QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) + "/toast-trace.log");
    if (f.size() > 512 * 1024) f.remove();
    QDir().mkpath(QFileInfo(f).absolutePath());
    if (f.open(QIODevice::Append | QIODevice::Text))
        f.write((QDateTime::currentDateTime().toString("HH:mm:ss.zzz ") + line + "\n").toUtf8());
}

// «*.dominio» que conviene ofrecer para un nombre: el dominio de arriba si tiene al menos dos partes propias
// («*.shotgrid.autodesk.com» para «wanka.shotgrid.autodesk.com»). Para «bbc.co.uk» no se sube a «*.co.uk».
QString parentWildcard(const QString &host) {
    const QStringList labels = host.split('.', Qt::SkipEmptyParts);
    if (labels.size() < 2) return {};
    if (labels.size() == 2) return "*." + host;
    const QStringList parent = labels.mid(1);
    static const QStringList second{"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"};
    if (parent.size() == 2 && parent[1].size() == 2 && second.contains(parent[0])) return "*." + host;
    return "*." + parent.join('.');
}

// Texto de una sola línea recortado al ancho; el entero va en el tooltip sólo si quedó recortado.
void elide(QLabel *label, const QString &text, int width, Qt::TextElideMode mode = Qt::ElideMiddle) {
    label->ensurePolished();
    const QString shown = label->fontMetrics().elidedText(text, mode, width);
    label->setText(shown);
    CustomTooltip::instance()->setToolTip(label, shown != text ? text.toHtmlEscaped() : QString());
}

// Ancho fijo y alto justo para un texto que se parte en renglones: así el aviso nunca corta un párrafo.
void fit(QLabel *label, int width) {
    label->setFixedWidth(qMax(1, width));
    label->ensurePolished();
    label->setFixedHeight(label->text().isEmpty() ? 0 : label->heightForWidth(label->width()));
}

// Cambia una propiedad que usa la hoja de estilo y vuelve a aplicarla.
void restyle(QWidget *widget, const char *name, const QString &value) {
    if (widget->property(name).toString() == value) return;
    widget->setProperty(name, value);
    widget->style()->unpolish(widget);
    widget->style()->polish(widget);
}

// Íconos de la barra dibujados: los caracteres «⋯» y «×» no quedan centrados en botones chicos.
QIcon headerIcon(bool close) {
    const qreal dpr = qMax(qreal(2), qApp->devicePixelRatio());
    QIcon icon;
    for (const auto &[mode, color] : {std::pair{QIcon::Normal, Theme::color(Theme::kTextCaption)},
                                      std::pair{QIcon::Active, Theme::color(Theme::kTextBright)}}) {
        QPixmap pixmap(QSize(16, 16) * dpr);
        pixmap.setDevicePixelRatio(dpr);
        pixmap.fill(Qt::transparent);
        QPainter p(&pixmap);
        p.setRenderHint(QPainter::Antialiasing);
        if (close) {
            p.setPen(QPen(color, 1.3, Qt::SolidLine, Qt::RoundCap));
            p.drawLine(QPointF(4.5, 4.5), QPointF(11.5, 11.5));
            p.drawLine(QPointF(11.5, 4.5), QPointF(4.5, 11.5));
        } else {
            p.setPen(Qt::NoPen);
            p.setBrush(color);
            for (const qreal x : {3.6, 8.0, 12.4}) p.drawEllipse(QPointF(x, 8), 1.0, 1.0);
        }
        p.end();
        icon.addPixmap(pixmap, mode);
    }
    return icon;
}

// Desplegable de la regla («pick» de la maqueta), dibujado entero: fondo de campo, texto y flecha. La rueda nunca
// cambia lo elegido (el aviso aparece debajo del puntero mientras se trabaja). Si el texto no entra se usa el corto
// del ítem (recortado con «…» sólo si tampoco entra) y el entero va en el tooltip; la lista abierta se ensancha para
// mostrar cada opción completa.
class ScopeCombo final : public QComboBox {
  public:
    using QComboBox::QComboBox;
    Qt::TextElideMode elideMode = Qt::ElideRight;

    QString shownText() {
        ensurePolished();
        const QString full = currentText();
        const int room = textRect().width();
        const QFontMetrics fm = fontMetrics();
        if (fm.horizontalAdvance(full) <= room) return full;
        const QString brief = currentData(ShortTextRole).toString();
        return fm.elidedText(brief.isEmpty() ? full : brief, elideMode, room);
    }

  protected:
    QRect textRect() const { return rect().adjusted(10, 0, -(9 + 14 + 6), 0); }
    void wheelEvent(QWheelEvent *event) override { event->ignore(); }
    void enterEvent(QEnterEvent *event) override {
        update();
        QComboBox::enterEvent(event);
    }
    void leaveEvent(QEvent *event) override {
        update();
        QComboBox::leaveEvent(event);
    }
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const bool on = isEnabled();
        p.setPen(QColor(on && underMouse() ? PickHoverBorder : Theme::kFieldBorder));
        p.setBrush(Theme::color(Theme::kField));
        p.drawRoundedRect(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5), 6, 6);
        p.setFont(font());
        p.setPen(Theme::color(on ? Theme::kTextStrong : Theme::kTextFaint));
        p.drawText(textRect(), Qt::AlignVCenter | Qt::AlignLeft, shownText());
        // Flecha de 14 px (la «chev» de la maqueta) a 9 px del borde derecho.
        const QPointF o(width() - 9 - 14, (height() - 14) / 2.0);
        p.setPen(QPen(Theme::color(on ? Theme::kTextCaption : Theme::kTextDisabled), 1.3, Qt::SolidLine, Qt::RoundCap,
                      Qt::RoundJoin));
        p.setBrush(Qt::NoBrush);
        p.drawPolyline(QPolygonF({o + QPointF(3.5, 5.6), o + QPointF(7, 9.1), o + QPointF(10.5, 5.6)}));
    }
    void showPopup() override {
        QComboBox::showPopup();
        // La lista abierta muestra cada opción entera: más ancha que el desplegable si hace falta, sin salir de la
        // pantalla (el aviso vive abajo a la derecha).
        QWidget *popup = view()->window();
        const QFontMetrics fm = view()->fontMetrics();
        int need = 0;
        for (int i = 0; i < count(); ++i) need = qMax(need, fm.horizontalAdvance(itemText(i)));
        need += 2 * 8 + 2 * 4 + 2 + 6; // relleno del ítem, de la lista, borde y aire
        if (need <= popup->width()) return;
        QRect g = popup->geometry();
        g.setWidth(need);
        if (const QScreen *s = screen()) {
            const QRect area = s->availableGeometry();
            if (g.right() > area.right()) g.moveRight(area.right());
            if (g.left() < area.left()) g.moveLeft(area.left());
        }
        popup->setGeometry(g);
    }
};

// Indicador de «pidiendo»: un aro tenue con un tramo de acento que gira.
class Spinner final : public QWidget {
  public:
    using QWidget::QWidget;
    int angle = 0;

  protected:
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const QRectF r = QRectF(rect()).adjusted(1, 1, -1, -1);
        p.setPen(QPen(Theme::color(Theme::kBorderStrong), 2));
        p.drawEllipse(r);
        p.setPen(QPen(Theme::color(Theme::kAccent), 2, Qt::SolidLine, Qt::FlatCap));
        p.drawArc(r, (90 - angle) * 16, -90 * 16);
    }
};

// Nombre corto del modelo («claude-haiku-5-5», «nemotron-3-ultra-550b-a55b»).
QString modelName(const QString &model) { return model.section('/', -1); }

QLabel *label(QWidget *parent, const char *name, bool wrap = false) {
    auto *l = new QLabel(parent);
    l->setObjectName(name);
    l->setWordWrap(wrap);
    l->setTextFormat(Qt::PlainText);
    return l;
}

QPushButton *link(QWidget *parent, const char *name, const QString &text) {
    auto *b = new QPushButton(text, parent);
    b->setObjectName(name);
    b->setFlat(true);
    b->setCursor(Qt::PointingHandCursor);
    return b;
}

// Rótulo en versalitas con aire entre letras («RULE», «WHY IT CONNECTS»): la hoja de estilo no tiene letter-spacing.
void smallCaps(QLabel *l) {
    QFont f = l->font();
    f.setCapitalization(QFont::AllUppercase);
    f.setLetterSpacing(QFont::AbsoluteSpacing, 0.9);
    l->setFont(f);
}

// Hoja del aviso con los tokens del Pliego: «%nombre%» se reemplaza por el color de theme.h.
QString toastSheet() {
    using namespace Theme;
    QString s = QStringLiteral(R"(
        #accessToast QLabel, #accessToast QPushButton, #accessToast QComboBox { background:transparent; border:0;
            color:%text%; font-family:'Inter'; font-size:13px; font-weight:400; padding:0; }
        #accessToast QPushButton { min-height:0; }
        #accessToast QLabel#toastHeader { font-family:@title; font-size:13px; font-weight:700; color:%textBright%; }
        #accessToast QLabel#toastAppIcon { background:%tile%; border-radius:8px; }
        #accessToast QPushButton#toastMenu, #accessToast QPushButton#toastClose { border-radius:6px; }
        #accessToast QPushButton#toastMenu:hover, #accessToast QPushButton#toastClose:hover { background:%rowHover%; }
        #accessToast QLabel#toastTitle { font-family:@title; font-size:16px; font-weight:700; color:%textBright%; }
        #accessToast QLabel#toastBody { font-size:12.5px; color:%textCaption%; }
        #accessToast QWidget#toastWarn { background:rgba(242,203,63,15); border:1px solid %warnBorder%;
            border-radius:8px; }
        #accessToast QWidget#toastWarn QLabel { font-size:12.5px; color:%warn%; }
        #accessToast QWidget#toastInfo { background:%card%; border:1px solid %borderStrong%; border-radius:8px; }
        #accessToast QWidget#toastInfo QLabel { font-size:12.5px; color:%textMuted%; }
        #accessToast QWidget#toastLine { background:%divider%; }
        #accessToast QLabel#toastKey { font-size:12.5px; color:%textFaint%; }
        #accessToast QLabel#toastValue { font-size:12.5px; color:%textStrong%; }
        #accessToast QLabel#toastValueDetail { font-size:12px; color:%textFaint%; }
        #accessToast QLabel#toastKnownPill { font-size:12px; font-weight:600; color:%textCaption%;
            border:1px solid %borderStrong%; border-radius:11px; padding:0 9px; }
        #accessToast QLabel#toastKnownText { font-size:12.5px; color:%textMuted%; }
        #accessToast QWidget#toastExplainBox { background:%card%; border:1px solid %cardBorder%; border-radius:10px; }
        #accessToast QWidget#toastExplainBox[tone="err"] { border-color:%errBorder%; }
        #accessToast QLabel#toastExplainStatus { font-size:13px; color:%textCaption%; }
        #accessToast QLabel#toastExplainStatus[tone="working"] { font-size:12.5px; color:%textMuted%; }
        #accessToast QLabel#toastExplainStatus[tone="err"] { color:%error%; }
        #accessToast QLabel#toastSuggestion { font-size:12px; font-weight:600; color:%textCaption%;
            border:1px solid %borderStrong%; border-radius:11px; padding:0 9px; }
        #accessToast QLabel#toastSuggestion[kind="block"] { color:%error%; border-color:%errBorder%;
            background:%errBg%; }
        #accessToast QLabel#toastSuggestion[kind="allow"] { color:%okText%; border-color:%okBorder%;
            background:%okBg%; }
        #accessToast QLabel#toastWhat { font-size:13px; color:%textStrong%; }
        #accessToast QWidget#toastMoreLine { background:%divider%; }
        #accessToast QLabel#toastMoreHead { font-size:11px; font-weight:600; color:%textFaint%; }
        #accessToast QLabel#toastMoreBody { font-size:12.5px; color:%text%; }
        #accessToast QLabel#toastExplainFoot { font-size:11.5px; color:%textFaint%; }
        #accessToast QPushButton#toastDetails, #accessToast QPushButton#toastSettings,
            #accessToast QPushButton#toastOpen { font-size:12.5px; font-weight:600; color:%accent%; }
        #accessToast QPushButton#toastDetails:hover, #accessToast QPushButton#toastSettings:hover,
            #accessToast QPushButton#toastOpen:hover { color:%accentHover%; }
        #accessToast QPushButton#toastExplain { background:%tile%; color:%textStrong%; border:1px solid %borderStrong%;
            border-radius:6px; font-size:12.5px; font-weight:500; padding:0 10px; min-height:24px; max-height:24px; }
        #accessToast QPushButton#toastExplain:hover { background:%buttonHover%; border-color:%buttonHoverBorder%;
            color:%textBright%; }
        #accessToast QLabel#toastRuleLabel { font-size:11px; font-weight:600; color:%textFaint%; }
        #accessToast QLabel#toastFolderNote { font-size:12px; color:%textFaint%; }
        #accessToast QComboBox { font-size:13px; color:%textStrong%; }
        #accessToast QComboBox QAbstractItemView { background:%card%; border:1px solid %borderStrong%;
            color:%textStrong%; font-size:13px; outline:0; padding:4px; selection-background-color:%listSelected%;
            selection-color:%textBright%; }
        #accessToast QComboBox QAbstractItemView::item { min-height:26px; padding:0 8px; border-radius:4px; }
        #accessToast QComboBox QAbstractItemView::item:hover { background:%rowHover%; }
        #accessToast QComboBox QAbstractItemView::item:selected { background:%listSelected%; color:%textBright%; }
        #accessToast QPushButton#toastBlock, #accessToast QPushButton#toastAllow { border-radius:6px;
            font-size:12.5px; font-weight:600; min-width:70px; max-width:70px; min-height:24px; max-height:24px; }
        #accessToast QPushButton#toastBlock { background:%errBg%; color:%error%; border:1px solid %errBorder%; }
        #accessToast QPushButton#toastBlock:hover { background:%blockHover%; border-color:%blockHoverBorder%; }
        #accessToast QPushButton#toastAllow { background:%primary%; color:%onAccent%; border:1px solid %primaryBorder%; }
        #accessToast QPushButton#toastAllow:hover { background:%primaryHover%; border-color:%primaryHoverBorder%; }
        #accessToast QPushButton#toastAllow[rec="1"] { border-color:%primaryHoverBorder%; }
        #accessToast QPushButton#toastBlock[rec="1"] { border-color:%blockHoverBorder%; }
        #accessToast QPushButton#toastBlock:disabled, #accessToast QPushButton#toastAllow:disabled {
            background:%tile%; color:%textFaint%; border-color:%borderStrong%; }
        #accessToast QLabel#toastFooter { font-size:12px; color:%textFaint%; }
        #accessToast QMenu { background:%card%; border:1px solid %borderStrong%; padding:4px; }
        #accessToast QMenu::item { color:%textStrong%; font-size:13px; padding:5px 12px; border-radius:4px; }
        #accessToast QMenu::item:selected { background:%rowHover%; color:%textBright%; }
    )");
    const std::pair<const char *, const char *> tokens[] = {
        {"%text%", kText},
        {"%textBright%", kTextBright},
        {"%textStrong%", kTextStrong},
        {"%textMuted%", kTextMuted},
        {"%textCaption%", kTextCaption},
        {"%textFaint%", kTextFaint},
        {"%tile%", kTile},
        {"%card%", kCard},
        {"%cardBorder%", kCardBorder},
        {"%borderStrong%", kBorderStrong},
        {"%divider%", kDivider},
        {"%rowHover%", kRowHover},
        {"%listSelected%", kListSelected},
        {"%accent%", kAccent},
        {"%accentHover%", kAccentHover},
        {"%primary%", kPrimary},
        {"%primaryBorder%", kPrimaryBorder},
        {"%primaryHover%", kPrimaryHover},
        {"%primaryHoverBorder%", kPrimaryHoverBorder},
        {"%onAccent%", kOnAccent},
        {"%okText%", kOkText},
        {"%okBg%", kOkBg},
        {"%okBorder%", kOkBorder},
        {"%warn%", kWarn},
        {"%warnBorder%", kWarnBorder},
        {"%error%", kError},
        {"%errBg%", kErrBg},
        {"%errBorder%", kErrBorder},
        {"%buttonHover%", ButtonHover},
        {"%buttonHoverBorder%", ButtonHoverBorder},
        {"%blockHover%", BlockHover},
        {"%blockHoverBorder%", BlockHoverBorder},
    };
    for (const auto &[name, value] : tokens) s.replace(QLatin1String(name), QLatin1String(value));
    return css(s);
}
} // namespace

AccessToast::AccessToast(QWidget *parent) : QWidget(parent) {
    if (!parent) {
        setWindowFlags(Qt::Tool | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint);
        setAttribute(Qt::WA_ShowWithoutActivating);
    }
    setAttribute(Qt::WA_TranslucentBackground);
    setObjectName("accessToast");
    setAccessibleName("Access request");
    setMouseTracking(true);
    width_ = Width;
    setFixedWidth(Width);
    setStyleSheet(toastSheet());

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    // Barra: la marca, «⋯» con el menú y «×» que cierra sin decidir.
    auto *bar = new QWidget(this);
    bar->setFixedHeight(36);
    auto *barRow = new QHBoxLayout(bar);
    barRow->setContentsMargins(13, 0, 9, 0);
    barRow->setSpacing(8);
    auto *small = new QLabel(bar);
    small->setFixedSize(18, 18);
    small->setPixmap(QIcon(":/gatebouncer/resources/icons/LGA_GateBouncer.png").pixmap(18, 18));
    barRow->addWidget(small);
    auto *name = new QLabel("LGA GateBouncer", bar);
    name->setObjectName("toastHeader");
    barRow->addWidget(name, 1);
    auto *more = new QPushButton(bar);
    more->setObjectName("toastMenu");
    more->setFixedSize(26, 26);
    more->setIcon(headerIcon(false));
    more->setIconSize(QSize(16, 16));
    more->setAccessibleName("More actions");
    more->setCursor(Qt::PointingHandCursor);
    barRow->addWidget(more);
    auto *close = new QPushButton(bar);
    close->setObjectName("toastClose");
    close->setFixedSize(26, 26);
    close->setIcon(headerIcon(true));
    close->setIconSize(QSize(16, 16));
    CustomTooltip::instance()->setToolTip(close, "Close and keep it waiting");
    close->setAccessibleName("Close and keep it waiting");
    close->setCursor(Qt::PointingHandCursor);
    barRow->addWidget(close);
    layout->addWidget(bar);

    auto *menu = new QMenu(this);
    menu->addAction("Open GateBouncer", this, [this] { emit openRequested(); });
    menu->addAction("Pending list", this, [this] { emit pendingListRequested(); });
    connect(more, &QPushButton::clicked, this, [more, menu] { menu->popup(more->mapToGlobal(QPoint(0, more->height()))); });
    connect(close, &QPushButton::clicked, this, [this] { emit dismissed(request_.id); });

    // Cabecera: ícono del programa, nombre del archivo y qué pasó, centrados en vertical.
    auto *head = new QHBoxLayout;
    head->setContentsMargins(Pad, 4, Pad, 0);
    head->setSpacing(IconGap);
    icon_ = new QLabel(this);
    icon_->setObjectName("toastAppIcon"); // la misma caja que en la ventana: un ícono oscuro se sigue leyendo
    icon_->setFixedSize(IconSize, IconSize);
    icon_->setAlignment(Qt::AlignCenter);
    head->addWidget(icon_, 0, Qt::AlignVCenter);
    auto *text = new QVBoxLayout;
    text->setSpacing(2);
    text->addStretch(1);
    title_ = label(this, "toastTitle");
    text->addWidget(title_);
    body_ = label(this, "toastBody", true);
    text->addWidget(body_);
    text->addStretch(1);
    head->addLayout(text, 1);
    layout->addLayout(head);

    // Recuadros de aviso: sin firma (amarillo) y modo por destino (neutro).
    // El margen va en un contenedor que se oculta entero: un layout suelto con el recuadro oculto dejaría su margen.
    const auto noteBox = [this, layout](const char *name, QLabel *&note, Qt::TextFormat format) {
        auto *holder = new QWidget(this);
        auto *wrap = new QHBoxLayout(holder);
        wrap->setContentsMargins(Pad, Gap, Pad, 0);
        auto *box = new QWidget(holder);
        box->setObjectName(name);
        box->setAttribute(Qt::WA_StyledBackground);
        auto *inner = new QVBoxLayout(box);
        inner->setContentsMargins(NoteInsetX, NoteInsetY, NoteInsetX, NoteInsetY);
        note = new QLabel(box);
        note->setWordWrap(true);
        note->setTextFormat(format);
        inner->addWidget(note);
        wrap->addWidget(box);
        layout->addWidget(holder);
        return holder;
    };
    warnBox_ = noteBox("toastWarn", warn_, Qt::PlainText); // el texto depende de si hay carpeta que ofrecer
    infoBox_ = noteBox("toastInfo", info_, Qt::RichText);
    info_->setText(QString("Allow or Block applies to this server only. Choose <b style=\"color:%1\">Any destination "
                           "(whole app)</b> in the menu to replace its server rules.")
                       .arg(Theme::kTextStrong));

    // Datos en grilla bajo una línea: firma, a dónde quería ir y quién la lanzó.
    auto *line = new QWidget(this);
    line->setObjectName("toastLine");
    line->setAttribute(Qt::WA_StyledBackground);
    line->setFixedHeight(1);
    auto *lineRow = new QHBoxLayout;
    lineRow->setContentsMargins(Pad, Gap, Pad, 0);
    lineRow->addWidget(line);
    layout->addLayout(lineRow);
    auto *facts = new QGridLayout;
    facts->setContentsMargins(Pad, Gap, Pad, 0);
    facts->setHorizontalSpacing(ColumnGap);
    facts->setVerticalSpacing(7);
    facts->setColumnMinimumWidth(0, KeyColumn);
    const auto key = [this](const QString &text) {
        auto *k = label(this, "toastKey");
        k->setText(text);
        k->setFixedWidth(KeyColumn);
        return k;
    };
    facts->addWidget(key("Signature"), 0, 0, Qt::AlignTop);
    auto *signature = new QVBoxLayout;
    signature->setSpacing(1);
    signature_ = new QLabel(this);
    signature_->setObjectName("toastValue");
    signature_->setWordWrap(true);
    signature_->setTextFormat(Qt::RichText);
    signature->addWidget(signature_);
    signatureDetail_ = label(this, "toastValueDetail");
    signature->addWidget(signatureDetail_);
    facts->addLayout(signature, 0, 1, Qt::AlignTop);
    wantsKey_ = key("Wants");
    facts->addWidget(wantsKey_, 1, 0, Qt::AlignTop);
    auto *wants = new QVBoxLayout;
    wants->setSpacing(1);
    destination_ = label(this, "toastValue");
    wants->addWidget(destination_);
    destinationDetail_ = label(this, "toastValueDetail");
    wants->addWidget(destinationDetail_);
    facts->addLayout(wants, 1, 1, Qt::AlignTop);
    launchedKey_ = key("Started by");
    facts->addWidget(launchedKey_, 2, 0, Qt::AlignTop);
    launched_ = label(this, "toastValue");
    facts->addWidget(launched_, 2, 1, Qt::AlignTop);
    facts->setColumnStretch(1, 1);
    layout->addLayout(facts);

    // Catálogo de apps conocidas: al instante, sin pedir nada a nadie. Como la explicación, sólo ayuda a decidir.
    knownBox_ = new QWidget(this);
    auto *known = new QVBoxLayout(knownBox_);
    known->setContentsMargins(Pad, Gap, Pad, 0);
    known->setSpacing(6);
    knownPill_ = label(knownBox_, "toastKnownPill");
    knownPill_->setFixedHeight(22);
    known->addWidget(knownPill_, 0, Qt::AlignLeft);
    knownText_ = label(knownBox_, "toastKnownText", true);
    known->addWidget(knownText_);
    layout->addWidget(knownBox_);

    // Tarjeta de la explicación con IA. Nunca toca la decisión: ningún botón se resalta por la sugerencia.
    explainBox_ = new QWidget(this);
    explainBox_->setObjectName("toastExplainBox");
    explainBox_->setAttribute(Qt::WA_StyledBackground);
    auto *card = new QVBoxLayout(explainBox_);
    card->setContentsMargins(CardInsetX, CardInsetY, CardInsetX, CardInsetY);
    card->setSpacing(0);
    auto *cardRow = new QHBoxLayout;
    cardRow->setSpacing(8);
    spinner_ = new Spinner(explainBox_);
    spinner_->setFixedSize(13, 13);
    cardRow->addWidget(spinner_);
    explainStatus_ = label(explainBox_, "toastExplainStatus");
    explainStatus_->setMinimumHeight(26); // el alto del botón «Ask AI»: la tarjeta no salta entre estados
    cardRow->addWidget(explainStatus_);
    suggestion_ = label(explainBox_, "toastSuggestion");
    suggestion_->setFixedHeight(22);
    cardRow->addWidget(suggestion_);
    cardRow->addStretch(1);
    details_ = link(explainBox_, "toastDetails", "Details");
    cardRow->addWidget(details_);
    settingsLink_ = link(explainBox_, "toastSettings", "Set up in Settings");
    cardRow->addWidget(settingsLink_);
    explainAction_ = new QPushButton(explainBox_);
    explainAction_->setObjectName("toastExplain");
    explainAction_->setCursor(Qt::PointingHandCursor);
    cardRow->addWidget(explainAction_);
    card->addLayout(cardRow);
    // Las separaciones van como margen de cada texto (y no como espaciadores): así desaparecen con el texto oculto.
    what_ = label(explainBox_, "toastWhat", true);
    what_->setContentsMargins(0, 8, 0, 0);
    card->addWidget(what_);
    more_ = new QWidget(explainBox_);
    auto *moreLayout = new QVBoxLayout(more_);
    moreLayout->setContentsMargins(0, 10, 0, 0);
    moreLayout->setSpacing(0);
    auto *moreLine = new QWidget(more_);
    moreLine->setObjectName("toastMoreLine");
    moreLine->setAttribute(Qt::WA_StyledBackground);
    moreLine->setFixedHeight(1);
    moreLayout->addWidget(moreLine);
    moreLayout->addSpacing(10);
    // La respuesta del modelo es texto no confiable: siempre plano, nunca HTML ni enlaces.
    const auto section = [this, moreLayout](const QString &title, QLabel *&head, QLabel *&body, bool last) {
        head = label(more_, "toastMoreHead");
        head->setText(title);
        moreLayout->addWidget(head);
        moreLayout->addSpacing(3);
        body = label(more_, "toastMoreBody", true);
        moreLayout->addWidget(body);
        if (!last) moreLayout->addSpacing(9);
    };
    section("WHY IT CONNECTS", whyHead_, why_, false);
    section("WHY THIS SUGGESTION", reasonHead_, reason_, false);
    section("IS IT GENUINE", riskHead_, risk_, true);
    for (auto *h : {whyHead_, reasonHead_, riskHead_}) smallCaps(h);
    card->addWidget(more_);
    explainFoot_ = label(explainBox_, "toastExplainFoot", true);
    explainFoot_->setContentsMargins(0, 8, 0, 0);
    card->addWidget(explainFoot_);
    auto *cardWrap = new QHBoxLayout;
    cardWrap->setContentsMargins(Pad, Gap, Pad, 0);
    cardWrap->addWidget(explainBox_);
    layout->addLayout(cardWrap);
    spin_ = new QTimer(this);
    spin_->setInterval(40);
    connect(spin_, &QTimer::timeout, this, [this] {
        auto *spinner = static_cast<Spinner *>(spinner_);
        spinner->angle = (spinner->angle + 24) % 360;
        spinner->update();
    });
    connect(explainAction_, &QPushButton::clicked, this, [this] {
        if (explanation_.state == Explanation::NoKey) emit settingsRequested();
        else emit explainRequested(request_.id);
    });
    connect(settingsLink_, &QPushButton::clicked, this, [this] { emit settingsRequested(); });
    connect(details_, &QPushButton::clicked, this, [this] {
        detailsOpen_ = !detailsOpen_;
        renderExplanation();
        relayout();
    });

    // Regla en rejilla: «Apply to» a todo el ancho arriba; «For» y «Destination» a medias, con el mismo ancho, abajo.
    auto *rule = new QVBoxLayout;
    rule->setContentsMargins(Pad, Gap, Pad, 0);
    rule->setSpacing(6);
    auto *ruleLabel = label(this, "toastRuleLabel");
    ruleLabel->setText("Rule");
    smallCaps(ruleLabel);
    rule->addWidget(ruleLabel);
    choices_ = new QWidget(this);
    rule->addWidget(choices_);
    folderNote_ = label(this, "toastFolderNote", true);
    folderNote_->hide();
    rule->addWidget(folderNote_);
    layout->addLayout(rule);
    scope_ = new ScopeCombo(choices_);
    scope_->setObjectName("toastScope");
    scope_->setAccessibleName("Apply to");
    duration_ = new ScopeCombo(choices_);
    duration_->setObjectName("toastDuration");
    duration_->setAccessibleName("For");
    duration_->addItem("Always", "always");
    for (const int minutes : {1, 5, 10, 15, 30})
        duration_->addItem(minutes == 1 ? QStringLiteral("1 minute") : QString("%1 minutes").arg(minutes),
                           QString::number(minutes * 60));
    duration_->addItem("1 hour", "3600");
    duration_->addItem("Until restart", "restart");
    target_ = new ScopeCombo(choices_);
    target_->setObjectName("toastTarget");
    target_->setAccessibleName("Destination");
    static_cast<ScopeCombo *>(target_)->elideMode = Qt::ElideMiddle; // un nombre largo conserva su dominio
    for (auto *combo : {scope_, duration_, target_}) {
        // Con el delegado común la lista toma el estilo de cada fila de la hoja de estilo.
        combo->setItemDelegate(new QStyledItemDelegate(combo));
        combo->installEventFilter(this);
        combo->setCursor(Qt::PointingHandCursor);
        // El texto que se ve (entero, corto o recortado) cambia con lo elegido: se rehace el tooltip.
        connect(combo, qOverload<int>(&QComboBox::currentIndexChanged), this, [this] {
            if (request_.id.isEmpty()) return;
            layoutChoices();
        });
    }
    connect(target_, qOverload<int>(&QComboBox::activated), this, [this] {
        targetChosen_ = true;
        chosenTarget_ = target_->currentData().toString();
    });
    connect(scope_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this] {
        if (request_.id.isEmpty()) return;
        syncFolderScope();
        relayout();
    });
    duration_->view()->window()->installEventFilter(this);
    connect(duration_, qOverload<int>(&QComboBox::activated), this,
            [this](int index) { trace(QString("toastDuration elegido=%1").arg(duration_->itemText(index))); });
    connect(duration_, qOverload<int>(&QComboBox::currentIndexChanged), this,
            [this](int index) { trace(QString("toastDuration ahora=%1").arg(duration_->itemText(index))); });

    // Block y Allow chicos y del mismo ancho, a la derecha: Block en rojo, Allow en el color principal.
    auto *buttons = new QHBoxLayout;
    buttons->setContentsMargins(Pad, Gap, Pad, 0);
    buttons->setSpacing(8);
    buttons->addStretch(1);
    block_ = new QPushButton("Block", this);
    block_->setObjectName("toastBlock");
    allow_ = new QPushButton("Allow", this);
    allow_->setObjectName("toastAllow");
    // 72 x 26: la hoja de estilo fija 70 x 24 de contenido más el borde (un tamaño fijo en código lo pisa la hoja
    // global de la app al volver a aplicar el estilo).
    for (auto *b : {block_, allow_}) {
        b->setCursor(Qt::PointingHandCursor);
        buttons->addWidget(b);
    }
    layout->addLayout(buttons);
    for (auto *b : {block_, allow_})
        connect(b, &QPushButton::clicked, this, [this, allowed = b == allow_] {
            emit decided(request_.id, allowed, scope_->currentData().toString(), duration_->currentData().toString(),
                         target_->currentData().toString());
        });

    auto *foot = new QHBoxLayout;
    foot->setContentsMargins(Pad, 10, Pad, 15);
    foot->setSpacing(6);
    footer_ = label(this, "toastFooter");
    foot->addWidget(footer_, 1);
    auto *open = link(this, "toastOpen", "Open GateBouncer");
    foot->addWidget(open);
    connect(open, &QPushButton::clicked, this, [this] { emit openRequested(); });
    layout->addLayout(foot);
}

void AccessToast::setRequest(const Request &request) {
    const bool samePath = request.id.compare(request_.id, Qt::CaseInsensitive) == 0 &&
                          request.signer == request_.signer && !request_.id.isEmpty();
    // El nombre puede llegar un segundo después del bloqueo, y un intento nuevo puede ir a otra dirección: entonces se
    // rehacen las opciones de destino.
    const bool newHost = request.host != request_.host || (request.host.isEmpty() && request.remote != request_.remote);
    request_ = request;
    if (!samePath) trace("pedido nuevo: " + request.id + " firma=" + request.signer);
    if (!samePath) {
        icon_->setPixmap(appIconPixmap(request.path, IconGlyph, qApp->devicePixelRatio()));
        rebuildScopes();
        targetChosen_ = false;
        chosenTarget_.clear();
        rebuildTargets();
        duration_->setCurrentIndex(0);
        explanation_ = {};
        detailsOpen_ = false;
        renderExplanation();
        armed_ = false;
        QTimer::singleShot(600, this, [this, id = request.id] {
            if (request_.id != id) return;
            armed_ = true;
            updateCounters();
        });
    } else if (newHost) {
        rebuildTargets();
    }
    const QString exe = QFileInfo(request.path).fileName();
    body_->setText(!request.perDestination ? QStringLiteral("Blocked. Allow lets its next attempt connect.")
                   : request.serverRules > 0
                       ? QString("Blocked: a new server. %1 already has rules for %2 %3.")
                             .arg(exe)
                             .arg(request.serverRules)
                             .arg(request.serverRules == 1 ? "server" : "servers")
                       : QString("Blocked: a new server for %1.").arg(exe));
    infoBox_->setVisible(request.perDestination);
    renderKnown();
    // Se resalta el botón que recomienda el catálogo (o una app LGA): los dos quedan iguales y nada se decide solo.
    const QString recommended = KnownApps::suggestion(request.known);
    restyle(allow_, "rec", recommended == "allow" ? "1" : "");
    restyle(block_, "rec", recommended == "block" ? "1" : "");
    updateCounters();
    // Fuera del bloque anterior: un intento nuevo de la misma app puede ir a otro destino (relayout lo dibuja).
    relayout();
}

void AccessToast::rebuildTargets() {
    // Lo que eligió el usuario se conserva si sigue estando (el nombre llegó tarde y se agregan opciones). Si ya no
    // está, se cae a la opción más estrecha, nunca a la app entera. Con una opción de carpeta elegida el destino se ve en
    // «Any destination», pero lo elegido sigue guardado.
    const QString chosen = targetChosen_ ? chosenTarget_ : target_->currentData().toString();
    const QSignalBlocker quiet(target_);
    target_->clear();
    const QString host = request_.host;
    const QString kind = FirewallClient::destinationKind(request_.remote);
    QStringList targets;
    if (!host.isEmpty()) {
        targets << host;
        const QString wide = parentWildcard(host);
        if (!wide.isEmpty()) targets << wide;
    } else if (!kind.isEmpty() && kind != "This PC") {
        targets << request_.remote;
    }
    // En modo por destino la decisión es sobre este destino; la app entera queda como última opción.
    if (!request_.perDestination) target_->addItem("Any destination", QString());
    // A media fila «Only www.github.com» no suele entrar: el desplegable muestra el nombre solo antes que recortarlo.
    for (const auto &t : targets) {
        target_->addItem("Only " + t, t);
        target_->setItemData(target_->count() - 1, t, ShortTextRole);
    }
    if (request_.perDestination) {
        target_->addItem("Any destination (whole app)", QString());
        target_->setItemData(target_->count() - 1, QStringLiteral("Any destination"), ShortTextRole);
    }
    const int keep = targetChosen_ ? target_->findData(chosen) : -1;
    const int narrowest = targets.isEmpty() ? 0 : target_->findData(targets.first());
    target_->setCurrentIndex(folderScope() ? qMax(0, target_->findData(QString()))
                             : keep >= 0  ? keep
                             : targetChosen_ ? narrowest
                                             : 0);
    target_->setEnabled(target_->count() > 1 && !folderScope());
}

bool AccessToast::folderScope() const { return FolderTrust::isFolderScope(scope_->currentData().toString()); }

void AccessToast::syncFolderScope() {
    const QString scope = scope_->currentData().toString();
    const bool folder = FolderTrust::isFolderScope(scope);
    // Sin señales: no cuenta como una elección del usuario (targetChosen_). Si después se elige otra opción, el destino
    // vuelve a lo que el usuario había elegido.
    const QSignalBlocker quiet(target_);
    if (folder) {
        target_->setCurrentIndex(qMax(0, target_->findData(QString())));
    } else if (targetChosen_) {
        const int back = target_->findData(chosenTarget_);
        if (back >= 0) target_->setCurrentIndex(back);
    }
    folderNote_->setText(FolderTrust::note(scope, request_.path));
    folderNote_->setVisible(folder);
    updateCounters();
}

// Firma, destino y quién la lanzó, recortados al ancho actual.
void AccessToast::renderDestination() {
    const int value = width_ - 2 * Pad - KeyColumn - ColumnGap;
    const QString full = QDir::toNativeSeparators(request_.path);
    // La firma en color (cian válida, amarillo sin firma) y debajo la carpeta del programa, recortada al medio si no
    // entra; la ruta entera va en el tooltip de las dos.
    signature_->setText(request_.signer.isEmpty()
                            ? QString("<span style=\"color:%1; font-weight:500\">Not signed</span>").arg(Theme::kWarn)
                            : QString("<span style=\"color:%1; font-weight:500\">%2</span> · valid")
                                  .arg(QLatin1String(Theme::kOk), request_.signer.toHtmlEscaped()));
    CustomTooltip::instance()->setToolTip(signature_, full.toHtmlEscaped());
    fit(signature_, value);
    signatureDetail_->setFixedWidth(value);
    elide(signatureDetail_, QDir::toNativeSeparators(QFileInfo(request_.path).path()), value);
    CustomTooltip::instance()->setToolTip(signatureDetail_, full.toHtmlEscaped());

    const QString kind = FirewallClient::destinationKind(request_.remote);
    const bool known = !kind.isEmpty();
    wantsKey_->setVisible(known);
    destination_->setVisible(known);
    destinationDetail_->setVisible(known);
    if (known) {
        destination_->setFixedWidth(value);
        destinationDetail_->setFixedWidth(value);
        elide(destination_, request_.host.isEmpty() ? request_.remote : request_.host, value);
        const QString port = request_.port ? FirewallClient::protocolName(request_.protocol) + " " +
                                                 QString::number(request_.port)
                                           : FirewallClient::protocolName(request_.protocol);
        // Sin nombre: la app se conectó directo a la IP o resolvió por su cuenta, y eso también es un dato.
        elide(destinationDetail_,
              kind + (request_.host.isEmpty() ? QStringLiteral(" · no server name seen") : QString()) + " · " + port,
              value, Qt::ElideRight);
    }
    const bool launched = !request_.launchedBy.isEmpty();
    launchedKey_->setVisible(launched);
    launched_->setVisible(launched);
    if (launched) {
        launched_->setFixedWidth(value);
        elide(launched_, request_.launchedBy, value, Qt::ElideRight);
    }
}

// «Known app · usually Block · qué es»: la primera parte va en la píldora y el resto como texto debajo.
void AccessToast::renderKnown() {
    const QString text = request_.known;
    knownBox_->setVisible(!text.isEmpty());
    if (text.isEmpty()) return;
    const QStringList parts = text.split(" · ");
    const int head = qMin(2, int(parts.size()));
    knownPill_->setProperty("full", QStringList(parts.mid(0, head)).join(" · "));
    knownText_->setText(QStringList(parts.mid(head)).join(" · "));
    knownText_->setVisible(!knownText_->text().isEmpty());
}

void AccessToast::rebuildScopes() {
    const QSignalBlocker quiet(scope_); // setRequest rehace el alto al final
    scope_->clear();
    // Las mismas opciones que Requests, en el mismo orden: un build sin firma dentro de un repositorio preselecciona el
    // programa en todo el repositorio («This app in LGA_DayTrace»), así los builds nuevos no vuelven a preguntar.
    bool repository = false;
    for (const auto &[text, data] : FolderTrust::scopeChoices(request_.path, request_.signer, request_.perDestination)) {
        scope_->addItem(text, data);
        repository = repository || FolderTrust::isFolderScope(data);
    }
    scope_->setCurrentIndex(0);
    scope_->setEnabled(scope_->count() > 1);
    warn_->setText(repository ? QStringLiteral("No signature: the rule can't follow a publisher, only this file or this "
                                               "app's name inside its repository.")
                              : QStringLiteral("No signature: a rule can only cover this exact file. If the file "
                                               "changes, it asks again."));
    warnBox_->setVisible(request_.signer.isEmpty());
    syncFolderScope();
}

void AccessToast::updateCounters() {
    block_->setEnabled(request_.canDecide && armed_);
    allow_->setEnabled(request_.canDecide && armed_);
    scope_->setEnabled(request_.canDecide && armed_ && scope_->count() > 1);
    duration_->setEnabled(request_.canDecide && armed_);
    target_->setEnabled(request_.canDecide && armed_ && target_->count() > 1 && !folderScope());
    QStringList parts;
    if (request_.attempts > 0)
        parts << (request_.attempts == 1 ? QStringLiteral("1 attempt") : QString("%1 attempts").arg(request_.attempts));
    if (request_.othersWaiting > 0) parts << QString("%1 more waiting").arg(request_.othersWaiting);
    if (!request_.canDecide) parts << "read only";
    footer_->setText(parts.join(" · "));
}

void AccessToast::setExplanation(const QString &id, const Explanation &explanation) {
    if (id.compare(request_.id, Qt::CaseInsensitive) != 0) return;
    // Una respuesta nueva arranca con los detalles cerrados; la misma que vuelve a llegar conserva lo abierto.
    if (explanation.state != Explanation::Ready || explanation_.state != Explanation::Ready ||
        explanation.what != explanation_.what)
        detailsOpen_ = false;
    explanation_ = explanation;
    renderExplanation();
    // Crece hacia arriba desde su esquina de abajo (resizeEvent): los botones nunca quedan bajo la barra de tareas.
    relayout();
}

void AccessToast::renderExplanation() {
    const auto &e = explanation_;
    const bool working = e.state == Explanation::Working, ready = e.state == Explanation::Ready;
    working ? spin_->start() : spin_->stop();
    spinner_->setVisible(working);
    restyle(explainBox_, "tone",
            e.state == Explanation::Failed                                 ? QStringLiteral("err")
            : e.state == Explanation::Offer || e.state == Explanation::NoKey ? QStringLiteral("quiet")
                                                                             : QString());
    explainStatus_->setVisible(!ready);
    restyle(explainStatus_, "tone",
            working ? QStringLiteral("working") : e.state == Explanation::Failed ? QStringLiteral("err") : QString());
    const QString model = modelName(e.model.isEmpty() ? Explain::Settings::load().model : e.model);
    explainStatus_->setText(working ? "Asking " + (model.isEmpty() ? QStringLiteral("the AI") : model) +
                                          " what this is" + QChar(0x2026)
                            : e.state == Explanation::NoKey  ? QStringLiteral("Explanations are off.")
                            : e.state == Explanation::Failed ? QStringLiteral("The explanation did not arrive.")
                                                             : QStringLiteral("What is this program?"));
    settingsLink_->setVisible(e.state == Explanation::NoKey);
    explainAction_->setVisible(e.state == Explanation::Offer || e.state == Explanation::Failed);
    explainAction_->setText(e.state == Explanation::Failed ? "Try again" : "Ask AI");

    suggestion_->setVisible(ready);
    restyle(suggestion_, "kind", e.suggestion == "block" || e.suggestion == "allow" ? e.suggestion : QString());
    suggestion_->setText(e.suggestion == "block"   ? QStringLiteral("AI suggests Block")
                         : e.suggestion == "allow" ? QStringLiteral("AI suggests Allow")
                                                   : QStringLiteral("AI: your call"));
    const bool hasMore = ready && !(e.why.isEmpty() && e.reason.isEmpty() && e.risk.isEmpty());
    details_->setVisible(hasMore);
    details_->setText(detailsOpen_ ? "Less" : "Details");
    what_->setText(ready ? e.what : QString());
    what_->setVisible(ready && !e.what.isEmpty());
    more_->setVisible(hasMore && detailsOpen_);
    why_->setText(e.why);
    reason_->setText(e.reason);
    risk_->setText(e.risk);
    for (auto [head, body] : {std::pair{whyHead_, why_}, std::pair{reasonHead_, reason_}, std::pair{riskHead_, risk_}}) {
        head->setVisible(!body->text().isEmpty());
        body->setVisible(!body->text().isEmpty());
    }
    // Los rótulos van en inglés como el resto de la interfaz; el contenido llega en el idioma elegido en Settings.
    const QString foot = ready     ? "AI explanation · " + modelName(e.model) + " · may be wrong"
                         : working ? QStringLiteral("You can decide now; the answer never holds the notice.")
                         : e.state == Explanation::Failed ? e.error
                         : e.state == Explanation::Offer && !Explain::Settings::load().automatic
                             ? QStringLiteral("Automatic explanations are off.")
                             : QString();
    explainFoot_->setText(foot);
    explainFoot_->setVisible(!foot.isEmpty());
}

void AccessToast::layoutChoices() {
    // «Apply to» a todo el ancho; «For» y «Destination» abajo con el mismo ancho (si sobra un píxel va al espacio).
    const int avail = width_ - 2 * Pad;
    const int half = (avail - ChipGap) / 2;
    scope_->setGeometry(0, 0, avail, ChipHeight);
    duration_->setGeometry(0, ChipHeight + ChipGap, half, ChipHeight);
    target_->setGeometry(avail - half, ChipHeight + ChipGap, half, ChipHeight);
    choices_->setFixedSize(avail, 2 * ChipHeight + ChipGap);
    // El texto entero en el tooltip sólo si el desplegable muestra uno corto o recortado.
    for (auto *combo : {scope_, duration_, target_}) {
        const QString shown = static_cast<ScopeCombo *>(combo)->shownText();
        CustomTooltip::instance()->setToolTip(combo, shown != combo->currentText() ? combo->currentText().toHtmlEscaped()
                                                                                  : QString());
        combo->update();
    }
}

void AccessToast::relayout() {
    const int section = width_ - 2 * Pad;
    const int card = section - 2 - 2 * CardInsetX;
    const QString exe = QFileInfo(request_.path).fileName();
    title_->setFixedWidth(section - IconSize - IconGap);
    elide(title_, exe, title_->width());
    fit(body_, section - IconSize - IconGap);
    fit(warn_, section - 2 - 2 * NoteInsetX);
    fit(info_, section - 2 - 2 * NoteInsetX);
    renderDestination();
    if (knownBox_->isVisibleTo(this)) {
        elide(knownPill_, knownPill_->property("full").toString(), section - 20, Qt::ElideRight);
        knownPill_->setFixedWidth(knownPill_->sizeHint().width());
        fit(knownText_, section);
    }
    for (auto *l : {what_, why_, reason_, risk_, explainFoot_}) fit(l, card);
    for (auto *l : {whyHead_, reasonHead_, riskHead_}) l->setFixedWidth(card);
    // La píldora y el estado van en una sola línea con su enlace o botón a la derecha.
    suggestion_->setFixedWidth(suggestion_->sizeHint().width());
    layoutChoices();
    fit(folderNote_, section);
    // Los recuadros internos recalculan su layout recién en el próximo ciclo de eventos: se fuerza ya, de adentro
    // hacia afuera, para que el alto que sigue (también al achicarse con «Less») sea el nuevo.
    const auto boxes = findChildren<QWidget *>();
    for (auto it = boxes.crbegin(); it != boxes.crend(); ++it) {
        if (!(*it)->layout()) continue;
        (*it)->layout()->invalidate();
        (*it)->layout()->activate();
        (*it)->updateGeometry();
    }
    if (layout()) {
        layout()->invalidate();
        layout()->activate();
    }
    adjustSize();
}

void AccessToast::placeOn(QScreen *screen) {
    // Donde el usuario lo dejó, si esa esquina sigue en alguna pantalla; si no, abajo a la derecha.
    auto s = store();
    const QPoint saved(s.value("toast/right", -1).toInt(), s.value("toast/bottom", -1).toInt());
    const int savedWidth = s.value("toast/width", Width).toInt();
    QScreen *home = s.contains("toast/right") ? QGuiApplication::screenAt(saved) : nullptr;
    if (home) screen = home;
    if (!screen) screen = QGuiApplication::primaryScreen();
    if (!screen) return;
    screen_ = screen;
    applyWidth(savedWidth);
    const QRect area = screen->availableGeometry();
    anchor_ = home ? saved : QPoint(area.right() - Margin, area.bottom() - Margin);
    anchored_ = true;
    if (layout()) layout()->activate();
    adjustSize();
    keepInside();
}

void AccessToast::applyWidth(int width) {
    width_ = qBound(Width, width, MaxWidth);
    setFixedWidth(width_);
    relayout();
}

void AccessToast::keepInside() {
    if (!anchored_) return;
    QScreen *screen = QGuiApplication::screenAt(anchor_);
    if (!screen) screen = screen_ ? screen_.data() : QGuiApplication::primaryScreen();
    if (!screen) return;
    const QRect area = screen->availableGeometry();
    // La esquina se corre lo justo para que el aviso entero quede dentro del área visible (sin la barra de tareas).
    const int right = qBound(area.left() + width() - 1, anchor_.x(), area.right());
    const int bottom = qBound(qMin(area.top() + height() - 1, area.bottom()), anchor_.y(), area.bottom());
    move(right - width() + 1, bottom - height() + 1);
}

void AccessToast::remember() {
    auto s = store();
    s.setValue("toast/right", anchor_.x());
    s.setValue("toast/bottom", anchor_.y());
    s.setValue("toast/width", width_);
}

int AccessToast::edgeAt(const QPoint &pos) const {
    if (pos.x() < Edge) return -1;
    if (pos.x() >= width() - Edge) return 1;
    return 0;
}

void AccessToast::mousePressEvent(QMouseEvent *event) {
    if (event->button() != Qt::LeftButton) return QWidget::mousePressEvent(event);
    edge_ = edgeAt(event->position().toPoint());
    dragging_ = edge_ == 0;
    pressGlobal_ = event->globalPosition().toPoint();
    pressAnchor_ = anchor_;
    pressWidth_ = width_;
    event->accept();
}

void AccessToast::mouseMoveEvent(QMouseEvent *event) {
    const QPoint delta = event->globalPosition().toPoint() - pressGlobal_;
    if (event->buttons() & Qt::LeftButton) {
        if (edge_ != 0) {
            // Borde derecho: crece hacia la derecha; borde izquierdo: hacia la izquierda, con el derecho quieto.
            applyWidth(pressWidth_ + (edge_ > 0 ? delta.x() : -delta.x()));
            if (edge_ > 0) anchor_.setX(pressAnchor_.x() + (width_ - pressWidth_));
            keepInside();
        } else if (dragging_) {
            anchor_ = pressAnchor_ + delta;
            keepInside();
        }
        return;
    }
    setCursor(edgeAt(event->position().toPoint()) ? Qt::SizeHorCursor : Qt::ArrowCursor);
}

void AccessToast::mouseReleaseEvent(QMouseEvent *event) {
    // Sólo si se movió o se ensanchó de verdad: un clic suelto no guarda la posición.
    const bool moved = (event->globalPosition().toPoint() - pressGlobal_).manhattanLength() > 2;
    if (event->button() == Qt::LeftButton && (dragging_ || edge_) && moved) {
        // La esquina queda donde se ve el aviso (keepInside pudo correrla).
        anchor_ = geometry().bottomRight();
        remember();
    }
    dragging_ = false;
    edge_ = 0;
    QWidget::mouseReleaseEvent(event);
}

bool AccessToast::eventFilter(QObject *watched, QEvent *event) {
    // El aviso aparece sin activarse; un desplegable de una ventana inactiva abre su lista a medias y pierde la
    // elección. El clic del usuario lo activa antes de que el desplegable lo procese.
    if (event->type() == QEvent::MouseButtonPress && !isActiveWindow()) activateWindow();
    const auto t = event->type();
    if (t == QEvent::MouseButtonPress || t == QEvent::Show || t == QEvent::Hide)
        trace(QString("%1 %2 activo=%3 habilitado=%4 indice=%5")
                  .arg(watched->objectName().isEmpty() ? QString("lista") : watched->objectName())
                  .arg(t == QEvent::MouseButtonPress ? "clic" : t == QEvent::Show ? "abre" : "cierra")
                  .arg(isActiveWindow())
                  .arg(duration_->isEnabled())
                  .arg(duration_->currentIndex()));
    return QWidget::eventFilter(watched, event);
}

void AccessToast::leaveEvent(QEvent *event) {
    if (!dragging_ && !edge_) unsetCursor();
    QWidget::leaveEvent(event);
}

void AccessToast::resizeEvent(QResizeEvent *event) {
    QWidget::resizeEvent(event);
    // Cualquier cambio de alto (la explicación, un destino con nombre) crece hacia arriba y queda en pantalla.
    if (isVisible() && !dragging_) keepInside();
}

void AccessToast::paintEvent(QPaintEvent *) {
    // La hoja del Pliego con su borde y esquinas de 12 px.
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    QPainterPath path;
    path.addRoundedRect(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5), 12, 12);
    painter.fillPath(path, Theme::color(Theme::kSheet));
    painter.setPen(Theme::color(Theme::kBorder));
    painter.drawPath(path);
}

} // namespace Gate
