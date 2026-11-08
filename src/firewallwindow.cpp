#include "firewallwindow.h"
#include "appicon.h"
#include "customtooltip.h"
#include "explain/KnownApps.h"
#include "folder_rule.h"
#include "foldertrust.h"
#include "platform/WindowFrame.h"
#include "theme.h"
#include "toggleswitch.h"
#include <QAbstractButton>
#include <QApplication>
#include <QComboBox>
#include <QDateTime>
#include <QDesktopServices>
#include <QUrl>
#include <QDialog>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QGridLayout>
#include <QHash>
#include <QHeaderView>
#include <QHostAddress>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSettings>
#include <QShowEvent>
#include <QStyle>
#include <QStyleOptionComboBox>
#include <QStylePainter>
#include <QTableWidget>
#include <QWindow>
#include <QVBoxLayout>
#include <algorithm>
#include <thread>
#include <windows.h>
#include <tlhelp32.h>

namespace Gate {

// ------------------------------------------------------------------------------------------------------------------
// Piezas de la ventana: estilo, íconos y controles chicos.

namespace {

// Pliego de Mighty Tools (src/ui/Theme.h) con el acento violeta de las apps LGA; tokens en theme.h. Los tamaños con
// medio píxel pasan a puntos en Theme::css().
const char *kStyle = R"(
QWidget#fwRoot { background: #0D0D0F; }
QWidget#fwWorkspace, QWidget#fwPage, QScrollArea#fwScroll, QScrollArea#fwScroll > QWidget > QWidget { background: transparent; }
QScrollArea#fwScroll { border: 0; }
QFrame#fwTitle { background: #0D0D0F; border: 0; }
QLabel { background: transparent; }
QLabel[r="appname"] { color: #ECE9E2; font-family: @title; font-size: 14px; font-weight: 700; }
QLabel[r="big"] { color: #ECE9E2; font-family: @title; font-size: 34px; font-weight: 800; }
QLabel[r="desc"] { color: #A6A5AC; font-size: 13.5px; }
QLabel[r="cardtitle"] { color: #ECE9E2; font-family: @title; font-size: 16px; font-weight: 700; }
QLabel[r="midtitle"] { color: #ECE9E2; font-family: @title; font-size: 24px; font-weight: 800; }
QLabel[r="strong"] { color: #E3E1DA; font-size: 14px; font-weight: 500; }
QLabel[r="body"] { color: #C4C3C9; font-size: 13px; }
QLabel[r="value"] { color: #E3E1DA; font-size: 13px; }
QLabel[r="sub"] { color: #9C9BA2; font-size: 12.5px; }
QLabel[r="small"] { color: #9C9BA2; font-size: 12.5px; }
QLabel[r="faint"] { color: #8C8B93; font-size: 12px; }
QLabel[r="colhead"] { color: #8C8B93; font-size: 11.5px; }
QLabel[r="label"] { color: #8C8B93; font-size: 11px; font-weight: 600; }
QLabel[r="section"] { color: #8C8B93; font-size: 11px; font-weight: 600; }
QLabel[r="stat"] { color: #ECE9E2; font-family: @title; font-size: 30px; font-weight: 800; }
QLabel[r="ok"] { color: #4CC9EE; font-size: 12.5px; }
QLabel[r="warn"] { color: #F2CB3F; font-size: 12.5px; }
QLabel[r="bad"] { color: #F0645C; font-size: 12.5px; }
QLabel[r="time"] { color: #8C8B93; font-size: 12.5px; }
QLabel[r="sidename"] { color: #DCDAD3; font-family: @title; font-size: 14px; font-weight: 600; }
QLabel[r="sidename"][sel="1"] { color: #F3F0E9; }
QLabel[r="sidestatus"] { color: #8C8B93; font-size: 12px; }
QLabel[r="sidestatus"][tone="ok"] { color: #4CC9EE; }
QLabel[r="sidestatus"][tone="warn"] { color: #F2CB3F; }
QLabel[r="sidestatus"][tone="bad"] { color: #F0645C; }
QLabel[r="hownumber"] { color: #ECE9E2; font-family: @title; font-size: 19px; font-weight: 800; }
QLabel[r="howtitle"] { color: #DCDAD3; font-size: 13px; font-weight: 600; }
QLabel[r="howstep"] { color: #C4C3C9; font-size: 13.5px; }
QLabel[r="note"] { color: #E6C870; font-size: 12.5px; background: #1F1C12; border: 1px solid #5A4E26; border-radius: 8px; padding: 8px 10px; }
QLabel[r="info"] { color: #B7B0E8; font-size: 12.5px; background: #1D1B2C; border: 1px solid #3A3466; border-radius: 8px; padding: 8px 10px; }
QFrame[r="card"] { background: #1E1E23; border: 1px solid #25252B; border-radius: 10px; }
QFrame[r="alert"] { background: #1E1E23; border: 1px solid #5A4E26; border-radius: 10px; }
QFrame[r="danger"] { background: #1E1E23; border: 1px solid #6B2E31; border-radius: 10px; }
QFrame[r="ai"] { background: #1A1A1F; border: 1px solid #2E2E36; border-radius: 10px; }
QFrame[r="aierr"] { background: #1A1A1F; border: 1px solid #6B2E31; border-radius: 10px; }
QFrame[r="aiquiet"] { background: #1A1A1F; border: 1px solid #2A2A31; border-radius: 10px; }
QFrame[r="how"] { background: transparent; border: 1px solid #2A2A31; border-radius: 10px; }
QFrame[r="how"][open="1"] { background: #1E1E23; border: 1px solid #2E2E36; }
QFrame[r="divider"] { background: #2A2A31; border: 0; }
QFrame[r="seg"] { background: #15151A; border: 1px solid #2F2F37; border-radius: 7px; }
QFrame#fwMessage { background: #1D1B2C; border: 1px solid #3A3466; border-radius: 8px; }
QLabel[pill] { border-radius: 4px; padding: 0 8px; font-size: 12px; font-weight: 600; }
QLabel[pill="allow"] { background: #0D2A33; border: 1px solid #24586A; color: #57CDEF; }
QLabel[pill="block"] { background: #361B1D; border: 1px solid #6B2E31; color: #F0645C; }
QLabel[pill="temp"] { background: #25223B; border: 1px solid #5243A8; color: #C5BBF4; }
QLabel[pill="dest"] { background: #2A2A31; border: 1px solid #3A3A43; color: #C4C3C9; }
QLabel[pill="none"] { background: transparent; border: 1px solid #3A3A43; color: #9C9BA2; }
QLabel[hint] { border-radius: 11px; padding: 0 9px; font-size: 12px; font-weight: 600; }
QLabel[hint="block"] { background: #361B1D; border: 1px solid #6B2E31; color: #F0645C; }
QLabel[hint="allow"] { background: #0D2A33; border: 1px solid #24586A; color: #57CDEF; }
QLabel[hint="either"] { background: transparent; border: 1px solid #3A3A43; color: #C4C3C9; }
QLabel[hint="known"] { background: #25223B; border: 1px solid #5243A8; color: #C5BBF4; }
QLabel[hint="none"] { background: transparent; border: 1px dashed #3A3A43; color: #8C8B93; }
QLabel[chip] { border-radius: 4px; padding: 0 8px; font-size: 12px; font-weight: 600; }
QLabel[chip="1"] { background: transparent; border: 1px solid #3A3A43; color: #9C9BA2; }
QLabel[chip="wait"] { background: #F2CB3F; border: 1px solid #F2CB3F; color: #1C1606; }
QLabel[chip="allow"] { background: #0D2A33; border: 1px solid #24586A; color: #57CDEF; }
QLabel[chip="block"] { background: #361B1D; border: 1px solid #6B2E31; color: #F0645C; }
QLabel[chip="mute"] { background: transparent; border: 1px solid #3A3A43; color: #9C9BA2; font-weight: 500; }
QLabel[chip="warn"] { background: #F2CB3F; border: 0; color: #1C1606; }
QLabel[chip="ok"] { background: transparent; border: 1px solid #24586A; color: #57CDEF; }
QLabel#fwBadge { background: #F2CB3F; color: #1C1606; border-radius: 4px; font-size: 12px; font-weight: 600; }
QLabel[key="1"] { background: #2A2A31; border: 1px solid #3B3B44; border-bottom: 3px solid #0F0F12; border-radius: 4px; color: #E3E1DA; font-size: 11.5px; font-weight: 600; padding: 0 6px; }
QPushButton { border: 1px solid #3A3A43; border-radius: 6px; background: #2A2A31; color: #E3E1DA; padding: 0 14px; min-height: 28px; font-size: 13px; font-weight: 500; }
QPushButton:hover { background: #34343C; border: 1px solid #4A4A55; }
QPushButton:disabled { background: #222227; border: 1px solid #2E2E36; color: #6E6D75; }
QPushButton[k="primary"], QPushButton[k="allow"] { background: #443A91; border: 1px solid #5243A8; color: #DDDBEE; font-weight: 600; }
QPushButton[k="primary"]:hover, QPushButton[k="allow"]:hover { background: #5446B4; border: 1px solid #7060D0; }
QPushButton[k="block"] { background: #361B1D; border: 1px solid #6B2E31; color: #F0645C; font-weight: 600; }
QPushButton[k="block"]:hover { background: #4A2326; border: 1px solid #8A3A3E; }
QPushButton[k="allow"][rec="1"] { border: 1px solid #9D8FE0; }
QPushButton[k="block"][rec="1"] { border: 1px solid #F0645C; }
QPushButton[k="primary"]:disabled, QPushButton[k="allow"]:disabled, QPushButton[k="block"]:disabled { background: #222227; border: 1px solid #2E2E36; color: #6E6D75; }
QPushButton[k="ghost"] { background: transparent; }
QPushButton[k="ghost"]:hover { background: #26262D; }
QPushButton[k="link"] { background: transparent; border: 0; color: #9D8FE0; padding: 0; min-height: 0; font-size: 12.5px; font-weight: 600; }
QPushButton[k="link"]:hover { color: #C5BBF4; border: 0; background: transparent; }
QPushButton[k="link"]:disabled { color: #6E6D75; border: 0; background: transparent; }
QPushButton[k="seg"] { background: transparent; border: 1px solid transparent; color: #8C8B93; border-radius: 5px; min-height: 22px; padding: 0 11px; font-size: 12.5px; font-weight: 600; }
QPushButton[k="seg"]:hover { background: #202026; color: #E3E1DA; border: 1px solid transparent; }
QPushButton[k="seg"][on="1"] { background: #2A2552; border: 1px solid #5243A8; color: #DDDBEE; }
QPushButton[k="x"] { background: transparent; border: 0; color: #9C9BA2; padding: 0; min-height: 22px; min-width: 22px; font-size: 14px; }
QPushButton[k="x"]:hover { color: #F0645C; background: transparent; border: 0; }
QPushButton[sm="1"] { min-height: 24px; padding: 0 10px; font-size: 12.5px; }
QPushButton:focus { outline: none; }
QLineEdit { background: #15151A; border: 1px solid #2F2F37; border-radius: 6px; color: #E3E1DA; padding: 0 10px; min-height: 28px; font-size: 13px; selection-background-color: #2A2552; }
QLineEdit:hover { border: 1px solid #44444E; }
QLineEdit:focus { border: 1px solid #5243A8; }
QComboBox { background: #15151A; border: 1px solid #2F2F37; border-radius: 6px; color: #E3E1DA; padding: 0 26px 0 10px; min-height: 26px; font-size: 13px; }
QComboBox:hover { border: 1px solid #44444E; }
QComboBox:disabled { color: #6E6D75; }
QComboBox::drop-down { border: 0; width: 22px; }
QComboBox::down-arrow { image: none; }
QComboBox QAbstractItemView { background: #1E1E23; color: #E3E1DA; selection-background-color: #25223B; selection-color: #ECE9E2; border: 1px solid #2E2E36; outline: 0; }
QTableWidget#fwTable { background: transparent; border: 0; outline: 0; }
QTableWidget#fwTable::item { border: 0; border-bottom: 1px solid #2A2A31; padding: 0; }
QTableWidget#fwTable::item:hover { background: #26262D; }
QHeaderView { background: transparent; border: 0; }
QHeaderView::section { background: transparent; color: #8C8B93; border: 0; border-bottom: 1px solid #2A2A31; border-right: 1px solid #222227; padding: 0 14px; min-height: 33px; font-size: 11px; font-weight: 600; }
QHeaderView::section:hover { background: #202026; color: #C4C3C9; }
QHeaderView::section:last { border-right: 0; }
QScrollBar:vertical { width: 8px; background: transparent; margin: 2px; }
QScrollBar::handle:vertical { background: #3A3A43; border-radius: 2px; min-height: 25px; }
QScrollBar::handle:vertical:hover { background: #4A4A55; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QScrollBar:horizontal { height: 8px; background: transparent; margin: 2px; }
QScrollBar::handle:horizontal { background: #3A3A43; border-radius: 2px; min-width: 25px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: transparent; }
QDialog { background: #17171B; border: 1px solid #2E2E36; }
)";

QLabel *text(const QString &value, const char *role = "body", bool wrap = false) {
    auto *l = new QLabel(value);
    l->setProperty("r", role);
    l->setWordWrap(wrap);
    l->setTextFormat(Qt::PlainText);
    return l;
}
QLabel *pill(const QString &value, const char *kind) {
    auto *l = new QLabel(value);
    l->setProperty("pill", kind);
    l->setTextFormat(Qt::PlainText);
    l->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
    l->setFixedHeight(22);
    return l;
}
QLabel *hint(const QString &value, const char *kind) {
    auto *l = new QLabel(value);
    l->setProperty("hint", kind);
    l->setTextFormat(Qt::PlainText);
    l->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
    l->setFixedHeight(22);
    return l;
}
QLabel *chip(const QString &value, const char *tone = "1") {
    auto *l = new QLabel(value);
    l->setProperty("chip", tone);
    l->setTextFormat(Qt::PlainText);
    l->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
    l->setFixedHeight(22);
    return l;
}
QPushButton *button(const QString &label, const char *kind = nullptr, bool small = false) {
    auto *b = new QPushButton(label);
    if (kind) b->setProperty("k", kind);
    if (small) b->setProperty("sm", "1");
    b->setCursor(Qt::PointingHandCursor);
    b->setFocusPolicy(Qt::TabFocus);
    return b;
}
// Block y Allow de un pedido (`.btn.dec`): chicos y del mismo ancho, Block en rojo y Allow en el violeta del acento.
QPushButton *decision(const QString &label, const char *kind) {
    auto *b = button(label, kind, true);
    b->setFixedSize(72, 26);
    b->setStyleSheet("padding: 0;");
    return b;
}
// Rótulo en versalitas con aire entre letras (`FIREWALL`, `RULE`).
QLabel *caps(const QString &value, const char *role = "label") {
    auto *l = new QLabel(value.toUpper());
    l->setProperty("r", role);
    l->setTextFormat(Qt::PlainText);
    QFont f = l->font();
    f.setLetterSpacing(QFont::PercentageSpacing, 109);
    l->setFont(f);
    return l;
}
// Resalta el botón que recomienda el catálogo de apps conocidas (o una app LGA); nunca decide nada.
void recommend(QPushButton *block, QPushButton *allow, const QString &known) {
    const QString suggested = KnownApps::suggestion(known);
    allow->setProperty("rec", suggested == "allow" ? "1" : "");
    block->setProperty("rec", suggested == "block" ? "1" : "");
}
QFrame *card(const char *role = "card") {
    auto *f = new QFrame;
    f->setProperty("r", role);
    return f;
}
// Tarjeta del Pliego (`.card`): 15 arriba, 18 a los costados, 16 abajo.
QVBoxLayout *cardColumn(QWidget *w, int spacing = 8) {
    auto *l = new QVBoxLayout(w);
    l->setContentsMargins(18, 15, 18, 16);
    l->setSpacing(spacing);
    return l;
}
QVBoxLayout *column(QWidget *w, int margin = 14, int spacing = 8) {
    auto *l = new QVBoxLayout(w);
    l->setContentsMargins(margin, margin, margin, margin);
    l->setSpacing(spacing);
    return l;
}
QHBoxLayout *row(int spacing = 10) {
    auto *l = new QHBoxLayout;
    l->setContentsMargins(0, 0, 0, 0);
    l->setSpacing(spacing);
    return l;
}
QFrame *divider() {
    auto *f = new QFrame;
    f->setProperty("r", "divider");
    f->setFixedHeight(1);
    return f;
}

// La rueda nunca cambia lo elegido: desplaza la página aunque el puntero pase por encima.
class Combo final : public QComboBox {
  public:
    using QComboBox::QComboBox;
  protected:
    void wheelEvent(QWheelEvent *event) override { event->ignore(); }
    void paintEvent(QPaintEvent *) override {
        // Lo elegido se recorta con «…» si no entra (Qt lo corta a secas); entero, en el tooltip propio.
        QStylePainter sp(this);
        QStyleOptionComboBox opt;
        initStyleOption(&opt);
        const QString full = opt.currentText;
        opt.currentText.clear();
        sp.drawComplexControl(QStyle::CC_ComboBox, opt);
        // El texto, con los mismos 10 de aire de la hoja de estilo y lugar para la flecha a la derecha.
        const QRect field = rect().adjusted(11, 0, -26, 0);
        const QString shown = fontMetrics().elidedText(full, Qt::ElideRight, field.width());
        sp.setPen(palette().color(isEnabled() ? QPalette::Active : QPalette::Disabled, QPalette::ButtonText));
        sp.drawText(field, Qt::AlignLeft | Qt::AlignVCenter | Qt::TextSingleLine, shown);
        const QString tip = shown == full ? QString() : full.toHtmlEscaped();
        if (tip != tip_) {
            tip_ = tip;
            CustomTooltip::instance()->setToolTip(this, tip);
        }
        sp.end();
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.setPen(QPen(QColor(isEnabled() ? "#9C9BA2" : "#5E5D66"), 1.2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        const QPointF c(width() - 12, height() / 2.0);
        QPainterPath chevron;
        chevron.moveTo(c + QPointF(-3, -1.5));
        chevron.lineTo(c + QPointF(0, 1.5));
        chevron.lineTo(c + QPointF(3, -1.5));
        p.drawPath(chevron);
    }

  private:
    QString tip_;
};

// Texto de una línea que se recorta con «…» cuando no entra, en vez de ensanchar la página. Si se recorta, el texto
// entero queda en el tooltip (es lo único que no se ve).
class ElideLabel final : public QLabel {
  public:
    explicit ElideLabel(const QString &value, const char *role, Qt::TextElideMode mode = Qt::ElideRight)
        : QLabel(value), mode_(mode) {
        setProperty("r", role);
        setTextFormat(Qt::PlainText);
        setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    }
    QSize minimumSizeHint() const override { return {12, QLabel::minimumSizeHint().height()}; }

  protected:
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.setPen(palette().color(foregroundRole()));
        p.setFont(font());
        const QRect r = contentsRect();
        const QString shown = fontMetrics().elidedText(text(), mode_, r.width());
        p.drawText(r, int(alignment()) | Qt::TextSingleLine, shown);
        const QString tip = shown == text() ? QString() : text().toHtmlEscaped();
        if (tip_ != tip) {
            tip_ = tip;
            CustomTooltip::instance()->setToolTip(this, tip);
        }
    }

  private:
    Qt::TextElideMode mode_;
    QString tip_; // el tooltip propio que ya tiene: se registra sólo cuando cambia, no en cada repintado
};

// Tabla de una vista (Apps, Activity): encabezado fijo con columnas que se ensanchan arrastrando, y sólo las filas se
// desplazan. Los anchos que elige el usuario se guardan por tabla. La última columna toma el espacio que sobra.
struct Column {
    QString title;
    int width;
    Qt::Alignment align = Qt::AlignLeft;
};
QSettings tableStore() { return QSettings(QSettings::NativeFormat, QSettings::UserScope, "LGA", "GateBouncer"); }
// Los recorridos de QA no guardan tamaños: no pisan las preferencias de quien usa la app.
bool rememberSizes() { return qEnvironmentVariableIsEmpty("GATEBOUNCER_QA_SHOT"); }
// Al achicar la ventana las columnas anchas ceden (hasta 140 px), así la última no queda tapada ni aparece la barra
// horizontal. Lo que el usuario ensancha a mano no se toca hasta el próximo cambio de tamaño.
class TableFitter final : public QObject {
  public:
    explicit TableFitter(QTableWidget *table) : QObject(table), table_(table) { table->viewport()->installEventFilter(this); }
    void fit() {
        const int n = table_->columnCount();
        if (n < 2) return;
        // Se parte siempre de los anchos que eligió el usuario (o los de fábrica): al agrandar la ventana los recuperan.
        table_->setProperty("fitting", true);
        const QStringList preferred = table_->property("preferred").toStringList();
        for (int i = 0; i + 1 < n && i < preferred.size(); ++i) table_->setColumnWidth(i, preferred[i].toInt());
        const int lastMin = table_->property("lastMinimum").toInt();
        int used = qMax(lastMin, 90);
        for (int i = 0; i + 1 < n; ++i) used += table_->columnWidth(i);
        int overflow = used - table_->viewport()->width();
        while (overflow > 0) {
            int widest = -1;
            for (int i = 0; i + 1 < n; ++i)
                if (table_->columnWidth(i) > 140 && (widest < 0 || table_->columnWidth(i) > table_->columnWidth(widest)))
                    widest = i;
            if (widest < 0) break;
            const int take = qMin(overflow, table_->columnWidth(widest) - 140);
            table_->setColumnWidth(widest, table_->columnWidth(widest) - take);
            overflow -= take;
        }
        table_->setProperty("fitting", false);
    }

  protected:
    bool eventFilter(QObject *, QEvent *event) override {
        if (event->type() == QEvent::Resize) QTimer::singleShot(0, this, [this] { fit(); });
        return false;
    }

  private:
    QTableWidget *table_;
};
QTableWidget *makeTable(const QString &name, int rowHeight) {
    auto *t = new QTableWidget;
    t->setObjectName("fwTable");
    t->setProperty("tableName", name);
    t->setFrameShape(QFrame::NoFrame);
    t->setShowGrid(false);
    t->setWordWrap(false);
    t->setFocusPolicy(Qt::NoFocus);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setSelectionMode(QAbstractItemView::NoSelection);
    t->setSelectionBehavior(QAbstractItemView::SelectRows); // el hover pinta la fila entera
    t->setMouseTracking(true);
    t->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    t->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    t->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    t->verticalHeader()->hide();
    t->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    t->verticalHeader()->setDefaultSectionSize(rowHeight);
    auto *h = t->horizontalHeader();
    h->setHighlightSections(false);
    h->setSectionsClickable(false);
    h->setMinimumSectionSize(60);
    h->setStretchLastSection(true);
    h->setFixedHeight(34);
    t->setProperty("fitter", QVariant::fromValue(static_cast<QObject *>(new TableFitter(t))));
    return t;
}
// Columnas de la tabla; con otro juego de columnas (otro filtro) se guarda aparte.
void setColumns(QTableWidget *t, const QString &set, const QVector<Column> &columns) {
    const QString key = "tables/" + t->property("tableName").toString() + "-" + set;
    if (t->property("columnSet").toString() == key) return;
    auto *h = t->horizontalHeader();
    // El guardado de anchos del juego anterior se desconecta borrando su objeto (sin tocar las conexiones de Qt).
    delete t->findChild<QObject *>("columnSaver", Qt::FindDirectChildrenOnly);
    auto *saver = new QObject(t);
    saver->setObjectName("columnSaver");
    t->setColumnCount(int(columns.size()));
    for (int i = 0; i < columns.size(); ++i) {
        auto *item = new QTableWidgetItem(columns[i].title);
        item->setTextAlignment(columns[i].align | Qt::AlignVCenter);
        t->setHorizontalHeaderItem(i, item);
        h->setSectionResizeMode(i, QHeaderView::Interactive);
        t->setColumnWidth(i, columns[i].width);
    }
    const QStringList saved = tableStore().value(key).toStringList();
    if (saved.size() == columns.size())
        for (int i = 0; i + 1 < saved.size(); ++i) t->setColumnWidth(i, qMax(60, saved[i].toInt()));
    QStringList preferred;
    for (int i = 0; i < t->columnCount(); ++i) preferred << QString::number(t->columnWidth(i));
    t->setProperty("preferred", preferred);
    t->setProperty("columnSet", key);
    t->setProperty("lastMinimum", columns.last().width);
    if (auto *fitter = static_cast<TableFitter *>(t->property("fitter").value<QObject *>()))
        QTimer::singleShot(0, fitter, [fitter] { fitter->fit(); });
    QObject::connect(h, &QHeaderView::sectionResized, saver, [t, key](int section) {
        // La última columna se estira sola, y lo que ajusta TableFitter tampoco es una elección del usuario.
        if (t->property("fitting").toBool() || section == t->columnCount() - 1) return;
        QStringList widths;
        for (int i = 0; i < t->columnCount(); ++i) widths << QString::number(t->columnWidth(i));
        t->setProperty("preferred", widths);
        if (rememberSizes()) tableStore().setValue(key, widths);
    });
}
// Celda: el contenido con aire a los costados, sin capturar el mouse (el clic y el hover son de la fila).
QWidget *cell(QWidget *content, Qt::Alignment align = Qt::AlignLeft, bool interactive = false) {
    auto *w = new QWidget;
    auto *l = new QHBoxLayout(w);
    l->setContentsMargins(14, 0, 14, 0);
    l->setSpacing(10);
    if (align & Qt::AlignRight) l->addStretch();
    // Una etiqueta de tamaño justo (Allow, 3 servers) queda a la izquierda; un texto que se recorta toma el ancho.
    const auto fit = content->sizePolicy().horizontalPolicy();
    const bool snug = fit == QSizePolicy::Maximum || fit == QSizePolicy::Fixed;
    l->addWidget(content, align & (Qt::AlignRight | Qt::AlignHCenter) || snug ? 0 : 1);
    if (snug && !(align & (Qt::AlignRight | Qt::AlignHCenter))) l->addStretch();
    if (align & Qt::AlignHCenter) l->insertStretch(0);
    if (!interactive) w->setAttribute(Qt::WA_TransparentForMouseEvents);
    return w;
}
void fillRow(QTableWidget *t, int row, const QVector<QWidget *> &cells) {
    for (int c = 0; c < cells.size(); ++c) {
        t->setItem(row, c, new QTableWidgetItem); // vacío: lleva el hover y la línea de abajo
        t->setCellWidget(row, c, cells[c]);
    }
}

// Íconos de línea de la barra lateral y de los encabezados (dibujados en una grilla de 20 x 20).
void drawIcon(QPainter &p, const QString &name, const QRectF &r, const QColor &color) {
    p.save();
    p.translate(r.topLeft());
    p.scale(r.width() / 20.0, r.height() / 20.0);
    p.setPen(QPen(color, 1.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    p.setBrush(Qt::NoBrush);
    QPainterPath path;
    if (name == "shield") {
        path.moveTo(10, 2.5);
        path.lineTo(16, 4.8);
        path.lineTo(16, 9.4);
        path.cubicTo(16, 13.3, 13.4, 16.1, 10, 17.5);
        path.cubicTo(6.6, 16.1, 4, 13.3, 4, 9.4);
        path.lineTo(4, 4.8);
        path.closeSubpath();
        path.moveTo(7.3, 10);
        path.lineTo(9.2, 11.9);
        path.lineTo(12.8, 8.1);
    } else if (name == "bell") {
        path.moveTo(5.5, 13.5);
        path.lineTo(5.5, 9);
        path.arcTo(QRectF(5.5, 4.5, 9, 9), 180, -180);
        path.lineTo(14.5, 13.5);
        path.lineTo(15.8, 15);
        path.lineTo(4.2, 15);
        path.closeSubpath();
        path.moveTo(8.3, 17);
        path.quadTo(10, 18.6, 11.7, 17);
    } else if (name == "apps") {
        for (const QPointF o : {QPointF(3, 3), QPointF(11.5, 3), QPointF(3, 11.5), QPointF(11.5, 11.5)})
            path.addRoundedRect(QRectF(o, QSizeF(5.5, 5.5)), 1.3, 1.3);
    } else if (name == "pulse") {
        path.moveTo(2.5, 10.5);
        path.lineTo(5.7, 10.5);
        path.lineTo(7.7, 5.5);
        path.lineTo(11.1, 14.5);
        path.lineTo(13.1, 10.5);
        path.lineTo(17.5, 10.5);
    } else if (name == "gear") {
        path.addEllipse(QPointF(10, 10), 2.6, 2.6);
        const QLineF spokes[] = {{10, 2.8, 10, 4.8}, {10, 15.2, 10, 17.2}, {2.8, 10, 4.8, 10}, {15.2, 10, 17.2, 10},
                                 {4.9, 4.9, 6.3, 6.3}, {13.7, 13.7, 15.1, 15.1}, {4.9, 15.1, 6.3, 13.7},
                                 {13.7, 6.3, 15.1, 4.9}};
        for (const auto &s : spokes) {
            path.moveTo(s.p1());
            path.lineTo(s.p2());
        }
    } else if (name == "help") {
        path.addEllipse(QPointF(10, 10), 7.2, 7.2);
        path.moveTo(7.9, 8.1);
        path.cubicTo(7.9, 6.8, 9.0, 5.9, 10.1, 5.9);
        path.cubicTo(11.3, 5.9, 12.3, 6.9, 12.2, 8.1);
        path.cubicTo(12.15, 8.7, 11.9, 9.05, 11.6, 9.3);
        path.cubicTo(10.9, 9.9, 9.95, 10.2, 9.95, 11.5);
        path.addEllipse(QPointF(10, 14), 0.45, 0.45);
    } else if (name == "chev-down" || name == "chev-up") {
        const qreal a = name == "chev-down" ? 8 : 12.5, b = name == "chev-down" ? 12.5 : 8;
        path.moveTo(5.5, a);
        path.lineTo(10, b);
        path.lineTo(14.5, a);
    } else if (name == "search") {
        path.addEllipse(QPointF(9, 9), 5, 5);
        path.moveTo(13, 13);
        path.lineTo(16.5, 16.5);
    } else if (name == "folder") {
        path.moveTo(2.8, 6.2);
        path.quadTo(2.8, 4.7, 4.3, 4.7);
        path.lineTo(7.5, 4.7);
        path.lineTo(9.1, 6.5);
        path.lineTo(15.7, 6.5);
        path.quadTo(17.2, 6.5, 17.2, 8);
        path.lineTo(17.2, 14.3);
        path.quadTo(17.2, 15.8, 15.7, 15.8);
        path.lineTo(4.3, 15.8);
        path.quadTo(2.8, 15.8, 2.8, 14.3);
        path.closeSubpath();
    } else { // ventana genérica: una app sin ícono propio
        path = genericAppGlyph();
    }
    p.drawPath(path);
    p.restore();
}

QPixmap iconPixmap(const QString &name, int size, const QColor &color, qreal dpr) {
    QPixmap pm(QSize(size, size) * dpr);
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    drawIcon(p, name, QRectF(0, 0, size, size), color);
    return pm;
}

// Ícono real del programa (el de Windows), en su caja (`.tile`, 36 o 30); si no hay archivo, uno genérico.
QLabel *appIcon(const QString &path, int box = 30) {
    auto *l = new QLabel;
    l->setFixedSize(box, box);
    l->setAlignment(Qt::AlignCenter);
    l->setStyleSheet(QString("background: #2A2A31; border: 0; border-radius: %1px;").arg(box >= 36 ? 8 : 7));
    l->setPixmap(appIconPixmap(path, box >= 36 ? 24 : 20, qApp->devicePixelRatio()));
    return l;
}

// Encabezado de una página (`.ph`): el título grande en Bricolage, la descripción debajo y, a la derecha, lo que se
// pase (el switch grande, un selector). Con `lead`, una caja a la izquierda del título (el ícono de una app).
QWidget *header(const QString &title, const QString &description, QWidget *right = nullptr, QWidget *lead = nullptr) {
    auto *w = new QWidget;
    auto *h = new QHBoxLayout(w);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(16);
    auto *t = new QVBoxLayout;
    t->setSpacing(6);
    auto *line = new QHBoxLayout;
    line->setSpacing(12);
    if (lead) line->addWidget(lead, 0, Qt::AlignVCenter);
    auto *big = new ElideLabel(title, lead ? "midtitle" : "big");
    big->setObjectName("page-title");
    if (!lead) {
        QFont f = Theme::titleFont(34, 800);
        f.setLetterSpacing(QFont::PercentageSpacing, 98);
        big->setFont(f);
    } else {
        big->setFont(Theme::titleFont(26, 800));
    }
    big->setFixedHeight(40);
    line->addWidget(big, 1);
    t->addLayout(line);
    if (!description.isEmpty()) {
        auto *d = text(description, "desc", true);
        d->setObjectName("page-description");
        d->setMaximumWidth(560);
        t->addWidget(d);
    }
    h->addLayout(t, 1);
    if (right) {
        auto *rb = new QVBoxLayout;
        rb->setContentsMargins(0, 9, 0, 0);
        rb->addWidget(right);
        rb->addStretch();
        h->addLayout(rb);
    }
    return w;
}

QString clock(qint64 seconds) {
    if (seconds <= 0) return {};
    const QDateTime t = QDateTime::fromSecsSinceEpoch(seconds);
    if (t.date() == QDate::currentDate()) return t.toString("HH:mm");
    return QLocale(QLocale::English).toString(t.date(), "MMM d");
}
QString clockFull(qint64 seconds) {
    if (seconds <= 0) return QStringLiteral("—");
    return QLocale(QLocale::English).toString(QDateTime::fromSecsSinceEpoch(seconds), "MMM d, HH:mm");
}
// Carpeta corta para mostrar: las dos últimas partes.
QString shortFolder(const QString &path) {
    const QStringList parts = QDir::fromNativeSeparators(QFileInfo(path).path()).split('/', Qt::SkipEmptyParts);
    if (parts.size() <= 2) return QDir::toNativeSeparators(QFileInfo(path).path());
    return parts.mid(parts.size() - 2).join('\\');
}

// Igual que el aviso: el comodín del dominio padre (api.github.com -> *.github.com).
QString parentWildcard(const QString &host) {
    const QStringList labels = host.split('.', Qt::SkipEmptyParts);
    if (labels.size() < 2) return {};
    if (labels.size() == 2) return "*." + host;
    const QStringList parent = labels.mid(1);
    static const QStringList second{"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"};
    if (parent.size() == 2 && parent[1].size() == 2 && second.contains(parent[0])) return "*." + host;
    return "*." + parent.join('.');
}
// Opciones del aviso, para elegir lo mismo desde la ventana. Primero va lo que el aviso preselecciona.
QVector<QPair<QString, QString>> scopeOptions(const FirewallClient::PendingItem &p) {
    return FolderTrust::scopeChoices(p.path, p.signer, p.perDestination);
}
QVector<QPair<QString, QString>> durationOptions() {
    QVector<QPair<QString, QString>> d{{"Always", "always"}};
    for (const int minutes : {1, 5, 10, 15, 30})
        d.push_back({minutes == 1 ? QStringLiteral("1 minute") : QString("%1 minutes").arg(minutes),
                     QString::number(minutes * 60)});
    d.push_back({"1 hour", "3600"});
    d.push_back({"Until restart", "restart"});
    return d;
}
QVector<QPair<QString, QString>> targetOptions(const FirewallClient::PendingItem &p) {
    QStringList targets;
    const QString kind = FirewallClient::destinationKind(p.remote);
    if (!p.host.isEmpty()) {
        targets << p.host;
        const QString wide = parentWildcard(p.host);
        if (!wide.isEmpty()) targets << wide;
    } else if (!kind.isEmpty() && kind != "This PC") {
        targets << p.remote;
    }
    QVector<QPair<QString, QString>> t;
    if (!p.perDestination) t.push_back({"Any destination", QString()});
    for (const auto &x : targets) t.push_back({"Only " + x, x});
    if (p.perDestination) t.push_back({"Any destination (whole app)", QString()});
    return t;
}
QString destinationLine(const FirewallClient::PendingItem &p) {
    const QString kind = FirewallClient::destinationKind(p.remote);
    QStringList parts;
    if (!kind.isEmpty()) parts << kind;
    if (p.host.isEmpty() && kind == "Internet") parts << "no server name seen";
    if (p.port) parts << FirewallClient::protocolName(p.protocol) + " " + QString::number(p.port);
    return parts.join(" · ");
}
// La dirección como la escribe el motor en sus pedidos (IPv4 mapeada a IPv6 pasa a IPv4, sin zona), para comparar
// la del historial, que viene tal cual la vio WFP, con la de un pedido abierto.
QString plainAddress(const QString &address) {
    const QHostAddress a(address.section('%', 0, 0).trimmed());
    if (a.isNull()) return address.trimmed().toLower();
    bool v4 = false;
    const quint32 ip = a.toIPv4Address(&v4);
    return v4 ? QHostAddress(ip).toString() : a.toString().toLower();
}

// Motivo de un bloqueo en el historial, con el tono de su etiqueta.
struct BlockReason {
    QString text;
    const char *tone = "1"; // "1" neutro, "wait", "allow", "block"
};

// El motor anota «waiting for decision» en el momento del intento y no reescribe el historial: la ventana averigua si
// ese pedido sigue abierto o cómo terminó. Una sola pasada de lo más nuevo a lo más viejo; para cada intento cuenta la
// primera decisión posterior de la misma app (o el primer permiso por regla al mismo destino), siempre que llegue antes
// de que el motor dé el pedido por vencido. Devuelve un motivo por evento; vacío en los que no son bloqueos.
QVector<BlockReason> blockReasons(const QVector<FirewallClient::ActivityItem> &events,
                                  const QVector<FirewallClient::PendingItem> &pending) {
    // El motor descarta un pedido sin respuesta a las 24 h: una decisión posterior es sobre otra pregunta.
    constexpr qint64 PendingLife = 24 * 3600;
    // La ventana lee pedidos e historial en dos respuestas seguidas: un intento recién anotado puede llegar antes que
    // su pedido. Sin decisión a la vista, uno de hace segundos se da por abierto en vez de mostrarlo cerrado un instante.
    constexpr qint64 FreshGrace = 10;
    // Pedidos abiertos: clave (ruta, o ruta|dirección en modo por destino) -> el comienzo más viejo.
    QHash<QString, qint64> open;
    for (const auto &p : pending) {
        const QString k = p.path.toLower() + (p.perDestination ? '|' + plainAddress(p.remote) : QString());
        const auto at = open.find(k);
        if (at == open.end() || p.first < at.value()) open[k] = p.first;
    }
    QVector<BlockReason> out(events.size());
    struct Seen {
        int index = -1;
        qint64 time = 0;
        BlockReason reason;
    };
    QHash<QString, Seen> saved;   // ruta -> primera «Rule saved» posterior
    QHash<QString, Seen> granted; // ruta|dirección -> primer «Allowed/Blocked by rule» posterior
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    for (int i = events.size() - 1; i >= 0; --i) {
        const auto &e = events[i];
        const QString app = e.path.toLower();
        if (e.kind.startsWith("Rule saved: Allow")) {
            saved[app] = {i, e.time, {"You allowed · " + clock(e.time), "allow"}};
            continue;
        }
        if (e.kind.startsWith("Rule saved: Block")) {
            saved[app] = {i, e.time, {"You blocked · " + clock(e.time), "block"}};
            continue;
        }
        if (e.kind.startsWith("Allowed by rule")) {
            granted[app + '|' + plainAddress(e.remote)] = {i, e.time, {"Allowed by your rule", "allow"}};
            continue;
        }
        if (!e.kind.startsWith("Blocked")) continue;
        if (e.kind.startsWith("Blocked by rule")) {
            out[i] = {"Your Block rule"};
            granted[app + '|' + plainAddress(e.remote)] = {i, e.time, {"Your Block rule"}};
            continue;
        }
        if (!e.kind.contains("waiting", Qt::CaseInsensitive)) {
            out[i] = {e.kind};
            continue;
        }
        // Sigue abierto si hay un pedido de esa app (o de ese destino, en modo por destino) que empezó en este intento
        // o antes. Uno que empezó después es otra pregunta: ésta ya se cerró.
        const QString destination = app + '|' + plainAddress(e.remote);
        const auto whole = open.constFind(app);
        const auto one = open.constFind(destination);
        if ((whole != open.constEnd() && whole.value() <= e.time) || (one != open.constEnd() && one.value() <= e.time)) {
            out[i] = {"Waiting for you", "wait"};
            continue;
        }
        const Seen *first = nullptr;
        const auto s = saved.constFind(app);
        if (s != saved.constEnd() && s->time - e.time <= PendingLife) first = &s.value();
        const auto g = granted.constFind(destination);
        if (g != granted.constEnd() && g->time - e.time <= PendingLife && (!first || g->index < first->index))
            first = &g.value();
        if (first) out[i] = first->reason;
        else if (now - e.time <= FreshGrace) out[i] = {"Waiting for you", "wait"};
        // Sin decisión a la vista: se cerró por otro camino (regla de la misma firma en otra copia, vencido a las 24 h,
        // el programa ya no existe).
        else out[i] = {"Request closed"};
    }
    return out;
}

} // namespace

// ------------------------------------------------------------------------------------------------------------------
// El marco del Pliego (src/app/WindowParts.cpp de Mighty Tools): la mesa negra con el índice, la hoja de cada página
// y la ficha elegida del índice unida a la hoja.

namespace {
constexpr int kNavWidth = 224;   // `.nav`
constexpr int kTabInset = 10;    // la ficha empieza a 10 del borde
constexpr int kSheetTop = 4;     // la hoja, 4 debajo de la barra de título
constexpr int kSheetMargin = 10; // y 10 de los bordes derecho e inferior
constexpr qreal kSheetRadius = 12;
constexpr qreal kTabRadius = 10;
constexpr qreal kFillet = 10;

// Rectángulo redondeado con un radio por esquina (QPainterPath::addRoundedRect usa uno solo).
QPainterPath roundedRect(const QRectF &r, qreal topLeft, qreal topRight, qreal bottomRight, qreal bottomLeft) {
    QPainterPath path;
    path.moveTo(r.left() + topLeft, r.top());
    path.lineTo(r.right() - topRight, r.top());
    if (topRight > 0) path.arcTo(QRectF(r.right() - 2 * topRight, r.top(), 2 * topRight, 2 * topRight), 90, -90);
    path.lineTo(r.right(), r.bottom() - bottomRight);
    if (bottomRight > 0)
        path.arcTo(QRectF(r.right() - 2 * bottomRight, r.bottom() - 2 * bottomRight, 2 * bottomRight, 2 * bottomRight), 0,
                   -90);
    path.lineTo(r.left() + bottomLeft, r.bottom());
    if (bottomLeft > 0)
        path.arcTo(QRectF(r.left(), r.bottom() - 2 * bottomLeft, 2 * bottomLeft, 2 * bottomLeft), 270, -90);
    path.lineTo(r.left(), r.top() + topLeft);
    if (topLeft > 0) path.arcTo(QRectF(r.left(), r.top(), 2 * topLeft, 2 * topLeft), 180, -90);
    path.closeSubpath();
    return path;
}

void repolish(QWidget *w) {
    w->style()->unpolish(w);
    w->style()->polish(w);
    w->update();
}

// Un ícono de línea que cambia de dibujo y de color.
class Glyph final : public QWidget {
  public:
    Glyph(const QString &name, int size, const QColor &color) : name_(name), color_(color) {
        setFixedSize(size, size);
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }
    void set(const QString &name, const QColor &color) {
        name_ = name;
        color_ = color;
        update();
    }

  protected:
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        drawIcon(p, name_, QRectF(rect()), color_);
    }

  private:
    QString name_;
    QColor color_;
};

// Botones de la barra de título: el «?» de How it works (34 x 28) y minimizar, maximizar y cerrar (42 x 40).
class ChromeButton final : public QAbstractButton {
  public:
    explicit ChromeButton(const QString &kind) : kind_(kind) {
        setFocusPolicy(Qt::NoFocus);
        setCursor(Qt::PointingHandCursor);
        setAttribute(Qt::WA_Hover);
        if (kind == "help") setFixedSize(34, 28);
        else setFixedSize(42, 40);
    }
    void setActive(bool on) {
        active_ = on;
        update();
    }

  protected:
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const bool hover = underMouse();
        QColor ink = Theme::color(Theme::kTextCaption);
        if (kind_ == "help") {
            if (active_ || hover) {
                p.setPen(Qt::NoPen);
                p.setBrush(Theme::color(active_ ? Theme::kListSelected : "#1B1B20"));
                p.drawRoundedRect(QRectF(rect()), 6, 6);
            }
            if (active_) ink = Theme::color(Theme::kAccent);
            else if (hover) ink = Theme::color(Theme::kTextStrong);
            drawIcon(p, "help", QRectF((width() - 16) / 2.0, (height() - 16) / 2.0, 16, 16), ink);
            return;
        }
        if (hover) {
            p.fillRect(rect(), QColor(kind_ == "close" ? "#C42B1C" : "#1B1B20"));
            ink = QColor(kind_ == "close" ? "#FFFFFF" : Theme::kTextStrong);
        }
        p.setPen(QPen(ink, 1.2));
        p.setBrush(Qt::NoBrush);
        const QPointF c(width() / 2.0, height() / 2.0);
        if (kind_ == "min") {
            p.drawLine(c + QPointF(-4.5, 0), c + QPointF(4.5, 0));
        } else if (kind_ == "max") {
            p.drawRoundedRect(QRectF(c - QPointF(4.5, 4.5), QSizeF(9, 9)), 1.5, 1.5);
        } else {
            p.drawLine(c + QPointF(-4.5, -4.5), c + QPointF(4.5, 4.5));
            p.drawLine(c + QPointF(4.5, -4.5), c + QPointF(-4.5, 4.5));
        }
    }
    void enterEvent(QEnterEvent *) override { update(); }
    void leaveEvent(QEvent *) override { update(); }

  private:
    QString kind_;
    bool active_ = false;
};

// La línea de 36 de la franja How it works: un botón sin foco con sus piezas adentro.
class StripHeader final : public QAbstractButton {
  public:
    StripHeader() {
        setFocusPolicy(Qt::NoFocus);
        setCursor(Qt::PointingHandCursor);
        setFixedHeight(36);
    }

  protected:
    void paintEvent(QPaintEvent *) override {}
};

// El resaltado de un paso (<b>…</b>) va en el blanco de los títulos.
QString stepHtml(const QString &html) {
    QString out = html;
    out.replace("<b>", QString("<span style=\"color:%1; font-weight:600;\">").arg(Theme::kTextBright));
    out.replace("</b>", "</span>");
    return out;
}
} // namespace

// Fila del índice (`.nrow`): ícono, nombre, línea de estado en color y, a la derecha, el switch de Protection o el
// contador de Requests. La ficha elegida la pinta Desk (unida a la hoja); acá sólo el hover de las otras.
class SideItem final : public QWidget {
  public:
    SideItem(const QString &icon, const QString &title, bool withSwitch, QWidget *parent = nullptr)
        : QWidget(parent), icon_(icon) {
        setFixedHeight(44);
        setCursor(Qt::PointingHandCursor);
        setAttribute(Qt::WA_Hover);
        auto *h = new QHBoxLayout(this);
        h->setContentsMargins(kTabInset + 12 + 20 + 11, 0, 14, 0);
        h->setSpacing(8);
        auto *v = new QVBoxLayout;
        v->setContentsMargins(0, 0, 0, 0);
        v->setSpacing(0);
        title_ = text(title, "sidename");
        title_->setFixedHeight(18);
        status_ = new ElideLabel({}, "sidestatus");
        status_->setFixedHeight(15);
        v->addWidget(title_);
        v->addWidget(status_);
        h->addLayout(v, 1);
        if (withSwitch) {
            switch_ = new ToggleSwitch;
            switch_->setAccessibleName(title);
            h->addWidget(switch_, 0, Qt::AlignVCenter);
        }
        badge_ = new QLabel;
        badge_->setObjectName("fwBadge");
        badge_->setAlignment(Qt::AlignCenter);
        badge_->setFixedHeight(20);
        badge_->setMinimumWidth(20);
        badge_->hide();
        h->addWidget(badge_, 0, Qt::AlignVCenter);
    }
    std::function<void()> onClick;
    ToggleSwitch *toggle() const { return switch_; }
    QRect tabRect() const { return rect().adjusted(kTabInset, 0, 0, 0); }
    void setSelected(bool on) {
        if (selected_ == on) return;
        selected_ = on;
        title_->setProperty("sel", on ? "1" : "");
        repolish(title_);
        update();
    }
    void setState(const QString &status, const QString &tone, int badge = 0) {
        status_->setText(status);
        if (status_->property("tone").toString() != tone) {
            status_->setProperty("tone", tone);
            repolish(status_);
        }
        badge_->setVisible(badge > 0);
        badge_->setText(QString::number(badge));
        badge_->setFixedWidth(qMax(20, badge_->fontMetrics().horizontalAdvance(badge_->text()) + 12));
    }

  protected:
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        if (!selected_ && underMouse()) {
            p.setPen(Qt::NoPen);
            p.setBrush(Theme::color(Theme::kNavHover));
            p.drawRoundedRect(QRectF(tabRect()).adjusted(0, 1, -4, -1), kTabRadius, kTabRadius);
        }
        drawIcon(p, icon_, QRectF(kTabInset + 12, (height() - 20) / 2.0, 20, 20),
                 QColor(selected_ ? Theme::kTextBright : "#CFCDD4"));
    }
    void mouseReleaseEvent(QMouseEvent *e) override {
        if (e->button() == Qt::LeftButton && rect().contains(e->position().toPoint()) && onClick) onClick();
    }
    void enterEvent(QEnterEvent *) override { update(); }
    void leaveEvent(QEvent *) override { update(); }

  private:
    QString icon_;
    bool selected_ = false;
    QLabel *title_ = nullptr, *badge_ = nullptr;
    ElideLabel *status_ = nullptr;
    ToggleSwitch *switch_ = nullptr;
};

// La mesa con la hoja: pinta el fondo, la hoja redondeada y la ficha elegida unida a ella con esquinas cóncavas.
class Desk final : public QWidget {
  public:
    using QWidget::QWidget;
    QRect sheetRect() const {
        return QRect(kNavWidth, kSheetTop, width() - kNavWidth - kSheetMargin, height() - kSheetTop - kSheetMargin);
    }
    void setSelected(SideItem *item) {
        selected_ = item;
        update();
    }

  protected:
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.fillRect(rect(), Theme::color(Theme::kDesk));
        const QRectF sheet = sheetRect();
        QRectF tab;
        if (selected_ && selected_->isVisibleTo(this)) {
            const QRect r = selected_->tabRect();
            tab = QRectF(QRect(selected_->mapTo(this, r.topLeft()), r.size()));
            tab.setRight(sheet.left());
        }
        // La ficha cerca del borde de la hoja: la esquina de la hoja se cuadra y la cóncava se achica, así la unión no
        // deja una muesca de mesa.
        const qreal topRoom = tab.isNull() ? 99 : tab.top() - sheet.top();
        const qreal bottomRoom = tab.isNull() ? 99 : sheet.bottom() - tab.bottom();
        const qreal sheetTopLeft = topRoom >= kSheetRadius + kFillet ? kSheetRadius : 0;
        const qreal sheetBottomLeft = bottomRoom >= kSheetRadius + kFillet ? kSheetRadius : 0;
        QPainterPath shape = roundedRect(sheet, sheetTopLeft, kSheetRadius, kSheetRadius, sheetBottomLeft);
        if (!tab.isNull()) {
            shape = shape.united(roundedRect(tab, kTabRadius, 0, 0, kTabRadius));
            const qreal top = qMin(kFillet, qMax<qreal>(0, topRoom));
            if (top > 0) {
                const QRectF square(tab.right() - top, tab.top() - top, top, top);
                QPainterPath fillet, round;
                fillet.addRect(square);
                round.addEllipse(square.topLeft(), top, top);
                shape = shape.united(fillet.subtracted(round));
            }
            const qreal bottom = qMin(kFillet, qMax<qreal>(0, bottomRoom));
            if (bottom > 0) {
                const QRectF square(tab.right() - bottom, tab.bottom(), bottom, bottom);
                QPainterPath fillet, round;
                fillet.addRect(square);
                round.addEllipse(square.bottomLeft(), bottom, bottom);
                shape = shape.united(fillet.subtracted(round));
            }
        }
        p.setPen(Qt::NoPen);
        p.setBrush(Theme::color(Theme::kSheet));
        p.drawPath(shape);
    }

  private:
    QPointer<SideItem> selected_;
};

// ------------------------------------------------------------------------------------------------------------------

FirewallWindow::FirewallWindow(QWidget *parent) : QMainWindow(parent) {
    setObjectName("GateBouncer");
    setWindowTitle("LGA GateBouncer");
    setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
    setMinimumSize(900, 620);
    resize(tableStore().value("window/size", QSize(1100, 720)).toSize().expandedTo(minimumSize()));
    setStyleSheet(Theme::css(kStyle));
    howOpen_ = rememberSizes() && tableStore().value("window/howItWorks", false).toBool();
    buildShell();
    static_cast<ChromeButton *>(helpButton_.data())->setActive(howOpen_);
    connect(&firewall_, &FirewallClient::changed, this, &FirewallWindow::engineChanged);
    connect(&firewall_, &FirewallClient::changed, this, &FirewallWindow::updateLifecycle);
    // El aviso sigue al motor en cada cambio: pedidos nuevos o resueltos, el nombre del servidor que llega tarde, el
    // motor caído. Después de que el cliente termine de leer: el aviso necesita los datos completos.
    connect(&firewall_, &FirewallClient::changed, this, [this] { QTimer::singleShot(0, this, &FirewallWindow::updateToast); });
    connect(&firewall_, &FirewallClient::commandFinished, this, [this](bool, const QString &t) {
        if (!closing_) message(t);
    });
    connect(&explainer_, &Explain::Explainer::finished, this,
            [this](const QString &id, bool ok, const Explain::Answer &a, const QString &error) {
        if (ok) explainErrors_.remove(id.toLower());
        else explainErrors_.insert(id.toLower(), error);
        ++explainVersion_;
        if (toast_) {
            AccessToast::Explanation e;
            if (ok) e = {AccessToast::Explanation::Ready, a.what, a.why, a.risk, a.suggestion, a.reason, a.model, {}};
            else e = {AccessToast::Explanation::Failed, {}, {}, {}, {}, {}, {}, error};
            toast_->setExplanation(id, e); // el aviso la descarta si ya muestra otro pedido
        }
        engineChanged();
    });
    refreshLater_.setSingleShot(true);
    refreshLater_.setInterval(400);
    connect(&refreshLater_, &QTimer::timeout, this, &FirewallWindow::engineChanged);
    runningTimer_.setInterval(5000);
    connect(&runningTimer_, &QTimer::timeout, this, &FirewallWindow::refreshRunning);
    messageTimer_.setSingleShot(true);
    connect(&messageTimer_, &QTimer::timeout, this, [this] { message_->hide(); });
    firewall_.setActive(true);
    render();
}

FirewallWindow::~FirewallWindow() {
    delete toast_; // ventana propia, sin padre
}

void FirewallWindow::buildShell() {
    auto *root = new QWidget;
    root->setObjectName("fwRoot");
    setCentralWidget(root);
    auto *rl = new QVBoxLayout(root);
    rl->setContentsMargins(0, 0, 0, 0);
    rl->setSpacing(0);

    // Barra de título (`.tb`): 40 de alto sobre la mesa, el logo, el nombre en Bricolage, el «?» que abre How it works
    // y los botones de la ventana.
    auto *bar = new QFrame;
    bar->setObjectName("fwTitle");
    bar->setFixedHeight(40);
    bar->installEventFilter(this);
    auto *bl = new QHBoxLayout(bar);
    bl->setContentsMargins(14, 0, 0, 0);
    bl->setSpacing(0);
    auto *logo = new QLabel;
    logo->setPixmap(QIcon(":/gatebouncer/resources/icons/LGA_GateBouncer.png").pixmap(QSize(22, 22), devicePixelRatio()));
    logo->setAttribute(Qt::WA_TransparentForMouseEvents);
    bl->addWidget(logo);
    bl->addSpacing(10);
    auto *name = text("LGA GateBouncer", "appname");
    name->setAttribute(Qt::WA_TransparentForMouseEvents);
    bl->addWidget(name);
    bl->addStretch();
    auto *help = new ChromeButton("help");
    help->setObjectName("help-window");
    help->setAccessibleName("How it works");
    CustomTooltip::instance()->setToolTip(help, "Opens and closes How it works on every page.");
    helpButton_ = help;
    connect(help, &QAbstractButton::clicked, this, [this] { setHowOpen(!howOpen_); });
    bl->addWidget(help);
    bl->addSpacing(6);
    auto *sep = new QFrame;
    sep->setFixedSize(1, 14);
    sep->setStyleSheet(QString("background: %1;").arg(Theme::kDivider));
    bl->addWidget(sep);
    bl->addSpacing(4);
    const struct { const char *kind, *name, *access; } chrome[] = {
        {"min", "minimize-window", "Minimize"}, {"max", "maximize-window", "Maximize or restore"},
        {"close", "close-window", "Close to the tray"}};
    for (const auto &c : chrome) {
        auto *b = new ChromeButton(c.kind);
        b->setObjectName(c.name);
        b->setAccessibleName(c.access);
        bl->addWidget(b);
        connect(b, &QAbstractButton::clicked, this, [this, kind = QString(c.kind)] {
            if (kind == "min") showMinimized();
            else if (kind == "max") isMaximized() ? showNormal() : showMaximized();
            else close();
        });
    }
    rl->addWidget(bar);

    // La mesa: el índice a la izquierda y la hoja con la página.
    auto *desk = new Desk;
    desk_ = desk;
    auto *sl = new QHBoxLayout(desk);
    sl->setContentsMargins(0, 0, 0, 0);
    sl->setSpacing(0);
    auto *side = new QWidget;
    side->setObjectName("fwSide");
    side->setFixedWidth(kNavWidth);
    auto *sv = new QVBoxLayout(side);
    sv->setContentsMargins(0, kSheetTop, 0, 8);
    sv->setSpacing(0);
    const auto add = [this, sv](const QString &id, const QString &icon, const QString &title, bool withSwitch = false) {
        auto *item = new SideItem(icon, title, withSwitch);
        item->setObjectName("nav-" + id);
        item->onClick = [this, id] { selectView(id); };
        side_.insert(id, item);
        sv->addWidget(item);
        return item;
    };
    const auto label = [sv](const QString &t) {
        auto *l = caps(t, "section");
        l->setFixedHeight(28);
        l->setContentsMargins(24, 11, 0, 0);
        l->setAlignment(Qt::AlignLeft | Qt::AlignTop);
        sv->addWidget(l);
    };
    auto *protection = add("overview", "shield", "Protection", true);
    protection->toggle()->setObjectName("nav-ask-switch");
    // clicked y no toggled: reflejar el estado con setChecked no es un pedido del usuario.
    connect(protection->toggle(), &QAbstractButton::clicked, this, [this](bool on) { firewall_.setAsk(on); });
    label("Firewall");
    add("requests", "bell", "Requests");
    add("apps", "apps", "Apps");
    add("activity", "pulse", "Activity");
    label("App");
    add("settings", "gear", "Settings");
    sv->addStretch();
    sl->addWidget(side);

    workspace_ = new QWidget;
    workspace_->setObjectName("fwWorkspace");
    auto *wl = new QVBoxLayout(workspace_);
    wl->setContentsMargins(0, kSheetTop, kSheetMargin, kSheetMargin);
    wl->setSpacing(0);
    scroll_area_ = new QScrollArea;
    scroll_area_->setObjectName("fwScroll");
    scroll_area_->setWidgetResizable(true);
    scroll_area_->setFrameShape(QFrame::NoFrame);
    scroll_area_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll_area_->viewport()->setAutoFillBackground(false);
    wl->addWidget(scroll_area_, 1);
    message_ = new QFrame;
    message_->setObjectName("fwMessage");
    auto *ml = new QHBoxLayout(message_);
    ml->setContentsMargins(12, 8, 12, 8);
    messageText_ = text({}, "body", true);
    ml->addWidget(messageText_, 1);
    message_->hide();
    auto *mw = new QWidget;
    auto *mwl = new QHBoxLayout(mw);
    mwl->setContentsMargins(28, 0, 28, 14);
    mwl->addWidget(message_);
    wl->addWidget(mw);
    sl->addWidget(workspace_, 1);
    rl->addWidget(desk, 1);
}

// How it works (`.how`): la franja de cada página, cerrada o abierta según el «?» de la barra. Abierta, los pasos
// numerados y una nota; cerrada, cuántos pasos hay.
QWidget *FirewallWindow::how(const QStringList &steps, const QString &note) {
    auto *f = new QFrame;
    f->setObjectName("how-it-works");
    f->setProperty("r", "how");
    f->setProperty("open", howOpen_ ? "1" : "");
    auto *col = new QVBoxLayout(f);
    col->setContentsMargins(1, 1, 1, 1);
    col->setSpacing(0);
    auto *head = new StripHeader;
    head->setObjectName("how-it-works-toggle");
    head->setAccessibleName("How it works");
    auto *hl = new QHBoxLayout(head);
    hl->setContentsMargins(13, 0, 13, 0);
    hl->setSpacing(9);
    hl->addWidget(new Glyph("help", 16, Theme::color(howOpen_ ? Theme::kAccent : Theme::kTextCaption)), 0,
                  Qt::AlignVCenter);
    auto *title = text("How it works", "howtitle");
    title->setAttribute(Qt::WA_TransparentForMouseEvents);
    hl->addWidget(title, 0, Qt::AlignVCenter);
    hl->addStretch();
    if (!howOpen_) {
        auto *count = text(steps.size() == 1 ? QString("1 step") : QString("%1 steps").arg(steps.size()), "faint");
        count->setAttribute(Qt::WA_TransparentForMouseEvents);
        hl->addWidget(count, 0, Qt::AlignVCenter);
    }
    hl->addWidget(new Glyph(howOpen_ ? "chev-up" : "chev-down", 16, Theme::color(Theme::kTextCaption)), 0,
                  Qt::AlignVCenter);
    connect(head, &QAbstractButton::clicked, this, [this] { setHowOpen(!howOpen_); });
    col->addWidget(head);
    if (howOpen_) {
        auto *body = new QWidget;
        auto *bl = new QVBoxLayout(body);
        bl->setContentsMargins(13, 0, 17, 13);
        bl->setSpacing(0);
        for (int i = 0; i < steps.size(); ++i) {
            auto *r = new QHBoxLayout;
            r->setContentsMargins(0, 4, 0, 4);
            r->setSpacing(12);
            auto *n = text(QString::number(i + 1), "hownumber");
            n->setFixedSize(18, 22);
            n->setAlignment(Qt::AlignCenter);
            r->addWidget(n, 0, Qt::AlignTop);
            auto *s = new QLabel(stepHtml(steps[i]));
            s->setProperty("r", "howstep");
            s->setTextFormat(Qt::RichText);
            s->setWordWrap(true);
            r->addWidget(s, 1);
            bl->addLayout(r);
        }
        if (!note.isEmpty()) {
            auto *nb = new QVBoxLayout;
            nb->setContentsMargins(30, 6, 0, 0);
            nb->setSpacing(11);
            nb->addWidget(divider());
            nb->addWidget(text(note, "sub", true));
            bl->addLayout(nb);
        }
        col->addWidget(body);
    }
    return f;
}

void FirewallWindow::setHowOpen(bool open) {
    howOpen_ = open;
    if (rememberSizes()) tableStore().setValue("window/howItWorks", open);
    if (auto *b = static_cast<ChromeButton *>(helpButton_.data())) b->setActive(open);
    render(true);
}

void FirewallWindow::selectView(const QString &view) {
    static const QStringList known{"overview", "requests", "apps", "activity", "settings", "import",
                                   // nombres de la ventana vieja, para la bandeja y la QA
                                   "pending", "rules", "processes"};
    if (!known.contains(view) && !view.startsWith("detail:")) return;
    view_ = view == "pending" ? "requests" : view == "rules" || view == "processes" ? "apps" : view;
    render();
}

bool FirewallWindow::armed() const { return QDateTime::currentMSecsSinceEpoch() >= armedAt_; }

bool FirewallWindow::canDecide() const {
    const auto &s = firewall_.status();
    return s.connected && s.control && !firewall_.busy();
}

// ------------------------------------------------------------------------------------------------------------------
// Rearmado: la página se rehace sólo si cambió lo que muestra, para no perder lo elegido ni el desplazamiento.

QString FirewallWindow::pageKey() const {
    const auto &s = firewall_.status();
    QString key = QString("%1|%2%3%4%5%6|").arg(view_).arg(s.connected).arg(s.ask).arg(s.allApps).arg(s.control)
                      .arg(s.localNetwork);
    key += QString::number(firewall_.busy()) + "|"; // los botones se habilitan de nuevo al terminar un comando
    const auto pendingKey = [this] {
        QString k;
        for (const auto &p : firewall_.pending()) k += p.id + p.host + QString::number(p.attempts) + ";";
        return k;
    };
    const auto rulesKey = [this] {
        QString k;
        for (const auto &r : firewall_.rules())
            k += r.id + r.path + r.destination + QString::number(r.allow) + QString::number(r.expires) +
                 QString::number(r.lastBlock) + ";";
        return k;
    };
    if (view_ == "overview") {
        key += pendingKey() + "|" + rulesKey() + "|" + QString::number(explainVersion_) + "|";
        const auto &a = firewall_.activity();
        if (!a.isEmpty()) key += QString::number(a.size()) + QString::number(a.last().time);
    } else if (view_ == "requests") {
        key += pendingKey() + "|" + QString::number(explainVersion_) + "|" + expanded_;
    } else if (view_ == "apps" || view_.startsWith("detail:")) {
        key += rulesKey() + "|" + running_.join(';');
    } else if (view_ == "activity") {
        const auto &a = firewall_.activity();
        key += QString::number(a.size()) + (a.isEmpty() ? QString() : QString::number(a.last().time)) + activityFilter_;
    } else if (view_ == "import") {
        key += rulesKey() + netLimiterFile_;
    }
    return key;
}

void FirewallWindow::engineChanged() {
    updateSidebar();
    if (closing_) return;
    // Con un desplegable abierto no se rearma la página: se cerraría bajo el puntero. Se reintenta al rato.
    if (QApplication::activePopupWidget()) {
        if (!refreshLater_.isActive()) refreshLater_.start();
        return;
    }
    const QString key = pageKey();
    if (key == lastKey_) return;
    if (view_ == "apps" && appsTable_) {
        lastKey_ = key;
        fillApps();
        return;
    }
    render(true);
}

void FirewallWindow::render(bool keepScroll) {
    if (auto *current = scroll_area_->widget()) {
        const QString shownView = lastKey_.section('|', 0, 0);
        scroll_[shownView] = scroll_area_->verticalScrollBar()->value();
        if (auto *table = current->findChild<QTableWidget *>("fwTable"))
            tableScroll_[shownView] = table->verticalScrollBar()->value();
    }
    const int scroll = keepScroll ? scroll_area_->verticalScrollBar()->value() : scroll_.value(view_, 0);
    appsTable_ = nullptr;
    appsTip_ = nullptr;
    appsSeg_ = nullptr;
    // Apps y Activity son una tabla que llena la página: arriba todo queda fijo y sólo se desplazan sus filas.
    const bool tableView = view_ == "apps" || view_ == "activity";
    scroll_area_->setVerticalScrollBarPolicy(tableView ? Qt::ScrollBarAlwaysOff : Qt::ScrollBarAsNeeded);
    // La fila que sube bajo el puntero al decidir otra no recibe el clic siguiente: un instante sin decidir.
    if (view_ == "overview" || view_ == "requests" || view_ == "apps") armedAt_ = QDateTime::currentMSecsSinceEpoch() + 600;
    QWidget *page = view_ == "requests"           ? requestsPage()
                    : view_ == "apps"             ? appsPage()
                    : view_.startsWith("detail:") ? detailPage(view_.mid(7))
                    : view_ == "activity"         ? activityPage()
                    : view_ == "settings"         ? settingsPage()
                    : view_ == "import"           ? importPage()
                                                  : overviewPage();
    page->setObjectName("fwPage");
    auto *old = scroll_area_->takeWidget();
    scroll_area_->setWidget(page);
    if (old) old->deleteLater();
    lastKey_ = pageKey();
    if (view_ == "apps") {
        refreshRunning();
        runningTimer_.start();
    } else {
        runningTimer_.stop();
    }
    updateSidebar();
    QPointer<QTableWidget> table = page->findChild<QTableWidget *>("fwTable");
    QTimer::singleShot(0, this, [this, scroll, table, tableScrolled = tableScroll_.value(view_)] {
        scroll_area_->verticalScrollBar()->setValue(scroll);
        if (table) table->verticalScrollBar()->setValue(tableScrolled);
    });
}

void FirewallWindow::updateSidebar() {
    const auto &s = firewall_.status();
    const QString sel = view_.startsWith("detail:") ? "apps" : view_ == "import" ? "settings" : view_;
    for (auto it = side_.begin(); it != side_.end(); ++it) it.value()->setSelected(it.key() == sel);
    if (desk_) desk_->setSelected(side_.value(sel));
    // El switch de Protection en el índice: preguntar antes de conectar. Refleja al motor, no decide solo.
    if (auto *ask = side_["overview"]->toggle()) {
        if (ask->isChecked() != (s.connected && s.ask)) ask->setChecked(s.connected && s.ask);
        ask->setEnabled(canDecide());
    }
    if (!s.connected) side_["overview"]->setState("Engine not running", "bad");
    else if (!s.ask) side_["overview"]->setState("On · not asking", "warn");
    else if (!s.allApps) side_["overview"]->setState("Test session", "warn");
    else side_["overview"]->setState("On · asking first", "ok");
    const auto &pending = firewall_.pending();
    qint64 oldest = 0;
    for (const auto &p : pending) if (!oldest || p.first < oldest) oldest = p.first;
    side_["requests"]->setState(pending.isEmpty() ? QString("Nothing waiting") : "Oldest " + clock(oldest),
                                pending.isEmpty() ? QString() : QString("warn"), int(pending.size()));
    // Igual que la lista de Apps: una fila por app, aunque tenga varias reglas por servidor.
    const auto entries = appEntries();
    int temporary = 0;
    for (const auto &e : entries)
        for (const auto &r : e.rules)
            if (r.expires != 0) {
                ++temporary;
                break;
            }
    const QString apps = entries.size() == 1 ? QString("1 app") : QString("%1 apps").arg(entries.size());
    side_["apps"]->setState(temporary ? QString("%1 · %2 temporary").arg(apps).arg(temporary) : apps, {});
    int blocked = 0;
    for (const auto &a : firewall_.activity()) blocked += a.kind.startsWith("Blocked");
    side_["activity"]->setState(s.started ? QString("%1 blocked since %2").arg(blocked).arg(clock(s.started))
                                          : QString("%1 blocked").arg(blocked),
                                {});
    const auto settings = Explain::Settings::load();
    const bool ai = Explain::KeyStore::has(Explain::providerOf(settings.model)) && settings.consent;
    side_["settings"]->setState(ai ? "AI: " + settings.model : QString("AI explanations off"), {});
}

void FirewallWindow::message(const QString &value) {
    if (value.isEmpty()) return;
    messageText_->setText(value);
    message_->show();
    messageTimer_.start(5000);
}

void FirewallWindow::trustFolderDialog(const QString &folder, const QString &name) {
    auto *d = new QDialog(this, Qt::Dialog | Qt::FramelessWindowHint);
    d->setObjectName("trust-folder-dialog");
    d->setAttribute(Qt::WA_DeleteOnClose);
    d->setStyleSheet("QDialog { background: #17171B; border: 1px solid #2E2E36; }");
    constexpr int Wide = 470;
    auto *l = column(d, 18, 8);
    l->addWidget(text("Trust a folder", "cardtitle"));
    auto *intro = text("The rule covers one program name, or every program, inside the folder and its subfolders, also "
                       "builds made or copied there later. A rule for a file, an app or a publisher comes first. Trust "
                       "only folders where you build or install programs yourself: whatever is saved there with that "
                       "name gets the same access.",
                       "sub", true);
    intro->setFixedWidth(Wide);
    l->addWidget(intro);
    l->addSpacing(6);
    l->addWidget(text("Folder", "colhead"));
    auto *fr = row(8);
    auto *path = new QLineEdit(QDir::toNativeSeparators(folder));
    path->setObjectName("trust-folder-path");
    path->setPlaceholderText("C:\\Projects\\MyApp");
    fr->addWidget(path, 1);
    auto *browse = button("Browse…");
    browse->setObjectName("trust-folder-browse");
    fr->addWidget(browse);
    l->addLayout(fr);
    auto *status = text({}, "sub", true);
    status->setObjectName("trust-folder-status");
    status->setFixedWidth(Wide);
    l->addWidget(status);
    l->addSpacing(6);
    l->addWidget(text("Program name (optional)", "colhead"));
    auto *program = new QLineEdit(name);
    program->setObjectName("trust-folder-name");
    program->setPlaceholderText("Every program, or one name such as MyApp.exe");
    l->addWidget(program);
    l->addSpacing(10);
    auto *buttons = row(8);
    buttons->addStretch();
    auto *cancel = button("Cancel");
    cancel->setObjectName("trust-folder-cancel");
    auto *block = button("Block", "block");
    block->setObjectName("trust-folder-block");
    auto *allow = button("Allow", "allow");
    allow->setObjectName("trust-folder-allow");
    for (auto *b : {cancel, block, allow}) {
        b->setMinimumWidth(84);
        buttons->addWidget(b);
    }
    l->addLayout(buttons);

    // Lo validado: la carpeta por su ruta final y el nombre en minúsculas, o vacío si todavía no se puede crear.
    auto resolved = std::make_shared<QPair<QString, QString>>();
    const auto check = [this, path, program, status, block, allow, resolved] {
        gbe::FinalPath place;
        std::wstring exe;
        const QString typed = path->text().trimmed();
        const QString problem =
            typed.isEmpty() ? QString() : QString::fromStdWString(gbe::resolveTrustedFolder(typed.toStdWString(), place));
        const bool nameOk = gbe::normalizeFolderRuleName(program->text().toStdWString(), exe);
        QString message, tone = "sub";
        if (typed.isEmpty()) {
            message = "Choose the folder of a project or an app.";
        } else if (!problem.isEmpty()) {
            message = problem;
            tone = "bad";
        } else if (!nameOk) {
            message = "Use a file name such as MyApp.exe, or leave it empty for every program.";
            tone = "bad";
        } else {
            const QString where = QString::fromStdWString(place.dos);
            message = (exe.empty() ? QStringLiteral("✓ Every program in ") : "✓ " + program->text().trimmed() + " in ") +
                      where + " and its subfolders.";
            tone = "ok";
            // El nombre como se escribió, para el mensaje («DayTrace.exe»): el motor lo pasa a minúsculas.
            *resolved = {where, exe.empty() ? QString() : program->text().trimmed()};
        }
        if (tone != "ok") *resolved = {};
        status->setText(message);
        status->setProperty("r", tone);
        status->style()->unpolish(status);
        status->style()->polish(status);
        block->setEnabled(canDecide() && !resolved->first.isEmpty());
        allow->setEnabled(canDecide() && !resolved->first.isEmpty());
    };
    // Validar lee el disco y el registro: se espera a que se deje de escribir.
    auto *later = new QTimer(d);
    later->setSingleShot(true);
    later->setInterval(250);
    connect(later, &QTimer::timeout, d, check);
    connect(path, &QLineEdit::textChanged, later, qOverload<>(&QTimer::start));
    connect(program, &QLineEdit::textChanged, later, qOverload<>(&QTimer::start));
    check();
    connect(browse, &QPushButton::clicked, d, [d, path] {
        auto *dialog = new QFileDialog(d, "Choose the folder to trust", path->text().trimmed());
        dialog->setObjectName("trust-folder-picker");
        dialog->setOption(QFileDialog::DontUseNativeDialog);
        dialog->setOption(QFileDialog::ShowDirsOnly);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setFileMode(QFileDialog::Directory);
        connect(dialog, &QFileDialog::fileSelected, path,
                [path](const QString &chosen) { path->setText(QDir::toNativeSeparators(chosen)); });
        dialog->open();
    });
    connect(cancel, &QPushButton::clicked, d, &QDialog::close);
    for (auto *b : {block, allow})
        connect(b, &QPushButton::clicked, d, [this, d, later, check, resolved, allowed = b == allow] {
            // Lo que se ve es lo que se manda: si había una validación pendiente, se hace ya.
            if (later->isActive()) {
                later->stop();
                check();
            }
            if (resolved->first.isEmpty()) return;
            firewall_.trustFolder(resolved->first, resolved->second, allowed);
            d->close();
        });
    d->open();
}

// ------------------------------------------------------------------------------------------------------------------
// Protection: el estado, lo que espera decisión y un resumen.

QWidget *FirewallWindow::overviewPage() {
    const auto &s = firewall_.status();
    auto *page = new QWidget;
    auto *l = column(page, 28, 12);
    l->setContentsMargins(28, 24, 28, 28);
    // El switch grande del encabezado es el de Settings: preguntar antes de que una app desconocida conecte.
    auto *askSwitch = new ToggleSwitch;
    askSwitch->setLarge(true);
    askSwitch->setObjectName("protection-ask");
    askSwitch->setAccessibleName("Ask before unknown applications connect");
    askSwitch->setChecked(s.connected && s.ask);
    askSwitch->setEnabled(canDecide());
    connect(askSwitch, &QAbstractButton::clicked, this, [this](bool on) { firewall_.setAsk(on); });
    l->addWidget(header("Protection",
                        !s.connected ? "Without the engine, new applications cannot ask for access."
                        : s.ask      ? "Unknown applications are blocked until you decide."
                                     : "Unknown applications connect. Saved rules still apply.",
                        askSwitch));

    // Estado en vivo (`.live`): el punto de color, qué pasa y una acción.
    auto *status = new QWidget;
    status->setObjectName("protection-status");
    auto *sh = new QHBoxLayout(status);
    sh->setContentsMargins(0, 4, 0, 0);
    sh->setSpacing(9);
    auto *dot = new QLabel;
    dot->setFixedSize(8, 8);
    const char *tone = !s.connected ? Theme::kError : (s.ask && s.allApps) ? Theme::kOk : Theme::kWarn;
    dot->setStyleSheet(QString("background: %1; border-radius: 4px;").arg(tone));
    sh->addWidget(dot, 0, Qt::AlignVCenter);
    sh->addSpacing(3);
    auto *st = new QVBoxLayout;
    st->setSpacing(1);
    QString title, sub;
    if (!s.connected) {
        title = "The GateBouncer engine is not running";
        sub = "Saved rules and the block on unknown applications still apply, but nothing can ask you. Restart Windows "
              "or run the installer again.";
    } else if (!s.ask) {
        title = "Unknown applications can connect";
        sub = "Asking is off. Saved Allow and Block rules still apply.";
    } else if (!s.allApps) {
        title = "Test session";
        sub = "Only the selected test applications ask before connecting. Rules disappear when the engine stops.";
    } else {
        title = "GateBouncer is protecting this PC";
        QStringList parts;
        if (s.started) parts << "Engine running since " + clock(s.started);
        parts << (s.localNetwork ? "local network connects without asking" : "local network asks first");
        if (!s.control) parts << "view only";
        sub = parts.join(" · ");
    }
    auto *stt = text(title, "strong");
    stt->setStyleSheet(QString("color: %1; font-weight: 600;").arg(Theme::kTextBright));
    st->addWidget(stt);
    st->addWidget(text(sub, "sub", true));
    sh->addLayout(st, 1);
    if (s.connected && !s.ask) {
        auto *on = button("Turn asking on", "primary");
        on->setEnabled(canDecide());
        connect(on, &QPushButton::clicked, this, [this] { firewall_.setAsk(true); });
        sh->addWidget(on, 0, Qt::AlignVCenter);
    } else if (s.connected) {
        auto *go = button("Firewall settings");
        go->setObjectName("open-settings");
        connect(go, &QPushButton::clicked, this, [this] { selectView("settings"); });
        sh->addWidget(go, 0, Qt::AlignVCenter);
    }
    l->addWidget(status);
    l->addSpacing(2);
    l->addWidget(how({"GateBouncer blocks any program that has no rule and asks you in a notice.",
                      "Choose <b>Allow</b> or <b>Block</b> there, or later in <b>Requests</b>.",
                      "The first attempt of a program fails; <b>Allow</b> lets its next attempt connect."},
                     "A program with a rule never asks again. The engine is a Windows service: closing this window "
                     "keeps the firewall working. Turn the switch off to let everything without a rule connect; Block "
                     "rules still apply."));

    if (s.connected) {
        auto pending = firewall_.pending();
        std::sort(pending.begin(), pending.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
        auto *wait = card(pending.isEmpty() ? "card" : "alert");
        auto *wl = cardColumn(wait, 0);
        auto *wh = row(10);
        wh->addWidget(text("Waiting for you", "cardtitle"));
        if (!pending.isEmpty()) wh->addWidget(chip(QString("%1 waiting").arg(pending.size()), "warn"));
        wh->addStretch();
        if (!pending.isEmpty()) {
            auto *all = button("Open Requests", "link");
            all->setObjectName("review-all");
            connect(all, &QPushButton::clicked, this, [this] { selectView("requests"); });
            wh->addWidget(all);
        }
        wl->addLayout(wh);
        if (pending.isEmpty()) {
            wl->addSpacing(6);
            wl->addWidget(text("Nothing is waiting. A new application that tries to connect appears here and in a "
                               "notice.",
                               "sub", true));
        } else {
            wl->addSpacing(8);
        }
        const int shown = qMin<int>(4, pending.size());
        for (int i = 0; i < shown; ++i) {
            const auto p = pending[i];
            wl->addWidget(divider());
            auto *item = new QWidget;
            item->setMinimumHeight(54);
            auto *h = new QHBoxLayout(item);
            h->setContentsMargins(0, 10, 0, 10);
            h->setSpacing(12);
            h->addWidget(appIcon(p.path));
            auto *info = new QVBoxLayout;
            info->setSpacing(2);
            info->addWidget(new ElideLabel(FirewallClient::fileName(p.path), "strong"));
            const QString target = p.host.isEmpty() ? p.remote : p.host;
            info->addWidget(new ElideLabel("Wants " + target + " · first try " + clock(p.first), "small"));
            h->addLayout(info, 1);
            const auto e = explanationFor(p.id);
            // Lo revisado (catálogo o app LGA) va antes que la explicación con IA.
            const QString known = KnownApps::hint(p.signer, p.path, p.host);
            if (!known.isEmpty())
                h->addWidget(hint(known.section(" · ", 0, 1), "known"));
            else if (e.state == AccessToast::Explanation::Ready)
                h->addWidget(e.suggestion == "block"   ? hint("AI suggests Block", "block")
                             : e.suggestion == "allow" ? hint("AI suggests Allow", "allow")
                                                       : hint("AI: your call", "either"));
            else
                h->addWidget(hint(e.state == AccessToast::Explanation::Working ? "Asking AI…" : "Not explained yet",
                                  "none"));
            auto *block = decision("Block", "block");
            auto *allow = decision("Allow", "allow");
            block->setObjectName("overview-block");
            allow->setObjectName("overview-allow");
            recommend(block, allow, known);
            block->setEnabled(canDecide());
            allow->setEnabled(canDecide());
            connect(block, &QPushButton::clicked, this, [this, p] { decideDefault(p, false); });
            connect(allow, &QPushButton::clicked, this, [this, p] { decideDefault(p, true); });
            h->addWidget(block);
            h->addWidget(allow);
            wl->addWidget(item);
        }
        if (!pending.isEmpty()) {
            wl->addWidget(divider());
            wl->addSpacing(10);
            const QString em = QString("<span style='color:%1;font-weight:500'>").arg(Theme::kTextStrong);
            auto *tip = new QLabel("Block and Allow here use the choices the notice would preselect: " + em +
                                   "this app, any version</span> when it is signed, " + em +
                                   "this app in its repository</span> for an unsigned build inside a Git repository, " +
                                   em + "this file</span> otherwise, and " + em +
                                   "only that server</span> for an app that already has server rules. Open the "
                                   "request to choose another.");
            tip->setProperty("r", "faint");
            tip->setWordWrap(true);
            wl->addWidget(tip);
        }
        l->addWidget(wait);
    }

    auto *grid = new QHBoxLayout;
    grid->setSpacing(12);
    {
        auto *rc = card();
        auto *rl = cardColumn(rc, 0);
        auto *rh = row();
        rh->addWidget(text("Rules", "cardtitle"));
        rh->addStretch();
        auto *open = button("Open Apps", "link");
        connect(open, &QPushButton::clicked, this, [this] { selectView("apps"); });
        rh->addWidget(open);
        rl->addLayout(rh);
        int allow = 0, block = 0, temporary = 0, perServer = 0;
        const FirewallClient::RuleItem *soonest = nullptr;
        for (const auto &r : firewall_.rules()) {
            if (r.scope == "covered") continue;
            if (!r.destination.isEmpty()) ++perServer;
            if (r.expires != 0) {
                ++temporary;
                if (r.expires > 0 && (!soonest || soonest->expires < 0 || r.expires < soonest->expires)) soonest = &r;
                else if (!soonest) soonest = &r;
            } else {
                r.allow ? ++allow : ++block;
            }
        }
        rl->addSpacing(10);
        auto *stats = row(26);
        for (const auto &[n, name] : {std::pair{allow, "allow"}, {block, "block"}, {temporary, "temporary"}}) {
            auto *sv = new QVBoxLayout;
            sv->setSpacing(0);
            auto *num = text(QString::number(n), "stat");
            num->setFont(Theme::titleFont(30, 800));
            sv->addWidget(num);
            sv->addWidget(text(name, "sub"));
            stats->addLayout(sv);
        }
        stats->addStretch();
        rl->addLayout(stats);
        rl->addSpacing(12);
        if (soonest) {
            const QString who = soonest->scope == "app"         ? soonest->name
                                : soonest->scope == "publisher" ? "Apps from " + soonest->signer
                                : soonest->scope == "folder"
                                    ? (soonest->name.isEmpty() ? QStringLiteral("Apps") : soonest->name) + " in " +
                                          FolderTrust::label(soonest->path)
                                    : FirewallClient::fileName(soonest->path);
            rl->addWidget(text(QString("%1 can %2 %3.")
                                   .arg(who, soonest->allow ? "connect" : "stay blocked",
                                        soonest->expires < 0 ? QString("until restart")
                                                             : "until " + clock(soonest->expires)),
                               "sub", true));
        } else if (perServer) {
            rl->addWidget(text(perServer == 1 ? QString("1 of them only for one server.")
                                              : QString("%1 of them only for one server.").arg(perServer),
                               "sub", true));
        }
        rl->addStretch();
        grid->addWidget(rc, 4);
    }
    {
        auto *ac = card();
        auto *al = cardColumn(ac, 0);
        auto *ah = row();
        ah->addWidget(text("Blocked recently", "cardtitle"));
        ah->addStretch();
        auto *open = button("Activity", "link");
        connect(open, &QPushButton::clicked, this, [this] { selectView("activity"); });
        ah->addWidget(open);
        al->addLayout(ah);
        al->addSpacing(8);
        int shown = 0;
        QSet<QString> listed; // una fila por app: los reintentos de la misma no tapan a las demás
        const auto &events = firewall_.activity();
        const auto reasons = blockReasons(events, firewall_.pending());
        for (int i = events.size() - 1; i >= 0 && shown < 3; --i) {
            const auto &e = events[i];
            if (!e.kind.startsWith("Blocked") || e.path.isEmpty() || listed.contains(e.path.toLower())) continue;
            listed.insert(e.path.toLower());
            al->addWidget(divider());
            auto *h = new QWidget;
            h->setMinimumHeight(32);
            auto *hl = new QHBoxLayout(h);
            hl->setContentsMargins(0, 7, 0, 7);
            hl->setSpacing(10);
            auto *t = text(clock(e.time), "time");
            t->setFixedWidth(40);
            hl->addWidget(t);
            auto *what = new ElideLabel(FirewallClient::fileName(e.path) + "  ·  " + reasons[i].text.toLower(), "value");
            hl->addWidget(what, 1);
            al->addWidget(h);
            ++shown;
        }
        if (!shown) al->addWidget(text("Nothing blocked since the engine started.", "sub", true));
        al->addStretch();
        grid->addWidget(ac, 5);
    }
    l->addLayout(grid);
    l->addStretch();
    return page;
}

// ------------------------------------------------------------------------------------------------------------------
// Requests: cada pedido con su explicación y las mismas opciones del aviso.

AccessToast::Explanation FirewallWindow::explanationFor(const QString &id) const {
    AccessToast::Explanation e;
    const auto settings = Explain::Settings::load();
    if (!Explain::qaFixture() && (!Explain::KeyStore::has(Explain::providerOf(settings.model)) || !settings.consent)) {
        e.state = AccessToast::Explanation::NoKey;
    } else if (const auto *hit = explainer_.cached(id)) {
        e = {AccessToast::Explanation::Ready, hit->what, hit->why, hit->risk, hit->suggestion, hit->reason, hit->model, {}};
    } else if (explainer_.busy(id)) {
        e.state = AccessToast::Explanation::Working;
    } else if (explainErrors_.contains(id.toLower())) {
        e.state = AccessToast::Explanation::Failed;
        e.error = explainErrors_.value(id.toLower());
    }
    return e;
}

QString FirewallWindow::launchedBy(const FirewallClient::PendingItem &p) {
    const QString key = p.id.toLower();
    if (!launchers_.contains(key))
        launchers_.insert(key, Explain::collectFacts(p.path, p.signer, p.remote, p.port, p.protocol, p.attempts, p.host)
                                   .launchedBy);
    return launchers_.value(key);
}

QWidget *FirewallWindow::aiCard(const FirewallClient::PendingItem &p) {
    const auto e = explanationFor(p.id);
    const bool ready = e.state == AccessToast::Explanation::Ready;
    auto *c = card(e.state == AccessToast::Explanation::Failed ? "aierr"
                   : ready || e.state == AccessToast::Explanation::Working ? "ai"
                                                                            : "aiquiet");
    auto *l = new QVBoxLayout(c);
    l->setContentsMargins(12, 11, 12, 11);
    l->setSpacing(8);
    const QString known = KnownApps::hint(p.signer, p.path, p.host);
    if (!known.isEmpty()) {
        auto *k = row();
        k->addWidget(hint(known.section(" · ", 0, 1), "known"));
        k->addStretch();
        l->addLayout(k);
        if (known.count(" · ") >= 2) l->addWidget(text(known.section(" · ", 2), "body", true));
    }
    const QString model = Explain::Settings::load().model;
    if (ready) {
        auto *h = row(8);
        h->addWidget(e.suggestion == "block"   ? hint("AI suggests Block", "block")
                     : e.suggestion == "allow" ? hint("AI suggests Allow", "allow")
                                               : hint("AI: your call", "either"));
        h->addStretch();
        l->addLayout(h);
        auto *what = text(e.what, "value", true);
        l->addWidget(what);
        l->addWidget(divider());
        for (const auto &[title, value] : {std::pair{QString("WHY IT CONNECTS"), e.why},
                                           {QString("WHY THIS SUGGESTION"), e.reason},
                                           {QString("IS IT GENUINE"), e.risk}}) {
            if (value.isEmpty()) continue;
            auto *t = caps(title);
            l->addWidget(t);
            auto *v = text(value, "body", true);
            l->addWidget(v);
        }
        l->addWidget(text("AI explanation · " + (e.model.isEmpty() ? model : e.model) +
                              " · may be wrong and never decides for you",
                          "faint", true));
    } else if (e.state == AccessToast::Explanation::Working) {
        l->addWidget(text("Asking " + model + " what this is…", "body"));
        l->addWidget(text("You can decide now; the answer never holds the request.", "colhead"));
    } else if (e.state == AccessToast::Explanation::NoKey) {
        auto *h = row();
        h->addWidget(text("Explanations are off.", "sub"));
        h->addStretch();
        auto *go = button("Set up in Settings", "link");
        connect(go, &QPushButton::clicked, this, [this] { selectView("settings"); });
        h->addWidget(go);
        l->addLayout(h);
    } else {
        auto *h = row();
        h->addWidget(text(e.state == AccessToast::Explanation::Failed ? "The explanation did not arrive."
                                                                      : "What is this program?",
                          e.state == AccessToast::Explanation::Failed ? "bad" : "sub"));
        h->addStretch();
        auto *ask = button(e.state == AccessToast::Explanation::Failed ? "Try again" : "Ask AI", nullptr, true);
        ask->setObjectName("request-ask-ai");
        connect(ask, &QPushButton::clicked, this, [this, id = p.id] { explain(id, false); });
        h->addWidget(ask);
        l->addLayout(h);
        if (!e.error.isEmpty()) l->addWidget(text(e.error, "colhead", true));
    }
    return c;
}

QWidget *FirewallWindow::requestCard(const FirewallClient::PendingItem &p, bool expanded) {
    auto *c = card();
    c->setObjectName("request-card");
    auto *cl = new QVBoxLayout(c);
    cl->setContentsMargins(0, 0, 0, 0);
    cl->setSpacing(0);
    auto *top = new QWidget;
    auto *th = new QHBoxLayout(top);
    th->setContentsMargins(18, expanded ? 14 : 12, 18, expanded ? 14 : 12);
    th->setSpacing(12);
    th->addWidget(appIcon(p.path, 36));
    auto *info = new QVBoxLayout;
    info->setSpacing(2);
    auto *name = new ElideLabel(FirewallClient::fileName(p.path), "cardtitle");
    name->setFont(Theme::titleFont(16, 700));
    info->addWidget(name);
    const QString signature =
        p.signer.isEmpty()
            ? QString("<span style='color:%1;font-weight:500'>Not signed</span>").arg(Theme::kWarn)
            : QString("<span style='color:%1;font-weight:500'>%2</span>").arg(Theme::kOk, p.signer.toHtmlEscaped());
    // La firma en color y, recortados al medio si no entran, la carpeta y los intentos (una sola línea).
    auto *metaRow = row(0);
    auto *signed_ = new QLabel(signature + " · ");
    signed_->setProperty("r", "small");
    metaRow->addWidget(signed_);
    metaRow->addWidget(new ElideLabel(QDir::toNativeSeparators(QFileInfo(p.path).path()) + " · " +
                                          (p.attempts == 1 ? QString("1 attempt") : QString("%1 attempts").arg(p.attempts)) +
                                          " since " + clock(p.first),
                                      "small", Qt::ElideMiddle),
                       1);
    info->addLayout(metaRow);
    th->addLayout(info, 1);
    const QString known = KnownApps::hint(p.signer, p.path, p.host);
    if (!expanded) {
        const auto e = explanationFor(p.id);
        if (!known.isEmpty()) th->addWidget(hint(known.section(" · ", 0, 1), "known"));
        if (e.state == AccessToast::Explanation::Ready)
            th->addWidget(e.suggestion == "block"   ? hint("AI suggests Block", "block")
                          : e.suggestion == "allow" ? hint("AI suggests Allow", "allow")
                                                    : hint("AI: your call", "either"));
        auto *open = decision("Review", nullptr);
        open->setObjectName("request-open");
        connect(open, &QPushButton::clicked, this, [this, id = p.id] {
            expanded_ = id;
            render(true);
        });
        th->addWidget(open);
        auto *block = decision("Block", "block");
        auto *allow = decision("Allow", "allow");
        recommend(block, allow, known);
        block->setEnabled(canDecide());
        allow->setEnabled(canDecide());
        connect(block, &QPushButton::clicked, this, [this, p] { decideDefault(p, false); });
        connect(allow, &QPushButton::clicked, this, [this, p] { decideDefault(p, true); });
        th->addWidget(block);
        th->addWidget(allow);
    }
    cl->addWidget(top);
    if (!expanded) return c;

    cl->addWidget(divider());
    auto *body = new QWidget;
    auto *bh = new QHBoxLayout(body);
    bh->setContentsMargins(18, 14, 18, 16);
    bh->setSpacing(20);
    auto *leftCol = new QVBoxLayout;
    leftCol->setSpacing(12);
    if (p.perDestination) {
        auto *n = text("This app already has rules for other servers: Allow or Block applies to this server only. "
                       "Choose Any destination (whole app) to replace its server rules.",
                       "info", true);
        leftCol->addWidget(n);
    }
    if (p.signer.isEmpty()) {
        const bool repository = FolderTrust::isFolderScope(scopeOptions(p).first().second);
        auto *n = text(repository ? "No signature: the rule can't follow a publisher, only this file or this app's name "
                                    "inside its repository."
                                  : "No signature: a rule can only cover this exact file. If the file changes, it asks "
                                    "again.",
                       "note", true);
        leftCol->addWidget(n);
    }
    auto *facts = new QGridLayout;
    facts->setHorizontalSpacing(10);
    facts->setVerticalSpacing(7);
    facts->setColumnMinimumWidth(0, 76);
    facts->setColumnStretch(1, 1);
    int r = 0;
    const auto fact = [&](const QString &name, QWidget *value) {
        auto *n = text(name, "faint");
        n->setStyleSheet("font-size: 13px;");
        facts->addWidget(n, r, 0, Qt::AlignTop);
        facts->addWidget(value, r++, 1);
    };
    auto *wants = new QWidget;
    auto *wv = new QVBoxLayout(wants);
    wv->setContentsMargins(0, 0, 0, 0);
    wv->setSpacing(1);
    auto *target = text(p.host.isEmpty() ? p.remote : p.host, "value", true);
    target->setTextInteractionFlags(Qt::TextSelectableByMouse);
    wv->addWidget(target);
    wv->addWidget(text(destinationLine(p), "faint"));
    fact("Wants", wants);
    const QString parent = launchedBy(p);
    if (!parent.isEmpty()) fact("Started by", text(parent, "value", true));
    leftCol->addLayout(facts);
    leftCol->addWidget(aiCard(p));
    leftCol->addStretch();
    bh->addLayout(leftCol, 1);

    // La regla (`.rulegrid`): «Apply to» a todo el ancho; «For» y «Destination» a medias debajo. Los botones, al pie.
    auto *rightCol = new QVBoxLayout;
    rightCol->setContentsMargins(0, 0, 0, 0);
    rightCol->setSpacing(0);
    auto *grid = new QGridLayout;
    grid->setHorizontalSpacing(8);
    grid->setVerticalSpacing(4);
    grid->setColumnStretch(0, 1);
    grid->setColumnStretch(1, 1);
    auto &choice = choices_[p.id.toLower()];
    const auto addCombo = [&](const QString &label, const QVector<QPair<QString, QString>> &options, QString &value,
                              const char *name, int gridRow, int gridCol, int span) -> Combo * {
        grid->addWidget(text(label, "colhead"), gridRow, gridCol, 1, span);
        auto *combo = new Combo;
        combo->setObjectName(name);
        combo->setAccessibleName(label);
        combo->setMinimumWidth(60);
        combo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
        for (const auto &[t, d] : options) combo->addItem(t, d);
        const int keep = choice.set ? combo->findData(value) : -1;
        combo->setCurrentIndex(keep >= 0 ? keep : 0);
        value = combo->currentData().toString();
        combo->setEnabled(canDecide() && combo->count() > 1);
        connect(combo, &QComboBox::currentIndexChanged, this, [this, combo, id = p.id.toLower(), name] {
            auto &c = choices_[id];
            const QString v = combo->currentData().toString();
            if (QString(name) == "request-scope") c.scope = v;
            else if (QString(name) == "request-duration") c.duration = v;
            else c.target = v;
        });
        grid->addWidget(combo, gridRow + 1, gridCol, 1, span);
        return combo;
    };
    auto *scopeBox = addCombo("Apply to", scopeOptions(p), choice.scope, "request-scope", 0, 0, 2);
    grid->setRowMinimumHeight(2, 8);
    addCombo("For", durationOptions(), choice.duration, "request-duration", 3, 0, 1);
    auto *targetBox = addCombo("Destination", targetOptions(p), choice.target, "request-target", 3, 1, 1);
    choice.set = true;
    rightCol->addLayout(grid);
    // Una regla por carpeta es para la app entera: el destino queda en «Any destination» y se dice qué carpeta abre.
    auto *folderNote = text({}, "faint", true);
    folderNote->setObjectName("request-folder-note");
    folderNote->setContentsMargins(0, 8, 0, 0);
    rightCol->addWidget(folderNote);
    const auto syncFolder = [this, scopeBox, targetBox, folderNote, id = p.id.toLower(), path = p.path] {
        const QString scope = scopeBox->currentData().toString();
        const bool folder = FolderTrust::isFolderScope(scope);
        {
            // Sin tocar lo elegido (choices_): una carpeta muestra «Any destination» y, al dejarla, vuelve lo de antes.
            const QSignalBlocker quiet(targetBox);
            const int at = folder ? targetBox->findData(QString()) : targetBox->findData(choices_.value(id).target);
            if (at >= 0) targetBox->setCurrentIndex(at);
        }
        targetBox->setEnabled(canDecide() && targetBox->count() > 1 && !folder);
        folderNote->setText(FolderTrust::note(scope, path));
        folderNote->setVisible(folder);
    };
    connect(scopeBox, &QComboBox::currentIndexChanged, this, syncFolder);
    syncFolder();
    rightCol->addStretch(1);
    rightCol->addSpacing(12);
    auto *buttons = row(8);
    buttons->addStretch();
    auto *block = decision("Block", "block");
    auto *allow = decision("Allow", "allow");
    block->setObjectName("request-block");
    allow->setObjectName("request-allow");
    recommend(block, allow, known);
    for (auto *b : {block, allow}) {
        b->setEnabled(canDecide());
        buttons->addWidget(b);
        connect(b, &QPushButton::clicked, this, [this, p, allowed = b == allow] {
            if (!armed()) return;
            const auto c = choices_.value(p.id.toLower());
            firewall_.decide(p.path, allowed, c.scope, c.duration, c.target);
            choices_.remove(p.id.toLower());
            if (expanded_ == p.id) expanded_.clear();
        });
    }
    rightCol->addLayout(buttons);
    auto *rw = new QWidget;
    rw->setFixedWidth(290);
    rw->setLayout(rightCol);
    bh->addWidget(rw);
    cl->addWidget(body);
    return c;
}

QWidget *FirewallWindow::requestsPage() {
    auto *page = new QWidget;
    auto *l = column(page, 28, 12);
    l->setContentsMargins(28, 24, 28, 28);
    l->addWidget(header("Requests",
                        "Each application here was blocked and is waiting. Allow lets its next attempt connect."));
    l->addSpacing(2);
    l->addWidget(how({"Each program here was blocked and is waiting for you.",
                      "Choose what the rule covers: <b>this file</b>, <b>any version</b> of a signed app or the app "
                      "inside its <b>repository</b>, and for how long and to which server.",
                      "Press <b>Allow</b> or <b>Block</b>. Allow lets the next attempt connect."},
                     "Closing a notice keeps the request waiting here. Block and Allow on a closed card use what the "
                     "notice would preselect."));
    auto pending = firewall_.pending();
    std::sort(pending.begin(), pending.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
    if (!firewall_.status().connected) {
        auto *c = card();
        cardColumn(c)->addWidget(text("The engine is not running, so no requests can arrive.", "sub", true));
        l->addWidget(c);
    } else if (pending.isEmpty()) {
        auto *c = card();
        cardColumn(c)->addWidget(text("Nothing is waiting. A new application that tries to connect appears here and in a "
                                  "notice in the corner of the screen.",
                                  "sub", true));
        l->addWidget(c);
    }
    bool found = false;
    for (const auto &p : pending) found |= p.id == expanded_;
    if (!found) expanded_ = pending.isEmpty() ? QString() : pending.first().id;
    for (const auto &p : pending) l->addWidget(requestCard(p, p.id == expanded_));
    // Lo elegido de pedidos que ya no están se olvida.
    QSet<QString> alive;
    for (const auto &p : pending) alive.insert(p.id.toLower());
    for (auto it = choices_.begin(); it != choices_.end();) it = alive.contains(it.key()) ? std::next(it) : choices_.erase(it);
    l->addStretch();
    return page;
}

void FirewallWindow::decideDefault(const FirewallClient::PendingItem &p, bool allow) {
    if (!armed()) return;
    QString target;
    if (p.perDestination) {
        const auto t = targetOptions(p);
        if (!t.isEmpty()) target = t.first().second;
    }
    firewall_.decide(p.path, allow, scopeOptions(p).first().second, "always", target);
}

// ------------------------------------------------------------------------------------------------------------------
// Apps: una fila por app con reglas. Las reglas por destino de una misma app se juntan en «Per server».

QVector<FirewallWindow::AppEntry> FirewallWindow::appEntries() const {
    QVector<AppEntry> entries;
    QHash<QString, int> index;
    const auto &rules = firewall_.rules();
    for (const auto &r : rules) {
        if (r.scope == "covered") continue;
        // La clave de una regla por carpeta ya es «folder|carpeta|nombre» (la del motor).
        const QString key = r.scope == "path"     ? "path|" + r.path.toLower()
                            : r.scope == "app"    ? "app|" + r.signer.toLower() + "|" + r.name.toLower()
                            : r.scope == "folder" ? r.id.toLower()
                                                  : "pub|" + r.signer.toLower();
        int at = index.value(key, -1);
        if (at < 0) {
            AppEntry e;
            e.key = key;
            e.scope = r.scope;
            e.signer = r.signer;
            e.path = r.path;
            if (r.scope == "path") {
                e.title = FirewallClient::fileName(r.path);
                e.subtitle = "This file · " + shortFolder(r.path);
                e.iconPath = r.path;
            } else if (r.scope == "app") {
                e.title = r.name;
                e.subtitle = "Any version · " + r.signer;
            } else if (r.scope == "folder") {
                // Con nombre: como una regla de app («node.exe · Any version»), pero por carpeta.
                e.title = r.name.isEmpty() ? "All apps in " + FolderTrust::label(r.path) : r.name;
                e.subtitle = (r.name.isEmpty() ? "Folder rule · " : "Anywhere in ") + QDir::toNativeSeparators(r.path);
                if (r.name.isEmpty()) e.iconPath = r.path; // el ícono de carpeta de Windows
            } else {
                e.title = "All apps from " + r.signer;
                e.subtitle = "Publisher rule";
            }
            at = entries.size();
            index.insert(key, at);
            entries.push_back(e);
        }
        entries[at].rules.push_back(r);
        if (!r.destination.isEmpty()) entries[at].perServer = true;
    }
    // Ícono y archivos de las reglas por firma o por carpeta: los que ya cubrieron (si no, el de la carpeta).
    for (auto &e : entries) {
        if (!e.iconPath.isEmpty()) continue;
        for (const auto &r : e.rules)
            for (const auto &c : rules)
                if (c.scope == "covered" && c.name == r.id && e.iconPath.isEmpty()) e.iconPath = c.path;
        if (e.iconPath.isEmpty() && e.scope == "folder") e.iconPath = e.path;
        // El motor guarda el nombre en minúsculas: un archivo cubierto trae las mayúsculas reales («DayTrace.exe»).
        if (e.scope == "folder" && !e.rules.first().name.isEmpty() && e.iconPath != e.path &&
            FirewallClient::fileName(e.iconPath).compare(e.title, Qt::CaseInsensitive) == 0)
            e.title = FirewallClient::fileName(e.iconPath);
    }
    std::sort(entries.begin(), entries.end(),
              [](const AppEntry &a, const AppEntry &b) { return a.title.compare(b.title, Qt::CaseInsensitive) < 0; });
    return entries;
}

// Exes que corren en esta sesión de Windows (las apps del usuario, no los servicios).
void FirewallWindow::refreshRunning() {
    QStringList found;
    DWORD session = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &session);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        QSet<QString> seen;
        for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
            DWORD s = 0;
            if (!ProcessIdToSessionId(pe.th32ProcessID, &s) || s != session) continue;
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!h) continue;
            wchar_t buffer[MAX_PATH * 2];
            DWORD size = DWORD(std::size(buffer));
            if (QueryFullProcessImageNameW(h, 0, buffer, &size)) {
                const QString path = QString::fromWCharArray(buffer, int(size));
                if (!seen.contains(path.toLower())) {
                    seen.insert(path.toLower());
                    found << path;
                }
            }
            CloseHandle(h);
        }
        CloseHandle(snap);
    }
    std::sort(found.begin(), found.end(), [](const QString &a, const QString &b) { return a.compare(b, Qt::CaseInsensitive) < 0; });
    if (found != running_) {
        running_ = found;
        engineChanged();
    }
}

QStringList FirewallWindow::runningWithoutRule() const {
    QStringList result;
    const QString self = QDir::toNativeSeparators(QCoreApplication::applicationFilePath()).toLower();
    for (const auto &path : running_) {
        // Una carpeta de confianza también es una regla: no le pregunta nada a nadie (su primer intento igual se pierde).
        if (path.toLower() == self || firewall_.ruleFor(path) || firewall_.folderRuleFor(path) || firewall_.pendingFor(path))
            continue;
        result << path;
    }
    std::sort(result.begin(), result.end(), [](const QString &a, const QString &b) {
        return FirewallClient::fileName(a).compare(FirewallClient::fileName(b), Qt::CaseInsensitive) < 0;
    });
    return result;
}

QWidget *FirewallWindow::appsPage() {
    auto *page = new QWidget;
    auto *l = column(page, 28, 12);
    l->setContentsMargins(28, 24, 28, 24);
    l->addWidget(header("Apps",
                        "Every application with a rule. A signed app keeps its rule across updates; a rule in a folder "
                        "also covers builds made there later."));
    l->addSpacing(2);
    l->addWidget(how({"Every program with a rule is listed here, with what it covers and where it may connect.",
                      "A <b>signed</b> program keeps its rule across updates; a <b>folder rule</b> covers every build made "
                      "inside that folder.",
                      "Click a row to change or remove its rule. <b>Running, no rule</b> lets you decide before a "
                      "program asks."}));
    auto *bar = row(10);
    auto *search = new QLineEdit(appsQuery_);
    search->setObjectName("apps-search");
    search->setPlaceholderText("Search apps or publishers");
    search->setClearButtonEnabled(true);
    search->setMinimumWidth(140);
    search->setMinimumHeight(30);
    search->addAction(QIcon(iconPixmap("search", 16, Theme::color(Theme::kTextCaption), devicePixelRatioF())),
                      QLineEdit::LeadingPosition);
    bar->addWidget(search, 1);
    auto *trust = button("Trust a folder…");
    trust->setObjectName("apps-trust-folder");
    trust->setEnabled(canDecide());
    connect(trust, &QPushButton::clicked, this, [this] { trustFolderDialog({}, {}); });
    bar->addWidget(trust);
    l->addLayout(bar);
    auto *filters = row(0);
    appsSeg_ = card("seg");
    appsSeg_->setFixedHeight(30);
    auto *sl = new QHBoxLayout(appsSeg_);
    sl->setContentsMargins(2, 2, 2, 2);
    sl->setSpacing(2);
    filters->addWidget(appsSeg_);
    filters->addStretch();
    l->addLayout(filters);
    connect(search, &QLineEdit::textChanged, this, [this](const QString &v) {
        appsQuery_ = v;
        fillApps();
    });
    // La tabla ocupa el resto de la página: el encabezado queda fijo y sólo se desplazan las filas.
    auto *list = card();
    auto *ll = new QVBoxLayout(list);
    ll->setContentsMargins(1, 1, 1, 1);
    appsTable_ = makeTable("apps", 54);
    ll->addWidget(appsTable_);
    connect(appsTable_, &QTableWidget::cellClicked, this, [this](int row, int) {
        const QString key = appsTable_->item(row, 0) ? appsTable_->item(row, 0)->data(Qt::UserRole).toString() : QString();
        if (key.startsWith("rule:")) selectView("detail:" + key.mid(5));
    });
    l->addWidget(list, 1);
    appsTip_ = text({}, "faint", true);
    l->addWidget(appsTip_);
    fillApps();
    return page;
}

void FirewallWindow::fillApps() {
    if (!appsTable_ || !appsSeg_) return;
    armedAt_ = QDateTime::currentMSecsSinceEpoch() + 600;
    const auto entries = appEntries();
    const QStringList loose = runningWithoutRule();
    int allow = 0, block = 0, perServer = 0, temporary = 0, folders = 0;
    const auto classify = [](const AppEntry &e) {
        if (e.perServer) return QString("server");
        const auto &r = e.rules.first();
        if (r.expires != 0) return QString("temp");
        return QString(r.allow ? "allow" : "block");
    };
    for (const auto &e : entries) {
        const QString c = classify(e);
        allow += c == "allow";
        block += c == "block";
        perServer += c == "server";
        temporary += c == "temp";
        folders += e.scope == "folder";
    }
    // Filtros: se rehacen con los números del momento.
    auto *sl = static_cast<QHBoxLayout *>(appsSeg_->layout());
    while (auto *item = sl->takeAt(0)) {
        // Diferido: el clic que rearma los filtros viene de uno de estos botones.
        if (auto *old = item->widget()) {
            old->hide();
            old->deleteLater();
        }
        delete item;
    }
    const QVector<std::tuple<QString, QString, int>> filters{{"all", "All", int(entries.size())},
                                                            {"allow", "Allow", allow},
                                                            {"block", "Block", block},
                                                            {"server", "Per server", perServer},
                                                            {"temp", "Temporary", temporary},
                                                            {"folder", "Folders", folders},
                                                            {"running", "Running, no rule", int(loose.size())}};
    for (const auto &[id, name, n] : filters) {
        // El número va más apagado que el nombre (`.seg em`): dos textos dentro del botón, que no toman el mouse.
        const bool on = appsFilter_ == id;
        auto *b = button({}, "seg");
        b->setAccessibleName(QString("%1 %2").arg(name).arg(n));
        auto *bl = new QHBoxLayout(b);
        bl->setContentsMargins(11, 0, 11, 0);
        bl->setSpacing(5);
        auto *nameLabel = new QLabel(name);
        auto *countLabel = new QLabel(QString::number(n));
        nameLabel->setStyleSheet(QString("color: %1; font-size: %2; font-weight: 600;")
                                     .arg(on ? Theme::kOnAccent : Theme::kTextFaint, "9.375pt"));
        countLabel->setStyleSheet(QString("color: %1; font-size: %2; font-weight: 500;")
                                      .arg(on ? "#A39DD0" : "#6E6D75", "9.375pt"));
        for (auto *x : {nameLabel, countLabel}) {
            x->setAttribute(Qt::WA_TransparentForMouseEvents);
            bl->addWidget(x);
        }
        b->setMinimumWidth(bl->sizeHint().width());
        b->setFixedHeight(24);
        b->setObjectName("apps-filter-" + id);
        b->setProperty("on", on ? "1" : "0");
        connect(b, &QPushButton::clicked, this, [this, id = id] {
            appsFilter_ = id;
            fillApps();
        });
        sl->addWidget(b);
    }

    // Filas. El desplazamiento se conserva: la tabla se rehace con cada cambio del motor.
    auto *t = appsTable_;
    const int scrolled = t->verticalScrollBar()->value();
    t->setRowCount(0);
    t->clearSpans();
    const bool runningView = appsFilter_ == "running";
    const auto matches = [this](const QString &haystack) {
        return appsQuery_.isEmpty() || haystack.contains(appsQuery_, Qt::CaseInsensitive);
    };
    const auto nameCell = [](const QString &iconPath, const QString &title, const QString &subtitle,
                             Qt::TextElideMode mode = Qt::ElideRight) {
        auto *w = new QWidget;
        auto *h = new QHBoxLayout(w);
        h->setContentsMargins(0, 0, 0, 0);
        h->setSpacing(11);
        h->addWidget(appIcon(iconPath));
        auto *v = new QVBoxLayout;
        v->setSpacing(1);
        v->addWidget(new ElideLabel(title, "strong"));
        if (!subtitle.isEmpty()) v->addWidget(new ElideLabel(subtitle, "faint", mode));
        h->addLayout(v, 1);
        return w;
    };
    if (runningView) {
        setColumns(t, "running", {{"APPLICATION", 260}, {"FOLDER", 340}, {"RULE FOR THIS FILE", 170}});
        t->viewport()->setCursor(Qt::ArrowCursor);
        for (const auto &path : loose) {
            if (!matches(path)) continue;
            const int r = t->rowCount();
            t->insertRow(r);
            auto *folder = new ElideLabel(QDir::toNativeSeparators(QFileInfo(path).path()), "small", Qt::ElideMiddle);
            // Una regla para este archivo, sin esperar a que pida: como «This file only» en el aviso.
            auto *decide = new QWidget;
            auto *dh = new QHBoxLayout(decide);
            dh->setContentsMargins(0, 0, 0, 0);
            dh->setSpacing(8);
            for (const bool allowed : {false, true}) {
                auto *b = decision(allowed ? "Allow" : "Block", allowed ? "allow" : "block");
                b->setObjectName(allowed ? "running-allow" : "running-block");
                b->setEnabled(canDecide());
                connect(b, &QPushButton::clicked, this, [this, path, allowed] {
                    if (armed()) firewall_.decide(path, allowed, "path", "always");
                });
                dh->addWidget(b);
            }
            dh->addStretch();
            fillRow(t, r, {cell(nameCell(path, FirewallClient::fileName(path), {})), cell(folder), cell(decide, Qt::AlignLeft, true)});
        }
        appsTip_->setText("Applications running in your Windows session without a rule. They ask the first time they "
                          "connect, or Allow and Block here save a rule for that file now.");
    } else {
        setColumns(t, "rules",
                   {{"APPLICATION", 330}, {"DESTINATION", 120}, {"RULE", 170}, {"WHEN", 130, Qt::AlignRight}});
        t->viewport()->setCursor(Qt::PointingHandCursor);
        for (const auto &e : entries) {
            const QString c = classify(e);
            // «Folders» junta las reglas por carpeta (con o sin nombre de exe), sean Allow, Block o temporales.
            if (appsFilter_ == "folder" ? e.scope != "folder" : appsFilter_ != "all" && appsFilter_ != c) continue;
            QString hay = e.title + " " + e.subtitle + " " + e.path + " " + e.signer;
            for (const auto &r : e.rules) hay += " " + r.destination;
            if (!matches(hay)) continue;
            const int r = t->rowCount();
            t->insertRow(r);
            const auto &r0 = e.rules.first();
            QWidget *dest = e.perServer ? static_cast<QWidget *>(chip(e.rules.size() == 1 ? QString("1 server")
                                                                                          : QString("%1 servers").arg(e.rules.size())))
                                        : new ElideLabel("Anywhere", "small");
            QLabel *policy = c == "server" ? pill("Per server", "dest")
                             : c == "temp" ? pill(QString(r0.allow ? "Allow" : "Block") + " · " +
                                                      (r0.expires < 0 ? QString("until restart") : "until " + clock(r0.expires)),
                                                  "temp")
                             : c == "allow" ? pill("Allow", "allow")
                                            : pill("Block", "block");
            qint64 lastBlock = 0, created = 0;
            for (const auto &x : e.rules) {
                lastBlock = qMax(lastBlock, x.allow ? 0 : x.lastBlock);
                if (!created || x.created < created) created = x.created;
            }
            auto *when = new ElideLabel(lastBlock ? "blocked " + clock(lastBlock) : "added " + clock(created), "time");
            when->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
            // Una ruta se recorta al medio (se ve el final); un editor, al final.
            fillRow(t, r, {cell(nameCell(e.iconPath, e.title, e.subtitle, e.scope == "path" ? Qt::ElideMiddle : Qt::ElideRight)),
                           cell(dest), cell(policy), cell(when)});
            t->item(r, 0)->setData(Qt::UserRole, "rule:" + e.key);
        }
        if (appsFilter_ == "folder")
            appsTip_->setText("A folder rule covers programs in that folder and its subfolders, also ones built or copied "
                              "there later. A notice offers it for one app in its repository; Trust a folder… adds any "
                              "folder by hand, for one program name or for all of them.");
        else
            appsTip_->clear();
    }
    if (t->rowCount() == 0) {
        t->insertRow(0);
        auto *empty = new ElideLabel(runningView ? "Every running application of this session has a rule or is waiting."
                                     : !appsQuery_.isEmpty()   ? "No app matches the search."
                                     : appsFilter_ == "folder" ? "No folder rules yet."
                                                               : "No rules here yet.",
                                     "sub");
        fillRow(t, 0, {cell(empty)});
        t->setSpan(0, 0, 1, t->columnCount());
        t->viewport()->setCursor(Qt::ArrowCursor);
    }
    appsTip_->setVisible(!appsTip_->text().isEmpty());
    QTimer::singleShot(0, t, [t, scrolled] { t->verticalScrollBar()->setValue(scrolled); });
}

QWidget *FirewallWindow::detailPage(const QString &key) {
    auto *page = new QWidget;
    auto *l = column(page, 28, 12);
    l->setContentsMargins(28, 24, 28, 28);
    auto *back = button("‹ Apps", "link");
    back->setObjectName("detail-back");
    connect(back, &QPushButton::clicked, this, [this] { selectView("apps"); });
    auto *bl = row();
    bl->addWidget(back);
    bl->addStretch();
    l->addLayout(bl);
    const auto entries = appEntries();
    const AppEntry *e = nullptr;
    for (const auto &x : entries) if (x.key == key) e = &x;
    if (!e) {
        l->addWidget(text("This app has no rules any more.", "sub"));
        l->addStretch();
        return page;
    }
    const auto &r0 = e->rules.first();
    // e->title es el nombre con sus mayúsculas reales si ya cubrió un archivo (appEntries).
    const QString folderText = (r0.name.isEmpty() ? QStringLiteral("Every program in ") : e->title + " anywhere in ") +
                               FolderTrust::shown(e->path) + " and its subfolders";
    QString where = e->scope == "path"     ? QDir::toNativeSeparators(e->path)
                    : e->scope == "app"    ? "Any version signed by " + e->signer
                    : e->scope == "folder" ? folderText
                                           : "Any application signed by " + e->signer;
    if (e->scope == "app" && !e->iconPath.isEmpty())
        where = QDir::toNativeSeparators(e->iconPath) + " · any version signed by " + e->signer;
    l->addWidget(header(e->title, where, nullptr, appIcon(e->iconPath, 36)));
    const bool can = canDecide();
    int covered = 0;
    for (const auto &r : e->rules)
        for (const auto &c : firewall_.rules()) covered += c.scope == "covered" && c.name == r.id;

    if (e->perServer) {
        auto *c = card();
        auto *cl = cardColumn(c, 0);
        auto *ch = row(10);
        ch->addWidget(text("Server rules", "cardtitle"));
        ch->addWidget(chip(QString::number(e->rules.size()), "mute"));
        ch->addStretch();
        cl->addLayout(ch);
        cl->addSpacing(6);
        bool first = true;
        for (const auto &r : e->rules) {
            if (!first) cl->addWidget(divider());
            first = false;
            auto *w = new QWidget;
            w->setMinimumHeight(38);
            auto *h = new QHBoxLayout(w);
            h->setContentsMargins(0, 3, 0, 3);
            h->setSpacing(10);
            h->addWidget(new ElideLabel(r.destination, "value"), 1);
            h->addWidget(text(r.expires == 0 ? QString("Always")
                              : r.expires < 0 ? QString("Until restart")
                                              : "Until " + clock(r.expires),
                              "sub"));
            auto *pw = new QWidget;
            pw->setFixedWidth(70);
            auto *pl = new QHBoxLayout(pw);
            pl->setContentsMargins(0, 0, 0, 0);
            pl->addStretch();
            pl->addWidget(pill(r.allow ? "Allow" : "Block", r.allow ? "allow" : "block"));
            h->addWidget(pw);
            auto *x = button("×", "x");
            x->setObjectName("remove-server-rule");
            CustomTooltip::instance()->setToolTip(x, "Remove only this server rule");
            x->setEnabled(can);
            connect(x, &QPushButton::clicked, this, [this, id = r.id] { firewall_.removeRule(id); });
            h->addWidget(x);
            cl->addWidget(w);
        }
        cl->addSpacing(4);
        cl->addWidget(divider());
        cl->addSpacing(10);
        cl->addWidget(text("Any other server asks first, with its own notice. A name is matched through the address the "
                           "app looked up, so on a shared network like Cloudflare an allowed address also reaches other "
                           "sites there.",
                           "faint", true));
        l->addWidget(c);
    } else {
        auto *c = card();
        auto *cl = cardColumn(c, 10);
        cl->addWidget(text("Rule", "cardtitle"));
        auto *grid = new QGridLayout;
        grid->setHorizontalSpacing(12);
        grid->setVerticalSpacing(9);
        grid->setColumnMinimumWidth(0, 130);
        int gr = 0;
        const auto kv = [&](const QString &k, QWidget *v) {
            grid->addWidget(text(k, "faint"), gr, 0, Qt::AlignTop);
            grid->addWidget(v, gr++, 1);
        };
        auto *pw = new QWidget;
        auto *pl = new QHBoxLayout(pw);
        pl->setContentsMargins(0, 0, 0, 0);
        pl->addWidget(r0.expires != 0 ? pill(QString(r0.allow ? "Allow" : "Block") + " · " +
                                                 (r0.expires < 0 ? QString("until restart") : "until " + clock(r0.expires)),
                                             "temp")
                                      : pill(r0.allow ? "Allow" : "Block", r0.allow ? "allow" : "block"));
        pl->addStretch();
        kv("Decision", pw);
        kv("Applies to", text(e->scope == "path"     ? QString("This file only")
                              : e->scope == "app"    ? "Any version of " + r0.name + " signed by this publisher"
                              : e->scope == "folder" ? folderText + ", also programs built or copied there later. A "
                                                                    "rule for a file, an app or a publisher comes first."
                                                     : "Any application signed by " + r0.signer,
                              "value", true));
        if (e->scope != "path") kv("Files seen", text(QString::number(covered), "value"));
        kv("Created", text(clockFull(r0.created), "value"));
        kv("Last blocked attempt", text(r0.allow ? QString("—") : clockFull(r0.lastBlock), "value"));
        cl->addLayout(grid);
        if ((e->scope == "path" || e->scope == "folder") && r0.expires == 0) {
            // Una regla por ruta o por carpeta se puede invertir aquí; las de firma se cambian en el próximo aviso que
            // coincida.
            auto *actions = row(8);
            actions->addStretch();
            auto *flip = button(r0.allow ? "Change to Block" : "Change to Allow", r0.allow ? "block" : "allow");
            flip->setObjectName("rule-flip");
            flip->setEnabled(can);
            connect(flip, &QPushButton::clicked, this,
                    [this, folder = e->scope == "folder", path = e->path, name = r0.name, allow = !r0.allow] {
                        if (folder) firewall_.trustFolder(path, name, allow);
                        else firewall_.decide(path, allow);
                    });
            actions->addWidget(flip);
            cl->addLayout(actions);
        }
        l->addWidget(c);
    }
    // Una regla de un archivo no sigue a los builds nuevos: dentro de un repositorio se ofrece la regla del programa en
    // todo el repositorio. Si ya está dentro de una carpeta de confianza, se dice quién decide.
    const auto *inside = e->scope == "path" && !e->perServer ? firewall_.folderRuleFor(e->path) : nullptr;
    if (e->scope == "path" && !e->perServer) {
        bool inRepository = false;
        const QString folder = inside ? QString() : FolderTrust::suggestion(e->path, &inRepository);
        if (inside || (r0.allow && inRepository && !folder.isEmpty())) {
            auto *c = card();
            c->setObjectName("detail-folder-card");
            auto *ch = new QHBoxLayout(c);
            ch->setContentsMargins(18, 15, 18, 16);
            ch->setSpacing(12);
            auto *ct = new QVBoxLayout;
            ct->setSpacing(2);
            if (inside && inside->allow) {
                ct->addWidget(text("Inside a trusted folder", "strong"));
                ct->addWidget(text(QString("%1 is a trusted folder. This file rule comes first; if you remove it, the "
                                           "folder rule takes over after one blocked attempt.")
                                       .arg(FolderTrust::shown(inside->path)),
                                   "small", true));
            } else if (inside) {
                ct->addWidget(text("Inside a blocked folder", "strong"));
                ct->addWidget(text(QString("A folder rule blocks %1 in %2. This file rule comes first; if you remove it, "
                                           "the folder rule blocks it without asking.")
                                       .arg(e->title, FolderTrust::shown(inside->path)),
                                   "small", true));
            } else {
                ct->addWidget(text("Cover new builds too", "strong"));
                ct->addWidget(text(QString("This rule covers only this file: a build of %1 in another folder asks "
                                           "again. A rule for %1 anywhere in %2 covers every build there.")
                                       .arg(e->title, FolderTrust::shown(folder)),
                                   "small", true));
            }
            ch->addLayout(ct, 1);
            if (!inside) {
                auto *b = button("Cover all builds…");
                b->setObjectName("detail-trust-folder");
                b->setEnabled(can);
                connect(b, &QPushButton::clicked, this, [this, folder, name = e->title] { trustFolderDialog(folder, name); });
                ch->addWidget(b, 0, Qt::AlignVCenter);
            }
            l->addWidget(c);
        }
    }
    auto *remove = card();
    auto *rh = new QHBoxLayout(remove);
    rh->setContentsMargins(18, 15, 18, 16);
    rh->setSpacing(12);
    auto *rt = new QVBoxLayout;
    rt->setSpacing(2);
    rt->addWidget(text(e->rules.size() > 1 ? "Remove all rules for " + e->title : "Remove this rule", "strong"));
    rt->addWidget(text(inside && inside->allow ? "The trusted folder decides for " + e->title + " after one blocked attempt."
                       : inside            ? "The folder rule blocks " + e->title + " without asking."
                       : e->scope == "path" ? e->title + " asks again the next time it connects."
                       : e->scope == "folder"
                           ? "Programs in " + FolderTrust::shown(e->path) +
                                 " ask again the next time they connect, unless another rule covers them."
                           : e->title + " asks again the next time it connects. To change a rule like this one, decide "
                                        "on its next notice.",
                       "small", true));
    rh->addLayout(rt, 1);
    auto *rb = button(e->rules.size() > 1 ? "Remove rules" : "Remove rule");
    rb->setObjectName("remove-rule");
    rb->setEnabled(can);
    connect(rb, &QPushButton::clicked, this, [this, rules = e->rules] {
        for (const auto &r : rules) firewall_.removeRule(r.id);
        selectView("apps");
    });
    rh->addWidget(rb);
    l->addWidget(remove);
    l->addStretch();
    return page;
}

// ------------------------------------------------------------------------------------------------------------------
// Activity: lo que el motor guardó desde que arrancó.

QWidget *FirewallWindow::activityPage() {
    const auto &s = firewall_.status();
    auto *page = new QWidget;
    auto *l = column(page, 28, 12);
    l->setContentsMargins(28, 24, 28, 24);
    auto *seg = card("seg");
    seg->setFixedHeight(30);
    auto *sl = new QHBoxLayout(seg);
    sl->setContentsMargins(2, 2, 2, 2);
    sl->setSpacing(2);
    for (const auto &[id, name] : {std::pair{QString("blocked"), QString("Blocked")}, {QString("decisions"), QString("Decisions")}}) {
        auto *b = button(name, "seg");
        b->setFixedHeight(24);
        b->setObjectName("activity-filter-" + id);
        b->setProperty("on", activityFilter_ == id ? "1" : "0");
        connect(b, &QPushButton::clicked, this, [this, id = id] {
            activityFilter_ = id;
            render();
        });
        sl->addWidget(b);
    }
    l->addWidget(header("Activity",
                        (s.started ? "Since the engine started at " + clock(s.started) + ". " : QString()) +
                            "Allowed connections are not recorded.",
                        seg));
    l->addSpacing(2);
    l->addWidget(how({"<b>Blocked</b> lists every attempt the engine stopped and how each request ended.",
                      "<b>Decisions</b> shows what you chose and when one of your rules let a program through.",
                      "Repeated attempts of one program are grouped in one row."},
                     "The list keeps the latest 2,000 events and starts again when the engine restarts."));
    const bool blockedView = activityFilter_ == "blocked";
    auto *c = card();
    auto *cl = new QVBoxLayout(c);
    cl->setContentsMargins(1, 1, 1, 1);
    auto *t = makeTable("activity", 50);
    t->viewport()->setCursor(Qt::ArrowCursor);
    if (blockedView)
        setColumns(t, "blocked", {{"TIME", 80}, {"APPLICATION", 260}, {"DESTINATION", 200}, {"REASON", 160}});
    else
        setColumns(t, "decisions", {{"TIME", 80}, {"APPLICATION", 260}, {"DECISION", 300}});
    cl->addWidget(t);
    const auto &events = firewall_.activity();
    const auto reasons = blockedView ? blockReasons(events, firewall_.pending()) : QVector<BlockReason>();
    // Una fila por ráfaga: los intentos de una misma app con el mismo motivo van juntos aunque alternen entre varias
    // direcciones o se intercalen con otras apps. Un intento se suma a la fila de su clave si es la última fila o si
    // llegó a menos de un minuto del más viejo de ella, y siempre que la fila no pase de diez minutos: una regla Block
    // que corta a una app cada minuto no se vuelve una sola fila de toda la mañana.
    constexpr qint64 BurstGap = 60;
    constexpr qint64 RowSpan = 600;
    constexpr int RowLimit = 500;
    struct Row {
        const FirewallClient::ActivityItem *newest = nullptr;
        BlockReason reason;
        qint64 oldest = 0;
        QStringList destinations; // de la más nueva a la más vieja
        QHash<QString, int> hits; // destino -> intentos
    };
    QVector<Row> rows;
    QHash<QString, int> rowOf; // clave -> fila más nueva de esa clave
    for (int i = events.size() - 1; i >= 0; --i) {
        const auto &e = events[i];
        if (blockedView != e.kind.startsWith("Blocked")) continue;
        const BlockReason reason = blockedView ? reasons[i] : BlockReason{e.kind};
        const QString key = e.path.toLower() + '\n' + reason.text + '\n' + reason.tone;
        const auto at = rowOf.constFind(key);
        int r = -1;
        if (at != rowOf.constEnd() && rows[at.value()].newest->time - e.time <= RowSpan &&
            (at.value() == rows.size() - 1 || rows[at.value()].oldest - e.time <= BurstGap))
            r = at.value();
        if (r < 0) {
            if (rows.size() >= RowLimit) break;
            rows.push_back({&e, reason, e.time, {}, {}});
            r = rows.size() - 1;
            rowOf[key] = r;
        }
        auto &row = rows[r];
        row.oldest = e.time;
        // Normalizada: la misma dirección escrita como IPv4 o como IPv4 mapeada a IPv6 es un solo destino.
        const QString dest = e.remote.isEmpty() ? QString("—")
                                                : plainAddress(e.remote) + (e.port ? ":" + QString::number(e.port) : QString());
        if (!row.hits.contains(dest)) row.destinations << dest;
        ++row.hits[dest];
    }
    for (const auto &row : rows) {
        const auto &e = *row.newest;
        // Los intentos se cuentan por destino: una app que prueba 8 direcciones 4 veces muestra «4 times».
        int repeats = 0;
        for (const int n : row.hits) repeats = std::max(repeats, n);
        const int r = t->rowCount();
        t->insertRow(r);
        auto *when = new ElideLabel(clock(e.time), "time");
        auto *app = new QWidget;
        auto *ah = new QHBoxLayout(app);
        ah->setContentsMargins(0, 0, 0, 0);
        ah->setSpacing(10);
        if (!e.path.isEmpty()) ah->addWidget(appIcon(e.path, 30));
        auto *appName = new ElideLabel(e.path.isEmpty() ? QString("GateBouncer") : FirewallClient::fileName(e.path), "value");
        appName->setStyleSheet("font-weight: 500;");
        ah->addWidget(appName, 1);
        if (repeats > 1) ah->addWidget(text(QString("%1 times").arg(repeats), "time"));
        if (blockedView) {
            QString where = row.destinations.first();
            if (row.destinations.size() > 1) where += QString(" +%1 more").arg(row.destinations.size() - 1);
            auto *dest = new ElideLabel(where, "sub");
            auto *reason = new QWidget;
            auto *rh = new QHBoxLayout(reason);
            rh->setContentsMargins(0, 0, 0, 0);
            rh->addWidget(chip(row.reason.text, row.reason.tone));
            rh->addStretch();
            fillRow(t, r, {cell(when), cell(app), cell(dest), cell(reason)});
        } else {
            // «Allowed by rule: …» / «Rule saved: …»: el qué en claro y el detalle más apagado.
            auto *what = new QWidget;
            auto *wh = new QHBoxLayout(what);
            wh->setContentsMargins(0, 0, 0, 0);
            wh->setSpacing(5);
            const qsizetype colon = e.kind.indexOf(": ");
            if (colon > 0) {
                auto *lead = text(e.kind.left(colon + 1), "value");
                lead->setStyleSheet("font-weight: 600;");
                wh->addWidget(lead);
                wh->addWidget(new ElideLabel(e.kind.mid(colon + 2), "sub"), 1);
            } else {
                wh->addWidget(new ElideLabel(e.kind, "sub"), 1);
            }
            fillRow(t, r, {cell(when), cell(app), cell(what)});
        }
    }
    if (t->rowCount() == 0) {
        t->insertRow(0);
        fillRow(t, 0, {cell(new ElideLabel(blockedView ? "Nothing blocked since the engine started."
                                                       : "No decisions since the engine started.",
                                           "sub"))});
        t->setSpan(0, 0, 1, t->columnCount());
    }
    l->addWidget(c, 1);
    return page;
}

// ------------------------------------------------------------------------------------------------------------------
// Settings: modo del firewall, explicaciones con IA, importar de NetLimiter y la ventana.

QWidget *FirewallWindow::settingsPage() {
    const auto &s = firewall_.status();
    const bool can = canDecide();
    auto *page = new QWidget;
    auto *l = column(page, 28, 12);
    l->setContentsMargins(28, 24, 28, 28);
    l->addWidget(header("Settings", "Firewall mode, AI explanations, import and startup."));
    l->addSpacing(2);
    l->addWidget(how({"<b>Ask before unknown applications connect</b> is the switch of Protection: off, everything "
                      "without a rule connects.",
                      "<b>AI explanations</b> need your own key and your consent; they only explain, they never allow "
                      "or block.",
                      "<b>Import from NetLimiter</b> turns its rules for single applications into GateBouncer rules."},
                     "Closing the window keeps the firewall running: the engine is a Windows service. Quit in the tray "
                     "menu closes only this window."));

    const auto setRow = [](QVBoxLayout *into, const QString &title, const QString &caption, QWidget *trailing,
                           bool first = false) {
        if (!first) into->addWidget(divider());
        auto *w = new QWidget;
        w->setMinimumHeight(46);
        auto *h = new QHBoxLayout(w);
        h->setContentsMargins(0, first ? 8 : 12, 0, 12);
        h->setSpacing(14);
        auto *t = new QVBoxLayout;
        t->setSpacing(2);
        t->addWidget(text(title, "strong", true));
        if (!caption.isEmpty()) t->addWidget(text(caption, "small", true));
        h->addLayout(t, 1);
        if (trailing) h->addWidget(trailing, 0, Qt::AlignVCenter);
        into->addWidget(w);
        return h;
    };

    auto *fw = card();
    auto *fl = cardColumn(fw, 0);
    fl->addWidget(text("Firewall", "cardtitle"));
    fl->addSpacing(4);
    auto *ask = new ToggleSwitch;
    ask->setObjectName("firewall-ask");
    ask->setChecked(s.ask);
    ask->setEnabled(can);
    connect(ask, &ToggleSwitch::toggled, this, [this](bool on) { firewall_.setAsk(on); });
    setRow(fl, "Ask before unknown applications connect",
           "Off lets everything without a rule connect. Block rules still apply.", ask, true);
    auto *lan = new ToggleSwitch;
    lan->setObjectName("firewall-lan");
    lan->setChecked(s.localNetwork);
    lan->setEnabled(can);
    connect(lan, &ToggleSwitch::toggled, this, [this](bool on) { firewall_.setLocalNetwork(on); });
    setRow(fl, "Allow the local network without asking",
           "Other computers, printers and storage at home or the office, and devices on Tailscale. A Block rule for an "
           "application still applies there.",
           lan);
    fl->addSpacing(4);
    fl->addWidget(divider());
    fl->addSpacing(12);
    auto *off = new QLabel(QString("Windows services, DNS and connections inside this PC always connect. To turn "
                                   "GateBouncer off completely, run <span style=\"background:%1; color:%2; "
                                   "font-weight:600;\">&nbsp;GateBouncerEngine.exe --remove-filters&nbsp;</span> as "
                                   "administrator.")
                               .arg(Theme::kTile, Theme::kTextStrong));
    off->setProperty("r", "sub");
    off->setWordWrap(true);
    fl->addWidget(off);
    if (!s.connected)
        fl->addWidget(text("The engine is not running: these options apply when it starts again.", "warn", true));
    l->addWidget(fw);

    // Explicaciones: key, consentimiento y textos son del proveedor del modelo elegido.
    const auto settings = Explain::Settings::load();
    const auto provider = Explain::providerOf(settings.model);
    const QString providerName = Explain::providerName(provider);
    const bool hasKey = Explain::KeyStore::has(provider);
    auto *ai = card();
    auto *al = cardColumn(ai, 0);
    auto *aih = row(10);
    aih->addWidget(text("AI explanations", "cardtitle"));
    aih->addStretch();
    aih->addWidget(hasKey && settings.consent ? chip("Ready", "ok") : hasKey ? chip("Key saved", "mute") : chip("Off", "mute"));
    al->addLayout(aih);
    al->addSpacing(6);
    al->addWidget(text("When an application is blocked, an AI model can say what it is and why it connects. The answer "
                       "only helps you decide: it never allows or blocks anything, and it can be wrong.",
                       "small", true));
    al->addSpacing(6);
    auto *keyBox = new QWidget;
    auto *kb = new QHBoxLayout(keyBox);
    kb->setContentsMargins(0, 0, 0, 0);
    kb->setSpacing(8);
    auto *key = new QLineEdit;
    key->setObjectName("explain-key");
    key->setEchoMode(QLineEdit::Password);
    key->setFixedWidth(200);
    key->setPlaceholderText(hasKey ? "Paste a new key"
                                   : QString("Paste your key (%1…)").arg(provider == Explain::Provider::Anthropic ? "sk-ant-" : "nvapi-"));
    kb->addWidget(key);
    auto *saveKey = button("Save key", "primary");
    saveKey->setObjectName("explain-save-key");
    saveKey->setEnabled(false);
    // Sin nada pegado no hay qué guardar: el botón principal no invita a una acción vacía.
    connect(key, &QLineEdit::textChanged, saveKey, [saveKey](const QString &v) { saveKey->setEnabled(!v.trimmed().isEmpty()); });
    kb->addWidget(saveKey);
    auto *removeKey = button("Remove");
    removeKey->setObjectName("explain-remove-key");
    removeKey->setEnabled(hasKey);
    kb->addWidget(removeKey);
    setRow(al, providerName + " key",
           hasKey ? "Saved for this Windows account, encrypted." : "No key saved: explanations are off.", keyBox, true);
    auto *consent = new ToggleSwitch;
    consent->setObjectName("explain-consent");
    consent->setChecked(settings.consent);
    setRow(al, "Send app details to " + providerName + " when an explanation is requested",
           "The file name, its folder without your account name, signature and version, the public server it wanted and "
           "the program that started it. Never the file, its command line or your local network. Uses your " +
               providerName + " account and its terms; up to 100 a day.",
           consent);
    auto *automatic = new ToggleSwitch;
    automatic->setObjectName("explain-automatic");
    automatic->setChecked(settings.automatic);
    setRow(al, "Explain automatically when a notice appears", "Off shows an Ask AI button on the notice instead.",
           automatic);
    auto *opts = new QWidget;
    auto *ol = new QHBoxLayout(opts);
    ol->setContentsMargins(0, 0, 0, 0);
    ol->setSpacing(8);
    auto *model = new Combo;
    model->setObjectName("explain-model");
    model->addItems(Explain::Settings::models());
    if (!Explain::Settings::models().contains(settings.model)) model->addItem(settings.model);
    model->setCurrentText(settings.model);
    model->setFixedWidth(230);
    ol->addWidget(model);
    auto *language = new Combo;
    language->setObjectName("explain-language");
    language->addItems({"English", "Español"});
    language->setCurrentIndex(settings.language == "es" ? 1 : 0);
    language->setFixedWidth(110);
    ol->addWidget(language);
    auto *test = button("Test with Notepad");
    test->setObjectName("explain-test");
    test->setEnabled(hasKey && settings.consent);
    ol->addWidget(test);
    setRow(al, "Model and language", {}, opts);
    auto *testResult = text({}, "small", true);
    testResult->setObjectName("explain-test-result");
    testResult->hide();
    al->addWidget(testResult);
    l->addWidget(ai);

    const auto store = [consent, model, language, automatic, provider] {
        // Con el desplegable ya en otro proveedor (la página se está rearmando), estos controles son del anterior.
        if (Explain::providerOf(model->currentText()) != provider) return;
        auto next = Explain::Settings::load();
        next.consent = consent->isChecked();
        next.model = model->currentText();
        next.language = language->currentIndex() == 1 ? "es" : "en";
        next.automatic = automatic->isChecked();
        next.save();
    };
    connect(consent, &ToggleSwitch::toggled, this, [this, store, test, provider](bool on) {
        store();
        test->setEnabled(on && Explain::KeyStore::has(provider));
        updateSidebar();
    });
    connect(automatic, &ToggleSwitch::toggled, this, store);
    connect(model, &QComboBox::currentTextChanged, this, [this, store, provider](const QString &chosen) {
        // Otro proveedor tiene su propia key y su propio consentimiento: la página se rearma para mostrarlos.
        if (Explain::providerOf(chosen) != provider) {
            Explain::Settings::saveModel(chosen);
            QTimer::singleShot(0, this, [this] { render(true); });
            return;
        }
        store();
        updateSidebar();
    });
    connect(language, &QComboBox::currentIndexChanged, this, store);
    connect(saveKey, &QPushButton::clicked, this, [this, key, provider, providerName] {
        QString error;
        if (!Explain::KeyStore::save(provider, key->text().trimmed(), error)) {
            message(error);
            return;
        }
        key->clear();
        message(providerName + " key saved for this Windows account.");
        render(true);
    });
    connect(removeKey, &QPushButton::clicked, this, [this, provider, providerName] {
        QString error;
        if (!Explain::KeyStore::clear(provider, error)) {
            message(error);
            return;
        }
        message(providerName + " key removed.");
        render(true);
    });
    connect(test, &QPushButton::clicked, this, [test, testResult, providerName] {
        // La prueba también manda datos: exige el consentimiento y la key vigentes, no los de cuando se armó la página.
        const auto current = Explain::Settings::load();
        const auto allowed = [] {
            const auto s = Explain::Settings::load();
            return s.consent && Explain::KeyStore::has(Explain::providerOf(s.model));
        };
        test->setEnabled(false);
        if (!allowed()) return;
        testResult->show();
        testResult->setText("Asking " + providerName + " about notepad.exe…");
        const QString notepad = QDir::fromNativeSeparators(qEnvironmentVariable("SystemRoot") + "\\System32\\notepad.exe");
        const auto facts = Explain::collectFacts(notepad, "Microsoft Windows", {}, 0, 6, 1);
        QPointer<QLabel> result(testResult);
        QPointer<QPushButton> again(test);
        // Hilo suelto, como las explicaciones: salir de la app no espera esta prueba.
        std::thread([facts, current, result, again, allowed] {
            Explain::Answer answer;
            QString error;
            qint64 ms = 0;
            const bool ok = Explain::explainNow(facts, current.model, current.language, answer, error, &ms);
            if (!QCoreApplication::instance()) return;
            QMetaObject::invokeMethod(
                QCoreApplication::instance(),
                [ok, answer, error, ms, result, again, allowed] {
                    if (again) again->setEnabled(allowed());
                    if (!result) return;
                    result->setText(ok ? QString("Working · %1 s · %2").arg(ms / 1000.0, 0, 'f', 1).arg(answer.what)
                                       : "Not working: " + error);
                },
                Qt::QueuedConnection);
        }).detach();
    });

    auto *imp = card();
    auto *ih = new QHBoxLayout(imp);
    ih->setContentsMargins(18, 15, 18, 16);
    ih->setSpacing(14);
    auto *it = new QVBoxLayout;
    it->setSpacing(2);
    it->addWidget(text("Import from NetLimiter", "strong"));
    it->addWidget(text("Turns NetLimiter firewall rules for single applications into GateBouncer rules.", "small", true));
    ih->addLayout(it, 1);
    auto *openImport = button("Choose file…");
    openImport->setObjectName("open-import");
    connect(openImport, &QPushButton::clicked, this, [this] { selectView("import"); });
    ih->addWidget(openImport);
    l->addWidget(imp);

    // Colofón (`.colophon`), como General de Mighty Tools: logo, nombre, autor y cómo arranca la ventana. El arranque
    // al iniciar sesión lo registra el motor al instalarse (HKLM Run, para todos los usuarios).
    l->addSpacing(14);
    l->addWidget(divider());
    l->addSpacing(6);
    auto *colophon = row(14);
    auto *logo = new QLabel;
    logo->setPixmap(QIcon(":/gatebouncer/resources/icons/LGA_GateBouncer.png").pixmap(QSize(40, 40), devicePixelRatioF()));
    colophon->addWidget(logo, 0, Qt::AlignTop);
    auto *cv = new QVBoxLayout;
    cv->setSpacing(2);
    auto *ct = row(8);
    auto *cn = text("LGA GateBouncer", "cardtitle");
    cn->setFont(Theme::titleFont(15, 700));
    ct->addWidget(cn);
    ct->addWidget(text("Development build", "sub"));
    ct->addStretch();
    cv->addLayout(ct);
    auto *by = row(4);
    by->addWidget(text("Developed by Lega Pugliese ·", "sub"));
    auto *site = button("lega.com.ar", "link");
    site->setObjectName("settings-site");
    connect(site, &QPushButton::clicked, this, [] { QDesktopServices::openUrl(QUrl("https://lega.com.ar")); });
    by->addWidget(site);
    by->addStretch();
    cv->addLayout(by);
    cv->addWidget(text("Opens at sign-in, minimized to the tray. Closing the window hides it; the firewall keeps "
                       "working either way.",
                       "sub", true));
    colophon->addLayout(cv, 1);
    l->addLayout(colophon);
    l->addStretch();
    return page;
}

QWidget *FirewallWindow::importPage() {
    // QA: un archivo de NetLimiter de prueba sin pasar por el diálogo.
    if (netLimiterFile_.isEmpty() && !qEnvironmentVariableIsEmpty("GATEBOUNCER_QA_NETLIMITER")) {
        netLimiterFile_ = qEnvironmentVariable("GATEBOUNCER_QA_NETLIMITER");
        QFile input(netLimiterFile_);
        QString error;
        if (input.open(QIODevice::ReadOnly)) netLimiterRules_ = NetLimiterRules::read(input, error);
    }
    auto *page = new QWidget;
    auto *l = column(page, 28, 12);
    l->setContentsMargins(28, 24, 28, 28);
    auto *back = button("‹ Settings", "link");
    connect(back, &QPushButton::clicked, this, [this] { selectView("settings"); });
    auto *bl = row();
    bl->addWidget(back);
    bl->addStretch();
    l->addLayout(bl);
    int importable = 0;
    for (const auto &r : netLimiterRules_) importable += r.importable && !firewall_.ruleFor(r.path);
    l->addWidget(header("Import from NetLimiter",
                        netLimiterFile_.isEmpty() ? QString("NetLimiter keeps its rules in nl_settings.xml.")
                                                  : QString("%1 · %2 NetLimiter rules · %3 can be imported")
                                                        .arg(QFileInfo(netLimiterFile_).fileName())
                                                        .arg(netLimiterRules_.size())
                                                        .arg(importable)));
    auto *choose = card();
    auto *ch = new QHBoxLayout(choose);
    ch->setContentsMargins(18, 15, 18, 16);
    auto *ct = text(netLimiterFile_.isEmpty() ? QString("No file chosen.") : QDir::toNativeSeparators(netLimiterFile_),
                    "small", true);
    ch->addWidget(ct, 1);
    auto *pick = button("Choose file…");
    pick->setObjectName("netlimiter-choose");
    ch->addWidget(pick);
    l->addWidget(choose);
    connect(pick, &QPushButton::clicked, this, [this] {
        auto *dialog = new QFileDialog(this, "Choose NetLimiter settings file", NetLimiterRules::defaultFolder(),
                                       "NetLimiter settings (nl_settings.xml *.xml);;All files (*)");
        dialog->setObjectName("netlimiter-file-dialog");
        dialog->setOption(QFileDialog::DontUseNativeDialog);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setFileMode(QFileDialog::ExistingFile);
        connect(dialog, &QFileDialog::fileSelected, this, [this](const QString &path) {
            QFile input(path);
            QString error;
            netLimiterFile_ = path;
            netLimiterRules_.clear();
            if (!input.open(QIODevice::ReadOnly)) error = "The file could not be opened.";
            else netLimiterRules_ = NetLimiterRules::read(input, error);
            if (!error.isEmpty()) message(error);
            render();
        });
        dialog->open();
    });
    if (!netLimiterRules_.isEmpty()) {
        auto *c = card();
        auto *cl = cardColumn(c, 0);
        auto *grid = new QGridLayout;
        grid->setHorizontalSpacing(12);
        grid->setVerticalSpacing(0);
        grid->setColumnStretch(0, 3);
        grid->setColumnStretch(1, 2);
        grid->setColumnStretch(2, 2);
        int gr = 0;
        for (const auto &h : {QString("APPLICATION"), QString("NETLIMITER RULE"), QString("IN GATEBOUNCER")}) {
            auto *x = text(h, "colhead");
            x->setContentsMargins(0, 0, 0, 8);
            grid->addWidget(x, gr, grid->count() % 3);
        }
        ++gr;
        for (int i = 0; i < netLimiterRules_.size() && i < 500; ++i) {
            const auto &r = netLimiterRules_[i];
            const auto *existing = r.path.isEmpty() ? nullptr : firewall_.ruleFor(r.path);
            auto *line = divider();
            grid->addWidget(line, gr++, 0, 1, 3);
            auto *app = new QWidget;
            auto *av = new QVBoxLayout(app);
            av->setContentsMargins(0, 8, 0, 8);
            av->setSpacing(2);
            av->addWidget(text(r.path.isEmpty() ? r.ruleName : QFileInfo(r.path).fileName(), "body"));
            if (!r.path.isEmpty()) {
                auto *p = text(QDir::toNativeSeparators(QFileInfo(r.path).path()), "small");
                CustomTooltip::instance()->setToolTip(p, QDir::toNativeSeparators(r.path).toHtmlEscaped());
                av->addWidget(p);
            }
            grid->addWidget(app, gr, 0);
            grid->addWidget(text(r.action + (r.ruleName.isEmpty() ? QString() : " · " + r.ruleName), "body", true), gr, 1);
            const QString state = existing ? QString("Already has a rule (%1)").arg(existing->allow ? "Allow" : "Block")
                                  : r.importable ? QString(r.allow ? "Will be allowed" : "Will be blocked")
                                                 : "Not imported: " + r.reason;
            grid->addWidget(text(state, r.importable && !existing ? "body" : "sub", true), gr, 2);
            ++gr;
        }
        cl->addLayout(grid);
        cl->addSpacing(8);
        cl->addWidget(divider());
        cl->addSpacing(10);
        cl->addWidget(text("Rules limited to addresses, ports, zones or schedules, Ask rules and incoming-only rules are "
                           "listed and not imported. Nothing changes until you import.",
                           "faint", true));
        l->addWidget(c);
    }
    auto *actions = row(8);
    actions->addStretch();
    auto *cancel = button("Cancel");
    connect(cancel, &QPushButton::clicked, this, [this] { selectView("settings"); });
    actions->addWidget(cancel);
    auto *run = button(importable == 1 ? QString("Import 1 rule") : QString("Import %1 rules").arg(importable), "primary");
    run->setObjectName("netlimiter-import");
    run->setEnabled(importable > 0 && canDecide());
    actions->addWidget(run);
    connect(run, &QPushButton::clicked, this, [this] {
        int sent = 0;
        for (const auto &r : netLimiterRules_)
            if (r.importable && !firewall_.ruleFor(r.path)) {
                firewall_.decide(r.path, r.allow, "path", "always");
                ++sent;
            }
        message(QString("Importing %1 rules from NetLimiter…").arg(sent));
    });
    l->addLayout(actions);
    l->addStretch();
    return page;
}

// ------------------------------------------------------------------------------------------------------------------
// Aviso fijo: uno por vez, el pedido más viejo que no se cerró.

void FirewallWindow::closeToast() {
    if (!toast_) return;
    toast_->close();
    toast_->deleteLater();
    toast_.clear();
}

void FirewallWindow::updateToast() {
    const auto &pending = firewall_.pending();
    if (closing_ || !firewall_.status().connected) {
        closeToast();
        return;
    }
    // Lo cerrado que ya no está pendiente se olvida: si la app vuelve a pedir, se avisa de nuevo.
    QSet<QString> waiting;
    for (const auto &p : pending) waiting.insert(p.id.toLower());
    dismissed_.intersect(waiting);
    const auto showable = [this](const FirewallClient::PendingItem &p) { return !dismissed_.contains(p.id.toLower()); };
    if (toast_ && !firewall_.pendingById(toast_->id())) closeToast();
    const FirewallClient::PendingItem *current = toast_ ? firewall_.pendingById(toast_->id()) : nullptr;
    if (!current)
        for (const auto &p : pending)
            if (showable(p) && (!current || p.first < current->first)) current = &p;
    if (!current) return;
    if (!toast_) {
        toast_ = new AccessToast;
        connect(toast_, &AccessToast::decided, this,
                [this](const QString &id, bool allow, const QString &scope, const QString &duration,
                       const QString &destination) {
            const auto *p = firewall_.pendingById(id);
            if (p) firewall_.decide(p->path, allow, scope, duration, destination);
            // Se oculta ya: si la decisión falla, el pedido sigue pendiente y vuelve a aparecer.
            closeToast();
            dismissed_.insert(id.toLower());
            QTimer::singleShot(1500, this, [this, id] {
                dismissed_.remove(id.toLower());
                updateToast();
            });
            updateToast();
        });
        connect(toast_, &AccessToast::dismissed, this, [this](const QString &id) {
            dismissed_.insert(id.toLower());
            closeToast();
            updateToast();
        });
        connect(toast_, &AccessToast::openRequested, this, &FirewallWindow::bringToFront);
        connect(toast_, &AccessToast::pendingListRequested, this, [this] {
            bringToFront();
            selectView("requests");
        });
        connect(toast_, &AccessToast::explainRequested, this, [this](const QString &id) { explain(id, false); });
        connect(toast_, &AccessToast::settingsRequested, this, [this] {
            bringToFront();
            selectView("settings");
        });
    }
    int others = 0;
    for (const auto &p : pending)
        if (showable(p) && p.id.compare(current->id, Qt::CaseInsensitive) != 0) ++others;
    const bool newApp = toast_->id().compare(current->id, Qt::CaseInsensitive) != 0;
    AccessToast::Request request;
    request.id = current->id;
    request.perDestination = current->perDestination;
    request.path = current->path;
    request.signer = current->signer;
    request.attempts = current->attempts;
    request.othersWaiting = others;
    request.canDecide = canDecide();
    request.remote = current->remote;
    request.host = current->host;
    request.port = current->port;
    request.protocol = current->protocol;
    request.known = KnownApps::hint(current->signer, current->path, current->host);
    request.launchedBy = launchedBy(*current);
    if (current->perDestination)
        for (const auto &r : firewall_.rules())
            if (!r.destination.isEmpty() &&
                (r.path.compare(current->path, Qt::CaseInsensitive) == 0 ||
                 (r.scope == "app" && r.signer == current->signer &&
                  r.name.compare(FirewallClient::fileName(current->path), Qt::CaseInsensitive) == 0)))
                ++request.serverRules;
    toast_->setRequest(request);
    // El nombre del servidor llega por DNS un instante después del bloqueo: sin él, se espera antes de preguntar.
    if (newApp && current->host.isEmpty())
        QTimer::singleShot(1500, this, [this, id = current->id] {
            if (toast_ && toast_->id().compare(id, Qt::CaseInsensitive) == 0) explain(id, true);
        });
    else if (newApp) explain(current->id, true);
    if (!toast_->isVisible()) {
        toast_->placeOn(isVisible() ? screen() : nullptr);
        toast_->show();
    }
}

// id: el pedido (la ruta, o «ruta|dirección» en modo por destino): la explicación de un destino no se usa para otro.
void FirewallWindow::explain(const QString &id, bool automatic) {
    // Un pedido que ya no está (resuelto, motor caído) no se explica: su id no es una ruta.
    const auto *p = firewall_.pendingById(id);
    if (!p) return;
    const QString path = p->path;
    AccessToast::Explanation e;
    const auto settings = Explain::Settings::load();
    if (!Explain::qaFixture() && (!Explain::KeyStore::has(Explain::providerOf(settings.model)) || !settings.consent)) {
        e.state = AccessToast::Explanation::NoKey;
    } else if (const auto *hit = explainer_.cached(id)) {
        e = {AccessToast::Explanation::Ready, hit->what, hit->why, hit->risk, hit->suggestion, hit->reason, hit->model, {}};
    } else if (explainer_.busy(id)) {
        e.state = AccessToast::Explanation::Working;
    } else if (automatic && !settings.automatic) {
        // Al aparecer el aviso sólo se pregunta solo si el usuario lo eligió; si no, queda el botón.
        const auto failed = explainErrors_.constFind(id.toLower());
        if (failed != explainErrors_.constEnd()) e = {AccessToast::Explanation::Failed, {}, {}, {}, {}, {}, {}, *failed};
    } else {
        auto facts = Explain::collectFacts(path, p->signer, p->remote, p->port, p->protocol, p->attempts, p->host);
        facts.id = id;
        QString error;
        if (explainer_.request(facts, error)) {
            e.state = AccessToast::Explanation::Working;
        } else {
            e.state = AccessToast::Explanation::Failed;
            e.error = error;
            explainErrors_.insert(id.toLower(), error);
        }
    }
    if (toast_) toast_->setExplanation(id, e);
    ++explainVersion_;
    engineChanged();
}

// ------------------------------------------------------------------------------------------------------------------
// Bandeja, cierre y arrastre de la ventana sin marco.

void FirewallWindow::bringToFront() {
    if (lifecycle_) lifecycle_->openWindow();
    else showNormal();
    raise();
    activateWindow();
}

void FirewallWindow::startLifecycle(std::unique_ptr<Lifecycle::TraySurface> tray, bool minimized) {
    if (lifecycle_ || closing_) return;
    lifecycle_ = new Lifecycle::LifecycleController(this, std::move(tray), windowIcon(), this);
    connect(lifecycle_, &Lifecycle::LifecycleController::pendingRequested, this, [this] { selectView("requests"); });
    connect(lifecycle_, &Lifecycle::LifecycleController::settingsRequested, this, [this] { selectView("settings"); });
    connect(lifecycle_, &Lifecycle::LifecycleController::quitRequested, this, &FirewallWindow::requestQuit);
    updateLifecycle();
    lifecycle_->start(minimized);
}

void FirewallWindow::updateLifecycle() {
    if (!lifecycle_) return;
    // El estado y el contador salen del canal del motor.
    const auto &s = firewall_.status();
    Lifecycle::EngineSnapshot snapshot;
    snapshot.simulation = false;
    snapshot.current = s.connected;
    snapshot.state = s.connected ? Lifecycle::EngineState::Active : Lifecycle::EngineState::Unavailable;
    snapshot.asking = s.ask;
    snapshot.pendingCount = quint64(firewall_.pending().size());
    lifecycle_->applyEngineSnapshot(snapshot);
}

void FirewallWindow::requestQuit() {
    if (closing_) return;
    closing_ = true;
    closeToast();
    firewall_.setActive(false);
    QTimer::singleShot(0, this, &FirewallWindow::finishQuit);
}

void FirewallWindow::finishQuit() {
    if (lifecycle_) lifecycle_->finishGuiShutdown();
    close();
    QApplication::quit();
}

bool FirewallWindow::eventFilter(QObject *object, QEvent *event) {
    if (object->objectName() == "fwTitle") {
        // El arrastre lo hace Windows: así la ventana se acomoda contra los costados y arriba se maximiza.
        if (event->type() == QEvent::MouseButtonPress && static_cast<QMouseEvent *>(event)->button() == Qt::LeftButton) {
            if (windowHandle()) windowHandle()->startSystemMove();
            return true;
        }
        if (event->type() == QEvent::MouseButtonDblClick) {
            isMaximized() ? showNormal() : showMaximized();
            return true;
        }
    }
    return QMainWindow::eventFilter(object, event);
}

void FirewallWindow::showEvent(QShowEvent *event) {
    if (!shownOnce_) {
        shownOnce_ = true;
        // La bandera va antes de apply(): WM_NCCALCSIZE llega en el acto.
        frameApplied_ = true;
        frameApplied_ = WindowFrame::apply(this, true);
    }
    QMainWindow::showEvent(event);
}

void FirewallWindow::hideEvent(QHideEvent *event) {
    // El tamaño que dejó el usuario, para la próxima vez (maximizada, el de antes de maximizar).
    if (shownOnce_ && rememberSizes()) {
        auto store = tableStore();
        store.setValue("window/size", normalGeometry().size());
    }
    QMainWindow::hideEvent(event);
}

bool FirewallWindow::nativeEvent(const QByteArray &eventType, void *message, qintptr *result) {
    if (frameApplied_ && WindowFrame::handleNativeEvent(message, result)) return true;
    return QMainWindow::nativeEvent(eventType, message, result);
}

} // namespace Gate
