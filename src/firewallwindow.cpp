#include "firewallwindow.h"
#include "appicon.h"
#include "explain/KnownApps.h"
#include "platform/WindowFrame.h"
#include "toggleswitch.h"
#include <QAbstractButton>
#include <QApplication>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSettings>
#include <QShowEvent>
#include <QTableWidget>
#include <QWindow>
#include <QVBoxLayout>
#include <thread>
#include <windows.h>
#include <tlhelp32.h>

namespace Gate {

// ------------------------------------------------------------------------------------------------------------------
// Piezas de la ventana: estilo, íconos y controles chicos.

namespace {

// Tokens de Mighty Tools (+Building_Blocks/canvas/window_layouts/mockup.html) y los de estado de GateBouncer.
const char *kStyle = R"(
QWidget#fwRoot, QWidget#fwWorkspace, QWidget#fwPage { background: #161616; }
QFrame#fwTitle { background: #101010; border-bottom: 1px solid #242424; }
QFrame#fwSide { background: #131313; border-right: 1px solid #292929; }
QScrollArea#fwScroll { background: #161616; border: 0; }
QLabel { background: transparent; }
QLabel[r="title"] { color: #e6e6e6; font-size: 16px; font-weight: 600; }
QLabel[r="desc"] { color: #858585; font-size: 13px; }
QLabel[r="cardtitle"] { color: #cccccc; font-size: 14px; font-weight: 600; }
QLabel[r="strong"] { color: #d2d2d2; font-size: 13px; font-weight: 500; }
QLabel[r="body"] { color: #c8c8c8; font-size: 13px; }
QLabel[r="sub"] { color: #888888; font-size: 12px; }
QLabel[r="small"] { color: #7c7c7c; font-size: 12px; }
QLabel[r="faint"] { color: #747474; font-size: 12px; }
QLabel[r="colhead"] { color: #6f6f6f; font-size: 11px; }
QLabel[r="section"] { color: #777777; font-size: 11px; }
QLabel[r="appname"] { color: #929292; font-size: 13px; }
QLabel[r="stat"] { color: #dddddd; font-size: 22px; font-weight: 600; }
QLabel[r="ok"] { color: #a8d86a; font-size: 12px; }
QLabel[r="warn"] { color: #d4a437; font-size: 12px; }
QLabel[r="bad"] { color: #e0796b; font-size: 12px; }
QLabel[r="time"] { color: #777777; font-size: 12px; }
QFrame[r="card"] { background: #1d1d1d; border-radius: 8px; }
QFrame[r="alert"] { background: #2a1d1b; border: 1px solid #4d2c27; border-radius: 8px; }
QFrame[r="ai"] { background: #222127; border: 1px solid #2f2c3a; border-radius: 8px; }
QFrame[r="aierr"] { background: #261d1c; border: 1px solid #43302d; border-radius: 8px; }
QFrame[r="aiquiet"] { background: #1f1f1f; border: 1px solid #2c2c2c; border-radius: 8px; }
QFrame[r="divider"] { background: #2a2a2a; }
QFrame[r="seg"] { background: #1a1a1a; border: 1px solid #333333; border-radius: 5px; }
QFrame#fwMessage { background: #25212f; border: 1px solid #4b3e66; border-radius: 6px; }
QLabel[pill="allow"] { background: #25301c; color: #bfe08f; border-radius: 9px; padding: 2px 8px; font-size: 11px; font-weight: 500; }
QLabel[pill="block"] { background: #3a2220; color: #f0a497; border-radius: 9px; padding: 2px 8px; font-size: 11px; font-weight: 500; }
QLabel[pill="temp"] { background: #2c2540; color: #c9b8f5; border-radius: 9px; padding: 2px 8px; font-size: 11px; font-weight: 500; }
QLabel[pill="dest"] { background: #262626; color: #bbbbbb; border-radius: 9px; padding: 2px 8px; font-size: 11px; font-weight: 500; }
QLabel[pill="none"] { background: #232323; color: #999999; border-radius: 9px; padding: 2px 8px; font-size: 11px; font-weight: 500; }
QLabel[hint="block"] { border: 1px solid #6a3a33; color: #e7a196; border-radius: 9px; padding: 1px 8px; font-size: 11px; }
QLabel[hint="allow"] { border: 1px solid #4c6233; color: #b5d88b; border-radius: 9px; padding: 1px 8px; font-size: 11px; }
QLabel[hint="either"] { border: 1px solid #444444; color: #aaaaaa; border-radius: 9px; padding: 1px 8px; font-size: 11px; }
QLabel[hint="known"] { border: 1px solid #33475f; color: #9cc0ee; border-radius: 9px; padding: 1px 8px; font-size: 11px; }
QLabel[hint="none"] { border: 1px dashed #444444; color: #777777; border-radius: 9px; padding: 1px 8px; font-size: 11px; }
QLabel[chip="1"] { background: #262626; border: 1px solid #333333; color: #aaaaaa; border-radius: 4px; padding: 1px 6px; font-size: 11px; }
QLabel#fwBadge { background: #4a3a14; color: #f0c75e; border-radius: 9px; font-size: 11px; font-weight: 600; }
QPushButton { border: 0; border-radius: 5px; background: #2b2b2b; color: #c4c4c4; padding: 0 12px; min-height: 29px; font-size: 13px; }
QPushButton:hover { background: #333333; }
QPushButton:disabled { color: #656565; background: #212121; }
QPushButton[k="primary"] { background: #443a91; color: #eeeeee; font-weight: 600; }
QPushButton[k="primary"]:hover { background: #4e43a3; }
QPushButton[k="allow"] { background: #25301c; color: #c9e6a4; border: 1px solid #45592f; }
QPushButton[k="allow"]:hover { background: #2c3a21; }
QPushButton[k="block"] { background: #3a2220; color: #f2b2a8; border: 1px solid #5e3530; }
QPushButton[k="block"]:hover { background: #452826; }
QPushButton[k="allow"][rec="1"] { border: 1px solid #7ea653; color: #e3f6c8; }
QPushButton[k="block"][rec="1"] { border: 1px solid #a8564b; color: #ffd0c8; }
QPushButton[k="allow"]:disabled, QPushButton[k="block"]:disabled { background: #212121; color: #656565; border: 1px solid #2a2a2a; }
QPushButton[k="link"] { background: transparent; color: #aa95ed; padding: 0; min-height: 0; font-size: 13px; }
QPushButton[k="link"]:hover { color: #c3b4f5; }
QPushButton[k="chrome"] { background: transparent; color: #777777; border-radius: 0; padding: 0; min-height: 34px; min-width: 39px; font-size: 15px; }
QPushButton[k="chrome"]:hover { background: #1e1e1e; color: #cccccc; }
QPushButton[k="seg"] { background: transparent; color: #999999; border-radius: 4px; min-height: 24px; padding: 0 9px; font-size: 12px; }
QPushButton[k="seg"][on="1"] { background: #302a49; color: #eeeeee; }
QPushButton[k="x"] { background: transparent; color: #777777; padding: 0; min-height: 22px; min-width: 22px; font-size: 14px; }
QPushButton[k="x"]:hover { color: #e0796b; }
QPushButton[sm="1"] { min-height: 25px; padding: 0 10px; font-size: 12px; }
QPushButton:focus { outline: none; }
QLineEdit { background: #1a1a1a; border: 1px solid #353535; border-radius: 5px; color: #d4d4d4; padding: 0 9px; min-height: 28px; font-size: 13px; }
QLineEdit:focus { border: 1px solid #774dcb; }
QComboBox { background: #1a1a1a; border: 1px solid #353535; border-radius: 4px; color: #d0d0d0; padding: 0 26px 0 9px; min-height: 27px; font-size: 13px; }
QComboBox:disabled { color: #656565; }
QComboBox::drop-down { border: 0; width: 22px; }
QComboBox::down-arrow { image: none; }
QComboBox QAbstractItemView { background: #1d1d1d; selection-background-color: #393455; border: 1px solid #39333f; }
QTableWidget#fwTable { background: transparent; border: 0; outline: 0; }
QTableWidget#fwTable::item { border: 0; border-bottom: 1px solid #272727; padding: 0; }
QTableWidget#fwTable::item:hover { background: #222222; }
QHeaderView { background: #191919; border: 0; }
QHeaderView::section { background: #191919; color: #8d8d8d; border: 0; border-bottom: 1px solid #343434; border-right: 1px solid #292929; padding: 0 12px; min-height: 31px; font-size: 11px; font-weight: 600; }
QHeaderView::section:hover { background: #202020; color: #c2c2c2; }
QHeaderView::section:last { border-right: 0; }
QScrollBar:vertical { width: 8px; background: transparent; margin: 0; }
QScrollBar::handle:vertical { background: #3c3a41; border-radius: 3px; min-height: 25px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QScrollBar:horizontal { height: 8px; background: transparent; margin: 0; }
QScrollBar::handle:horizontal { background: #3c3a41; border-radius: 3px; min-width: 25px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: transparent; }
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
    l->setFixedHeight(19);
    return l;
}
QLabel *hint(const QString &value, const char *kind) {
    auto *l = new QLabel(value);
    l->setProperty("hint", kind);
    l->setTextFormat(Qt::PlainText);
    l->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
    l->setFixedHeight(19);
    return l;
}
QLabel *chip(const QString &value) {
    auto *l = new QLabel(value);
    l->setProperty("chip", "1");
    l->setTextFormat(Qt::PlainText);
    l->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
    l->setFixedHeight(19);
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
    void paintEvent(QPaintEvent *event) override {
        QComboBox::paintEvent(event);
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.setPen(QPen(QColor(isEnabled() ? "#8f8f8f" : "#656565"), 1.2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        const QPointF c(width() - 12, height() / 2.0);
        QPainterPath chevron;
        chevron.moveTo(c + QPointF(-3, -1.5));
        chevron.lineTo(c + QPointF(0, 1.5));
        chevron.lineTo(c + QPointF(3, -1.5));
        p.drawPath(chevron);
    }
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
        const QString tip = shown == text() ? QString() : text();
        if (toolTip() != tip) const_cast<ElideLabel *>(this)->setToolTip(tip);
    }

  private:
    Qt::TextElideMode mode_;
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
    h->setFixedHeight(32);
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
    l->setContentsMargins(12, 0, 12, 0);
    l->setSpacing(10);
    if (align & Qt::AlignRight) l->addStretch();
    l->addWidget(content, align & (Qt::AlignRight | Qt::AlignHCenter) ? 0 : 1);
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

// Caja del encabezado de cada sección (38 x 38, como en Mighty Tools).
QLabel *headIcon(const QString &name) {
    auto *l = new QLabel;
    l->setFixedSize(38, 38);
    l->setAlignment(Qt::AlignCenter);
    l->setStyleSheet("background: #1f1d27; border: 1px solid #312c42; border-radius: 8px;");
    l->setPixmap(iconPixmap(name, 20, QColor("#b9a5eb"), qApp->devicePixelRatio()));
    return l;
}

// Ícono real del programa (el de Windows), en una caja chica; si no hay archivo, uno genérico.
QLabel *appIcon(const QString &path, int box = 30) {
    auto *l = new QLabel;
    l->setFixedSize(box, box);
    l->setAlignment(Qt::AlignCenter);
    l->setStyleSheet(QString("background: #242424; border-radius: %1px;").arg(box >= 36 ? 9 : 7));
    l->setPixmap(appIconPixmap(path, box >= 36 ? 24 : 20, qApp->devicePixelRatio()));
    return l;
}

// Encabezado de una sección: ícono, título y descripción; a la derecha, lo que se pase.
QWidget *header(QWidget *icon, const QString &title, const QString &description, QWidget *right = nullptr) {
    auto *w = new QWidget;
    auto *h = new QHBoxLayout(w);
    h->setContentsMargins(2, 0, 0, 2);
    h->setSpacing(11);
    h->addWidget(icon, 0, Qt::AlignTop);
    auto *t = new QVBoxLayout;
    t->setSpacing(3);
    t->addWidget(text(title, "title"));
    auto *d = text(description, "desc", true);
    t->addWidget(d);
    h->addLayout(t, 1);
    if (right) h->addWidget(right, 0, Qt::AlignTop);
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
    if (p.signer.isEmpty()) return {{"This file only", "path"}};
    QVector<QPair<QString, QString>> s{{"This app, any version", "app"}, {"This file only", "path"}};
    if (FirewallClient::publisherRuleAllowed(p.signer)) s.push_back({"All apps from " + p.signer, "publisher"});
    return s;
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
QString activityChip(const QString &kind) {
    if (kind.startsWith("Blocked by rule")) return "Your Block rule";
    if (kind.contains("waiting", Qt::CaseInsensitive)) return "Waiting for you";
    return kind;
}
const QString kHelp =
    "GateBouncer asks before an application connects to the internet for the first time. Its first attempt is "
    "blocked; Allow lets the next one connect.\n\nThe engine (GateBouncerEngine.exe) runs as a Windows service and "
    "keeps your rules even when this window is closed. Closing the window hides it in the tray; Quit in the tray "
    "menu exits it.\n\nTo turn GateBouncer off completely, run GateBouncerEngine.exe --remove-filters from an "
    "administrator command prompt.";

} // namespace

// Fila de la barra lateral: ícono, nombre, línea de estado y, en Requests, el contador.
class SideItem final : public QWidget {
  public:
    SideItem(const QString &icon, const QString &title, QWidget *parent = nullptr) : QWidget(parent), icon_(icon) {
        setFixedHeight(42);
        setCursor(Qt::PointingHandCursor);
        setAttribute(Qt::WA_Hover);
        auto *h = new QHBoxLayout(this);
        h->setContentsMargins(37, 0, 9, 0);
        h->setSpacing(8);
        auto *v = new QVBoxLayout;
        v->setSpacing(1);
        title_ = text(title, "body");
        status_ = new QLabel;
        status_->setTextFormat(Qt::PlainText);
        v->addWidget(title_);
        v->addWidget(status_);
        h->addLayout(v, 1);
        badge_ = new QLabel;
        badge_->setObjectName("fwBadge");
        badge_->setAlignment(Qt::AlignCenter);
        badge_->setFixedHeight(19);
        badge_->setMinimumWidth(19);
        badge_->hide();
        h->addWidget(badge_);
    }
    std::function<void()> onClick;
    void setSelected(bool on) {
        selected_ = on;
        title_->setStyleSheet(on ? "color: #f0f0f0;" : "color: #b7b7b7;");
        update();
    }
    void setState(const QString &status, const QString &tone, int badge = 0) {
        status_->setText(status);
        const QString color = tone == "ok" ? "#a8d86a" : tone == "warn" ? "#d4a437" : tone == "bad" ? "#e0796b" : "#6f6f6f";
        status_->setStyleSheet("font-size: 11px; color: " + color + ";");
        badge_->setVisible(badge > 0);
        badge_->setText(QString::number(badge));
        badge_->setFixedWidth(qMax(19, badge_->fontMetrics().horizontalAdvance(badge_->text()) + 10));
    }

  protected:
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const bool hover = underMouse();
        if (selected_ || hover) {
            p.setPen(Qt::NoPen);
            p.setBrush(QColor(selected_ ? "#212027" : "#1b1b1f"));
            p.drawRoundedRect(rect(), 6, 6);
        }
        drawIcon(p, icon_, QRectF(9, (height() - 18) / 2.0, 18, 18), QColor("#ad99df"));
    }
    void mouseReleaseEvent(QMouseEvent *e) override {
        if (e->button() == Qt::LeftButton && rect().contains(e->position().toPoint()) && onClick) onClick();
    }
    void enterEvent(QEnterEvent *) override { update(); }
    void leaveEvent(QEvent *) override { update(); }

  private:
    QString icon_;
    bool selected_ = false;
    QLabel *title_ = nullptr, *status_ = nullptr, *badge_ = nullptr;
};

// ------------------------------------------------------------------------------------------------------------------

FirewallWindow::FirewallWindow(QWidget *parent) : QMainWindow(parent) {
    setObjectName("GateBouncer");
    setWindowTitle("LGA GateBouncer");
    setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
    setMinimumSize(900, 620);
    resize(tableStore().value("window/size", QSize(1100, 720)).toSize().expandedTo(minimumSize()));
    setStyleSheet(kStyle);
    buildShell();
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

    auto *bar = new QFrame;
    bar->setObjectName("fwTitle");
    bar->setFixedHeight(35);
    bar->installEventFilter(this);
    auto *bl = new QHBoxLayout(bar);
    bl->setContentsMargins(12, 0, 0, 0);
    bl->setSpacing(10);
    auto *logo = new QLabel;
    logo->setPixmap(QIcon(":/gatebouncer/resources/icons/tray/tray_32.png").pixmap(QSize(16, 16), devicePixelRatio()));
    bl->addWidget(logo);
    bl->addWidget(text("LGA GateBouncer", "appname"));
    bl->addStretch();
    const struct { const char *glyph, *name, *access; } chrome[] = {{"?", "help-window", "Help"},
                                                                    {"−", "minimize-window", "Minimize"},
                                                                    {"□", "maximize-window", "Maximize or restore"},
                                                                    {"×", "close-window", "Close to the tray"}};
    for (const auto &c : chrome) {
        auto *b = button(QString::fromUtf8(c.glyph), "chrome");
        b->setObjectName(c.name);
        b->setAccessibleName(c.access);
        b->setFocusPolicy(Qt::NoFocus);
        bl->addWidget(b);
        connect(b, &QPushButton::clicked, this, [this, name = QString(c.name)] {
            if (name == "help-window") showHelp();
            else if (name == "minimize-window") showMinimized();
            else if (name == "maximize-window") isMaximized() ? showNormal() : showMaximized();
            else close();
        });
    }
    rl->addWidget(bar);

    auto *shell = new QWidget;
    auto *sl = new QHBoxLayout(shell);
    sl->setContentsMargins(0, 0, 0, 0);
    sl->setSpacing(0);
    auto *side = new QFrame;
    side->setObjectName("fwSide");
    side->setFixedWidth(224);
    auto *sv = new QVBoxLayout(side);
    sv->setContentsMargins(8, 8, 8, 8);
    sv->setSpacing(1);
    const auto add = [this, sv](const QString &id, const QString &icon, const QString &title) {
        auto *item = new SideItem(icon, title);
        item->setObjectName("nav-" + id);
        item->onClick = [this, id] { selectView(id); };
        side_.insert(id, item);
        sv->addWidget(item);
    };
    const auto label = [sv](const QString &t) {
        auto *l = text(t, "section");
        l->setContentsMargins(8, 12, 0, 7);
        QFont f = l->font();
        f.setLetterSpacing(QFont::AbsoluteSpacing, 0.8);
        l->setFont(f);
        sv->addWidget(l);
    };
    add("overview", "shield", "Protection");
    label("FIREWALL");
    add("requests", "bell", "Requests");
    add("apps", "apps", "Apps");
    add("activity", "pulse", "Activity");
    label("APP");
    add("settings", "gear", "Settings");
    sv->addStretch();
    sl->addWidget(side);

    workspace_ = new QWidget;
    workspace_->setObjectName("fwWorkspace");
    auto *wl = new QVBoxLayout(workspace_);
    wl->setContentsMargins(0, 0, 0, 0);
    wl->setSpacing(0);
    scroll_area_ = new QScrollArea;
    scroll_area_->setObjectName("fwScroll");
    scroll_area_->setWidgetResizable(true);
    scroll_area_->setFrameShape(QFrame::NoFrame);
    scroll_area_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
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
    mwl->setContentsMargins(18, 0, 18, 12);
    mwl->addWidget(message_);
    wl->addWidget(mw);
    sl->addWidget(workspace_, 1);
    rl->addWidget(shell, 1);
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

void FirewallWindow::showHelp() {
    auto *d = new QDialog(this, Qt::Dialog | Qt::FramelessWindowHint);
    d->setAttribute(Qt::WA_DeleteOnClose);
    d->setStyleSheet("QDialog { background: #1e1e1e; border: 1px solid #3a3544; }");
    auto *l = column(d, 18, 10);
    l->addWidget(text("LGA GateBouncer", "cardtitle"));
    l->addWidget(text("Development build", "sub"));
    auto *body = text(kHelp, "body", true);
    body->setFixedWidth(420);
    l->addWidget(body);
    auto *ok = button("Close", "primary");
    auto *r = row();
    r->addStretch();
    r->addWidget(ok);
    l->addLayout(r);
    connect(ok, &QPushButton::clicked, d, &QDialog::close);
    d->open();
}

// ------------------------------------------------------------------------------------------------------------------
// Protection: el estado, lo que espera decisión y un resumen.

QWidget *FirewallWindow::overviewPage() {
    const auto &s = firewall_.status();
    auto *page = new QWidget;
    auto *l = column(page, 18, 10);
    l->setContentsMargins(18, 16, 18, 22);
    l->addWidget(header(headIcon("shield"), "Protection",
                        !s.connected ? "Without the engine, new applications cannot ask for access."
                        : s.ask      ? "Unknown applications are blocked until you decide."
                                     : "Unknown applications connect. Saved rules still apply."));

    auto *status = card(s.connected ? "card" : "alert");
    status->setObjectName("protection-status");
    auto *sh = new QHBoxLayout(status);
    sh->setContentsMargins(14, 12, 14, 12);
    sh->setSpacing(12);
    auto *dot = new QLabel;
    dot->setFixedSize(9, 9);
    const QString tone = !s.connected ? "#e0796b" : (s.ask && s.allApps) ? "#a8d86a" : "#d4a437";
    dot->setStyleSheet("background: " + tone + "; border-radius: 4px;");
    sh->addWidget(dot);
    auto *st = new QVBoxLayout;
    st->setSpacing(3);
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
    auto *stt = text(title, "cardtitle");
    st->addWidget(stt);
    st->addWidget(text(sub, "sub", true));
    sh->addLayout(st, 1);
    if (s.connected && !s.ask) {
        auto *on = button("Turn asking on");
        on->setEnabled(canDecide());
        connect(on, &QPushButton::clicked, this, [this] { firewall_.setAsk(true); });
        sh->addWidget(on);
    } else if (s.connected) {
        auto *go = button("Firewall settings");
        go->setObjectName("open-settings");
        connect(go, &QPushButton::clicked, this, [this] { selectView("settings"); });
        sh->addWidget(go);
    } else {
        auto *help = button("Help");
        connect(help, &QPushButton::clicked, this, &FirewallWindow::showHelp);
        sh->addWidget(help);
    }
    l->addWidget(status);

    if (s.connected) {
        auto pending = firewall_.pending();
        std::sort(pending.begin(), pending.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
        auto *wait = card();
        auto *wl = column(wait, 14, 0);
        auto *wh = row(8);
        wh->addWidget(text("Waiting for you", "cardtitle"));
        if (!pending.isEmpty()) {
            auto *count = text(QString::number(pending.size()), "colhead");
            count->setStyleSheet("border: 1px solid #333; border-radius: 4px; padding: 1px 6px; color: #888;");
            wh->addWidget(count);
        }
        wh->addStretch();
        if (!pending.isEmpty()) {
            auto *all = button("Review all", "link");
            all->setObjectName("review-all");
            connect(all, &QPushButton::clicked, this, [this] { selectView("requests"); });
            wh->addWidget(all);
        }
        wl->addLayout(wh);
        wl->addSpacing(6);
        if (pending.isEmpty()) {
            wl->addWidget(text("Nothing is waiting. A new application that tries to connect appears here and in a "
                               "notice.",
                               "sub", true));
        }
        const int shown = qMin<int>(4, pending.size());
        for (int i = 0; i < shown; ++i) {
            const auto p = pending[i];
            if (i) wl->addWidget(divider());
            auto *item = new QWidget;
            item->setMinimumHeight(52);
            auto *h = new QHBoxLayout(item);
            h->setContentsMargins(0, 7, 0, 7);
            h->setSpacing(11);
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
            auto *block = button("Block", "block", true);
            auto *allow = button("Allow", "allow", true);
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
            wl->addSpacing(4);
            wl->addWidget(divider());
            wl->addSpacing(10);
            auto *tip = new QLabel("Block and Allow here use the choices the notice would preselect: <b "
                                   "style='color:#aaa;font-weight:500'>this app, any version</b> when it is signed, <b "
                                   "style='color:#aaa;font-weight:500'>this file</b> when it is not, and <b "
                                   "style='color:#aaa;font-weight:500'>only that server</b> for an app that already has "
                                   "server rules. Open the request to choose another.");
            tip->setProperty("r", "faint");
            tip->setWordWrap(true);
            wl->addWidget(tip);
        }
        l->addWidget(wait);
    }

    auto *grid = new QHBoxLayout;
    grid->setSpacing(10);
    {
        auto *rc = card();
        auto *rl = column(rc, 14, 6);
        auto *rh = row();
        rh->addWidget(text("Rules", "cardtitle"));
        rh->addStretch();
        auto *open = button("Open Apps", "link");
        connect(open, &QPushButton::clicked, this, [this] { selectView("apps"); });
        rh->addWidget(open);
        rl->addLayout(rh);
        int allow = 0, block = 0, temporary = 0;
        const FirewallClient::RuleItem *soonest = nullptr;
        for (const auto &r : firewall_.rules()) {
            if (r.scope == "covered") continue;
            if (r.expires != 0) {
                ++temporary;
                if (r.expires > 0 && (!soonest || soonest->expires < 0 || r.expires < soonest->expires)) soonest = &r;
                else if (!soonest) soonest = &r;
            } else {
                r.allow ? ++allow : ++block;
            }
        }
        auto *stats = row(22);
        for (const auto &[n, name] : {std::pair{allow, "allow"}, {block, "block"}, {temporary, "temporary"}}) {
            auto *sv = row(5);
            sv->addWidget(text(QString::number(n), "stat"), 0, Qt::AlignBaseline);
            sv->addWidget(text(name, "sub"), 0, Qt::AlignBaseline);
            stats->addLayout(sv);
        }
        stats->addStretch();
        rl->addLayout(stats);
        if (soonest) {
            const QString who = soonest->scope == "app"         ? soonest->name
                                : soonest->scope == "publisher" ? "Apps from " + soonest->signer
                                                                : FirewallClient::fileName(soonest->path);
            rl->addWidget(text(QString("%1 can %2 %3.")
                                   .arg(who, soonest->allow ? "connect" : "stay blocked",
                                        soonest->expires < 0 ? QString("until restart")
                                                             : "until " + clock(soonest->expires)),
                               "sub", true));
        }
        rl->addStretch();
        grid->addWidget(rc, 1);
    }
    {
        auto *ac = card();
        auto *al = column(ac, 14, 0);
        auto *ah = row();
        ah->addWidget(text("Blocked recently", "cardtitle"));
        ah->addStretch();
        auto *open = button("Activity", "link");
        connect(open, &QPushButton::clicked, this, [this] { selectView("activity"); });
        ah->addWidget(open);
        al->addLayout(ah);
        al->addSpacing(4);
        int shown = 0;
        QSet<QString> listed; // una fila por app: los reintentos de la misma no tapan a las demás
        const auto &events = firewall_.activity();
        for (int i = events.size() - 1; i >= 0 && shown < 3; --i) {
            const auto &e = events[i];
            if (!e.kind.startsWith("Blocked") || e.path.isEmpty() || listed.contains(e.path.toLower())) continue;
            listed.insert(e.path.toLower());
            if (shown) al->addWidget(divider());
            auto *h = new QWidget;
            h->setMinimumHeight(38);
            auto *hl = new QHBoxLayout(h);
            hl->setContentsMargins(0, 4, 0, 4);
            auto *t = text(clock(e.time), "time");
            t->setFixedWidth(44);
            hl->addWidget(t);
            auto *what = new QLabel(FirewallClient::fileName(e.path).toHtmlEscaped() + " <span style='color:#8a8a8a'>· " +
                                    activityChip(e.kind).toLower().toHtmlEscaped() + "</span>");
            what->setProperty("r", "body");
            hl->addWidget(what, 1);
            al->addWidget(h);
            ++shown;
        }
        if (!shown) al->addWidget(text("Nothing blocked since the engine started.", "sub", true));
        al->addStretch();
        grid->addWidget(ac, 1);
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
    auto *l = column(c, 11, 7);
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
        l->addWidget(text(e.what, "body", true));
        l->addWidget(divider());
        for (const auto &[title, value] : {std::pair{QString("WHY IT CONNECTS"), e.why},
                                           {QString("WHY THIS SUGGESTION"), e.reason},
                                           {QString("IS IT GENUINE"), e.risk}}) {
            if (value.isEmpty()) continue;
            auto *t = text(title, "colhead");
            t->setStyleSheet("color: #8f88a8; font-weight: 500;");
            l->addWidget(t);
            auto *v = text(value, "sub", true);
            v->setStyleSheet("color: #aeaeae;");
            l->addWidget(v);
        }
        l->addWidget(text("AI explanation · " + (e.model.isEmpty() ? model : e.model) +
                              " · may be wrong and never decides for you",
                          "colhead", true));
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
    th->setContentsMargins(14, 12, 14, 12);
    th->setSpacing(11);
    th->addWidget(appIcon(p.path));
    auto *info = new QVBoxLayout;
    info->setSpacing(2);
    info->addWidget(new ElideLabel(FirewallClient::fileName(p.path), "strong"));
    const QString signature = p.signer.isEmpty() ? QString("<span style='color:#d4a437'>Not signed</span>")
                                                 : "<span style='color:#9bbf73'>✓ " + p.signer.toHtmlEscaped() + "</span>";
    auto *meta = new QLabel(signature + " · " + QDir::toNativeSeparators(QFileInfo(p.path).path()).toHtmlEscaped() +
                            " · " + (p.attempts == 1 ? QString("1 attempt") : QString("%1 attempts").arg(p.attempts)) +
                            " since " + clock(p.first));
    meta->setProperty("r", "small");
    meta->setWordWrap(true);
    meta->setMinimumWidth(10);
    info->addWidget(meta);
    th->addLayout(info, 1);
    const QString known = KnownApps::hint(p.signer, p.path, p.host);
    if (!expanded) {
        const auto e = explanationFor(p.id);
        if (!known.isEmpty()) th->addWidget(hint(known.section(" · ", 0, 1), "known"));
        if (e.state == AccessToast::Explanation::Ready)
            th->addWidget(e.suggestion == "block"   ? hint("AI suggests Block", "block")
                          : e.suggestion == "allow" ? hint("AI suggests Allow", "allow")
                                                    : hint("AI: your call", "either"));
        auto *open = button("Review", nullptr, true);
        open->setObjectName("request-open");
        connect(open, &QPushButton::clicked, this, [this, id = p.id] {
            expanded_ = id;
            render(true);
        });
        th->addWidget(open);
        auto *block = button("Block", "block", true);
        auto *allow = button("Allow", "allow", true);
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
    bh->setContentsMargins(14, 12, 14, 14);
    bh->setSpacing(16);
    auto *leftCol = new QVBoxLayout;
    leftCol->setSpacing(10);
    if (p.perDestination) {
        auto *n = text("This app already has rules for other servers: Allow or Block applies to this server only. "
                       "Choose Any destination (whole app) to replace its server rules.",
                       "body", true);
        n->setStyleSheet("background: #20232b; border: 1px solid #2f3646; border-radius: 6px; padding: 7px 9px; "
                         "color: #a9bfe0;");
        leftCol->addWidget(n);
    }
    if (p.signer.isEmpty()) {
        auto *n = text("No signature: a rule can only cover this exact file. If the file changes, it asks again.",
                       "body", true);
        n->setStyleSheet("background: #2f2716; border: 1px solid #4d3e19; border-radius: 6px; padding: 7px 9px; "
                         "color: #e6c16a;");
        leftCol->addWidget(n);
    }
    auto *facts = new QGridLayout;
    facts->setHorizontalSpacing(12);
    facts->setVerticalSpacing(7);
    facts->setColumnMinimumWidth(0, 80);
    facts->setColumnStretch(1, 1);
    int r = 0;
    const auto fact = [&](const QString &name, QWidget *value) {
        facts->addWidget(text(name, "sub"), r, 0, Qt::AlignTop);
        facts->addWidget(value, r++, 1);
    };
    auto *wants = new QWidget;
    auto *wv = new QVBoxLayout(wants);
    wv->setContentsMargins(0, 0, 0, 0);
    wv->setSpacing(2);
    auto *target = text(p.host.isEmpty() ? p.remote : p.host, "body", true);
    target->setTextInteractionFlags(Qt::TextSelectableByMouse);
    wv->addWidget(target);
    wv->addWidget(text(destinationLine(p), "small"));
    fact("Wants", wants);
    const QString parent = launchedBy(p);
    if (!parent.isEmpty()) fact("Started by", text(parent, "body", true));
    leftCol->addLayout(facts);
    leftCol->addWidget(aiCard(p));
    leftCol->addStretch();
    bh->addLayout(leftCol, 1);

    auto *rightCol = new QVBoxLayout;
    rightCol->setSpacing(8);
    auto &choice = choices_[p.id.toLower()];
    const auto addCombo = [&](const QString &label, const QVector<QPair<QString, QString>> &options, QString &value,
                              const char *name) {
        rightCol->addWidget(text(label, "colhead"));
        auto *combo = new Combo;
        combo->setObjectName(name);
        combo->setAccessibleName(label);
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
        rightCol->addWidget(combo);
    };
    addCombo("Apply to", scopeOptions(p), choice.scope, "request-scope");
    addCombo("For", durationOptions(), choice.duration, "request-duration");
    addCombo("Destination", targetOptions(p), choice.target, "request-target");
    choice.set = true;
    rightCol->addSpacing(6);
    auto *buttons = row(8);
    auto *block = button("Block", "block");
    auto *allow = button("Allow", "allow");
    block->setObjectName("request-block");
    allow->setObjectName("request-allow");
    recommend(block, allow, known);
    for (auto *b : {block, allow}) {
        b->setMinimumHeight(34);
        b->setEnabled(canDecide());
        buttons->addWidget(b, 1);
        connect(b, &QPushButton::clicked, this, [this, p, allowed = b == allow] {
            if (!armed()) return;
            const auto c = choices_.value(p.id.toLower());
            firewall_.decide(p.path, allowed, c.scope, c.duration, c.target);
            choices_.remove(p.id.toLower());
            if (expanded_ == p.id) expanded_.clear();
        });
    }
    rightCol->addLayout(buttons);
    rightCol->addStretch();
    auto *rw = new QWidget;
    rw->setFixedWidth(290);
    rw->setLayout(rightCol);
    bh->addWidget(rw, 0, Qt::AlignTop);
    cl->addWidget(body);
    return c;
}

QWidget *FirewallWindow::requestsPage() {
    auto *page = new QWidget;
    auto *l = column(page, 18, 10);
    l->setContentsMargins(18, 16, 18, 22);
    l->addWidget(header(headIcon("bell"), "Requests",
                        "Each application here was blocked and is waiting. Allow lets its next attempt connect."));
    auto pending = firewall_.pending();
    std::sort(pending.begin(), pending.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
    if (!firewall_.status().connected) {
        auto *c = card();
        column(c)->addWidget(text("The engine is not running, so no requests can arrive.", "sub", true));
        l->addWidget(c);
    } else if (pending.isEmpty()) {
        auto *c = card();
        column(c)->addWidget(text("Nothing is waiting. A new application that tries to connect appears here and in a "
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
        const QString key = r.scope == "path"  ? "path|" + r.path.toLower()
                            : r.scope == "app" ? "app|" + r.signer.toLower() + "|" + r.name.toLower()
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
    // Ícono y archivos de las reglas por firma: los que ya cubrieron.
    for (auto &e : entries) {
        if (!e.iconPath.isEmpty()) continue;
        for (const auto &r : e.rules)
            for (const auto &c : rules)
                if (c.scope == "covered" && c.name == r.id && e.iconPath.isEmpty()) e.iconPath = c.path;
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
        if (path.toLower() == self || firewall_.ruleFor(path) || firewall_.pendingFor(path)) continue;
        result << path;
    }
    std::sort(result.begin(), result.end(), [](const QString &a, const QString &b) {
        return FirewallClient::fileName(a).compare(FirewallClient::fileName(b), Qt::CaseInsensitive) < 0;
    });
    return result;
}

QWidget *FirewallWindow::appsPage() {
    auto *page = new QWidget;
    auto *l = column(page, 18, 10);
    l->setContentsMargins(18, 16, 18, 16);
    l->addWidget(header(headIcon("apps"), "Apps", "Every application with a rule. A signed app keeps its rule across updates."));
    auto *bar = row(8);
    auto *search = new QLineEdit(appsQuery_);
    search->setObjectName("apps-search");
    search->setPlaceholderText("Search apps or publishers");
    search->setClearButtonEnabled(true);
    search->setMinimumWidth(140);
    bar->addWidget(search, 1);
    appsSeg_ = card("seg");
    auto *sl = new QHBoxLayout(appsSeg_);
    sl->setContentsMargins(2, 2, 2, 2);
    sl->setSpacing(2);
    bar->addWidget(appsSeg_);
    l->addLayout(bar);
    connect(search, &QLineEdit::textChanged, this, [this](const QString &v) {
        appsQuery_ = v;
        fillApps();
    });
    // La tabla ocupa el resto de la página: el encabezado queda fijo y sólo se desplazan las filas.
    auto *list = card();
    auto *ll = new QVBoxLayout(list);
    ll->setContentsMargins(0, 0, 0, 0);
    appsTable_ = makeTable("apps", 52);
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
    int allow = 0, block = 0, perServer = 0, temporary = 0;
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
                                                            {"running", "Running, no rule", int(loose.size())}};
    for (const auto &[id, name, n] : filters) {
        auto *b = button(QString("%1  %2").arg(name).arg(n), "seg");
        b->setObjectName("apps-filter-" + id);
        b->setProperty("on", appsFilter_ == id ? "1" : "0");
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
        v->setSpacing(2);
        v->addWidget(new ElideLabel(title, "strong"));
        if (!subtitle.isEmpty()) v->addWidget(new ElideLabel(subtitle, "small", mode));
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
                auto *b = button(allowed ? "Allow" : "Block", allowed ? "allow" : "block", true);
                b->setObjectName(allowed ? "running-allow" : "running-block");
                b->setFixedWidth(64);
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
                   {{"APPLICATION", 330}, {"DESTINATION", 120}, {"RULE", 170, Qt::AlignRight}, {"WHEN", 130, Qt::AlignRight}});
        t->viewport()->setCursor(Qt::PointingHandCursor);
        for (const auto &e : entries) {
            const QString c = classify(e);
            if (appsFilter_ != "all" && appsFilter_ != c) continue;
            QString hay = e.title + " " + e.subtitle + " " + e.path + " " + e.signer;
            for (const auto &r : e.rules) hay += " " + r.destination;
            if (!matches(hay)) continue;
            const int r = t->rowCount();
            t->insertRow(r);
            const auto &r0 = e.rules.first();
            QWidget *dest = e.perServer ? static_cast<QWidget *>(chip(e.rules.size() == 1 ? QString("1 server")
                                                                                          : QString("%1 servers").arg(e.rules.size())))
                                        : new ElideLabel("Anywhere", "colhead");
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
                           cell(dest), cell(policy, Qt::AlignRight), cell(when)});
            t->item(r, 0)->setData(Qt::UserRole, "rule:" + e.key);
        }
        appsTip_->clear();
    }
    if (t->rowCount() == 0) {
        t->insertRow(0);
        auto *empty = new ElideLabel(runningView ? "Every running application of this session has a rule or is waiting."
                                     : appsQuery_.isEmpty() ? "No rules here yet."
                                                            : "No app matches the search.",
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
    auto *l = column(page, 18, 10);
    l->setContentsMargins(18, 10, 18, 22);
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
    QString where = e->scope == "path"  ? QDir::toNativeSeparators(e->path)
                    : e->scope == "app" ? "Any version signed by " + e->signer
                                        : "Any application signed by " + e->signer;
    if (e->scope == "app" && !e->iconPath.isEmpty())
        where = QDir::toNativeSeparators(e->iconPath) + " · any version signed by " + e->signer;
    l->addWidget(header(appIcon(e->iconPath, 38), e->title, where));
    const bool can = canDecide();
    int covered = 0;
    for (const auto &r : e->rules)
        for (const auto &c : firewall_.rules()) covered += c.scope == "covered" && c.name == r.id;

    if (e->perServer) {
        auto *c = card();
        auto *cl = column(c, 14, 0);
        auto *ch = row(8);
        ch->addWidget(text("Server rules", "cardtitle"));
        auto *count = text(QString::number(e->rules.size()), "colhead");
        count->setStyleSheet("border: 1px solid #333; border-radius: 4px; padding: 1px 6px; color: #888;");
        ch->addWidget(count);
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
            h->addWidget(new ElideLabel(r.destination, "body"), 1);
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
            x->setToolTip("Remove only this server rule");
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
        auto *cl = column(c, 14, 9);
        cl->addWidget(text("Rule", "cardtitle"));
        auto *grid = new QGridLayout;
        grid->setHorizontalSpacing(12);
        grid->setVerticalSpacing(9);
        grid->setColumnMinimumWidth(0, 130);
        int gr = 0;
        const auto kv = [&](const QString &k, QWidget *v) {
            grid->addWidget(text(k, "sub"), gr, 0);
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
        kv("Applies to", text(e->scope == "path"  ? QString("This file only")
                              : e->scope == "app" ? "Any version of " + r0.name + " signed by this publisher"
                                                  : "Any application signed by " + r0.signer,
                              "body", true));
        if (e->scope != "path") kv("Files seen", text(QString::number(covered), "body"));
        kv("Created", text(clockFull(r0.created), "body"));
        kv("Last blocked attempt", text(r0.allow ? QString("—") : clockFull(r0.lastBlock), "body"));
        cl->addLayout(grid);
        if (e->scope == "path" && r0.expires == 0) {
            // Una regla por ruta se puede invertir aquí; las de firma se cambian en el próximo aviso que coincida.
            auto *actions = row(8);
            actions->addStretch();
            auto *flip = button(r0.allow ? "Change to Block" : "Change to Allow", r0.allow ? "block" : "allow");
            flip->setObjectName("rule-flip");
            flip->setEnabled(can);
            connect(flip, &QPushButton::clicked, this, [this, path = e->path, allow = !r0.allow] {
                firewall_.decide(path, allow);
            });
            actions->addWidget(flip);
            cl->addLayout(actions);
        }
        l->addWidget(c);
    }
    auto *remove = card();
    auto *rh = new QHBoxLayout(remove);
    rh->setContentsMargins(14, 12, 14, 12);
    rh->setSpacing(12);
    auto *rt = new QVBoxLayout;
    rt->setSpacing(2);
    rt->addWidget(text(e->rules.size() > 1 ? "Remove all rules for " + e->title : "Remove this rule", "strong"));
    rt->addWidget(text(e->scope == "path" ? e->title + " asks again the next time it connects."
                                          : e->title + " asks again the next time it connects. To change a rule like "
                                                       "this one, decide on its next notice.",
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
    auto *l = column(page, 18, 10);
    l->setContentsMargins(18, 16, 18, 16);
    auto *seg = card("seg");
    auto *sl = new QHBoxLayout(seg);
    sl->setContentsMargins(2, 2, 2, 2);
    sl->setSpacing(2);
    for (const auto &[id, name] : {std::pair{QString("blocked"), QString("Blocked")}, {QString("decisions"), QString("Decisions")}}) {
        auto *b = button(name, "seg");
        b->setObjectName("activity-filter-" + id);
        b->setProperty("on", activityFilter_ == id ? "1" : "0");
        connect(b, &QPushButton::clicked, this, [this, id = id] {
            activityFilter_ = id;
            render();
        });
        sl->addWidget(b);
    }
    l->addWidget(header(headIcon("pulse"), "Activity",
                        (s.started ? "Since the engine started at " + clock(s.started) + ". " : QString()) +
                            "Allowed connections are not recorded.",
                        seg));
    const bool blockedView = activityFilter_ == "blocked";
    auto *c = card();
    auto *cl = new QVBoxLayout(c);
    cl->setContentsMargins(0, 0, 0, 0);
    auto *t = makeTable("activity", 44);
    t->viewport()->setCursor(Qt::ArrowCursor);
    if (blockedView)
        setColumns(t, "blocked", {{"TIME", 80}, {"APPLICATION", 260}, {"DESTINATION", 200}, {"REASON", 160}});
    else
        setColumns(t, "decisions", {{"TIME", 80}, {"APPLICATION", 260}, {"DECISION", 300}});
    cl->addWidget(t);
    const auto &events = firewall_.activity();
    const auto same = [](const FirewallClient::ActivityItem &a, const FirewallClient::ActivityItem &b) {
        return a.path.compare(b.path, Qt::CaseInsensitive) == 0 && a.remote == b.remote && a.port == b.port &&
               a.kind == b.kind;
    };
    for (int i = events.size() - 1; i >= 0 && t->rowCount() < 500; --i) {
        const auto &e = events[i];
        const bool blocked = e.kind.startsWith("Blocked");
        if (blockedView != blocked) continue;
        // Los reintentos seguidos de una misma app al mismo destino van en una sola fila, con la cuenta.
        int repeats = 1;
        while (i > 0 && same(events[i - 1], e)) {
            --i;
            ++repeats;
        }
        const int r = t->rowCount();
        t->insertRow(r);
        auto *when = new ElideLabel(clock(e.time), "time");
        auto *app = new QWidget;
        auto *ah = new QHBoxLayout(app);
        ah->setContentsMargins(0, 0, 0, 0);
        ah->setSpacing(10);
        if (!e.path.isEmpty()) ah->addWidget(appIcon(e.path, 26));
        ah->addWidget(new ElideLabel(e.path.isEmpty() ? QString("GateBouncer") : FirewallClient::fileName(e.path), "body"), 1);
        if (repeats > 1) ah->addWidget(text(QString("%1 times").arg(repeats), "time"));
        if (blockedView) {
            auto *dest = new ElideLabel(e.remote.isEmpty() ? QString("—")
                                                           : e.remote + (e.port ? ":" + QString::number(e.port) : QString()),
                                        "sub");
            auto *reason = new QWidget;
            auto *rh = new QHBoxLayout(reason);
            rh->setContentsMargins(0, 0, 0, 0);
            rh->addWidget(chip(activityChip(e.kind)));
            rh->addStretch();
            fillRow(t, r, {cell(when), cell(app), cell(dest), cell(reason)});
        } else {
            fillRow(t, r, {cell(when), cell(app), cell(new ElideLabel(e.kind, "sub"))});
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
    l->addWidget(text("The list keeps the latest 2,000 events and starts again when the engine restarts.", "faint", true));
    return page;
}

// ------------------------------------------------------------------------------------------------------------------
// Settings: modo del firewall, explicaciones con IA, importar de NetLimiter y la ventana.

QWidget *FirewallWindow::settingsPage() {
    const auto &s = firewall_.status();
    const bool can = canDecide();
    auto *page = new QWidget;
    auto *l = column(page, 18, 10);
    l->setContentsMargins(18, 16, 18, 22);
    l->addWidget(header(headIcon("gear"), "Settings", "Firewall mode, AI explanations, import and startup."));

    const auto setRow = [](QVBoxLayout *into, const QString &title, const QString &caption, QWidget *trailing,
                           bool first = false) {
        if (!first) into->addWidget(divider());
        auto *w = new QWidget;
        w->setMinimumHeight(44);
        auto *h = new QHBoxLayout(w);
        h->setContentsMargins(0, 7, 0, 7);
        h->setSpacing(12);
        auto *t = new QVBoxLayout;
        t->setSpacing(2);
        t->addWidget(text(title, "strong"));
        if (!caption.isEmpty()) t->addWidget(text(caption, "small", true));
        h->addLayout(t, 1);
        if (trailing) h->addWidget(trailing, 0, Qt::AlignVCenter);
        into->addWidget(w);
        return h;
    };

    auto *fw = card();
    auto *fl = column(fw, 14, 0);
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
    fl->addWidget(divider());
    fl->addSpacing(10);
    fl->addWidget(text("Windows services, DNS and connections inside this PC always connect. To turn GateBouncer off "
                       "completely, run GateBouncerEngine.exe --remove-filters as administrator.",
                       "faint", true));
    if (!s.connected)
        fl->addWidget(text("The engine is not running: these options apply when it starts again.", "warn", true));
    l->addWidget(fw);

    // Explicaciones: key, consentimiento y textos son del proveedor del modelo elegido.
    const auto settings = Explain::Settings::load();
    const auto provider = Explain::providerOf(settings.model);
    const QString providerName = Explain::providerName(provider);
    const bool hasKey = Explain::KeyStore::has(provider);
    auto *ai = card();
    auto *al = column(ai, 14, 0);
    al->addWidget(text("AI explanations", "cardtitle"));
    al->addSpacing(4);
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
    key->setFixedWidth(250);
    key->setPlaceholderText(hasKey ? "Paste a new key to replace it"
                                   : QString("Paste your key (%1…)").arg(provider == Explain::Provider::Anthropic ? "sk-ant-" : "nvapi-"));
    kb->addWidget(key);
    auto *saveKey = button("Save key", "primary");
    saveKey->setObjectName("explain-save-key");
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
    ih->setContentsMargins(14, 12, 14, 12);
    ih->setSpacing(12);
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

    auto *win = card();
    auto *wl = column(win, 14, 0);
    wl->addWidget(text("Window", "cardtitle"));
    wl->addSpacing(4);
    // El arranque al iniciar sesión lo registra el motor al instalarse (HKLM Run, para todos los usuarios).
    auto *help = button("Help");
    help->setObjectName("settings-help");
    connect(help, &QPushButton::clicked, this, &FirewallWindow::showHelp);
    setRow(wl, "Opens at sign-in, minimized to the tray",
           "Closing the window hides it there; Quit in the tray menu exits it. The firewall keeps working either way.",
           help, true);
    l->addWidget(win);
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
    auto *l = column(page, 18, 10);
    l->setContentsMargins(18, 10, 18, 22);
    auto *back = button("‹ Settings", "link");
    connect(back, &QPushButton::clicked, this, [this] { selectView("settings"); });
    auto *bl = row();
    bl->addWidget(back);
    bl->addStretch();
    l->addLayout(bl);
    int importable = 0;
    for (const auto &r : netLimiterRules_) importable += r.importable && !firewall_.ruleFor(r.path);
    l->addWidget(header(headIcon("gear"), "Import from NetLimiter",
                        netLimiterFile_.isEmpty() ? QString("NetLimiter keeps its rules in nl_settings.xml.")
                                                  : QString("%1 · %2 NetLimiter rules · %3 can be imported")
                                                        .arg(QFileInfo(netLimiterFile_).fileName())
                                                        .arg(netLimiterRules_.size())
                                                        .arg(importable)));
    auto *choose = card();
    auto *ch = new QHBoxLayout(choose);
    ch->setContentsMargins(14, 12, 14, 12);
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
        auto *cl = column(c, 14, 0);
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
                p->setToolTip(QDir::toNativeSeparators(r.path));
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
