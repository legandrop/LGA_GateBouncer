#include "mainwindow.h"
#include <QAbstractTableModel>
#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QComboBox>
#include <QEvent>
#include <QFontMetrics>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QStyleOptionViewItem>
#include <QStyledItemDelegate>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>
#include <algorithm>

namespace Gate {
namespace {
constexpr int IdRole = Qt::UserRole + 1, KindRole = Qt::UserRole + 2, SortRole = Qt::UserRole + 3;
struct Cell {
    QString text, kind;
    QVariant sort;
};
struct Row {
    QString id;
    QVector<Cell> cells;
};
QLabel *label(const QString &text, const QString &role = {}, bool wrap = false) {
    auto *w = new QLabel(text);
    w->setTextFormat(Qt::PlainText);
    w->setWordWrap(wrap);
    w->setProperty("role", role);
    w->setTextInteractionFlags(Qt::TextSelectableByMouse);
    return w;
}
QPushButton *button(const QString &text, const QString &name, const QString &role = {}) {
    auto *w = new QPushButton(text);
    w->setObjectName(name);
    w->setProperty("role", role);
    w->setCursor(Qt::PointingHandCursor);
    if (text == "×")
        w->setProperty("compact-close", true);
    return w;
}
class ChevronCombo final : public QComboBox {
  protected:
    void paintEvent(QPaintEvent *event) override {
        QComboBox::paintEvent(event);
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.setPen(QPen(QColor(isEnabled() ? "#8f8f8f" : "#656565"), 1.2,
                            Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        const QPointF center(width() - 11, height() / 2.0);
        QPainterPath chevron;
        chevron.moveTo(center + QPointF(-3, -1.5));
        chevron.lineTo(center + QPointF(0, 1.5));
        chevron.lineTo(center + QPointF(3, -1.5));
        painter.drawPath(chevron);
    }
};
QComboBox *combo(const QStringList &values, const QString &name) {
    auto *w = new ChevronCombo;
    w->setObjectName(name);
    w->setAccessibleName(name);
    w->addItems(values);
    w->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    w->setMinimumContentsLength(10);
    return w;
}
void dispose(QWidget *widget) {
    if (widget) {
        widget->hide();
        widget->deleteLater();
    }
}
QIcon navigationIcon(int index) {
    QPixmap image(17, 17);
    image.fill(Qt::transparent);
    QPainter p(&image);
    p.setRenderHint(QPainter::Antialiasing);
    p.setPen(QPen(QColor("#8f8f8f"), 1.3, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    p.scale(0.85, 0.85);
    if (index == 0) {
        p.drawRoundedRect(QRectF(3, 3, 14, 14), 2, 2);
        p.drawLine(QPointF(6, 7), QPointF(14, 7));
        p.drawLine(QPointF(6, 10), QPointF(14, 10));
        p.drawLine(QPointF(6, 13), QPointF(11, 13));
    } else if (index == 1) {
        QPainterPath path;
        path.moveTo(4, 14);
        path.lineTo(4, 8);
        path.cubicTo(4, 0, 16, 0, 16, 8);
        path.lineTo(16, 14);
        path.closeSubpath();
        p.drawPath(path);
        p.drawLine(QPointF(8, 17), QPointF(12, 17));
    } else if (index == 2) {
        QPainterPath path;
        path.moveTo(2, 11);
        path.lineTo(6, 11);
        path.lineTo(8, 5);
        path.lineTo(11, 16);
        path.lineTo(14, 9);
        path.lineTo(18, 9);
        p.drawPath(path);
    } else if (index == 3) {
        p.drawRect(QRectF(5, 2, 10, 16));
        p.drawLine(QPointF(8, 6), QPointF(12, 6));
        p.drawLine(QPointF(8, 10), QPointF(12, 10));
        p.drawLine(QPointF(8, 14), QPointF(11, 14));
    } else if (index == 4) {
        p.drawLine(QPointF(3, 12), QPointF(3, 17));
        p.drawLine(QPointF(3, 17), QPointF(17, 17));
        p.drawLine(QPointF(17, 17), QPointF(17, 12));
        p.drawLine(QPointF(10, 2), QPointF(10, 12));
        p.drawLine(QPointF(6, 8), QPointF(10, 12));
        p.drawLine(QPointF(10, 12), QPointF(14, 8));
    } else if (index == 5) {
        QPainterPath path;
        path.moveTo(8, 2);
        path.lineTo(12, 2);
        path.lineTo(13, 5);
        path.lineTo(16, 6);
        path.lineTo(18, 10);
        path.lineTo(16, 13);
        path.lineTo(13, 14);
        path.lineTo(12, 18);
        path.lineTo(8, 18);
        path.lineTo(7, 14);
        path.lineTo(4, 13);
        path.lineTo(2, 10);
        path.lineTo(4, 6);
        path.lineTo(7, 5);
        path.closeSubpath();
        p.drawPath(path);
        p.drawEllipse(QPointF(10, 10), 3, 3);
    } else {
        p.drawEllipse(QPointF(8, 8), 5, 5);
        p.drawLine(QPointF(12, 12), QPointF(17, 17));
    }
    p.end();
    QIcon icon(image);
    QPixmap chosen = image;
    QPainter tint(&chosen);
    tint.setCompositionMode(QPainter::CompositionMode_SourceIn);
    tint.fillRect(chosen.rect(), QColor("#b7aef0"));
    tint.end();
    icon.addPixmap(chosen, QIcon::Normal, QIcon::On);
    return icon;
}
QFrame *frame(const QString &role) {
    auto *w = new QFrame;
    w->setProperty("role", role);
    return w;
}
QFrame *note(const QString &text, bool neutral = false) {
    auto *w = frame(neutral ? "neutral" : "note");
    auto *l = new QHBoxLayout(w);
    l->setContentsMargins(12, 10, 12, 10);
    l->addWidget(label("ⓘ", "muted"));
    l->addWidget(label(text, "muted", true), 1);
    return w;
}
QWidget *scrollArea(QWidget *content) {
    auto *s = new QScrollArea;
    s->setWidgetResizable(true);
    s->setWidget(content);
    s->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    return s;
}
void divider(QVBoxLayout *l) {
    auto *w = new QFrame;
    w->setFixedHeight(1);
    w->setStyleSheet("background: #262626;");
    l->addWidget(w);
}
QHBoxLayout *line(QVBoxLayout *layout) {
    auto *l = new QHBoxLayout;
    l->setSpacing(8);
    layout->addLayout(l);
    return l;
}
void definition(QVBoxLayout *layout, const QString &name, const QString &value) {
    auto *l = new QHBoxLayout;
    l->setSpacing(12);
    auto *key = label(name, "muted", true);
    key->setFixedWidth(95);
    key->setStyleSheet("font-size: 11px; color: #8f8f8f;");
    auto *v = label(value, "strong", true);
    v->setStyleSheet("font-size: 11px; color: #ccc;");
    l->addWidget(key, 0, Qt::AlignTop);
    l->addWidget(v, 1);
    layout->addLayout(l);
}
QColor tone(const QString &kind) {
    return kind == "Allow" || kind == "Ready" || kind == "Authorized attempt" ? QColor("#a8d86a")
           : kind == "Block" || kind == "Unsupported"                         ? QColor("#e8836f")
           : kind == "Ask" || kind == "Needs review"                          ? QColor("#d4a437")
                                                                              : QColor("#8f8f8f");
}

class CellDelegate final : public QStyledItemDelegate {
  public:
    using QStyledItemDelegate::QStyledItemDelegate;
    void paint(QPainter *p, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override {
        p->save();
        const QRect r = option.rect;
        p->fillRect(r, option.state & QStyle::State_Selected    ? QColor("#212027")
                       : option.state & QStyle::State_MouseOver ? QColor("#242424")
                                                                : QColor("#1d1d1d"));
        p->setPen(QColor("#242424"));
        p->drawLine(r.bottomLeft(), r.bottomRight());
        const auto parts = index.data().toString().split('\n');
        const auto kind = index.data(KindRole).toString();
        QFont f = option.font;
        f.setPixelSize(12);
        p->setFont(f);
        QRect textRect = r.adjusted(11, 0, -11, 0);
        if (kind.startsWith("glyph:")) {
            const QString initials = kind.mid(6);
            const QRect g(r.x() + 11, r.center().y() - 11, 22, 22);
            p->setPen(QColor("#383341"));
            p->setBrush(QColor("#25232b"));
            p->drawRoundedRect(g, 4, 4);
            QFont gf = f;
            gf.setPixelSize(10);
            gf.setWeight(QFont::DemiBold);
            p->setFont(gf);
            p->setPen(QColor("#a89dc8"));
            p->drawText(g, Qt::AlignCenter, initials);
            p->setFont(f);
            textRect.setLeft(g.right() + 9);
        }
        if (kind == "Allow" || kind == "Block" || kind == "Ask" || kind == "AskPending" ||
            kind == "inactive") {
            QFont cf = f;
            cf.setPixelSize(11);
            cf.setWeight(QFont::Medium);
            p->setFont(cf);
            const QString value = parts.first();
            const int width =
                qMin(textRect.width(), QFontMetrics(cf).horizontalAdvance(value) + 12);
            QRect chip(textRect.x(), r.center().y() - 10, width, 21);
            const QColor color = tone(kind == "AskPending" ? "Ask" : kind);
            p->setPen(kind == "Allow"          ? QColor("#3a4d27")
                      : kind == "Block"        ? QColor("#5c3330")
                      : kind.startsWith("Ask") ? QColor("#4d4020")
                                               : QColor("#383838"));
            p->setBrush(kind == "Allow"          ? QColor("#1f2a17")
                        : kind == "Block"        ? QColor("#35211f")
                        : kind.startsWith("Ask") ? QColor("#2d2614")
                                                 : QColor("#292929"));
            p->drawRoundedRect(chip, 3, 3);
            p->setPen(color);
            p->drawText(chip.adjusted(6, 0, -4, 0), Qt::AlignVCenter,
                        QFontMetrics(cf).elidedText(value, Qt::ElideRight, width - 10));
            if (kind == "AskPending" && textRect.width() >= 100) {
                cf.setPixelSize(10);
                cf.setWeight(QFont::Normal);
                p->setFont(cf);
                p->setPen(QColor("#6f6f6f"));
                p->drawText(textRect.adjusted(width + 6, 0, 0, 0), Qt::AlignVCenter, "pending");
            }
        } else if (kind == "action") {
            p->setPen(QColor(option.state & QStyle::State_Enabled ? "#9d8fe0" : "#656565"));
            QFont af = f;
            af.setPixelSize(11);
            p->setFont(af);
            p->drawText(textRect, Qt::AlignVCenter, parts.first());
        } else {
            p->setPen(kind.startsWith("glyph:") || kind == "strong"
                          ? QColor("#ccc")
                          : tone(kind == "warning" ? "Ask" : kind));
            if (parts.size() > 1) {
                const int top = r.center().y() - 14;
                p->drawText(
                    QRect(textRect.x(), top, textRect.width(), 17), Qt::AlignVCenter,
                    QFontMetrics(f).elidedText(parts.first(), Qt::ElideRight, textRect.width()));
                QFont sf = f;
                sf.setPixelSize(9);
                p->setFont(sf);
                p->setPen(QColor("#6f6f6f"));
                p->drawText(QRect(textRect.x(), top + 17, textRect.width(), 12), Qt::AlignVCenter,
                            QFontMetrics(sf).elidedText(parts.mid(1).join(" · "), Qt::ElideRight,
                                                        textRect.width()));
            } else
                p->drawText(
                    textRect, Qt::AlignVCenter,
                    QFontMetrics(f).elidedText(parts.first(), Qt::ElideRight, textRect.width()));
        }
        if (option.state & QStyle::State_HasFocus) {
            p->setBrush(Qt::NoBrush);
            p->setPen(QColor("#774dcb"));
            p->drawRect(r.adjusted(1, 1, -2, -2));
        }
        p->restore();
    }
};
class Spinner final : public QWidget {
  public:
    explicit Spinner(QWidget *parent = nullptr) : QWidget(parent) {
        setObjectName("explanation-spinner");
        setFixedSize(12, 12);
        auto *timer = new QTimer(this);
        timer->setInterval(100);
        connect(timer, &QTimer::timeout, this, [this] {
            angle_ = (angle_ + 45) % 360;
            update();
        });
        timer->start();
    }

  protected:
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.setPen(QPen(QColor("#51445f"), 2));
        p.drawEllipse(QRectF(1, 1, 10, 10));
        p.setPen(QPen(QColor("#c8b5e9"), 2));
        p.drawArc(QRectF(1, 1, 10, 10), angle_ * 16, 90 * 16);
    }

  private:
    int angle_ = 90;
};
} // namespace

class RowsModel final : public QAbstractTableModel {
  public:
    explicit RowsModel(QStringList headers, QObject *parent)
        : QAbstractTableModel(parent), headers_(std::move(headers)) {}
    int rowCount(const QModelIndex &parent = {}) const override {
        return parent.isValid() ? 0 : int(rows_.size());
    }
    int columnCount(const QModelIndex &parent = {}) const override {
        return parent.isValid() ? 0 : int(headers_.size());
    }
    QVariant data(const QModelIndex &i, int role = Qt::DisplayRole) const override {
        if (!i.isValid() || i.row() >= rows_.size() || i.column() >= rows_[i.row()].cells.size())
            return {};
        const auto &r = rows_[i.row()];
        const auto &c = r.cells[i.column()];
        if (role == Qt::DisplayRole || role == Qt::AccessibleTextRole || role == Qt::ToolTipRole)
            return c.text;
        if (role == IdRole)
            return r.id;
        if (role == KindRole)
            return c.kind;
        if (role == SortRole)
            return c.sort.isValid() ? c.sort : c.text;
        return {};
    }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        return orientation == Qt::Horizontal && role == Qt::DisplayRole ? headers_.value(section)
                                                                        : QVariant{};
    }
    void replace(QVector<Row> rows) {
        beginResetModel();
        rows_ = std::move(rows);
        endResetModel();
        sort(sortColumn_, sortOrder_);
    }
    void sort(int column, Qt::SortOrder order) override {
        if (column < 0 || column >= headers_.size())
            return;
        sortColumn_ = column;
        sortOrder_ = order;
        beginResetModel();
        std::stable_sort(rows_.begin(), rows_.end(), [&](const Row &a, const Row &b) {
            const auto &ac = a.cells[column];
            const auto &bc = b.cells[column];
            int cmp;
            if (ac.sort.isValid() && bc.sort.isValid() &&
                ac.sort.metaType().id() != QMetaType::QString)
                cmp = ac.sort.toLongLong() < bc.sort.toLongLong()   ? -1
                      : ac.sort.toLongLong() > bc.sort.toLongLong() ? 1
                                                                    : 0;
            else
                cmp = QString::compare(ac.text, bc.text, Qt::CaseInsensitive);
            return order == Qt::AscendingOrder ? cmp < 0 : cmp > 0;
        });
        endResetModel();
    }

  private:
    QStringList headers_;
    QVector<Row> rows_;
    int sortColumn_ = -1;
    Qt::SortOrder sortOrder_ = Qt::AscendingOrder;
};

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), model_(this), explanation_(&model_) {
    setObjectName("GateBouncer");
    setWindowTitle("LGA GateBouncer · Simulation");
    setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
    resize(1280, 800);
    setMinimumSize(900, 620);
    buildShell();
    buildPage();
    connect(&model_, &Simulation::changed, this, &MainWindow::refresh);
    connect(&explanation_, &Explanation::changed, this, &MainWindow::renderNotice);
    qApp->installEventFilter(this);
}
void MainWindow::buildShell() {
    root_ = new QWidget;
    root_->setObjectName("root");
    setCentralWidget(root_);
    auto *rootLayout = new QVBoxLayout(root_);
    rootLayout->setContentsMargins(1, 1, 1, 1);
    rootLayout->setSpacing(0);
    auto *bar = new QFrame;
    bar->setObjectName("titlebar");
    bar->setFixedHeight(36);
    bar->installEventFilter(this);
    auto *barLayout = new QHBoxLayout(bar);
    barLayout->setContentsMargins(13, 0, 10, 0);
    barLayout->setSpacing(9);
    auto *brand = label("LGA", "link");
    brand->setStyleSheet("color: #9d8fe0; font-size: 11px; font-weight: 600;");
    barLayout->addWidget(brand);
    barLayout->addWidget(label("GateBouncer", "muted"));
    barLayout->addStretch();
    auto *simulation = label("Simulation · Firewall engine not connected", "warning");
    simulation->setObjectName("simulation-banner");
    barLayout->addWidget(simulation);
    barLayout->addSpacing(18);
    for (const auto &v : {QString("−"), QString("□"), QString("×")}) {
        auto *b = button(v,
                         v == "×"   ? "close-window"
                         : v == "□" ? "maximize-window"
                                    : "minimize-window",
                         "ghost");
        b->setFixedSize(30, 29);
        b->setAccessibleName(v == "×"   ? "Close application"
                             : v == "□" ? "Maximize or restore"
                                        : "Minimize");
        barLayout->addWidget(b);
        connect(b, &QPushButton::clicked, this, [this, v] {
            if (v == "×")
                close();
            else if (v == "□")
                isMaximized() ? showNormal() : showMaximized();
            else
                showMinimized();
        });
    }
    rootLayout->addWidget(bar);
    auto *shell = new QWidget;
    auto *shellLayout = new QHBoxLayout(shell);
    shellLayout->setContentsMargins(0, 0, 0, 0);
    shellLayout->setSpacing(0);
    sidebar_ = new QFrame;
    sidebar_->setObjectName("sidebar");
    sidebar_->setFixedWidth(208);
    auto *side = new QVBoxLayout(sidebar_);
    side->setContentsMargins(8, 14, 9, 12);
    side->setSpacing(2);
    auto *section = label("NETWORK ACCESS", "faint");
    section->setContentsMargins(10, 6, 0, 8);
    section->setFixedHeight(24);
    side->addWidget(section);
    const QStringList ids{"processes", "pending", "activity", "rules", "import", "settings"};
    const QStringList names{"Processes", "Pending", "Activity", "Rules", "Import", "Settings"};
    for (int i = 0; i < ids.size(); ++i) {
        auto *b = button("  " + names[i], "nav-" + ids[i], "nav");
        b->setIcon(navigationIcon(i));
        b->setIconSize(QSize(17, 17));
        b->setCheckable(true);
        b->setChecked(i == 0);
        b->setAccessibleName(names[i]);
        side->addWidget(b);
        navigation_[ids[i]] = b;
        connect(b, &QPushButton::clicked, this, [this, id = ids[i]] { selectView(id); });
    }
    pendingCount_ = new QLabel(navigation_["pending"]);
    pendingCount_->setObjectName("pending-count");
    pendingCount_->setAlignment(Qt::AlignCenter);
    pendingCount_->setFixedSize(20, 18);
    pendingCount_->setAttribute(Qt::WA_TransparentForMouseEvents);
    pendingCount_->setStyleSheet("color: #d4a437; background: #2d2614; border: 1px solid #4d4020; "
                                 "border-radius: 3px; font-size: 11px;");
    side->addStretch();
    divider(side);
    sideStatus_ = label("Synthetic model available\nNo protection is active", "muted", true);
    sideStatus_->setContentsMargins(10, 10, 10, 7);
    side->addWidget(sideStatus_);
    auto *help = button("ⓘ    Help & about", "help-about", "ghost");
    side->addWidget(help);
    connect(help, &QPushButton::clicked, this, &MainWindow::about);
    shellLayout->addWidget(sidebar_);
    workspace_ = new QWidget;
    workspace_->setObjectName("workspace");
    workspaceLayout_ = new QVBoxLayout(workspace_);
    workspaceLayout_->setContentsMargins(18, 18, 18, 0);
    workspaceLayout_->setSpacing(0);
    auto *header = new QHBoxLayout;
    header->setSpacing(10);
    auto *headText = new QVBoxLayout;
    headText->setSpacing(4);
    title_ = label({}, "title");
    title_->setFixedHeight(24);
    subtitle_ = label({}, "muted");
    subtitle_->setFixedHeight(18);
    headText->addWidget(title_);
    headText->addWidget(subtitle_);
    header->addLayout(headText, 1);
    status_ = label("Synthetic data only\nNo network filtering", "warning");
    status_->setAlignment(Qt::AlignRight | Qt::AlignTop);
    header->addWidget(status_);
    workspaceLayout_->addLayout(header);
    workspaceLayout_->addSpacing(15);
    page_ = new QWidget;
    page_->setObjectName("page");
    pageLayout_ = new QVBoxLayout(page_);
    pageLayout_->setContentsMargins(0, 0, 0, 0);
    pageLayout_->setSpacing(12);
    workspaceLayout_->addWidget(page_, 1);
    footer_ = label("Synthetic fixtures · session memory only                 Sample clock: "
                    "2026-10-08 10:42:40 UTC−03",
                    "faint");
    footer_->setObjectName("workspace-footer");
    footer_->setFixedHeight(27);
    footer_->setStyleSheet("border-top: 1px solid #262626; font-size: 10px; color: #6f6f6f;");
    workspaceLayout_->addWidget(footer_);
    shellLayout->addWidget(workspace_, 1);
    rootLayout->addWidget(shell, 1);
}
void MainWindow::selectView(const QString &view) {
    if (!navigation_.contains(view))
        return;
    closeModal();
    if (message_) {
        dispose(message_);
        message_.clear();
    }
    if (detail_) {
        dispose(detail_);
        detail_.clear();
    }
    selected_.clear();
    view_ = view;
    buildPage();
}
void MainWindow::buildPage() {
    if (refreshing_)
        return;
    refreshing_ = true;
    while (auto *item = pageLayout_->takeAt(0)) {
        if (item->widget())
            dispose(item->widget());
        else if (item->layout()) {
            auto *l = item->layout();
            while (auto *c = l->takeAt(0)) {
                dispose(c->widget());
                delete c;
            }
        }
        delete item;
    }
    table_.clear();
    rows_.clear();
    count_.clear();
    emptyState_.clear();
    for (auto it = navigation_.begin(); it != navigation_.end(); ++it)
        it.value()->setChecked(it.key() == view_);
    pendingCount_->setText(QString::number(model_.state().pending.size()));
    pendingCount_->setVisible(!model_.state().pending.isEmpty());
    sideStatus_->setText(model_.available()
                             ? (model_.service() == Service::UiClosed
                                    ? "UI closed · simulated scenario\nThis preview stays open"
                                    : "Synthetic model available\nNo protection is active")
                             : "Simulated service unavailable\nPolicy changes disabled");
    status_->setText(model_.available() ? "Synthetic data only\nNo network filtering"
                                        : "Simulated service unavailable\nPolicy changes disabled");
    const QMap<QString, QStringList> headings{
        {"processes",
         {"Processes", "Review each application’s access policy and latest attempts."}},
        {"pending",
         {"Pending decisions", "Review unmatched sample attempts while they remain pending."}},
        {"activity",
         {"Activity", "Attempts, authorizations and observed traffic are separate events."}},
        {"rules", {"Rules", "Review executable and service policies saved in this demo."}},
        {"import",
         {"Import from NetLimiter", "Preview a synthetic export before applying any demo rule."}},
        {"settings", {"Settings", "Explore protection states without changing your system."}}};
    title_->setText(headings[view_][0]);
    subtitle_->setText(headings[view_][1]);
    if (!model_.available()) {
        auto *n = note("Simulated service unavailable. Permission changes, import, activation, "
                       "cleanup and restore are disabled. No firewall engine is connected.");
        n->setObjectName("degraded-banner");
        pageLayout_->addWidget(n);
    }
    if (view_ == "processes")
        renderProcesses();
    else if (view_ == "pending")
        renderPending();
    else if (view_ == "activity")
        renderActivity();
    else if (view_ == "rules")
        renderRules();
    else if (view_ == "import")
        renderImport();
    else
        renderSettings();
    refreshing_ = false;
    refreshTable();
    renderNotice();
    positionOverlays();
}
void MainWindow::refresh() {
    if (detail_) {
        dispose(detail_);
        detail_.clear();
    }
    buildPage();
    if (!selected_.isEmpty() && view_ == "processes" && model_.process(selected_))
        openDetail(selected_);
    if (modalOverlay_ && !model_.available())
        closeModal();
}
QTableView *MainWindow::makeTable(const QStringList &headers, const QVector<int> &widths,
                                  int rowHeight) {
    table_ = new QTableView;
    table_->setObjectName(view_ + "-table");
    table_->setAccessibleName(view_ + " sample data");
    rows_ = new RowsModel(headers, table_);
    table_->setModel(rows_);
    table_->setItemDelegate(new CellDelegate(table_));
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setShowGrid(false);
    table_->setMouseTracking(true);
    table_->setAlternatingRowColors(false);
    table_->verticalHeader()->hide();
    table_->verticalHeader()->setDefaultSectionSize(rowHeight);
    table_->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    table_->horizontalHeader()->setFixedHeight(32);
    table_->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    table_->horizontalHeader()->setSectionsMovable(false);
    table_->setSortingEnabled(view_ == "processes" || view_ == "activity");
    if (table_->isSortingEnabled())
        table_->sortByColumn(0, Qt::AscendingOrder);
    QVariantList ws;
    for (int w : widths)
        ws << w;
    table_->setProperty("column-weights", ws);
    table_->viewport()->installEventFilter(this);
    table_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    emptyState_ = new QLabel(table_->viewport());
    emptyState_->setObjectName("empty-state");
    emptyState_->setAlignment(Qt::AlignCenter);
    emptyState_->setWordWrap(true);
    emptyState_->setProperty("role", "muted");
    emptyState_->setAttribute(Qt::WA_TransparentForMouseEvents);
    emptyState_->hide();
    connect(table_, &QTableView::clicked, this, [this](const QModelIndex &index) {
        if (view_ == "processes" ||
            (view_ == "pending" && (index.column() == 0 || index.column() == 3)) ||
            (view_ == "rules" && index.column() == 5))
            tableAction(index);
    });
    connect(table_, &QTableView::activated, this, &MainWindow::tableAction);
    pageLayout_->addWidget(table_, 1);
    return table_;
}
void MainWindow::renderProcesses() {
    auto *toolbar = line(pageLayout_);
    auto *search = new QLineEdit(query_);
    search->setObjectName("process-search");
    search->setAccessibleName("Search processes, paths or publishers");
    search->setPlaceholderText("Search processes, paths or publishers…");
    search->addAction(navigationIcon(6), QLineEdit::LeadingPosition);
    toolbar->addWidget(search, 1);
    auto *policy = combo({"All policies", "Ask", "Allow", "Block"}, "policy-filter");
    policy->setCurrentIndex(policyFilter_ == "All" ? 0 : policy->findText(policyFilter_));
    policy->setFixedWidth(113);
    toolbar->addWidget(policy);
    auto *running = combo({"All applications", "Running", "Missing executable"}, "running-filter");
    running->setCurrentIndex(runningFilter_ == "All" ? 0 : running->findText(runningFilter_));
    running->setFixedWidth(161);
    toolbar->addWidget(running);
    makeTable({"Process", "Policy", "Last attempt", "Last authorized attempt", "State"},
              {32, 15, 16, 22, 15});
    auto *foot = line(pageLayout_);
    count_ = label({}, "faint");
    foot->addWidget(count_);
    foot->addWidget(label("Last attempt includes blocked requests", "faint"));
    foot->addStretch();
    auto *stale = button("Review stale rules  →", "review-stale", "ghost");
    stale->setEnabled(model_.available());
    foot->addWidget(stale);
    connect(stale, &QPushButton::clicked, this, &MainWindow::cleanup);
    connect(search, &QLineEdit::textChanged, this, [this](const QString &v) {
        query_ = v;
        refreshTable();
    });
    connect(policy, &QComboBox::currentIndexChanged, this, [this, policy](int i) {
        policyFilter_ = i ? policy->currentText() : "All";
        refreshTable();
    });
    connect(running, &QComboBox::currentIndexChanged, this, [this, running](int i) {
        runningFilter_ = i ? running->currentText() : "All";
        refreshTable();
    });
}
void MainWindow::renderPending() {
    auto *n = note(QString("%1 applications need a decision. Closing a request keeps it pending in "
                           "this session. Repeated sample attempts are grouped by identity.")
                       .arg(model_.state().pending.size()));
    n->setObjectName("pending-state");
    pageLayout_->addWidget(n);
    auto *summary = line(pageLayout_);
    summary->addWidget(label("Blocked pending a decision · simulation", "warning"));
    summary->addWidget(label("No permanent permission is granted automatically", "muted"));
    summary->addStretch();
    makeTable({"Application", "Latest destination", "Last attempt", "Decision"}, {32, 31, 14, 23},
              57);
    auto *foot = line(pageLayout_);
    foot->addWidget(label(
        "Synthetic requests only · closing this application discards all demo state", "faint"));
    foot->addStretch();
    auto *review = button("Review selected request", "review-selected");
    review->setEnabled(model_.available());
    foot->addWidget(review);
    connect(review, &QPushButton::clicked, this, [this] {
        if (table_ && table_->currentIndex().isValid())
            openRequest(table_->currentIndex().data(IdRole).toString());
    });
}
void MainWindow::renderActivity() {
    auto *toolbar = line(pageLayout_);
    auto *search = new QLineEdit(activityQuery_);
    search->setObjectName("activity-search");
    search->setAccessibleName("Search activity");
    search->setPlaceholderText("Search activity…");
    toolbar->addWidget(search, 1);
    auto *filter = combo({"All event types", "Blocked attempts", "Authorized attempts",
                          "Observed traffic", "Rule decisions saved"},
                         "event-filter");
    filter->setCurrentIndex(eventFilter_ == "All" ? 0 : filter->findText(eventFilter_));
    toolbar->addWidget(filter);
    makeTable({"Time", "Process", "Event", "Destination", "Reason"}, {19, 22, 19, 20, 20}, 42);
    table_->sortByColumn(0, Qt::AscendingOrder);
    pageLayout_->addWidget(label("Synthetic history · coverage: this demo session. A decision "
                                 "never creates authorization or traffic.",
                                 "faint", true));
    connect(search, &QLineEdit::textChanged, this, [this](const QString &v) {
        activityQuery_ = v;
        refreshTable();
    });
    connect(filter, &QComboBox::currentIndexChanged, this, [this, filter](int i) {
        eventFilter_ = i ? filter->currentText() : "All";
        refreshTable();
    });
}
void MainWindow::renderRules() {
    auto *toolbar = line(pageLayout_);
    int active = 0;
    for (const auto &r : model_.state().rules)
        if (r.active)
            ++active;
    toolbar->addWidget(label(QString("%1 active demo rules · %2 inactive candidates")
                                 .arg(active)
                                 .arg(model_.state().rules.size() - active),
                             "muted"));
    toolbar->addStretch();
    if (model_.hasBackup()) {
        auto *restore = button("Restore demo backup", "restore-backup", "ghost");
        restore->setEnabled(model_.available());
        toolbar->addWidget(restore);
        connect(restore, &QPushButton::clicked, this, [this, epoch = model_.epoch()] {
            if (model_.restore(epoch))
                message("Demo backup restored in memory, including pending state and import "
                        "candidates.");
        });
    }
    auto *stale = button("Review stale rules", "review-stale");
    stale->setEnabled(model_.available());
    toolbar->addWidget(stale);
    connect(stale, &QPushButton::clicked, this, &MainWindow::cleanup);
    makeTable(
        {"Application", "Policy / state", "Application identity", "Last attempt", "Source", "Rule"},
        {24, 15, 20, 20, 12, 9});
    auto *foot = line(pageLayout_);
    foot->addWidget(label("Inactive candidates do not grant permission.", "faint"));
    foot->addStretch();
    auto *editButton = button("Edit / review selected", "edit-selected", "ghost");
    editButton->setEnabled(model_.available());
    foot->addWidget(editButton);
    connect(editButton, &QPushButton::clicked, this, [this] {
        if (!table_ || !table_->currentIndex().isValid())
            return;
        const auto id = table_->currentIndex().data(IdRole).toString();
        if (const auto *r = model_.rule(id))
            edit(id, !r->active);
    });
    pageLayout_->addWidget(
        label("Rules cover all outbound destinations and protocols · simulation only", "faint"));
}
void MainWindow::renderImport() {
    auto *n = note("Experimental import. Only a synthetic sample is available. Real NetLimiter "
                   "exports are not read, and no settings are accessed or changed.",
                   true);
    n->setObjectName("experimental-import");
    pageLayout_->addWidget(n);
    if (!model_.state().importLoaded) {
        auto *p = frame("panel");
        p->setObjectName("import-start");
        auto *l = new QVBoxLayout(p);
        l->setContentsMargins(16, 16, 16, 16);
        auto *h = line(l);
        auto *texts = new QVBoxLayout;
        texts->addWidget(label("Preview a sample export", "heading"));
        texts->addWidget(label("12 synthetic rules cover executable policies, conflicts, service "
                               "scopes and unsupported bandwidth settings.",
                               "muted", true));
        texts->addWidget(label("No NetLimiter settings are accessed or changed.", "muted"));
        h->addLayout(texts, 1);
        auto *load = button("Load sample export", "load-sample", "primary");
        load->setEnabled(model_.available());
        h->addWidget(load, 0, Qt::AlignTop);
        connect(load, &QPushButton::clicked, this,
                [this, epoch = model_.epoch()] { model_.loadImport(epoch); });
        pageLayout_->addWidget(p);
        pageLayout_->addStretch();
        return;
    }
    auto *counts = line(pageLayout_);
    counts->addWidget(label("7 Ready", "strong"));
    counts->addWidget(label("3 Need review", "warning"));
    counts->addWidget(label("2 Unsupported", "warning"));
    counts->addStretch();
    auto *reset = button("Reset sample", "reset-import", "ghost");
    reset->setEnabled(model_.available());
    counts->addWidget(reset);
    connect(reset, &QPushButton::clicked, this,
            [this, epoch = model_.epoch()] { model_.resetImport(epoch); });
    makeTable({"Original target", "Original policy", "Mapping", "Preview result"}, {27, 17, 18, 38},
              38);
    auto *foot = line(pageLayout_);
    foot->addWidget(label(model_.state().importApplied
                              ? "7 inactive sample candidates saved. Review them in Rules."
                              : "Only ready mappings are saved as inactive candidates.",
                          "faint", true),
                    1);
    auto *apply =
        button(model_.state().importApplied ? "Candidates saved" : "Save 7 inactive candidates",
               "apply-import", "primary");
    apply->setEnabled(model_.available() && !model_.state().importApplied);
    foot->addWidget(apply);
    connect(apply, &QPushButton::clicked, this, [this, epoch = model_.epoch()] {
        if (model_.applyImport(epoch))
            message(
                "7 inactive candidates saved. Review each candidate in Rules before activation.");
    });
}
void MainWindow::refreshTable() {
    if (!rows_ || !table_)
        return;
    const auto current = table_->currentIndex().data(IdRole).toString();
    QVector<Row> result;
    const auto &state = model_.state();
    if (view_ == "processes") {
        for (const auto &p : state.processes) {
            if (!query_.isEmpty() && !(p.name + " " + p.path + " " + p.publisher + " " + p.scope)
                                          .contains(query_, Qt::CaseInsensitive))
                continue;
            if (policyFilter_ != "All" && policyFilter_ != policyText(p.policy))
                continue;
            if ((runningFilter_ == "Running" && !p.running) ||
                (runningFilter_ == "Missing executable" && !p.missing))
                continue;
            result.push_back({p.id,
                              {{p.name, "glyph:" + p.initials, {}},
                               {policyText(p.policy),
                                model_.isPending(p.id) ? "AskPending" : policyText(p.policy),
                                {}},
                               {timestamp(p.attempt), {}, p.attempt},
                               {timestamp(p.authorized), {}, p.authorized},
                               {p.missing   ? "Missing file"
                                : p.running ? "Running"
                                            : "Not running",
                                p.missing ? "warning" : "",
                                {}}}});
        }
        if (count_)
            count_->setText(
                QString("%1 of %2 applications").arg(result.size()).arg(state.processes.size()));
    } else if (view_ == "pending") {
        for (const auto &id : {QString("updater"), QString("telemetry"), QString("helper")})
            if (model_.isPending(id))
                if (const auto *p = model_.process(id))
                    result.push_back(
                        {p->id,
                         {{p->name + "\n" + p->publisher, "strong", {}},
                          {p->destination + "\n" + p->protocol + " · outbound", "strong", {}},
                          {timestamp(p->attempt), {}, p->attempt},
                          {"Review request   →", "action", {}}}});
    } else if (view_ == "activity") {
        for (int i = 0; i < state.events.size(); ++i) {
            const auto &e = state.events[i];
            const QString match = e.kind == EventKind::Attempt         ? "Blocked attempts"
                                  : e.kind == EventKind::Authorization ? "Authorized attempts"
                                  : e.kind == EventKind::Traffic       ? "Observed traffic"
                                                                       : "Rule decisions saved";
            if (eventFilter_ != "All" && eventFilter_ != match)
                continue;
            if (!activityQuery_.isEmpty() && !(e.name + " " + e.destination + " " + e.reason)
                                                  .contains(activityQuery_, Qt::CaseInsensitive))
                continue;
            result.push_back({QString::number(i),
                              {{timestamp(e.age), {}, e.age},
                               {e.name, "strong", {}},
                               {eventText(e.kind), eventText(e.kind), {}},
                               {e.destination, {}, {}},
                               {e.reason, {}, {}}}});
        }
    } else if (view_ == "rules")
        for (const auto &r : state.rules)
            result.push_back(
                {r.id,
                 {{r.name, "strong", {}},
                  {r.active ? policyText(r.policy) : "Inactive · " + policyText(r.policy),
                   r.active ? policyText(r.policy) : "inactive",
                   {}},
                  {r.scope, {}, {}},
                  {timestamp(r.last), {}, r.last},
                  {r.source, {}, {}},
                  {r.active ? "Edit" : "Review", "action", {}}}});
    else if (view_ == "import")
        for (const auto &r : model_.sampleImport())
            result.push_back({r.id,
                              {{r.name, "strong", {}},
                               {r.bandwidth ? "Limit bandwidth" : policyText(r.policy),
                                r.bandwidth ? "" : policyText(r.policy),
                                {}},
                               {r.status, r.status, {}},
                               {r.note, {}, {}}}});
    rows_->replace(result);
    for (int i = 0; i < rows_->rowCount(); ++i)
        if (rows_->index(i, 0).data(IdRole).toString() == current) {
            table_->selectRow(i);
            break;
        }
    const bool empty = result.isEmpty();
    table_->setProperty("empty-state", empty);
    table_->setAccessibleDescription(
        empty ? "No matching sample rows. Change the search or filter."
              : "Synthetic fixtures only. Enter opens the selected row where available.");
    if (emptyState_) {
        emptyState_->setText(
            view_ == "pending"
                ? "No pending decisions\nEvery sample request has been resolved in this session."
                : "No matching sample rows\nChange the search or filter.");
        emptyState_->setVisible(empty);
    }
    positionOverlays();
}
void MainWindow::tableAction(const QModelIndex &index) {
    if (!index.isValid())
        return;
    const QString id = index.data(IdRole).toString();
    if (view_ == "processes")
        openDetail(id);
    else if (view_ == "pending")
        openRequest(id);
    else if (view_ == "rules" && (index.column() == 5 || index == table_->currentIndex()))
        if (const auto *r = model_.rule(id))
            edit(id, !r->active);
}
void MainWindow::openDetail(const QString &id) {
    const auto *p = model_.process(id);
    if (!p || view_ != "processes")
        return;
    selected_ = id;
    if (detail_)
        dispose(detail_);
    detail_ = new QFrame(page_);
    detail_->setObjectName("detail");
    auto *l = new QVBoxLayout(detail_);
    l->setContentsMargins(15, 15, 15, 13);
    l->setSpacing(10);
    auto *h = line(l);
    h->addWidget(label(p->name, "heading"), 1);
    auto *close = button("×", "close-detail", "ghost");
    close->setFixedWidth(25);
    close->setAccessibleName("Close process details");
    h->addWidget(close);
    connect(close, &QPushButton::clicked, this, [this] {
        selected_.clear();
        dispose(detail_);
        detail_.clear();
    });
    divider(l);
    auto *content = new QWidget;
    auto *body = new QVBoxLayout(content);
    body->setContentsMargins(0, 0, 0, 0);
    body->setSpacing(9);
    body->addWidget(label("Executable · synthetic", "muted"));
    body->addWidget(label(p->path, "link", true));
    definition(body, "Publisher", p->publisher);
    definition(body, "Signature", p->signature + " · sample");
    definition(body, "Policy", policyText(p->policy));
    definition(body, "Application identity", p->scope);
    definition(body, "Rule network scope", "All outbound destinations and protocols");
    definition(body, "Duration", p->duration);
    definition(body, "Last attempt", timestamp(p->attempt));
    definition(body, "Authorized", timestamp(p->authorized));
    definition(body, "Observed traffic", timestamp(p->traffic));
    body->addWidget(label("Recent destination · synthetic", "muted"));
    body->addWidget(label(p->destination + "\n" + p->protocol + " · outbound", "strong", true));
    body->addWidget(note("An authorized attempt is not proof that a connection succeeded.", true));
    body->addWidget(label("Identity", "muted"));
    body->addWidget(label("Rules refer to an executable or service identity. Names and icons alone "
                          "do not identify an application.",
                          "muted", true));
    body->addStretch();
    l->addWidget(scrollArea(content), 1);
    divider(l);
    auto *actions = line(l);
    auto *editButton = button("Edit demo rule", "detail-edit");
    editButton->setEnabled(model_.available());
    auto *activity = button("View activity", "detail-activity", "ghost");
    actions->addWidget(editButton);
    actions->addWidget(activity);
    connect(editButton, &QPushButton::clicked, this, [this, id] { edit(id); });
    connect(activity, &QPushButton::clicked, this, [this, name = p->name] {
        activityQuery_ = name;
        selectView("activity");
    });
    positionOverlays();
    detail_->show();
    detail_->raise();
}
void MainWindow::openRequest(const QString &id) {
    if (explanation_.open(id)) {
        renderNotice();
        if (auto *b = notice_->findChild<QPushButton *>("keep-access-pending"))
            b->setFocus();
    }
}
void MainWindow::renderNotice() {
    const auto id = explanation_.visibleId();
    const auto *p = model_.process(id);
    const QString focused = notice_ && notice_->isAncestorOf(QApplication::focusWidget())
                                ? QApplication::focusWidget()->objectName()
                                : QString{};
    const auto *oldScroll = notice_ ? notice_->findChild<QScrollArea *>("access-scroll") : nullptr;
    const int scrollPosition = oldScroll ? oldScroll->verticalScrollBar()->value() : 0;
    if (notice_) {
        dispose(notice_);
        notice_.clear();
    }
    if (!p || !model_.isPending(id))
        return;
    const auto review = model_.review(id);
    const auto epoch = model_.epoch();
    notice_ = new QFrame(root_);
    notice_->setObjectName("access-notice");
    notice_->setAccessibleName("Access request · simulation");
    auto *l = new QVBoxLayout(notice_);
    l->setContentsMargins(15, 12, 15, 12);
    l->setSpacing(9);
    auto *head = line(l);
    head->addWidget(label("LGA   GateBouncer · access request", "faint"), 1);
    auto *close = button("×", "close-request", "ghost");
    close->setFixedSize(25, 25);
    close->setAccessibleName("Close request and keep it pending");
    head->addWidget(close);
    connect(close, &QPushButton::clicked, &explanation_, &Explanation::close);
    l->addWidget(label(p->name, "heading"));
    l->addWidget(label(model_.available() ? "Blocked pending your decision · simulation"
                                          : "Simulated service unavailable · decision disabled",
                       "warning"));
    auto *content = new QWidget;
    auto *body = new QVBoxLayout(content);
    body->setContentsMargins(0, 0, 0, 0);
    body->setSpacing(9);
    auto *expl = new QFrame;
    expl->setObjectName("explanation");
    auto *el = new QVBoxLayout(expl);
    el->setContentsMargins(12, 11, 12, 11);
    el->setSpacing(7);
    auto *explanationHeader = line(el);
    if (explanation_.status() == ExplanationState::Loading)
        explanationHeader->addWidget(new Spinner);
    explanationHeader->addWidget(label("AI explanation · synthetic", "link"), 1);
    QString text;
    QString action = "Check this app";
    const auto state = explanation_.status();
    if (!model_.available())
        text = "The simulated service is unavailable. No permission change is possible.";
    else if (!explanation_.configured()) {
        text = "Set up the NVIDIA demo to see a sample explanation of what this app may be for.";
        action = "Open settings";
    } else if (!explanation_.consent()) {
        text = "Review the proposed sharing in Settings before asking for an explanation.";
        action = "Review settings";
    } else if (state == ExplanationState::Loading) {
        text = "Preparing a sample explanation…";
        action = "Cancel explanation";
    } else if (state == ExplanationState::Known) {
        text = "Local details · demo\n" + p->name + " · " + p->publisher +
               "\n\nPossible explanation\n" +
               (id == "updater" ? QString("This appears to be an updater. Checking for updates "
                                          "could explain an internet request.")
                : id == "telemetry"
                    ? QString("This name suggests a component that reports usage information. A "
                              "usage report could explain an internet request.")
                    : QString("This appears to be a helper for another application. Its name alone "
                              "does not explain why it needs internet access.")) +
               "\n\nWe cannot verify this file’s contents or whether the requested destination is "
               "appropriate.";
        action = "Check again";
    } else if (state == ExplanationState::Unclear) {
        text = "There is not enough information to explain this app. A name and publisher do not "
               "identify what the file actually does.";
        action = "Check again";
    } else if (state == ExplanationState::Error) {
        text = "The sample explanation could not be loaded. This request remains pending. You can "
               "try again or use the details below.";
        action = "Try again";
    } else
        text = "You can ask for a plain sample explanation of what this app may be for.";
    auto *result = label(text.left(2000), "muted", true);
    result->setObjectName("explanation-text");
    el->addWidget(result);
    auto *check = button(action, "check-explanation");
    check->setEnabled(model_.available());
    el->addWidget(check, 0, Qt::AlignLeft);
    connect(check, &QPushButton::clicked, this, [this, state] {
        if (!explanation_.configured() || !explanation_.consent())
            selectView("settings");
        else if (state == ExplanationState::Loading)
            explanation_.cancel();
        else
            explanation_.start();
    });
    el->addWidget(
        label("This is advice, not a malware scan.\nSample explanation · no external request",
              "faint", true));
    body->addWidget(expl);
    auto *accessScroll = qobject_cast<QScrollArea *>(scrollArea(content));
    accessScroll->setObjectName("access-scroll");
    l->addWidget(accessScroll, 1);
    QTimer::singleShot(0, accessScroll, [accessScroll, scrollPosition] {
        accessScroll->verticalScrollBar()->setValue(scrollPosition);
    });
    auto *fields = new QHBoxLayout;
    fields->setSpacing(9);
    auto *sl = new QVBoxLayout;
    sl->setSpacing(5);
    sl->addWidget(label("Apply to", "faint"));
    auto *scope = combo({"This executable", "Current process"}, "decision-scope");
    scope->setCurrentIndex(review.scope);
    scope->setEnabled(model_.available());
    sl->addWidget(scope);
    auto *dl = new QVBoxLayout;
    dl->setSpacing(5);
    dl->addWidget(label("Keep this decision", "faint"));
    auto *duration =
        combo({"Permanent", "For 15 minutes", "Until restart"},
              "decision-duration");
    duration->setCurrentIndex(review.duration);
    duration->setEnabled(model_.available());
    dl->addWidget(duration);
    fields->addLayout(sl, 1);
    fields->addLayout(dl, 1);
    l->addLayout(fields);
    connect(scope, &QComboBox::currentIndexChanged, this, [this, id, epoch](int value) {
        auto r = model_.review(id);
        r.scope = value;
        model_.setReview(id, epoch, r);
    });
    connect(duration, &QComboBox::currentIndexChanged, this, [this, id, epoch](int value) {
        auto r = model_.review(id);
        r.duration = value;
        model_.setReview(id, epoch, r);
    });
    l->addWidget(label("Process scope and timed permissions are simulated. Expiry and "
                          "enforcement are not implemented.",
                          "faint", true));
    auto *technical = button(review.expanded ? "▾ Technical details" : "▸ Technical details",
                             "technical-toggle", "link");
    l->addWidget(technical, 0, Qt::AlignLeft);
    connect(technical, &QPushButton::clicked, this, [this, id, epoch] {
        auto r = model_.review(id);
        r.expanded = !r.expanded;
        if (model_.setReview(id, epoch, r))
            renderNotice();
    });
    if (review.expanded) {
        auto *details = new QWidget;
        auto *detailsLayout = new QVBoxLayout(details);
        detailsLayout->setContentsMargins(0, 0, 0, 0);
        detailsLayout->setSpacing(9);
        detailsLayout->addWidget(label(p->path, "link", true));
        detailsLayout->addWidget(label(p->publisher + " · " + p->signature + " · sample", "faint", true));
        definition(detailsLayout, "Application identity",
                   review.scope ? "Current process · simulation" : "This executable");
        definition(detailsLayout, "Requested destination", p->destination);
        definition(detailsLayout, "Protocol", p->protocol + " · outbound");
        definition(detailsLayout, "Last attempt", timestamp(p->attempt));
        detailsLayout->addWidget(
            label("Allow saves a sample decision. It does not resume or observe a connection.",
                  "faint", true));
        auto *detailsScroll = scrollArea(details);
        detailsScroll->setObjectName("technical-scroll");
        l->addWidget(detailsScroll, 1);
    }
    divider(l);
    l->addWidget(label("If implemented, Allow would cover any destination.\nAll outbound "
                       "destinations and protocols",
                       "muted", true));
    auto *actions = line(l);
    auto *keep = button("Keep pending", "keep-access-pending", "ghost");
    actions->addWidget(keep);
    actions->addStretch();
    auto *block = button("Block", "decide-block", "danger");
    auto *allow = button("Allow", "decide-allow", "primary");
    block->setEnabled(model_.available());
    allow->setEnabled(model_.available());
    actions->addWidget(block);
    actions->addWidget(allow);
    connect(keep, &QPushButton::clicked, &explanation_, &Explanation::close);
    for (auto *b : {block, allow})
        connect(
            b, &QPushButton::clicked, this,
            [this, id, epoch, decision = b == allow ? Policy::Allow : Policy::Block] {
                if (explanation_.visibleId() == id && model_.decide(id, epoch, decision))
                    message(
                        "Decision saved in demo memory. Authorization and traffic are unchanged.");
            });
    auto *pendingLine = line(l);
    pendingLine->addWidget(
        label(QString::number(model_.state().pending.size()) + " pending applications", "faint"));
    pendingLine->addStretch();
    auto *list = button("View pending list", "view-pending-list", "link");
    pendingLine->addWidget(list);
    connect(list, &QPushButton::clicked, this, [this] { selectView("pending"); });
    notice_->setProperty("explanation-state", int(state));
    positionOverlays();
    notice_->show();
    notice_->raise();
    if (!focused.isEmpty())
        if (auto *control = notice_->findChild<QWidget *>(focused))
            control->setFocus();
    if (modalOverlay_)
        modalOverlay_->raise();
}
void MainWindow::renderSettings() {
    auto *content = new QWidget;
    auto *l = new QVBoxLayout(content);
    l->setContentsMargins(0, 0, 0, 15);
    l->setSpacing(12);
    content->setMaximumWidth(830);
    auto makePanel = [&](const QString &title, const QString &description) {
        auto *p = frame("panel");
        auto *pl = new QVBoxLayout(p);
        pl->setContentsMargins(16, 16, 16, 16);
        pl->setSpacing(8);
        pl->addWidget(label(title, "heading"));
        auto *paragraph = label(description, "muted", true);
        paragraph->setMinimumHeight(19);
        pl->addWidget(paragraph);
        l->addWidget(p);
        return pl;
    };
    auto *protection = makePanel("Protection state preview",
                                 "These scenarios change the interface only. No service is "
                                 "installed, started or stopped. No firewall engine is connected.");
    protection->parentWidget()->setObjectName("settings-state");
    protection->parentWidget()->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    protection->setSpacing(0);
    protection->insertSpacing(1, 8);
    protection->addSpacing(6);
    auto *serviceRow = new QWidget;
    serviceRow->setFixedHeight(58);
    auto *serviceLine = new QHBoxLayout(serviceRow);
    serviceLine->setContentsMargins(0, 6, 0, 13);
    serviceLine->setSpacing(16);
    protection->addWidget(serviceRow);
    auto *serviceText = new QVBoxLayout;
    serviceText->setSpacing(5);
    auto *serviceCaption = label("Demo service state", "strong");
    serviceCaption->setStyleSheet("color: #ccc; font-size: 12px; font-weight: 400;");
    serviceCaption->setFixedHeight(14);
    serviceText->addWidget(serviceCaption);
    serviceText->addWidget(label(
        model_.service() == Service::Unavailable
            ? "Simulated service unavailable. Policy changes are disabled."
        : model_.service() == Service::UiClosed ? "Only a scenario; this preview stays open. No service is installed."
                                               : "Synthetic model available. No firewall engine is connected.",
        "muted", true));
    serviceLine->addLayout(serviceText, 1);
    auto *service = combo({"Available · simulation", "UI closed · service continues (demo)",
                           "Unavailable · simulation"},
                          "demo-service");
    service->setMinimumWidth(214);
    service->setCurrentIndex(int(model_.service()));
    serviceLine->addWidget(service, 0, Qt::AlignTop);
    connect(service, &QComboBox::currentIndexChanged, this,
            [this](int i) { model_.setService(Service(i)); });
    auto *defaultRow = new QWidget;
    defaultRow->setFixedHeight(85);
    defaultRow->setObjectName("default-row");
    defaultRow->setStyleSheet("QWidget#default-row { border-top: 1px solid #262626; }");
    auto *defaultLine = new QHBoxLayout(defaultRow);
    defaultLine->setContentsMargins(0, 13, 0, 13);
    defaultLine->setSpacing(16);
    auto *defaultText = new QVBoxLayout;
    defaultText->setSpacing(5);
    auto *defaultCaption = label("Default policy", "strong");
    defaultCaption->setStyleSheet("color: #ccc; font-size: 12px; font-weight: 400;");
    defaultCaption->setFixedHeight(14);
    defaultText->addWidget(defaultCaption);
    auto *defaultDescription = label("Ask is a sample policy. A future engine must validate blocking.\nThis prototype does not filter traffic.", "muted", true);
    defaultDescription->setMinimumHeight(38);
    defaultText->addWidget(defaultDescription);
    defaultLine->addLayout(defaultText, 1);
    auto *defaultChip = label("Ask · demo only");
    defaultChip->setFixedHeight(21);
    defaultChip->setStyleSheet("background: #2d2614; border: 1px solid #4d4020; border-radius: 3px; color: #d4a437; font-size: 11px; padding: 2px 6px;");
    defaultLine->addWidget(defaultChip, 0, Qt::AlignTop);
    protection->addWidget(defaultRow);
    auto *history =
        makePanel("Activity and history",
                  "Last attempt includes blocked and authorized requests. Last authorized attempt "
                  "records policy authorization. Observed traffic is separate evidence; "
                  "authorization alone does not prove connectivity.");
    divider(history);
    definition(history, "Sample history coverage",
               "310 days of synthetic history. ‘Not observed’ means no sample event exists; it "
               "does not mean the application never connected.");
    auto *resetPanel = makePanel("Reset the preview",
                                 "Reset every sample decision, rule, import candidate and pending "
                                 "request. No system preferences or firewall rules are touched.");
    auto *reset = button("Reset demo", "reset-demo");
    resetPanel->addWidget(reset, 0, Qt::AlignRight);
    connect(reset, &QPushButton::clicked, this, [this] {
        explanation_.configure(false);
        model_.reset();
        message("Original synthetic fixtures restored. Nothing was changed on this machine.");
    });
    auto *lookup = makePanel("Application explanations · NVIDIA",
                             "Understand what an unfamiliar app may be for before deciding. This "
                             "is a synthetic explanation workflow.");
    lookup->addWidget(label("Use an NVIDIA API key", "strong"));
    auto *key = new QLineEdit;
    key->setObjectName("nvidia-demo-key");
    key->setReadOnly(true);
    key->setEchoMode(QLineEdit::Password);
    key->setPlaceholderText("Not connected in this demo");
    key->setMaximumWidth(375);
    key->setAccessibleDescription(
        "Read only and empty. No API key is entered, read, stored or sent.");
    lookup->addWidget(key);
    lookup->addWidget(
        label("Demo only. No key is read from another application, entered, stored or sent.",
              "muted", true));
    auto *configured = button(explanation_.configured() ? "Remove sample configuration"
                                                        : "Use sample configured state",
                              "sample-configuration");
    lookup->addWidget(configured, 0, Qt::AlignLeft);
    connect(configured, &QPushButton::clicked, this, [this] {
        explanation_.configure(!explanation_.configured());
        buildPage();
    });
    lookup->addWidget(label("Provider possibility: NVIDIA · sample responses are generated locally",
                            "faint", true));
    lookup->addWidget(
        note("A future online feature would send public app names and publishers to NVIDIA. No "
             "files, full paths or destinations would be shared. Automatic explanations would send "
             "those details even while the app remains blocked.\nNo data leaves this preview. "
             "Service, privacy, transport and key storage conditions remain unresolved.",
             true));
    auto *consent = new QCheckBox("I understand the proposed sharing");
    consent->setObjectName("lookup-consent");
    consent->setChecked(explanation_.consent());
    consent->setEnabled(explanation_.configured());
    lookup->addWidget(consent);
    connect(consent, &QCheckBox::toggled, this, [this](bool on) {
        explanation_.setConsent(on);
        buildPage();
    });
    auto *automatic = new QCheckBox("Automatically explain new requests");
    automatic->setObjectName("lookup-automatic");
    automatic->setChecked(explanation_.automatic());
    automatic->setEnabled(explanation_.configured() && explanation_.consent());
    lookup->addWidget(automatic);
    connect(automatic, &QCheckBox::toggled, &explanation_, &Explanation::setAutomatic);
    lookup->addWidget(label("A real connection requires separate authorization. An explanation "
                            "never allows an app or verifies safety.",
                            "muted", true));
    auto *fixtureLine = line(lookup);
    fixtureLine->addWidget(label("Demo explanation result", "strong"), 1);
    auto *fixture =
        combo({"Expected purpose", "Not enough information", "Service error"}, "lookup-fixture");
    fixture->setCurrentIndex(explanation_.fixture() == ExplanationState::Known     ? 0
                             : explanation_.fixture() == ExplanationState::Unclear ? 1
                                                                                   : 2);
    fixtureLine->addWidget(fixture);
    connect(fixture, &QComboBox::currentIndexChanged, this, [this](int i) {
        explanation_.setFixture(i == 0   ? ExplanationState::Known
                                : i == 1 ? ExplanationState::Unclear
                                         : ExplanationState::Error);
    });
    l->removeWidget(history->parentWidget());
    l->removeWidget(resetPanel->parentWidget());
    l->addWidget(history->parentWidget());
    l->addWidget(resetPanel->parentWidget());
    l->addStretch();
    pageLayout_->addWidget(scrollArea(content), 1);
}
QVBoxLayout *MainWindow::modal(const QString &title) {
    closeModal();
    previousFocus_ = QApplication::focusWidget();
    modalOverlay_ = new QFrame(root_);
    modalOverlay_->setObjectName("modal-overlay");
    auto *outer = new QVBoxLayout(modalOverlay_);
    outer->setContentsMargins(18, 18, 18, 18);
    outer->addStretch();
    auto *middle = new QHBoxLayout;
    middle->addStretch();
    auto *panel = new QFrame;
    panel->setObjectName("modal-panel");
    panel->setMaximumWidth(570);
    panel->setMinimumWidth(520);
    modalPanel_ = panel;
    auto *pl = new QVBoxLayout(panel);
    pl->setContentsMargins(22, 18, 22, 18);
    pl->setSpacing(12);
    auto *h = line(pl);
    h->addWidget(label(title, "title"), 1);
    auto *close = button("×", "close-modal", "ghost");
    close->setFixedWidth(25);
    close->setAccessibleName("Close dialog and keep current state");
    h->addWidget(close);
    connect(close, &QPushButton::clicked, this, &MainWindow::closeModal);
    middle->addWidget(panel, 1);
    middle->addStretch();
    outer->addLayout(middle);
    outer->addStretch();
    positionOverlays();
    modalOverlay_->show();
    modalOverlay_->raise();
    return pl;
}
void MainWindow::closeModal() {
    if (modalOverlay_) {
        dispose(modalOverlay_);
        modalOverlay_.clear();
        modalPanel_.clear();
        if (previousFocus_)
            previousFocus_->setFocus();
        previousFocus_.clear();
    }
}
void MainWindow::edit(const QString &id, bool candidate) {
    if (!model_.available())
        return;
    const auto *r = model_.rule(id);
    const auto *p = model_.process(id);
    if (!r && !p)
        return;
    if (candidate && (!r || r->active))
        return;
    if (!candidate && r && !r->active)
        return;
    const auto epoch = model_.epoch();
    const QString name = p ? p->name : r->name;
    const QString scope = p ? p->scope : r->scope;
    auto *l = modal(candidate ? "Review inactive demo candidate" : "Edit demo rule");
    l->addWidget(label(candidate ? "This candidate is inactive and grants no permission. Review "
                                   "the target, policy and scope before activation."
                                 : "Change the policy in this session only.",
                       "muted", true));
    l->addWidget(
        note(name + "\n" + (p ? p->path : "C:\\Demo Import\\" + name) + "\nSynthetic identity only",
             true));
    auto *form = line(l);
    form->addWidget(label(candidate ? "Policy to activate" : "Policy", "muted"));
    auto *policy = combo(candidate ? QStringList{"Allow", "Block"}
                                   : QStringList{"Allow", "Block", "Ask next time"},
                         "edit-policy");
    const auto selected = p ? p->policy : r->policy;
    policy->setCurrentIndex(selected == Policy::Allow ? 0 : selected == Policy::Block ? 1 : 2);
    form->addWidget(policy);
    form->addStretch();
    l->addWidget(label("Application identity: " + scope +
                           "\nRule network scope: All outbound destinations and "
                           "protocols\nDuration: permanent in this demo session",
                       "muted", true));
    l->addWidget(note(candidate ? "Activation is a separate decision. It does not create an "
                                  "authorized attempt or observed traffic."
                                : "Ask next time removes the matching demo rule. It does not "
                                  "create a new request or network event.",
                      true));
    divider(l);
    auto *actions = line(l);
    auto *cancel = button(candidate ? "Keep inactive" : "Cancel", "cancel-edit", "ghost");
    actions->addWidget(cancel);
    actions->addStretch();
    auto *save =
        button(candidate ? "Activate demo rule" : "Save demo rule", "save-rule", "primary");
    actions->addWidget(save);
    connect(cancel, &QPushButton::clicked, this, &MainWindow::closeModal);
    connect(save, &QPushButton::clicked, this, [this, id, epoch, policy, candidate] {
        const auto choice = policy->currentIndex() == 0   ? Policy::Allow
                            : policy->currentIndex() == 1 ? Policy::Block
                                                          : Policy::Ask;
        const bool done =
            candidate ? model_.activate(id, epoch, choice) : model_.editRule(id, epoch, choice);
        if (done) {
            closeModal();
            message(candidate ? "Reviewed candidate activated in demo memory."
                              : "Policy updated in demo memory.");
        }
    });
    cancel->setFocus();
}
void MainWindow::cleanup() {
    if (!model_.available())
        return;
    const auto epoch = model_.epoch();
    const auto candidates = model_.cleanupCandidates(cleanupDays_);
    auto *l = modal("Review stale demo rules");
    l->addWidget(label("No rule is removed automatically. The sample history covers 310 days. Real "
                       "incomplete history would require a coverage warning.",
                       "muted", true));
    auto *form = line(l);
    form->addWidget(label("No attempts observed for", "muted"));
    auto *threshold = combo({"90 days", "180 days", "365 days"}, "cleanup-threshold");
    threshold->setCurrentIndex(cleanupDays_ == 90 ? 0 : cleanupDays_ == 180 ? 1 : 2);
    form->addWidget(threshold);
    form->addStretch();
    connect(threshold, &QComboBox::currentIndexChanged, this, [this](int i) {
        cleanupDays_ = i == 0 ? 90 : i == 1 ? 180 : 365;
        cleanup();
    });
    l->addWidget(note("Removing selected rules returns those sample applications to Ask. No file "
                      "is deleted, and no request or traffic is generated.",
                      true));
    auto *checks = new QWidget;
    auto *cl = new QVBoxLayout(checks);
    cl->setContentsMargins(0, 0, 0, 0);
    cl->setSpacing(8);
    QVector<QCheckBox *> boxes;
    for (const auto &r : candidates) {
        auto *b = new QCheckBox(r.name + " · " + policyText(r.policy));
        b->setObjectName("cleanup-" + r.id);
        b->setProperty("rule-id", r.id);
        cl->addWidget(b);
        cl->addWidget(label((r.missing ? "Executable missing · " : "Executable present · ") +
                                QString::number(r.days) +
                                " days since rule creation\nLast attempt: " + timestamp(r.last),
                            "faint", true));
        boxes.push_back(b);
    }
    if (candidates.isEmpty())
        cl->addWidget(label("No sample rules match this age.", "muted"));
    l->addWidget(checks);
    l->addWidget(label("A complete synthetic state backup is saved in memory before removal. "
                       "Closing the application discards the backup.",
                       "faint", true));
    divider(l);
    auto *actions = line(l);
    auto *cancel = button("Cancel", "cancel-cleanup", "ghost");
    actions->addWidget(cancel);
    actions->addStretch();
    auto *remove = button("Back up & remove selected", "cleanup-remove", "danger");
    remove->setEnabled(false);
    actions->addWidget(remove);
    connect(cancel, &QPushButton::clicked, this, &MainWindow::closeModal);
    for (auto *b : boxes)
        connect(b, &QCheckBox::toggled, remove, [boxes, remove] {
            bool selected = false;
            for (const auto *box : boxes)
                selected |= box->isChecked();
            remove->setEnabled(selected);
        });
    connect(remove, &QPushButton::clicked, this, [this, boxes, epoch] {
        QSet<QString> ids;
        for (const auto *b : boxes)
            if (b->isChecked())
                ids.insert(b->property("rule-id").toString());
        if (model_.cleanup(ids, cleanupDays_, epoch)) {
            closeModal();
            selectView("rules");
            message(QString::number(ids.size()) +
                    " demo rules removed. Complete memory backup available to restore.");
        }
    });
    cancel->setFocus();
}
void MainWindow::about() {
    auto *l = modal("About LGA GateBouncer");
    l->addWidget(label("Native desktop prototype · offline simulation", "heading"));
    l->addWidget(note("This application does not protect this machine or filter network traffic. "
                      "No firewall engine is connected.",
                      true));
    l->addWidget(
        label("All process names, paths, signatures, timestamps, destinations, import rules and "
              "activity are synthetic fixtures. No real processes, files, network events, API keys "
              "or NetLimiter configuration are read.\n\nSearch, filters, sorting, decisions, "
              "import and cleanup use session memory only. Close the application to discard all "
              "demo state.\n\nEscape closes an overlay while preserving a pending request. Tab "
              "moves between controls; Enter opens a selected table row. Timed permissions are "
              "simulated and do not expire through an enforcement engine.",
              "muted", true));
    auto *close = button("Close", "about-close");
    l->addWidget(close, 0, Qt::AlignRight);
    connect(close, &QPushButton::clicked, this, &MainWindow::closeModal);
    close->setFocus();
}
void MainWindow::message(const QString &text) {
    if (message_)
        dispose(message_);
    message_ = new QFrame(root_);
    message_->setObjectName("message");
    auto *l = new QHBoxLayout(message_);
    l->setContentsMargins(13, 11, 13, 11);
    l->setSpacing(15);
    l->addWidget(label(text, "link", true), 1);
    auto *close = button("×", "dismiss-message", "ghost");
    close->setFixedWidth(25);
    close->setAccessibleName("Dismiss notice");
    l->addWidget(close);
    connect(close, &QPushButton::clicked, this, [this] {
        dispose(message_);
        message_.clear();
    });
    positionOverlays();
    message_->show();
    message_->raise();
}
void MainWindow::positionOverlays() {
    if (!root_)
        return;
    const bool small = width() <= 1100;
    sidebar_->setFixedWidth(small ? 190 : 208);
    workspaceLayout_->setContentsMargins(small ? 14 : 18, small ? 15 : 18, small ? 14 : 18, 0);
    pendingCount_->move(navigation_["pending"]->width() - 30, 10);
    if (table_) {
        const auto weights = table_->property("column-weights").toList();
        const int width = table_->viewport()->width();
        int used = 0;
        for (int i = 0; i < weights.size(); ++i) {
            const int size =
                i == weights.size() - 1 ? width - used : width * weights[i].toInt() / 100;
            table_->setColumnWidth(i, size);
            used += size;
        }
    }
    if (table_ && emptyState_)
        emptyState_->setGeometry(0, 20, table_->viewport()->width(), 100);
    if (detail_)
        detail_->setGeometry(qMax(0, page_->width() - (small ? 325 : 338)), 0, small ? 325 : 338,
                             qMax(100, page_->height() - 43));
    if (notice_) {
        const int w = small ? 400 : 420;
        const int h = qMin(root_->height() - 105,
                           model_.review(explanation_.visibleId()).expanded ? 625 : 541);
        notice_->setGeometry(root_->width() - w - 20, root_->height() - h - 20, w, h);
    }
    if (modalOverlay_)
        modalOverlay_->setGeometry(0, 36, root_->width(), root_->height() - 36);
    if (message_) {
        const int w = notice_ ? qMin(460, root_->width() - 480) : 460;
        message_->setGeometry(notice_ ? 18 : root_->width() - w - 18, root_->height() - 90, w,
                              qMax(52, message_->sizeHint().height()));
    }
}
void MainWindow::resizeEvent(QResizeEvent *event) {
    QMainWindow::resizeEvent(event);
    positionOverlays();
}
bool MainWindow::eventFilter(QObject *object, QEvent *event) {
    if (event->type() == QEvent::Resize && table_ && object == table_->viewport()) {
        positionOverlays();
    }
    if (object->objectName() == "titlebar") {
        if (event->type() == QEvent::MouseButtonPress) {
            auto *e = static_cast<QMouseEvent *>(event);
            if (e->button() == Qt::LeftButton)
                dragStart_ = e->globalPosition().toPoint() - frameGeometry().topLeft();
        }
        if (event->type() == QEvent::MouseMove) {
            auto *e = static_cast<QMouseEvent *>(event);
            if (e->buttons() & Qt::LeftButton)
                move(e->globalPosition().toPoint() - dragStart_);
        }
    }
    if (event->type() == QEvent::KeyPress) {
        auto *key = static_cast<QKeyEvent *>(event);
        auto *widget = qobject_cast<QWidget *>(object);
        if (!widget || (widget != this && !isAncestorOf(widget)))
            return QMainWindow::eventFilter(object, event);
        if (key->key() == Qt::Key_Escape) {
            if (modalOverlay_)
                closeModal();
            else if (notice_)
                explanation_.close();
            else if (detail_) {
                selected_.clear();
                dispose(detail_);
                detail_.clear();
            }
            return true;
        }
        if (modalPanel_ && (key->key() == Qt::Key_Tab || key->key() == Qt::Key_Backtab)) {
            QWidget *focus = QApplication::focusWidget();
            if (!focus)
                focus = modalPanel_;
            const bool forward =
                key->key() == Qt::Key_Tab && !(key->modifiers() & Qt::ShiftModifier);
            QWidget *next = focus;
            for (int i = 0; i < 200; ++i) {
                next = forward ? next->nextInFocusChain() : next->previousInFocusChain();
                if (modalPanel_->isAncestorOf(next) && next->isEnabled() &&
                    next->isVisibleTo(modalPanel_) && (next->focusPolicy() & Qt::TabFocus)) {
                    next->setFocus(forward ? Qt::TabFocusReason : Qt::BacktabFocusReason);
                    break;
                }
            }
            return true;
        }
    }
    return QMainWindow::eventFilter(object, event);
}
} // namespace Gate
