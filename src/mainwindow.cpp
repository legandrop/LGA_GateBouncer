#include "mainwindow.h"
#include "assistance/ui/SettingsWidget.h"
#include "assistance/ui/ExplanationWidget.h"
#include "assistance/ui/ObservationSelection.h"
#include <QAbstractTableModel>
#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QEvent>
#include <QDateTime>
#include <QDataStream>
#include <QIODevice>
#include <QFileDialog>
#include <QFontMetrics>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QHash>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QProgressBar>
#include <QPlainTextEdit>
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
QString recordText(const gb::wire::Bytes &bytes, const QString &fallback) {
    return bytes.empty() ? fallback : QString::fromUtf8(reinterpret_cast<const char *>(bytes.data()), qsizetype(bytes.size()));
}
QString accountText(const gb::wire::Bytes &sid) {
    if (sid.size() < 8 || sid[0] != 1 || sid.size() != 8u + 4u * sid[1]) return "Unknown";
    quint64 authority = 0;
    for (int i = 2; i < 8; ++i) authority = (authority << 8) | sid[i];
    QString text = "S-1-" + QString::number(authority);
    for (std::size_t i = 8; i < sid.size(); i += 4) {
        quint32 value = 0;
        for (int b = 0; b < 4; ++b) value |= quint32(sid[i+b]) << (8*b);
        text += '-' + QString::number(value);
    }
    return text;
}
QString targetAccountText(const gb::wire::iv::PrincipalRuleRecord &rule) {
    gb::wire::iv::OriginalTarget target;
    return gb::wire::iv::unpackOriginalTarget(rule.originalTarget,target) == gb::wire::Error::Ok
        ? accountText(target.accountSid) : QString("Unknown");
}
QString reconstructionText(const Data::SemanticCandidate *candidate) {
    if (!candidate) return "Analysis pending";
    switch (candidate->reconstruction) {
    case Data::Reconstruction::ReconstructedSubset: return "Reconstructed subset";
    case Data::Reconstruction::Unsupported: return "Unsupported type";
    default: return "Incomplete · known fields retained";
    }
}
QString semanticFacts(const ImportedReviewView &view, const Data::SemanticCandidate *candidate) {
    QStringList text{"Inactive · Unverified", "Profile: External · unaccredited", "Engine policy eligible: No"};
    if (!candidate) {
        text << (view.busy ? "Deriving source facts… Reopen after analysis completes."
                          : "Derived facts unavailable: " + view.facts.error);
        return text.join('\n');
    }
    text << "Reconstruction: " + reconstructionText(candidate)
         << "Source action: " + (candidate->action ? Data::actionName(*candidate->action) : "Unknown")
         << "Source direction: " + Data::directionName(candidate->direction)
         << QString("Source enabled: ") + (candidate->sourceEnabled ? (*candidate->sourceEnabled ? "True" : "False") : "Unknown")
         << "Source weight: " + (candidate->sourceWeight ? QString::number(*candidate->sourceWeight) : "Unknown")
         << "Subject scope: Unknown · no automatic path or instance mapping"
         << "Constraints: Unknown · dependencies retained below"
         << "Conflicts: " + QString(candidate->potentialConflict ? "Potential conflict" : "No confirmed conflict")
         << "Overlap: " + QString(candidate->overlapUnknown ? "Unknown" : "No unresolved overlap reported")
         << "Conflict analysis complete: " + QString(view.facts.conflictsComplete ? "Yes · within this profile" : "No")
         << "Diagnostics: " + QStringList(candidate->diagnostics.begin(), candidate->diagnostics.end()).join(" · ")
         << "Profile diagnostics: " + QStringList(view.facts.diagnostics.begin(), view.facts.diagnostics.end()).join(" · ");
    return text.join('\n');
}
QString qnameAction(const Data::QNameCandidateFacts *c) {
    if (!c || !c->action.known()) return "Unknown";
    switch (c->action.value) {
    case Data::SourceFwAction::None: return "None (0)";
    case Data::SourceFwAction::Ask: return "Ask (1)";
    case Data::SourceFwAction::Allow: return "Allow (2)";
    case Data::SourceFwAction::Deny: return "Deny (3)";
    case Data::SourceFwAction::Block: return "Block (4)";
    }
    return "Unknown";
}
QString qnameFacts(const ImportedReviewView &view, const Data::QNameCandidateFacts *c) {
    QStringList out{"Inactive · Unverified", "Profile: Explicit QName source subset", "Engine policy eligible: No"};
    if (!c || !view.qname) { out << (view.busy ? "Deriving source facts… Reopen after analysis completes." : "QName facts unavailable"); return out.join('\n'); }
    const auto &v = *view.qname;
    out << "Source action: " + qnameAction(c) << "Source direction: " + (c->direction.known() ? Data::directionName(c->direction.value) : "Unknown")
        << "Source enabled: " + (c->enabled.known() ? (c->enabled.value ? QString("True") : QString("False")) : QString("Unknown"))
        << "Source weight: " + (c->weight.known() ? QString::number(c->weight.value) : "Unknown")
        << "Reconstructed source subset complete: " + QString(c->complete ? "Yes" : "No · known fields retained")
        << "Profile version known: " + QString(v.profileKnown ? "Yes" : "No")
        << "Omissions / residues: " + QString::number(c->residues.size())
        << "Conflict analysis complete: " + QString(v.conflictsComplete ? "Yes · within this profile" : "No · comparison limit or unresolved input")
        << "Conflict: " + QString(c->potentialConflict ? "Potential" : "No confirmed conflict")
        << "Subject scope: Source constraints only · Windows identity and service scope Unknown";
    auto application = [&](const Data::ApplicationConstraint &a) {
        out << "Path: " + (a.path.known() ? a.path.value : "Unknown")
            << "Path exact predicate: " + QString(a.pathExact ? "True" : "Unknown or non-exact")
            << "SID source bytes: " + (a.sidBytes.known() ? a.sidBytes.value : "Unknown")
            << "Package: " + (a.packageId.known() ? a.packageId.value : "Unknown")
            << "Service: " + (a.serviceName.known() ? a.serviceName.value : "Unknown");
    };
    if (c->filterIndex >= 0 && c->filterIndex < v.filters.size()) {
        const auto &f = v.filters[c->filterIndex]; application(f.package);
        int shown = 0;
        for (const auto &p : f.predicates) {
            if (++shown > 12) { out << "Additional predicates retained in source evidence"; break; }
            out << "Predicate: " + p.kind + " · " + (p.complete ? "Known subset" : "Incomplete")
                << "Match: " + (p.match.known() ? (p.match.value ? QString("True") : QString("False")) : QString("Unknown"));
            if (p.kind == "FFIsInternetTraffic" || p.kind == "FFIsLocalNetworkTraffic")
                out << "Zone classification: NetLimiter source · current Windows coverage Unknown";
            else out << "Values: OR within this predicate · match applies to the combined result";
            for (const auto &a : p.applications) { if (out.size() >= 140) break; application(a); }
            for (const auto &domain : p.domains) { if (out.size() >= 140) break; out << "Domain source: " + (domain.known() ? domain.value : "Unknown"); }
            for (const auto &tag : p.tags) { if (out.size() >= 140) break; out << "Tag source: " + (tag.known() ? tag.value : "Unknown"); }
            for (const auto &range : p.remoteRanges) { if (out.size() >= 140) break; out << "Remote range source: " + (range.lexical.known() ? range.lexical.value : "Unknown") + " · inclusive endpoints"; }
        }
        out << "Filter functions: AND · source weight: higher values take precedence; ties remain unresolved";
    } else out << "Constraints: Unknown · unresolved filter";
    out << "Profile diagnostics: " + QStringList(v.diagnostics.begin(), v.diagnostics.end()).join(" · ");
    return out.join('\n').left(32000);
}
QString recordUtc(quint64 nanos, bool present) {
    return present ? QDateTime::fromMSecsSinceEpoch(qint64(nanos / 1000000), QTimeZone::UTC)
                         .toString("yyyy-MM-dd HH:mm:ss 'UTC'") : "Unknown";
}
QString engineRowId(const QString &kind, const gb::wire::Id &epoch, const gb::wire::Id &id) {
    return kind + ":" + QString::fromStdString(gb::wire::hex(epoch)) + ":" + QString::fromStdString(gb::wire::hex(id));
}
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
        widget->setProperty("retired",true);
        widget->hide();
        widget->deleteLater();
    }
}
template<class T> T *pageControl(QWidget *page,const char *name) {
    for (auto *control : page->findChildren<T *>(name)) {
        bool retired = false;
        for (auto *p = static_cast<QWidget *>(control); p && p != page; p = p->parentWidget())
            if (p->property("retired").toBool()) { retired = true; break; }
        if (!retired) return control;
    }
    return nullptr;
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
    v->setProperty("definition-name",name);
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
        if (role == Qt::DisplayRole || role == Qt::AccessibleTextRole)
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
        QHash<QString, int> incoming;
        for (int i = 0; i < rows.size(); ++i) incoming.insert(rows[i].id, i);
        // Las identidades supervivientes conservan selección e índices persistentes.
        bool changed = false;
        for (int end = rows_.size() - 1; end >= 0;) {
            if (incoming.contains(rows_[end].id)) { --end; continue; }
            int start = end;
            while (start && !incoming.contains(rows_[start - 1].id)) --start;
            beginRemoveRows({}, start, end); rows_.remove(start, end - start + 1); endRemoveRows();
            changed = true; end = start - 1;
        }
        QSet<QString> retained;
        for (int i = 0; i < rows_.size(); ++i) {
            retained.insert(rows_[i].id);
            const auto &next = rows[incoming.value(rows_[i].id)];
            bool equal = rows_[i].cells.size() == next.cells.size();
            for (int c = 0; equal && c < next.cells.size(); ++c)
                equal = rows_[i].cells[c].text == next.cells[c].text &&
                    rows_[i].cells[c].kind == next.cells[c].kind && rows_[i].cells[c].sort == next.cells[c].sort;
            if (!equal) {
                rows_[i] = next; changed = true;
                emit dataChanged(index(i, 0), index(i, headers_.size() - 1));
            }
        }
        QVector<Row> added;
        for (auto &r : rows) if (!retained.contains(r.id)) added.push_back(std::move(r));
        if (!added.isEmpty()) {
            const int first = rows_.size(); beginInsertRows({}, first, first + added.size() - 1);
            rows_ += added; endInsertRows(); changed = true;
        }
        if (changed) sort(sortColumn_, sortOrder_);
    }
    void sort(int column, Qt::SortOrder order) override {
        if (column < 0 || column >= headers_.size())
            return;
        sortColumn_ = column;
        sortOrder_ = order;
        const auto less = [&](const Row &a, const Row &b) {
            const auto &ac = a.cells[column]; const auto &bc = b.cells[column];
            int cmp = ac.sort.isValid() && bc.sort.isValid() && ac.sort.metaType().id() != QMetaType::QString
                ? (ac.sort.toLongLong() < bc.sort.toLongLong() ? -1 : ac.sort.toLongLong() > bc.sort.toLongLong() ? 1 : 0)
                : QString::compare(ac.text, bc.text, Qt::CaseInsensitive);
            if (!cmp) cmp = QString::compare(a.id, b.id, Qt::CaseSensitive);
            return order == Qt::AscendingOrder ? cmp < 0 : cmp > 0;
        };
        if (std::is_sorted(rows_.begin(), rows_.end(), less)) return;
        emit layoutAboutToBeChanged({}, QAbstractItemModel::VerticalSortHint);
        const auto persistent = persistentIndexList();
        QStringList identities;
        for (const auto &i : persistent) identities.append(rows_[i.row()].id);
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
            if (cmp == 0) cmp = QString::compare(a.id, b.id, Qt::CaseSensitive);
            return order == Qt::AscendingOrder ? cmp < 0 : cmp > 0;
        });
        QHash<QString, int> positions;
        for (int row = 0; row < rows_.size(); ++row) positions.insert(rows_[row].id, row);
        QModelIndexList remapped;
        for (int i = 0; i < persistent.size(); ++i) {
            const int row = positions.value(identities[i], -1);
            remapped.append(row < 0 ? QModelIndex{} : index(row, persistent[i].column()));
        }
        changePersistentIndexList(persistent, remapped);
        emit layoutChanged({}, QAbstractItemModel::VerticalSortHint);
    }

  private:
    QStringList headers_;
    QVector<Row> rows_;
    int sortColumn_ = -1;
    Qt::SortOrder sortOrder_ = Qt::AscendingOrder;
};

MainWindow::MainWindow(QWidget *parent, bool isolatedQa, const QString &qaRoot,
                       std::unique_ptr<gb::ipc::ii::SessionChannel> decisionChannel,
                       std::unique_ptr<ReviewBackend> reviewer,
                       std::unique_ptr<gb::ipc::ii::SessionChannel> ordinaryChannel)
    : QMainWindow(parent), model_(this), explanation_(&model_), product_(isolatedQa, qaRoot, this, std::move(decisionChannel), std::move(ordinaryChannel)),
      reviewer_(isolatedQa, this, std::move(reviewer)) {
    setObjectName("GateBouncer");
    setWindowTitle("LGA GateBouncer");
    setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
    resize(1280, 800);
    setMinimumSize(900, 620);
    buildShell();
    buildPage();
    connect(&model_, &Simulation::changed, this, &MainWindow::refresh);
    connect(&explanation_, &Explanation::changed, this, &MainWindow::renderNotice);
    connect(&product_, &ProductController::changed, this, &MainWindow::refresh);
    connect(&product_, &ProductController::changed, this, &MainWindow::updateLifecycle);
    connect(&product_, &ProductController::reviewSaved, this, [this](const QString &text) { if (!closing_) message(text); });
    connect(&product_, &ProductController::changed, this, &MainWindow::renderOrdinaryNotice);
    connect(&product_, &ProductController::importedViewsInvalidated, this, &MainWindow::closeStaleModal);
    connect(&model_, &Simulation::changed, this, &MainWindow::updateLifecycle);
    connect(&reviewer_, &ReviewGateway::changed, this, [this] {
        // Las páginas anteriores se retiran con deleteLater; actualizar también el aviso actual.
        for (auto *status : findChildren<QLabel *>("reviewer-status")) status->setText(reviewer_.status());
    });
    connect(&product_, &ProductController::invalidated, this, [this] {
        if(assistance_)assistance_->invalidate();
        explanation_.close(); reviewer_.invalidate(); closeStaleModal(); selected_.clear();
        if (detail_) { dispose(detail_); detail_.clear(); }
    });
    qApp->installEventFilter(this);
    QTimer::singleShot(0, &product_, &ProductController::refreshProcesses);
}
MainWindow::~MainWindow(){
    if(assistanceConnection_)assistanceConnection_->close();
    if(assistance_)assistance_->close();
    assistanceConnection_.reset();
}
void MainWindow::enableNativeAssistance(){
    if(closing_||assistanceConnection_)return;
    assistanceConnection_=std::make_unique<Assistance::Ui::GeneralConnection>(*this);
    connect(assistanceConnection_.get(),&Assistance::Ui::GeneralConnection::failed,this,&MainWindow::message);
}
void MainWindow::setAssistance(std::unique_ptr<Assistance::Ui::GeneralSession> session) {
    if(assistance_)assistance_->close();
    assistance_=std::move(session);
    if(ordinaryExplanation_)ordinaryExplanation_->setSession(assistance_.get());
    buildPage();
}
void MainWindow::startLifecycle(std::unique_ptr<Lifecycle::TraySurface> tray, bool minimized,
                                std::unique_ptr<Lifecycle::StartupPreference> startup) {
    if (lifecycle_ || closing_) return;
    startup_ = std::move(startup);
    lifecycle_ = new Lifecycle::LifecycleController(this, std::move(tray), windowIcon(), this);
    connect(lifecycle_, &Lifecycle::LifecycleController::pendingRequested, this,
            [this] { selectView("pending"); });
    connect(lifecycle_, &Lifecycle::LifecycleController::settingsRequested, this,
            [this] { selectView("settings"); });
    connect(lifecycle_, &Lifecycle::LifecycleController::quitRequested, this,
            &MainWindow::requestGuiShutdown);
    updateLifecycle();
    lifecycle_->start(minimized);
}
void MainWindow::updateLifecycle() {
    if (!lifecycle_) return;
    Lifecycle::EngineSnapshot snapshot;
    snapshot.simulation = product_.simulation();
    snapshot.current = snapshot.simulation || product_.engine().current;
    // El perfil de cobertura validada aún no tiene evidencia consumible en esta GUI.
    snapshot.state = product_.engine().current
        ? Lifecycle::EngineState::Degraded : Lifecycle::EngineState::Unavailable;
    if (!snapshot.simulation && product_.ordinary()->current())
        snapshot.pendingCount = product_.ordinary()->observations().size();
    else if (!snapshot.simulation && !product_.administrativeSelected() && product_.recordsSelected() && product_.records()->recordsCurrent())
        snapshot.pendingCount = product_.records()->pending().size();
    lifecycle_->applyEngineSnapshot(snapshot);
}
void MainWindow::requestGuiShutdown() {
    if (closing_) return;
    if (lifecycle_ && !lifecycle_->quitPending()) { lifecycle_->requestQuit(); return; }
    closing_ = true;
    if(assistanceConnection_)assistanceConnection_->close();
    if(assistance_)assistance_->close();
    explanation_.close();
    model_.setEnabled(false);
    product_.stop();
    reviewer_.stop();
    setEnabled(false);
    // Terminar el Close interceptado antes de solicitar el cierre efectivo.
    QTimer::singleShot(0, this, &MainWindow::finishShutdownWhenIdle);
}
void MainWindow::finishShutdownWhenIdle() {
    if (!closing_) return;
    if (!guiDrained()) {
        QTimer::singleShot(50, this, &MainWindow::finishShutdownWhenIdle);
        return;
    }
    if (lifecycle_) lifecycle_->finishGuiShutdown();
    close();
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
    auto *help = button("ⓘ    Help && About", "help-about", "ghost");
    help->setAccessibleName("Help & About");
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
    if(assistance_)assistance_->cancel();
    if (!navigation_.contains(view))
        return;
    saveViewState();
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
    table_.clear(); rows_.clear();
    restoreViewState();
    buildPage();
}
void MainWindow::closeEvent(QCloseEvent *event) {
    if (!closing_) {
        if(assistanceConnection_)assistanceConnection_->close();
        closing_ = true; if(assistance_)assistance_->close(); explanation_.close(); model_.setEnabled(false); product_.stop(); reviewer_.stop();
    }
    if (!guiDrained()) {
        event->ignore(); setEnabled(false);
        QTimer::singleShot(50, this, [this] { close(); });
        return;
    }
    QMainWindow::closeEvent(event);
}
void MainWindow::buildPage() {
    if (refreshing_)
        return;
    saveViewState();
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
    updatePageState();
    if (!product_.simulation()) {
        const QMap<QString, QStringList> liveHeadings{
            {"processes", {"Processes", "Observed local processes · policy and network history are unknown."}},
            {"pending", {"Pending requests", "Review an application's request and choose how long your decision applies."}},
            {"activity", {"Activity", "Connection requests, decisions and available history."}},
            {"rules", {"Rules", "Service policy records and inactive local review candidates."}},
            {"import", {"Import from NetLimiter", "Structural analysis only · compatibility not validated."}},
            {"settings", {"Settings", "Engine status and assistance configuration with separate consents."}}};
        title_->setText(liveHeadings[view_][0]); subtitle_->setText(liveHeadings[view_][1]);
        renderLive(); updatePageState(); refreshing_ = false; refreshTable(true); restoreFocus(); positionOverlays(); return;
    }
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
    {
        auto *n = note("Simulated service unavailable. Permission changes, import, activation, "
                       "cleanup and restore are disabled. No firewall engine is connected.");
        n->setObjectName("degraded-banner");
        n->setVisible(!model_.available());
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
    updatePageState();
    refreshing_ = false;
    refreshTable(true);
    restoreFocus();
    renderNotice();
    positionOverlays();
}
void MainWindow::updatePageState() {
    for (auto it = navigation_.begin(); it != navigation_.end(); ++it)
        it.value()->setChecked(it.key() == view_);
    pendingCount_->setText(product_.simulation() ? QString::number(model_.state().pending.size())
        : product_.ordinary()->current() ? QString::number(product_.ordinary()->observations().size())
        : !product_.administrativeSelected() && product_.recordsSelected() && product_.records()->recordsCurrent()
            ? QString::number(product_.records()->pending().size()) : "—");
    pendingCount_->setVisible(!product_.simulation() || !model_.state().pending.isEmpty());
    sideStatus_->setText(model_.available()
                             ? (model_.service() == Service::UiClosed
                                    ? "UI closed · simulated scenario\nThis preview stays open"
                                    : "Synthetic model available\nNo protection is active")
                             : "Simulated service unavailable\nPolicy changes disabled");
    status_->setText(model_.available() ? "Synthetic data only\nNo network filtering"
                                        : "Simulated service unavailable\nPolicy changes disabled");
    auto *banner = root_->findChild<QLabel *>("simulation-banner");
    if (banner) banner->setText(product_.simulation() ? "Simulation · no network filtering"
        : product_.engine().current ? product_.engineSummary() : "Live processes · firewall engine not connected");
    footer_->setText(product_.simulation()
        ? "Synthetic fixtures · session memory only                 Sample clock: 2026-10-08 10:42:40 UTC−03"
        : "Live process catalog · files not inspected · network collector unavailable");
    if (product_.simulation()) {
        const bool available = model_.available();
        for (const char *name : {"review-stale","edit-selected","review-selected","detail-edit","load-sample","reset-import"})
            if (auto *control = pageControl<QPushButton>(page_,name)) control->setEnabled(available);
        if (auto *banner = pageControl<QFrame>(page_,"degraded-banner")) banner->setVisible(!available);
        if (auto *restore = pageControl<QPushButton>(page_,"restore-backup")) {
            restore->setVisible(model_.hasBackup()); restore->setEnabled(available && model_.hasBackup());
        }
        if (auto *start = pageControl<QFrame>(page_,"import-start")) start->setVisible(!model_.state().importLoaded);
        if (auto *preview = pageControl<QWidget>(page_,"simulation-import-preview")) preview->setVisible(model_.state().importLoaded);
        if (auto *apply = pageControl<QPushButton>(page_,"apply-import")) {
            apply->setText(model_.state().importApplied ? "Candidates saved" : "Save 7 inactive candidates");
            apply->setEnabled(available && model_.state().importLoaded && !model_.state().importApplied);
        }
        if (auto *result = pageControl<QLabel>(page_,"simulation-import-result")) result->setText(model_.state().importApplied
            ? "7 inactive sample candidates saved. Review them in Rules." : "Only ready mappings are saved as inactive candidates.");
        if (auto *count = pageControl<QLabel>(page_,"simulation-rule-count")) {
            int active = 0; for (const auto &r : model_.state().rules) active += r.active;
            count->setText(QString("%1 active demo rules · %2 inactive candidates").arg(active).arg(model_.state().rules.size() - active));
        }
        if (auto *pending = pageControl<QFrame>(page_,"pending-state")) {
            const auto labels = pending->findChildren<QLabel *>();
            if (labels.size() == 2) labels.last()->setText(QString("%1 applications need a decision. Closing a request keeps it pending in this session. Repeated sample attempts are grouped by identity.").arg(model_.state().pending.size()));
        }
    }
    if (!product_.simulation()) {
        sideStatus_->setText(product_.engineSummary() + "\nCoverage not validated");
        status_->setText("Read only · no administrator control\nNetwork collector unavailable");
        if (product_.recordsSelected() && product_.records()->recordsCurrent()) {
            status_->setText("Read only · decisions require administrator review\nCoverage not validated");
            footer_->setText("Read-only snapshots · attempts and applied decisions remain separate from traffic");
        }
        if (product_.ordinary()->current()) {
            status_->setText("Request review available\nCoverage not validated");
            footer_->setText("Pending requests · review each connection or save a rule for this application and account");
        }
        const auto *client = product_.ordinary();
        if (product_.administrativeSelected()) {
            status_->setText((client->current() || client->rulesCurrent()
                ? QString("Administrative review connected") : QString("Administrative review unavailable")) + "\nCoverage not validated");
            footer_->setText("Original target accounts · future application rules only · current traffic remains unknown");
        }
        const bool ordinaryIdle = client->idle() && client->state() != OrdinaryDecisionClient::State::Uncertain;
        const auto enable = [this](const char *name, bool enabled) {
            if (auto *b = pageControl<QPushButton>(page_,name)) b->setEnabled(enabled);
        };
        enable("refresh-ordinary",ordinaryIdle);
        enable("refresh-principal-rules",ordinaryIdle && !client->visible());
        for (const char *name : {"cleanup-live-rules","edit-file-rule","backup-file-rules"}) enable(name,client->rulesCurrent());
        enable("connect-history",product_.records()->idle() && !product_.records()->refreshing());
        enable("cancel-analysis",product_.importBusy());
        enable("save-candidates",!product_.importBusy() && !product_.reviewBusy() && product_.reviewWritable() && product_.draft().accepted);
        enable("prepare-source-files",product_.importedView(false).current && product_.importedView(false).qname.has_value());
        for (const char *name : {"ordinary-recover-page","rule-recover"})
            if (auto *b = pageControl<QPushButton>(page_,name)) {
                b->setVisible(client->state() == OrdinaryDecisionClient::State::Uncertain); b->setEnabled(client->idle());
            }
        if (auto *text = pageControl<QLabel>(page_,"ordinary-page-message")) text->setText(client->message());
        const auto text = [this](const char *name,const QString &value) {
            if (auto *w = pageControl<QLabel>(page_,name)) { if (w->text() != value) w->setText(value); w->setVisible(!value.isEmpty()); }
        };
        text("catalog-error",product_.catalog().error); text("history-error",product_.historyError());
        text("review-error",product_.reviewError()); text("engine-summary",product_.engineSummary());
        text("engine-revision",product_.revisionSummary()); text("engine-error",product_.engine().error);
        text("engine-connection",client->current() ? "Request review connected" : product_.engine().current
            ? "View connected · reading service status" : "No current service snapshot");
        if (auto *panel = pageControl<QFrame>(page_,"pending-context-note")) {
            const auto labels = panel->findChildren<QLabel *>();
            if (labels.size() == 2) labels.last()->setText(client->current()
                ? client->administrative()
                    ? "Review requests for each application and account. Choose a connection, app-instance or future-connection rule when the request supports it. Protection coverage has not been validated."
                    : "Review each request to choose Allow or Block and how long it applies. Always rules cover future connections for this application and account. Protection coverage has not been validated."
                : !product_.administrativeSelected() && product_.recordsSelected() && product_.records()->recordsCurrent()
                    ? "View request snapshot · read only. These requests use the separate administrator reviewer; coverage remains unvalidated."
                    : "No current request list. Refresh requests to check the connection; a running process is not an access request.");
        }
        text("import-count",QString::number(product_.draft().candidates.size()) + " inactive rows · compatibility: not validated");
        text("engine-rule-count","Engine rules: " + (product_.recordsSelected() && product_.records()->recordsCurrent()
            ? QString::number(product_.records()->rules().size()) + " read only" : "Unavailable") +
            " · local candidates: " + QString::number(product_.review().report.candidates.size()) + " inactive");
        if (pageControl<QLabel>(page_,"history-coverage")) {
            int sources = 0, live = 0, gaps = 0;
            for (const auto &c : product_.history().coverage) if (c.native) {
                ++sources; gaps += c.gaps.size(); live += c.status != Data::CoverageStatus::Unavailable;
            }
            text("history-coverage",sources ? QString("Coverage: %1 · %2 historical sources · %3 recorded gaps. Archived records do not report current permissions.")
                .arg(live ? "Partial available history" : "Monitoring unavailable; saved history retained").arg(sources).arg(gaps)
                : "Monitoring unavailable · a service heartbeat does not report traffic.");
        }
        if (auto *text = pageControl<QLabel>(page_,"principal-page-count")) text->setText(QString(client->administrative() ? "Administrative catalog rules: " : "Rules for your account: ") +
            (client->rulesCurrent() ? QString::number(client->rules().size()) : "Unavailable") + " · no recorded activity does not mean inactive");
        if (auto *text = pageControl<QLabel>(page_,"import-page-state")) {
            QStringList messages;
            if (product_.importBusy()) messages << "Analyzing the chosen file in the background · preview preserved";
            if (product_.reviewBusy()) messages << "Loading or saving inactive review in the background";
            if (!product_.importError().isEmpty()) messages << "Preview preserved · " + product_.importError();
            if (!product_.reviewError().isEmpty()) messages << product_.reviewError();
            text->setText(messages.join('\n')); text->setVisible(!messages.isEmpty());
        }
    }
}
void MainWindow::refresh() {
    updatePageState();
    refreshTable();
    if (detail_ && !selected_.isEmpty()) openDetail(selected_);
    renderNotice();
    closeStaleModal();
}
QTableView *MainWindow::makeTable(const QStringList &headers, const QVector<int> &widths,
                                  int rowHeight) {
    table_ = new QTableView;
    table_->setObjectName(view_ + "-table");
    table_->setAccessibleName(view_ + (product_.simulation() ? " sample data" : " read only data"));
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
            (view_ == "rules" && index.column() == 5) ||
            (view_ == "import" && !product_.simulation()))
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
    const auto &coverage = model_.state().history.coverage;
    const int gaps = coverage.isEmpty() ? 0 : coverage.front().gaps.size();
    pageLayout_->addWidget(label("Synthetic history · detail limit: 4,096 events · recorded gaps: " + QString::number(gaps) +
                                 ". A decision never creates authorization or traffic.",
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
    auto *summary = label(QString("%1 active demo rules · %2 inactive candidates")
                                 .arg(active)
                                 .arg(model_.state().rules.size() - active),
                             "muted");
    summary->setObjectName("simulation-rule-count"); toolbar->addWidget(summary);
    toolbar->addStretch();
    {
        auto *restore = button("Restore demo backup", "restore-backup", "ghost");
        restore->setEnabled(model_.available());
        restore->setVisible(model_.hasBackup());
        toolbar->addWidget(restore);
        connect(restore, &QPushButton::clicked, this, [this] {
            if (model_.restore(model_.epoch()))
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
    {
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
                [this] { model_.loadImport(model_.epoch()); });
        pageLayout_->addWidget(p);
        p->setVisible(!model_.state().importLoaded);
    }
    auto *preview = new QWidget; preview->setObjectName("simulation-import-preview");
    auto *previewLayout = new QVBoxLayout(preview); previewLayout->setContentsMargins(0,0,0,0);
    pageLayout_->addWidget(preview,1); preview->setVisible(model_.state().importLoaded);
    auto *counts = line(previewLayout);
    counts->addWidget(label("7 Ready", "strong"));
    counts->addWidget(label("3 Need review", "warning"));
    counts->addWidget(label("2 Unsupported", "warning"));
    counts->addStretch();
    auto *reset = button("Reset sample", "reset-import", "ghost");
    reset->setEnabled(model_.available());
    counts->addWidget(reset);
    connect(reset, &QPushButton::clicked, this,
            [this] { model_.resetImport(model_.epoch()); });
    makeTable({"Original target", "Original policy", "Mapping", "Preview result"}, {27, 17, 18, 38},
              38);
    pageLayout_->removeWidget(table_); previewLayout->addWidget(table_,1);
    auto *foot = line(previewLayout);
    auto *result = label(model_.state().importApplied
                              ? "7 inactive sample candidates saved. Review them in Rules."
                              : "Only ready mappings are saved as inactive candidates.",
                          "faint", true);
    result->setObjectName("simulation-import-result"); foot->addWidget(result,1);
    auto *apply =
        button(model_.state().importApplied ? "Candidates saved" : "Save 7 inactive candidates",
               "apply-import", "primary");
    apply->setEnabled(model_.available() && !model_.state().importApplied);
    foot->addWidget(apply);
    connect(apply, &QPushButton::clicked, this, [this] {
        if (model_.applyImport(model_.epoch()))
            message(
                "7 inactive candidates saved. Review each candidate in Rules before activation.");
    });
}
void MainWindow::refreshTable(bool newPage) {
    if (!rows_ || !table_)
        return;
    // El preview grande no se recorre por avisos del motor o del writer sin cambios de fuente.
    if (!product_.simulation() && view_ == "import") {
        const auto &source = product_.importedView(true);
        QByteArray key; QDataStream stamp(&key,QIODevice::WriteOnly);
        stamp << product_.draft().digest << qint64(product_.draft().candidates.size()) << product_.draft().accepted
              << source.digest << source.revision << source.job << source.current << source.busy << source.facts.error;
        if (!newPage && key == tableSourceKey_) return;
        tableSourceKey_ = key;
    } else tableSourceKey_.clear();
    if (!newPage) saveViewState();
    const auto saved = viewStates_.value(stateKey());
    const auto current = table_->currentIndex().isValid() ? table_->currentIndex().data(IdRole).toString() : saved.selectedId;
    QVector<Row> result;
    const auto &state = model_.state();
    if (!product_.simulation()) {
        if (view_ == "processes") for (const auto &p : product_.catalog().processes) {
            if (!(p.name + " " + p.imagePath).contains(query_, Qt::CaseInsensitive)) continue;
            const QString status = p.status == Data::FieldStatus::Known ? "Observed"
                : p.status == Data::FieldStatus::Gone ? "Gone" : p.status == Data::FieldStatus::AccessDenied ? "Access denied" : "Unknown";
            const QString name = p.name.isEmpty() ? "Unattributed PID " + QString::number(p.instance.pid) : p.name;
            const auto when = [](const QDateTime &at) { return at.isValid() ? at.toUTC().toString(Qt::ISODateWithMs) : QString("Unknown"); };
            result.push_back({product_.processId(p), {{name, "glyph:" + name.left(2).toUpper(), {}},
                {"Policy unknown", "inactive", {}}, {when(p.lastAttemptUtc), {}, {}},
                {when(p.lastAuthorizedUtc), {}, {}}, {when(p.lastTrafficUtc), {}, {}},
                {p.identityEvidence.isEmpty() ? status : "Origin paired · snapshot", {}, {}}}});
        }
        else if (view_ == "import" || view_ == "rules") {
            if (view_ == "rules" && product_.ordinary()->rulesCurrent())
                for (const auto &r : product_.ordinary()->rules()) {
                    const QString account = recordText(r.display.principal,"Account unknown") + " · " + targetAccountText(r);
                    if (!query_.isEmpty() && !(recordText(r.display.name,{}) + " " + recordText(r.display.path,{}) + " " + account)
                        .contains(query_,Qt::CaseInsensitive)) continue;
                    result.push_back({"principal-rule:" + QString::fromStdString(gb::wire::hex(r.rule)),
                        {{recordText(r.display.name,"Application unknown") + "\n" + account,"strong",{}},
                         {r.action == 2 ? "Allow rule" : "Block rule",{},{}},
                         {r.direction == 1 ? (r.action == 2 ? "Outbound unicast" : "Outbound")
                             : r.direction == 2 ? "Inbound" : r.action == 2 ? "Both · includes non-unicast" : "Both",{},{}},
                         {"Unknown",{},{}},{"App and account · coverage unvalidated",{},{}},{"Review removal", "action",{}}}});
                }
            if (view_ == "rules" && !product_.administrativeSelected() && product_.recordsSelected() && product_.records()->recordsCurrent())
                for (const auto &r : product_.records()->rules()) {
                    const auto name = recordText(r.name, "Selector " + QString::fromStdString(gb::wire::hex(r.selector)));
                    result.push_back({engineRowId("rule", product_.engine().serviceEpoch, r.rule),
                        {{name, "strong", {}}, {r.action == 2 ? "Allow · soft" : "Block", {}, {}},
                         {r.direction == 1 ? (r.mode == 1 ? "Outbound unicast · path" : "Outbound · path")
                                            : r.direction == 2 ? "Inbound · path" : "Both · permanent path", {}, {}}, {"Unknown", {}, {}},
                         {r.effective == 1 ? "Applied revision" : "Effect unknown", {}, {}}, {"Read only", {}, {}}}});
                }
            const auto &report = view_ == "import" ? product_.draft() : product_.review().report;
            for (const auto &c : report.candidates) {
                if (view_ == "rules" && product_.administrativeSelected()) continue;
                const auto *derived = product_.derivedCandidate(view_ == "import", c.id);
                const auto *qname = product_.derivedQNameCandidate(view_ == "import", c.id);
                const auto &derivedView = product_.importedView(view_ == "import");
                const QString status = qname ? (qname->complete ? "Known source subset" : "Incomplete · known fields retained") : derived ? reconstructionText(derived)
                    : derivedView.busy ? "Deriving facts" : "Derived facts unavailable";
                const QString source = c.sourceId.isEmpty() ? c.source.name : c.sourceId;
                const QString action = qname ? qnameAction(qname) : derived && derived->action ? Data::actionName(*derived->action) : "Unknown";
                if (view_ == "import") result.push_back({"candidate:" + report.digest + ":" + c.id,
                    {{source, "strong", {}}, {action, {}, {}}, {status, status, {}},
                     {qname ? "Inactive · QName source · omissions retained" : derived ? QStringList(derived->diagnostics.begin(), derived->diagnostics.end()).join(" · ")
                              : derivedView.busy ? "Source retained · deriving facts" : "Source retained · " + derivedView.facts.error, {}, {}}}});
                else result.push_back({"candidate:" + report.digest + ":" + c.id,
                    {{source, "strong", {}}, {"Inactive · Unverified", "inactive", {}}, {qname && qname->direction.known() ? Data::directionName(qname->direction.value) : derived ? Data::directionName(derived->direction) : "Unknown", {}, {}},
                     {"Unknown · no collector", {}, {}}, {status, status, {}}, {"Review", "action", {}}}});
            }
        }
        else if (view_ == "pending" && product_.ordinary()->current()) {
            for (const auto &p : product_.ordinary()->observations()) {
                const QString account = recordText(p.display.principal,"Account unknown");
                if (!query_.isEmpty() && !(recordText(p.display.name,{}) + " " + recordText(p.display.path,{}) + " " + account)
                    .contains(query_,Qt::CaseInsensitive)) continue;
                result.push_back({"ordinary:" + QString::fromStdString(gb::wire::hex(p.observed)),
                    {{recordText(p.display.name, "Unattributed application") + "\n" + account, "strong", {}},
                     {"Requested destination unknown", {}, {}},
                     {recordUtc(p.lastUtc, p.presence & 2), {}, qulonglong(p.lastUtc)},
                     {"Review request →", "action", {}}}});
            }
        }
        else if (view_ == "pending" && !product_.administrativeSelected() && product_.recordsSelected() && product_.records()->recordsCurrent())
            for (const auto &p : product_.records()->pending())
                result.push_back({engineRowId("pending", product_.engine().serviceEpoch, p.request),
                    {{recordText(p.name, "Unattributed request"), "strong", {}},
                     {p.origin == 3 ? "Local listen · remote endpoint unknown"
                                    : p.flow == 2 ? "Outbound attempt · destination unknown" : "Inbound attempt · destination unknown", {}, {}},
                     {recordUtc(p.lastUtc, p.presence & 8), {}, qulonglong(p.lastUtc)},
                     {"Review in administrator window →", "action", {}}}});
        else if (view_ == "activity" && std::any_of(product_.history().coverage.begin(), product_.history().coverage.end(),
                                                 [](const Data::Coverage &c) { return bool(c.native); })) {
            const auto &history = product_.history();
            for (const auto &e : history.events) {
                if (!e.native) continue;
                const auto &n = *e.native;
                const QString at = e.observedAtUtc.isValid()
                    ? QLocale().toString(e.observedAtUtc.toLocalTime(), QLocale::ShortFormat)
                    : "Event time unknown";
                const QString received = QLocale().toString(e.receivedAtUtc.toLocalTime(), QLocale::ShortFormat);
                const QString kind = e.kind == Data::ActivityKind::Authorization
                    ? (n.scope == 2
                        ? (e.action == Data::Action::Allow ? "Allow rule saved" : "Block rule saved")
                        : (e.action == Data::Action::Allow ? "Access allowed" : "Access blocked"))
                    : e.kind == Data::ActivityKind::Traffic ? "Traffic observed" : "Connection request";
                const QString reason = e.kind == Data::ActivityKind::Traffic
                    ? QString("%1 bytes · %2 network buffers observed\n%3")
                        .arg(e.bytes ? QString::number(*e.bytes) : "Unknown", QString::number(n.packetCount),
                            n.externalPartial ? "Related request unavailable · history incomplete" : "Delivery and physical packet count unproven")
                    : n.externalPartial ? "Related request unavailable · history incomplete"
                    : e.kind == Data::ActivityKind::Authorization
                        ? (n.routeMask == 7 ? "Decision recorded · traffic recorded separately" : "Decision recorded · traffic unknown")
                    : n.source == 2 ? "Request recorded · traffic unknown" : "Blocked request reported · limited history";
                const bool administrativeHistory = e.sourceId.startsWith("NativeAdministrativeEvents:");
                const QString image = (n.process ? n.process->image.section('\\',-1) + "\nRecorded application" : "Application unknown") +
                    (administrativeHistory ? "\nAdministrative review" : "\nMy account monitoring");
                result.push_back({"history:" + Data::nativeEventKey(e),
                    {{at + "\nReceived " + received, {}, qulonglong(e.sequence.toULongLong())},
                     {image, {}, {}},
                     {kind, n.externalPartial ? "warning" : "", {}},
                     {(e.kind == Data::ActivityKind::Traffic ?
                        (n.packetDirection == 1 ? "Outbound packet activity" : "Inbound packet activity") :
                        (n.direction == 1 ? "Outbound" : "Inbound")) + QString(" · ") +
                        (e.protocol.isEmpty() ? "protocol unknown" : e.protocol) + "\nEndpoint unknown", {}, {}},
                     {reason, {}, {}}}});
            }
            for (const auto &coverage : history.coverage) {
                if (!coverage.native) continue;
                int index = 0;
                for (const auto &gap : coverage.gaps) {
                    const QString loss = gap.lostKnown ? QString::number(gap.lost) + " history records omitted"
                                                      : "Omitted record count unknown";
                    result.push_back({"history-gap:" + coverage.sourceId + ':' + coverage.sourceEpoch + ':' + QString::number(index++),
                        {{"Gap received\n" + QLocale().toString(gap.atUtc.toLocalTime(), QLocale::ShortFormat), {}, qulonglong(gap.resync)},
                         {"Application unknown", {}, {}},
                         {"History incomplete", "warning", {}}, {"Unknown", {}, {}},
                         {gap.reason + "\n" + loss, {}, {}}}});
                }
            }
        }
        else if (view_ == "activity" && product_.recordsSelected() && product_.engine().current)
            for (const auto &e : product_.records()->events()) {
                const auto sequence = gb::wire::get(e, gb::wire::Tag::EventSeq);
                const auto request = gb::wire::idValue(e, gb::wire::Tag::RequestId);
                const bool gap = e.type == gb::wire::Type::ObservationGap;
                result.push_back({"event:" + QString::fromStdString(gb::wire::hex(product_.engine().serviceEpoch)) + ":" + QString::number(sequence),
                    {{recordUtc(gb::wire::get(e, gb::wire::Tag::Timestamp), gb::wire::get(e, gb::wire::Tag::Presence) & (1ull << 19)), {}, qulonglong(sequence)},
                     {gb::wire::zero(request) ? "Unattributed" : QString::fromStdString(gb::wire::hex(request)), {}, {}},
                     {gap ? "Observation gap" : "Blocked attempt observed", gap ? "warning" : "", {}},
                     {"Unknown", {}, {}}, {gap ? "Coverage incomplete" : "WFP source · no traffic evidence", {}, {}}}});
            }
        if (count_) count_->setText(QString("%1 of %2 observed processes").arg(result.size()).arg(product_.catalog().processes.size()));
    } else if (view_ == "processes") {
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
            result.push_back({e.id,
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
    else if (view_ == "import" && state.importLoaded)
        for (const auto &r : model_.sampleImport())
            result.push_back({r.id,
                              {{r.name, "strong", {}},
                               {r.bandwidth ? "Limit bandwidth" : policyText(r.policy),
                                r.bandwidth ? "" : policyText(r.policy),
                                {}},
                               {r.status, r.status, {}},
                               {r.note, {}, {}}}});
    rows_->replace(result);
    if (newPage && table_->isSortingEnabled()) table_->sortByColumn(saved.sortColumn, saved.order);
    bool restored = table_->currentIndex().isValid() && table_->currentIndex().data(IdRole).toString() == current;
    for (int i = 0; i < rows_->rowCount(); ++i)
        if (!restored && rows_->index(i, 0).data(IdRole).toString() == current) {
            table_->setCurrentIndex(rows_->index(i, qMin(saved.currentColumn, rows_->columnCount() - 1)));
            restored = true;
            break;
        }
    if (!restored) { table_->clearSelection(); table_->setCurrentIndex({}); selected_.clear();
        if (detail_) { dispose(detail_); detail_.clear(); } }
    table_->verticalScrollBar()->setValue(saved.scroll);
    const bool empty = result.isEmpty();
    table_->setProperty("empty-state", empty);
    table_->setAccessibleDescription(
        empty ? "No matching sample rows. Change the search or filter."
              : "Synthetic fixtures only. Enter opens the selected row where available.");
    if (emptyState_) {
        emptyState_->setText(!product_.simulation()
            ? view_ == "pending" ? product_.ordinary()->current() ? "No requests awaiting a decision" : "Requests unavailable · refresh to check the connection"
                : view_ == "activity" ? "Network activity collector unavailable"
                : view_ == "rules" ? "No local review candidates\nEngine rules unavailable in this version"
                : view_ == "import" ? "Choose a migration file for structural analysis"
                : "No matching observed processes"
            : view_ == "pending"
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
    if (!product_.simulation()) {
        if (view_ == "processes") renderLiveDetail(id);
        else if (view_ == "pending") openEngineRequest(id);
        else if (view_ == "rules" && id.startsWith("principal-rule:")) cleanupLiveRule();
        else if (view_ == "rules" || view_ == "import") reviewCandidate(id, view_ == "import");
        return;
    }
    if (view_ == "processes")
        openDetail(id);
    else if (view_ == "pending")
        openRequest(id);
    else if (view_ == "rules" && (index.column() == 5 || index == table_->currentIndex()))
        if (const auto *r = model_.rule(id))
            edit(id, !r->active);
}
void MainWindow::openDetail(const QString &id) {
    if (!product_.simulation()) { renderLiveDetail(id); return; }
    const auto *p = model_.process(id);
    if (!p || view_ != "processes")
        return;
    QByteArray key; QDataStream stamp(&key, QIODevice::WriteOnly);
    stamp << id << p->name << p->path << p->publisher << p->signature << int(p->policy)
          << p->scope << p->duration << p->attempt << p->authorized << p->traffic
          << p->destination << p->protocol << model_.available();
    if (detail_ && detail_->property("detail-key").toByteArray() == key) return;
    if (detail_ && detail_->property("detail-id").toString() == id) {
        const QMap<QString,QString> values{{"Publisher",p->publisher},{"Signature",p->signature + " · sample"},
            {"Policy",policyText(p->policy)},{"Application identity",p->scope},{"Duration",p->duration},
            {"Last attempt",timestamp(p->attempt)},{"Authorized",timestamp(p->authorized)},
            {"Observed traffic",timestamp(p->traffic)}};
        for (auto *text : detail_->findChildren<QLabel *>()) {
            const auto name = text->property("definition-name").toString();
            if (values.contains(name) && text->text() != values[name]) text->setText(values[name]);
            if (text->property("role").toString() == "heading" && text->text() != p->name) text->setText(p->name);
        }
        if (auto *edit = detail_->findChild<QPushButton *>("detail-edit")) edit->setEnabled(model_.available());
        detail_->setProperty("detail-key",key); return;
    }
    selected_ = id;
    if (detail_)
        dispose(detail_);
    detail_ = new QFrame(page_);
    detail_->setObjectName("detail");
    detail_->setProperty("detail-key", key);
    detail_->setProperty("detail-id",id);
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
    if (!product_.simulation()) return;
    if (explanation_.open(id)) {
        renderNotice();
        if (auto *b = notice_->findChild<QPushButton *>("keep-access-pending"))
            b->setFocus();
    }
}
void MainWindow::renderOrdinaryNotice() {
    if (product_.simulation()) return;
    auto *client = product_.ordinary();
    QByteArray key; QDataStream stamp(&key, QIODevice::WriteOnly);
    gb::wire::Bytes encoded;
    if (client->observed()) gb::wire::iv::pack(std::vector<gb::wire::iv::ObservedRecord>{*client->observed()}, encoded);
    stamp << QByteArray(reinterpret_cast<const char *>(encoded.data()), encoded.size());
    encoded.clear();
    if (client->draft()) gb::wire::iv::pack(std::vector<gb::wire::iv::FutureDraftRecord>{*client->draft()}, encoded);
    stamp << QByteArray(reinterpret_cast<const char *>(encoded.data()), encoded.size())
          << client->administrative()
          << QByteArray(reinterpret_cast<const char *>(client->selectedOriginalTarget().data()),client->selectedOriginalTarget().size())
          << client->selection() << int(client->state()) << client->message() << client->visible()
          << client->ready() << client->selectedDirection() << client->selectedScope()
          << product_.importedActivation().busy << product_.importedActivation().ready;
    if (notice_ && key == ordinaryNoticeKey_) {
        if (auto *check = notice_->findChild<QPushButton *>("ordinary-recover")) check->setEnabled(client->idle());
        return;
    }
    ordinaryNoticeKey_ = key;
    const QString focused = notice_ && notice_->isAncestorOf(QApplication::focusWidget())
        ? QApplication::focusWidget()->objectName() : QString{};
    if (notice_) { dispose(notice_); notice_.clear(); }
    if (product_.importedActivation().busy || product_.importedActivation().ready) return;
    if (!client->visible() || !client->observed()) return;
    const auto row = *client->observed();
    const auto draft = client->draft();
    const auto *submitted = client->submitted();
    const auto display = draft ? draft->display : submitted ? submitted->display : row.display;
    const auto package = draft ? draft->package : submitted
        ? gb::wire::get(submitted->command, gb::wire::Tag::PackageMode) : 0;
    const auto directionValue = submitted ? int(gb::wire::get(submitted->command, gb::wire::Tag::PolicyDirection))
        : client->selectedDirection();
    const auto selection = client->selection();
    const bool held = row.temporal == 2;
    const auto scopeValue = submitted ? int(gb::wire::get(submitted->command, gb::wire::Tag::ScopeKind)) : client->selectedScope();
    const auto futureScope = Data::applicationRuleScopeText(quint8(package),
        directionValue == 1 ? Data::Direction::Out : directionValue == 2 ? Data::Direction::In :
        directionValue == 3 ? Data::Direction::Both : Data::Direction::Unknown,
        submitted ? gb::wire::get(submitted->command, gb::wire::Tag::Decision) == 2 ? Data::Action::Allow : Data::Action::Block
                  : Data::Action::Ask, held);
    notice_ = new QFrame(root_); notice_->setObjectName("access-notice");
    notice_->setAccessibleName("Application access request");
    auto *l = new QVBoxLayout(notice_); l->setContentsMargins(15, 12, 15, 12); l->setSpacing(9);
    auto *head = line(l); head->addWidget(label("LGA   GateBouncer · access request", "faint"), 1);
    auto *close = button("×", "close-request", "ghost"); close->setFixedSize(25, 25);
    close->setAccessibleName(client->state() == OrdinaryDecisionClient::State::Uncertain
        ? "Close review; the decision result remains unknown"
        : submitted ? "Close review" : "Close review and keep the request pending"); head->addWidget(close);
    connect(close, &QPushButton::clicked, client, &OrdinaryDecisionClient::closeNotice);
    l->addWidget(label(recordText(display.name, "Unattributed application"), "heading", true));
    auto *status = label(client->message(), "warning", true); status->setObjectName("ordinary-state"); l->addWidget(status);
    if (submitted) l->addWidget(label(QString(client->state() == OrdinaryDecisionClient::State::Recorded ? "Recorded decision: " : "Submitted decision: ") +
        (gb::wire::get(submitted->command, gb::wire::Tag::Decision) == 2 ? "Allow" : "Block"), "faint", true));
    auto *content = new QWidget; auto *body = new QVBoxLayout(content);
    body->setContentsMargins(0, 0, 0, 0); body->setSpacing(9);
    if (client->state() == OrdinaryDecisionClient::State::Preparing) body->addWidget(new Spinner, 0, Qt::AlignLeft);
    definition(body, "Requested destination", "Unknown · not provided with this request");
    definition(body, "Original attempt", held && scopeValue == 2 && client->state() == OrdinaryDecisionClient::State::Recorded
        ? "Request cancelled · the original connection stays blocked"
        : held && client->state() == OrdinaryDecisionClient::State::Recorded
            ? "Decision recorded for this connection · current traffic has not been validated"
        : client->state() == OrdinaryDecisionClient::State::Uncertain
            ? "Decision result unknown · Check the same command; do not repeat this decision."
        : client->state() == OrdinaryDecisionClient::State::Sending
            ? "Decision sent · waiting for the recorded result"
        : held ? "Network request waiting · closing keeps the request blocked and pending" : "Blocked attempt recorded · no connection is waiting");
    QString observedApplication;
    if(const auto source=Assistance::Ui::currentObservation(client)){
        const auto& name=source->record.display.name;
        const std::string text(name.begin(),name.end());
        if(Assistance::General::validPublicFields({text,{},text}))observedApplication=QString::fromUtf8(text);
    }
    ordinaryExplanation_=new Assistance::Ui::ExplanationWidget(assistance_.get(),[this,selection]{
        const auto* current=product_.ordinary();
        QPointer<Assistance::Ui::GeneralSession> explanation=assistance_.get();
        if(!explanation||current->administrative()||!current->visible()||!current->current()||current->selection()!=selection)return std::optional<Assistance::General::FullBinding>{};
        return explanation->pendingBinding();
    },observedApplication,content);
    body->addWidget(ordinaryExplanation_);
    definition(body, "Application", recordText(display.name, "Unknown"));
    definition(body, "Target account", recordText(display.principal, "Unknown") +
        (client->administrative() ? " · " + accountText(client->selectedPrincipalSid()) : QString{}));
    if (client->administrative()) {
        definition(body,"Acting account","Your signed-in administrative account · separate from the target account");
        body->addWidget(label("Connection and app-instance decisions require a current request. Observed traffic is recorded separately; protection coverage has not been validated.","warning",true));
    }
    definition(body, "Package", scopeValue >= 3 ? "Non-AppContainer process" : package == 1 ? futureScope.package : recordText(display.package, "Unknown"));
    if (!display.path.empty()) {
        auto *path = new QPlainTextEdit(recordText(display.path, "Unknown")); path->setReadOnly(true);
        path->setObjectName("ordinary-path"); path->setWordWrapMode(QTextOption::WrapAnywhere);
        path->setMinimumHeight(52); path->setMaximumHeight(78); body->addWidget(path);
    }
    const QString scopeDescription = scopeValue == 3 ? "this exact network flow, once. " : scopeValue == 4
        ? "only this app instance, until it exits. " : scopeValue == 5 ? "only this app instance, for up to 15 minutes or until it exits. " :
        futureScope.scope;
    body->addWidget(label(QString(client->state() == OrdinaryDecisionClient::State::Recorded ? "Recorded scope: " : submitted ? "Submitted scope: " : "Will apply to: ") + scopeDescription +
        futureScope.coverage, "muted", true));
    l->addWidget(scrollArea(content), 1);
    auto *fields = new QHBoxLayout; fields->setSpacing(9);
    auto *sl = new QVBoxLayout; sl->setSpacing(5); sl->addWidget(label("Apply to", "faint"));
    auto *scope = combo({"Application + account", "This app instance", "Once"}, "decision-scope");
    if (!held) for (int i : {1, 2}) scope->setItemData(i, 0, Qt::UserRole - 1);
    scope->setCurrentIndex(scopeValue == 2 ? 0 : scopeValue == 3 ? 2 : 1);
    scope->setEnabled(client->ready()); sl->addWidget(scope); fields->addLayout(sl, 1);
    auto *dl = new QVBoxLayout; dl->setSpacing(5); dl->addWidget(label("Keep this decision", "faint"));
    auto *duration = combo({scopeValue == 3 ? "This connection" : scopeValue == 2 ? "Always" : "Until this instance exits",
        "15 minutes"}, "decision-duration");
    duration->setCurrentIndex(scopeValue == 5 ? 1 : 0);
    duration->setEnabled(client->ready() && scopeValue >= 4); dl->addWidget(duration); fields->addLayout(dl, 1); l->addLayout(fields);
    connect(scope, &QComboBox::currentIndexChanged, this, [client, selection](int index) {
        if (selection == client->selection()) client->scope(index == 0 ? 2 : index == 1 ? 4 : 3);
    });
    connect(duration, &QComboBox::currentIndexChanged, this, [client, selection](int index) {
        if (selection == client->selection()) client->scope(index == 1 ? 5 : 4);
    });
    if (held) l->addWidget(label(scopeValue == 2
        ? client->state() == OrdinaryDecisionClient::State::Recorded
            ? "The Always rule was saved. This request was cancelled and its original connection stays blocked."
            : submitted ? "The submitted Always rule would cover only future connections. Its result is shown above."
                : futureScope.originalAttempt
        : "This decision applies only to the selected connection or app instance.", "faint", true));
    auto *direction = combo({"Outbound", "Inbound", "Both"}, "ordinary-direction");
    direction->setCurrentIndex(directionValue - 1);
    direction->setEnabled(client->ready() && scopeValue == 2); l->addWidget(direction);
    connect(direction, &QComboBox::currentIndexChanged, this, [client, selection, direction](int index) {
        if (selection != client->selection() || !client->direction(index + 1)) {
            const QSignalBlocker guard(direction); direction->setCurrentIndex(client->selectedDirection() - 1);
        }
    });
    const QString network = scopeValue >= 3 ?
        QString(directionValue == 1 ? "Network flows started by this app, with packets in both directions. "
            : directionValue == 2 ? "Network flows accepted by this app, with packets in both directions. "
            : "Network flow direction unavailable; decisions are not ready. ") +
        "UDP, QUIC, ICMP and startup coverage have not been validated."
        : futureScope.connections;
    l->addWidget(label(QString(client->state() == OrdinaryDecisionClient::State::Recorded ? "Recorded connections: " : submitted ? "Submitted connections: " : "Will cover: ") + network, "muted", true));
    auto *consent = new QCheckBox("I accept the effective scope shown above.");
    consent->setObjectName("ordinary-consent"); consent->setEnabled(client->ready());
    consent->setStyleSheet("QCheckBox { font-size: 11px; }"); l->addWidget(consent);
    auto *actions = line(l); auto *keep = button(submitted || client->state() == OrdinaryDecisionClient::State::Uncertain ? "Close" : "Keep pending", "keep-access-pending", "ghost"); actions->addWidget(keep);
    connect(keep, &QPushButton::clicked, client, &OrdinaryDecisionClient::closeNotice); actions->addStretch();
    auto *block = button("Block", "decide-block", "danger"); auto *allow = button("Allow", "decide-allow", "primary");
    block->setEnabled(false); allow->setEnabled(false); actions->addWidget(block); actions->addWidget(allow);
    connect(consent, &QCheckBox::toggled, this, [client, selection, block, allow](bool checked) {
        const bool enabled = checked && selection == client->selection() && client->ready();
        block->setEnabled(enabled); allow->setEnabled(enabled);
    });
    for (auto *b : {block, allow}) connect(b, &QPushButton::clicked, this, [client, selection, consent, status, allowAction = b == allow] {
        if (!client->decide(allowAction, consent->isChecked(), selection) && selection == client->selection() && client->ready())
            status->setText("Review is being checked. Choose again when it finishes.");
    });
    if (client->state() == OrdinaryDecisionClient::State::Uncertain) {
        auto *check = button("Check same command", "ordinary-recover"); check->setEnabled(client->idle());
        l->addWidget(check); connect(check, &QPushButton::clicked, client, &OrdinaryDecisionClient::recover);
    }
    positionOverlays(); notice_->show(); notice_->raise();
    if (!focused.isEmpty()) if (auto *control = notice_->findChild<QWidget *>(focused)) control->setFocus();
    if (modalOverlay_) modalOverlay_->raise();
}
void MainWindow::renderNotice() {
    if (!product_.simulation()) { renderOrdinaryNotice(); return; }
    const auto id = explanation_.visibleId();
    const auto *p = model_.process(id);
    QByteArray key; QDataStream stamp(&key,QIODevice::WriteOnly);
    const auto reviewKey = model_.review(id);
    stamp << id << model_.epoch() << model_.available() << model_.isPending(id) << explanation_.generation()
          << int(explanation_.status()) << explanation_.text() << explanation_.problem() << explanation_.disclosure()
          << explanation_.configured() << explanation_.consent() << reviewKey.scope << reviewKey.duration << reviewKey.expanded;
    if (notice_ && notice_->property("simulation-notice-key").toByteArray() == key) return;
    const QString focused = notice_ && notice_->isAncestorOf(QApplication::focusWidget())
                                ? QApplication::focusWidget()->objectName()
                                : QString{};
    const auto *oldScroll = notice_ ? notice_->findChild<QScrollArea *>("access-scroll") : nullptr;
    const int scrollPosition = oldScroll ? oldScroll->verticalScrollBar()->value() : 0;
    if (notice_) {
        dispose(notice_);
        notice_.clear();
    }
    if (!product_.simulation() || !p || !model_.isPending(id))
        return;
    const auto review = model_.review(id);
    const auto epoch = model_.epoch();
    notice_ = new QFrame(root_);
    notice_->setObjectName("access-notice");
    notice_->setAccessibleName("Access request · simulation");
    notice_->setProperty("simulation-notice-key",key);
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
    l->addWidget(label(explanation_.disclosure(), "faint", true));
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
        text = explanation_.text();
        action = "Check again";    } else if (state == ExplanationState::Unclear) {
        text = "There is not enough information to explain this app. A name and publisher do not "
               "identify what the file actually does.";
        action = "Check again";
    } else if (state == ExplanationState::Error) {
        text = explanation_.problem();
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
    body->addWidget(expl);
    auto *accessScroll = qobject_cast<QScrollArea *>(scrollArea(content));
    accessScroll->setObjectName("access-scroll");
    l->addWidget(accessScroll, 1);
    auto *disclaimer = label(explanation_.disclaimer(), "faint", true);
    disclaimer->setObjectName("explanation-disclaimer");
    l->addWidget(disclaimer);
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
    modeSelector(l);
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
    auto *consent = new QCheckBox("I consent to the local sample demo · no data sent");
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
QString MainWindow::stateKey() const { return (product_.simulation() ? "simulation:" : "live:") + view_; }
void MainWindow::saveViewState() {
    if (restoringState_) return;
    auto &state = viewStates_[stateKey()];
    state.query = query_; state.activityQuery = activityQuery_; state.policy = policyFilter_;
    state.running = runningFilter_; state.event = eventFilter_;
    if (table_) {
        const auto current = table_->currentIndex();
        state.selectedId = current.data(IdRole).toString(); state.currentColumn = qMax(0, current.column());
        state.scroll = table_->verticalScrollBar()->value();
        state.sortColumn = table_->horizontalHeader()->sortIndicatorSection();
        state.order = table_->horizontalHeader()->sortIndicatorOrder();
    }
    if (QApplication::focusWidget() && isAncestorOf(QApplication::focusWidget()))
        state.focusName = QApplication::focusWidget()->objectName();
}
void MainWindow::restoreViewState() {
    const auto state = viewStates_.value(stateKey());
    query_ = state.query; activityQuery_ = state.activityQuery; policyFilter_ = state.policy;
    runningFilter_ = state.running; eventFilter_ = state.event;
}
void MainWindow::restoreFocus() {
    const auto key = stateKey(); const auto name = viewStates_.value(key).focusName;
    if (name.isEmpty()) return;
    QTimer::singleShot(0, this, [this, key, name] {
        if (key != stateKey()) return;
        if (auto *control = page_->findChild<QWidget *>(name))
            if (control->isEnabled() && !control->isHidden()) control->setFocus(Qt::OtherFocusReason);
    });
}
void MainWindow::setMode(UiMode mode) {
    if (mode == product_.mode()) return;
    saveViewState(); restoringState_ = true;
    const auto state = viewStates_.value((mode == UiMode::Simulation ? "simulation:" : "live:") + view_);
    query_ = state.query; activityQuery_ = state.activityQuery; policyFilter_ = state.policy;
    runningFilter_ = state.running; eventFilter_ = state.event;
    table_.clear(); rows_.clear(); selected_.clear(); explanation_.close(); closeModal();
    product_.setMode(mode); model_.setEnabled(mode == UiMode::Simulation);
    restoringState_ = false; buildPage();
}
void MainWindow::modeSelector(QVBoxLayout *layout) {
    auto *panel = frame("panel"); auto *l = new QVBoxLayout(panel);
    l->setContentsMargins(16, 16, 16, 16); l->setSpacing(8);
    l->addWidget(label("Data source", "heading"));
    l->addWidget(label("Live processes are read only. Simulation uses separate synthetic data and never filters network traffic.", "muted", true));
    auto *mode = combo({"Live processes · read only", "Simulation · offline samples"}, "data-source-mode");
    mode->setCurrentIndex(product_.simulation() ? 1 : 0); l->addWidget(mode);
    connect(mode, &QComboBox::currentIndexChanged, this, [this](int i) { setMode(i ? UiMode::Simulation : UiMode::LiveReadOnly); });
    layout->addWidget(panel);
}
void MainWindow::reviewSourceSelector() {
    auto *bar = line(pageLayout_);
    bar->addWidget(label("Review source","muted"));
    auto *source = combo({"My account", "Administrative accounts"},"principal-review-source");
    source->setMinimumWidth(source->fontMetrics().horizontalAdvance("Administrative accounts") + 52);
    source->setCurrentIndex(product_.administrativeSelected() ? 1 : 0); bar->addWidget(source); bar->addStretch();
    connect(source,&QComboBox::currentIndexChanged,this,[this,source](int index) {
        if (!product_.selectAdministrative(index == 1)) {
            const QSignalBlocker guard(source); source->setCurrentIndex(product_.administrativeSelected() ? 1 : 0);
            message("Finish the current review or recover the same command before changing accounts."); return;
        }
        // Cambiar explícitamente de origen retira sus callbacks y selecciones.
        // Las notificaciones del mismo origen conservan la página incremental.
        saveViewState(); closeModal(); selected_.clear(); buildPage();
    });
    auto *search = new QLineEdit(query_); search->setObjectName("principal-review-search");
    search->setPlaceholderText("Search application, account or path"); search->setClearButtonEnabled(true);
    pageLayout_->addWidget(search);
    connect(search,&QLineEdit::textChanged,this,[this](const QString &text) { query_ = text; refreshTable(); });
    pageLayout_->addWidget(label(product_.administrativeSelected()
        ? "Review other accounts using your current administrative sign-in. Your acting account is separate from each target account. Monitoring starts with this review session; missing application identity stays Unknown."
        : "Review requests and application rules for your account. Administrative review uses a separate signed-in session.","faint",true));
}
void MainWindow::renderLive() {
    if (view_ == "pending" || view_ == "rules") reviewSourceSelector();
    if (product_.administrativeSelected() && (view_ == "processes" || view_ == "activity"))
        pageLayout_->addWidget(note("Administrative history is recorded in a separate review session. Application identity is Unknown when no identity records are available; these records do not change the current process list."));
    const auto named = [](QLabel *text, const char *name) { text->setObjectName(name); return text; };
    if (view_ != "settings") pageLayout_->addWidget(note("Process and activity records are read only. Review pending access requests to choose Allow or Block. Protection coverage has not been validated.", true));
    if (view_ == "processes") {
        auto *bar = line(pageLayout_); auto *search = new QLineEdit(query_);
        search->setObjectName("process-search"); search->setPlaceholderText("Search observed processes and paths…");
        bar->addWidget(search, 1); auto *refresh = button("Refresh processes", "refresh-processes"); bar->addWidget(refresh);
        connect(refresh, &QPushButton::clicked, &product_, &ProductController::refreshProcesses);
        connect(search, &QLineEdit::textChanged, this, [this](const QString &q) { query_ = q; refreshTable(); });
        makeTable({"Process", "Policy", "Last request", "Last allowed request", "Last traffic", "State"}, {27, 13, 16, 18, 14, 12});
        pageLayout_->addWidget(label("Dates require a live original source and a retained local process instance. Traffic records bytes and network buffers observed by the OS; it does not confirm delivery. Unknown does not mean inactive.", "faint", true));
        count_ = label({}, "faint"); pageLayout_->addWidget(count_);
        pageLayout_->addWidget(named(label(product_.catalog().error, "warning", true),"catalog-error"));
    } else if (view_ == "pending") {
        auto *bar = line(pageLayout_);
        auto *refresh = button("Refresh requests", "refresh-ordinary"); bar->addWidget(refresh);
        refresh->setEnabled(product_.ordinary()->idle() && product_.ordinary()->state() != OrdinaryDecisionClient::State::Uncertain);
        connect(refresh, &QPushButton::clicked, product_.ordinary(), &OrdinaryDecisionClient::refresh);
        {
            auto *recover = button("Check same command", "ordinary-recover-page");
            recover->setEnabled(product_.ordinary()->idle()); recover->setVisible(product_.ordinary()->state() == OrdinaryDecisionClient::State::Uncertain); bar->addWidget(recover);
            connect(recover, &QPushButton::clicked, product_.ordinary(), &OrdinaryDecisionClient::recover);
        }
        bar->addStretch();
        pageLayout_->addWidget(named(label(product_.ordinary()->message(), "muted", true),"ordinary-page-message"));
        auto *contextNote = note(product_.ordinary()->current()
            ? product_.administrativeSelected()
                ? "Review requests for each application and account. Choose a connection, app-instance or future-connection rule when the request supports it. Protection coverage has not been validated."
                : "Review each request to choose Allow or Block and how long it applies. Always rules cover future connections for this application and account. Protection coverage has not been validated."
            : !product_.administrativeSelected() && product_.recordsSelected() && product_.records()->recordsCurrent()
                ? "View request snapshot · read only. These requests use the separate administrator reviewer; coverage remains unvalidated."
                : "No current request list. Refresh requests to check the connection; a running process is not an access request.");
        contextNote->setObjectName("pending-context-note"); pageLayout_->addWidget(contextNote);
        makeTable({"Application", "Destination", "Last request", "Decision"}, {32, 31, 14, 23}, 57);
    } else if (view_ == "activity") {
        auto *bar = line(pageLayout_);
        auto *connectHistory = button("Connect history", "connect-history");
        connectHistory->setEnabled(product_.records()->idle() && !product_.records()->refreshing());
        bar->addWidget(connectHistory, 0, Qt::AlignLeft); bar->addStretch();
        connect(connectHistory, &QPushButton::clicked, &product_, &ProductController::selectDecisionRecords);
        makeTable({"Time", "Process", "Event", "Destination", "Reason"}, {19, 22, 19, 20, 20}, 42);
        const auto &history = product_.history();
        int liveSources = 0, nativeSources = 0, gaps = 0;
        for (const auto &coverage : history.coverage) if (coverage.native) {
            ++nativeSources; gaps += coverage.gaps.size();
            if (coverage.status != Data::CoverageStatus::Unavailable) ++liveSources;
        }
        pageLayout_->addWidget(named(label(nativeSources
            ? QString("Coverage: %1 · %2 historical sources · %3 recorded gaps. Archived records do not report current permissions.")
                .arg(liveSources ? "Partial available history" : "Monitoring unavailable; saved history retained").arg(nativeSources).arg(gaps)
            : "Monitoring unavailable · a service heartbeat does not report traffic.", "faint", true),"history-coverage"));
        pageLayout_->addWidget(label("History starts when monitoring connects and retains 4,096 detail events. Connection requests, decisions and traffic are recorded separately. Decision time can be unknown; traffic and application identity remain unknown until their original sources are available. No recorded events does not mean an application was inactive.", "faint", true));
        pageLayout_->addWidget(named(label(product_.historyError(),"warning",true),"history-error"));
    } else if (view_ == "rules") {
        auto *bar = line(pageLayout_);
        auto *refresh = button(product_.administrativeSelected() ? "Refresh administrative rules" : "Refresh my rules","refresh-principal-rules");
        refresh->setEnabled(product_.ordinary()->idle() && !product_.ordinary()->visible() &&
            product_.ordinary()->state() != OrdinaryDecisionClient::State::Uncertain);
        bar->addWidget(refresh);
        connect(refresh,&QPushButton::clicked,product_.ordinary(),&OrdinaryDecisionClient::refreshRules);
        auto *remove = button("Review rule removal","cleanup-live-rules","ghost");
        remove->setEnabled(product_.ordinary()->rulesCurrent()); bar->addWidget(remove);
        connect(remove,&QPushButton::clicked,this,&MainWindow::cleanup);
        auto *files = line(pageLayout_);
        auto *create = button("New app rule…","new-file-rule","ghost"); files->addWidget(create);
        connect(create,&QPushButton::clicked,this,[this] { prepareFileRules(); });
        auto *edit = button("Edit selected…","edit-file-rule","ghost"); files->addWidget(edit);
        edit->setEnabled(product_.ordinary()->rulesCurrent()); connect(edit,&QPushButton::clicked,this,&MainWindow::editSelectedFileRule);
        auto *backup = button("Back up selected…","backup-file-rules","ghost"); files->addWidget(backup);
        backup->setEnabled(product_.ordinary()->rulesCurrent()); connect(backup,&QPushButton::clicked,this,&MainWindow::backupSelectedFileRules);
        auto *restore = button("Open inactive backup…","open-rule-backup","ghost"); files->addWidget(restore); files->addStretch();
        connect(restore,&QPushButton::clicked,this,&MainWindow::openRuleBackup);
        {
            auto *recover = button("Check same command","rule-recover","ghost");
            recover->setEnabled(product_.ordinary()->idle()); recover->setVisible(product_.ordinary()->state() == OrdinaryDecisionClient::State::Uncertain); bar->addWidget(recover);
            connect(recover,&QPushButton::clicked,product_.ordinary(),&OrdinaryDecisionClient::recover);
        }
        bar->addStretch();
        pageLayout_->addWidget(named(label(product_.ordinary()->message(),"muted",true),"ordinary-page-message"));
        pageLayout_->addWidget(named(label(QString(product_.administrativeSelected() ? "Administrative catalog rules: " : "Rules for your account: ") + (product_.ordinary()->rulesCurrent()
            ? QString::number(product_.ordinary()->rules().size()) : "Unavailable") +
            " · no recorded activity does not mean inactive", "faint",true),"principal-page-count"));
        pageLayout_->addWidget(named(label("Engine rules: " + (product_.recordsSelected() && product_.records()->recordsCurrent()
            ? QString::number(product_.records()->rules().size()) + " read only" : "Unavailable") +
            " · local candidates: " + QString::number(product_.review().report.candidates.size()) + " inactive", "muted", true),"engine-rule-count"));
        pageLayout_->addWidget(named(label(product_.reviewError(),"warning",true),"review-error"));
        makeTable({"Source target", "State", "Direction", "Last request", "Mapping", "Candidate"}, {24, 15, 20, 20, 12, 9});
        table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
        auto *review = button("Review selected candidate", "review-candidate"); pageLayout_->addWidget(review, 0, Qt::AlignRight);
        connect(review, &QPushButton::clicked, this, [this] { if (table_) reviewCandidate(table_->currentIndex().data(IdRole).toString()); });
    } else if (view_ == "import") {
        pageLayout_->addWidget(note("Structural analysis only · compatibility not validated. All rows are kept for inactive review; no rules are applied.", true));
        pageLayout_->addWidget(label("Inactive · Unverified · External unaccredited. Source fields may be known while subject scope, constraints and overlap remain unknown. No synthetic profile is selected automatically.", "muted", true));
        auto *profiles = line(pageLayout_); profiles->addWidget(label("Source profile", "muted"));
        auto *format = combo({"Structural XML · unknown semantics", "NetLimiter QName profile · source subset"}, "migration-format");
        format->setSizeAdjustPolicy(QComboBox::AdjustToContents); format->setCurrentIndex(product_.importFormat() == ImportFormat::QNameProfile ? 1 : 0); profiles->addWidget(format); profiles->addStretch();
        connect(format, &QComboBox::currentIndexChanged, this, [this](int index) { product_.setImportFormat(index == 1 ? ImportFormat::QNameProfile : ImportFormat::Structural); });
        auto *bar = line(pageLayout_); auto *choose = button("Choose migration XML…", "choose-migration"); bar->addWidget(choose);
        auto *reset = button("Clear preview", "clear-preview", "ghost"); bar->addWidget(reset); bar->addStretch();
        auto *cancel = button("Cancel analysis", "cancel-analysis", "ghost"); cancel->setEnabled(product_.importBusy()); bar->addWidget(cancel);
        connect(cancel, &QPushButton::clicked, this, [this] { product_.cancelImport(); refresh(); });
        connect(reset, &QPushButton::clicked, &product_, &ProductController::clearDraft);
        connect(choose, &QPushButton::clicked, this, [this] {
            auto *dialog = new QFileDialog(this, "Choose migration XML", QString{}, "XML files (*.xml);;All files (*)");
            dialog->setObjectName("migration-file-dialog"); dialog->setOption(QFileDialog::DontUseNativeDialog);
            dialog->setAttribute(Qt::WA_DeleteOnClose); dialog->setFileMode(QFileDialog::ExistingFile);
            connect(dialog, &QFileDialog::fileSelected, &product_, &ProductController::analyzeChosenFile); dialog->open();
        });
        pageLayout_->addWidget(named(label({},"warning",true),"import-page-state"));
        makeTable({"Source target", "Original policy", "Mapping", "Review reason"}, {27, 17, 18, 38}, 38);
        table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
        auto *selectedFiles = button("Review selected saved rules…","prepare-source-files","ghost");
        selectedFiles->setEnabled(product_.importedView(false).current && product_.importedView(false).qname.has_value());
        pageLayout_->addWidget(selectedFiles,0,Qt::AlignLeft);
        connect(selectedFiles,&QPushButton::clicked,this,&MainWindow::prepareSelectedSourceFiles);
        auto *foot = line(pageLayout_);
        foot->addWidget(named(label(QString::number(product_.draft().candidates.size()) + " inactive rows · compatibility: not validated", "faint"),"import-count"), 1);
        auto *save = button("Save all inactive candidates", "save-candidates", "primary");
        save->setEnabled(!product_.importBusy() && !product_.reviewBusy() && product_.reviewWritable() && product_.draft().accepted); foot->addWidget(save);
        connect(save, &QPushButton::clicked, this, [this] { if (product_.saveCandidates()) message("Saving inactive candidates in the background…"); });
    } else {
        auto *content = new QWidget; auto *l = new QVBoxLayout(content); l->setContentsMargins(0, 0, 0, 15); l->setSpacing(12); content->setMaximumWidth(830);
        modeSelector(l);
        auto *panel = frame("panel"); auto *p = new QVBoxLayout(panel); p->setContentsMargins(16, 16, 16, 16); p->setSpacing(8);
        p->addWidget(label("Network engine", "heading"));
        p->addWidget(named(label(product_.ordinary()->current() ? "Request review connected"
            : product_.engine().current ? "View connected · reading service status" : "No current service snapshot", "warning", true),"engine-connection"));
        p->addWidget(label("Network protection has not been validated. Access requests can be reviewed here without administrator confirmation. Read-only View requests require the separate administrator reviewer.", "faint", true));
        auto *refresh = button("Refresh connection", "refresh-engine"); p->addWidget(refresh, 0, Qt::AlignLeft);
        connect(refresh, &QPushButton::clicked, &product_, &ProductController::refreshEngine);
        auto *connectRecords = button("Connect requests", "connect-view-ii"); p->addWidget(connectRecords, 0, Qt::AlignLeft);
        connect(connectRecords, &QPushButton::clicked, &product_, &ProductController::selectDecisionRecords);
        auto *advancedToggle = button("Advanced", "engine-advanced", "ghost");
        advancedToggle->setCheckable(true);p->addWidget(advancedToggle, 0, Qt::AlignLeft);
        auto *advanced = new QWidget(panel);auto *advancedLayout = new QVBoxLayout(advanced);
        advancedLayout->setContentsMargins(0, 0, 0, 0);advanced->hide();p->addWidget(advanced);
        connect(advancedToggle, &QPushButton::toggled, advanced, &QWidget::setVisible);
        advancedLayout->addWidget(named(label(product_.engineSummary(), "muted", true),"engine-summary"));
        advancedLayout->addWidget(named(label(product_.revisionSummary(), "muted", true),"engine-revision"));
        advancedLayout->addWidget(named(label(product_.engine().error, "muted", true),"engine-error"));
        auto *statusOnly = button("Use status-only connection", "select-view-i", "ghost"); advancedLayout->addWidget(statusOnly, 0, Qt::AlignLeft);
        connect(statusOnly, &QPushButton::clicked, &product_, &ProductController::selectStatusOnly);
        advancedLayout->addWidget(label(product_.recordsSelected() ? "Selected source: service records · connection failure makes records unavailable" : "Selected source: engine status only", "faint", true));
        advancedLayout->addWidget(label("Coverage has not been validated. Permanent path rules span every matching instance and account. Outbound Allow is limited to unicast destinations; Both also opens inbound and removes that limit only after explicit review. Once, duration and instance scopes are unavailable.", "faint", true)); l->addWidget(panel);
        auto *reviewPanel = frame("panel"); auto *rp = new QVBoxLayout(reviewPanel); rp->setContentsMargins(16, 16, 16, 16); rp->setSpacing(8);
        rp->addWidget(label("Administrator reviewer", "heading"));
        rp->addWidget(label("Enable the reviewer to decide each request in a separate administrator window.", "muted", true));
        auto *reviewStatus = label(reviewer_.status(), "warning", true); reviewStatus->setObjectName("reviewer-status"); rp->addWidget(reviewStatus);
        auto *enableReviewer = button("Enable administrator reviewer…", "enable-reviewer"); rp->addWidget(enableReviewer, 0, Qt::AlignLeft);
        connect(enableReviewer, &QPushButton::clicked, &reviewer_, &ReviewGateway::launch);
        rp->addWidget(label("Unavailable in this portable build. A protected installation is required.", "faint", true)); l->addWidget(reviewPanel);
        auto* assistancePanel=new Assistance::Ui::SettingsWidget(assistance_.get(),content);
        connect(assistancePanel,&Assistance::Ui::SettingsWidget::connectRequested,this,&MainWindow::assistanceConnectRequested);
        l->addWidget(assistancePanel);
        auto *lifecyclePanel = frame("panel");
        auto *lp = new QVBoxLayout(lifecyclePanel);
        lp->setContentsMargins(16, 16, 16, 16); lp->setSpacing(8);
        lp->addWidget(label("Window and startup", "heading"));
        lp->addWidget(label(lifecycle_ && lifecycle_->recoverableTray()
            ? "Close hides this window. Use Quit in the tray menu to drain GUI clients and exit."
            : "A recoverable tray is unavailable. Close drains GUI clients and exits.", "muted", true));
        lp->addWidget(label("Closing or quitting the GUI never decides a pending request or stops the engine service.", "faint", true));
        lp->addWidget(label(startupResult_.detail.isEmpty() && startupResult_.state == Lifecycle::StartupState::Absent
            ? "GUI startup registration absent" : startupResult_.detail, "muted", true));
        auto *startupActions = line(lp);
        auto *inspectStartup = button("Inspect startup registration", "inspect-startup");
        auto *enableStartup = button("Register GUI at login", "enable-startup");
        auto *disableStartup = button("Remove GUI registration", "disable-startup", "ghost");
        for (auto *b : {inspectStartup, enableStartup, disableStartup}) {
            b->setEnabled(bool(startup_)); startupActions->addWidget(b);
        }
        connect(inspectStartup, &QPushButton::clicked, this, [this] {
            if (startup_) { startupResult_ = startup_->inspect(); buildPage(); }
        });
        connect(enableStartup, &QPushButton::clicked, this, [this] {
            if (startup_) { startupResult_ = startup_->setEnabled(true); buildPage(); }
        });
        connect(disableStartup, &QPushButton::clicked, this, [this] {
            if (startup_) { startupResult_ = startup_->setEnabled(false); buildPage(); }
        });
        lp->addWidget(label("This registers the ordinary GUI for this account. Registration does not guarantee launch at login and does not start an elevated reviewer or install protection.", "faint", true));
        l->addWidget(lifecyclePanel);
        if (!product_.reviewError().isEmpty()) l->addWidget(note(product_.reviewError()));
        l->addStretch(); pageLayout_->addWidget(scrollArea(content), 1);
    }
}
void MainWindow::openEngineRequest(const QString &rowId) {
    if (!product_.simulation() && rowId.startsWith("ordinary:")) {
        gb::wire::Id id{};
        if (gb::wire::parseId(rowId.mid(9).toStdString(), id)) product_.ordinary()->select(id);
        return;
    }
    if (product_.simulation() || !product_.recordsSelected() || !product_.records()->recordsCurrent()) return;
    for (const auto &record : product_.records()->pending()) {
        if (rowId != engineRowId("pending", product_.engine().serviceEpoch, record.request)) continue;
        const ReviewReference reference{product_.engine().serviceEpoch, record.request, record.profileGeneration};
        const auto generation = product_.generation();
        auto *l = modal("Service request · read only", ModalOwner::Live);
        l->addWidget(label(recordText(record.name, "Unattributed request"), "heading", true));
        auto *path = new QPlainTextEdit(recordText(record.path, "Application path unknown"));
        path->setObjectName("request-readonly-path"); path->setReadOnly(true);
        path->setMinimumHeight(54); path->setMaximumHeight(80);
        path->setWordWrapMode(QTextOption::WrapAnywhere); l->addWidget(path);
        l->addWidget(label("Observed origin: " + QString(record.origin == 3 ? "Local listen · remote endpoint unknown"
            : record.flow == 2 ? "Outbound initiated" : "Inbound initiated") +
            "\nPermanent path scope: all matching users, sessions and instances" +
            (product_.records()->protocolMinor() == 2 ? QString("\nRecommended direction: ") +
                (record.direction == 1 ? "Outbound · Allow is unicast only" : "Inbound") +
                "\nBoth requires explicit administrator review; no selection grants permission."
                : "\nPolicy direction: Both"), "muted", true));
        l->addWidget(note("Queueing grants no permission. Confirm only in the administrator reviewer.", true));
        l->addWidget(label("The reviewer fetches the current service request.\nClosing this dialog keeps the request undecided.", "muted", true));
        auto *queue = button("Queue administrator review", "queue-admin-review", "primary"); l->addWidget(queue, 0, Qt::AlignRight);
        auto *status = label(reviewer_.status(), "muted", true); status->setObjectName("reviewer-status");
        status->setMinimumHeight(3 * status->fontMetrics().lineSpacing()); l->addWidget(status);
        connect(queue, &QPushButton::clicked, this, [this, reference, generation] {
            if (product_.generation() == generation && product_.engine().current &&
                product_.engine().serviceEpoch == reference.epoch && product_.records()->profile() == reference.profile)
                reviewer_.open(reference);
        });
        return;
    }
}
void MainWindow::renderLiveDetail(const QString &id) {
    const auto *p = product_.process(id); if (!p || view_ != "processes") return;
    QByteArray key; QDataStream stamp(&key, QIODevice::WriteOnly);
    stamp << id << p->name << p->imagePath << p->lastAttemptUtc << p->lastAuthorizedUtc << p->lastTrafficUtc
          << bool(p->sourceImage);
    if (p->sourceImage) stamp << p->sourceImage->volumeSerial << p->sourceImage->indexHigh << p->sourceImage->indexLow;
    if (detail_ && detail_->property("detail-key").toByteArray() == key) return;
    if (detail_ && detail_->property("detail-id").toString() == id) {
        const auto at = [](const QDateTime &time) { return time.isValid() ? time.toUTC().toString(Qt::ISODateWithMs) : QString("Unknown"); };
        const QMap<QString,QString> values{{"Last request",at(p->lastAttemptUtc)},
            {"Last allowed",at(p->lastAuthorizedUtc)},{"Last traffic",at(p->lastTrafficUtc)},
            {"Image custody",p->sourceImage ? "Source-retained original image + local live process snapshot" : "Snapshot only · original image unknown"},
            {"Original NTFS file ID",p->sourceImage ? QString("%1:%2%3").arg(p->sourceImage->volumeSerial,8,16,QChar('0'))
                .arg(p->sourceImage->indexHigh,8,16,QChar('0')).arg(p->sourceImage->indexLow,8,16,QChar('0')) : "Unknown"}};
        for (auto *text : detail_->findChildren<QLabel *>()) {
            const auto name = text->property("definition-name").toString();
            if (values.contains(name) && text->text() != values[name]) text->setText(values[name]);
            if (text->property("role").toString() == "heading") {
                const auto title = p->name.isEmpty() ? QString("Unattributed process") : p->name;
                if (text->text() != title) text->setText(title);
            }
        }
        if (auto *path = detail_->findChild<QPlainTextEdit *>("observed-process-path")) {
            const auto text = p->imagePath.isEmpty() ? QString("Path unknown") : p->imagePath;
            if (path->toPlainText() != text) path->setPlainText(text);
        }
        detail_->setProperty("detail-key",key); return;
    }
    selected_ = id; if (detail_) dispose(detail_);
    detail_ = new QFrame(page_); detail_->setObjectName("detail"); auto *l = new QVBoxLayout(detail_);
    detail_->setProperty("detail-key", key);
    detail_->setProperty("detail-id",id);
    l->setContentsMargins(15, 15, 15, 13); l->setSpacing(10);
    auto *head = line(l); head->addWidget(label(p->name.isEmpty() ? "Unattributed process" : p->name, "heading"), 1); auto *close = button("×", "close-detail", "ghost"); head->addWidget(close);
    connect(close, &QPushButton::clicked, this, [this] { selected_.clear(); dispose(detail_); detail_.clear(); });
    divider(l); auto *content = new QWidget; auto *body = new QVBoxLayout(content); body->setContentsMargins(0, 0, 0, 0); body->setSpacing(9);
    body->addWidget(label("Process observation · read only", "muted"));
    auto *path = new QPlainTextEdit(p->imagePath.isEmpty() ? "Path unknown" : p->imagePath);
    path->setObjectName("observed-process-path"); path->setReadOnly(true);
    path->setFrameShape(QFrame::NoFrame); path->setWordWrapMode(QTextOption::WrapAnywhere);
    path->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    path->setMaximumHeight(78); path->setMinimumHeight(55);
    path->setStyleSheet("background: transparent; color: #70b8c8;"); body->addWidget(path);
    definition(body, "PID", QString::number(p->instance.pid)); definition(body, "Publisher", "Unknown"); definition(body, "Signature", "Unknown");
    definition(body, "Image custody", p->sourceImage ? "Source-retained original image + local live process snapshot" : "Snapshot only · original image unknown");
    if (p->sourceImage) {
        const auto &f = *p->sourceImage;
        definition(body, "Original NTFS file ID", QString("%1:%2%3").arg(f.volumeSerial,8,16,QChar('0')).arg(f.indexHigh,8,16,QChar('0')).arg(f.indexLow,8,16,QChar('0')));
    } else definition(body,"Original NTFS file ID","Unknown");
    definition(body, "Policy", "Unknown");
    const auto observed = [](const QDateTime &at) { return at.isValid() ? at.toUTC().toString(Qt::ISODateWithMs) : QString("Unknown"); };
    definition(body, "Last request", observed(p->lastAttemptUtc)); definition(body, "Last allowed", observed(p->lastAuthorizedUtc)); definition(body, "Last traffic", observed(p->lastTrafficUtc));
    body->addWidget(note("Public facts unavailable. A process name does not identify its purpose, reputation or network requests.", true)); body->addStretch(); l->addWidget(scrollArea(content), 1);
    l->addWidget(label("Administrator control is not available in this build.", "warning", true)); positionOverlays(); detail_->show(); detail_->raise();
}
void MainWindow::reviewCandidate(const QString &rowId, bool draft) {
    if (product_.simulation()) return;
    const auto &report = draft ? product_.draft() : product_.review().report;
    for (const auto &c : report.candidates) if (rowId == "candidate:" + report.digest + ":" + c.id) {
        auto *l = modal(draft ? "Imported source preview" : "Review inactive candidate", draft ? ModalOwner::ImportedDraft : ModalOwner::ImportedReview);
        l->addWidget(note("Inactive · Unverified. Compatibility not validated; this review cannot activate a rule.", true));
        auto *content = new QWidget; auto *body = new QVBoxLayout(content); body->setContentsMargins(0, 0, 0, 0); body->setSpacing(8);
        body->addWidget(label(c.sourceId + " · " + c.sourceType, "heading", true));
        const auto &view = product_.importedView(draft);
        auto *facts = new QPlainTextEdit(product_.importEvidence(draft) ? qnameFacts(view, product_.derivedQNameCandidate(draft, c.id)) : semanticFacts(view, product_.derivedCandidate(draft, c.id)));
        facts->setObjectName("candidate-derived-facts"); facts->setReadOnly(true); facts->setMinimumHeight(170); facts->setMaximumHeight(210); body->addWidget(facts);
        body->addWidget(label("Original source and dependencies · retained without activation", "muted", true));
        QString sourceText;
        std::function<void(const Data::XmlNode &, int)> append = [&](const Data::XmlNode &node, int depth) {
            if (sourceText.size() >= 64000) return;
            sourceText += QString(depth * 2, ' ') + node.name + ": " + node.text.trimmed() + "\n";
            for (auto it = node.attributes.begin(); it != node.attributes.end(); ++it)
                sourceText += QString((depth + 1) * 2, ' ') + it.key() + " = " + it.value() + "\n";
            for (const auto &child : node.children) append(child, depth + 1);
        };
        append(c.source, 0);
        for (const auto &node : report.filters) append(node, 0);
        for (const auto &node : report.identities) append(node, 0);
        if (const auto &evidence = product_.importEvidence(draft)) {
            sourceText = "Projected Version / Rules / Filters / AppInfos only. Presentation excerpt; source evidence retained.\n";
            std::function<void(int, int)> qappend = [&](int index, int depth) {
                if (sourceText.size() >= 64000 || index < 0 || index >= evidence->nodes.size()) return;
                const auto &node = evidence->nodes[index];
                sourceText += QString(depth * 2, ' ') + "{" + node.name.uri + "}" + node.name.local + "\n";
                for (const auto &a : node.attributes) sourceText += QString((depth + 1) * 2, ' ') + a.qualifiedName + " = " + a.value + "\n";
                for (const auto &item : node.content) { if (sourceText.size() >= 64000) break; if (item.child >= 0) qappend(item.child, depth + 1); else sourceText += item.text.trimmed() + "\n"; }
            };
            const auto *candidate = product_.derivedQNameCandidate(draft, c.id);
            if (candidate) qappend(candidate->node, 0);
            for (int role : evidence->roles) qappend(role, 0);
        }
        auto *source = new QPlainTextEdit; source->setObjectName("candidate-source-facts"); source->setReadOnly(true);
        source->setPlainText(sourceText.left(64000)); source->setMinimumHeight(100); source->setMaximumHeight(140); body->addWidget(source);
        auto *scroll = scrollArea(content); scroll->setMinimumHeight(300); scroll->setMaximumHeight(390); l->addWidget(scroll);
        l->addWidget(label("Local review choice: " + (c.reviewAction ? Data::actionName(*c.reviewAction) : "Not reviewed") + ". Source facts remain unchanged.\nLast authorization and traffic: Unknown.", "faint", true));
        auto *policy = combo({"Allow (review only)", "Block (review only)", "Ask (review only)"}, "candidate-review-action");
        const auto *derived = product_.derivedCandidate(draft, c.id);
        const auto choice = c.reviewAction.value_or(derived ? derived->action.value_or(Data::Action::Ask) : Data::Action::Ask);
        policy->setCurrentIndex(choice == Data::Action::Allow ? 0 : choice == Data::Action::Block ? 1 : 2); l->addWidget(policy);
        auto *save = button("Save inactive review", "save-inactive-review", "primary"); save->setEnabled(!draft && product_.reviewWritable()); l->addWidget(save, 0, Qt::AlignRight);
        connect(save, &QPushButton::clicked, this, [this, id = c.id, digest = report.digest, revision = product_.review().revision, generation = product_.importGeneration(), policy] {
            if (product_.simulation() || product_.importGeneration() != generation || product_.review().report.digest != digest || product_.review().revision != revision) return;
            const auto action = policy->currentIndex() == 0 ? Data::Action::Allow : policy->currentIndex() == 1 ? Data::Action::Block : Data::Action::Ask;
            if (product_.updateCandidate(id, action)) { closeModal(); message("Saving local review in the background…"); }
        });
        if (!draft && product_.derivedQNameCandidate(false, c.id)) {
            auto *file = button("Choose original executable…","prepare-inactive-file","ghost"); l->addWidget(file,0,Qt::AlignRight);
            connect(file,&QPushButton::clicked,this,[this,id=c.id] { prepareFileRules({id}); });
            auto *prepare = button("Prepare matching source rule…", "prepare-imported-rule", "ghost");
            l->addWidget(prepare, 0, Qt::AlignRight);
            connect(prepare, &QPushButton::clicked, this, [this,id=c.id] { prepareImportedRule(id); });
        }
        return;
    }
}
void MainWindow::prepareImportedRule(const QString &candidate) {
    const auto *source = product_.derivedQNameCandidate(false, candidate);
    if (!source || product_.simulation()) return;
    const QString policy = source->action.known() && source->action.value == Data::SourceFwAction::Allow ? "Allow" :
        source->action.known() && source->action.value == Data::SourceFwAction::Deny ? "Block" : "Unknown";
    auto *l = modal("Prepare a matching source rule", ModalOwner::ImportedActivation);
    l->addWidget(label("Original policy: " + policy + " · " + Data::directionName(source->direction.value), "heading", true));
    l->addWidget(note("This creates a new rule in GateBouncer after confirmation. The imported document stays inactive. Only an exact application and account scope can be represented; additional source conditions and unresolved priorities remain inactive.", true));
    auto *processes = combo({}, "imported-rule-process");
    processes->addItem("Choose an application with current original evidence", QString{});
    for (const auto &p : product_.catalog().processes)
        if (p.identityEvidence == "SourceRetainedImageAndOwnInstance" && p.sourceImage && !p.historyCauses.isEmpty())
            processes->addItem(p.name + " · " + p.imagePath, product_.processId(p));
    l->addWidget(processes);
    auto *status = label("Connect history and refresh pending requests to obtain original process evidence. Saved history and a running process alone cannot activate a rule.", "muted", true);
    status->setObjectName("imported-rule-status");
    auto *scopeContent = new QWidget; auto *scopeLayout = new QVBoxLayout(scopeContent);
    scopeLayout->setContentsMargins(0,0,0,0); scopeLayout->addWidget(status);
    auto *scopeScroll = scrollArea(scopeContent); scopeScroll->setMinimumHeight(100); scopeScroll->setMaximumHeight(200); l->addWidget(scopeScroll);
    auto *consent = new QCheckBox("I accept the scope shown above.");
    consent->setObjectName("imported-rule-consent"); consent->setEnabled(false); l->addWidget(consent);
    auto *actions = line(l);
    auto *prepare = button("Check original evidence", "check-imported-rule", "ghost"); actions->addWidget(prepare);
    auto *confirm = button("Activate " + policy + " rule", "confirm-imported-rule", "primary"); confirm->setEnabled(false); actions->addWidget(confirm);
    auto token = std::make_shared<quint64>(0);
    auto consentToken = std::make_shared<quint64>(0);
    auto update = [this,status,consent,prepare,confirm,processes,token,consentToken] {
        const auto &view = product_.importedActivation();
        if (view.token != *token) { *token = view.token; *consentToken = 0; consent->setChecked(false); }
        if (!view.message.isEmpty()) status->setText(view.message);
        prepare->setEnabled(!view.busy && !view.ready && !processes->currentData().toString().isEmpty());
        processes->setEnabled(!view.busy && !view.ready);
        consent->setEnabled(view.ready);
        if (!view.ready) { *consentToken = 0; consent->setChecked(false); }
        confirm->setEnabled(view.ready && consent->isChecked() && *consentToken == view.token);
    };
    connect(&product_, &ProductController::changed, status, update);
    connect(processes, &QComboBox::currentIndexChanged, status, [this,update](int) { product_.cancelImportedRule(); update(); });
    connect(prepare, &QPushButton::clicked, status, [this,candidate,processes,update] {
        product_.prepareImportedRule(candidate, processes->currentData().toString()); update();
    });
    connect(consent, &QCheckBox::toggled, status, [this,consentToken,confirm](bool checked) {
        const auto &view = product_.importedActivation(); *consentToken = checked && view.ready ? view.token : 0;
        confirm->setEnabled(checked && view.ready && *consentToken == view.token);
    });
    connect(confirm, &QPushButton::clicked, status, [this,consent,consentToken] {
        if (product_.confirmImportedRule(*consentToken, consent->isChecked())) {
            closeModal(); message("Decision submitted. The original request shows its result; imported candidates remain inactive.");
        }
    });
    update();
}
QVBoxLayout *MainWindow::modal(const QString &title, ModalOwner owner) {
    closeModal();
    modalOwner_ = owner;
    const bool draft = owner == ModalOwner::ImportedDraft;
    modalGeneration_ = owner == ModalOwner::Simulation ? model_.epoch() :
        owner == ModalOwner::ImportedDraft || owner == ModalOwner::ImportedReview ? product_.importGeneration() : product_.generation();
    modalDigest_ = draft ? product_.draft().digest : product_.review().report.digest;
    modalRevision_ = draft ? 0 : product_.review().revision;
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
void MainWindow::closeStaleModal() {
    if (!modalOverlay_) return;
    const bool draft = modalOwner_ == ModalOwner::ImportedDraft;
    const bool imported = draft || modalOwner_ == ModalOwner::ImportedReview;
    if ((imported && (product_.simulation() || product_.importGeneration() != modalGeneration_ ||
         modalDigest_ != (draft ? product_.draft().digest : product_.review().report.digest) ||
         (!draft && modalRevision_ != product_.review().revision))) ||
        (modalOwner_ == ModalOwner::Simulation && (!product_.simulation() || !model_.available() || model_.epoch() != modalGeneration_)) ||
        (modalOwner_ == ModalOwner::ImportedActivation && (product_.simulation() || product_.generation() != modalGeneration_)) ||
        ((modalOwner_ == ModalOwner::FileRule || modalOwner_ == ModalOwner::FileBackup) &&
         (product_.simulation() || product_.generation() != modalGeneration_)) ||
        (modalOwner_ == ModalOwner::Live && (product_.simulation() || product_.generation() != modalGeneration_ || !product_.engine().current))) closeModal();
}
void MainWindow::closeModal() {
    const auto owner = modalOwner_; modalOwner_ = ModalOwner::General;
    if(owner==ModalOwner::Live&&assistance_)assistance_->cancel();
    if (owner == ModalOwner::ImportedActivation) product_.cancelImportedRule();
    if (owner == ModalOwner::FileRule || owner == ModalOwner::FileBackup) product_.cancelApplicationFile();
    if (modalOverlay_) {
        dispose(modalOverlay_);
        modalOverlay_.clear();
        modalPanel_.clear();
        if (previousFocus_)
            previousFocus_->setFocus();
        previousFocus_.clear();
    }
    modalOwner_ = ModalOwner::General; modalDigest_.clear(); modalGeneration_ = modalRevision_ = 0;
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
    auto *l = modal(candidate ? "Review inactive demo candidate" : "Edit demo rule", ModalOwner::Simulation);
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
    if (!product_.simulation()) { cleanupLiveRule(); return; }
    if (!model_.available())
        return;
    const auto epoch = model_.epoch();
    const auto candidates = model_.cleanupCandidates(cleanupDays_);
    auto *l = modal("Review stale demo rules", ModalOwner::Simulation);
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
void MainWindow::cleanupLiveRule() {
    if (product_.simulation() || !table_ || !product_.ordinary()->rulesCurrent()) return;
    const auto selected = table_->currentIndex().data(IdRole).toString();
    const auto &rules = product_.ordinary()->rules();
    const auto found = std::find_if(rules.begin(),rules.end(),[&](const auto &r) {
        return selected == "principal-rule:" + QString::fromStdString(gb::wire::hex(r.rule));
    });
    if (found == rules.end()) { message("Select a rule for your account before reviewing removal."); return; }
    const auto rule = *found; const auto selection = product_.ordinary()->selection();
    auto *layout = modal("Review rule removal",ModalOwner::FileRule);
    layout->addWidget(label(recordText(rule.display.name,"Application unknown"),"heading",true));
    definition(layout,"Target account",recordText(rule.display.principal,"Account display unavailable") + " · " + targetAccountText(rule));
    if (product_.administrativeSelected()) definition(layout,"Acting account","Original authenticated administrative session");
    const auto direction = rule.direction == 1 ? Data::Direction::Out : rule.direction == 2 ? Data::Direction::In : Data::Direction::Both;
    const auto scope = Data::applicationRuleScopeText(rule.package,direction,
        rule.action == 2 ? Data::Action::Allow : Data::Action::Block,false);
    definition(layout,"Rule",(rule.action == 2 ? QString("Allow") : QString("Block")) + " · " + scope.connections);
    layout->addWidget(note("Removing this rule changes future policy for this application and account. Other rules still apply. No recorded requests does not prove inactivity. Protection coverage has not been validated.",true));
    layout->addWidget(label("An inactive backup preserves the original application and account target. Restoring it requires the selected file to match again; it does not restore permissions automatically.","faint",true));
    auto *backupConsent = new QCheckBox("Save this selected rule as an inactive backup");
    backupConsent->setObjectName("consent-rule-backup"); layout->addWidget(backupConsent);
    auto *backup = button("Save selected backup","save-selected-rule-backup","ghost");
    backup->setEnabled(false); layout->addWidget(backup,0,Qt::AlignLeft);
    connect(backupConsent,&QCheckBox::toggled,backup,[this,backup](bool checked) {
        backup->setEnabled(checked && !product_.ruleBackupBusy() && product_.reviewWritable());
    });
    connect(backup,&QPushButton::clicked,this,[this,rule,selection,backupConsent] {
        const bool saved = product_.backupSelectedRules({rule.rule},selection,backupConsent->isChecked());
        closeModal(); message(saved ? "Saving the selected inactive rule backup in the background. No rule was changed."
            : "Backup was not queued. Refresh your rules and check the stored review status.");
    });
    auto *consent = new QCheckBox("Remove this selected application and account rule");
    consent->setObjectName("consent-rule-removal"); layout->addWidget(consent);
    auto *actions = line(layout); auto *cancel = button("Cancel","cancel-rule-removal","ghost");
    actions->addWidget(cancel); actions->addStretch();
    auto *remove = button("Remove selected rule","confirm-rule-removal","danger");
    remove->setEnabled(false); actions->addWidget(remove);
    connect(consent,&QCheckBox::toggled,remove,&QPushButton::setEnabled);
    connect(cancel,&QPushButton::clicked,this,&MainWindow::closeModal);
    connect(remove,&QPushButton::clicked,this,[this,rule,selection,consent] {
        if (!product_.ordinary()->revokeRule(rule.rule,selection,consent->isChecked())) {
            closeModal(); message("Rule selection changed. Refresh your rules before reviewing removal."); return;
        }
        closeModal();
    });
    cancel->setFocus();
}
void MainWindow::editSelectedFileRule() {
    if (!table_ || !product_.ordinary()->rulesCurrent()) return;
    const auto id = table_->currentIndex().data(IdRole).toString();
    for (const auto &rule : product_.ordinary()->rules()) if (id == "principal-rule:" + QString::fromStdString(gb::wire::hex(rule.rule))) {
        if (rule.package != 1) { message("This package scope stays unchanged; the file route cannot represent it."); return; }
        prepareFileRules({},rule.rule); return;
    }
    message("Select a current rule for your account before editing.");
}
void MainWindow::backupSelectedFileRules() {
    if (!table_ || !product_.ordinary()->rulesCurrent()) return;
    std::vector<gb::wire::Id> selected;
    for (const auto &index : table_->selectionModel()->selectedRows()) {
        const auto id = index.data(IdRole).toString();
        const auto &rules = product_.ordinary()->rules();
        const auto found = std::find_if(rules.begin(),rules.end(),[&](const auto &r) { return id == "principal-rule:" + QString::fromStdString(gb::wire::hex(r.rule)); });
        if (found == rules.end()) { message("Select only current rules for your account for this backup."); return; }
        selected.push_back(found->rule);
    }
    if (selected.empty() || selected.size() > 128) { message("Select between 1 and 128 current rules for your account."); return; }
    const auto selection = product_.ordinary()->selection();
    auto *layout = modal("Back up selected rules",ModalOwner::FileRule);
    layout->addWidget(note(QString("Save %1 selected rules, including their original application and account targets, as an inactive backup. No rule will be changed. A backup cannot restore permissions automatically.").arg(selected.size()),true));
    auto *consent = new QCheckBox("Save these selected rules as an inactive backup"); layout->addWidget(consent);
    auto *save = button("Save inactive backup","save-rule-backup","primary"); save->setEnabled(false); layout->addWidget(save);
    connect(consent,&QCheckBox::toggled,save,&QPushButton::setEnabled);
    connect(save,&QPushButton::clicked,this,[this,selected,selection,consent] {
        if (!product_.backupSelectedRules(selected,selection,consent->isChecked())) { message("The original selection changed or a stored review write is unavailable."); return; }
        closeModal(); message("Saving selected inactive rules in the background. No rule was changed.");
    });
}
void MainWindow::prepareSelectedSourceFiles() {
    if (!table_ || !product_.importedView(false).current || !product_.importedView(false).qname) return;
    QStringList selected;
    const auto prefix = "candidate:" + product_.review().report.digest + ":";
    for (const auto &index : table_->selectionModel()->selectedRows()) {
        const auto id = index.data(IdRole).toString();
        if (!id.startsWith(prefix)) { message("Save the source preview first, then select saved inactive rules."); return; }
        selected.push_back(id.mid(prefix.size()));
    }
    if (selected.isEmpty() || selected.size() > 128) { message("Select between 1 and 128 saved inactive source rules."); return; }
    prepareFileRules(selected);
}
void MainWindow::openRuleBackup() {
    if (product_.simulation()) return;
    const auto path = QFileDialog::getOpenFileName(this,"Open inactive selected rule backup",product_.ruleBackupDirectory(),"Rule backups (*.json)");
    if (path.isEmpty()) return;
    auto *layout = modal("Open inactive selected rule backup",ModalOwner::FileBackup);
    layout->addWidget(note("A backup is historical data. No stored permission becomes active. Each restore requires the original executable, your original account and explicit confirmation of a new rule.",true));
    auto *status = label({},"muted",true); layout->addWidget(status);
    auto *rules = combo({},"inactive-backup-selection"); layout->addWidget(rules);
    auto *restore = button("Choose executable to restore…","restore-rule-backup","primary"); layout->addWidget(restore);
    auto token = std::make_shared<quint64>(0);
    auto update = [this,status,rules,restore,token] {
        const QSignalBlocker blocked(rules);
        const auto &view = product_.fileRuleView(); status->setText(view.message);
        if (view.token != *token) {
            *token = view.token; rules->clear();
            for (const auto &r : product_.inactiveRuleBackup()) rules->addItem(recordText(r.display.name,"Application unknown") +
                " · " + (r.action == 2 ? "Allow" : "Block") + " · " + recordText(r.display.principal,"Account unknown"));
        } else if (!view.busy && rules->count() != int(product_.inactiveRuleBackup().size())) {
            rules->clear(); for (const auto &r : product_.inactiveRuleBackup()) rules->addItem(recordText(r.display.name,"Application unknown") + " · " + (r.action == 2 ? "Allow" : "Block"));
        }
        const auto index = rules->currentIndex();
        restore->setEnabled(!view.busy && index >= 0 && std::size_t(index) < product_.inactiveRuleBackup().size() && product_.inactiveRuleBackup()[std::size_t(index)].package == 1);
    };
    connect(&product_,&ProductController::changed,status,update);
    connect(rules,&QComboBox::currentIndexChanged,status,[update](int) { update(); });
    connect(restore,&QPushButton::clicked,this,[this,rules] { const auto index = rules->currentIndex(); if (index >= 0) prepareFileRules({}, {},index); });
    if (!product_.loadSelectedRuleBackup(path)) message("A rule operation is already in progress; the backup was not opened.");
    update();
}
void MainWindow::prepareFileRules(const QStringList &candidates, const std::optional<gb::wire::Id> &editing, int backupIndex) {
    if (product_.simulation() || candidates.size() > 128) return;
    const auto selection = product_.ordinary()->selection();
    const auto digest = product_.review().report.digest; const auto revision = product_.review().revision;
    auto *layout = modal(editing ? "Edit selected application rule" : candidates.isEmpty() && backupIndex < 0 ? "New application rule" : "Review selected inactive rules",ModalOwner::FileRule);
    layout->addWidget(note(product_.administrativeSelected()
        ? "An administrative replacement preserves the account from the selected original catalog rule. The executable is retained under the acting account; that actor is separate from the target account. New file rules still use your own account. A saved backup cannot select another account. Unsupported source conditions, priorities and package scopes remain inactive; protection coverage has not been validated."
        : "This route covers your connected account only. SYSTEM, NetworkService and other accounts require their original administrator route. Source conditions, priorities or package scopes that cannot be represented stay inactive. Protection coverage has not been validated.",true));
    auto *sources = combo({},"file-source-selection");
    if (candidates.isEmpty()) sources->addItem(backupIndex >= 0 ? "Selected inactive backup" : editing ? "Selected current rule" : "New application and account rule",QString{});
    else for (const auto &id : candidates) sources->addItem(id,id);
    layout->addWidget(sources);
    auto *path = new QLineEdit; path->setReadOnly(true); path->setObjectName("selected-rule-executable"); path->setPlaceholderText("Choose the original executable; it may be closed.");
    auto *fileLine = line(layout); fileLine->addWidget(path,1); auto *choose = button("Choose…","choose-rule-executable","ghost"); fileLine->addWidget(choose);
    auto *policyLine = line(layout);
    auto *policy = combo({"Block","Allow"},"file-rule-policy"); auto *direction = combo({"Outbound","Inbound","Both"},"file-rule-direction");
    policyLine->addWidget(policy); policyLine->addWidget(direction);
    if (editing) for (const auto &r : product_.ordinary()->rules()) if (r.rule == *editing) { policy->setCurrentIndex(r.action == 2 ? 1 : 0); direction->setCurrentIndex(r.direction == 1 ? 0 : r.direction == 2 ? 1 : 2); }
    if (backupIndex >= 0 && std::size_t(backupIndex) < product_.inactiveRuleBackup().size()) {
        const auto &r = product_.inactiveRuleBackup()[std::size_t(backupIndex)]; policy->setCurrentIndex(r.action == 2 ? 1 : 0); direction->setCurrentIndex(r.direction == 1 ? 0 : r.direction == 2 ? 1 : 2);
    }
    auto *status = label("Choose an executable. It will be retained under your original account while the service prepares its own draft.","muted",true);
    status->setObjectName("file-rule-scope"); auto *content = new QWidget; auto *body = new QVBoxLayout(content); body->setContentsMargins(0,0,0,0); body->addWidget(status);
    auto *scroll = scrollArea(content); scroll->setMinimumHeight(120); scroll->setMaximumHeight(240); layout->addWidget(scroll);
    auto *consent = new QCheckBox("I accept this exact decision and the scope shown above."); consent->setObjectName("file-rule-consent"); consent->setEnabled(false); layout->addWidget(consent);
    auto *actions = line(layout); auto *prepare = button("Check original file and draft","prepare-file-rule","ghost"); actions->addWidget(prepare);
    auto *confirm = button(editing ? "Replace selected rule" : "Create reviewed rule","confirm-file-rule","primary"); confirm->setEnabled(false); actions->addWidget(confirm);
    auto token = std::make_shared<quint64>(0); auto consentToken = std::make_shared<quint64>(0);
    auto update = [this,sources,path,choose,policy,direction,status,consent,prepare,confirm,token,consentToken,candidates,backupIndex,digest,revision] {
        const auto &view = product_.fileRuleView();
        if (view.token != *token) { *token = view.token; *consentToken = 0; consent->setChecked(false); }
        if (!view.message.isEmpty()) status->setText(view.message);
        const auto state = product_.ordinary()->state();
        const bool inFlight = view.busy || view.ready || state == OrdinaryDecisionClient::State::Sending || state == OrdinaryDecisionClient::State::Uncertain;
        sources->setEnabled(!inFlight); choose->setEnabled(!inFlight); policy->setEnabled(!inFlight && candidates.isEmpty() && backupIndex < 0);
        direction->setEnabled(!inFlight && candidates.isEmpty() && backupIndex < 0);
        bool sourceKnown = true;
        if (!candidates.isEmpty()) {
            const auto *source = product_.derivedQNameCandidate(false,sources->currentData().toString());
            sourceKnown = source && source->action.known() && (source->action.value == Data::SourceFwAction::Allow || source->action.value == Data::SourceFwAction::Deny) && source->direction.known() && source->direction.value != Data::Direction::Unknown && product_.review().report.digest == digest && product_.review().revision == revision;
            if (sourceKnown) { policy->setCurrentIndex(source->action.value == Data::SourceFwAction::Allow ? 1 : 0); direction->setCurrentIndex(source->direction.value == Data::Direction::Out ? 0 : source->direction.value == Data::Direction::In ? 1 : 2); }
        }
        prepare->setEnabled(!inFlight && !Data::SelectedApplicationFile::physicalJobs() && !path->text().isEmpty() && sourceKnown);
        consent->setEnabled(view.ready);
        if (!view.ready) { *consentToken = 0; consent->setChecked(false); }
        confirm->setEnabled(view.ready && consent->isChecked() && *consentToken == view.token);
    };
    const auto reset = [this,consent,consentToken] { *consentToken = 0; consent->setChecked(false); product_.cancelApplicationFile(); };
    connect(choose,&QPushButton::clicked,status,[this,path,reset,update] { const auto selected = QFileDialog::getOpenFileName(this,"Choose original executable",{},"Executables (*.exe);;All files (*)"); if (!selected.isEmpty()) { reset(); path->setText(selected); update(); } });
    connect(sources,&QComboBox::currentIndexChanged,status,[path,reset,update](int) { reset(); path->clear(); update(); });
    connect(policy,&QComboBox::activated,status,[reset,update](int) { reset(); update(); });
    connect(direction,&QComboBox::activated,status,[reset,update](int) { reset(); update(); });
    connect(&product_,&ProductController::changed,status,update);
    connect(prepare,&QPushButton::clicked,status,[this,path,policy,direction,sources,editing,selection,backupIndex,update] {
        const auto action = policy->currentIndex() == 1 ? Data::Action::Allow : Data::Action::Block;
        const auto scope = direction->currentIndex() == 0 ? Data::Direction::Out : direction->currentIndex() == 1 ? Data::Direction::In : Data::Direction::Both;
        if (!product_.prepareApplicationFile(path->text(),action,scope,editing,selection,sources->currentData().toString(),backupIndex)) message("The original file review could not start. Check the current selection and wait for any previous operation to finish."); update();
    });
    connect(consent,&QCheckBox::toggled,status,[this,consentToken,confirm](bool checked) { const auto &view = product_.fileRuleView(); *consentToken = checked && view.ready ? view.token : 0; confirm->setEnabled(checked && view.ready && *consentToken == view.token); });
    connect(confirm,&QPushButton::clicked,status,[this,consent,consentToken,update] { product_.confirmApplicationFile(*consentToken,consent->isChecked()); update(); });
    update();
}
void MainWindow::about() {
    auto *l = modal("About LGA GateBouncer");
    if (!product_.simulation()) {
        l->addWidget(note("Live process catalog and inactive migration review. Service snapshots require an explicit connection. This window is read only; decisions require the separate protected administrator reviewer. Network protection and coverage have not been validated.", true));
        l->addWidget(label("Executable contents, publishers and signatures are not inspected. Only the migration file you choose is analyzed. Simulation is an explicit offline sample mode.", "muted", true));
        auto *close = button("Close", "about-close"); l->addWidget(close, 0, Qt::AlignRight);
        connect(close, &QPushButton::clicked, this, &MainWindow::closeModal); return;
    }
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
                           !product_.simulation() || model_.review(explanation_.visibleId()).expanded ? 625 : 541);
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
                product_.simulation() ? explanation_.close() : product_.ordinary()->closeNotice();
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
