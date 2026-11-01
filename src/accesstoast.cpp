#include "accesstoast.h"
#include <QComboBox>
#include <QDir>
#include <QEvent>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QFontDatabase>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QLinearGradient>
#include <QMenu>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QScreen>
#include <QStandardPaths>
#include <QTimer>
#include <QVBoxLayout>
#include <QWheelEvent>
#include <utility>

namespace Gate {
namespace {
// Mismos valores que el aviso de disco de Mighty Tools.
constexpr char Text[] = "#f5f5f5";
constexpr char Body[] = "#d0d0d0";
constexpr char Faint[] = "#8a8a8a";
constexpr char FieldBorder[] = "#3c3c3c";
constexpr char Field[] = "#202020";
constexpr char Button[] = "rgba(255,255,255,8)";
constexpr char ButtonBorder[] = "#404040";
constexpr char ButtonHover[] = "#383838";
constexpr char HeaderIcon[] = "#aaaaaa";
constexpr char Link[] = "#b9b4f0";
constexpr int Width = 352;
constexpr int Margin = 15;

QString elideMiddle(const QLabel *label, const QString &text, int width) {
    return label->fontMetrics().elidedText(text, Qt::ElideMiddle, width);
}

// Íconos de la cabecera dibujados: los caracteres «···» y «×» no entran en botones de 24 px con Segoe UI.
QIcon headerIcon(bool close) {
    const qreal dpr = qMax(qreal(2), qApp->devicePixelRatio());
    QIcon icon;
    for (const auto &[mode, color] : {std::pair{QIcon::Normal, QColor(HeaderIcon)}, std::pair{QIcon::Active, QColor(Text)}}) {
        QPixmap pixmap(QSize(14, 14) * dpr);
        pixmap.setDevicePixelRatio(dpr);
        pixmap.fill(Qt::transparent);
        QPainter p(&pixmap);
        p.setRenderHint(QPainter::Antialiasing);
        if (close) {
            p.setPen(QPen(color, 1.4, Qt::SolidLine, Qt::RoundCap));
            p.drawLine(QPointF(3, 3), QPointF(11, 11));
            p.drawLine(QPointF(11, 3), QPointF(3, 11));
        } else {
            p.setPen(Qt::NoPen);
            p.setBrush(color);
            for (const qreal x : {2.5, 7.0, 11.5}) p.drawEllipse(QPointF(x, 7), 1.2, 1.2);
        }
        p.end();
        icon.addPixmap(pixmap, mode);
    }
    return icon;
}

// Desplegable del aviso: la rueda nunca cambia lo elegido (el aviso aparece debajo del puntero mientras se trabaja)
// y la flecha se dibuja, porque la hoja de estilo le saca la del sistema.
class ScopeCombo final : public QComboBox {
  public:
    using QComboBox::QComboBox;

  protected:
    void wheelEvent(QWheelEvent *event) override { event->ignore(); }
    void paintEvent(QPaintEvent *event) override {
        QComboBox::paintEvent(event);
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.setPen(QPen(QColor(isEnabled() ? Body : "#5a5a5a"), 1.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        const QPointF c(width() - 18, height() / 2.0 + 1);
        p.drawPolyline(QPolygonF({c + QPointF(-4.5, -2.5), c + QPointF(0, 2), c + QPointF(4.5, -2.5)}));
    }
};

QPixmap dot(const QColor &color) {
    const qreal dpr = qMax(qreal(1), qApp->devicePixelRatio());
    QPixmap pixmap(QSize(8, 8) * dpr);
    pixmap.setDevicePixelRatio(dpr);
    pixmap.fill(Qt::transparent);
    QPainter p(&pixmap);
    p.setRenderHint(QPainter::Antialiasing);
    p.setPen(Qt::NoPen);
    p.setBrush(color);
    p.drawEllipse(QRectF(0, 0, 8, 8));
    return pixmap;
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
    setFixedWidth(Width);
#ifdef Q_OS_WIN
    // Offscreen (capturas de QA) no enumera las fuentes de Windows: usa el mismo archivo que el escritorio real.
    if (QGuiApplication::platformName() == QLatin1String("offscreen")) {
        static const int fontId = QFontDatabase::addApplicationFont(
            QStandardPaths::locate(QStandardPaths::FontsLocation, QStringLiteral("segoeui.ttf")));
        Q_UNUSED(fontId);
    }
#endif
    setStyleSheet(QString(
        "#accessToast QLabel, #accessToast QComboBox, #accessToast QPushButton { background:transparent; border:0;"
        " color:%1; font-family:'Segoe UI'; font-size:13px; font-weight:400; }"
        "#accessToast QLabel#toastHeader { font-size:12px; color:%2; }"
        "#accessToast QLabel#toastBody { color:%2; }"
        "#accessToast QLabel#toastPath, #accessToast QLabel#toastNote, #accessToast QLabel#toastFooter { font-size:11px; color:%3; }"
        "#accessToast QLabel#toastSignature { font-size:12px; }"
        "#accessToast QComboBox { background:%4; border:1px solid %5; border-radius:5px; padding:0 10px; min-height:30px; max-height:30px; }"
        "#accessToast QComboBox:disabled { color:#7a7a7a; }"
        "#accessToast QComboBox::drop-down { width:28px; border:0; }"
        "#accessToast QComboBox QAbstractItemView { background:%4; border:1px solid %5; color:%1; font-family:'Segoe UI';"
        " font-size:13px; selection-background-color:%8; }"
        "#accessToast QPushButton#toastBlock, #accessToast QPushButton#toastAllow { min-height:32px; max-height:32px;"
        " background:%6; border:1px solid %7; border-radius:4px; padding:0 10px; }"
        "#accessToast QPushButton#toastBlock:hover, #accessToast QPushButton#toastAllow:hover { background:%8; }"
        "#accessToast QPushButton:disabled { color:#6f6f6f; }"
        "#accessToast QPushButton#toastOpen { font-size:11px; color:%9; }"
        "#accessToast QPushButton#toastOpen:hover { text-decoration:underline; }"
        "#accessToast QPushButton#toastMenu, #accessToast QPushButton#toastClose { color:%10; font-size:15px; }"
        "#accessToast QPushButton#toastMenu:hover, #accessToast QPushButton#toastClose:hover { color:%1; }"
        "#accessToast QWidget#toastExplainBox { background:%4; border:1px solid %5; border-radius:6px; }"
        "#accessToast QLabel#toastExplainStatus, #accessToast QLabel#toastExplainFoot, #accessToast QLabel#toastRisk"
        " { font-size:11px; color:%3; }"
        "#accessToast QLabel#toastWhat, #accessToast QLabel#toastWhy { font-size:12px; color:%2; }"
        "#accessToast QLabel#toastSuggestion { font-size:12px; color:%1; }"
        "#accessToast QPushButton#toastExplain { font-size:12px; color:%9; text-align:left; padding:0; }"
        "#accessToast QPushButton#toastExplain:hover { text-decoration:underline; }")
        .arg(Text, Body, Faint, Field, FieldBorder, Button, ButtonBorder, ButtonHover, Link)
        .arg(HeaderIcon));

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 14, 16, 14);
    layout->setSpacing(0);

    auto *header = new QHBoxLayout;
    header->setSpacing(8);
    auto *small = new QLabel(this);
    small->setFixedSize(16, 16);
    small->setPixmap(QIcon(":/gatebouncer/resources/icons/LGA_GateBouncer.png").pixmap(16, 16));
    header->addWidget(small);
    auto *name = new QLabel("LGA GateBouncer", this);
    name->setObjectName("toastHeader");
    header->addWidget(name, 1);
    auto *more = new QPushButton(this);
    more->setObjectName("toastMenu");
    more->setFixedSize(24, 24);
    more->setIcon(headerIcon(false));
    more->setIconSize(QSize(14, 14));
    more->setAccessibleName("More actions");
    more->setCursor(Qt::PointingHandCursor);
    header->addWidget(more);
    auto *close = new QPushButton(this);
    close->setObjectName("toastClose");
    close->setFixedSize(20, 24);
    close->setIcon(headerIcon(true));
    close->setIconSize(QSize(14, 14));
    close->setAccessibleName("Close and keep the application blocked");
    close->setCursor(Qt::PointingHandCursor);
    header->addWidget(close);
    layout->addLayout(header);
    layout->addSpacing(12);

    auto *menu = new QMenu(this);
    menu->addAction("Open GateBouncer", this, [this] { emit openRequested(); });
    menu->addAction("Pending list", this, [this] { emit pendingListRequested(); });
    connect(more, &QPushButton::clicked, this, [more, menu] { menu->popup(more->mapToGlobal(QPoint(0, more->height()))); });
    connect(close, &QPushButton::clicked, this, [this] { emit dismissed(request_.path); });

    auto *summary = new QHBoxLayout;
    summary->setSpacing(12);
    icon_ = new QLabel(this);
    icon_->setFixedSize(48, 48);
    auto *iconColumn = new QVBoxLayout;
    iconColumn->addSpacing(2);
    iconColumn->addWidget(icon_);
    iconColumn->addStretch();
    summary->addLayout(iconColumn);
    auto *text = new QVBoxLayout;
    text->setSpacing(1);
    title_ = new QLabel(this);
    title_->setObjectName("toastTitle");
    text->addWidget(title_);
    auto *body = new QLabel("Its first attempt to connect was blocked. If you allow it, the next attempt connects.", this);
    body->setObjectName("toastBody");
    body->setWordWrap(true);
    text->addWidget(body);
    summary->addLayout(text, 1);
    layout->addLayout(summary);
    layout->addSpacing(12);

    auto *signature = new QHBoxLayout;
    signature->setSpacing(7);
    signatureMark_ = new QLabel(this);
    signatureMark_->setFixedSize(8, 8);
    signature->addWidget(signatureMark_);
    signature_ = new QLabel(this);
    signature_->setObjectName("toastSignature");
    signature->addWidget(signature_, 1);
    layout->addLayout(signature);
    layout->addSpacing(2);
    path_ = new QLabel(this);
    path_->setObjectName("toastPath");
    layout->addWidget(path_);
    layout->addSpacing(10);

    // Explicación con IA. El enlace la pide; la respuesta va en un recuadro aparte y nunca toca la decisión.
    explainAction_ = new QPushButton(this);
    explainAction_->setObjectName("toastExplain");
    explainAction_->setCursor(Qt::PointingHandCursor);
    explainAction_->setFlat(true);
    layout->addWidget(explainAction_, 0, Qt::AlignLeft);
    explainStatus_ = new QLabel(this);
    explainStatus_->setObjectName("toastExplainStatus");
    explainStatus_->setWordWrap(true);
    explainStatus_->setFixedWidth(Width - 32);
    explainStatus_->setTextFormat(Qt::PlainText);
    layout->addWidget(explainStatus_);
    explainBox_ = new QWidget(this);
    explainBox_->setObjectName("toastExplainBox");
    explainBox_->setAttribute(Qt::WA_StyledBackground);
    auto *box = new QVBoxLayout(explainBox_);
    box->setContentsMargins(11, 9, 11, 9);
    box->setSpacing(6);
    for (auto **label : {&what_, &why_, &risk_, &suggestion_, &explainFoot_}) {
        *label = new QLabel(explainBox_);
        (*label)->setWordWrap(true);
        // La respuesta del modelo es texto no confiable: siempre plano, nunca HTML ni enlaces.
        (*label)->setTextFormat(Qt::PlainText);
        // Ancho fijo: así el alto de cada párrafo se calcula bien y el recuadro no corta el texto.
        (*label)->setFixedWidth(Width - 32 - 22);
        box->addWidget(*label);
    }
    what_->setObjectName("toastWhat");
    why_->setObjectName("toastWhy");
    risk_->setObjectName("toastRisk");
    suggestion_->setObjectName("toastSuggestion");
    explainFoot_->setObjectName("toastExplainFoot");
    layout->addWidget(explainBox_);
    dots_ = new QTimer(this);
    dots_->setInterval(450);
    connect(dots_, &QTimer::timeout, this, [this] {
        dotCount_ = (dotCount_ + 1) % 4;
        explainStatus_->setText("Asking NVIDIA" + QString(dotCount_, QChar('.')));
    });
    connect(explainAction_, &QPushButton::clicked, this, [this] {
        if (explanation_.state == Explanation::NoKey) emit settingsRequested();
        else emit explainRequested(request_.path);
    });
    layout->addSpacing(12);

    auto *choices = new QHBoxLayout;
    choices->setSpacing(10);
    auto *scopeColumn = new QVBoxLayout;
    scopeColumn->setSpacing(7);
    scopeColumn->addWidget(new QLabel("Apply to", this));
    scope_ = new ScopeCombo(this);
    scope_->setObjectName("toastScope");
    scope_->setAccessibleName("Apply to");
    scopeColumn->addWidget(scope_);
    choices->addLayout(scopeColumn, 1);
    auto *durationColumn = new QVBoxLayout;
    durationColumn->setSpacing(7);
    durationColumn->addWidget(new QLabel("For", this));
    duration_ = new ScopeCombo(this);
    duration_->setObjectName("toastDuration");
    duration_->setAccessibleName("For");
    duration_->setFixedWidth(120);
    duration_->addItem("Always", "always");
    for (const int minutes : {1, 5, 10, 15, 30})
        duration_->addItem(minutes == 1 ? QStringLiteral("1 minute") : QString("%1 minutes").arg(minutes),
                           QString::number(minutes * 60));
    duration_->addItem("1 hour", "3600");
    duration_->addItem("Until restart", "restart");
    durationColumn->addWidget(duration_);
    choices->addLayout(durationColumn);
    layout->addLayout(choices);
    note_ = new QLabel("Unsigned apps can only get a rule for this exact file.", this);
    note_->setObjectName("toastNote");
    note_->setWordWrap(true);
    layout->addSpacing(6);
    layout->addWidget(note_);
    layout->addSpacing(14);

    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(10);
    block_ = new QPushButton("Block", this);
    block_->setObjectName("toastBlock");
    allow_ = new QPushButton("Allow", this);
    allow_->setObjectName("toastAllow");
    buttons->addWidget(block_);
    buttons->addWidget(allow_);
    layout->addLayout(buttons);
    layout->addSpacing(10);
    for (auto *b : {block_, allow_})
        connect(b, &QPushButton::clicked, this, [this, allowed = b == allow_] {
            emit decided(request_.path, allowed, scope_->currentData().toString(), duration_->currentData().toString());
        });

    auto *foot = new QHBoxLayout;
    footer_ = new QLabel(this);
    footer_->setObjectName("toastFooter");
    foot->addWidget(footer_, 1);
    auto *open = new QPushButton("Open GateBouncer", this);
    open->setObjectName("toastOpen");
    open->setCursor(Qt::PointingHandCursor);
    foot->addWidget(open);
    connect(open, &QPushButton::clicked, this, [this] { emit openRequested(); });
    layout->addLayout(foot);
}

void AccessToast::setRequest(const Request &request) {
    const bool samePath = request.path.compare(request_.path, Qt::CaseInsensitive) == 0 &&
                          request.signer == request_.signer && !request_.path.isEmpty();
    request_ = request;
    if (!samePath) {
        const QFileInfo file(request.path);
        title_->setText(file.fileName() + " was blocked");
        QIcon appIcon = QFileIconProvider().icon(file);
        if (appIcon.isNull()) appIcon = QIcon(":/gatebouncer/resources/icons/LGA_GateBouncer.png");
        icon_->setPixmap(appIcon.pixmap(48, 48));
        const bool signedApp = !request.signer.isEmpty();
        signature_->setText(signedApp ? request.signer + " · valid signature" : QString("No valid signature"));
        signatureMark_->setPixmap(dot(signedApp ? QColor("#8fcf6a") : QColor("#e8b46f")));
        path_->setText(elideMiddle(path_, QDir::toNativeSeparators(request.path), Width - 32));
        // La ruta entera sólo cuando no entra: el texto visible ya la muestra si es corta.
        path_->setToolTip(path_->text() != QDir::toNativeSeparators(request.path) ? QDir::toNativeSeparators(request.path)
                                                                                   : QString());
        rebuildScopes();
        duration_->setCurrentIndex(0);
        explanation_ = {};
        renderExplanation();
        armed_ = false;
        QTimer::singleShot(600, this, [this, path = request.path] {
            if (request_.path != path) return;
            armed_ = true;
            updateCounters();
        });
    }
    updateCounters();
    adjustSize();
}

void AccessToast::rebuildScopes() {
    scope_->clear();
    const auto &signer = request_.signer;
    if (signer.isEmpty()) {
        scope_->addItem("This file only", "path");
    } else {
        scope_->addItem("This app, any version", "app");
        scope_->addItem("This file only", "path");
        // Igual que el motor: «todo Microsoft» incluiría herramientas de Windows que descargan archivos.
        if (!signer.startsWith("Microsoft", Qt::CaseInsensitive)) scope_->addItem("All apps from " + signer, "publisher");
    }
    scope_->setCurrentIndex(0);
    scope_->setEnabled(scope_->count() > 1);
    note_->setVisible(signer.isEmpty());
}

void AccessToast::updateCounters() {
    block_->setEnabled(request_.canDecide && armed_);
    allow_->setEnabled(request_.canDecide && armed_);
    scope_->setEnabled(request_.canDecide && armed_ && scope_->count() > 1);
    duration_->setEnabled(request_.canDecide && armed_);
    QStringList parts;
    if (request_.attempts > 1) parts << QString("%1 attempts").arg(request_.attempts);
    if (request_.othersWaiting > 0) parts << QString("%1 more waiting").arg(request_.othersWaiting);
    if (!request_.canDecide) parts << "read only";
    footer_->setText(parts.join(" · "));
}

void AccessToast::setExplanation(const QString &path, const Explanation &explanation) {
    if (path.compare(request_.path, Qt::CaseInsensitive) != 0) return;
    explanation_ = explanation;
    renderExplanation();
    // Crece hacia arriba: el borde de abajo queda en su lugar.
    if (screen_ && isVisible()) placeOn(screen_);
    else adjustSize();
}

void AccessToast::renderExplanation() {
    const auto &e = explanation_;
    const bool working = e.state == Explanation::Working;
    working ? dots_->start() : dots_->stop();
    explainAction_->setVisible(e.state != Explanation::Working && e.state != Explanation::Ready);
    explainAction_->setText(e.state == Explanation::NoKey   ? "Set up AI explanations in Settings"
                            : e.state == Explanation::Failed ? "Try again"
                                                             : "What is this? Ask AI");
    explainStatus_->setVisible(working || e.state == Explanation::Failed);
    if (working) explainStatus_->setText("Asking NVIDIA");
    else if (e.state == Explanation::Failed) explainStatus_->setText(e.error);
    explainBox_->setVisible(e.state == Explanation::Ready);
    if (e.state != Explanation::Ready) return;
    what_->setText(e.what);
    why_->setText(e.why);
    why_->setVisible(!e.why.isEmpty());
    risk_->setText(e.risk);
    risk_->setVisible(!e.risk.isEmpty());
    const QString verdict = e.suggestion == "allow" ? "Suggestion: Allow" : e.suggestion == "block" ? "Suggestion: Block"
                                                                                                  : "Suggestion: Your call";
    suggestion_->setText(e.reason.isEmpty() ? verdict : verdict + " · " + e.reason);
    explainFoot_->setText("AI explanation · " + e.model.section('/', -1) + " · it can be wrong and never decides for you");
    // El alto de cada párrafo se fija con la fuente ya aplicada: el recuadro estaba oculto y no se había calculado.
    for (auto *label : {what_, why_, risk_, suggestion_, explainFoot_}) {
        label->ensurePolished();
        label->setFixedHeight(label->heightForWidth(label->width()));
    }
}

void AccessToast::placeOn(QScreen *screen) {
    if (!screen) screen = QGuiApplication::primaryScreen();
    if (!screen) return;
    screen_ = screen;
    adjustSize();
    const QRect area = screen->availableGeometry();
    move(area.right() - width() - Margin, area.bottom() - height() - Margin);
}

void AccessToast::paintEvent(QPaintEvent *) {
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    QPainterPath path;
    path.addRoundedRect(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5), 8, 8);
    QLinearGradient fill(0, 0, 0, height());
    fill.setColorAt(0, QColor("#252323"));
    fill.setColorAt(1, QColor("#202020"));
    painter.fillPath(path, fill);
    painter.setPen(QColor("#363636"));
    painter.drawPath(path);
}

} // namespace Gate
