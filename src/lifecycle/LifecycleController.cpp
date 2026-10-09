#include "LifecycleController.h"
#include <QAction>
#include <QCloseEvent>
#include <QLocale>
#include <QMenu>
#include <QSystemTrayIcon>
#include <QWidget>

namespace Gate::Lifecycle {
namespace {
class NativeTraySurface final : public TraySurface {
  public:
    NativeTraySurface() {
        connect(&tray_, &QSystemTrayIcon::activated, this,
                [this](QSystemTrayIcon::ActivationReason reason) {
            if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick)
                emit openRequested();
        });
    }
    bool available() const override { return QSystemTrayIcon::isSystemTrayAvailable(); }
    bool visible() const override { return tray_.isVisible() && !tray_.icon().isNull(); }
    void setMenu(QMenu *menu) override { tray_.setContextMenu(menu); }
    void setIcon(const QIcon &icon) override { tray_.setIcon(icon); }
    void setToolTip(const QString &text) override { tray_.setToolTip(text); }
    void show() override { if (available() && !tray_.icon().isNull()) tray_.show(); }
    void hide() override { tray_.hide(); }
  private:
    QSystemTrayIcon tray_;
};
} // namespace
std::unique_ptr<TraySurface> makeNativeTraySurface() {
    return std::make_unique<NativeTraySurface>();
}

LifecycleController::LifecycleController(QWidget *window, std::unique_ptr<TraySurface> tray,
                                         const QIcon &icon, QObject *parent)
    : QObject(parent), window_(window), tray_(std::move(tray)), menu_(std::make_unique<QMenu>()) {
    menu_->setObjectName(QStringLiteral("lifecycleTrayMenu"));
    status_ = menu_->addAction(QString{});
    status_->setObjectName(QStringLiteral("trayEngineStatus"));
    status_->setEnabled(false);
    menu_->addSeparator();
    auto *open = menu_->addAction(tr("Open"));
    open->setObjectName(QStringLiteral("trayOpen"));
    pending_ = menu_->addAction(tr("Pending"));
    pending_->setObjectName(QStringLiteral("trayPending"));
    auto *settings = menu_->addAction(tr("Settings"));
    settings->setObjectName(QStringLiteral("traySettings"));
    menu_->addSeparator();
    auto *quit = menu_->addAction(tr("Quit"));
    quit->setObjectName(QStringLiteral("trayQuit"));
    connect(open, &QAction::triggered, this, &LifecycleController::openWindow);
    connect(pending_, &QAction::triggered, this, [this] {
        if (!finished_) { openWindow(); emit pendingRequested(); }
    });
    connect(settings, &QAction::triggered, this, [this] {
        if (!finished_) { openWindow(); emit settingsRequested(); }
    });
    connect(quit, &QAction::triggered, this, &LifecycleController::requestQuit);
    if (tray_) {
        tray_->setMenu(menu_.get());
        tray_->setIcon(icon);
        connect(tray_.get(), &TraySurface::openRequested, this, &LifecycleController::openWindow);
    }
    if (window_) {
        window_->installEventFilter(this);
        // QWidget emite destroyed antes de borrar children; QPointer se limpia
        // después, en QObject. No mostrar un owner que ya está en su destructor.
        connect(window_.data(), &QObject::destroyed, this, [this] {
            window_.clear();
            hiddenByController_ = false;
            availabilityTimer_.stop();
        }, Qt::DirectConnection);
    }
    availabilityTimer_.setInterval(1000);
    connect(&availabilityTimer_, &QTimer::timeout, this, &LifecycleController::refreshAvailability);
    updatePresentation();
}
LifecycleController::~LifecycleController() {
    if (window_) window_->removeEventFilter(this);
    // No dejar una ventana oculta si el dueño retira esta fachada antes de salir.
    if (window_ && hiddenByController_ && !finished_) window_->showNormal();
    if (tray_) { tray_->hide(); tray_->setMenu(nullptr); }
}
bool LifecycleController::recoverableTray() const {
    return started_ && !finished_ && tray_ && tray_->available() && tray_->visible();
}
void LifecycleController::start(bool startMinimized) {
    if (finished_ || started_) return;
    started_ = true;
    if (tray_) tray_->show();
    availabilityTimer_.start();
    if (window_ && startMinimized && recoverableTray()) {
        window_->hide();
        hiddenByController_ = true;
    } else if (window_) {
        window_->showNormal();
    }
}
void LifecycleController::refreshAvailability() {
    if (!started_ || finished_) return;
    if (tray_ && tray_->available() && !tray_->visible()) tray_->show();
    if (hiddenByController_ && !recoverableTray() && window_) {
        hiddenByController_ = false;
        // Recuperar accesibilidad no requiere quitarle el foco a otra aplicación.
        window_->showNormal();
    }
}
void LifecycleController::openWindow() {
    if (!window_ || finished_) return;
    hiddenByController_ = false;
    window_->showNormal();
    window_->raise();
    window_->activateWindow();
}
void LifecycleController::requestQuit() {
    if (finished_ || quitPending_) return;
    quitPending_ = true;
    // El receptor drena sólo recursos GUI y confirma finishGuiShutdown().
    emit quitRequested();
}
void LifecycleController::cancelQuit() {
    if (finished_) return;
    quitPending_ = false;
    refreshAvailability();
}
void LifecycleController::finishGuiShutdown() {
    if (!quitPending_ || finished_) return;
    finished_ = true;
    availabilityTimer_.stop();
    if (tray_) tray_->hide();
    if (window_) window_->removeEventFilter(this);
}
bool LifecycleController::eventFilter(QObject *object, QEvent *event) {
    if (object != window_ || event->type() != QEvent::Close || finished_)
        return QObject::eventFilter(object, event);
    static_cast<QCloseEvent *>(event)->ignore();
    if (recoverableTray() && !quitPending_) {
        window_->hide();
        hiddenByController_ = true;
    } else {
        // Sin bandeja, Close solicita salida pero mantiene la ventana mientras drena.
        openWindow();
        requestQuit();
    }
    return true;
}
void LifecycleController::applyEngineSnapshot(const EngineSnapshot &snapshot) {
    snapshot_ = snapshot;
    updatePresentation();
}
QString LifecycleController::statusText() const {
    if (!snapshot_.current) return tr("Engine unavailable");
    if (snapshot_.simulation) return tr("Simulation: no traffic filtering");
    switch (snapshot_.state) {
    case EngineState::Active: return tr("Engine reports active");
    case EngineState::Degraded: return tr("Engine degraded");
    case EngineState::Unavailable: return tr("Engine unavailable");
    }
    return tr("Engine unavailable");
}
void LifecycleController::updatePresentation() {
    status_->setText(statusText());
    // El contador es una lectura; cerrar o navegar nunca modifica el DTO.
    pending_->setText(tr("Pending (%1)").arg(QLocale().toString(snapshot_.pendingCount)));
    if (tray_) tray_->setToolTip(tr("LGA GateBouncer\n%1\n%2 pending requests")
                                   .arg(statusText(), QLocale().toString(snapshot_.pendingCount)));
}
} // namespace Gate::Lifecycle
