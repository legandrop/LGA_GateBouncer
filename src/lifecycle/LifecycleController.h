#pragma once
#include <QIcon>
#include <QObject>
#include <QPointer>
#include <QTimer>
#include <memory>

class QAction;
class QMenu;
class QWidget;

namespace Gate::Lifecycle {
enum class EngineState { Unavailable, Degraded, Active };
// Sólo el adaptador de un canal autenticado vigente puede proveer este DTO.
// La UI no deriva estado de protección a partir de la existencia del proceso.
struct EngineSnapshot {
    bool current = false;
    EngineState state = EngineState::Unavailable;
    bool simulation = true;
    quint64 pendingCount = 0;
};

class TraySurface : public QObject {
    Q_OBJECT
  public:
    using QObject::QObject;
    virtual bool available() const = 0;
    virtual bool visible() const = 0;
    virtual void setMenu(QMenu *menu) = 0;
    virtual void setIcon(const QIcon &icon) = 0;
    virtual void setToolTip(const QString &text) = 0;
    virtual void show() = 0;
    virtual void hide() = 0;
  signals:
    void openRequested();
};
// Construir no publica un icono. start() del controlador lo publica explícitamente.
std::unique_ptr<TraySurface> makeNativeTraySurface();

class LifecycleController final : public QObject {
    Q_OBJECT
  public:
    LifecycleController(QWidget *window, std::unique_ptr<TraySurface> tray,
                        const QIcon &icon, QObject *parent = nullptr);
    ~LifecycleController() override;
    void start(bool startMinimized);
    void applyEngineSnapshot(const EngineSnapshot &snapshot);
    void refreshAvailability();
    void openWindow();
    void requestQuit();
    void cancelQuit();
    // Llamar después del cierre asíncrono de clientes GUI; no toca el servicio.
    // El dueño llama QApplication::quit() luego, desde su punto de composición.
    void finishGuiShutdown();
    bool recoverableTray() const;
    bool quitPending() const { return quitPending_; }
    QMenu *menu() const { return menu_.get(); }
    QString statusText() const;
  signals:
    void pendingRequested();
    void settingsRequested();
    void quitRequested();
  protected:
    bool eventFilter(QObject *object, QEvent *event) override;
  private:
    void updatePresentation();
    QPointer<QWidget> window_;
    std::unique_ptr<TraySurface> tray_;
    std::unique_ptr<QMenu> menu_;
    QAction *status_ = nullptr;
    QAction *pending_ = nullptr;
    QTimer availabilityTimer_;
    EngineSnapshot snapshot_;
    bool started_ = false;
    bool hiddenByController_ = false;
    bool quitPending_ = false;
    bool finished_ = false;
};
} // namespace Gate::Lifecycle
