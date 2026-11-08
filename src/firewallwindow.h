#pragma once
// Ventana del firewall sin driver (GateBouncerEngine.exe): Protection, Requests, Apps, Activity y Settings, con el
// lenguaje visual de las apps LGA (barra lateral con el estado de cada sección, tarjetas). Todo lo que muestra sale del
// canal del motor (FirewallClient); nunca filtra nada por sí misma. La ventana vieja (MainWindow) queda para el
// simulador y el enfoque con driver, pausado.
#include "accesstoast.h"
#include "engine/FirewallClient.h"
#include "engine/NetLimiterRules.h"
#include "explain/Explainer.h"
#include "lifecycle/LifecycleController.h"
#include <lgaupdate/LgaUpdateService.h>
#include <QHash>
#include <QMainWindow>
#include <QPointer>
#include <QSet>
#include <QTimer>
#include <functional>
#include <memory>

class QLabel;
class QLineEdit;
class QScrollArea;
class QVBoxLayout;
class QHBoxLayout;
class QFrame;
class QTableWidget;
class QAbstractButton;

namespace Gate {

class SideItem;
class Desk;

class FirewallWindow final : public QMainWindow {
    Q_OBJECT
  public:
    explicit FirewallWindow(QWidget *parent = nullptr);
    ~FirewallWindow() override;
    // overview, requests, apps, activity, settings, import, o detail:<clave de la app>.
    QString view() const { return view_; }
    void selectView(const QString &view);
    // Muestra la ventana aunque esté oculta en la bandeja (aviso, segunda instancia).
    void bringToFront();
    // Sólo QA: el aviso fijo actual, para capturarlo.
    AccessToast *accessToast() const { return toast_; }
    void startLifecycle(std::unique_ptr<Lifecycle::TraySurface> tray, bool minimized);

  protected:
    bool eventFilter(QObject *object, QEvent *event) override;
    void showEvent(QShowEvent *event) override;
    void hideEvent(QHideEvent *event) override;
    bool nativeEvent(const QByteArray &eventType, void *message, qintptr *result) override;

  private:
    // Lo elegido en los desplegables de un pedido en Requests: se conserva aunque la página se rearme.
    struct Choice {
        QString scope, duration = "always", target;
        bool set = false;
    };
    // Una app en Apps: su regla de app entera o sus reglas por destino (cada destino es una regla del motor).
    struct AppEntry {
        QString key, title, subtitle, iconPath, scope, signer, path;
        QVector<FirewallClient::RuleItem> rules;
        bool perServer = false;
    };

    void buildShell();
    void render(bool keepScroll = false);
    void engineChanged();
    QString pageKey() const;
    void updateSidebar();
    void updateLifecycle();
    void requestQuit();
    void finishQuit();
    // Salir de la app por el camino de la bandeja (el mismo que «Salir» del menú), para que el cierre no lo frene el
    // filtro que esconde la ventana: relanzar por zoom o idioma, y cerrar para instalar una actualización.
    void quitApp();
    void message(const QString &text);
    QWidget *how(const QStringList &steps, const QString &note = {});
    void setHowOpen(bool open);
    // «Trust a folder»: una regla por carpeta, con la carpeta y el nombre del exe (vacío: todos) ya propuestos. Valida
    // mientras se escribe con la misma regla del motor, que igual la vuelve a validar al crearla.
    void trustFolderDialog(const QString &folder, const QString &name);

    QWidget *overviewPage();
    QWidget *requestsPage();
    QWidget *appsPage();
    void fillApps();
    QWidget *detailPage(const QString &key);
    QWidget *activityPage();
    QWidget *settingsPage();
    // Tarjeta App de Settings: buscar actualizaciones al iniciar, idioma y zoom (como General de Mighty Tools).
    QWidget *appCard();
    // Zoom e idioma se aplican al arrancar: guarda lo elegido, abre una ventana nueva y cierra esta.
    void relaunchWindow();
    // Actualizaciones (lgaupdate): chequeo al iniciar y cada 3 h si está activado, y «Check now» de Settings.
    void setupUpdates();
    static int updateDialog(QWidget *parent, const LgaUpdateDialogSpec &spec);
    QPointer<LgaUpdateService> updates_;
    QWidget *importPage();
    QWidget *requestCard(const FirewallClient::PendingItem &p, bool expanded);
    QWidget *aiCard(const FirewallClient::PendingItem &p);

    QVector<AppEntry> appEntries() const;
    QStringList runningWithoutRule() const;
    void refreshRunning();
    bool canDecide() const;
    void decideDefault(const FirewallClient::PendingItem &p, bool allow);
    // Estado de la explicación de un pedido, sin pedirla.
    AccessToast::Explanation explanationFor(const QString &id) const;
    void explain(const QString &id, bool automatic);
    QString launchedBy(const FirewallClient::PendingItem &p);

    void updateToast();
    void closeToast();

    FirewallClient firewall_;
    Explain::Explainer explainer_;
    QPointer<Lifecycle::LifecycleController> lifecycle_;
    QPointer<AccessToast> toast_;
    QHash<QString, QString> explainErrors_; // id en minúsculas -> último error
    QHash<QString, QString> launchers_;     // id en minúsculas -> programas que lanzaron a la app
    QHash<QString, Choice> choices_;        // id en minúsculas -> lo elegido en Requests
    QSet<QString> dismissed_;               // pedidos cerrados con ×: siguen pendientes, sin aviso
    QString view_ = "overview", expanded_, lastKey_;
    QString appsQuery_, appsFilter_ = "all", activityFilter_ = "blocked";
    QStringList running_; // exes de esta sesión de Windows, por ruta
    QTimer runningTimer_;
    QTimer refreshLater_;
    qint64 armedAt_ = 0; // antes de este instante, los Allow/Block de la página no deciden
    bool armed() const;
    int explainVersion_ = 0;
    QHash<QString, int> scroll_;
    QHash<QString, int> tableScroll_; // desplazamiento de la tabla de cada vista, entre rearmados
    QVector<NetLimiterRule> netLimiterRules_;
    QString netLimiterFile_;
    bool closing_ = false;
    bool shownOnce_ = false, frameApplied_ = false; // marco nativo: bordes para estirar, sombra, acomodo

    QWidget *workspace_ = nullptr;
    QScrollArea *scroll_area_ = nullptr;
    QFrame *message_ = nullptr;
    QLabel *messageText_ = nullptr;
    QTimer messageTimer_;
    QTableWidget *appsTable_ = nullptr;
    QLabel *appsTip_ = nullptr;
    QWidget *appsSeg_ = nullptr;
    QHash<QString, SideItem *> side_;
    Desk *desk_ = nullptr;
    QPointer<QAbstractButton> helpButton_; // el «?» de la barra: marcado mientras How it works está abierta
    bool howOpen_ = false;
};

} // namespace Gate
