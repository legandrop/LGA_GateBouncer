#pragma once
#include "simulation.h"
#include "productcontroller.h"
#include "lifecycle/LifecycleController.h"
#include "lifecycle/StartupPreference.h"
#include "engine/ReviewGateway.h"
#include "engine/FirewallClient.h"
#include "engine/NetLimiterRules.h"
#include "accesstoast.h"
#include "explain/Explainer.h"
#include <QMainWindow>
#include <QPointer>
#include <QSet>
#include "assistance/ui/GeneralSession.h"
#include "assistance/ui/GeneralConnection.h"

class QVBoxLayout;
class QHBoxLayout;
class QLabel;
class QFrame;
class QTableView;
class QComboBox;
class QLineEdit;
class QPushButton;

namespace Gate {
namespace Assistance::Ui { class ExplanationWidget; }
class RowsModel;
class MainWindow final : public QMainWindow {
    Q_OBJECT
  public:
    explicit MainWindow(QWidget *parent = nullptr, bool isolatedQa = false, const QString &qaRoot = {},
                        std::unique_ptr<gb::ipc::ii::SessionChannel> decisionChannel = {},
                        std::unique_ptr<ReviewBackend> reviewer = {},
                        std::unique_ptr<gb::ipc::ii::SessionChannel> ordinaryChannel = {});
    ~MainWindow() override;
    ProductController *product() { return &product_; }
    void setMode(UiMode mode);
    Simulation *simulation() { return &model_; }
    Explanation *explanation() { return &explanation_; }
    QString view() const { return view_; }
    void selectView(const QString &view);
    // Muestra la ventana aunque esté oculta en la bandeja (aviso, segunda instancia).
    void bringToFront();
    // Sólo QA: el aviso fijo actual, para capturarlo.
    AccessToast *accessToast() const { return firewallToast_; }
    void openRequest(const QString &id);
    void openDetail(const QString &id);
    void startLifecycle(std::unique_ptr<Lifecycle::TraySurface> tray, bool minimized,
                        std::unique_ptr<Lifecycle::StartupPreference> startup = {});
    Lifecycle::LifecycleController *lifecycle() const { return lifecycle_; }
    void requestGuiShutdown();
    bool guiDrained() const { return closing_ && product_.idle() && reviewer_.idle() && (!assistanceConnection_ || assistanceConnection_->idle()); }
    ReviewGateway *reviewer() { return &reviewer_; }
    void setAssistance(std::unique_ptr<Assistance::Ui::GeneralSession> session);
    Assistance::Ui::GeneralSession* assistance() const {return assistance_.get();}
    void enableNativeAssistance();
  signals:
    void assistanceConnectRequested();

  protected:
    void closeEvent(QCloseEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;
    bool eventFilter(QObject *object, QEvent *event) override;

  private:
    void buildShell();
    void buildPage();
    void refresh();
    void updatePageState();
    void refreshTable(bool newPage = false);
    void renderProcesses();
    void renderPending();
    void renderActivity();
    void renderRules();
    void renderImport();
    void renderSettings();
    void renderLive();
    void reviewSourceSelector();
    void renderLiveDetail(const QString &id);
    void reviewCandidate(const QString &id, bool draft = false);
    void prepareImportedRule(const QString &id);
    void restoreFocus();
    void modeSelector(QVBoxLayout *layout);
    void saveViewState();
    void restoreViewState();
    void renderNotice();
    void renderOrdinaryNotice();
    void positionOverlays();
    void edit(const QString &id, bool candidate = false);
    void cleanup();
    void reviewOlderLiveRules();
    void cleanupLiveRule(const QString &ruleId = {}, quint64 selection = 0);
    void prepareFileRules(const QStringList &candidates = {}, const std::optional<gb::wire::Id> &editing = {}, int backupIndex = -1);
    void editSelectedFileRule();
    void backupSelectedFileRules();
    void openRuleBackup();
    void prepareSelectedSourceFiles();
    void about();
    void updateLifecycle();
    void openEngineRequest(const QString &rowId);
    // Motor sin driver: Processes, Pending, Activity y Rules en modo Live.
    bool firewallView() const;
    void renderFirewall();
    void openFirewallRequest(const QString &path);
    // Aviso fijo de escritorio (AccessToast): uno por vez, el pendiente más viejo que no se cerró.
    void updateFirewallToast();
    // Explicación con IA de la app del aviso: sólo ayuda, nunca decide. automatic: pedida al aparecer el aviso.
    void explainFirewallRequest(const QString &path, bool automatic);
    void buildFirewallSettings(QVBoxLayout *layout);
    // Import de reglas de NetLimiter al motor sin driver.
    void buildFirewallImport();
    void editFirewallRule(const QString &id);
    void onNewFirewallPending(const QString &path);
    void finishShutdownWhenIdle();
    enum class ModalOwner { General, Simulation, Live, ImportedDraft, ImportedReview, ImportedActivation, FileRule, FileBackup };
    QVBoxLayout *modal(const QString &title, ModalOwner owner = ModalOwner::General);
    void closeStaleModal();
    void closeModal();
    void message(const QString &text);
    QTableView *makeTable(const QStringList &headers, const QVector<int> &widths,
                          int rowHeight = 36);
    void tableAction(const QModelIndex &index);
    Simulation model_;
    Explanation explanation_;
    std::unique_ptr<Assistance::Ui::GeneralSession> assistance_;
    std::unique_ptr<Assistance::Ui::GeneralConnection> assistanceConnection_;
    ProductController product_;
    ReviewGateway reviewer_;
    QPointer<Lifecycle::LifecycleController> lifecycle_;
    std::unique_ptr<Lifecycle::StartupPreference> startup_;
    Lifecycle::StartupResult startupResult_{Lifecycle::StartupState::Error,
                                          "Startup registration has not been inspected"};
    struct ViewState {
        QString selectedId, focusName, query, activityQuery, policy = "All", running = "All", event = "All";
        int sortColumn = 0, currentColumn = 0, scroll = 0;
        Qt::SortOrder order = Qt::AscendingOrder;
    };
    QMap<QString, ViewState> viewStates_;
    QString stateKey() const;
    bool restoringState_ = false;
    bool closing_ = false;
    QString view_ = "processes", selected_;
    QString query_, activityQuery_, policyFilter_ = "All", runningFilter_ = "All",
                                    eventFilter_ = "All";
    QWidget *root_ = nullptr, *workspace_ = nullptr, *page_ = nullptr;
    QFrame *sidebar_ = nullptr;
    QVBoxLayout *workspaceLayout_ = nullptr, *pageLayout_ = nullptr;
    QLabel *title_ = nullptr, *subtitle_ = nullptr, *status_ = nullptr, *sideStatus_ = nullptr,
           *footer_ = nullptr, *pendingCount_ = nullptr;
    QMap<QString, QPushButton *> navigation_;
    QPointer<QTableView> table_;
    QPointer<RowsModel> rows_;
    QPointer<QLabel> count_;
    QPointer<QLabel> emptyState_;
    QPointer<QFrame> detail_, notice_, modalOverlay_, message_;
    FirewallClient firewall_;
    QPointer<AccessToast> firewallToast_;
    Explain::Explainer explainer_;
    QHash<QString, QString> explainErrors_; // ruta en minúsculas -> último error de explicación
    QVector<NetLimiterRule> netLimiterRules_;
    QString netLimiterFile_;
    QSet<QString> dismissedRequests_; // rutas en minúsculas cerradas con ×: siguen pendientes, sin aviso
    QString preferredRequest_;        // la que se pidió ver desde Pending
    QByteArray ordinaryNoticeKey_;
    QByteArray tableSourceKey_;
    QPointer<Assistance::Ui::ExplanationWidget> ordinaryExplanation_;
    QPointer<QWidget> modalPanel_;
    QPointer<QWidget> previousFocus_;
    ModalOwner modalOwner_ = ModalOwner::General;
    QString modalDigest_;
    quint64 modalGeneration_ = 0, modalRevision_ = 0;
    bool refreshing_ = false;
    int cleanupDays_ = 180;
    QPoint dragStart_;
};
} // namespace Gate
