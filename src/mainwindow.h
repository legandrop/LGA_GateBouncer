#pragma once
#include "simulation.h"
#include "productcontroller.h"
#include <QMainWindow>
#include <QPointer>

class QVBoxLayout;
class QHBoxLayout;
class QLabel;
class QFrame;
class QTableView;
class QComboBox;
class QLineEdit;
class QPushButton;

namespace Gate {
class RowsModel;
class MainWindow final : public QMainWindow {
    Q_OBJECT
  public:
    explicit MainWindow(QWidget *parent = nullptr, bool isolatedQa = false, const QString &qaRoot = {});
    ProductController *product() { return &product_; }
    void setMode(UiMode mode);
    Simulation *simulation() { return &model_; }
    Explanation *explanation() { return &explanation_; }
    QString view() const { return view_; }
    void selectView(const QString &view);
    void openRequest(const QString &id);
    void openDetail(const QString &id);

  protected:
    void closeEvent(QCloseEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;
    bool eventFilter(QObject *object, QEvent *event) override;

  private:
    void buildShell();
    void buildPage();
    void refresh();
    void refreshTable(bool newPage = false);
    void renderProcesses();
    void renderPending();
    void renderActivity();
    void renderRules();
    void renderImport();
    void renderSettings();
    void renderLive();
    void renderLiveDetail(const QString &id);
    void reviewCandidate(const QString &id, bool draft = false);
    void restoreFocus();
    void modeSelector(QVBoxLayout *layout);
    void saveViewState();
    void restoreViewState();
    void renderNotice();
    void positionOverlays();
    void edit(const QString &id, bool candidate = false);
    void cleanup();
    void about();
    QVBoxLayout *modal(const QString &title);
    void closeModal();
    void message(const QString &text);
    QTableView *makeTable(const QStringList &headers, const QVector<int> &widths,
                          int rowHeight = 36);
    void tableAction(const QModelIndex &index);
    Simulation model_;
    Explanation explanation_;
    ProductController product_;
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
    QPointer<QWidget> modalPanel_;
    QPointer<QWidget> previousFocus_;
    bool refreshing_ = false;
    int cleanupDays_ = 180;
    QPoint dragStart_;
};
} // namespace Gate
