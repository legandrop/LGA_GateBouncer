#pragma once
#include "review_ingress.h"
#include "review_state.h"
#include "session_qt.h"
#include <QAbstractNativeEventFilter>
#include <QTimer>
#include <QWidget>
#include <condition_variable>
#include <map>
class QLabel;
class QListWidget;
class QPushButton;
class QCheckBox;
class QComboBox;
namespace gb::controller {
class ReviewWindow : public QWidget, public QAbstractNativeEventFilter {
    Q_OBJECT
  public:
    explicit ReviewWindow(std::filesystem::path protectedRoot, QWidget *parent = nullptr,
                          std::unique_ptr<ipc::ii::SessionChannel> channel = {});
    ~ReviewWindow() override;
    void startLive();
    bool nativeEventFilter(const QByteArray &type, void *message, qintptr *result) override;
    bool eventFilter(QObject *watched, QEvent *event) override;

  protected:
    void closeEvent(QCloseEvent *event) override;

  private:
    friend struct ReviewProbe;
    void status(const wire::Frame &frame);
    void reply(bool authenticated, const wire::Frame &frame, wire::Id correlation);
    void list();
    void select();
    void choice();
    void fence();
    void poll();
    void invalidate(const QString &reason);
    struct OpenWait {
        OpenReference reference;
        std::mutex mutex;
        std::condition_variable changed;
        bool done = false, cancelled = false;
        wire::Error error = wire::Error::Timeout;
    };
    wire::Error ingress(OpenReference reference);
    void answerOpen(const std::shared_ptr<OpenWait> &wait, wire::Error error);
    void beginIngress();
    std::filesystem::path root_;
    Session session_;
    ReviewState review_;
    QLabel *state_ = nullptr, *identity_ = nullptr, *queued_ = nullptr;
    QListWidget *rows_ = nullptr;
    QPushButton *reviewButton_ = nullptr, *confirm_ = nullptr, *connect_ = nullptr;
    QCheckBox *both_ = nullptr, *remember_ = nullptr;
    QComboBox *action_ = nullptr;
    QTimer timer_;
    wire::Id epoch_{}, boot_{}, selectCorrelation_{}, command_{}, listSnapshot_{};
    std::uint64_t profile_ = 0;
    DWORD cutoff_ = 0;
    bool barrier_ = true, armed_ = false, closing_ = false, authenticated_ = false,
         loading_ = false;
    std::optional<Binding> pressBinding_;
    std::vector<wire::ii::PendingRecord> pending_, pageRows_;
    std::uint32_t cursor_ = 0;
    std::unique_ptr<ReviewIngress> ingress_;
    std::map<wire::Id, std::shared_ptr<OpenWait>> opens_;
};
} // namespace gb::controller
