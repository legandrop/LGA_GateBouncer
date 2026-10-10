#pragma once
#include "../../common/wire_iv.h"
#include "../../controller/ordinary_qt.h"
#include <QElapsedTimer>
#include <QTimer>
#include <QByteArray>
#include <set>
#include <map>
#include <tuple>
#include "../platform/ProcessCatalog.h"
namespace Gate {
class OrdinaryDecisionClient final : public QObject {
    Q_OBJECT
  public:
    enum class State { Closed, Loading, Preparing, Ready, Sending, Uncertain, Recorded, Failed };
    // Copia de presentación del comando enviado; nunca admite otra decisión.
    struct SubmittedPresentation {
        gb::wire::Frame command;
        gb::wire::iv::Display display;
        gb::wire::Id boot{}, observed{};
        quint64 observedRevision = 0, bindingGeneration = 0;
    };
    // Copia observacional; no concede autoridad ni acredita tráfico o permisos actuales.
    struct ObservationContext {
        gb::wire::iv::ServiceContext service;
        gb::wire::Id connection{};
        quint64 profile = 0, desired = 0, selection = 0, observedRevision = 0;
    };
    std::optional<ObservationContext> observationContext() const;
    explicit OrdinaryDecisionClient(bool isolatedQa, QObject *parent = nullptr,
                                    std::unique_ptr<gb::ipc::ii::SessionChannel> channel = {}, bool administrative = false);
    bool administrative() const { return administrative_; }
    void rejectHistory(const QString &reason);
    const auto &selectedPrincipalSid() const { return selectedSid_; }
    const auto &selectedOriginalTarget() const { return selectedTarget_; }
    void pauseAutomatic();
    bool refresh();
    bool refreshRules();
    // La selección procede de la página original vigente; el archivo no admite la operación.
    bool revokeRule(const gb::wire::Id &rule, quint64 selection, bool consent);
    bool rulesCurrent() const { return rulesCurrent_; }
    const auto &rules() const { return rules_; }
    std::optional<QByteArray> selectedRuleBackup(const std::vector<gb::wire::Id> &, quint64 selection) const;
    void startAutomatic();
    // Sólo una señal de lectura; no aporta identidad ni autoridad a la revisión.
    void observationChanged();
    bool select(const gb::wire::Id &observed);
    bool direction(int direction);
    bool scope(int scope);
    void closeNotice();
    bool decide(bool allow, bool consent, quint64 selection);
    bool recover();
    void stop();
    void invalidate();
    bool idle() const { return session_.idle(); }
    bool current() const { return current_; }
    bool visible() const { return visible_; }
    bool ready() const;
    quint64 selection() const { return generation_; }
    State state() const { return state_; }
    int selectedDirection() const { return direction_; }
    int selectedScope() const { return scope_; }
    const QString &message() const { return message_; }
    const auto &observations() const { return rows_; }
    const auto &observed() const { return observed_; }
    const auto &draft() const { return draft_; }
    const auto &fileDraft() const { return fileDraft_; }
    const SubmittedPresentation *submitted() const {
        return submitted_ && submitted_->command.correlation == command_ ? &*submitted_ : nullptr;
    }
    gb::wire::Id command() const { return command_; }
  signals:
    void changed();
    void nativeSourceOpened(const Gate::Data::NativeSourceBinding &binding, quint64 baseline);
    void nativeEvent(const Gate::Data::ActivityEvent &event);
    void nativeGap(const Gate::Data::NativeSourceBinding &binding, quint64 after, quint64 resync,
                   quint64 revision, quint8 reason, bool lostKnown, quint64 lost);
    void nativeSourceLost(const Gate::Data::NativeSourceBinding &binding, const QString &reason);
  private:
    friend class ProductController;
    bool prepareFile(std::shared_ptr<Data::SelectedApplicationFile>, int direction,
                     const gb::wire::Bytes &expectedTarget, const std::optional<gb::wire::Id> &editing,
                     quint64 selection);
    bool decideFile(bool allow, bool consent, quint64 selection);
    bool commitDraft(bool allow, bool consent, quint64 selection);
    void submitFilePreparation();
    void opened(bool ok, gb::wire::Frame hello);
    void received(bool ok, gb::wire::Frame reply, gb::wire::Id correlation, quint64 generation);
    bool status(const gb::wire::Frame &, bool same);
    bool send(gb::wire::Type, std::vector<gb::wire::Field> fields = {});
    void page();
    void rulePage();
    void submitRevocation();
    void prepare();
    void outcome(const gb::wire::Frame &);
    void fail(const QString &, bool uncertain = false);
    void showNext();
    void automaticRead();
    std::optional<Data::NativeSourceBinding> nativeBinding(const gb::wire::Frame &) const;
    void observation(gb::wire::Frame);
    void streamRead();
    void endNativeSource(const QString &reason);
    gb::controller::OrdinarySession session_;
    const bool administrative_;
    gb::wire::Bytes selectedSid_, selectedTarget_;
    State state_ = State::Closed;
    bool stopping_ = false, connected_ = false, current_ = false, visible_ = false;
    bool finalStatus_ = false, checkOnly_ = false;
    bool readingRules_ = false, rulesCurrent_ = false;
    bool backgroundRead_ = false;
    bool checkingObservation_ = false;
    bool checkingObservationAfter_ = false;
    int quietPollMs_ = 2000;
    quint64 generation_ = 1, desired_ = 0, profile_ = 0, bindingGeneration_ = 0, pageRevision_ = 0;
    quint64 observedGeneration_ = 0;
    int direction_ = 1;
    int scope_ = 2;
    quint32 cursor_ = 0;
    std::size_t rulePageBytes_ = 0;
    gb::wire::Id epoch_{}, boot_{}, source_{}, connection_{}, snapshot_{}, expected_{}, command_{};
    gb::wire::Type expectedType_ = gb::wire::Type::GetStatus;
    std::vector<gb::wire::iv::ObservedRecord> rows_, pageRows_;
    std::vector<gb::wire::iv::PrincipalRuleRecord> rules_, rulePageRows_;
    std::optional<gb::wire::iv::PrincipalRuleRecord> revocation_;
    std::set<gb::wire::Id> ids_;
    std::optional<gb::wire::iv::ObservedRecord> observed_;
    std::optional<gb::wire::iv::FutureDraftRecord> draft_;
    std::optional<gb::wire::iv::FileFutureDraftRecord> fileDraft_;
    std::optional<gb::wire::iv::PrincipalRuleRecord> editing_;
    std::shared_ptr<Data::SelectedApplicationFile> fileOwner_;
    gb::wire::Bytes expectedFileTarget_;
    quint64 capabilities_ = 0;
    std::optional<SubmittedPresentation> submitted_;
    QElapsedTimer pageAge_, draftAge_;
    QElapsedTimer streamStatusAge_;
    QTimer draftExpiry_;
    QTimer poll_;
    QTimer streamPoll_;
    std::optional<Data::NativeSourceBinding> nativeSource_;
    quint64 lastEvent_ = 0, requestedAfter_ = 0;
    quint8 nativeMask_ = 3, requestedMask_ = 3;
    int streamPollMs_ = 100;
    bool subscribed_ = false, requestOutstanding_ = false;
    bool initialSubscription_ = false, streamStatus_ = false;
    bool automatic_ = false;
    using ShownKey = std::tuple<gb::wire::Id, gb::wire::Id, gb::wire::Id, quint64, quint64>;
    std::map<gb::wire::Id, ShownKey> shown_;
    QString message_;
};
}
