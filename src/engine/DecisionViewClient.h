#pragma once
#include "../../common/wire_iv.h"
#include "../../controller/session_qt.h"
#include "EngineViewClient.h"
#include "../data/contracts.h"
#include <QElapsedTimer>
#include <QTimer>
#include <set>

namespace Gate {
// Cliente ordinary minor3: sólo status, páginas y observaciones. No verbos de mutación.
class DecisionViewClient final : public QObject {
    Q_OBJECT
  public:
    explicit DecisionViewClient(bool isolatedQa, QObject *parent = nullptr,
                                std::unique_ptr<gb::ipc::ii::SessionChannel> channel = {});
    bool refresh();
    // Copia de presentación: no demuestra vigencia del motor ni de un pendiente.
    std::optional<gb::wire::iv::ServiceContext> serviceContext() const;
    void invalidate();
    void stop();
    bool idle() const { return session_.idle(); }
    bool refreshing() const { return busy_; }
    const EngineStatus &status() const { return status_; }
    quint64 profile() const { return profile_; }
    bool recordsCurrent() const { return status_.current && recordsCurrent_; }
    const auto &pending() const { return pending_; }
    const auto &rules() const { return rules_; }
    const auto &events() const { return events_; }
    bool historyGap() const { return historyGap_; }
    quint8 collector() const { return collector_; }
    std::uint16_t protocolMinor() const { return minor_; }
    void rejectHistory(const QString &reason);
  signals:
    void changed();
    void nativeSourceOpened(const Gate::Data::NativeSourceBinding &binding, quint64 baseline);
    void nativeEvent(const Gate::Data::ActivityEvent &event);
    void nativeGap(const Gate::Data::NativeSourceBinding &binding, quint64 after, quint64 resync,
                   quint64 revision, quint8 reason, bool lostKnown, quint64 lost);
    void nativeSourceLost(const Gate::Data::NativeSourceBinding &binding, const QString &reason);

  private:
    void opened(bool ok, gb::wire::Frame frame);
    void received(bool ok, gb::wire::Frame frame, gb::wire::Id correlation);
    void observation(gb::wire::Frame frame);
    void fail(const QString &reason);
    void statusOnly();
    bool adoptStatus(const gb::wire::Frame &frame);
    bool send(gb::wire::Type type);
    void startPages(bool rules);
    void page(const gb::wire::Frame &frame);
    void endNativeSource(const QString &reason);
    std::optional<Data::NativeSourceBinding> nativeBinding(const gb::wire::Frame &frame) const;
    bool blocked_;
    gb::controller::Session session_;
    EngineStatus status_;
    std::optional<gb::wire::iv::ServiceContext> serviceContext_;
    std::shared_ptr<const gb::ipc::ii::ReadPeerLease> readPeer_;
    std::optional<Data::NativeSourceBinding> nativeSource_;
    QTimer poll_;
    QElapsedTimer pageAge_;
    bool stopping_ = false, connected_ = false, busy_ = false;
    bool recordsCurrent_ = false, historyGap_ = true, subscribed_ = false;
    bool observationUpdateQueued_ = false;
    quint64 profile_ = 0, lastEvent_ = 0, pageRevision_ = 0;
    quint8 collector_ = 0;
    std::uint16_t minor_ = 1;
    gb::wire::Id expected_{}, snapshot_{};
    gb::wire::Type expectedType_ = gb::wire::Type::GetStatus;
    quint32 cursor_ = 0;
    std::set<gb::wire::Id> ids_;
    std::vector<gb::wire::ii::PendingRecord> pending_, pendingDraft_;
    std::vector<gb::wire::ii::RuleRecord> rules_, rulesDraft_;
    std::vector<gb::wire::Frame> events_;
};
} // namespace Gate
