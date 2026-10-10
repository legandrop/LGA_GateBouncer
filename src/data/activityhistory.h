#pragma once
#include "contracts.h"

namespace Gate::Data {
class ActivityHistory final {
  public:
    explicit ActivityHistory(int eventLimit = 4096, int stagingLimit = 4096);
    bool addSyntheticSource(const QString &id, const QString &epoch, const QString &scope);
    bool addNativeSource(const NativeSourceBinding &binding, quint64 baseline);
    bool nativeGap(const NativeSourceBinding &binding, quint64 after, quint64 resync,
                   quint64 revision, quint8 reason, bool lostKnown, quint64 lost);
    void disconnectNative(const NativeSourceBinding &binding, const QString &reason);
    bool ingest(const ActivityEvent &event);
    const HistoryState &state() const { return state_; }
    bool restore(const HistoryState &state);
    void gap(const QString &sourceId, const QString &epoch, const QString &reason,
             quint64 lost = 0, bool lostKnown = true);
    void storageFailed();
    void checkpoint(const QDateTime &atUtc);
    bool flushDue(const QDateTime &nowUtc) const;
    bool canInferInactivity() const { return false; }
  private:
    Coverage *source(const QString &id, const QString &epoch);
    void stage(const QDateTime &receivedAtUtc);
    HistoryState state_;
    QMap<QString, quint64> lastSequences_;
    QMap<QString, QString> nativeCommands_;
    int eventLimit_, stagingLimit_, staged_ = 0;
    QDateTime stagedSince_;
};
QString nativeSourceId(const NativeSourceBinding &binding);
QString nativeEpochKey(const NativeSourceBinding &binding);
QString nativeEventKey(const ActivityEvent &event);
bool validNativeBinding(const NativeSourceBinding &binding);
bool validNativeProcessFacts(const NativeProcessFacts &facts);
bool validNativeEvent(const ActivityEvent &event);
bool nativeCauseMatches(const ActivityEvent &attempt, const ActivityEvent &authorization);
bool nativeTrafficMatches(const ActivityEvent &attempt, const ActivityEvent &authorization, const ActivityEvent &traffic);
bool validNativeHistory(const HistoryState &state);
} // namespace Gate::Data
