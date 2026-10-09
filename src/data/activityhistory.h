#pragma once
#include "contracts.h"

namespace Gate::Data {
class ActivityHistory final {
  public:
    explicit ActivityHistory(int eventLimit = 4096, int stagingLimit = 4096);
    bool addSyntheticSource(const QString &id, const QString &epoch, const QString &scope);
    bool ingest(const ActivityEvent &event);
    const HistoryState &state() const { return state_; }
    bool restore(const HistoryState &state);
    void gap(const QString &sourceId, const QString &epoch, const QString &reason,
             quint64 lost = 0);
    void storageFailed();
    void checkpoint(const QDateTime &atUtc);
    bool flushDue(const QDateTime &nowUtc) const;
    bool canInferInactivity() const { return false; }
  private:
    Coverage *source(const QString &id, const QString &epoch);
    HistoryState state_;
    QMap<QString, quint64> lastSequences_;
    int eventLimit_, stagingLimit_, staged_ = 0;
    QDateTime stagedSince_;
};
} // namespace Gate::Data
