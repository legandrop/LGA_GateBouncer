#include "activityhistory.h"
#include <algorithm>
#include <limits>

namespace Gate::Data {
namespace {
QString sequenceKey(const QString &id, const QString &epoch) {
    return QString::number(id.size()) + ':' + id + epoch;
}
bool utc(const QDateTime &date) { return date.isValid() && date.offsetFromUtc() == 0; }
bool bounded(const QString &text) { return text.size() <= 32768; }
void update(std::optional<EventFact> &target, const ActivityEvent &event) {
    if (!target || target->atUtc < event.observedAtUtc)
        target = EventFact{event.observedAtUtc, event.sourceId, event.sourceEpoch, event.sequence};
}
} // namespace
ActivityHistory::ActivityHistory(int eventLimit, int stagingLimit)
    : eventLimit_(std::clamp(eventLimit, 1, 4096)), stagingLimit_(std::clamp(stagingLimit, 1, 4096)) {}
Coverage *ActivityHistory::source(const QString &id, const QString &epoch) {
    for (auto &coverage : state_.coverage)
        if (coverage.sourceId == id && coverage.sourceEpoch == epoch) return &coverage;
    return nullptr;
}
bool ActivityHistory::addSyntheticSource(const QString &id, const QString &epoch, const QString &scope) {
    if (id.isEmpty() || epoch.isEmpty() || !bounded(id) || !bounded(epoch) || !bounded(scope) ||
        source(id, epoch) || state_.coverage.size() >= 128)
        return false;
    Coverage coverage;
    coverage.sourceId = id;
    coverage.sourceEpoch = epoch;
    coverage.declaredScope = scope;
    coverage.synthetic = true;
    coverage.status = CoverageStatus::DeclaredScope;
    coverage.sinceUtc = QDateTime::currentDateTimeUtc();
    state_.coverage.push_back(std::move(coverage));
    return true;
}
bool ActivityHistory::ingest(const ActivityEvent &event) {
    auto *coverage = source(event.sourceId, event.sourceEpoch);
    quint64 sequence = 0;
    if (!coverage || !coverage->synthetic || !event.synthetic || int(event.kind) < 0 || int(event.kind) > 4 ||
        !utc(event.observedAtUtc) || !utc(event.receivedAtUtc) ||
        !decimalUnsigned(event.sequence, &sequence) || sequence == 0 ||
        !bounded(event.subjectId) || !bounded(event.endpoint) || !bounded(event.protocol) ||
        !bounded(event.requestId) || !bounded(event.flowId) || !bounded(event.winningRuleId) ||
        !bounded(event.winningRuleRevision))
        return false;
    if (event.instance && (event.instance->sourceEpoch != event.sourceEpoch ||
                           event.instance->creationFiletime == 0)) return false;
    if ((event.kind == ActivityKind::Authorization &&
         (!event.action || *event.action == Action::Ask)) ||
        (event.action && (int(*event.action) < 0 || int(*event.action) > 2)) ||
        (!event.winningRuleId.isEmpty() && !decimalUnsigned(event.winningRuleRevision)) ||
        (event.winningRuleId.isEmpty() && !event.winningRuleRevision.isEmpty()) ||
        (event.bytes && event.kind != ActivityKind::Traffic)) return false;
    const auto key = sequenceKey(event.sourceId, event.sourceEpoch);
    const auto previous = lastSequences_.value(key);
    if (sequence <= previous) return false;
    if (previous && sequence - previous > 1)
        gap(event.sourceId, event.sourceEpoch, "SequenceLoss", sequence - previous - 1);
    lastSequences_[key] = sequence;
    coverage->lastSequence = sequence;
    if (coverage->lastObservedUtc.isValid() && event.observedAtUtc < coverage->lastObservedUtc)
        gap(event.sourceId, event.sourceEpoch, "TimestampDiscontinuity");
    if (!coverage->lastObservedUtc.isValid() || coverage->lastObservedUtc < event.observedAtUtc)
        coverage->lastObservedUtc = event.observedAtUtc;
    if (staged_ >= stagingLimit_ ||
        (!event.subjectId.isEmpty() && !state_.subjects.contains(event.subjectId) &&
         state_.subjects.size() >= 20000) ||
        (!event.winningRuleId.isEmpty() && !state_.ruleHits.contains(event.winningRuleId + ':' + event.winningRuleRevision) &&
         state_.ruleHits.size() >= 20000)) {
        gap(event.sourceId, event.sourceEpoch, "StagingOverflow", 1);
        return false;
    }
    if (!event.subjectId.isEmpty()) {
        auto &aggregate = state_.subjects[event.subjectId];
        switch (event.kind) {
        case ActivityKind::Attempt: update(aggregate.lastAttempt, event); break;
        case ActivityKind::Authorization:
            if (*event.action == Action::Allow) update(aggregate.lastAuthorized, event);
            break;
        case ActivityKind::Traffic: update(aggregate.lastTraffic, event); break;
        case ActivityKind::HumanDecision:
        case ActivityKind::PolicyApplied: break;
        }
    }
    if (!event.winningRuleId.isEmpty() &&
        (event.kind == ActivityKind::Attempt || event.kind == ActivityKind::Authorization)) {
        const auto ruleKey = event.winningRuleId + ':' + event.winningRuleRevision;
        const EventFact fact{event.observedAtUtc, event.sourceId, event.sourceEpoch, event.sequence};
        if (!state_.ruleHits.contains(ruleKey) || state_.ruleHits[ruleKey].atUtc < fact.atUtc)
            state_.ruleHits[ruleKey] = fact;
    }
    state_.events.push_back(event);
    if (state_.events.size() > eventLimit_) state_.events.removeFirst();
    if (staged_++ == 0) stagedSince_ = event.receivedAtUtc;
    return true;
}
void ActivityHistory::gap(const QString &id, const QString &epoch, const QString &reason, quint64 lost) {
    auto *coverage = source(id, epoch);
    if (!coverage) return;
    // Una discontinuidad no convierte una fuente sin validar en observacion disponible.
    if (coverage->status != CoverageStatus::Unavailable)
        coverage->status = CoverageStatus::Partial;
    const auto safeReason = reason.left(32768);
    if (!coverage->gaps.isEmpty() && coverage->gaps.back().reason == safeReason) {
        auto &count = coverage->gaps.back().lost;
        count = lost > std::numeric_limits<quint64>::max() - count
                    ? std::numeric_limits<quint64>::max() : count + lost;
    } else {
        if (coverage->gaps.size() >= 128) coverage->gaps.removeFirst();
        coverage->gaps.push_back({QDateTime::currentDateTimeUtc(), safeReason, lost});
    }
}
void ActivityHistory::storageFailed() {
    for (const auto &coverage : state_.coverage)
        gap(coverage.sourceId, coverage.sourceEpoch, "StorageFailure");
}
void ActivityHistory::checkpoint(const QDateTime &atUtc) {
    if (!utc(atUtc)) return;
    for (auto &coverage : state_.coverage) coverage.checkpointUtc = atUtc;
    staged_ = 0;
    stagedSince_ = {};
}
bool ActivityHistory::flushDue(const QDateTime &nowUtc) const {
    return staged_ >= 256 || (staged_ > 0 && utc(nowUtc) &&
                             stagedSince_.msecsTo(nowUtc) >= 2000);
}
bool ActivityHistory::restore(const HistoryState &state) {
    // El consumidor entrega el HistoryState validado por ReviewStore, no entradas externas.
    if (state.events.size() > eventLimit_ || state.coverage.size() > 128 ||
        state.subjects.size() > 20000 || state.ruleHits.size() > 20000) return false;
    QMap<QString, quint64> sequences;
    for (const auto &coverage : state.coverage) {
        if (coverage.sourceId.isEmpty() || coverage.sourceEpoch.isEmpty() ||
            !utc(coverage.sinceUtc) || coverage.gaps.size() > 128 ||
            (!coverage.synthetic && coverage.status != CoverageStatus::Unavailable)) return false;
        const auto key = sequenceKey(coverage.sourceId, coverage.sourceEpoch);
        if (sequences.contains(key)) return false;
        sequences[key] = coverage.lastSequence;
    }
    for (const auto &event : state.events) {
        quint64 sequence = 0;
        if (!event.synthetic || !utc(event.observedAtUtc) || !utc(event.receivedAtUtc) ||
            !decimalUnsigned(event.sequence, &sequence) || sequence == 0 ||
            int(event.kind) < 0 || int(event.kind) > 4 ||
            (event.kind == ActivityKind::Authorization && (!event.action || *event.action == Action::Ask))) return false;
        const auto key = sequenceKey(event.sourceId, event.sourceEpoch);
        if (!sequences.contains(key) || sequences[key] < sequence) return false;
    }
    state_ = state;
    lastSequences_ = sequences;
    staged_ = 0;
    stagedSince_ = {};
    for (const auto &coverage : state_.coverage)
        gap(coverage.sourceId, coverage.sourceEpoch, "ObservationRestart");
    return true;
}
} // namespace Gate::Data
