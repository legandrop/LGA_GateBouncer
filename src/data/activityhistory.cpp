#include "activityhistory.h"
#include <algorithm>
#include <limits>
#include <QSet>

namespace Gate::Data {
namespace {
QString sequenceKey(const QString &id, const QString &epoch) {
    return QString::number(id.size()) + ':' + id + epoch;
}
bool utc(const QDateTime &date) { return date.isValid() && date.offsetFromUtc() == 0; }
bool bounded(const QString &text) { return text.size() <= 32768; }
bool id(const QString &text) {
    if (text.size() != 32 || text == QString(32, '0')) return false;
    for (auto c : text)
        if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f')) return false;
    return true;
}
bool equivalent(const ActivityEvent &a, const ActivityEvent &b) {
    if (!a.native || !b.native) return false;
    const auto &x = *a.native, &y = *b.native;
    return a.sourceId == b.sourceId && a.sourceEpoch == b.sourceEpoch && a.sequence == b.sequence &&
        a.kind == b.kind && a.action == b.action && x.observed == y.observed &&
        x.captureBinding == y.captureBinding && x.command == y.command &&
        x.observedRevision == y.observedRevision && x.unixNanoseconds == y.unixNanoseconds &&
        x.presence == y.presence && x.attemptSequence == y.attemptSequence &&
        x.effectiveRevision == y.effectiveRevision && x.source == y.source &&
        x.direction == y.direction && x.protocol == y.protocol && x.scope == y.scope &&
        x.durable == y.durable && x.currentEffect == y.currentEffect &&
        a.bytes == b.bytes && x.packetCount == y.packetCount && x.packetDirection == y.packetDirection &&
        x.process == y.process;
}
void update(std::optional<EventFact> &target, const ActivityEvent &event) {
    if (!target || target->atUtc < event.observedAtUtc)
        target = EventFact{event.observedAtUtc, event.sourceId, event.sourceEpoch, event.sequence};
}
} // namespace
QString nativeSourceId(const NativeSourceBinding &b) {
    if (b.role == 2) return "NativeAdministrativeEvents:" + b.serviceEpoch + ':' +
        QString::number(b.profile) + ":2:" + b.connection;
    return "NativePrincipalEvents:" + b.serviceEpoch + ':' + QString::number(b.profile);
}
QString nativeEpochKey(const NativeSourceBinding &b) {
    return b.sourceEpoch + ':' + b.boot + ':' + b.engineContext + ':' + QString::number(b.generation);
}
QString nativeEventKey(const ActivityEvent &e) {
    return sequenceKey(e.sourceId, e.sourceEpoch) + ':' + e.sequence;
}
bool validNativeBinding(const NativeSourceBinding &b) {
    return id(b.serviceEpoch) && id(b.boot) && id(b.engineContext) &&
        b.sourceEpoch == b.engineContext && b.generation && b.profile &&
        ((b.role == 0 && b.connection.isEmpty()) || (b.role == 2 && id(b.connection)));
}
bool validNativeProcessFacts(const NativeProcessFacts &f) {
    const auto sid = [](const QByteArray &b) {
        return b.size() >= 8 && b.size() <= 68 && quint8(b[0]) == 1 &&
            b.size() == 8 + 4 * quint8(b[1]);
    };
    if (!f.pid || !f.created || !(f.indexHigh || f.indexLow) || !f.lastWrite ||
        !sid(f.accountSid) || !sid(f.logonSid) || f.image.isEmpty() || f.image.contains(QChar(0)) ||
        f.image.toUtf8().size() > 4096 || QString::fromUtf8(f.image.toUtf8()) != f.image ||
        f.appId.size() < 4 || f.appId.size() > 8192 || f.appId.size() % 2 ||
        f.appId[f.appId.size()-1] != 0 || f.appId[f.appId.size()-2] != 0) return false;
    const auto unit = [&](qsizetype at) { return quint16(quint8(f.appId[at])) | (quint16(quint8(f.appId[at+1])) << 8); };
    for (qsizetype at = 0; at + 2 < f.appId.size(); at += 2) {
        const auto c = unit(at);
        if (!c || (c >= 0xdc00 && c <= 0xdfff)) return false;
        if (c >= 0xd800 && c <= 0xdbff) {
            if (at + 4 >= f.appId.size() || unit(at+2) < 0xdc00 || unit(at+2) > 0xdfff) return false;
            at += 2;
        }
    }
    return true;
}
bool validNativeEvent(const ActivityEvent &e) {
    if (e.synthetic || !e.native || !utc(e.receivedAtUtc) || e.instance ||
        !e.requestId.isEmpty() || !e.flowId.isEmpty() || !e.winningRuleId.isEmpty() ||
        !e.winningRuleRevision.isEmpty() || !e.endpoint.isEmpty()) return false;
    const auto &n = *e.native;
    const bool administrative = e.sourceId.startsWith("NativeAdministrativeEvents:");
    if (administrative && !e.sourceId.endsWith(":2:" + n.connection)) return false;
    quint64 seq = 0;
    if (!decimalUnsigned(e.sequence, &seq) || !seq || !id(n.connection) || !id(n.observed) ||
        !id(n.captureBinding) || !n.observedRevision || (n.presence & ~7ull) ||
        bool(n.presence & 4) != n.process.has_value() ||
        (n.process && (n.source != 2 || !validNativeProcessFacts(*n.process))) ||
        (n.routeMask != 3 && n.routeMask != 7) ||
        (n.source != 1 && n.source != 2) || (n.direction != 1 && n.direction != 2) ||
        ((n.presence & 1) ? !n.unixNanoseconds : n.unixNanoseconds != 0) ||
        ((n.presence & 2) ? (n.source != 2 || (n.protocol != 6 && n.protocol != 17)) : n.protocol != 0) ||
        e.protocol != ((n.presence & 2) ? (n.protocol == 6 ? "TCP" : "UDP") : QString{}) ||
        e.subjectId != "native:" + e.sourceId + ':' + e.sourceEpoch + ':' + n.observed + ':' + n.captureBinding + ':' + QString::number(n.observedRevision)) return false;
    if (n.presence & 1) {
        if (!utc(e.observedAtUtc) || e.observedAtUtc.toMSecsSinceEpoch() != qint64(n.unixNanoseconds / 1000000ull)) return false;
    } else if (e.observedAtUtc.isValid()) return false;
    if (e.kind == ActivityKind::Attempt)
        return !e.action && n.command.isEmpty() && !n.attemptSequence && !n.effectiveRevision &&
            !n.scope && !n.durable && !n.currentEffect && !n.externalPartial &&
            !e.bytes && !n.packetCount && !n.packetDirection;
    const bool applied = n.source == 2 && id(n.command) && n.attemptSequence && n.attemptSequence < seq &&
        n.effectiveRevision && n.scope >= 3 && n.scope <= 5 && n.durable && n.currentEffect;
    if (e.kind == ActivityKind::Authorization)
        return applied && e.action && (*e.action == Action::Allow || *e.action == Action::Block) &&
            (n.routeMask == 7 || !(n.presence & 1) ||
             administrative) &&
            !e.bytes && !n.packetCount && !n.packetDirection;
    return e.kind == ActivityKind::Traffic && applied && !e.action && n.routeMask == 7 &&
        (n.presence == 3 || n.presence == 7) && e.bytes.has_value() && n.packetCount &&
        (n.packetDirection == 1 || n.packetDirection == 2);
}
bool nativeCauseMatches(const ActivityEvent &a, const ActivityEvent &b) {
    if (!validNativeEvent(a) || !validNativeEvent(b) || a.kind != ActivityKind::Attempt ||
        (b.kind != ActivityKind::Authorization && b.kind != ActivityKind::Traffic) || a.native->source != 2) return false;
    return a.sourceId == b.sourceId && a.sourceEpoch == b.sourceEpoch &&
        a.sequence == QString::number(b.native->attemptSequence) &&
        a.native->observed == b.native->observed &&
        a.native->observedRevision == b.native->observedRevision &&
        a.native->captureBinding == b.native->captureBinding &&
        a.native->direction == b.native->direction && a.native->protocol == b.native->protocol &&
        (a.native->presence & 6) == (b.native->presence & 6) && a.native->process == b.native->process;
}
bool nativeTrafficMatches(const ActivityEvent &a, const ActivityEvent &auth, const ActivityEvent &traffic) {
    return auth.kind == ActivityKind::Authorization && auth.action == Action::Allow &&
        traffic.kind == ActivityKind::Traffic && nativeCauseMatches(a, auth) && nativeCauseMatches(a, traffic) &&
        !auth.native->externalPartial && auth.sequence.toULongLong() < traffic.sequence.toULongLong() &&
        auth.native->command == traffic.native->command &&
        auth.native->effectiveRevision == traffic.native->effectiveRevision && auth.native->scope == traffic.native->scope;
}
NativeHistoryDates nativeProcessHistoryDates(const HistoryState &state,
    const QVector<std::shared_ptr<const ActivityEvent>> &causes) {
    std::optional<EventFact> selected[3]; bool ambiguous[3]{};
    QMap<QString,const ActivityEvent *> admitted, authorizations;
    const auto select=[&](int slot,const ActivityEvent &event) {
        // El cursor se compara únicamente dentro de la fuente/epoch del set admitido.
        const EventFact fact{event.observedAtUtc,event.sourceId,event.sourceEpoch,event.sequence};
        if (selected[slot] && (selected[slot]->sourceId!=fact.sourceId || selected[slot]->sourceEpoch!=fact.sourceEpoch)) {
            ambiguous[slot]=true; return;
        }
        if (!selected[slot] || fact.sequence.toULongLong()>selected[slot]->sequence.toULongLong()) selected[slot]=fact;
    };
    for (const auto &cause:causes) {
        if (!cause || !validNativeEvent(*cause) || cause->kind!=ActivityKind::Attempt ||
            !cause->native->process || cause->native->externalPartial) continue;
        const auto key=nativeEventKey(*cause); const auto stored=state.nativeAttempts.constFind(key);
        // Resolver la secuencia al compacto original; subject/PID/path nunca sustituyen el descriptor.
        if (stored==state.nativeAttempts.cend() || !validNativeEvent(*stored) || stored->native->externalPartial || !equivalent(*cause,*stored)) continue;
        admitted.insert(key,cause.get()); select(0,*stored);
    }
    for (const auto &auth:state.nativeAuthorizations) {
        if (!validNativeEvent(auth) || auth.native->externalPartial || auth.action!=Action::Allow) continue;
        auto link=auth; link.sequence=QString::number(auth.native->attemptSequence);
        const auto cause=admitted.constFind(nativeEventKey(link));
        if (cause==admitted.cend() || !nativeCauseMatches(**cause,auth)) continue;
        // Command y source/epoch resuelven el Authorization compacto para la cadena Traffic.
        authorizations.insert(sequenceKey(auth.sourceId,auth.sourceEpoch)+':'+auth.native->command,&auth);
        select(1,auth);
    }
    for (const auto &traffic:state.nativeTraffic) {
        if (!validNativeEvent(traffic) || traffic.native->externalPartial) continue;
        auto link=traffic; link.sequence=QString::number(traffic.native->attemptSequence);
        const auto cause=admitted.constFind(nativeEventKey(link));
        const auto auth=authorizations.constFind(sequenceKey(traffic.sourceId,traffic.sourceEpoch)+':'+traffic.native->command);
        if (cause==admitted.cend() || auth==authorizations.cend() || !nativeTrafficMatches(**cause,**auth,traffic)) continue;
        select(2,traffic);
    }
    return {!ambiguous[0] && selected[0] ? selected[0]->atUtc:QDateTime{},
        !ambiguous[1] && selected[1] ? selected[1]->atUtc:QDateTime{},
        !ambiguous[2] && selected[2] ? selected[2]->atUtc:QDateTime{}};
}
bool validNativeHistory(const HistoryState &s) {
    if (s.nativeAttempts.size() > 20000 || s.nativeAuthorizations.size() > 20000 || s.nativeTraffic.size() > 20000) return false;
    for (const auto &c : s.coverage) {
        if (!c.native) continue;
        QSet<QString> intervals;
        for (const auto &g : c.gaps) {
            if ((!g.lostKnown && g.lost) || g.resync > c.lastSequence ||
                (g.remote && (g.nativeReason < 1 || g.nativeReason > 4 || g.after > g.resync ||
                    (g.lostKnown && (!g.lost || g.after >= g.resync || g.lost != g.resync - g.after)))) ||
                (!g.remote && (g.nativeReason || g.after || g.revision))) return false;
            if (!g.remote) continue;
            const auto interval = QString::number(g.nativeReason) + ':' + QString::number(g.after) + ':' +
                QString::number(g.resync) + ':' + QString::number(g.revision);
            if (intervals.contains(interval)) return false;
            intervals.insert(interval);
        }
    }
    const auto known = [&](const ActivityEvent &e) {
        quint64 seq = 0;
        if (!validNativeEvent(e) || !decimalUnsigned(e.sequence, &seq)) return false;
        for (const auto &c : s.coverage)
            if (c.native && !c.synthetic && validNativeBinding(*c.native) &&
                c.sourceId == nativeSourceId(*c.native) && c.sourceEpoch == nativeEpochKey(*c.native) &&
                e.sourceId == c.sourceId && e.sourceEpoch == c.sourceEpoch && seq <= c.lastSequence &&
                (c.native->role != 2 || e.native->connection == c.native->connection)) return true;
        return false;
    };
    for (auto it = s.nativeAttempts.begin(); it != s.nativeAttempts.end(); ++it)
        if (it.key() != nativeEventKey(it.value()) || it->kind != ActivityKind::Attempt || !known(it.value())) return false;
    QMap<QString, QString> commands;
    for (auto it = s.nativeAuthorizations.begin(); it != s.nativeAuthorizations.end(); ++it) {
        auto linked = it.value(); linked.sequence = QString::number(it->native ? it->native->attemptSequence : 0);
        if (it.key() != nativeEventKey(it.value()) || it->kind != ActivityKind::Authorization ||
            !known(it.value()) || it->native->externalPartial || s.nativeAttempts.contains(it.key()) || s.nativeTraffic.contains(it.key()) ||
            !s.nativeAttempts.contains(nativeEventKey(linked)) ||
            !nativeCauseMatches(s.nativeAttempts[nativeEventKey(linked)], it.value())) return false;
        const auto command = sequenceKey(it->sourceId, it->sourceEpoch) + ':' + it->native->command;
        if (commands.contains(command)) return false;
        commands.insert(command, it.key());
    }
    for (auto it = s.nativeTraffic.begin(); it != s.nativeTraffic.end(); ++it) {
        if (it.key() != nativeEventKey(it.value()) || it->kind != ActivityKind::Traffic || !known(it.value()) ||
            it->native->externalPartial || s.nativeAttempts.contains(it.key()) || s.nativeAuthorizations.contains(it.key())) return false;
        auto linked = it.value(); linked.sequence = QString::number(it->native->attemptSequence);
        const auto cause = s.nativeAttempts.constFind(nativeEventKey(linked));
        const auto command = sequenceKey(it->sourceId, it->sourceEpoch) + ':' + it->native->command;
        if (cause == s.nativeAttempts.cend() || !commands.contains(command) ||
            !nativeTrafficMatches(*cause, s.nativeAuthorizations[commands[command]], it.value())) return false;
    }
    QSet<QString> cursors;
    for (const auto &e : s.events) {
        if (e.synthetic) { if (e.native) return false; continue; }
        if (!known(e)) return false;
        const auto cursor = nativeEventKey(e);
        if (cursors.contains(cursor)) return false;
        cursors.insert(cursor);
        const auto &sameKind = e.kind == ActivityKind::Attempt ? s.nativeAttempts :
            e.kind == ActivityKind::Authorization ? s.nativeAuthorizations : s.nativeTraffic;
        if ((e.kind != ActivityKind::Attempt && s.nativeAttempts.contains(cursor)) ||
            (e.kind != ActivityKind::Authorization && s.nativeAuthorizations.contains(cursor)) ||
            (e.kind != ActivityKind::Traffic && s.nativeTraffic.contains(cursor))) return false;
        if (sameKind.contains(cursor)) {
            const auto &compact = sameKind[cursor];
            if (!equivalent(compact, e) || compact.receivedAtUtc != e.receivedAtUtc ||
                compact.native->connection != e.native->connection ||
                compact.native->routeMask != e.native->routeMask ||
                compact.native->externalPartial != e.native->externalPartial) return false;
        } else if (e.kind != ActivityKind::Attempt && !e.native->externalPartial) return false;
        if (e.kind == ActivityKind::Traffic) {
            auto linked = e; linked.sequence = QString::number(e.native->attemptSequence);
            const auto cause = s.nativeAttempts.constFind(nativeEventKey(linked));
            const auto command = sequenceKey(e.sourceId, e.sourceEpoch) + ':' + e.native->command;
            const auto authKey = commands.value(command);
            const auto auth = s.nativeAuthorizations.constFind(authKey);
            if ((cause != s.nativeAttempts.cend() && !nativeCauseMatches(*cause, e)) ||
                (auth != s.nativeAuthorizations.cend() &&
                    (cause == s.nativeAttempts.cend() || !nativeTrafficMatches(*cause, *auth, e)))) return false;
        }
        if (e.kind == ActivityKind::Authorization) {
            const auto command = sequenceKey(e.sourceId, e.sourceEpoch) + ':' + e.native->command;
            if (commands.contains(command) && commands[command] != cursor) return false;
            commands.insert(command, cursor);
        }
    }
    for (auto it = s.subjects.begin(); it != s.subjects.end(); ++it)
        for (int kind = 0; kind < 3; ++kind) {
            const auto &fact = kind == 0 ? it->lastAttempt : kind == 1 ? it->lastAuthorized : it->lastTraffic;
            if (!fact) continue;
            bool native = false;
            for (const auto &c : s.coverage)
                if (c.sourceId == fact->sourceId && c.sourceEpoch == fact->sourceEpoch) native = bool(c.native);
            if (!native) continue;
            ActivityEvent key; key.sourceId = fact->sourceId; key.sourceEpoch = fact->sourceEpoch; key.sequence = fact->sequence;
            const auto &map = kind == 0 ? s.nativeAttempts : kind == 1 ? s.nativeAuthorizations : s.nativeTraffic;
            if (!map.contains(nativeEventKey(key))) return false;
            const auto &e = map[nativeEventKey(key)];
            if (e.subjectId != it.key() || fact->atUtc != e.observedAtUtc ||
                (kind == 1 && e.action != Action::Allow)) return false;
        }
    for (const auto &fact : s.ruleHits)
        for (const auto &c : s.coverage)
            if (c.native && c.sourceId == fact.sourceId && c.sourceEpoch == fact.sourceEpoch) return false;
    return true;
}
ActivityHistory::ActivityHistory(int eventLimit, int stagingLimit)
    : eventLimit_(std::clamp(eventLimit, 1, 4096)), stagingLimit_(std::clamp(stagingLimit, 1, 4096)) {}
void ActivityHistory::stage(const QDateTime &at) {
    if (!staged_) stagedSince_ = at;
    if (staged_ < stagingLimit_) ++staged_;
}
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
bool ActivityHistory::addNativeSource(const NativeSourceBinding &binding, quint64 baseline) {
    if (!validNativeBinding(binding)) return false;
    const auto id = nativeSourceId(binding), epoch = nativeEpochKey(binding);
    auto *coverage = source(id, epoch);
    if (!coverage) {
        if (state_.coverage.size() >= 128) return false;
        Coverage c; c.sourceId = id; c.sourceEpoch = epoch; c.native = binding;
        c.declaredScope = "Retained principal causes and causal applied decisions";
        c.sinceUtc = QDateTime::currentDateTimeUtc(); c.status = CoverageStatus::Partial;
        state_.coverage.push_back(std::move(c)); coverage = source(id, epoch);
    }
    if (coverage->synthetic || !coverage->native || !(*coverage->native == binding) || baseline < coverage->lastSequence) return false;
    coverage->status = CoverageStatus::Partial;
    coverage->lastSequence = baseline;
    lastSequences_[sequenceKey(id, epoch)] = baseline;
    gap(id, epoch, "SubscriptionBaseline", 0, false);
    return true;
}
void ActivityHistory::disconnectNative(const NativeSourceBinding &b, const QString &reason) {
    auto *c = source(nativeSourceId(b), nativeEpochKey(b));
    if (!c || !c->native || !(*c->native == b)) return;
    gap(c->sourceId, c->sourceEpoch, reason, 0, false);
    c->status = CoverageStatus::Unavailable;
}
bool ActivityHistory::nativeGap(const NativeSourceBinding &b, quint64 after, quint64 resync,
                                quint64 revision, quint8 reason, bool lostKnown, quint64 lost) {
    auto *c = source(nativeSourceId(b), nativeEpochKey(b));
    if (!c || !c->native || !(*c->native == b) || reason < 1 || reason > 4 || after > resync ||
        (lostKnown ? (!lost || after >= resync || lost != resync - after) : lost != 0)) return false;
    for (const auto &g : c->gaps)
        if (g.remote && g.after == after && g.resync == resync && g.revision == revision && g.nativeReason == reason)
            return g.lostKnown == lostKnown && g.lost == lost;
    if (resync < c->lastSequence) return true;
    gap(c->sourceId, c->sourceEpoch, "RemoteGap:" + QString::number(reason), lost, lostKnown);
    auto &g = c->gaps.back(); g.remote = true; g.after = after; g.resync = resync;
    g.revision = revision; g.nativeReason = reason;
    c->lastSequence = resync; lastSequences_[sequenceKey(c->sourceId, c->sourceEpoch)] = resync;
    return true;
}
bool ActivityHistory::ingest(const ActivityEvent &event) {
    auto *coverage = source(event.sourceId, event.sourceEpoch);
    if (event.native) {
        if (!coverage || coverage->synthetic || !coverage->native ||
            coverage->status == CoverageStatus::Unavailable || !validNativeEvent(event) ||
            (coverage->native->role == 2 && event.native->connection != coverage->native->connection)) return false;
        if (event.kind == ActivityKind::Traffic)
            coverage->declaredScope = "Retained principal causes, causal applied decisions and OS layer activity";
        const auto key = sequenceKey(event.sourceId, event.sourceEpoch);
        const quint64 sequence = event.sequence.toULongLong();
        if (sequence <= lastSequences_.value(key)) {
            const ActivityEvent *old = nullptr;
            if (state_.nativeAttempts.contains(nativeEventKey(event))) old = &state_.nativeAttempts[nativeEventKey(event)];
            else if (state_.nativeAuthorizations.contains(nativeEventKey(event))) old = &state_.nativeAuthorizations[nativeEventKey(event)];
            else if (state_.nativeTraffic.contains(nativeEventKey(event))) old = &state_.nativeTraffic[nativeEventKey(event)];
            else for (const auto &e : state_.events)
                if (nativeEventKey(e) == nativeEventKey(event)) { old = &e; break; }
            if (old && equivalent(*old, event)) return true;
            disconnectNative(*coverage->native, old ? "ReplayConflict" : "ReplayOutsideRetention");
            return false;
        }
        // La secuencia es global; un salto por si solo no demuestra perdida.
        lastSequences_[key] = sequence; coverage->lastSequence = sequence;
        if (staged_ >= stagingLimit_) { gap(event.sourceId, event.sourceEpoch, "StagingOverflow", 1); return false; }
        auto admitted = event;
        bool compact = true;
        if (admitted.kind == ActivityKind::Attempt) {
            if (state_.nativeAttempts.size() >= 20000 ||
                (!state_.subjects.contains(event.subjectId) && state_.subjects.size() >= 20000)) {
                compact = false; gap(event.sourceId, event.sourceEpoch, "DescriptorCapacity", 0, false);
            } else state_.nativeAttempts.insert(nativeEventKey(admitted), admitted);
        } else if (admitted.kind == ActivityKind::Authorization) {
            const auto command = key + ':' + admitted.native->command;
            const bool retainedCommand = std::any_of(state_.events.cbegin(), state_.events.cend(), [&](const ActivityEvent &old) {
                return old.native && old.kind == ActivityKind::Authorization &&
                    old.sourceId == admitted.sourceId && old.sourceEpoch == admitted.sourceEpoch &&
                    old.native->command == admitted.native->command;
            });
            if (nativeCommands_.contains(command) || retainedCommand) {
                disconnectNative(*coverage->native, "AuthorizationCommandReplay"); return false;
            }
            auto link = admitted; link.sequence = QString::number(admitted.native->attemptSequence);
            const auto found = state_.nativeAttempts.constFind(nativeEventKey(link));
            if (found != state_.nativeAttempts.cend() && !nativeCauseMatches(*found, admitted)) {
                disconnectNative(*coverage->native, "AuthorizationLinkMismatch"); return false;
            }
            compact = found != state_.nativeAttempts.cend() && state_.nativeAuthorizations.size() < 20000 &&
                (state_.subjects.contains(event.subjectId) || state_.subjects.size() < 20000);
            admitted.native->externalPartial = !compact;
            if (!compact) gap(event.sourceId, event.sourceEpoch, "MissingAttemptEvidence", 0, false);
            else {
                state_.nativeAuthorizations.insert(nativeEventKey(admitted), admitted);
                nativeCommands_.insert(command, admitted.sequence);
            }
        } else {
            auto linked = admitted; linked.sequence = QString::number(admitted.native->attemptSequence);
            const auto cause = state_.nativeAttempts.constFind(nativeEventKey(linked));
            const auto command = key + ':' + admitted.native->command;
            const auto authSequence = nativeCommands_.constFind(command);
            ActivityEvent authKey = admitted;
            if (authSequence != nativeCommands_.cend()) authKey.sequence = *authSequence;
            const auto auth = authSequence == nativeCommands_.cend() ? state_.nativeAuthorizations.cend() :
                state_.nativeAuthorizations.constFind(nativeEventKey(authKey));
            if ((cause != state_.nativeAttempts.cend() && !nativeCauseMatches(*cause, admitted)) ||
                (auth != state_.nativeAuthorizations.cend() && (auth->action != Action::Allow ||
                    auth->native->attemptSequence != admitted.native->attemptSequence ||
                    auth->native->effectiveRevision != admitted.native->effectiveRevision ||
                    auth->native->scope != admitted.native->scope ||
                    (cause != state_.nativeAttempts.cend() && !nativeTrafficMatches(*cause, *auth, admitted))))) {
                disconnectNative(*coverage->native, "TrafficLinkMismatch"); return false;
            }
            compact = cause != state_.nativeAttempts.cend() && auth != state_.nativeAuthorizations.cend() &&
                state_.nativeTraffic.size() < 20000 && (state_.subjects.contains(event.subjectId) || state_.subjects.size() < 20000);
            admitted.native->externalPartial = !compact;
            if (!compact) gap(event.sourceId, event.sourceEpoch,
                state_.nativeTraffic.size() >= 20000 ? "TrafficDescriptorCapacity" : "MissingTrafficEvidence", 0, false);
            else state_.nativeTraffic.insert(nativeEventKey(admitted), admitted);
        }
        if (compact) {
            auto &aggregate = state_.subjects[admitted.subjectId];
            auto &fact = admitted.kind == ActivityKind::Attempt ? aggregate.lastAttempt :
                admitted.kind == ActivityKind::Authorization ? aggregate.lastAuthorized : aggregate.lastTraffic;
            if (admitted.kind != ActivityKind::Authorization || admitted.action == Action::Allow)
                fact = EventFact{admitted.observedAtUtc, admitted.sourceId, admitted.sourceEpoch, admitted.sequence};
        }
        if (admitted.observedAtUtc.isValid()) {
            if (coverage->lastObservedUtc.isValid() && admitted.observedAtUtc < coverage->lastObservedUtc)
                gap(event.sourceId, event.sourceEpoch, "TimestampDiscontinuity", 0, false);
            if (!coverage->lastObservedUtc.isValid() || coverage->lastObservedUtc < admitted.observedAtUtc)
                coverage->lastObservedUtc = admitted.observedAtUtc;
        }
        state_.events.push_back(std::move(admitted));
        if (state_.events.size() > eventLimit_) {
            const auto retired = state_.events.takeFirst();
            gap(retired.sourceId, retired.sourceEpoch, "DetailRetention", 1);
        }
        stage(event.receivedAtUtc);
        return true;
    }
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
void ActivityHistory::gap(const QString &id, const QString &epoch, const QString &reason, quint64 lost, bool lostKnown) {
    auto *coverage = source(id, epoch);
    if (!coverage) return;
    // Una discontinuidad no convierte una fuente sin validar en observacion disponible.
    if (coverage->status != CoverageStatus::Unavailable)
        coverage->status = CoverageStatus::Partial;
    const auto safeReason = reason.left(32768);
    if (!lostKnown) lost = 0;
    if (coverage->native && !coverage->gaps.isEmpty() && !coverage->gaps.back().remote &&
        coverage->gaps.back().reason == safeReason && coverage->gaps.back().resync == coverage->lastSequence &&
        coverage->gaps.back().lostKnown == lostKnown && !safeReason.startsWith("RemoteGap:")) return;
    if (!coverage->native && !coverage->gaps.isEmpty() && coverage->gaps.back().reason == safeReason &&
        coverage->gaps.back().lostKnown == lostKnown) {
        auto &count = coverage->gaps.back().lost;
        count = lost > std::numeric_limits<quint64>::max() - count
                    ? std::numeric_limits<quint64>::max() : count + lost;
    } else {
        if (coverage->gaps.size() >= 128) {
            if (!coverage->native) coverage->gaps.removeFirst();
            else {
                if (coverage->gaps.front().reason != "GapDetailRetention") {
                    coverage->gaps.removeFirst();
                    coverage->gaps.prepend({QDateTime::currentDateTimeUtc(), "GapDetailRetention", 1});
                }
                coverage->gaps.removeAt(1);
                auto &count = coverage->gaps.front().lost;
                if (count != std::numeric_limits<quint64>::max()) ++count;
            }
        }
        CoverageGap gap{QDateTime::currentDateTimeUtc(), safeReason, lost};
        gap.lostKnown = lostKnown; gap.resync = coverage->lastSequence;
        coverage->gaps.push_back(std::move(gap));
    }
    if (coverage->native) stage(QDateTime::currentDateTimeUtc());
}
void ActivityHistory::storageFailed() {
    for (const auto &coverage : state_.coverage)
        gap(coverage.sourceId, coverage.sourceEpoch, "StorageFailure", 0, !coverage.native);
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
        state.subjects.size() > 20000 || state.ruleHits.size() > 20000 || !validNativeHistory(state)) return false;
    QMap<QString, quint64> sequences;
    for (const auto &coverage : state.coverage) {
        if (coverage.sourceId.isEmpty() || coverage.sourceEpoch.isEmpty() ||
            !utc(coverage.sinceUtc) || coverage.gaps.size() > 128 ||
            (!coverage.synthetic && !coverage.native && coverage.status != CoverageStatus::Unavailable) ||
            (coverage.native && (coverage.synthetic || !validNativeBinding(*coverage.native) ||
              coverage.sourceId != nativeSourceId(*coverage.native) || coverage.sourceEpoch != nativeEpochKey(*coverage.native)))) return false;
        const auto key = sequenceKey(coverage.sourceId, coverage.sourceEpoch);
        if (sequences.contains(key)) return false;
        sequences[key] = coverage.lastSequence;
    }
    for (const auto &event : state.events) {
        quint64 sequence = 0;
        if ((!event.synthetic && !event.native) || (!event.native && !utc(event.observedAtUtc)) || !utc(event.receivedAtUtc) ||
            !decimalUnsigned(event.sequence, &sequence) || sequence == 0 ||
            int(event.kind) < 0 || int(event.kind) > 4 ||
            (event.kind == ActivityKind::Authorization && (!event.action || *event.action == Action::Ask))) return false;
        const auto key = sequenceKey(event.sourceId, event.sourceEpoch);
        if (!sequences.contains(key) || sequences[key] < sequence) return false;
    }
    state_ = state;
    lastSequences_ = sequences;
    nativeCommands_.clear();
    for (const auto &event : state_.nativeAuthorizations)
        nativeCommands_.insert(sequenceKey(event.sourceId, event.sourceEpoch) + ':' + event.native->command, event.sequence);
    staged_ = 0;
    stagedSince_ = {};
    for (auto &coverage : state_.coverage) {
        gap(coverage.sourceId, coverage.sourceEpoch, "ObservationRestart", 0, !coverage.native);
        if (coverage.native) coverage.status = CoverageStatus::Unavailable;
    }
    return true;
}
} // namespace Gate::Data
