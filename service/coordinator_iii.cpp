#include "coordinator_iii.h"
#include <algorithm>

namespace gb::directional {
bool NativeSnapshotFile::claimWriter(const void *owner) {
    std::unique_lock<std::mutex> lock(leaseMutex_, std::try_to_lock);
    if (!lock || !owner || owner_ || lease_ || !directory_.writerLease(lease_))
        return false;
    owner_ = owner;
    return true;
}
void NativeSnapshotFile::releaseWriter(const void *owner) noexcept {
    std::lock_guard<std::mutex> lock(leaseMutex_);
    if (owner && owner_ == owner) {
        lease_.reset();
        owner_ = nullptr;
    }
}
bool NativeSnapshotFile::read(Bytes &b, bool &exists) {
    return lease_ && directory_.read(L"policy.bin", MaxSnapshotBytes, b, exists);
}
bool NativeSnapshotFile::readLegacyJournal(Bytes &b, bool &exists) {
    return lease_ && directory_.read(L"decisions-journal.bin", decisions::MaxJournalBytes, b, exists);
}
bool NativeSnapshotFile::replace(const Bytes &b) {
    return lease_ && directory_.replace(L"policy.bin", b, true);
}
SnapshotCoordinator::SnapshotCoordinator(SnapshotFile &file, DirectionalBackend &backend,
                                         SelectorRegistry &registry, Id epoch,
                                         std::function<std::uint64_t()> monotonic)
    : file_(file), backend_(backend), registry_(registry), epoch_(epoch),
      monotonic_(monotonic ? std::move(monotonic) : [] { return GetTickCount64(); }) {}
SnapshotCoordinator::~SnapshotCoordinator() {
    if (ownsWriter_)
        file_.releaseWriter(this);
}
bool SnapshotCoordinator::load() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (loaded_ || ownsWriter_ || zero(epoch_) || !file_.claimWriter(this))
        return false;
    // Fallo de load conserva sólo su lease hasta destrucción; ningún retry hereda estado.
    ownsWriter_ = true;
    Bytes policy, history;
    bool exists = false, historyExists = false;
    if (!file_.read(policy, exists))
        return false;
    Snapshot s;
    if (exists && policy.size() >= 4 &&
        Bytes(policy.begin(), policy.begin() + 4) == Bytes{'G', 'B', 'S', '3'}) {
        if (!parse(policy, s) || !runtimeAdmissible(s))
            return false;
        legacy_ = false;
    } else {
        if (!file_.readLegacyJournal(history, historyExists))
            return false;
        if (!exists) {
            if (historyExists)
                return false;
            s.writerEpoch = epoch_;
            s.legacyConsistent = true;
        } else if (!importLegacy(policy, historyExists ? &history : nullptr, epoch_, s))
            return false;
        legacy_ = true;
    }
    snapshot_ = std::move(s);
    // No reutilizar el reloj monotónico de un boot anterior ni alterar envelopes históricos.
    auto now = monotonic_();
    for (const auto &entry : snapshot_.entries)
        if (entry.command.state == State::Applied || entry.command.state == State::Failed)
            retainedAt_[entry.command.id] = now;
    activeBytes_ = std::move(policy);
    loaded_ = true;
    // Un archivo Applied sólo acredita historia después de reiniciar.
    recovery_ = true;
    observed_ = Observed::Unknown;
    return true;
}
bool SnapshotCoordinator::reconcile() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ownsWriter_ || !loaded_ || !backend_.ready() ||
        !backend_.matches(snapshot_.rules, snapshot_.desired))
        return false;
    if (legacy_) {
        if (!snapshot_.legacyConsistent)
            return false;
        recovery_ = false;
        return true;
    }
    if (observed_ == Observed::Unknown) {
        Bytes bytes;
        bool present = false;
        Snapshot actual;
        if (!file_.read(bytes, present) || !present || !parse(bytes, actual) ||
            !runtimeAdmissible(actual) || actual.active != snapshot_.active ||
            actual.activeAdmission != snapshot_.activeAdmission ||
            actual.activeProjection != snapshot_.activeProjection ||
            targetDigest(actual) != targetDigest(snapshot_))
            return false;
        snapshot_ = std::move(actual);
        activeBytes_ = std::move(bytes);
    }
    // Validación exacta del conjunto y los tres digests precede a cualquier ACK durable.
    if (!runtimeAdmissible(snapshot_))
        return false;
    if (zero(snapshot_.active)) {
        recovery_ = false;
        return true;
    }
    auto next = snapshot_;
    auto it = std::find_if(next.entries.begin(), next.entries.end(),
                           [&](const auto &e) { return e.command.id == next.active; });
    if (it == next.entries.end() || it->effect == 0 || it->target != targetDigest(next) ||
        it->projection != next.activeProjection || it->admission != next.activeAdmission)
        return false;
    it->command.state = State::Applied;
    it->command.error = Error::Ok;
    it->command.effectiveKnown = true;
    it->command.effective = next.desired;
    next.state = State::Applied;
    next.effectiveKnown = true;
    next.effective = next.desired;
    if (!write(std::move(next))) {
        observeAfterFailure();
        return false;
    }
    recovery_ = false;
    return true;
}
bool SnapshotCoordinator::write(Snapshot next) {
    if (!ownsWriter_ || !loaded_ || snapshot_.sequence == UINT64_MAX)
        return false;
    Bytes actual;
    bool exists = false;
    if (!file_.read(actual, exists) || actual != activeBytes_ || exists != !activeBytes_.empty())
        return false;
    next.sequence = snapshot_.sequence + 1;
    next.writerEpoch = epoch_;
    Bytes encoded;
    if (!runtimeAdmissible(next) || !serialize(next, encoded))
        return false;
    if (!file_.replace(encoded))
        return false;
    Bytes verified;
    bool present = false;
    Snapshot readback;
    if (!file_.read(verified, present) || !present || verified != encoded ||
        !parse(verified, readback) || !runtimeAdmissible(readback))
        return false;
    snapshot_ = std::move(readback);
    activeBytes_ = std::move(verified);
    legacy_ = false;
    observed_ = snapshot_.state == State::Applied    ? Observed::FinalApplied
                : snapshot_.state == State::Prepared ? Observed::Prepared
                                                     : Observed::Unknown;
    return true;
}
void SnapshotCoordinator::observeAfterFailure() {
    recovery_ = true;
    observed_ = Observed::Unknown;
    Bytes bytes;
    bool exists = false;
    Snapshot actual;
    if (!file_.read(bytes, exists) || !exists || !parse(bytes, actual) ||
        !runtimeAdmissible(actual)) {
        // No secuencia supuesta ni fallback de backup ante activo ausente/inverificable.
        activeBytes_.clear();
        snapshot_.effectiveKnown = false;
        snapshot_.effective = 0;
        return;
    }
    snapshot_ = std::move(actual);
    activeBytes_ = std::move(bytes);
    legacy_ = false;
    auto it = std::find_if(snapshot_.entries.begin(), snapshot_.entries.end(),
                           [&](const auto &e) { return e.command.id == observedCommand_; });
    if (it != snapshot_.entries.end())
        observed_ = it->command.state == State::Prepared  ? Observed::Prepared
                    : it->command.state == State::Applied ? Observed::FinalApplied
                                                          : Observed::Unknown;
}
Snapshot SnapshotCoordinator::snapshot() const {
    std::lock_guard<std::mutex> l(mutex_);
    return snapshot_;
}
bool SnapshotCoordinator::legacy() const {
    std::lock_guard<std::mutex> l(mutex_);
    return legacy_;
}
bool SnapshotCoordinator::recovery() const {
    std::lock_guard<std::mutex> l(mutex_);
    return recovery_;
}
Result SnapshotCoordinator::result(const Entry &e, bool durable) const {
    auto known = !recovery_ && e.command.effectiveKnown && e.command.desired == snapshot_.desired &&
                 backend_.ready() && backend_.matches(snapshot_.rules, snapshot_.desired);
    return {e.command.error,
            e.command.state,
            known,
            durable,
            backend_.actualOs() && known,
            e.command.desired,
            known ? e.command.effective : 0,
            observed_ == Observed::Unknown ? 0 : snapshot_.sequence,
            observed_};
}
Result SnapshotCoordinator::query(const Id &id) const {
    std::lock_guard<std::mutex> l(mutex_);
    for (const auto &e : snapshot_.entries)
        if (e.command.id == id)
            return result(e, !recovery_);
    Result r;
    r.error = Error::CommandUnknown;
    r.desired = snapshot_.desired;
    return r;
}
Result SnapshotCoordinator::prepareLocked(decisions::CommandEntry command,
                                          const std::vector<Rule> &target,
                                          std::uint64_t expectedSequence) {
    Result fail;
    fail.desired = snapshot_.desired;
    Frame f;
    if (decode(command.payload, f) != Error::Ok || f.minor != 2) {
        fail.error = Error::Malformed;
        return fail;
    }
    // El caller admite autoridad UI/OS; aquí se conserva y valida su binding cerrado.
    Entry entry;
    entry.command = std::move(command);
    for (const auto &old : snapshot_.entries)
        if (old.command.id == entry.command.id) {
            if (!old.legacyEnvelope.empty() || !bindEntry(entry, old.target) ||
                entry.admission != old.admission) {
                fail.error = Error::Conflict;
                return fail;
            }
            return result(old, !recovery_);
        }
    auto permanent = f.type != Type::CommitDecision || get(f, Tag::Remember) != 0;
    auto next = snapshot_;
    next.rules = target;
    next.desired = entry.command.desired;
    if (!rulesValid(target) || !bindEntry(entry, targetDigest(next))) {
        fail.error = Error::Malformed;
        return fail;
    }
    if (!ownsWriter_ || !loaded_ || recovery_)
        return fail;
    if (expectedSequence != snapshot_.sequence ||
        get(f, Tag::ExpectedDesiredRev) != snapshot_.desired) {
        fail.error = Error::Stale;
        return fail;
    }
    if (legacy_ && !permanent) {
        fail.error = Error::Unsupported;
        return fail;
    }
    if (!backend_.ready() || !backend_.matches(snapshot_.rules, snapshot_.desired)) {
        recovery_ = true;
        fail.error = Error::BackendUnavailable;
        return fail;
    }
    if (entry.command.state != State::Prepared || entry.command.commandEpoch != epoch_ ||
        entry.command.desired != snapshot_.desired + (permanent ? 1 : 0) ||
        (permanent && snapshot_.desired == UINT64_MAX)) {
        fail.error = Error::Malformed;
        return fail;
    }
    auto expected = snapshot_;
    expected.desired = entry.command.desired;
    if (entry.effect == 10) {
        auto blob = registry_.lookup(idValue(f, Tag::SelectorId));
        if (!blob || get(f, Tag::SelectorRevision) != 1) {
            fail.error = Error::IdentityUnavailable;
            return fail;
        }
        auto action = static_cast<std::uint8_t>(get(f, Tag::Decision)),
             direction = static_cast<std::uint8_t>(get(f, Tag::PolicyDirection));
        expected.rules.push_back({f.correlation, idValue(f, Tag::SelectorId), 1, 1, action,
                                  direction,
                                  static_cast<std::uint8_t>(action == 1 || direction == 2 ? 0
                                                            : direction == 1              ? 1
                                                                                          : 2),
                                  *blob});
    } else if (entry.effect == 11) {
        auto it = std::find_if(expected.rules.begin(), expected.rules.end(),
                               [&](const auto &r) { return r.id == idValue(f, Tag::RuleId); });
        if (it == expected.rules.end() || get(f, Tag::RuleRevision) != it->revision) {
            fail.error = Error::Stale;
            return fail;
        }
        expected.rules.erase(it);
    }
    if (!rulesValid(expected.rules)) {
        fail.error = Error::Conflict;
        return fail;
    }
    if (targetDigest(expected) != entry.target) {
        fail.error = Error::Conflict;
        return fail;
    }
    // Sólo resueltos retenidos 120s en esta ejecución; pin y uncertain nunca se evictan.
    if (next.entries.size() >= 4096) {
        auto now = monotonic_();
        auto oldest = next.entries.end();
        for (auto it = next.entries.begin(); it != next.entries.end(); ++it) {
            auto retained = retainedAt_.find(it->command.id);
            if (it->command.id != next.active && retained != retainedAt_.end() &&
                (it->command.state == State::Applied || it->command.state == State::Failed) &&
                now >= retained->second && now - retained->second >= 120000 &&
                (oldest == next.entries.end() ||
                 retained->second < retainedAt_.at(oldest->command.id)))
                oldest = it;
        }
        if (oldest == next.entries.end()) {
            fail.error = Error::Capacity;
            return fail;
        }
        next.entries.erase(oldest);
    }
    next.entries.push_back(entry);
    if (permanent) {
        next.active = entry.command.id;
        next.activeProjection = entry.projection;
        next.activeAdmission = entry.admission;
        next.state = State::Prepared;
    }
    observedCommand_ = entry.command.id;
    if (!write(next)) {
        observeAfterFailure();
        fail.error = Error::StoreFailure;
        fail.desired = snapshot_.desired;
        fail.observed = observed_;
        fail.observedSequence = observed_ == Observed::Unknown ? 0 : snapshot_.sequence;
        return fail;
    }
    inFlight_ = entry.command.id;
    attempted_ = false;
    recovery_ = true;
    Result prepared;
    prepared.error = Error::Ok;
    prepared.state = State::Prepared;
    prepared.desired = snapshot_.desired;
    prepared.durable = true;
    prepared.observed = Observed::Prepared;
    prepared.observedSequence = snapshot_.sequence;
    return prepared;
}
bool SnapshotCoordinator::applyLocked(const Id &id) {
    if (!ownsWriter_ || !loaded_ || inFlight_ != id || attempted_)
        return false;
    auto it = std::find_if(snapshot_.entries.begin(), snapshot_.entries.end(),
                           [&](const auto &e) { return e.command.id == id; });
    if (it == snapshot_.entries.end() || it->command.state != State::Prepared || !entryValid(*it) ||
        it->target != targetDigest(snapshot_))
        return false;
    attempted_ = true;
    return (!it->effect || backend_.apply(snapshot_.rules, snapshot_.desired)) &&
           backend_.matches(snapshot_.rules, snapshot_.desired);
}
Result SnapshotCoordinator::completeLocked(decisions::CommandEntry command) {
    Result fail;
    fail.desired = snapshot_.desired;
    if (!ownsWriter_ || !loaded_)
        return fail;
    auto next = snapshot_;
    auto it = std::find_if(next.entries.begin(), next.entries.end(),
                           [&](const auto &e) { return e.command.id == command.id; });
    if (it == next.entries.end() || !it->legacyEnvelope.empty() || inFlight_ != command.id ||
        !attempted_)
        return fail;
    auto incoming = *it;
    incoming.command = command;
    if (!bindEntry(incoming, it->target) || incoming.admission != it->admission) {
        fail.error = Error::Conflict;
        return fail;
    }
    bool applied = command.state == State::Applied && backend_.ready() &&
                   backend_.matches(next.rules, next.desired);
    if (!applied) {
        it->command.state = State::RecoveryRequired;
        it->command.error = Error::RecoveryRequired;
        it->command.effectiveKnown = false;
        it->command.effective = 0;
        next.state = State::RecoveryRequired;
        next.effectiveKnown = false;
        next.effective = 0;
        if (!write(next))
            observeAfterFailure();
        recovery_ = true;
        return fail;
    }
    auto &last = it->command;
    last.completedAt = command.completedAt;
    last.state = State::Applied;
    last.error = Error::Ok;
    last.effectiveKnown = true;
    last.effective = next.desired;
    next.state = State::Applied;
    next.effectiveKnown = true;
    next.effective = next.desired;
    if (!write(next)) {
        // Puede observarse Prepared o FinalApplied; ninguno prueba el flush fallido.
        observeAfterFailure();
        Result r;
        r.error = Error::StoreFailure;
        r.state = State::AppliedUnrecorded;
        r.desired = next.desired;
        r.effectiveKnown = backend_.matches(next.rules, next.desired);
        r.effective = r.effectiveKnown ? next.desired : 0;
        r.appliedReal = backend_.actualOs() && r.effectiveKnown;
        r.observed = observed_;
        r.observedSequence = observed_ == Observed::Unknown ? 0 : snapshot_.sequence;
        return r;
    }
    recovery_ = false;
    inFlight_ = {};
    attempted_ = false;
    retainedAt_[command.id] = monotonic_();
    auto final = std::find_if(snapshot_.entries.begin(), snapshot_.entries.end(),
                              [&](const auto &e) { return e.command.id == command.id; });
    return result(*final, true);
}
Result SnapshotCoordinator::prepare(decisions::CommandEntry command,
                                    const std::vector<Rule> &target, std::uint64_t sequence) {
    std::lock_guard<std::mutex> lock(mutex_);
    return prepareLocked(std::move(command), target, sequence);
}
bool SnapshotCoordinator::applyPrepared(const Id &id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return applyLocked(id);
}
Result SnapshotCoordinator::complete(decisions::CommandEntry command) {
    std::lock_guard<std::mutex> lock(mutex_);
    return completeLocked(std::move(command));
}
bool SnapshotCoordinator::currentReadback(std::uint64_t desired) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ownsWriter_ && loaded_ && desired == snapshot_.desired && backend_.ready() &&
           backend_.matches(snapshot_.rules, desired);
}
Result SnapshotCoordinator::commit(decisions::CommandEntry command, const std::vector<Rule> &target,
                                   std::uint64_t sequence) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto outcome = prepareLocked(command, target, sequence);
    if (outcome.error != Error::Ok || outcome.state != State::Prepared || inFlight_ != command.id ||
        attempted_)
        return outcome;
    if (!applyLocked(command.id)) {
        command.state = State::RecoveryRequired;
        command.error = Error::RecoveryRequired;
        return completeLocked(command);
    }
    command.state = State::Applied;
    command.effectiveKnown = true;
    command.effective = command.desired;
    return completeLocked(command);
}
} // namespace gb::directional
