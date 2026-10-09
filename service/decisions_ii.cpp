#include "decisions_ii.h"
#include <algorithm>
#include <limits>

namespace gb::decisions {
namespace {
constexpr std::uint64_t RetainMs = 120000, TtlMs = 600000;
Bytes canonical(Frame f) {
    f.connection.fill(1);
    f.sequence = 1;
    std::sort(f.fields.begin(), f.fields.end(),
              [](const auto &a, const auto &b) { return a.tag < b.tag; });
    Bytes b;
    if (encode(f, b) != Error::Ok)
        return {};
    return b;
}
bool next(std::uint64_t &counter) {
    if (counter == UINT64_MAX)
        return false;
    ++counter;
    return true;
}
} // namespace
Engine::Engine(Id epoch, Id boot, JournalSink &journal, EffectBackend &backend, std::uint16_t minor)
    : epoch_(epoch), boot_(boot), journal_(journal), backend_(backend), minor_(minor) {
    if (zero(epoch) || zero(boot) || (minor != 1 && minor != 2))
        recovery_ = true;
}
bool Engine::activate(Profile p, bool evidence, std::uint64_t now) {
    // Sólo la composición nativa fija evidence; no existe un campo wire equivalente.
    if (!evidence || p.state != 1 || zero(p.account) || zero(p.logon) || !p.generation ||
        p.generation < profile_.generation ||
        (profile_.state == 1 && p.generation == profile_.generation))
        return false;
    invalidateProfile(0, now);
    profile_ = p;
    return true;
}
void Engine::stale(Pending &p, std::uint64_t now) {
    if (p.record.state != ii::RequestState::Pending)
        return;
    p.record.state = ii::RequestState::Stale;
    p.record.ttl = 0;
    p.terminalAt = now;
    if (!next(p.record.authority))
        recovery_ = true;
}
void Engine::invalidateProfile(std::uint8_t state, std::uint64_t now) {
    profile_.state = state <= 2 ? state : 0;
    if (!next(profile_.generation))
        recovery_ = true;
    for (auto &pair : pending_)
        stale(pair.second, now);
    if (!next(gaps_))
        recovery_ = true;
}
void Engine::expire(std::uint64_t now) {
    for (auto it = pending_.begin(); it != pending_.end();) {
        auto &p = it->second;
        if (p.record.state == ii::RequestState::Pending && now >= p.deadline) {
            p.record.state = ii::RequestState::Expired;
            p.record.ttl = 0;
            p.terminalAt = now;
            if (!next(p.record.authority))
                recovery_ = true;
        }
        if (p.record.state != ii::RequestState::Pending && now >= p.terminalAt &&
            now - p.terminalAt >= RetainMs)
            it = pending_.erase(it);
        else
            ++it;
    }
}
Error Engine::observe(const VerifiedDrop &d, std::uint64_t now) {
    expire(now);
    const auto &r = d.record;
    if (recovery_ || profile_.state != 1 || !d.ownLedger || !d.appIdPresent || !d.userIdPresent ||
        !d.accountMatches || r.profileGeneration != profile_.generation || !ii::eligible(r, minor_)) {
        if (!next(gaps_))
            recovery_ = true;
        return Error::IdentityUnavailable;
    }
    // Agrupa sólo autoridad idéntica; no interpreta requestId de otro intento como mandato.
    for (auto &pair : pending_) {
        auto &p = pair.second;
        auto &old = p.record;
        if (old.state != ii::RequestState::Pending || old.selector != r.selector ||
            old.flow != r.flow || (minor_ == 2 && old.origin != r.origin))
            continue;
        if (old.selectorRevision != r.selectorRevision ||
            old.profileGeneration != r.profileGeneration || old.desired != r.desired) {
            stale(p, now);
            continue;
        }
        if (old.observation == UINT64_MAX) {
            if (!next(gaps_))
                recovery_ = true;
            return Error::Ok;
        }
        ++old.observation;
        old.lastUtc = r.lastUtc;
        old.presence = (old.presence & ~8ull) | (r.presence & 8ull);
        old.eventSequence = r.eventSequence;
        return Error::Ok;
    }
    if (r.desired != desired_)
        return Error::Stale;
    if (pending_.size() >= 512 || pending_.count(r.request) || now > UINT64_MAX - TtlMs)
        return Error::Capacity;
    Pending p;
    p.record = r;
    p.record.authority = 1;
    p.record.observation = 1;
    p.record.ttl = static_cast<std::uint32_t>(TtlMs);
    p.deadline = now + TtlMs;
    pending_.emplace(r.request, std::move(p));
    return Error::Ok;
}
std::optional<PendingRecord> Engine::lookup(const Id &id, std::uint64_t now) {
    expire(now);
    auto it = pending_.find(id);
    if (it == pending_.end())
        return {};
    auto r = it->second.record;
    if (r.state == ii::RequestState::Pending)
        r.ttl = static_cast<std::uint32_t>(it->second.deadline - now);
    return r;
}
bool Engine::persist() {
    std::vector<CommandEntry> rows;
    for (const auto &pair : commands_)
        rows.push_back(pair.second);
    return journal_.persist(rows);
}
std::optional<PendingRecord> Engine::pendingBySelector(Id selector, std::uint8_t flow,
                                                       std::uint64_t now) {
    expire(now);
    for (auto &pair : pending_)
        if (pair.second.record.selector == selector && pair.second.record.flow == flow &&
            pair.second.record.state == ii::RequestState::Pending)
            return lookup(pair.first, now);
    return {};
}
std::vector<PendingRecord> Engine::pendingRows(std::uint64_t now) {
    expire(now);
    std::vector<PendingRecord> out;
    for (auto &pair : pending_)
        if (pair.second.record.state == ii::RequestState::Pending)
            out.push_back(*lookup(pair.first, now));
    return out;
}
bool Engine::initializeRevision(std::uint64_t desired, bool readback) {
    if (!readback || !pending_.empty())
        return false;
    for (const auto &pair : commands_)
        if (pair.second.state != State::Applied)
            return false;
    desired_ = desired;
    recovery_ = false;
    return true;
}
bool Engine::advanceRevision(std::uint64_t desired, bool readback, std::uint64_t now) {
    if (!readback || desired <= desired_) { recovery_ = true; return false; }
    for (auto &pair : pending_) stale(pair.second, now);
    desired_ = desired;
    return !recovery_;
}
Result Engine::result(const CommandEntry &e, bool replay) const {
    // Los resultados históricos no aseguran efecto después de recuperación/restart.
    const bool uncertainProof = e.state == State::AppliedUnrecorded &&
                                e.commandEpoch == epoch_ && e.effectiveKnown &&
                                backend_.currentProof(e.effective);
    bool unknown = recovery_ && !uncertainProof;
    return {backend_.actualOs() && !unknown && e.effectiveKnown,
            e.error,
            e.state,
            e.desired,
            unknown ? 0 : e.effective,
            unknown ? false : e.effectiveKnown,
            replay};
}
Result Engine::commit(const Frame &f, const VerifiedControl &a, std::uint64_t now) {
    Result fail;
    fail.desired = desired_;
    const auto &principal = a.account;
    if (!a.highAdministrator || !a.fullServerToken || profile_.state != 1 || zero(principal) ||
        principal != profile_.account || a.logon != profile_.logon ||
        a.profileGeneration != profile_.generation) {
        fail.error = Error::Unauthorized;
        return fail;
    }
    if (f.minor != minor_ || f.type != Type::CommitDecision || wire::validate(f) != Error::Ok) {
        fail.error = Error::Malformed;
        return fail;
    }
    auto bytes = canonical(f);
    if (idValue(f, Tag::ServiceEpoch) != epoch_ ||
        get(f, Tag::ProfileGeneration) != profile_.generation) {
        fail.error = Error::Stale;
        return fail;
    }
    auto prior = commands_.find(f.correlation);
    if (prior != commands_.end()) {
        if (prior->second.principal != principal || prior->second.logon != a.logon ||
            prior->second.profileGeneration != a.profileGeneration ||
            prior->second.payload != bytes || prior->second.accountSid != a.accountSid ||
            prior->second.logonSid != a.logonSid || prior->second.sessionId != a.sessionId) {
            fail.error = Error::Conflict;
            return fail;
        }
        return result(prior->second, true);
    }
    if (recovery_) {
        fail.error = Error::RecoveryRequired;
        return fail;
    }
    if (idValue(f, Tag::ServiceEpoch) != epoch_ || profile_.state != 1 ||
        get(f, Tag::ProfileGeneration) != profile_.generation) {
        fail.error = Error::Stale;
        return fail;
    }
    auto row = lookup(idValue(f, Tag::RequestId), now);
    if (!row || !ii::eligible(*row, minor_) || row->authority != get(f, Tag::RequestVersion) ||
        row->selector != idValue(f, Tag::SelectorId) ||
        row->selectorRevision != get(f, Tag::SelectorRevision) ||
        row->desired != get(f, Tag::ExpectedDesiredRev) || row->desired != desired_) {
        fail.error = Error::Stale;
        return fail;
    }
    if(minor_ == 2 && get(f,Tag::PolicyDirection) != row->direction && get(f,Tag::PolicyDirection) != 3) {
        fail.error=Error::Conflict;return fail;
    }
    if (!backend_.ready()) {
        fail.error = Error::BackendUnavailable;
        return fail;
    }
    fail.error = journal_.admission(f);
    if (fail.error != Error::Ok)
        return fail;
    auto before = commands_;
    if (commands_.size() >= 4096) {
        auto oldest = commands_.end();
        for (auto it = commands_.begin(); it != commands_.end(); ++it) {
            auto &c = it->second;
            if (c.id != journal_.pinnedCommand() && (c.state == State::Applied || c.state == State::Failed) && now >= c.completedAt &&
                now - c.completedAt >= RetainMs &&
                (oldest == commands_.end() || c.completedAt < oldest->second.completedAt))
                oldest = it;
        }
        if (oldest == commands_.end()) {
            fail.error = Error::Capacity;
            return fail;
        }
        commands_.erase(oldest);
    }
    auto target = desired_;
    bool rule = get(f, Tag::Remember) != 0;
    if (rule && !next(target)) {
        commands_ = std::move(before);
        fail.error = Error::Capacity;
        return fail;
    }
    CommandEntry entry;
    entry.id = f.correlation;
    entry.principal = principal;
    entry.boot = boot_;
    entry.accountSid = a.accountSid;
    entry.logonSid = a.logonSid;
    entry.sessionId = a.sessionId;
    entry.logon = a.logon;
    entry.profileGeneration = a.profileGeneration;
    entry.commandEpoch = epoch_;
    entry.payload = std::move(bytes);
    entry.desired = target;
    commands_[entry.id] = entry;
    if (!persist()) {
        commands_ = std::move(before);
        if(journal_.suspendsMutations()) recovery_=true;
        fail.error = Error::StoreFailure;
        return fail;
    }
    auto &current = commands_.at(entry.id);
    if ((rule && !backend_.commit(f)) || !backend_.readback(target)) {
        current.state = State::RecoveryRequired;
        current.error = Error::RecoveryRequired;
        recovery_ = true;
        persist();
        return result(current);
    }
    desired_ = target;
    current.effective = target;
    current.effectiveKnown = true;
    current.state = State::Applied;
    current.completedAt = now;
    if (!persist()) {
        current.state = State::AppliedUnrecorded;
        current.error = Error::StoreFailure;
        recovery_ = true;
        return result(current);
    }
    auto &p = pending_.at(row->request);
    p.record.state = ii::RequestState::Resolved;
    p.record.ttl = 0;
    p.terminalAt = now;
    if (!next(p.record.authority))
        recovery_ = true;
    if (rule)
        for (auto &pair : pending_)
            stale(pair.second, now);
    return result(current);
}
std::optional<CommandEntry> Engine::command(const Id &id, const VerifiedControl &a) const {
    auto it = commands_.find(id);
    if (it == commands_.end() || !a.highAdministrator || !a.fullServerToken ||
        profile_.state != 1 || a.account != profile_.account || a.logon != profile_.logon ||
        a.profileGeneration != profile_.generation || it->second.principal != a.account ||
        it->second.logon != a.logon || it->second.accountSid != a.accountSid ||
        it->second.logonSid != a.logonSid || it->second.sessionId != a.sessionId)
        return {};
    auto c = it->second;
    if (recovery_ || c.commandEpoch != epoch_) {
        c.effective = 0;
        c.effectiveKnown = false;
    }
    return c;
}
bool Engine::restore(const std::vector<CommandEntry> &rows, std::uint64_t now) {
    if (!commands_.empty() || rows.size() > 4096)
        return false;
    std::map<Id, CommandEntry> restored;
    for (auto c : rows) {
        Frame f;
        auto state = static_cast<unsigned>(c.state);
        auto error = static_cast<unsigned>(c.error);
        if (state < 1 || state > 5 || error > 17 || c.effective > c.desired ||
            (!c.effectiveKnown && c.effective) || zero(c.id) || zero(c.principal) ||
            zero(c.logon) || !c.profileGeneration || zero(c.commandEpoch) ||
            decode(c.payload, f) != Error::Ok || f.type != Type::CommitDecision ||
            f.correlation != c.id || canonical(f) != c.payload ||
            idValue(f, Tag::ServiceEpoch) != c.commandEpoch ||
            get(f, Tag::ProfileGeneration) != c.profileGeneration ||
            !restored.emplace(c.id, c).second)
            return false;
        const auto expected = get(f, Tag::ExpectedDesiredRev);
        const bool rule = get(f, Tag::Remember) != 0;
        if ((rule && expected == UINT64_MAX) || c.desired != expected + (rule ? 1 : 0) ||
            (c.effectiveKnown && c.effective != c.desired) ||
            (c.state == State::Prepared &&
             (c.error != Error::Ok || c.effectiveKnown || c.completedAt)) ||
            (c.state == State::Applied && (c.error != Error::Ok || !c.effectiveKnown)) ||
            (c.state == State::AppliedUnrecorded &&
             (c.error != Error::StoreFailure || !c.effectiveKnown)))
            return false;
        // Los relojes de un boot/servicio anterior no reducen el mínimo de retención.
        if (c.state == State::Applied || c.state == State::Failed)
            restored.at(c.id).completedAt = now;
    }
    commands_ = std::move(restored);
    recovery_ = true;
    return true;
}
} // namespace gb::decisions
