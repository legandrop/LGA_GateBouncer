#include "snapshot_iii.h"
#include "effects_ii.h"
#include <algorithm>
#include <set>

namespace gb::directional {
namespace {
void append(Bytes &b, const Bytes &v) { b.insert(b.end(), v.begin(), v.end()); }
template <std::size_t N> void append(Bytes &b, const std::array<std::uint8_t, N> &v) {
    b.insert(b.end(), v.begin(), v.end());
}
void append(Bytes &b, std::uint64_t v, std::size_t w) { append(b, integer(v, w)); }
std::uint64_t n(const Bytes &b, std::size_t p, std::size_t w) {
    return number({Tag::Text, true, Bytes(b.begin() + p, b.begin() + p + w)});
}
void put(Bytes &b, std::size_t p, std::uint64_t v, std::size_t w) {
    auto x = integer(v, w);
    std::copy(x.begin(), x.end(), b.begin() + p);
}
template <std::size_t N> void put(Bytes &b, std::size_t p, const std::array<std::uint8_t, N> &v) {
    std::copy(v.begin(), v.end(), b.begin() + p);
}
template <std::size_t N> std::array<std::uint8_t, N> array(const Bytes &b, std::size_t p) {
    std::array<std::uint8_t, N> v{};
    std::copy_n(b.begin() + p, N, v.begin());
    return v;
}
bool zeros(const Bytes &b, std::size_t p, std::size_t w) {
    return std::all_of(b.begin() + p, b.begin() + p + w, [](auto c) { return c == 0; });
}
bool hashValid(const Bytes &b) {
    if (b.size() < 32)
        return false;
    auto hash = native::digest(Bytes(b.begin(), b.end() - 32));
    return std::equal(hash.begin(), hash.end(), b.end() - 32);
}
void finish(Bytes &b) {
    put(b, 8, b.size() + 32, 4);
    append(b, native::digest(b));
}
Bytes prefix(const decisions::CommandEntry &c) {
    Bytes b(128);
    put(b, 0, c.id);
    put(b, 16, c.commandEpoch);
    put(b, 32, c.principal);
    put(b, 48, c.logon);
    put(b, 64, c.profileGeneration, 8);
    put(b, 72, c.desired, 8);
    put(b, 80, c.effective, 8);
    put(b, 88, c.completedAt, 8);
    put(b, 96, c.boot);
    b[112] = static_cast<std::uint8_t>(c.state);
    b[113] = c.effectiveKnown ? 1 : 0;
    put(b, 114, static_cast<unsigned>(c.error), 2);
    put(b, 116, c.payload.size(), 4);
    put(b, 120, c.accountSid.size(), 2);
    put(b, 122, c.logonSid.size(), 2);
    put(b, 124, c.sessionId, 4);
    return b;
}
Digest admission(const Entry &e) {
    const auto &c = e.command;
    auto p = prefix(c);
    Bytes b = {'G', 'B', 'S', '3', 'C', 'M', 'D', '1'};
    b.insert(b.end(), p.begin(), p.begin() + 80);
    b.insert(b.end(), p.begin() + 96, p.begin() + 112);
    b.insert(b.end(), p.begin() + 124, p.end());
    append(b, c.payload.size(), 4);
    append(b, c.payload);
    append(b, c.accountSid.size(), 2);
    append(b, c.accountSid);
    append(b, c.logonSid.size(), 2);
    append(b, c.logonSid);
    append(b, e.effect, 1);
    append(b, e.projected.size(), 4);
    append(b, e.projected);
    append(b, e.target);
    return native::digest(b);
}
bool commandValid(const decisions::CommandEntry &c, Frame &f) {
    if (zero(c.id) || zero(c.commandEpoch) || zero(c.principal) || zero(c.logon) || zero(c.boot) ||
        !c.profileGeneration || c.payload.size() > 512 || !decisions::validSidBytes(c.accountSid) ||
        !decisions::validSidBytes(c.logonSid) || decode(c.payload, f) != Error::Ok ||
        f.minor != 2 || f.type < Type::CommitDecision || f.type > Type::RevokeRule ||
        f.correlation != c.id || f.sequence != 1 ||
        f.connection != Id{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1} ||
        idValue(f, Tag::ServiceEpoch) != c.commandEpoch ||
        get(f, Tag::ProfileGeneration) != c.profileGeneration)
        return false;
    for (std::size_t i = 1; i < f.fields.size(); ++i)
        if (f.fields[i - 1].tag >= f.fields[i].tag)
            return false;
    bool permanent = f.type != Type::CommitDecision || get(f, Tag::Remember) != 0;
    auto expected = get(f, Tag::ExpectedDesiredRev);
    if ((permanent && expected == UINT64_MAX) || c.desired != expected + (permanent ? 1 : 0))
        return false;
    auto state = static_cast<unsigned>(c.state), error = static_cast<unsigned>(c.error);
    return state >= 1 && state <= 5 && error <= 17 && c.effective <= c.desired &&
           (!c.effectiveKnown ? c.effective == 0 : c.effective == c.desired) &&
           (c.state != State::Prepared ||
            (c.error == Error::Ok && !c.effectiveKnown && !c.completedAt)) &&
           (c.state != State::Applied || (c.error == Error::Ok && c.effectiveKnown)) &&
           (c.state != State::AppliedUnrecorded ||
            (c.error == Error::StoreFailure && c.effectiveKnown));
}
bool legacy(const Bytes &envelope, decisions::CommandEntry &out) {
    if (envelope.size() < 136 || n(envelope, 0, 4) != envelope.size() - 8 ||
        n(envelope, 4, 2) != 1 || n(envelope, 6, 2) != 1 || envelope.size() > 1032)
        return false;
    Bytes b(64);
    b[0] = 'G';
    b[1] = 'B';
    b[2] = 'J';
    b[3] = '2';
    put(b, 4, 1, 2);
    put(b, 12, 1, 4);
    put(b, 16, 1, 8);
    put(b, 24, n(envelope, 80, 8), 8);
    b[32] = 1;
    append(b, envelope);
    finish(b);
    decisions::JournalSnapshot s;
    if (!decisions::parseJournal(b, s) || s.entries.size() != 1)
        return false;
    out = s.entries.front();
    return true;
}
Bytes journal(const Snapshot &s) {
    Bytes b(64);
    b[0] = 'G';
    b[1] = 'B';
    b[2] = 'J';
    b[3] = '2';
    put(b, 4, 2, 2);
    put(b, 12, s.entries.size(), 4);
    put(b, 16, s.sequence, 8);
    put(b, 24, s.desired, 8);
    put(b, 32, s.writerEpoch);
    std::set<Id> ids;
    for (const auto &e : s.entries) {
        if (!entryValid(e) || !ids.insert(e.command.id).second)
            return {};
        if (!e.legacyEnvelope.empty()) {
            append(b, e.legacyEnvelope);
            continue;
        }
        Bytes p = prefix(e.command);
        p.resize(232);
        put(p, 128, e.projected.size(), 4);
        p[132] = e.effect;
        p[133] = 1;
        put(p, 136, e.admission);
        put(p, 168, e.projection);
        put(p, 200, e.target);
        append(p, e.command.payload);
        append(p, e.projected);
        append(p, e.command.accountSid);
        append(p, e.command.logonSid);
        if (p.size() > 1536)
            return {};
        append(b, p.size(), 4);
        append(b, 1, 2);
        append(b, 2, 2);
        append(b, p);
        if (b.size() > decisions::MaxJournalBytes - 32)
            return {};
    }
    if (b.size() > decisions::MaxJournalBytes - 32)
        return {};
    finish(b);
    return b;
}
bool readJournal(const Bytes &b, Snapshot &s) {
    if (b.size() < 96 || b.size() > decisions::MaxJournalBytes || !hashValid(b) ||
        Bytes(b.begin(), b.begin() + 4) != Bytes{'G', 'B', 'J', '2'} || n(b, 4, 2) != 2 ||
        n(b, 6, 2) || n(b, 8, 4) != b.size() || n(b, 12, 4) > 4096 || n(b, 16, 8) != s.sequence ||
        n(b, 24, 8) != s.desired || !zeros(b, 48, 16) || zero(array<16>(b, 32)))
        return false;
    s.writerEpoch = array<16>(b, 32);
    std::size_t offset = 64;
    std::set<Id> ids;
    for (std::size_t i = 0; i < n(b, 12, 4); ++i) {
        if (offset > b.size() - 32 || b.size() - 32 - offset < 8)
            return false;
        auto size = n(b, offset, 4), version = n(b, offset + 6, 2);
        if (n(b, offset + 4, 2) != 1 || size > (version == 1 ? 1024u : 1536u) ||
            size > b.size() - 32 - offset - 8)
            return false;
        Entry e;
        if (version == 1) {
            e.legacyEnvelope = Bytes(b.begin() + offset, b.begin() + offset + 8 + size);
            if (!legacy(e.legacyEnvelope, e.command))
                return false;
        } else if (version == 2) {
            if (size < 232)
                return false;
            Bytes p(b.begin() + offset + 8, b.begin() + offset + 8 + size);
            auto &c = e.command;
            c.id = array<16>(p, 0);
            c.commandEpoch = array<16>(p, 16);
            c.principal = array<16>(p, 32);
            c.logon = array<16>(p, 48);
            c.profileGeneration = n(p, 64, 8);
            c.desired = n(p, 72, 8);
            c.effective = n(p, 80, 8);
            c.completedAt = n(p, 88, 8);
            c.boot = array<16>(p, 96);
            c.state = static_cast<State>(p[112]);
            c.effectiveKnown = p[113] == 1;
            c.error = static_cast<Error>(n(p, 114, 2));
            auto command = n(p, 116, 4), account = n(p, 120, 2), logon = n(p, 122, 2),
                 projected = n(p, 128, 4);
            if (p[113] > 1 || command > 512 || projected > 512 || account > 68 || logon > 68 ||
                232 + command + projected + account + logon != size || p[133] != 1 ||
                !zeros(p, 134, 2))
                return false;
            c.sessionId = static_cast<std::uint32_t>(n(p, 124, 4));
            e.effect = p[132];
            e.admission = array<32>(p, 136);
            e.projection = array<32>(p, 168);
            e.target = array<32>(p, 200);
            std::size_t at = 232;
            auto take = [&](std::uint64_t count) {
                Bytes v(p.begin() + at, p.begin() + at + count);
                at += static_cast<std::size_t>(count);
                return v;
            };
            c.payload = take(command);
            e.projected = take(projected);
            c.accountSid = take(account);
            c.logonSid = take(logon);
            if (!entryValid(e))
                return false;
        } else
            return false;
        if (!ids.insert(e.command.id).second)
            return false;
        s.entries.push_back(std::move(e));
        offset += 8 + static_cast<std::size_t>(size);
    }
    return offset == b.size() - 32;
}
} // namespace
bool rulesValid(const std::vector<Rule> &rules) {
    if (rules.size() > 4096)
        return false;
    std::set<Id> ids;
    for (std::size_t i = 0; i < rules.size(); ++i) {
        const auto &r = rules[i];
        if (zero(r.id) || zero(r.selector) || !ids.insert(r.id).second || r.revision != 1 ||
            r.selectorRevision != 1 || r.action < 1 || r.action > 2 || r.direction < 1 ||
            r.direction > 3 ||
            r.mode != (r.action == 1 || r.direction == 2 ? 0
                       : r.direction == 1                ? 1
                                                         : 2) ||
            r.appId.size() < 4 || r.appId.size() > 32768 || r.appId.size() % 2 ||
            r.appId[0] != '\\' || r.appId[1] != 0)
            return false;
        for (std::size_t j = 0; j < i; ++j)
            if ((rules[j].selector == r.selector || rules[j].appId == r.appId) &&
                (rules[j].direction & r.direction))
                return false;
    }
    return true;
}
bool sections(const Snapshot &s, Bytes &policy, Bytes &directions) {
    if (!rulesValid(s.rules))
        return false;
    auto rules = s.rules;
    std::sort(rules.begin(), rules.end(), [](const auto &a, const auto &b) { return a.id < b.id; });
    Bytes p(16), d(24);
    p[0] = 'P';
    p[1] = 'R';
    p[2] = 'L';
    p[3] = '3';
    put(p, 4, 1, 2);
    put(p, 8, rules.size(), 4);
    put(p, 12, 53, 2);
    d[0] = 'D';
    d[1] = 'I';
    d[2] = 'R';
    d[3] = '1';
    put(d, 4, 1, 2);
    put(d, 6, 40, 2);
    put(d, 8, rules.size(), 4);
    put(d, 16, s.desired, 8);
    for (const auto &r : rules) {
        append(p, r.id);
        append(p, r.selector);
        append(p, r.revision, 8);
        append(p, r.selectorRevision, 8);
        append(p, r.action, 1);
        append(p, r.appId.size(), 4);
        append(p, r.appId);
        append(d, r.id);
        append(d, r.selector);
        append(d, r.direction, 1);
        append(d, r.mode, 1);
        d.resize(d.size() + 6);
        if (p.size() > 16 * 1024 * 1024)
            return false;
    }
    policy = std::move(p);
    directions = std::move(d);
    return true;
}
Digest targetDigest(const Snapshot &s) {
    Bytes p, d;
    if (!sections(s, p, d))
        throw std::runtime_error("Conjunto direccional invalido");
    Bytes b = {'G', 'B', 'S', '3', 'S', 'E', 'T', '1'};
    append(b, s.desired, 8);
    append(b, p.size(), 4);
    append(b, p);
    append(b, d.size(), 4);
    append(b, d);
    return native::digest(b);
}
bool project(const Frame &f, Bytes &out, std::uint8_t &effect) {
    if (f.minor != 2 || validate(f) != Error::Ok || f.type < Type::CommitDecision ||
        f.type > Type::RevokeRule)
        return false;
    if (f.type == Type::CommitDecision && !get(f, Tag::Remember)) {
        effect = 0;
        out.clear();
        return get(f, Tag::Decision) == 1;
    }
    effect = f.type == Type::RevokeRule ? 11 : 10;
    std::vector<Field> fields = {value(Tag::ExpectedDesiredRev, get(f, Tag::ExpectedDesiredRev))};
    if (effect == 10) {
        fields.push_back(value(Tag::Decision, get(f, Tag::Decision), 1));
        fields.push_back(value(Tag::ScopeKind, 1, 1));
        fields.push_back(value(Tag::SelectorId, idValue(f, Tag::SelectorId)));
        fields.push_back(value(Tag::PolicyDirection, get(f, Tag::PolicyDirection), 1));
    } else {
        fields.push_back(value(Tag::RuleId, idValue(f, Tag::RuleId)));
        fields.push_back(value(Tag::RuleRevision, get(f, Tag::RuleRevision)));
    }
    Bytes b(64);
    b[0] = 'G';
    b[1] = 'B';
    b[2] = 'C';
    b[3] = '1';
    put(b, 4, 1, 2);
    put(b, 6, 2, 2);
    put(b, 8, effect, 2);
    b[16] = 1;
    put(b, 32, 2, 8);
    put(b, 40, f.correlation);
    for (const auto &v : fields) {
        append(b, static_cast<unsigned>(v.tag), 2);
        append(b, 1, 2);
        append(b, v.bytes.size(), 4);
        append(b, v.bytes);
    }
    put(b, 12, b.size() - 64, 4);
    out = std::move(b);
    return true;
}
bool entryValid(const Entry &e) {
    try {
        if (!e.legacyEnvelope.empty()) {
            decisions::CommandEntry c;
            return legacy(e.legacyEnvelope, c) && prefix(c) == prefix(e.command) &&
                   c.payload == e.command.payload && c.accountSid == e.command.accountSid &&
                   c.logonSid == e.command.logonSid && e.projected.empty() && e.effect == 0 &&
                   e.admission == Digest{} && e.projection == Digest{} && e.target == Digest{};
        }
        Frame f;
        Bytes p;
        std::uint8_t effect;
        return commandValid(e.command, f) && project(f, p, effect) && p == e.projected &&
               effect == e.effect && e.projected.size() <= 512 &&
               e.projection == (effect ? native::digest(p) : Digest{}) &&
               e.admission == admission(e);
    } catch (...) {
        return false;
    }
}
bool bindEntry(Entry &e, const Digest &target) {
    try {
        Frame f;
        if (!e.legacyEnvelope.empty() || !commandValid(e.command, f) ||
            !project(f, e.projected, e.effect))
            return false;
        e.target = target;
        e.projection = e.effect ? native::digest(e.projected) : Digest{};
        e.admission = admission(e);
        return entryValid(e);
    } catch (...) {
        return false;
    }
}
bool serialize(const Snapshot &s, Bytes &out) {
    try {
        if (!s.sequence || zero(s.writerEpoch) || s.entries.size() > 4096 ||
            s.effective > s.desired || (!s.effectiveKnown && s.effective) ||
            static_cast<unsigned>(s.state) < 1 || static_cast<unsigned>(s.state) > 5)
            return false;
        Bytes p, d;
        if (!sections(s, p, d))
            return false;
        auto j = journal(s);
        if (j.empty())
            return false;
        Bytes b(160);
        b[0] = 'G';
        b[1] = 'B';
        b[2] = 'S';
        b[3] = '3';
        put(b, 4, 3, 2);
        put(b, 12, 160, 4);
        put(b, 16, s.sequence, 8);
        put(b, 24, s.desired, 8);
        put(b, 32, s.effective, 8);
        b[40] = s.effectiveKnown ? 1 : 0;
        b[41] = static_cast<std::uint8_t>(s.state);
        put(b, 48, s.active);
        put(b, 64, s.activeProjection);
        put(b, 96, p.size(), 4);
        put(b, 100, d.size(), 4);
        put(b, 104, j.size(), 4);
        put(b, 112, s.activeAdmission);
        append(b, p);
        append(b, d);
        append(b, j);
        if (b.size() > MaxSnapshotBytes - 32)
            return false;
        finish(b);
        out = std::move(b);
        return true;
    } catch (...) {
        return false;
    }
}
bool parse(const Bytes &b, Snapshot &out) {
    try {
        if (b.size() < 160 + 16 + 24 + 96 + 32 || b.size() > MaxSnapshotBytes || !hashValid(b) ||
            Bytes(b.begin(), b.begin() + 4) != Bytes{'G', 'B', 'S', '3'} || n(b, 4, 2) != 3 ||
            n(b, 6, 2) || n(b, 8, 4) != b.size() || n(b, 12, 4) != 160 || !zeros(b, 42, 6) ||
            !zeros(b, 108, 4) || !zeros(b, 144, 16) || b[40] > 1)
            return false;
        auto ps = n(b, 96, 4), ds = n(b, 100, 4), js = n(b, 104, 4);
        if (ps < 16 || ps > 16 * 1024 * 1024 || ds < 24 || ds > 163864 || js < 96 ||
            js > decisions::MaxJournalBytes || 160 + ps + ds + js + 32 != b.size())
            return false;
        Snapshot s;
        s.sequence = n(b, 16, 8);
        s.desired = n(b, 24, 8);
        s.effective = n(b, 32, 8);
        s.effectiveKnown = b[40] == 1;
        s.state = static_cast<State>(b[41]);
        s.active = array<16>(b, 48);
        s.activeProjection = array<32>(b, 64);
        s.activeAdmission = array<32>(b, 112);
        Bytes p(b.begin() + 160, b.begin() + 160 + ps),
            d(b.begin() + 160 + ps, b.begin() + 160 + ps + ds);
        if (Bytes(p.begin(), p.begin() + 4) != Bytes{'P', 'R', 'L', '3'} || n(p, 4, 2) != 1 ||
            n(p, 6, 2) || n(p, 12, 2) != 53 || n(p, 14, 2) ||
            Bytes(d.begin(), d.begin() + 4) != Bytes{'D', 'I', 'R', '1'} || n(d, 4, 2) != 1 ||
            n(d, 6, 2) != 40 || n(d, 12, 4) || n(d, 16, 8) != s.desired || n(p, 8, 4) > 4096 ||
            n(p, 8, 4) != n(d, 8, 4) || 24 + 40 * n(d, 8, 4) != ds)
            return false;
        std::size_t at = 16;
        for (std::size_t i = 0; i < n(p, 8, 4); ++i) {
            if (at > p.size() || p.size() - at < 53)
                return false;
            auto count = n(p, at + 49, 4);
            if (count > 32768 || count > p.size() - at - 53)
                return false;
            Rule r;
            r.id = array<16>(p, at);
            r.selector = array<16>(p, at + 16);
            r.revision = n(p, at + 32, 8);
            r.selectorRevision = n(p, at + 40, 8);
            r.action = p[at + 48];
            r.appId = Bytes(p.begin() + at + 53, p.begin() + at + 53 + count);
            auto q = 24 + 40 * i;
            if (r.id != array<16>(d, q) || r.selector != array<16>(d, q + 16) ||
                !zeros(d, q + 34, 6) || (!s.rules.empty() && s.rules.back().id >= r.id))
                return false;
            r.direction = d[q + 32];
            r.mode = d[q + 33];
            s.rules.push_back(std::move(r));
            at += 53 + static_cast<std::size_t>(count);
        }
        if (at != p.size() || !rulesValid(s.rules) ||
            !readJournal(Bytes(b.begin() + 160 + ps + ds, b.end() - 32), s))
            return false;
        if (!zero(s.active)) {
            auto active = std::find_if(s.entries.begin(), s.entries.end(),
                                       [&](const auto &e) { return e.command.id == s.active; });
            if (active == s.entries.end() || !active->legacyEnvelope.empty() || !active->effect ||
                active->command.desired != s.desired || active->target != targetDigest(s) ||
                active->projection != s.activeProjection || active->admission != s.activeAdmission)
                return false;
        }
        Bytes encoded;
        if (!serialize(s, encoded) || encoded != b)
            return false;
        out = std::move(s);
        return true;
    } catch (...) {
        return false;
    }
}
bool runtimeAdmissible(const Snapshot &s) {
    try {
        if (zero(s.active))
            return s.activeProjection == Digest{} && s.activeAdmission == Digest{} &&
                   s.rules.empty() && s.entries.empty() && !s.desired && !s.effective &&
                   !s.effectiveKnown && s.state == State::RecoveryRequired;
        const Entry *active = nullptr;
        for (const auto &e : s.entries)
            if (e.command.id == s.active) {
                if (active)
                    return false;
                active = &e;
            }
        if (!active || !active->legacyEnvelope.empty() || !active->effect ||
            active->command.desired != s.desired || active->projection != s.activeProjection ||
            active->admission != s.activeAdmission || active->target != targetDigest(s))
            return false;
        if (s.state == State::Applied || s.state == State::AppliedUnrecorded)
            return active->command.state == s.state && s.effectiveKnown &&
                   s.effective == s.desired && active->command.effectiveKnown &&
                   active->command.effective == s.effective;
        if (s.state == State::Prepared)
            return active->command.state == State::Prepared;
        return s.state == State::RecoveryRequired && !s.effectiveKnown && !s.effective;
    } catch (...) {
        return false;
    }
}
bool importLegacy(const Bytes &policy, const Bytes *journalBytes, const Id &writer, Snapshot &out) {
    gb::Snapshot legacyPolicy;
    if (zero(writer) || !parseSnapshot(policy, legacyPolicy))
        return false;
    Snapshot s;
    s.writerEpoch = writer;
    s.desired = legacyPolicy.desired;
    s.legacyConsistent = legacyPolicy.state == State::Applied && legacyPolicy.effectiveKnown &&
                         legacyPolicy.effective == legacyPolicy.desired;
    if (!legacyPolicy.desired && legacyPolicy.rules.empty() && zero(legacyPolicy.command) &&
        legacyPolicy.commandDigest == Digest{})
        s.legacyConsistent = true;
    for (const auto &r : legacyPolicy.rules)
        s.rules.push_back({r.id, r.selector, 1, 1, r.decision, 3,
                           static_cast<std::uint8_t>(r.decision == 1 ? 0 : 2), r.appId});
    if (journalBytes) {
        decisions::JournalSnapshot j;
        if (!decisions::parseJournal(*journalBytes, j))
            return false;
        std::size_t at = 64;
        for (const auto &c : j.entries) {
            auto count = n(*journalBytes, at, 4);
            Entry e;
            e.command = c;
            e.legacyEnvelope =
                Bytes(journalBytes->begin() + at, journalBytes->begin() + at + 8 + count);
            s.entries.push_back(std::move(e));
            at += 8 + static_cast<std::size_t>(count);
        }
        for (const auto &e : s.entries)
            if (e.command.state != State::Applied && e.command.state != State::Failed)
                s.legacyConsistent = false;
        if (!zero(legacyPolicy.command)) {
            auto it = std::find_if(s.entries.begin(), s.entries.end(), [&](const auto &e) {
                return e.command.id == legacyPolicy.command;
            });
            if (it != s.entries.end()) {
                Frame command, projected;
                Bytes bytes;
                if (it->command.state != State::Applied ||
                    it->command.desired != legacyPolicy.desired ||
                    decode(it->command.payload, command) != Error::Ok ||
                    !decisions::projectPermanent(command, projected, bytes) ||
                    native::digest(bytes) != legacyPolicy.commandDigest)
                    s.legacyConsistent = false;
            }
        }
    }
    // Cargar legado es sólo lectura; no afirma readback ni reserializa sus entradas.
    out = std::move(s);
    return rulesValid(out.rules);
}
} // namespace gb::directional
