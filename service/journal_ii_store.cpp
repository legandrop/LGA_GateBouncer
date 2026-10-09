#include "journal_ii_store.h"
#include <algorithm>
#include <set>

namespace gb::decisions {
namespace {
void put(Bytes &b, std::uint64_t v, std::size_t width) {
    auto n = integer(v, width);
    b.insert(b.end(), n.begin(), n.end());
}
void put(Bytes &b, const Id &id) { b.insert(b.end(), id.begin(), id.end()); }
struct Reader {
    const Bytes &bytes;
    std::size_t position = 0;
    bool good = true;
    Bytes take(std::size_t count) {
        if (position > bytes.size() || count > bytes.size() - position) {
            good = false;
            return {};
        }
        Bytes b(bytes.begin() + position, bytes.begin() + position + count);
        position += count;
        return b;
    }
    std::uint64_t n(std::size_t width) { return number({Tag::Text, true, take(width)}); }
    Id id() {
        Id out{};
        auto b = take(16);
        if (good)
            std::copy(b.begin(), b.end(), out.begin());
        return out;
    }
};
bool canonical(const CommandEntry &e) {
    if (zero(e.id) || zero(e.commandEpoch) || zero(e.principal) || zero(e.logon) || zero(e.boot) ||
        !e.profileGeneration || e.payload.size() > 512 || !validSidBytes(e.accountSid) ||
        !validSidBytes(e.logonSid))
        return false;
    Frame f;
    if (decode(e.payload, f) != Error::Ok || f.minor != 1 || f.type != Type::CommitDecision ||
        f.correlation != e.id || f.sequence != 1 ||
        f.connection != Id{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1} ||
        idValue(f, Tag::ServiceEpoch) != e.commandEpoch ||
        get(f, Tag::ProfileGeneration) != e.profileGeneration)
        return false;
    for (std::size_t i = 1; i < f.fields.size(); ++i)
        if (f.fields[i - 1].tag >= f.fields[i].tag)
            return false;
    auto state = static_cast<unsigned>(e.state), error = static_cast<unsigned>(e.error);
    auto expected = get(f, Tag::ExpectedDesiredRev);
    bool rule = get(f, Tag::Remember) != 0;
    if ((rule && expected == UINT64_MAX) || e.desired != expected + (rule ? 1 : 0))
        return false;
    if (state < 1 || state > 5 || error > 17 || e.effective > e.desired ||
        (!e.effectiveKnown && e.effective))
        return false;
    if (e.effectiveKnown && e.effective != e.desired)
        return false;
    if (e.state == State::Prepared && (e.error != Error::Ok || e.effectiveKnown || e.completedAt))
        return false;
    if (e.state == State::Applied &&
        (e.error != Error::Ok || !e.effectiveKnown || e.effective != e.desired))
        return false;
    if (e.state == State::AppliedUnrecorded &&
        (e.error != Error::StoreFailure || !e.effectiveKnown || e.effective != e.desired))
        return false;
    return true;
}
} // namespace
bool validSidBytes(const Bytes &b) {
    return b.size() >= 8 && b[0] == SID_REVISION && b[1] <= SID_MAX_SUB_AUTHORITIES &&
           b.size() == 8 + std::size_t(b[1]) * 4 &&
           IsValidSid(const_cast<std::uint8_t *>(b.data()));
}
bool serializeJournal(const JournalSnapshot &s, Bytes &out) {
    if (zero(s.writerEpoch) || !s.sequence || s.entries.size() > 4096)
        return false;
    Bytes b = {'G', 'B', 'J', '2'};
    put(b, 1, 2);
    put(b, 0, 2);
    put(b, 0, 4);
    put(b, s.entries.size(), 4);
    put(b, s.sequence, 8);
    put(b, s.observedDesired, 8);
    put(b, s.writerEpoch);
    b.resize(64);
    std::set<Id> seen;
    for (const auto &e : s.entries) {
        if (!canonical(e) || !seen.insert(e.id).second)
            return false;
        Bytes p;
        put(p, e.id);
        put(p, e.commandEpoch);
        put(p, e.principal);
        put(p, e.logon);
        put(p, e.profileGeneration, 8);
        put(p, e.desired, 8);
        put(p, e.effective, 8);
        put(p, e.completedAt, 8);
        put(p, e.boot);
        put(p, static_cast<unsigned>(e.state), 1);
        put(p, e.effectiveKnown ? 1 : 0, 1);
        put(p, static_cast<unsigned>(e.error), 2);
        put(p, e.payload.size(), 4);
        put(p, e.accountSid.size(), 2);
        put(p, e.logonSid.size(), 2);
        put(p, e.sessionId, 4);
        p.insert(p.end(), e.payload.begin(), e.payload.end());
        p.insert(p.end(), e.accountSid.begin(), e.accountSid.end());
        p.insert(p.end(), e.logonSid.begin(), e.logonSid.end());
        if (p.size() > 1024 || p.size() + 8 + 32 > MaxJournalBytes - b.size())
            return false;
        put(b, p.size(), 4);
        put(b, 1, 2);
        put(b, 1, 2);
        b.insert(b.end(), p.begin(), p.end());
    }
    auto total = b.size() + 32;
    for (unsigned i = 0; i < 4; ++i)
        b[8 + i] = std::uint8_t(total >> (8 * i));
    try {
        auto hash = native::digest(b);
        b.insert(b.end(), hash.begin(), hash.end());
    } catch (...) {
        return false;
    }
    out = std::move(b);
    return true;
}
bool parseJournal(const Bytes &input, JournalSnapshot &out) {
    if (input.size() < 96 || input.size() > MaxJournalBytes)
        return false;
    Bytes b(input.begin(), input.end() - 32);
    try {
        auto hash = native::digest(b);
        if (!std::equal(hash.begin(), hash.end(), input.end() - 32))
            return false;
    } catch (...) {
        return false;
    }
    Reader r{b};
    if (r.take(4) != Bytes{'G', 'B', 'J', '2'} || r.n(2) != 1 || r.n(2) != 0 ||
        r.n(4) != input.size())
        return false;
    auto count = r.n(4);
    if (count > 4096)
        return false;
    JournalSnapshot s;
    s.sequence = r.n(8);
    s.observedDesired = r.n(8);
    s.writerEpoch = r.id();
    auto reserved = r.take(16);
    if (!r.good || std::any_of(reserved.begin(), reserved.end(), [](auto c) { return c != 0; }))
        return false;
    for (std::uint64_t i = 0; i < count; ++i) {
        auto size = r.n(4), type = r.n(2), version = r.n(2);
        if (!r.good || size < 128 || size > 1024 || type != 1 || version != 1)
            return false;
        auto p = r.take(static_cast<std::size_t>(size));
        if (!r.good)
            return false;
        Reader e{p};
        CommandEntry c;
        c.id = e.id();
        c.commandEpoch = e.id();
        c.principal = e.id();
        c.logon = e.id();
        c.profileGeneration = e.n(8);
        c.desired = e.n(8);
        c.effective = e.n(8);
        c.completedAt = e.n(8);
        c.boot = e.id();
        c.state = static_cast<State>(e.n(1));
        auto known = e.n(1);
        if (known > 1)
            return false;
        c.effectiveKnown = known != 0;
        c.error = static_cast<Error>(e.n(2));
        auto payload = e.n(4), account = e.n(2), logon = e.n(2);
        c.sessionId = static_cast<std::uint32_t>(e.n(4));
        if (payload > 512 || account > 68 || logon > 68 || 128 + payload + account + logon != size)
            return false;
        c.payload = e.take(static_cast<std::size_t>(payload));
        c.accountSid = e.take(static_cast<std::size_t>(account));
        c.logonSid = e.take(static_cast<std::size_t>(logon));
        if (!e.good || e.position != p.size() || !canonical(c))
            return false;
        s.entries.push_back(std::move(c));
    }
    if (!r.good || r.position != b.size())
        return false;
    Bytes reencoded;
    if (!serializeJournal(s, reencoded) || reencoded != input)
        return false;
    out = std::move(s);
    return true;
}
bool NativeJournal::load(JournalSnapshot &out, bool &exists) {
    Bytes b;
    if (!directory_.read(L"decisions-journal.bin", MaxJournalBytes, b, exists))
        return false;
    if (!exists) {
        out = {epoch_, 0, 0, {}};
        return true;
    }
    JournalSnapshot s;
    if (!parseJournal(b, s))
        return false;
    sequence_ = s.sequence;
    out = std::move(s);
    return true;
}
bool NativeJournal::persist(const std::vector<CommandEntry> &entries) {
    if (sequence_ == UINT64_MAX)
        return false;
    JournalSnapshot s;
    s.writerEpoch = epoch_;
    s.sequence = sequence_ + 1;
    s.entries = entries;
    s.observedDesired = observed_;
    Bytes b;
    if (!serializeJournal(s, b) || !directory_.replace(L"decisions-journal.bin", b))
        return false;
    ++sequence_;
    return true;
}
} // namespace gb::decisions
