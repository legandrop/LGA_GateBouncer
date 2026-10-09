#include "wire_ii.h"
#include <algorithm>
#include <limits>
#include <map>
#include <set>

namespace gb::wire::ii {
namespace {
using T = Tag;
using Schema = std::map<T, std::size_t>;
constexpr auto Variable = std::numeric_limits<std::size_t>::max();
std::uint64_t n(const Bytes &b, std::size_t offset, std::size_t width) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < width; ++i)
        v |= std::uint64_t(b[offset + i]) << (i * 8);
    return v;
}
Id id(const Bytes &b, std::size_t offset) {
    Id v{};
    std::copy_n(b.begin() + offset, 16, v.begin());
    return v;
}
void put(Bytes &b, std::size_t offset, std::uint64_t v, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i)
        b[offset + i] = std::uint8_t(v >> (i * 8));
}
void put(Bytes &b, std::size_t offset, const Id &v) {
    std::copy(v.begin(), v.end(), b.begin() + offset);
}
bool text(const Bytes &b) {
    if (!validUtf8(b))
        return false;
    for (auto c : b)
        if (c < 32 || c == 127)
            return false;
    // Bidi controls UTF-8 U+202A..E/U+2066..9 no forman texto de identidad.
    for (std::size_t i = 0; i + 2 < b.size(); ++i)
        if (b[i] == 0xe2 && ((b[i + 1] == 0x80 && b[i + 2] >= 0xaa && b[i + 2] <= 0xae) ||
                             (b[i + 1] == 0x81 && b[i + 2] >= 0xa6 && b[i + 2] <= 0xa9)))
            return false;
    return true;
}
bool strings(const Bytes &path, const Bytes &name, std::uint64_t presence) {
    return path.size() <= 4096 && name.size() <= 256 && text(path) && text(name) &&
           bool(presence & 1) == !path.empty() && bool(presence & 2) == !name.empty();
}
bool known(std::uint64_t presence, unsigned bit, std::uint64_t v) {
    return (presence & (1ull << bit)) ? v != 0 : v == 0;
}
bool known(std::uint64_t presence, unsigned bit, const Id &v) {
    return bool(presence & (1ull << bit)) != zero(v);
}
void envelope(Bytes &out, const Bytes &payload, unsigned type, unsigned version) {
    auto a = integer(payload.size(), 4);
    out.insert(out.end(), a.begin(), a.end());
    a = integer(type, 2);
    out.insert(out.end(), a.begin(), a.end());
    a = integer(version, 2);
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), payload.begin(), payload.end());
}
bool record(const Bytes &bytes, std::size_t &offset, unsigned type, unsigned version, std::size_t fixed,
            Bytes &payload) {
    if (offset > bytes.size() || bytes.size() - offset < 8)
        return false;
    auto size = n(bytes, offset, 4);
    if (n(bytes, offset + 4, 2) != type || n(bytes, offset + 6, 2) != version || size < fixed ||
        size > MaxRecordBytes || size > bytes.size() - offset - 8)
        return false;
    offset += 8;
    payload.assign(bytes.begin() + offset, bytes.begin() + offset + size);
    offset += static_cast<std::size_t>(size);
    return true;
}
Schema status() {
    return {{T::ServiceEpoch, 16},     {T::BootId, 16},           {T::Capabilities, 8}, {T::DesiredRev, 8},
            {T::EffectiveRev, 8},      {T::EffectiveKnown, 1},    {T::EngineState, 1},  {T::BackendMode, 1},
            {T::ProfileGeneration, 8}, {T::ReviewProfileState, 1}};
}
Schema schema(const Frame &f, Schema &optional) {
    switch (f.type) {
    case Type::Hello:
        return {{T::ClientRole, 1}};
    case Type::HelloAck:
        return status();
    case Type::GetStatus:
        return {};
    case Type::Status: {
        auto s = status();
        s[T::GapCount] = 8;
        optional = {{T::CollectorState, 1}, {T::SourceCoverage, 1}};
        return s;
    }
    case Type::ListRules:
    case Type::ListPending:
        return {{T::ServiceEpoch, 16}, {T::SnapshotId, 16}, {T::Cursor, 4}, {T::Limit, 2}};
    case Type::RulesPage:
    case Type::PendingPage:
        return {{T::ServiceEpoch, 16},
                {T::SnapshotId, 16},
                {f.type == Type::RulesPage ? T::DesiredRev : T::PendingSnapshotRevision, 8},
                {T::Cursor, 4},
                {T::NextCursor, 4},
                {T::Count, 2},
                {T::Records, Variable}};
    case Type::CommitDecision:
        return {{T::ServiceEpoch, 16},      {T::RequestId, 16},       {T::RequestVersion, 8},
                {T::ExpectedDesiredRev, 8}, {T::Decision, 1},         {T::Remember, 1},
                {T::ScopeKind, 1},          {T::SelectorId, 16},      {T::SelectorRevision, 8},
                {T::PolicyDirection, 1},    {T::ProfileGeneration, 8}};
    case Type::CreateRule:
        return {{T::ServiceEpoch, 16},   {T::ExpectedDesiredRev, 8}, {T::Decision, 1},
                {T::ScopeKind, 1},       {T::SelectorId, 16},        {T::SelectorRevision, 8},
                {T::PolicyDirection, 1}, {T::ProfileGeneration, 8}};
    case Type::RevokeRule:
        return {{T::ServiceEpoch, 16},
                {T::ExpectedDesiredRev, 8},
                {T::RuleId, 16},
                {T::RuleRevision, 8},
                {T::ProfileGeneration, 8}};
    case Type::MutationAck: {
        Schema s = {{T::ServiceEpoch, 16},  {T::DesiredRev, 8},   {T::EffectiveRev, 8},
                    {T::EffectiveKnown, 1}, {T::CommandState, 1}, {T::ErrorCode, 2}};
        if (find(f, T::RequestId)) {
            s[T::RequestId] = 16;
            s[T::RequestVersion] = 8;
            s[T::RequestState] = 1;
        }
        return s;
    }
    case Type::ProtocolError:
        optional = {{T::Text, Variable}};
        return {{T::ErrorCode, 2}};
    case Type::GetCommandStatus:
        return {{T::ServiceEpoch, 16}, {T::CommandId, 16}};
    case Type::CommandStatus: {
        Schema s = {{T::ServiceEpoch, 16}, {T::CommandId, 16}, {T::CommandFound, 1}, {T::ErrorCode, 2}};
        if (get(f, T::CommandFound) == 1) {
            s[T::OriginalCommandType] = 2;
            s[T::CommandState] = 1;
            s[T::DesiredRev] = 8;
            s[T::EffectiveRev] = 8;
            s[T::EffectiveKnown] = 1;
        }
        return s;
    }
    case Type::GetPending:
        return {{T::ServiceEpoch, 16}, {T::RequestId, 16}};
    case Type::PendingRecord:
        return {{T::ServiceEpoch, 16}, {T::Records, Variable}};
    case Type::SubscribeEvents:
        return {{T::ServiceEpoch, 16}, {T::EventMask, 4}, {T::AfterEventSeq, 8}};
    case Type::SubscriptionAck:
        return {{T::ServiceEpoch, 16},     {T::EventMask, 4},         {T::EventSeq, 8},
                {T::CollectorState, 1},    {T::SourceCoverage, 1},    {T::GapCount, 8},
                {T::ProfileGeneration, 8}, {T::ReviewProfileState, 1}};
    case Type::ObservationGap:
        return {{T::ServiceEpoch, 16},
                {T::EventSeq, 8},
                {T::Timestamp, 8},
                {T::Presence, 8},
                {T::Source, 1},
                {T::GapCount, 8},
                {T::LostCount, 8},
                {T::LostCountKnown, 1},
                {T::GapReason, 1},
                {T::ProfileGeneration, 8},
                {T::ReviewProfileState, 1}};
    case Type::Attempt:
    case Type::Authorization: {
        Schema s = {{T::ServiceEpoch, 16},
                    {T::EventSeq, 8},
                    {T::Timestamp, 8},
                    {T::Presence, 8},
                    {T::Source, 1},
                    {T::GapCount, 8},
                    {T::SourceCoverage, 1},
                    {T::ProfileGeneration, 8},
                    {T::SourceAccountMatched, 1}};
        const std::pair<T, std::size_t> links[] = {
            {T::SelectorId, 16},     {T::RequestId, 16},    {T::RuleId, 16},          {T::RuleRevision, 8},
            {T::NativeFilterId, 8},  {T::FilterGuid, 16},   {T::FilterGeneration, 8}, {T::FlowDirection, 1},
            {T::PacketDirection, 1}, {T::LocalAddress, 21}, {T::RemoteAddress, 21},   {T::LocalPort, 2},
            {T::RemotePort, 2},      {T::Protocol, 1},      {T::ByteCount, 8},        {T::PacketCount, 8},
            {T::CommandId, 16},      {T::AttemptLink, 16},  {T::EffectiveRev, 8}};
        auto p = get(f, T::Presence);
        for (unsigned i = 0; i < 19; ++i)
            if (p & (1ull << i))
                s[links[i].first] = links[i].second;
        if (p & 2) {
            s[T::RequestVersion] = 8;
            s[T::ObservationRevision] = 8;
        }
        if (f.type == Type::Authorization)
            s[T::ObservedResult] = 1;
        return s;
    }
    default:
        return {};
    }
}
bool enumValid(T tag, std::uint64_t v) {
    switch (tag) {
    case T::ClientRole:
    case T::Decision:
    case T::FlowDirection:
        return v == 1 || v == 2;
    case T::Remember:
    case T::EffectiveKnown:
    case T::LostCountKnown:
    case T::CommandFound:
        return v <= 1;
    case T::ScopeKind:
    case T::ObservedResult:
        return v == 1;
    case T::PolicyDirection:
        return v == 3;
    case T::SourceAccountMatched:
        return v == 1;
    case T::EngineState:
        return v <= 5;
    case T::BackendMode:
    case T::PacketDirection:
    case T::ReviewProfileState:
        return v <= 2;
    case T::CommandState:
        return v >= 1 && v <= 5;
    case T::RequestState:
    case T::Source:
        return v >= 1 && v <= 4;
    case T::CollectorState:
        return v <= 3;
    case T::SourceCoverage:
        return v <= 1;
    case T::GapReason:
        return v >= 1 && v <= 8;
    case T::ErrorCode:
        return v <= 17;
    case T::Capabilities:
        return (v >> 22) == 0 && (v & ((0x3full << 6) | (1ull << 16))) == 0;
    case T::EventMask:
        return v >= 1 && v <= 3;
    case T::OriginalCommandType:
        return v >= 9 && v <= 11;
    case T::Limit:
        return v >= 1 && v <= 32;
    case T::Count:
        return v <= 32;
    default:
        return true;
    }
}
} // namespace
bool valid(const RuleRecord &r) {
    return !zero(r.rule) && !zero(r.selector) && r.revision && r.selectorRevision && r.action >= 1 &&
           r.action <= 2 && r.scope == 1 && r.admin >= 1 && r.admin <= 2 && r.effective <= 2 &&
           !(r.admin == 2 && r.effective == 1) && r.direction == 3 && r.identity == 1 && !(r.presence >> 5) &&
           strings(r.path, r.name, r.presence) && ((r.presence & 4) || !r.created) &&
           ((r.presence & 8) || !r.updated) && known(r.presence, 4, r.filterGeneration);
}
bool valid(const PendingRecord &r) {
    auto s = static_cast<unsigned>(r.state);
    return !zero(r.request) && r.authority && r.observation && r.profileGeneration && s >= 1 && s <= 4 &&
           r.selectorState <= 2 && r.flow >= 1 && r.flow <= 2 && r.scope == 1 && r.source >= 1 &&
           r.source <= 4 && r.identity == 1 && r.direction == 3 && !(r.presence >> 8) &&
           strings(r.path, r.name, r.presence) && ((r.presence & 4) || !r.firstUtc) &&
           ((r.presence & 8) || !r.lastUtc) && known(r.presence, 4, r.attempt) &&
           known(r.presence, 5, r.filterId) && known(r.presence, 6, r.filterGeneration) &&
           known(r.presence, 7, r.selector) &&
           ((r.presence & 128) ? r.selectorRevision != 0 : r.selectorRevision == 0) &&
           (s == 1 ? (r.ttl >= 1 && r.ttl <= 600000) : r.ttl == 0);
}
bool eligible(const PendingRecord &r) {
    return valid(r) && r.state == RequestState::Pending && r.selectorState == 1 &&
           (r.presence & 0xf1) == 0xf1 && r.source == 1 && r.accountMatched;
}
Error pack(const std::vector<RuleRecord> &records, Bytes &out) {
    if (records.size() > 32)
        return Error::Capacity;
    Bytes b;
    for (const auto &r : records) {
        if (!valid(r))
            return Error::Malformed;
        Bytes p(104);
        put(p, 0, r.rule);
        put(p, 16, r.selector);
        put(p, 32, r.revision, 8);
        put(p, 40, r.desired, 8);
        put(p, 48, r.selectorRevision, 8);
        p[56] = r.action;
        p[57] = r.scope;
        p[58] = r.admin;
        p[59] = r.effective;
        p[60] = r.direction;
        p[61] = r.identity;
        put(p, 64, r.presence, 8);
        put(p, 72, r.created, 8);
        put(p, 80, r.updated, 8);
        put(p, 88, r.filterGeneration, 8);
        put(p, 96, r.path.size(), 2);
        put(p, 98, r.name.size(), 2);
        p.insert(p.end(), r.path.begin(), r.path.end());
        p.insert(p.end(), r.name.begin(), r.name.end());
        if (p.size() + 8 > MaxRecordsBytes - b.size())
            return Error::Capacity;
        envelope(b, p, 1, 1);
    }
    out = std::move(b);
    return Error::Ok;
}
Error pack(const std::vector<PendingRecord> &records, Bytes &out) {
    if (records.size() > 32)
        return Error::Capacity;
    Bytes b;
    for (const auto &r : records) {
        if (!valid(r))
            return Error::Malformed;
        Bytes p(160);
        put(p, 0, r.request);
        put(p, 16, r.authority, 8);
        put(p, 24, r.selector);
        put(p, 40, r.selectorRevision, 8);
        put(p, 48, r.desired, 8);
        put(p, 56, r.attempt);
        put(p, 72, r.firstUtc, 8);
        put(p, 80, r.lastUtc, 8);
        put(p, 88, r.presence, 8);
        put(p, 96, r.filterId, 8);
        put(p, 104, r.filterGeneration, 8);
        put(p, 112, r.eventSequence, 8);
        put(p, 120, r.ttl, 4);
        p[124] = static_cast<std::uint8_t>(r.state);
        p[125] = r.selectorState;
        p[126] = r.flow;
        p[127] = r.scope;
        p[128] = r.source;
        p[129] = r.identity;
        p[130] = r.direction;
        p[131] = r.accountMatched ? 1 : 0;
        put(p, 132, r.path.size(), 2);
        put(p, 134, r.name.size(), 2);
        put(p, 136, r.observation, 8);
        put(p, 144, r.profileGeneration, 8);
        p.insert(p.end(), r.path.begin(), r.path.end());
        p.insert(p.end(), r.name.begin(), r.name.end());
        if (p.size() + 8 > MaxRecordsBytes - b.size())
            return Error::Capacity;
        envelope(b, p, 2, 2);
    }
    out = std::move(b);
    return Error::Ok;
}
Error unpack(const Bytes &b, std::size_t count, std::vector<RuleRecord> &out) {
    if (b.size() > MaxRecordsBytes || count > 32)
        return Error::Capacity;
    std::vector<RuleRecord> rows;
    std::size_t offset = 0;
    for (std::size_t i = 0; i < count; ++i) {
        Bytes p;
        if (!record(b, offset, 1, 1, 104, p) || n(p, 62, 2) || n(p, 100, 4))
            return Error::Malformed;
        auto path = n(p, 96, 2), name = n(p, 98, 2);
        if (path > 4096 || name > 256 || 104 + path + name != p.size())
            return Error::Malformed;
        RuleRecord r;
        r.rule = id(p, 0);
        r.selector = id(p, 16);
        r.revision = n(p, 32, 8);
        r.desired = n(p, 40, 8);
        r.selectorRevision = n(p, 48, 8);
        r.action = p[56];
        r.scope = p[57];
        r.admin = p[58];
        r.effective = p[59];
        r.direction = p[60];
        r.identity = p[61];
        r.presence = n(p, 64, 8);
        r.created = n(p, 72, 8);
        r.updated = n(p, 80, 8);
        r.filterGeneration = n(p, 88, 8);
        r.path.assign(p.begin() + 104, p.begin() + 104 + path);
        r.name.assign(p.begin() + 104 + path, p.end());
        if (!valid(r))
            return Error::Malformed;
        rows.push_back(std::move(r));
    }
    if (offset != b.size())
        return Error::Malformed;
    out = std::move(rows);
    return Error::Ok;
}
Error unpack(const Bytes &b, std::size_t count, std::vector<PendingRecord> &out) {
    if (b.size() > MaxRecordsBytes || count > 32)
        return Error::Capacity;
    std::vector<PendingRecord> rows;
    std::size_t offset = 0;
    for (std::size_t i = 0; i < count; ++i) {
        Bytes p;
        if (!record(b, offset, 2, 2, 160, p) || n(p, 152, 8) || p[131] > 1)
            return Error::Malformed;
        auto path = n(p, 132, 2), name = n(p, 134, 2);
        if (path > 4096 || name > 256 || 160 + path + name != p.size())
            return Error::Malformed;
        PendingRecord r;
        r.request = id(p, 0);
        r.authority = n(p, 16, 8);
        r.selector = id(p, 24);
        r.selectorRevision = n(p, 40, 8);
        r.desired = n(p, 48, 8);
        r.attempt = id(p, 56);
        r.firstUtc = n(p, 72, 8);
        r.lastUtc = n(p, 80, 8);
        r.presence = n(p, 88, 8);
        r.filterId = n(p, 96, 8);
        r.filterGeneration = n(p, 104, 8);
        r.eventSequence = n(p, 112, 8);
        r.ttl = static_cast<std::uint32_t>(n(p, 120, 4));
        r.state = static_cast<RequestState>(p[124]);
        r.selectorState = p[125];
        r.flow = p[126];
        r.scope = p[127];
        r.source = p[128];
        r.identity = p[129];
        r.direction = p[130];
        r.accountMatched = p[131] == 1;
        r.observation = n(p, 136, 8);
        r.profileGeneration = n(p, 144, 8);
        r.path.assign(p.begin() + 160, p.begin() + 160 + path);
        r.name.assign(p.begin() + 160 + path, p.end());
        if (!valid(r))
            return Error::Malformed;
        rows.push_back(std::move(r));
    }
    if (offset != b.size())
        return Error::Malformed;
    out = std::move(rows);
    return Error::Ok;
}
Error validate(const Frame &f) {
    if (f.minor != 1)
        return Error::VersionMismatch;
    if (!supported(f.type, 1))
        return f.type == Type::Traffic ? Error::Unsupported : Error::Malformed;
    if (!f.sequence || zero(f.correlation) || f.fields.size() > 64)
        return Error::Malformed;
    if (f.type == Type::Hello) {
        if (!zero(f.connection) || f.sequence != 1)
            return Error::Malformed;
    } else if (f.type != Type::ProtocolError && zero(f.connection))
        return Error::Malformed;
    if (f.type == Type::HelloAck && f.sequence != 1)
        return Error::Malformed;
    Schema optional;
    auto required = schema(f, optional);
    std::set<T> seen;
    std::size_t body = 0;
    for (const auto &field : f.fields) {
        if (!seen.insert(field.tag).second)
            return Error::Malformed;
        auto a = required.find(field.tag), b = optional.find(field.tag);
        bool req = a != required.end();
        if (!req && b == optional.end())
            return Error::Malformed;
        auto width = req ? a->second : b->second;
        if (field.required != req || (width != Variable && field.bytes.size() != width))
            return Error::Malformed;
        if (field.bytes.size() > MaxFrameBytes - HeaderBytes - 8 ||
            body > MaxFrameBytes - HeaderBytes - 8 - field.bytes.size())
            return Error::Capacity;
        body += 8 + field.bytes.size();
        if (width != Variable && !enumValid(field.tag, number(field)))
            return Error::Malformed;
        if (width == 16 && field.tag != T::SnapshotId && zero(idValue(f, field.tag)))
            return Error::Malformed;
        if (field.tag == T::Text && (field.bytes.size() > 1024 || !text(field.bytes)))
            return Error::Malformed;
        if ((field.tag == T::LocalAddress || field.tag == T::RemoteAddress) &&
            (field.bytes[0] != 4 && field.bytes[0] != 6))
            return Error::Malformed;
        if ((field.tag == T::LocalAddress || field.tag == T::RemoteAddress) && field.bytes[0] == 4 &&
            std::any_of(field.bytes.begin() + 5, field.bytes.end(), [](auto c) { return c != 0; }))
            return Error::Malformed;
    }
    for (auto [tag, width] : required) {
        (void)width;
        if (!seen.count(tag))
            return Error::Malformed;
    }
    for (auto tag : {T::RequestVersion, T::SelectorRevision, T::RuleRevision, T::ProfileGeneration,
                     T::ObservationRevision})
        if (find(f, tag) && !get(f, tag))
            return Error::Malformed;
    if (f.type == Type::ListRules || f.type == Type::ListPending)
        if (zero(idValue(f, T::SnapshotId)) && get(f, T::Cursor))
            return Error::Malformed;
    if (f.type == Type::RulesPage || f.type == Type::PendingPage || f.type == Type::PendingRecord) {
        auto b = find(f, T::Records);
        if (!b)
            return Error::Malformed;
        auto count = f.type == Type::PendingRecord ? 1 : get(f, T::Count);
        if (f.type == Type::RulesPage) {
            std::vector<RuleRecord> rows;
            auto e = unpack(b->bytes, count, rows);
            if (e != Error::Ok)
                return e;
        } else {
            std::vector<PendingRecord> rows;
            auto e = unpack(b->bytes, count, rows);
            if (e != Error::Ok)
                return e;
        }
        if (f.type != Type::PendingRecord && zero(idValue(f, T::SnapshotId)))
            return Error::Malformed;
    }
    if (f.type == Type::CommitDecision && get(f, T::Decision) == 2 && !get(f, T::Remember))
        return Error::Unsupported;
    if (f.type == Type::GetCommandStatus && idValue(f, T::CommandId) == f.correlation)
        return Error::Malformed;
    if (f.type == Type::CommandStatus && !get(f, T::CommandFound) && get(f, T::ErrorCode) != 17)
        return Error::Malformed;
    if (find(f, T::EffectiveKnown)) {
        auto d = get(f, T::DesiredRev), e = get(f, T::EffectiveRev), k = get(f, T::EffectiveKnown);
        if (e > d || (!k && e))
            return Error::Malformed;
        if (f.type == Type::MutationAck) {
            auto s = get(f, T::CommandState), error = get(f, T::ErrorCode);
            if (s == 2 && (error || !k || e != d))
                return Error::Malformed;
            if (s == 5 && (error != 8 || !k || e != d))
                return Error::Malformed;
        }
    }
    if (f.type == Type::Status) {
        bool cap = (get(f, T::Capabilities) & (1ull << 21)) != 0;
        if (bool(find(f, T::CollectorState)) != cap || bool(find(f, T::SourceCoverage)) != cap)
            return Error::Malformed;
    }
    if (f.type == Type::ObservationGap) {
        auto p = get(f, T::Presence);
        if ((p & ~(1ull << 19)) || (!(p & (1ull << 19)) && get(f, T::Timestamp)) || !get(f, T::EventSeq))
            return Error::Malformed;
        if (!get(f, T::LostCountKnown) && get(f, T::LostCount))
            return Error::Malformed;
    }
    if (f.type == Type::Attempt || f.type == Type::Authorization) {
        auto p = get(f, T::Presence);
        auto allowed = f.type == Type::Attempt ? 0x83fffull : 0xf3fffull;
        if ((p & ~allowed) || !get(f, T::EventSeq) || (!(p & (1ull << 19)) && get(f, T::Timestamp)))
            return Error::Malformed;
        if ((p & 8) && !(p & 4))
            return Error::Malformed;
        if ((p & 0x60) && !(p & 0x10))
            return Error::Malformed;
        for (auto tag : {T::RuleRevision, T::NativeFilterId, T::FilterGeneration, T::EffectiveRev})
            if (find(f, tag) && !get(f, tag))
                return Error::Malformed;
    }
    return Error::Ok;
}
bool filetimeUtc(std::uint64_t ft, std::uint64_t &out) {
    constexpr std::uint64_t offset = 116444736000000000ull;
    out = 0;
    if (ft < offset || ft - offset > std::numeric_limits<std::uint64_t>::max() / 100)
        return false;
    out = (ft - offset) * 100;
    return true;
}
} // namespace gb::wire::ii
