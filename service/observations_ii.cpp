#include "observations_ii.h"

namespace gb::decisions {
void Pages::expire(std::uint64_t now) {
    for (auto it = snapshots_.begin(); it != snapshots_.end();)
        if (now >= it->second.deadline)
            it = snapshots_.erase(it);
        else
            ++it;
}
Error Pages::insert(Id id, bool rules, std::uint64_t revision, std::uint64_t now, std::vector<Bytes> rows) {
    expire(now);
    if (zero(id) || snapshots_.count(id) || snapshots_.size() >= 2 || now > UINT64_MAX - 10000)
        return Error::Capacity;
    Snapshot s;
    s.rules = rules;
    s.revision = revision;
    s.deadline = now + 10000;
    s.records = std::move(rows);
    snapshots_.emplace(id, std::move(s));
    return Error::Ok;
}
Error Pages::rules(Id id, const std::vector<ii::RuleRecord> &rows, std::uint64_t revision,
                   std::uint64_t now) {
    if (rows.size() > 4096)
        return Error::Capacity;
    std::vector<Bytes> records;
    for (const auto &r : rows) {
        Bytes b;
        auto e = ii::pack(std::vector<ii::RuleRecord>{r}, b, minor_);
        if (e != Error::Ok)
            return e;
        records.push_back(std::move(b));
    }
    return insert(id, true, revision, now, std::move(records));
}
Error Pages::pending(Id id, const std::vector<ii::PendingRecord> &rows, std::uint64_t revision,
                     std::uint64_t now) {
    if (rows.size() > 512)
        return Error::Capacity;
    std::vector<Bytes> records;
    for (const auto &r : rows) {
        if (r.state != ii::RequestState::Pending || r.profileGeneration != profile_)
            return Error::Stale;
        Bytes b;
        auto e = ii::pack(std::vector<ii::PendingRecord>{r}, b, minor_);
        if (e != Error::Ok)
            return e;
        records.push_back(std::move(b));
    }
    return insert(id, false, revision, now, std::move(records));
}
Error Pages::page(const Frame &f, std::uint64_t profile, std::uint64_t now, Frame &out) {
    if (f.minor != minor_ || wire::validate(f) != Error::Ok ||
        (f.type != Type::ListRules && f.type != Type::ListPending))
        return Error::Malformed;
    if (profile != profile_ || idValue(f, Tag::ServiceEpoch) != epoch_)
        return Error::Stale;
    auto it = snapshots_.find(idValue(f, Tag::SnapshotId));
    if (it == snapshots_.end() || now >= it->second.deadline)
        return Error::SnapshotExpired;
    auto &s = it->second;
    if (s.rules != (f.type == Type::ListRules) || get(f, Tag::Cursor) != s.next)
        return Error::Malformed;
    Bytes blob;
    std::uint32_t count = 0, cursor = s.next;
    auto limit = get(f, Tag::Limit);
    while (cursor < s.records.size() && count < limit) {
        auto &b = s.records[cursor];
        if (b.size() > ii::MaxRecordsBytes - blob.size())
            break;
        blob.insert(blob.end(), b.begin(), b.end());
        ++cursor;
        ++count;
    }
    Frame r;
    r.minor = minor_;
    r.type = s.rules ? Type::RulesPage : Type::PendingPage;
    r.connection = f.connection;
    r.correlation = f.correlation;
    r.sequence = f.sequence;
    auto next = cursor == s.records.size() ? 0xffffffffu : cursor;
    r.fields = {value(Tag::ServiceEpoch, epoch_),
                value(Tag::SnapshotId, it->first),
                value(s.rules ? Tag::DesiredRev : Tag::PendingSnapshotRevision, s.revision),
                value(Tag::Cursor, s.next, 4),
                value(Tag::NextCursor, next, 4),
                value(Tag::Count, count, 2),
                {Tag::Records, true, std::move(blob)}};
    auto e = wire::validate(r);
    if (e != Error::Ok)
        return e;
    if (next == 0xffffffffu)
        snapshots_.erase(it);
    else
        s.next = next;
    out = std::move(r);
    return Error::Ok;
}
Error ObservationRing::append(const Frame &event) {
    if (event.minor != minor_ || wire::validate(event) != Error::Ok ||
        (event.type != Type::Attempt && event.type != Type::Authorization &&
         event.type != Type::ObservationGap))
        return Error::Malformed;
    if (idValue(event, Tag::ServiceEpoch) != epoch_ || get(event, Tag::ProfileGeneration) != profile_)
        return Error::Stale;
    auto seq = get(event, Tag::EventSeq);
    if (sequence_ == UINT64_MAX || seq != sequence_ + 1)
        return Error::Conflict;
    if (event.type != Type::ObservationGap && get(event, Tag::Source) != 1)
        return Error::Unsupported;
    sequence_ = seq;
    events_.push_back(event);
    if (events_.size() > 4096) {
        lostThrough_ = get(events_.front(), Tag::EventSeq);
        events_.pop_front();
    }
    return Error::Ok;
}
Error ObservationRing::after(std::uint64_t seq, std::uint32_t mask, std::vector<Frame> &out,
                             bool &gap) const {
    if (!mask || (mask & ~3u) || seq > sequence_)
        return Error::Malformed;
    gap = false;
    out.clear();
    if (!seq)
        return Error::Ok;
    if (seq < lostThrough_)
        gap = true;
    for (const auto &e : events_) {
        if (get(e, Tag::EventSeq) <= seq)
            continue;
        if (e.type == Type::ObservationGap || (e.type == Type::Attempt && (mask & 1)) ||
            (e.type == Type::Authorization && (mask & 2))) {
            if (out.size() == 512) {
                out.clear();
                gap = true;
                return Error::Capacity;
            }
            out.push_back(e);
        }
    }
    return Error::Ok;
}
} // namespace gb::decisions
