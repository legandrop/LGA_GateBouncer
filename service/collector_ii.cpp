#include "collector_ii.h"
#include "journal_ii_store.h"
#include <algorithm>

namespace gb::decisions {
Id canonicalGuid(const GUID &g) {
    Id out{};
    out[0] = std::uint8_t(g.Data1 >> 24);
    out[1] = std::uint8_t(g.Data1 >> 16);
    out[2] = std::uint8_t(g.Data1 >> 8);
    out[3] = std::uint8_t(g.Data1);
    out[4] = std::uint8_t(g.Data2 >> 8);
    out[5] = std::uint8_t(g.Data2);
    out[6] = std::uint8_t(g.Data3 >> 8);
    out[7] = std::uint8_t(g.Data3);
    std::copy_n(g.Data4, 8, out.begin() + 8);
    return out;
}
bool NativeCollector::publish(std::vector<LedgerFilter> rows, std::uint64_t ft) {
    if (!ft || rows.empty() || rows.size() > MaxRules * 6 + 64)
        return false;
    std::sort(rows.begin(), rows.end(),
              [](const auto &a, const auto &b) { return a.filterId < b.filterId; });
    for (std::size_t i = 0; i < rows.size(); ++i) {
        auto &f = rows[i];
        if (!f.filterId || zero(f.guid) || !f.generation || !f.layerId || f.originalFlow > 2 ||
            (i && rows[i - 1].filterId == f.filterId))
            return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    bool identical = rows.size() == ledger_.size();
    for (std::size_t i = 0; identical && i < rows.size(); ++i) {
        auto &a = rows[i];
        auto &b = ledger_[i];
        identical = a.filterId == b.filterId && a.guid == b.guid && a.generation == b.generation &&
                    a.desired == b.desired && a.layerId == b.layerId &&
                    a.originalFlow == b.originalFlow && a.drop == b.drop;
    }
    if (identical && state_ == 1)
        return true;
    if (ft <= publishedAt_) {
        state_ = 3;
        pendingGap_ = 5;
        return false;
    }
    ledger_ = std::move(rows);
    publishedAt_ = ft;
    state_ = 1;
    return true;
}
void NativeCollector::whitelist(std::vector<Bytes> tools) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (tools.size() > 2) {
        state_ = 3;
        pendingGap_ = 7;
        return;
    }
    tools_ = std::move(tools);
}
void NativeCollector::unavailable(std::uint8_t reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    state_ = 2;
    ledger_.clear();
    pendingGap_ = reason;
}
std::uint8_t NativeCollector::state() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}
std::uint64_t NativeCollector::gaps() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return gaps_;
}
void NativeCollector::capture(const FWPM_NET_EVENT1 *e) {
    // Callback sólo copia metadata acotada. Nunca consulta filtros actuales o archivos.
    if (!e || e->type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP || !e->classifyDrop)
        return;
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != 1)
        return;
    constexpr DWORD required = FWPM_NET_EVENT_FLAG_APP_ID_SET | FWPM_NET_EVENT_FLAG_USER_ID_SET;
    if ((e->header.flags & required) != required || !e->header.appId.data ||
        !e->header.appId.size || e->header.appId.size > 32768 || !e->header.userId) {
        pendingGap_ = 7;
        return;
    }
    const auto sid = reinterpret_cast<const BYTE *>(e->header.userId);
    if (sid[0] != 1 || sid[1] > 15) {
        pendingGap_ = 7;
        return;
    }
    auto length = 8 + std::size_t(sid[1]) * 4;
    Capture c;
    c.appId.assign(e->header.appId.data, e->header.appId.data + e->header.appId.size);
    c.accountSid.assign(sid, sid + length);
    if (!validSidBytes(c.accountSid)) {
        pendingGap_ = 7;
        return;
    }
    c.filetime = (std::uint64_t(e->header.timeStamp.dwHighDateTime) << 32) |
                 e->header.timeStamp.dwLowDateTime;
    c.receivedMs = GetTickCount64();
    auto found =
        std::lower_bound(ledger_.begin(), ledger_.end(), e->classifyDrop->filterId,
                         [](const auto &row, std::uint64_t id) { return row.filterId < id; });
    if (found != ledger_.end() && found->filterId == e->classifyDrop->filterId && found->drop &&
        found->layerId == e->classifyDrop->layerId && c.filetime >= publishedAt_) {
        c.filter = *found;
        c.mapped = true;
    }
    // Hecho previo a publicación/otro layer/ID reciclado no se atribuye retroactivamente.
    if (!c.mapped || !c.filter.originalFlow) {
        pendingGap_ = 7;
        return;
    }
    if (queue_.size() == 512) {
        pendingGap_ = 1;
        return;
    }
    queue_.push_back(std::move(c));
}
bool NativeCollector::gap(std::uint8_t reason, std::uint64_t profile, std::uint8_t state) {
    std::uint64_t count = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (gaps_ == UINT64_MAX) {
            state_ = 3;
            return false;
        }
        count = ++gaps_;
    }
    if (ring_.latest() == UINT64_MAX)
        return false;
    Frame f;
    f.minor = 1;
    f.type = Type::ObservationGap;
    f.correlation = native::randomIdentity();
    f.connection.fill(1);
    FILETIME clock{};
    GetSystemTimeAsFileTime(&clock);
    std::uint64_t utc = 0;
    bool known = wire::ii::filetimeUtc(
        (std::uint64_t(clock.dwHighDateTime) << 32) | clock.dwLowDateTime, utc);
    f.fields = {value(Tag::ServiceEpoch, epoch_),
                value(Tag::EventSeq, ring_.latest() + 1),
                value(Tag::Timestamp, utc),
                value(Tag::Presence, known ? 1ull << 19 : 0),
                value(Tag::Source, 1, 1),
                value(Tag::GapCount, count),
                value(Tag::LostCount, 0),
                value(Tag::LostCountKnown, 0, 1),
                value(Tag::GapReason, reason, 1),
                value(Tag::ProfileGeneration, profile),
                value(Tag::ReviewProfileState, state, 1)};
    return ring_.append(f) == Error::Ok;
}
void NativeCollector::drain(const NativeProfile &p, std::uint64_t now) {
    std::deque<Capture> queue;
    std::vector<Bytes> tools;
    std::uint8_t reason = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue.swap(queue_);
        tools = tools_;
        reason = pendingGap_;
        pendingGap_ = 0;
    }
    if (reason)
        gap(reason, p.value().generation, p.value().state);
    for (auto &c : queue) {
        if (p.value().state != 1 || !native::equalSidBytes(c.accountSid, p.account())) {
            gap(8, p.value().generation, p.value().state);
            continue;
        }
        if (std::find(tools.begin(), tools.end(), c.appId) == tools.end()) {
            gap(7, p.value().generation, p.value().state);
            continue;
        }
        if (c.filter.desired != engine_.desiredRevision() || c.receivedMs > now) {
            gap(7, p.value().generation, p.value().state);
            continue;
        }
        std::uint64_t utc = 0;
        bool known = wire::ii::filetimeUtc(c.filetime, utc);
        if (known && lastUtc_ && utc < lastUtc_)
            gap(5, p.value().generation, p.value().state);
        if (known)
            lastUtc_ = utc;
        auto selector = registry_.registerNative(c.appId);
        if (zero(selector)) {
            gap(7, p.value().generation, p.value().state);
            continue;
        }
        // APP_ID es UTF16 nativo de tool propio, no input IPC ni parser de archivo.
        if (c.appId.size() < 4 || (c.appId.size() & 1)) {
            gap(7, p.value().generation, p.value().state);
            continue;
        }
        std::wstring path(c.appId.size() / 2, L'\0');
        memcpy(path.data(), c.appId.data(), c.appId.size());
        if (path.back() != L'\0') {
            gap(7, p.value().generation, p.value().state);
            continue;
        }
        path.pop_back();
        int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path.data(), int(path.size()),
                                       nullptr, 0, nullptr, nullptr);
        if (size <= 0 || size > 4096) {
            gap(7, p.value().generation, p.value().state);
            continue;
        }
        ii::PendingRecord record;
        record.path.resize(size);
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path.data(), int(path.size()),
                            reinterpret_cast<char *>(record.path.data()), size, nullptr, nullptr);
        record.request = native::randomIdentity();
        record.attempt = native::randomIdentity();
        record.selector = selector;
        record.authority = record.observation = record.selectorRevision = 1;
        record.desired = engine_.desiredRevision();
        record.profileGeneration = p.value().generation;
        record.selectorState = 1;
        record.flow = c.filter.originalFlow;
        record.accountMatched = true;
        record.ttl = 600000;
        record.filterId = c.filter.filterId;
        record.filterGeneration = c.filter.generation;
        record.presence = 0xf1 | (known ? 0xc : 0);
        record.firstUtc = record.lastUtc = utc;
        if (ring_.latest() == UINT64_MAX) {
            unavailable(1);
            return;
        }
        record.eventSequence = ring_.latest() + 1;
        if (engine_.observe({record, true, true, true, true}, now) != Error::Ok) {
            gap(7, p.value().generation, p.value().state);
            continue;
        }
        // observe puede agrupar retry en request anterior: buscar binding vigente del selector.
        auto live = engine_.pendingBySelector(record.selector, record.flow, now);
        if (!live) {
            gap(7, p.value().generation, p.value().state);
            continue;
        }
        Frame event;
        event.minor = 1;
        event.type = Type::Attempt;
        event.connection.fill(1);
        event.correlation = native::randomIdentity();
        event.fields = {value(Tag::ServiceEpoch, epoch_),
                        value(Tag::EventSeq, record.eventSequence),
                        value(Tag::Timestamp, utc),
                        value(Tag::Presence, 0xf3 | (known ? 1ull << 19 : 0)),
                        value(Tag::Source, 1, 1),
                        value(Tag::GapCount, gaps()),
                        value(Tag::SourceCoverage, 1, 1),
                        value(Tag::ProfileGeneration, p.value().generation),
                        value(Tag::SourceAccountMatched, 1, 1),
                        value(Tag::SelectorId, selector),
                        value(Tag::RequestId, live->request),
                        value(Tag::RequestVersion, live->authority),
                        value(Tag::ObservationRevision, live->observation),
                        value(Tag::NativeFilterId, c.filter.filterId),
                        value(Tag::FilterGuid, c.filter.guid),
                        value(Tag::FilterGeneration, c.filter.generation),
                        value(Tag::FlowDirection, c.filter.originalFlow, 1)};
        if (ring_.append(event) != Error::Ok) {
            unavailable(7);
            return;
        }
    }
}
} // namespace gb::decisions
