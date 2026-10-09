#include "AllAppsMetadata.h"
#include <utility>
#include <type_traits>

namespace gatebouncer::service::windows::allapps {
namespace {
std::uint64_t packed(Health h, std::uint64_t rev) noexcept
{ return (rev << 3) | static_cast<std::uint64_t>(h); }
Direction direction(std::uint32_t type, std::uint32_t raw) noexcept
{
    if (type == 3) return raw == 0x3901 ? Direction::Outbound : raw == 0x3900 ? Direction::Inbound : Direction::Unknown;
    if (type == 6) return raw == 0 ? Direction::Outbound : raw == 1 ? Direction::Inbound : Direction::Unknown;
    return Direction::Unknown;
}
Reason field(const FieldView& v, bool present, bool sid, ai::CopiedField& out)
{
    if (!present) return v.declared ? Reason::BadPresence : Reason::None;
    if (v.declared > (sid ? ai::MaximumSidBytes : ai::MaximumAppIdBytes)) return Reason::Oversized;
    if (!v.data || !v.declared || v.available < v.declared) return Reason::Unreadable;
    if (sid && (v.declared < 8 || v.data[0] != 1 || v.data[1] > 15 || v.declared != 8u + 4u * v.data[1])) return Reason::InvalidSid;
    out.bytes.assign(v.data, v.data + v.declared);
    out.state = ai::FieldState::Copied;
    return Reason::None;
}
}
SourceState::SourceState(std::uint64_t epoch, std::uint64_t generation, std::uint64_t sequence,
                         std::uint64_t revision) noexcept : epoch_(epoch), generation_(generation), sequence_(sequence),
    status_(packed(!epoch || !generation ? Health::Absent : revision ? Health::Degraded : Health::Ready,
                   revision > MaxLossRevision ? MaxLossRevision : revision)) {}
SourceState::Lease::Lease(Lease&& other) noexcept : stamp(other.stamp), lossRevision(other.lossRevision),
    owner_(std::exchange(other.owner_, nullptr)) {}
SourceState::Lease::~Lease() { if (owner_) owner_->copiers_.fetch_sub(1); }
HealthSnapshot SourceState::health() const noexcept
{ const auto s = status_.load(); return {static_cast<Health>(s & 7), s >> 3}; }
bool SourceState::current(const Stamp& stamp) const noexcept
{ return stamp.epoch == epoch_ && stamp.generation == generation_ && stamp.sequence && stamp.sequence <= sequence_.load(); }
void SourceState::lost() noexcept
{
    auto old = status_.load();
    for (;;) {
        const auto rev = old >> 3; const auto h = static_cast<Health>(old & 7);
        const auto next = packed(h == Health::Ready ? Health::Degraded : h, rev == MaxLossRevision ? rev : rev + 1);
        if (status_.compare_exchange_weak(old, next)) return;
    }
}
void SourceState::stop() noexcept
{ auto old = status_.load(); while (!status_.compare_exchange_weak(old, packed(Health::Stopping, old >> 3))) {} }
bool SourceState::recover(std::uint64_t revision) noexcept
{
    if (revision >= MaxLossRevision || sequence_.load() == std::numeric_limits<std::uint64_t>::max()) return false;
    auto expected = packed(Health::Degraded, revision);
    return status_.compare_exchange_strong(expected, packed(Health::Ready, revision));
}
SourceState::Lease SourceState::acquire() noexcept
{
    const auto before = health();
    if (before.health != Health::Ready) return Lease{};
    auto count = copiers_.load();
    do { if (count >= MaxCopiers) { lost(); return Lease{}; } }
    while (!copiers_.compare_exchange_weak(count, count + 1));
    Lease result(this);
    auto seq = sequence_.load();
    do { if (seq == std::numeric_limits<std::uint64_t>::max()) { lost(); return Lease{}; } }
    while (!sequence_.compare_exchange_weak(seq, seq + 1));
    if (seq + 1 == std::numeric_limits<std::uint64_t>::max()) { lost(); return Lease{}; }
    result.stamp = {epoch_, seq + 1, generation_}; result.lossRevision = before.lossRevision;
    if (health().health != Health::Ready) return Lease{};
    return result;
}
std::size_t chargedBytes(const OwnedNetEvent& e) noexcept
{
    const auto a = e.identity.appId.bytes.capacity(), u = e.identity.userSid.bytes.capacity(), p = e.identity.packageSid.bytes.capacity();
    if (a > ai::MaximumAppIdBytes || u > ai::MaximumSidBytes || p > ai::MaximumSidBytes) return MaxRecordBytes + 1;
    return sizeof(OwnedNetEvent) + a + u + p;
}
CopyOutcome copyMetadata(const NetEventView& v, SourceState& source) noexcept
{
    auto lease = source.acquire();
    if (!lease) return {Reason::SourceGap, std::nullopt};
    if (v.profile != 3 || (v.type != 3 && v.type != 6)) return {Reason::Unsupported, std::nullopt};
    const auto dir = direction(v.type, v.rawDirection);
    if (!v.classifyPresent || v.classifyType != v.type || dir == Direction::Unknown || !v.filterId || !v.layerId)
        return {Reason::InvalidEvent, std::nullopt};
    if (v.flags & ~0x7ffu || ((v.flags & (LocalAddrSet | RemoteAddrSet)) && !(v.flags & IpVersionSet)) ||
        ((v.flags & IpVersionSet) && v.ipVersion != 0 && v.ipVersion != 1)) return {Reason::BadPresence, std::nullopt};
    if (static_cast<bool>(v.flags & 0x200) != v.reauth.has_value()) return {Reason::BadPresence, std::nullopt};
    try {
        OwnedNetEvent e; e.acquired = lease.stamp; e.acquiredLossRevision = lease.lossRevision;
        e.identity.binding = {lease.stamp.epoch, lease.stamp.sequence};
        auto r = field(v.app, v.flags & AppSet, false, e.identity.appId);
        if (r == Reason::None) r = field(v.user, v.flags & UserSet, true, e.identity.userSid);
        if (r == Reason::None) r = field(v.package, v.flags & PackageSet, true, e.identity.packageSid);
        if (r != Reason::None) return {r, std::nullopt};
        e.profile = v.profile; e.type = v.type; e.flags = v.flags; e.rawDirection = v.rawDirection;
        e.ipVersion = v.flags & IpVersionSet ? v.ipVersion : 0; e.direction = dir;
        e.filterId = v.filterId; e.layerId = v.layerId; e.loopback = v.loopback;
        e.reauth = v.reauth; e.timestamp = v.timestamp; e.receivedMonotonic = v.receivedMonotonic;
        if (chargedBytes(e) > MaxRecordBytes) return {Reason::Oversized, std::nullopt};
        return {Reason::None, std::move(e)};
    } catch (...) { source.lost(); return {Reason::SourceGap, std::nullopt}; }
}
bool BoundedQueue::push(OwnedNetEvent&& event) noexcept
{
    static_assert(std::is_nothrow_move_constructible_v<OwnedNetEvent>);
    try {
        std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
        const auto charge = chargedBytes(event); const auto state = source_.health();
        if (!lock || state.health != Health::Ready || !source_.current(event.acquired) ||
            event.acquiredLossRevision != state.lossRevision || charge > MaxRecordBytes ||
            count_ == MaxRecords || charge > MaxQueueBytes - bytes_) { source_.lost(); return false; }
        slots_[(head_ + count_) % MaxRecords].emplace(std::move(event)); ++count_; bytes_ += charge;
        return true;
    } catch (...) { source_.lost(); return false; }
}
std::optional<OwnedNetEvent> BoundedQueue::take() noexcept
{
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!count_) return std::nullopt;
        auto& slot = slots_[head_]; bytes_ -= chargedBytes(*slot);
        auto result = std::move(slot); slot.reset(); head_ = (head_ + 1) % MaxRecords; --count_;
        return result;
    } catch (...) { source_.lost(); return std::nullopt; }
}
void BoundedQueue::clear() noexcept
{ while (take()) {} }
} // namespace gatebouncer::service::windows::allapps
