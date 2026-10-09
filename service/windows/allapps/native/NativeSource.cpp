#include "NativeSource.h"
#include <stdexcept>
#include <algorithm>
#include <system_error>

namespace gatebouncer::service::windows::allapps::native {
namespace {
bool present(const Guid& id) noexcept { return std::any_of(id.begin(), id.end(), [](auto b) { return b != 0; }); }
template<class F> struct Exit { F fn; ~Exit() noexcept { fn(); } };
template<class F> Exit<F> onExit(F fn) { return {fn}; }
}
EngineLease::EngineLease(HANDLE h, std::shared_ptr<void> life) : engine_(h), lifetime_(std::move(life))
{ if (!h || h == INVALID_HANDLE_VALUE || !lifetime_) throw std::invalid_argument("Invalid engine lease"); }
BindReceipt::BindReceipt(gb::wire::Id e, std::uint64_t g) : epoch_(e), generation_(g)
{ if (!present(e) || !g) throw std::invalid_argument("Invalid source binding"); }
CatalogReceipt::CatalogReceipt(std::shared_ptr<const BindingState> b, std::uint64_t r, std::vector<CatalogEntry> entries)
    : binding_(std::move(b)), revision_(r), entries_(std::make_shared<const std::vector<CatalogEntry>>(std::move(entries)))
{
    if (!binding_ || !r || entries_->empty() || entries_->capacity() > MaxRecords) throw std::invalid_argument("Invalid catalog");
    std::size_t charged = entries_->capacity() * sizeof(CatalogEntry);
    for (const auto& entry : *entries_) {
        const auto& s = entry.shape;
        if (s.conditions.capacity() > MaxConditions) throw std::length_error("Condition capacity");
        std::size_t bytes = sizeof(s) + s.conditions.capacity() * sizeof(ConditionShape);
        for (const auto& c : s.conditions) {
            if (c.bytes.capacity() > MaxProofBytes || bytes > MaxProofBytes - c.bytes.capacity()) throw std::length_error("Condition capacity");
            bytes += c.bytes.capacity();
        }
        if (!s.id || !present(s.key) || !present(s.provider) || !present(s.sublayer) || logicalLayer(s.layer) == Layer::Unknown ||
            s.conditions.size() > MaxConditions || bytes > MaxProofBytes || charged > MaxQueueBytes - bytes ||
            (entry.role != Role::UnknownAppGate && entry.role != Role::ExplicitBlock && entry.role != Role::ExplicitAllow) ||
            ((entry.role == Role::ExplicitAllow) ? s.action != FWP_ACTION_PERMIT : s.action != FWP_ACTION_BLOCK) ||
            s.provider != entries_->front().shape.provider || s.sublayer != entries_->front().shape.sublayer)
            throw std::invalid_argument("Invalid catalog entry");
        charged += bytes;
        for (const auto& other : *entries_) if (&entry != &other && (s.id == other.shape.id || s.key == other.shape.key))
            throw std::invalid_argument("Duplicate catalog entry");
    }
}
NativeSource::NativeSource(EngineLease engine, BindReceipt bind, SdkApi sdk)
    : engine_(std::move(engine)), sdk_(std::move(sdk)), binding_([&] {
        LUID luid{};
        if (!sdk_.allocate) throw std::invalid_argument("Missing source index API");
        if (!sdk_.allocate(&luid)) throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "Source index allocation failed");
        const auto index = (std::uint64_t(static_cast<std::uint32_t>(luid.HighPart)) << 32) | luid.LowPart;
        if (!index || index == std::numeric_limits<std::uint64_t>::max()) throw std::runtime_error("Invalid source index");
        return std::shared_ptr<const BindingState>(new BindingState(bind.epoch_, index, bind.generation_));
      }()), source_(binding_->index, binding_->generation), queue_(source_)
{ for (auto& slot : slots_) slot.store(false); }
Reason NativeSource::start(const CatalogReceipt& catalog) noexcept
{
    try {
        auto keep = shared_from_this();
        if (catalog.binding_ != binding_ || !sdk_.copy || !sdk_.subscribe || !sdk_.unsubscribe || !sdk_.module || !sdk_.option || !sdk_.filter ||
            !sdk_.layer || !sdk_.freeMemory || !sdk_.begin || !sdk_.abort || !sdk_.createEnum || !sdk_.enumerate || !sdk_.destroyEnum)
            return Reason::Unsupported;
        if (!control_.begin()) return Reason::SourceGap;
        std::atomic_store(&retained_, keep); // Antes del RPC: retiene sesión, módulo y contexto incluso si no vuelve.
        FWPM_NET_EVENT_SUBSCRIPTION0 subscription{};
        HANDLE late = nullptr;
        const auto result = sdk_.subscribe(engine_.engine_, &subscription, &callback, this, &late);
        if (auto h = control_.publish(result, late, seen_.load())) cancel(h);
        Reason reason = Reason::SourceGap;
        if (result == ERROR_SUCCESS && late && control_.beginWorker(true)) {
            const auto revision = source_.health().lossRevision;
            reason = reconcile(catalog);
            if (!poisoned_.load()) if (auto h = control_.finishWorker()) cancel(h);
            if (reason == Reason::None && !poisoned_.load()) {
                auto health = source_.health();
                const bool ready = (health.health == Health::Ready && health.lossRevision == revision) || source_.recover(revision);
                if (ready && control_.activate()) admission_.store(true);
                else reason = Reason::SourceGap;
            }
        }
        if (reason != Reason::None) { source_.lost(); source_.stop(); if (auto h = control_.requestStop()) cancel(h); }
        control_.finishStart(); finalize();
        return reason;
    } catch (...) { poisoned_.store(true); admission_.store(false); source_.lost(); return Reason::SourceGap; }
}
void NativeSource::cancel(HANDLE h)
{ auto keep = shared_from_this(); control_.finishCancel(sdk_.unsubscribe(engine_.engine_, h)); }
void NativeSource::finalize()
{
    if (!poisoned_.load() && control_.drain(callbacks_.load(), source_.inFlight())) {
        queue_.clear(); std::atomic_store(&retained_, std::shared_ptr<NativeSource>{});
    }
}
Stage NativeSource::stop() noexcept
{
    try {
        auto keep = shared_from_this(); admission_.store(false); source_.stop();
        if (auto h = control_.requestStop()) cancel(h);
        finalize(); return stage();
    } catch (...) { poisoned_.store(true); return Stage::FaultRetained; }
}
Stage NativeSource::stage() const noexcept
{ try { return poisoned_.load() ? Stage::FaultRetained : control_.stage(); } catch (...) { return Stage::FaultRetained; } }
void CALLBACK NativeSource::callback(void* context, const FWPM_NET_EVENT3* event) noexcept
{ if (context) static_cast<NativeSource*>(context)->emit(event); }
void NativeSource::emit(const FWPM_NET_EVENT3* event) noexcept
{
    unsigned count = callbacks_.load();
    do { if (count == std::numeric_limits<unsigned>::max()) { poisoned_.store(true); source_.lost(); return; } }
    while (!callbacks_.compare_exchange_weak(count, count + 1));
    auto rundown = onExit([this] { callbacks_.fetch_sub(1); });
    seen_.store(true);
    if (!admission_.load()) { source_.lost(); return; }
    const auto binding = binding_; const auto before = source_.health();
    unsigned slot = MaxCopiers;
    for (unsigned i = 0; i < MaxCopiers; ++i) { bool empty = false; if (slots_[i].compare_exchange_strong(empty, true)) { slot = i; break; } }
    if (slot == MaxCopiers) { source_.lost(); return; }
    auto release = onExit([this, slot] { slots_[slot].store(false); });
    const auto copied = sdk_.copy(event, pool_[slot], GetTickCount64());
    if (copied != Reason::None) { if (copied == Reason::Unreadable || copied == Reason::Oversized) source_.lost(); return; }
    auto result = copyMetadata(pool_[slot].view, source_);
    const auto after = source_.health();
    if (!result.event) { if (result.reason == Reason::Oversized) source_.lost(); return; }
    if (!admission_.load() || binding != binding_ || before.health != Health::Ready || after.health != Health::Ready ||
        before.lossRevision != after.lossRevision || result.event->acquiredLossRevision != before.lossRevision ||
        result.event->acquired.epoch != binding->index || result.event->acquired.generation != binding->generation) return;
    queue_.push(std::move(*result.event));
}
bool NativeSource::valid(const NativeCopiedMetadata& value) const noexcept
{
    const auto h = source_.health();
    return admission_.load() && !poisoned_.load() && value.binding_ == binding_ && value.binding_->epoch == binding_->epoch &&
        value.binding_->index == binding_->index && value.binding_->generation == binding_->generation && source_.current(value.event_.acquired) &&
        h.health == Health::Ready && h.lossRevision == value.event_.acquiredLossRevision;
}
std::optional<NativeCopiedMetadata> NativeSource::takeCopied() noexcept
{
    try { auto event = queue_.take(); if (!event) return {}; NativeCopiedMetadata result(std::move(*event), binding_);
        if (!valid(result)) return {}; return result;
    } catch (...) { source_.lost(); return {}; }
}
bool NativeSource::recover(const RecoveryReceipt& receipt) noexcept
{ return receipt.binding_ == binding_ && !poisoned_.load() && source_.recover(receipt.revision_); }
EvidenceOutcome NativeSource::evaluate(const NativeCopiedMetadata& event, const NativeProof& proof, ai::SidFormatter& formatter) const noexcept
{
    EvidenceOutcome unknown; unknown.reason = Reason::StaleStamp;
    if (!valid(event) || proof.binding_ != binding_ || !(proof.stamp_ == event.event_.acquired) || proof.loss_ != event.event_.acquiredLossRevision) return unknown;
    auto result = allapps::evaluate(event.event_, source_, {proof.view_.provider, proof.view_.sublayer}, proof.view_, formatter);
    return valid(event) && proof.binding_ == binding_ ? result : unknown;
}
} // namespace gatebouncer::service::windows::allapps::native
