#include "NativeSource.h"
#include <algorithm>
#include <cstring>

namespace gatebouncer::service::windows::allapps::native {
namespace {
struct Memory {
    const SdkApi& api; void* value = nullptr;
    ~Memory() { if (value) api.freeMemory(&value); }
};
struct Transaction {
    const SdkApi& api; HANDLE engine; bool& fault; std::atomic<bool>& poison; bool open = false;
    Transaction(const SdkApi& a, HANDLE e, bool& f, std::atomic<bool>& p) : api(a), engine(e), fault(f), poison(p)
    { open = api.begin(engine, FWPM_TXN_READ_ONLY) == ERROR_SUCCESS; }
    bool close() { if (!open) return !fault; open = false; if (api.abort(engine) != ERROR_SUCCESS) { fault = true; poison.store(true); } return !fault; }
    ~Transaction() { close(); }
};
struct Enumeration {
    const SdkApi& api; HANDLE engine, handle = nullptr; bool& fault; std::atomic<bool>& poison;
    bool close() { if (!handle) return !fault; auto h = handle; handle = nullptr;
        if (api.destroyEnum(engine, h) != ERROR_SUCCESS) { fault = true; poison.store(true); } return !fault; }
    ~Enumeration() { close(); }
};
}
bool NativeSource::readOptions()
{
    Memory collect{sdk_}, keywords{sdk_};
    if (sdk_.option(engine_.engine_, FWPM_ENGINE_COLLECT_NET_EVENTS, reinterpret_cast<FWP_VALUE0**>(&collect.value)) != ERROR_SUCCESS ||
        sdk_.option(engine_.engine_, FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, reinterpret_cast<FWP_VALUE0**>(&keywords.value)) != ERROR_SUCCESS) return false;
    FWP_VALUE0 c{}, k{};
    if (!guardedRead(&c, collect.value, sizeof(c)) || !guardedRead(&k, keywords.value, sizeof(k)) ||
        c.type != FWP_UINT32 || k.type != FWP_UINT32 || c.uint32 != 1) return false;
    keywords_.store(k.uint32); // Raw: no reinterpretar keywords como cobertura o ausencia de tráfico.
    return true;
}
Reason NativeSource::readInventory(const CatalogReceipt& catalog)
{
    if (catalog.binding_ != binding_) return Reason::StaleStamp;
    std::array<bool, MaxRecords> seen{}; std::size_t count = 0; bool cleanupFault = false;
    const GUID layers[] = {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
    GUID provider{}; std::memcpy(&provider, catalog.entries_->front().shape.provider.data(), sizeof(provider));
    for (const auto& layer : layers) {
        FWPM_FILTER_ENUM_TEMPLATE0 pattern{}; pattern.providerKey = &provider; pattern.layerKey = layer;
        pattern.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED; pattern.flags = FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;
        pattern.actionMask = 0xffffffffu;
        Enumeration enumeration{sdk_, engine_.engine_, nullptr, cleanupFault, poisoned_};
        if (sdk_.createEnum(engine_.engine_, &pattern, &enumeration.handle) != ERROR_SUCCESS || !enumeration.handle) return Reason::SourceGap;
        bool end = false;
        for (unsigned page = 0; page <= MaxRecords && !end; ++page) {
            Memory memory{sdk_}; UINT32 returned = 0;
            if (sdk_.enumerate(engine_.engine_, enumeration.handle, 16, reinterpret_cast<FWPM_FILTER0***>(&memory.value), &returned) != ERROR_SUCCESS ||
                returned > 16 || (returned && !memory.value)) return Reason::SourceGap;
            end = returned < 16;
            for (UINT32 i = 0; i < returned; ++i) {
                FWPM_FILTER0* filter = nullptr;
                if (!guardedRead(&filter, static_cast<FWPM_FILTER0**>(memory.value) + i, sizeof(filter))) return Reason::Unreadable;
                FilterShape shape; auto reason = copyFilterShape(filter, shape); if (reason != Reason::None) return reason;
                if (shape.provider != catalog.entries_->front().shape.provider || shape.layer != guidBytes(layer) || ++count > MaxRecords) return Reason::ForeignFilter;
                auto found = std::find_if(catalog.entries_->begin(), catalog.entries_->end(), [&](const auto& e) { return e.shape.id == shape.id; });
                if (found == catalog.entries_->end() || !sameShape(found->shape, shape)) return Reason::ForeignFilter;
                const auto index = static_cast<std::size_t>(found - catalog.entries_->begin());
                if (seen[index]) return Reason::Ambiguous; seen[index] = true;
            }
        }
        if (!end || !enumeration.close()) { poisoned_.store(true); return Reason::SourceGap; }
    }
    if (cleanupFault) { poisoned_.store(true); return Reason::SourceGap; }
    return count == catalog.entries_->size() ? Reason::None : Reason::ForeignFilter;
}
Reason NativeSource::reconcile(const CatalogReceipt& catalog)
{
    bool fault = false; Transaction transaction(sdk_, engine_.engine_, fault, poisoned_);
    if (!transaction.open) return Reason::SourceGap;
    const auto reason = readOptions() ? readInventory(catalog) : Reason::Unsupported;
    if (!transaction.close()) { poisoned_.store(true); return Reason::SourceGap; }
    return reason;
}
ProofOutcome NativeSource::readCurrentProof(const NativeCopiedMetadata& event, const CatalogReceipt& catalog) noexcept
{
    try {
        auto keep = shared_from_this();
        if (!valid(event) || catalog.binding_ != binding_) return {Reason::StaleStamp, {}};
        if (!control_.beginWorker()) return {Reason::SourceGap, {}};
        struct Worker {
            NativeSource& owner;
            ~Worker() noexcept { try { if (!owner.poisoned_.load()) { if (auto h = owner.control_.finishWorker()) owner.cancel(h); owner.finalize(); } }
                catch (...) { owner.poisoned_.store(true); } }
        } worker{*this};
        bool fault = false; Transaction transaction(sdk_, engine_.engine_, fault, poisoned_);
        if (!transaction.open || !readOptions()) return {Reason::SourceGap, {}};
        auto reason = readInventory(catalog); if (reason != Reason::None) { source_.lost(); return {reason, {}}; }
        Memory filter{sdk_}, layer{sdk_};
        if (sdk_.filter(engine_.engine_, event.event_.filterId, reinterpret_cast<FWPM_FILTER0**>(&filter.value)) != ERROR_SUCCESS ||
            sdk_.layer(engine_.engine_, event.event_.layerId, reinterpret_cast<FWPM_LAYER0**>(&layer.value)) != ERROR_SUCCESS) return {Reason::ForeignFilter, {}};
        FilterShape shape; reason = copyFilterShape(static_cast<FWPM_FILTER0*>(filter.value), shape);
        FWPM_LAYER0 layerData{};
        if (reason != Reason::None || !guardedRead(&layerData, layer.value, sizeof(layerData))) return {Reason::Unreadable, {}};
        auto found = std::find_if(catalog.entries_->begin(), catalog.entries_->end(), [&](const auto& e) { return e.shape.id == shape.id; });
        if (found == catalog.entries_->end() || !sameShape(found->shape, shape) || shape.id != event.event_.filterId ||
            layerData.layerId != event.event_.layerId || guidBytes(layerData.layerKey) != shape.layer) return {Reason::ForeignFilter, {}};
        CurrentView view; view.reconciled = event.event_.acquired; view.inventoryRevision = catalog.revision_;
        view.filterId = shape.id; view.layerId = layerData.layerId; view.filterKey = shape.key; view.provider = shape.provider;
        view.sublayer = shape.sublayer; view.layerKey = shape.layer; view.layer = logicalLayer(shape.layer); view.role = found->role;
        view.action = shape.action == FWP_ACTION_BLOCK ? Action::Block : Action::Permit;
        view.active = view.conditions = Confirmation::Exact;
        // Enum sólo acredita entradas accesibles a READ. Ni snapshot ni LUID acreditan continuidad histórica.
        view.temporal = view.inventory = Confirmation::Missing;
        if (!transaction.close()) { poisoned_.store(true); return {Reason::SourceGap, {}}; }
        if (!valid(event) || catalog.binding_ != binding_) return {Reason::StaleStamp, {}};
        NativeProof proof(binding_, event.event_.acquired, event.event_.acquiredLossRevision, std::move(view));
        return {Reason::None, std::move(proof)};
    } catch (...) { poisoned_.store(true); source_.lost(); return {Reason::SourceGap, {}}; }
}
} // namespace gatebouncer::service::windows::allapps::native
