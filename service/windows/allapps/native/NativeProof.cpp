#include "NativeRecipe.h"
#include "NativeSource.h"
#include <algorithm>
#include <cstring>

namespace gatebouncer::service::windows::allapps::native
{
namespace
{
struct Memory
{
    const SdkApi &api;
    void *value = nullptr;
    ~Memory()
    {
        if (value)
            api.freeMemory(&value);
    }
};
struct Transaction
{
    const SdkApi &api;
    HANDLE engine;
    bool &fault;
    std::atomic<bool> &poison;
    bool open = false;
    Transaction(const SdkApi &a, HANDLE e, bool &f, std::atomic<bool> &p) : api(a), engine(e), fault(f), poison(p)
    {
        open = api.begin(engine, FWPM_TXN_READ_ONLY) == ERROR_SUCCESS;
    }
    bool close()
    {
        if (!open)
            return !fault;
        open = false;
        if (api.abort(engine) != ERROR_SUCCESS)
        {
            fault = true;
            poison.store(true);
        }
        return !fault;
    }
    ~Transaction()
    {
        close();
    }
};
struct Enumeration
{
    const SdkApi &api;
    HANDLE engine, handle = nullptr;
    bool &fault;
    std::atomic<bool> &poison;
    bool close()
    {
        if (!handle)
            return !fault;
        auto h = handle;
        handle = nullptr;
        if (api.destroyEnum(engine, h) != ERROR_SUCCESS)
        {
            fault = true;
            poison.store(true);
        }
        return !fault;
    }
    ~Enumeration()
    {
        close();
    }
};
} // namespace
bool NativeSource::readOptions()
{
    Memory collect{sdk_}, keywords{sdk_};
    if (sdk_.option(engine_.engine_, FWPM_ENGINE_COLLECT_NET_EVENTS, reinterpret_cast<FWP_VALUE0 **>(&collect.value)) !=
            ERROR_SUCCESS ||
        sdk_.option(engine_.engine_, FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS,
                    reinterpret_cast<FWP_VALUE0 **>(&keywords.value)) != ERROR_SUCCESS)
        return false;
    FWP_VALUE0 c{}, k{};
    if (!guardedRead(&c, collect.value, sizeof(c)) || !guardedRead(&k, keywords.value, sizeof(k)) ||
        c.type != FWP_UINT32 || k.type != FWP_UINT32 || c.uint32 != 1)
        return false;
    keywords_.store(k.uint32); // Raw: no reinterpretar keywords como cobertura o ausencia de tráfico.
    return true;
}
Reason NativeSource::readInventory(const CatalogReceipt &receipt)
{
    return readInventory(engine_.engine_, receipt);
}
bool NativeSource::retainedCause(const NativeCopiedMetadata &event, const NativeProof &proof,
    const CatalogReceipt &receipt, Stage required) const noexcept
{
    const auto snapshot = std::atomic_load(&catalog_);
    if ((required != Stage::Active && required != Stage::Drained) || stage() != required ||
        poisoned_.load() || !snapshot || receipt.snapshot_ != snapshot || receipt.binding_ != binding_ ||
        event.binding_ != binding_ || event.snapshot_ != snapshot || proof.binding_ != event.binding_ ||
        proof.snapshot_ != event.snapshot_ || !(proof.stamp_ == event.event_.acquired) ||
        proof.loss_ != event.event_.acquiredLossRevision ||
        source_.health().lossRevision != proof.loss_ || proof.view_.role != Role::UnknownAppGate ||
        proof.view_.action != Action::Block) return false;
    // Drained conserva sólo la causa adquirida; no recrea Current, cobertura
    // temporal ni una solicitud retenida en el socket.
    return required == Stage::Drained || valid(event);
}
Reason NativeSource::readInventory(HANDLE engine, const CatalogReceipt &receipt)
{
    if (!engine) return Reason::SourceGap;
    if (receipt.binding_ != binding_ || receipt.snapshot_ != std::atomic_load(&catalog_))
        return Reason::StaleStamp;
    const auto &catalog = *receipt.snapshot_;
    constexpr std::size_t BitmapBytes = (MaxCatalogSlots + 7) / 8;
    struct Workspace
    {
        recipe::RecipeWorkspace recipe;
        std::array<std::uint8_t, BitmapBytes> seenDomain{}, seenGlobalOwn{};
    } workspace{};
    static_assert(sizeof(Workspace) + 2048 <= 64 * 1024);
    bool cleanupFault = false;
    std::size_t domainCount = 0, globalCount = 0, globalOwnCount = 0, domainPages = 0;
    const auto providerBytes = catalog.provider_;
    GUID provider{};
    std::memcpy(&provider, providerBytes.data(), sizeof(provider));
    auto scan = [&](const GUID *layer) -> Reason {
        FWPM_FILTER_ENUM_TEMPLATE0 pattern{};
        if (layer)
        {
            pattern.providerKey = &provider;
            pattern.layerKey = *layer;
            pattern.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED;
            pattern.flags = FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;
            pattern.actionMask = 0xffffffffu;
        }
        Enumeration enumeration{sdk_, engine, nullptr, cleanupFault, poisoned_};
        if (sdk_.createEnum(engine, layer ? &pattern : nullptr, &enumeration.handle) != ERROR_SUCCESS ||
            !enumeration.handle)
            return Reason::SourceGap;
        bool terminal = false;
        for (std::size_t page = 0; !terminal; ++page)
        {
            if (layer ? (++domainPages > 1553) : (page >= 4097))
                return Reason::Exhausted;
            Memory memory{sdk_};
            UINT32 returned = 0;
            if (sdk_.enumerate(engine, enumeration.handle, 16,
                               reinterpret_cast<FWPM_FILTER0 ***>(&memory.value), &returned) != ERROR_SUCCESS ||
                returned > 16 || (returned && !memory.value))
                return Reason::SourceGap;
            terminal = returned < 16;
            for (UINT32 i = 0; i < returned; ++i)
            {
                if (!layer && ++globalCount > 65536)
                    return Reason::Exhausted;
                FWPM_FILTER0 *borrowed = nullptr;
                FWPM_FILTER0 header{};
                GUID actualProvider{};
                const auto base = reinterpret_cast<std::uintptr_t>(memory.value), offset = sizeof(borrowed) * i;
                if (!base || base > UINTPTR_MAX - offset ||
                    !guardedRead(&borrowed, reinterpret_cast<const void *>(base + offset), sizeof(borrowed)) ||
                    !guardedRead(&header, borrowed, sizeof(header)))
                    return Reason::Unreadable;
                if (!header.providerKey)
                {
                    if (layer)
                        return Reason::ForeignFilter;
                    continue;
                }
                if (!guardedRead(&actualProvider, header.providerKey, sizeof(actualProvider)))
                    return Reason::Unreadable;
                if (guidBytes(actualProvider) != providerBytes)
                {
                    if (layer)
                        return Reason::ForeignFilter;
                    continue;
                }
                const auto resolved = nativeLayer(header.layerKey);
                if (!resolved || (layer && guidBytes(header.layerKey) != guidBytes(*layer)))
                    return Reason::ForeignFilter;
                std::size_t index = 0;
                const auto *slot = catalog.byKey(guidBytes(header.filterKey), &index);
                if (!slot || slot->id != header.filterId || slot->layer != static_cast<std::uint8_t>(*resolved))
                    return Reason::ForeignFilter;
                auto &seen = layer ? workspace.seenDomain : workspace.seenGlobalOwn;
                const auto mask = static_cast<std::uint8_t>(1u << (index % 8));
                if (seen[index / 8] & mask)
                    return Reason::Ambiguous;
                const auto reason = catalog.compareSlot(index, borrowed, workspace.recipe);
                if (reason != Reason::None)
                    return reason;
                seen[index / 8] |= mask;
                if (layer)
                {
                    if (++domainCount > catalog.slots_.size())
                        return Reason::ForeignFilter;
                }
                else
                {
                    if (++globalOwnCount > catalog.slots_.size())
                        return Reason::ForeignFilter;
                }
            }
        }
        return enumeration.close() ? Reason::None : Reason::SourceGap;
    };
    for (std::uint8_t i = 0; i < 8; ++i)
    {
        const auto &layer = nativeLayerGuid(static_cast<NativeLayer8>(i));
        const auto reason = scan(&layer);
        if (reason != Reason::None)
            return reason;
    }
    if (domainCount != catalog.slots_.size())
        return Reason::ForeignFilter;
    const auto reason = scan(nullptr);
    if (reason != Reason::None)
        return reason;
    if (cleanupFault || poisoned_.load())
        return Reason::SourceGap;
    if (globalOwnCount != catalog.slots_.size())
        return Reason::ForeignFilter;
    return receipt.snapshot_ == std::atomic_load(&catalog_) ? Reason::None : Reason::StaleStamp;
}
Reason NativeSource::reconcile(const CatalogReceipt &catalog)
{
    bool fault = false;
    Transaction transaction(sdk_, engine_.engine_, fault, poisoned_);
    if (!transaction.open)
        return Reason::SourceGap;
    const auto reason = readOptions() ? readInventory(catalog) : Reason::Unsupported;
    if (!transaction.close() || poisoned_.load())
        return Reason::SourceGap;
    return reason;
}
std::vector<ProofOutcome> NativeSource::readCurrentProofBatch(const NativeCopiedMetadata *const *events,
                                                              std::size_t count, const CatalogReceipt &receipt) noexcept
{
    std::vector<ProofOutcome> results;
    try
    {
        if (!events || !count || count > 32)
            return results;
        results.resize(count);
        auto fail = [&](Reason reason) {
            for (auto &result : results)
            {
                result.reason = reason;
                result.proof.reset();
            }
        };
        auto keep = shared_from_this();
        const auto snapshot = receipt.snapshot_;
        if (!snapshot || receipt.binding_ != binding_ || snapshot != std::atomic_load(&catalog_))
        {
            fail(Reason::StaleStamp);
            return results;
        }
        const auto loss = source_.health().lossRevision;
        for (std::size_t i = 0; i < count; ++i)
        {
            if (!events[i] || !valid(*events[i]) || events[i]->snapshot_ != snapshot ||
                events[i]->event_.acquiredLossRevision != loss)
            {
                fail(Reason::StaleStamp);
                return results;
            }
        }
        if (!control_.beginWorker())
        {
            fail(Reason::SourceGap);
            return results;
        }
        struct Worker
        {
            NativeSource &owner;
            ~Worker() noexcept
            {
                try
                {
                    if (!owner.poisoned_.load())
                    {
                        if (auto h = owner.control_.finishWorker())
                            owner.cancel(h);
                        owner.finalize();
                    }
                }
                catch (...)
                {
                    owner.poisoned_.store(true);
                }
            }
        } worker{*this};
        bool fault = false;
        Transaction transaction(sdk_, engine_.engine_, fault, poisoned_);
        if (!transaction.open || !readOptions())
        {
            source_.lost();
            fail(Reason::SourceGap);
            return results;
        }
        auto reason = readInventory(receipt);
        if (reason != Reason::None)
        {
            source_.lost();
            fail(reason);
            return results;
        }
        recipe::RecipeWorkspace workspace{};
        static_assert(2 * sizeof(recipe::RecipeWorkspace) + 2 * ((MaxCatalogSlots + 7) / 8) + 8192 <= 64 * 1024);
        for (std::size_t i = 0; i < count; ++i)
        {
            const auto &event = *events[i];
            if (!valid(event))
            {
                fail(Reason::StaleStamp);
                return results;
            }
            std::size_t index = 0;
            const auto *slot = snapshot->byId(event.event_.filterId, &index);
            if (!slot || slot->layerId != event.event_.layerId || slot->layer >= 4)
            {
                fail(slot && slot->layer >= 4 ? Reason::Unsupported : Reason::ForeignFilter);
                return results;
            }
            Memory filter{sdk_}, layer{sdk_};
            if (sdk_.filter(engine_.engine_, event.event_.filterId, reinterpret_cast<FWPM_FILTER0 **>(&filter.value)) !=
                    ERROR_SUCCESS ||
                sdk_.layer(engine_.engine_, event.event_.layerId, reinterpret_cast<FWPM_LAYER0 **>(&layer.value)) !=
                    ERROR_SUCCESS)
            {
                source_.lost();
                fail(Reason::ForeignFilter);
                return results;
            }
            FWPM_LAYER0 layerData{};
            reason = snapshot->compareSlot(index, static_cast<FWPM_FILTER0 *>(filter.value), workspace);
            if (reason != Reason::None || !guardedRead(&layerData, layer.value, sizeof(layerData)))
            {
                source_.lost();
                fail(reason == Reason::None ? Reason::Unreadable : reason);
                return results;
            }
            const auto layerKey = guidBytes(nativeLayerGuid(static_cast<NativeLayer8>(slot->layer)));
            if (layerData.layerId != slot->layerId || guidBytes(layerData.layerKey) != layerKey)
            {
                source_.lost();
                fail(Reason::ForeignFilter);
                return results;
            }
            CurrentView view;
            view.reconciled = event.event_.acquired;
            view.inventoryRevision = snapshot->revision_;
            view.filterId = slot->id;
            view.layerId = slot->layerId;
            view.filterKey = slot->key;
            view.provider = snapshot->provider_;
            view.sublayer = snapshot->sublayer_;
            view.layerKey = layerKey;
            view.layer = logicalLayer(layerKey);
            const bool baseline = slot->ruleIndex == BaselineRuleIndex;
            const bool permit = !baseline && snapshot->rules_[slot->ruleIndex].action == 2;
            view.role = baseline ? Role::UnknownAppGate : permit ? Role::ExplicitAllow : Role::ExplicitBlock;
            view.action = permit ? Action::Permit : Action::Block;
            view.active = view.conditions = Confirmation::Exact;
            // La lectura accesible no acredita continuidad temporal ni cobertura del enforcement.
            view.temporal = view.inventory = Confirmation::Missing;
            results[i].proof = NativeProof(binding_, snapshot, event.event_.acquired, event.event_.acquiredLossRevision,
                                           std::move(view));
        }
        if (!transaction.close() || poisoned_.load())
        {
            fail(Reason::SourceGap);
            return results;
        }
        for (std::size_t i = 0; i < count; ++i)
            if (!valid(*events[i]) || events[i]->snapshot_ != snapshot)
            {
                fail(Reason::StaleStamp);
                return results;
            }
        return results;
    }
    catch (...)
    {
        poisoned_.store(true);
        source_.lost();
        for (auto &result : results)
        {
            result.reason = Reason::SourceGap;
            result.proof.reset();
        }
        return results;
    }
}
ProofOutcome NativeSource::readCurrentProof(const NativeCopiedMetadata &event, const CatalogReceipt &receipt) noexcept
{
    const NativeCopiedMetadata *input = &event;
    auto result = readCurrentProofBatch(&input, 1, receipt);
    return result.empty() ? ProofOutcome{Reason::Exhausted, {}} : std::move(result.front());
}
} // namespace gatebouncer::service::windows::allapps::native
