#include "NativeCatalog.h"
#include "NativeSource.h"
#include <algorithm>
#include <cstring>
#include <numeric>
#include <stdexcept>

namespace gatebouncer::service::windows::allapps::native
{
namespace
{
constexpr std::size_t ControlBudget = 4096;
bool present(const Guid &g) noexcept
{
    return std::any_of(g.begin(), g.end(), [](auto b) { return b != 0; });
}
bool sliceFits(ArenaSlice s, std::size_t n) noexcept
{
    return s.offset <= n && s.size <= n - s.offset;
}
} // namespace
CatalogRegistry::CatalogRegistry() : state_(std::make_shared<State>())
{
}
CatalogRegistry::ChargeToken::~ChargeToken()
{
    std::lock_guard<std::mutex> lock(state->mutex);
    state->bytes -= bytes;
    --state->generations;
}
std::shared_ptr<CatalogRegistry::ChargeToken> CatalogRegistry::reserve(std::size_t bytes)
{
    if (bytes > MaxCatalogStorageBytes)
        throw std::length_error("Capacidad de catálogo");
    std::lock_guard<std::mutex> lock(state_->mutex);
    if (state_->generations >= 2 || bytes > MaxLiveCatalogBytes - state_->bytes)
        throw std::length_error("Generaciones de catálogo retenidas");
    auto token = std::make_shared<ChargeToken>(state_, bytes);
    state_->bytes += bytes;
    ++state_->generations;
    return token;
}
CatalogStorageBuilder::CatalogStorageBuilder(CatalogRegistry &registry, std::size_t arenaBytes, std::size_t rules,
                                             std::size_t slots)
{
    if (arenaBytes > MaxPolicyArenaBytes || rules > MaxCatalogRules || slots < 28 || slots > MaxCatalogSlots)
        throw std::length_error("Capacidad de catálogo");
    const auto aux = rules * sizeof(RuleSnapshot) + slots * (sizeof(SlotRecord) + 2 * sizeof(std::uint32_t)) +
                     sizeof(CatalogSnapshot) + ControlBudget;
    if (aux > MaxCatalogAuxBytes)
        throw std::length_error("Auxiliares de catálogo");
    auto charge = registry.reserve(arenaBytes + MaxCatalogAuxBytes);
    auto storage = std::shared_ptr<CatalogSnapshot>(new CatalogSnapshot);
    storage->charge_ = std::move(charge);
    storage->rules_.resize(rules);
    storage->slots_.resize(slots);
    storage->keyIndex_.resize(slots);
    storage->idIndex_.resize(slots);
    const auto actualAux = storage->rules_.capacity() * sizeof(RuleSnapshot) +
                           storage->slots_.capacity() * sizeof(SlotRecord) +
                           (storage->keyIndex_.capacity() + storage->idIndex_.capacity()) * sizeof(std::uint32_t) +
                           sizeof(CatalogSnapshot) + ControlBudget;
    if (actualAux > aux)
        throw std::length_error("Capacity real supera reserva de catálogo");
    reservedArenaBytes_ = arenaBytes;
    storage_ = std::move(storage);
}
std::shared_ptr<const void> CatalogStorageBuilder::budgetFactory(void *context, std::size_t physicalBytes) noexcept
{
    auto *builder = static_cast<CatalogStorageBuilder *>(context);
    if (!builder || !builder->storage_ || physicalBytes > builder->reservedArenaBytes_)
        return {};
    return builder->storage_->charge_;
}
BudgetRetention CatalogStorageBuilder::attachArena(std::shared_ptr<const CatalogArena> arena) noexcept
{
    if (!storage_ || !arena || arena->size() > arena->ownedCapacityBytes() ||
        arena->ownedCapacityBytes() > reservedArenaBytes_ || (arena->size() && !arena->data()))
        return BudgetRetention::Rejected;
    if (storage_->arena_)
        return storage_->arena_ == arena ? BudgetRetention::Existing : BudgetRetention::Rejected;
    const auto result = arena->retainBudget(storage_->charge_->state, this, &budgetFactory);
    // Existing de otro builder no reserva su segunda copia de auxiliares.
    if (result == BudgetRetention::Attached)
        storage_->arena_ = std::move(arena);
    return result == BudgetRetention::Existing ? BudgetRetention::Rejected : result;
}
Reason CatalogStorageBuilder::validateLayout(bool runtimeIds) noexcept
{
    if (!storage_)
        return Reason::StaleStamp;
    auto &s = *storage_;
    if (!s.arena_ || !s.binding_ || !s.revision_ || !s.generation_ || s.recipeRevision_ != 1 || !present(s.provider_) ||
        !present(s.sublayer_) || s.supportCount_ > s.support_.size())
        return Reason::InvalidEvent;
    for (std::size_t i = 0; i < s.domain_.size(); ++i)
    {
        if (!s.domain_[i])
            return Reason::InvalidEvent;
        for (std::size_t j = 0; j < i; ++j)
            if (s.domain_[i] == s.domain_[j])
                return Reason::Ambiguous;
    }
    std::size_t count = 28;
    for (std::size_t i = 0; i < s.rules_.size(); ++i)
    {
        const auto &r = s.rules_[i];
        if (!sliceFits(r.app, s.arena_->size()) || !sliceFits(r.user, s.arena_->size()) ||
            !sliceFits(r.package, s.arena_->size()) || !r.slotCount || r.slotCount > 6 || r.slotBegin != count ||
            count > s.slots_.size() || r.slotCount > s.slots_.size() - count)
            return Reason::InvalidEvent;
        if (r.desired != s.desired_ || r.filterGeneration != s.generation_)
            return Reason::InvalidEvent;
        auto view = s.ruleView(i);
        const auto reason = recipe::validateRule(view, {s.support_.data(), s.supportCount_});
        if (reason != Reason::None)
            return reason;
        std::uint32_t required = 0;
        if (recipe::slotCount(view, required) != Reason::None || required != r.slotCount)
            return Reason::InvalidEvent;
        count += r.slotCount;
    }
    if (count != s.slots_.size())
        return Reason::InvalidEvent;
    // Reutiliza el índice preasignado; dos reglas no pueden compartir el ID aunque tengan direcciones disjuntas.
    std::iota(s.keyIndex_.begin(), s.keyIndex_.begin() + s.rules_.size(), 0u);
    std::sort(s.keyIndex_.begin(), s.keyIndex_.begin() + s.rules_.size(),
              [&](auto a, auto b) { return s.rules_[a].rule < s.rules_[b].rule; });
    for (std::size_t i = 1; i < s.rules_.size(); ++i)
        if (s.rules_[s.keyIndex_[i - 1]].rule == s.rules_[s.keyIndex_[i]].rule)
            return Reason::Ambiguous;
    for (std::size_t i = 0; i < s.slots_.size(); ++i)
    {
        const auto &slot = s.slots_[i];
        if (!present(slot.key) || slot.layer >= 8 ||
            (runtimeIds ? (!slot.id || slot.layerId != s.domain_[slot.layer]) : (slot.id || slot.layerId)))
            return Reason::InvalidEvent;
        if (i < 28)
        {
            if (slot.ruleIndex != BaselineRuleIndex || slot.slot != i)
                return Reason::InvalidEvent;
        }
        else
        {
            if (slot.ruleIndex >= s.rules_.size() || slot.slot >= 6 || slot.layer != slot.slot)
                return Reason::InvalidEvent;
            const auto &rule = s.rules_[slot.ruleIndex];
            if (i < rule.slotBegin || i >= rule.slotBegin + rule.slotCount || !(rule.slotMask & (1u << slot.slot)))
                return Reason::InvalidEvent;
        }
    }
    std::iota(s.keyIndex_.begin(), s.keyIndex_.end(), 0u);
    std::iota(s.idIndex_.begin(), s.idIndex_.end(), 0u);
    std::sort(s.keyIndex_.begin(), s.keyIndex_.end(),
              [&](auto a, auto b) { return s.slots_[a].key < s.slots_[b].key; });
    std::sort(s.idIndex_.begin(), s.idIndex_.end(), [&](auto a, auto b) { return s.slots_[a].id < s.slots_[b].id; });
    for (std::size_t i = 1; i < s.slots_.size(); ++i)
    {
        if (s.slots_[s.keyIndex_[i - 1]].key == s.slots_[s.keyIndex_[i]].key ||
            (runtimeIds && s.slots_[s.idIndex_[i - 1]].id == s.slots_[s.idIndex_[i]].id))
            return Reason::Ambiguous;
    }
    recipe::RecipeWorkspace workspace{};
    for (std::size_t i = 0; i < s.slots_.size(); ++i)
    {
        recipe::ExpectedFilterView expected;
        const auto reason = s.expectedSlot(i, workspace, expected);
        if (reason != Reason::None)
            return reason;
        if (guidBytes(expected.provider) != s.provider_ || guidBytes(expected.sublayer) != s.sublayer_ ||
            guidBytes(expected.layer) != guidBytes(nativeLayerGuid(static_cast<NativeLayer8>(s.slots_[i].layer))))
            return Reason::ForeignFilter;
    }
    return Reason::None;
}
recipe::RuleView CatalogSnapshot::ruleView(std::size_t index) const noexcept
{
    const auto &source = rules_[index];
    recipe::RuleView view;
    view.ruleId = source.rule;
    view.selectorId = source.selector;
    view.ruleRevision = source.ruleRevision;
    view.targetRevision = source.targetRevision;
    view.desired = source.desired;
    view.filterGeneration = source.filterGeneration;
    view.recipeRevision = recipeRevision_;
    view.action = source.action;
    view.direction = source.direction;
    view.mode = source.mode;
    view.origin = source.origin;
    view.scope = source.scope;
    view.packageMode = source.packageMode;
    view.targetKind = source.targetKind;
    view.slotMask = source.slotMask;
    view.remoteCondition = source.remoteCondition;
    auto bytes = [&](ArenaSlice slice) -> recipe::ByteView {
        if (!arena_ || !sliceFits(slice, arena_->size()) || !slice.size)
            return {};
        return {arena_->data() + slice.offset, slice.size};
    };
    view.app = bytes(source.app);
    view.user = bytes(source.user);
    view.package = bytes(source.package);
    return view;
}
Reason CatalogSnapshot::expectedSlot(std::size_t index, recipe::RecipeWorkspace &workspace,
                                     recipe::ExpectedFilterView &expected) const noexcept
{
    if (index >= slots_.size())
        return Reason::InvalidEvent;
    const auto &slot = slots_[index];
    if (slot.layer >= 8 || (slot.ruleIndex != BaselineRuleIndex && slot.ruleIndex >= rules_.size()))
        return Reason::InvalidEvent;
    recipe::RuleView rule;
    recipe::SlotView view;
    if (slot.ruleIndex != BaselineRuleIndex)
    {
        rule = ruleView(slot.ruleIndex);
        view.rule = &rule;
    }
    view.ordinal = slot.slot;
    view.layer = static_cast<NativeLayer8>(slot.layer);
    std::memcpy(&view.key, slot.key.data(), sizeof(view.key));
    view.desired = desired_;
    view.filterGeneration = generation_;
    view.runtimeFilterId = slot.id;
    view.runtimeLayerId = slot.layerId;
    return recipe::buildExpectedView(view, workspace, expected);
}
Reason CatalogSnapshot::compareSlot(std::size_t index, const FWPM_FILTER0 *borrowed,
                                    recipe::RecipeWorkspace &workspace) const noexcept
{
    recipe::ExpectedFilterView expected;
    const auto reason = expectedSlot(index, workspace, expected);
    return reason == Reason::None ? recipe::compareFilter(borrowed, expected, workspace, &guardedRead) : reason;
}
std::shared_ptr<const CatalogSnapshot> CatalogStorageBuilder::freeze() noexcept
{
    if (validateLayout(true) != Reason::None)
        return {};
    std::shared_ptr<const CatalogSnapshot> result = std::move(storage_);
    return result;
}
const SlotRecord *CatalogSnapshot::byId(std::uint64_t id, std::size_t *index) const noexcept
{
    const auto it = std::lower_bound(idIndex_.begin(), idIndex_.end(), id,
                                     [&](auto n, auto value) { return slots_[n].id < value; });
    if (it == idIndex_.end() || slots_[*it].id != id)
        return nullptr;
    if (index)
        *index = *it;
    return &slots_[*it];
}
const SlotRecord *CatalogSnapshot::byKey(const Guid &key, std::size_t *index) const noexcept
{
    const auto it = std::lower_bound(keyIndex_.begin(), keyIndex_.end(), key,
                                     [&](auto n, const auto &value) { return slots_[n].key < value; });
    if (it == keyIndex_.end() || slots_[*it].key != key)
        return nullptr;
    if (index)
        *index = *it;
    return &slots_[*it];
}
const GUID &nativeLayerGuid(NativeLayer8 layer) noexcept
{
    static const GUID values[] = {FWPM_LAYER_ALE_AUTH_CONNECT_V4,        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                                  FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                                  FWPM_LAYER_ALE_AUTH_LISTEN_V4,         FWPM_LAYER_ALE_AUTH_LISTEN_V6,
                                  FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4, FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6};
    static const GUID invalid{};
    const auto i = static_cast<std::uint8_t>(layer);
    return i < 8 ? values[i] : invalid;
}
std::optional<NativeLayer8> nativeLayer(const GUID &guid) noexcept
{
    const auto bytes = guidBytes(guid);
    for (std::uint8_t i = 0; i < 8; ++i)
        if (bytes == guidBytes(nativeLayerGuid(static_cast<NativeLayer8>(i))))
            return static_cast<NativeLayer8>(i);
    return {};
}
} // namespace gatebouncer::service::windows::allapps::native
