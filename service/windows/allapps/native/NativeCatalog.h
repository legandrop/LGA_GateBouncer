#pragma once
#include "../../../../common/wire_v1.h"
#include "NativeRecipe.h"
#include "NativeShape.h"
#include <memory>

namespace gb::decisions
{
class NativeRuntime;
class CatalogPlanBuilder;
} // namespace gb::decisions
namespace gb::principal
{
class ByteView;
}
namespace gatebouncer::service::windows::allapps::native
{
class BindingState;
class NativeSource;
using NativeLayer8 = recipe::NativeLayer8;
constexpr std::size_t MaxCatalogRules = 4096, MaxCatalogSlots = 24604;
constexpr std::size_t MaxPolicyArenaBytes = 32 * 1024 * 1024;
constexpr std::size_t MaxCatalogAuxBytes = 8 * 1024 * 1024;
constexpr std::size_t MaxCatalogStorageBytes = MaxPolicyArenaBytes + MaxCatalogAuxBytes;
constexpr std::size_t MaxLiveCatalogBytes = 2 * MaxCatalogStorageBytes;
constexpr std::uint32_t BaselineRuleIndex = UINT32_MAX;
enum class BudgetRetention : std::uint8_t
{
    Attached,
    Existing,
    RegistryMismatch,
    Rejected
};
using BudgetFactory = std::shared_ptr<const void> (*)(void *, std::size_t) noexcept;
class CatalogArena
{
    friend class gb::decisions::NativeRuntime;
    friend class gb::decisions::CatalogPlanBuilder;
    friend class CatalogStorageBuilder;
    CatalogArena() = default;
    virtual BudgetRetention retainBudget(std::shared_ptr<const void>, void *, BudgetFactory) const noexcept = 0;

  public:
    virtual ~CatalogArena() = default;
    virtual const std::uint8_t *data() const noexcept = 0;
    virtual std::size_t size() const noexcept = 0;
    virtual std::size_t ownedCapacityBytes() const noexcept = 0;
};
struct ArenaSlice
{
    std::uint32_t offset = 0, size = 0;
};
struct RuleSnapshot
{
    gb::wire::Id rule{}, selector{};
    std::uint64_t ruleRevision = 0, targetRevision = 0, desired = 0, filterGeneration = 0;
    ArenaSlice app, user, package;
    std::uint32_t slotBegin = 0;
    std::uint8_t action = 0, direction = 0, mode = 0, origin = 0;
    std::uint8_t scope = 0, packageMode = 0, targetKind = 0, slotMask = 0, slotCount = 0;
};
struct SlotRecord
{
    Guid key{};
    std::uint64_t id = 0;
    std::uint32_t ruleIndex = BaselineRuleIndex;
    std::uint16_t layerId = 0;
    std::uint8_t slot = 0, layer = 0;
};
static_assert(sizeof(RuleSnapshot) <= 256);
static_assert(sizeof(SlotRecord) <= 128);

// El registro cuenta storage vivo, incluso cuando perdió autoridad y sigue retenido.
class CatalogRegistry
{
    friend class gb::decisions::NativeRuntime;
    friend class gb::decisions::CatalogPlanBuilder;
    friend class CatalogStorageBuilder;
    friend class CatalogSnapshot;
    struct State
    {
        std::mutex mutex;
        std::size_t bytes = 0, generations = 0;
    };
    struct ChargeToken
    {
        std::shared_ptr<State> state;
        std::size_t bytes;
        ChargeToken(std::shared_ptr<State> s, std::size_t b) : state(std::move(s)), bytes(b)
        {
        }
        ChargeToken(const ChargeToken &) = delete;
        ChargeToken &operator=(const ChargeToken &) = delete;
        ~ChargeToken();
    };
    std::shared_ptr<State> state_;
    CatalogRegistry();
    CatalogRegistry(const CatalogRegistry &) = delete;
    CatalogRegistry &operator=(const CatalogRegistry &) = delete;
    std::shared_ptr<ChargeToken> reserve(std::size_t);
};
class CatalogSnapshot
{
    friend class gb::decisions::NativeRuntime;
    friend class gb::decisions::CatalogPlanBuilder;
    friend class CatalogStorageBuilder;
    friend class NativeSource;
    friend class CatalogReceipt;
    // Primero declarado: se libera después de arena/arrays, no antes de sus bytes.
    std::shared_ptr<CatalogRegistry::ChargeToken> charge_;
    std::shared_ptr<const BindingState> binding_;
    std::shared_ptr<const CatalogArena> arena_;
    std::vector<RuleSnapshot> rules_;
    std::vector<SlotRecord> slots_;
    std::vector<std::uint32_t> keyIndex_, idIndex_;
    std::array<std::uint16_t, 8> domain_{};
    std::array<recipe::SupportField, 32> support_{};
    std::uint32_t supportCount_ = 0;
    Guid provider_{}, sublayer_{};
    std::uint64_t revision_ = 0, desired_ = 0, generation_ = 0;
    std::uint32_t recipeRevision_ = 1;
    CatalogSnapshot() = default;
    recipe::RuleView ruleView(std::size_t) const noexcept;
    Reason expectedSlot(std::size_t, recipe::RecipeWorkspace &, recipe::ExpectedFilterView &) const noexcept;
    Reason compareSlot(std::size_t, const FWPM_FILTER0 *, recipe::RecipeWorkspace &) const noexcept;

  public:
    CatalogSnapshot(const CatalogSnapshot &) = delete;
    CatalogSnapshot &operator=(const CatalogSnapshot &) = delete;
    const SlotRecord *byId(std::uint64_t, std::size_t *index = nullptr) const noexcept;
    const SlotRecord *byKey(const Guid &, std::size_t *index = nullptr) const noexcept;
};
class CatalogStorageBuilder
{
    friend class gb::decisions::NativeRuntime;
    friend class gb::decisions::CatalogPlanBuilder;
    std::shared_ptr<CatalogSnapshot> storage_;
    std::size_t reservedArenaBytes_ = 0;
    static std::shared_ptr<const void> budgetFactory(void *, std::size_t) noexcept;
    // El adapter tipado se define en el owner central, sin enlazar su runtime entero en la hoja.
    static std::shared_ptr<const CatalogArena> fromView(const gb::principal::ByteView &);
    explicit CatalogStorageBuilder(CatalogRegistry &, std::size_t arenaBytes, std::size_t rules, std::size_t slots);
    CatalogStorageBuilder(const CatalogStorageBuilder &) = delete;
    CatalogStorageBuilder &operator=(const CatalogStorageBuilder &) = delete;
    BudgetRetention attachArena(std::shared_ptr<const CatalogArena>) noexcept;
    Reason validateLayout(bool runtimeIds) noexcept;
    std::shared_ptr<const CatalogSnapshot> freeze() noexcept;
};
const GUID &nativeLayerGuid(NativeLayer8) noexcept;
std::optional<NativeLayer8> nativeLayer(const GUID &) noexcept;
} // namespace gatebouncer::service::windows::allapps::native
