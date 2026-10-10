#include "catalog_plan_iv.h"
#include "windows/allapps/native/NativeSource.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace gatebouncer::service::windows::allapps::native {
std::shared_ptr<const CatalogArena>
CatalogStorageBuilder::fromView(const gb::principal::ByteView &view) {
  struct OwnedArena final : CatalogArena {
    const gb::principal::ByteView bytes;
    explicit OwnedArena(const gb::principal::ByteView &value) : bytes(value) {}
    const std::uint8_t *data() const noexcept override { return bytes.data(); }
    std::size_t size() const noexcept override { return bytes.size(); }
    std::size_t ownedCapacityBytes() const noexcept override { return bytes.ownedCapacityBytes(); }
    BudgetRetention retainBudget(std::shared_ptr<const void> registry,
                                 void *context, BudgetFactory factory) const noexcept override {
      using Retention = gb::principal::ByteView::BudgetRetention;
      switch (bytes.retainBudget(std::move(registry), context, factory)) {
      case Retention::Attached: return BudgetRetention::Attached;
      case Retention::Existing: return BudgetRetention::Existing;
      case Retention::RegistryMismatch: return BudgetRetention::RegistryMismatch;
      case Retention::Rejected: return BudgetRetention::Rejected;
      }
      return BudgetRetention::Rejected;
    }
  };
  return std::make_shared<const OwnedArena>(view);
}
} // namespace gatebouncer::service::windows::allapps::native

namespace gb::decisions {
namespace recipe = allnative::recipe;
using Reason = gatebouncer::service::windows::allapps::Reason;
namespace {
bool present(const Id &id) noexcept {
  return std::any_of(id.begin(), id.end(), [](auto value) { return value != 0; });
}
// Conservador: cuatro juegos de metadata Store/parser/archive, crecimiento
// vector hasta 2x, nodos de validación, workspace y wrappers. Nunca payload.
constexpr std::size_t MetadataEnvelope =
    4 * 2 * allnative::MaxCatalogRules * (sizeof(principal::Rule) + sizeof(principal::ByteView)) +
    allnative::MaxCatalogRules * 128;
constexpr std::size_t WorkspaceEnvelope = 64 * 1024, ControlEnvelope = 4096;
// Serializer directo: índice de reglas32KiB, entrada nueva≤4KiB, comparación
// APP/SID temporal≤66KiB y testigo/headers/hash/control acotados. Las cuatro
// metadata completas ya están cargadas en MetadataEnvelope; nunca payload32.
constexpr std::size_t WriterEnvelope = 192 * 1024 +
    sizeof(principal::Entry) + sizeof(principal::Snapshot) + sizeof(principal::Legacy) + 64;
bool slice(const principal::ByteView &whole, const principal::ByteView &part,
           allnative::ArenaSlice &out) noexcept {
  out = {};
  if (!part.size())
    return true;
  const auto base = reinterpret_cast<std::uintptr_t>(whole.data());
  const auto address = reinterpret_cast<std::uintptr_t>(part.data());
  if (!base || address < base || address - base > whole.size() ||
      part.size() > whole.size() - (address - base) ||
      address - base > UINT32_MAX || part.size() > UINT32_MAX)
    return false;
  out = {static_cast<std::uint32_t>(address - base), static_cast<std::uint32_t>(part.size())};
  return true;
}
}
CatalogPlanBuilder::CatalogPlanBuilder(allnative::CatalogRegistry &registry,
                                       std::size_t capacity, std::size_t rules,
                                       std::size_t slots)
    : storage_(registry, capacity, rules, slots), maxRules_(rules), maxSlots_(slots) {
  const auto &s = *storage_.storage_;
  const auto aux = sizeof(*this) + sizeof(s) + sizeof(allnative::NativeSource) +
                   ControlEnvelope + MetadataEnvelope + WorkspaceEnvelope + WriterEnvelope +
                   s.rules_.capacity() * sizeof(allnative::RuleSnapshot) +
                   s.slots_.capacity() * sizeof(allnative::SlotRecord) +
                   (s.keyIndex_.capacity() + s.idIndex_.capacity()) * sizeof(std::uint32_t);
  if (aux > allnative::MaxCatalogAuxBytes)
    throw std::length_error("Auxiliares centrales de catálogo");
}
Reason CatalogPlanBuilder::reservationStatus() const noexcept {
  return phase_ == Phase::Reserved && storage_.storage_ ? Reason::None : Reason::StaleStamp;
}
bool CatalogPlanBuilder::retainRead(void *owner, const principal::ByteView &bytes) noexcept {
  return owner && static_cast<CatalogPlanBuilder *>(owner)->retain(bytes);
}
bool CatalogPlanBuilder::retain(const principal::ByteView &bytes) noexcept {
  if (reservationStatus() != Reason::None)
    return false;
  try {
    auto arena = allnative::CatalogStorageBuilder::fromView(bytes);
    const auto &existing = storage_.storage_->arena_;
    if (existing) {
      if (existing->data() != arena->data() || existing->size() != arena->size() ||
          existing->ownedCapacityBytes() != arena->ownedCapacityBytes())
        return false;
      return arena->retainBudget(storage_.storage_->charge_->state, &storage_,
                                 &allnative::CatalogStorageBuilder::budgetFactory) == allnative::BudgetRetention::Existing;
    }
    return storage_.attachArena(std::move(arena)) == allnative::BudgetRetention::Attached;
  } catch (...) { return false; }
}
Reason CatalogPlanBuilder::fail(Reason reason) noexcept {
  phase_ = Phase::Failed;
  reason_ = reason;
  return reason;
}
Reason CatalogPlanBuilder::stage(const principal::ByteView &bytes,
                                 std::shared_ptr<const allnative::BindingState> binding,
                                 std::uint64_t revision,
                                 const std::array<std::uint16_t, 8> &domain,
                                 const recipe::PrincipalSupportView &support) noexcept {
  if (reservationStatus() != Reason::None)
    return Reason::StaleStamp;
  try {
    if (!binding || !present(binding->epoch) || !binding->index || !binding->generation ||
        !revision || support.count > 32 || (support.count && !support.fields))
      return fail(Reason::InvalidEvent);
    if (!retain(bytes))
      return fail(Reason::Exhausted);
    principal::Snapshot parsed;
    if (!principal::parse(bytes, parsed) || parsed.desired == UINT64_MAX)
      return fail(Reason::InvalidEvent);
    initialCandidate_ = parsed.sequence == 1 && !parsed.desired && !parsed.effective && !parsed.storedKnown &&
        parsed.storedState == State::RecoveryRequired && zero(parsed.active) && !zero(parsed.writerEpoch) &&
        parsed.rules.empty() && parsed.entries.empty() && !parsed.archive.size() && !parsed.migrationBase &&
        parsed.activeProjection == Digest{} && parsed.activeAdmission == Digest{} && parsed.archiveDigest == Digest{};
    if (parsed.rules.size() > maxRules_ || parsed.rules.capacity() > 2 * allnative::MaxCatalogRules ||
        parsed.entries.capacity() > 2 * allnative::MaxCatalogRules)
      return fail(Reason::Oversized);
    auto &s = *storage_.storage_;
    s.binding_ = std::move(binding);
    s.revision_ = revision;
    s.desired_ = parsed.desired;
    s.generation_ = parsed.desired + 1;
    s.domain_ = domain;
    s.supportCount_ = static_cast<std::uint32_t>(support.count);
    if (support.count)
      std::copy_n(support.fields, support.count, s.support_.begin());
    s.rules_.resize(parsed.rules.size());
    std::size_t count = 28;
    for (std::size_t i = 0; i < parsed.rules.size(); ++i) {
      const auto &input = parsed.rules[i];
      auto &rule = s.rules_[i];
      rule.rule = input.id;
      rule.selector = input.selector;
      rule.ruleRevision = input.revision;
      rule.targetRevision = input.targetRevision;
      rule.desired = s.desired_;
      rule.filterGeneration = s.generation_;
      rule.action = input.action;
      rule.direction = input.direction;
      rule.mode = input.mode;
      rule.targetKind = input.kind;
      rule.origin = input.kind == 1 || input.kind == 3 ? 1 : 0;
      rule.scope = input.kind == 1 || input.kind == 3 ? 2 : 1;
      rule.slotMask = input.direction == 1 ? 3 : input.direction == 2 ? 0x3c : 0x3f;
      if (input.kind == 1 || input.kind == 3) {
        principal::Target target;
        if (!(input.kind == 3 ? principal::parseConditionalTarget(input.target, target)
                             : principal::parseTarget(input.target, target)) ||
            !slice(bytes, target.app, rule.app) || !slice(bytes, target.user, rule.user) ||
            !slice(bytes, target.package, rule.package))
          return fail(Reason::InvalidEvent);
        rule.packageMode = target.packageMode;
        rule.remoteCondition = target.remoteCondition;
      } else if (!slice(bytes, input.target, rule.app))
        return fail(Reason::InvalidEvent);
      const auto view = s.ruleView(i);
      const auto validated = recipe::validateRule(view, {s.support_.data(), s.supportCount_});
      if (validated != Reason::None)
        return fail(validated);
      std::uint32_t slots = 0;
      const auto counted = recipe::slotCount(view, slots);
      if (counted != Reason::None || slots > maxSlots_ - count)
        return fail(counted == Reason::None ? Reason::Oversized : counted);
      rule.slotBegin = static_cast<std::uint32_t>(count);
      rule.slotCount = static_cast<std::uint8_t>(slots);
      count += slots;
    }
    s.slots_.resize(count);
    s.keyIndex_.resize(count);
    s.idIndex_.resize(count);
    recipe::RecipeWorkspace workspace{};
    auto add = [&](std::size_t index, std::uint32_t ruleIndex, std::uint8_t ordinal) {
      auto &record = s.slots_[index];
      record.ruleIndex = ruleIndex;
      record.slot = ordinal;
      Id id{};
      id[0] = 0xab;
      recipe::RuleView rule;
      recipe::SlotView slot;
      if (ruleIndex != allnative::BaselineRuleIndex) {
        rule = s.ruleView(ruleIndex);
        slot.rule = &rule;
        id = rule.ruleId;
      }
      slot.ordinal = ordinal;
      slot.desired = s.desired_;
      slot.filterGeneration = s.generation_;
      const auto keyResult = recipe::deriveFilterKey(id, ordinal, slot.key);
      if (keyResult != Reason::None)
        return keyResult;
      record.key = allnative::guidBytes(slot.key);
      // La receta única determina la capa; el builder no duplica formas WFP.
      unsigned matches = 0;
      for (std::uint8_t layer = 0; layer < 8; ++layer) {
        slot.layer = static_cast<recipe::NativeLayer8>(layer);
        recipe::ExpectedFilterView expected;
        if (recipe::buildExpectedView(slot, workspace, expected) == Reason::None) {
          record.layer = layer;
          s.provider_ = allnative::guidBytes(expected.provider);
          s.sublayer_ = allnative::guidBytes(expected.sublayer);
          ++matches;
        }
      }
      return matches == 1 ? Reason::None : Reason::InvalidEvent;
    };
    for (std::uint8_t i = 0; i < 28; ++i) {
      const auto result = add(i, allnative::BaselineRuleIndex, i);
      if (result != Reason::None)
        return fail(result);
    }
    for (std::size_t i = 0; i < s.rules_.size(); ++i) {
      const auto &rule = s.rules_[i];
      std::size_t at = rule.slotBegin;
      for (std::uint8_t slot = 0; slot < 6; ++slot)
        if (rule.slotMask & (1u << slot)) {
          const auto result = add(at++, static_cast<std::uint32_t>(i), slot);
          if (result != Reason::None)
            return fail(result);
        }
    }
    const auto validated = storage_.validateLayout(false);
    if (validated != Reason::None)
      return fail(validated);
    phase_ = Phase::Staged;
    return Reason::None;
  } catch (...) {
    return fail(Reason::Exhausted);
  }
}
Reason CatalogPlanBuilder::expected(std::size_t index, recipe::RecipeWorkspace &workspace,
                                    recipe::ExpectedFilterView &out) const noexcept {
  out = {};
  return phase_ == Phase::Staged && storage_.storage_
             ? storage_.storage_->expectedSlot(index, workspace, out) : Reason::StaleStamp;
}
bool CatalogPlanBuilder::detachOutcomeArena() noexcept {
  if (phase_ != Phase::Staged || !storage_.storage_ || outcomePointer_ ||
      observed_ != storage_.storage_->slots_.size() || !storage_.storage_->arena_) return false;
  const auto &arena = storage_.storage_->arena_;
  outcomePointer_ = arena->data(); outcomeSize_ = arena->size(); outcomeCapacity_ = arena->ownedCapacityBytes();
  storage_.storage_->arena_.reset();
  return true;
}
bool CatalogPlanBuilder::attachOutcomeArena(const principal::ByteView &bytes) noexcept {
  if (phase_ != Phase::Staged || !storage_.storage_ || !outcomePointer_ ||
      storage_.storage_->arena_ || bytes.data() != outcomePointer_ || bytes.size() != outcomeSize_ ||
      bytes.ownedCapacityBytes() != outcomeCapacity_) return false;
  try {
    auto arena = allnative::CatalogStorageBuilder::fromView(bytes);
    if (arena->retainBudget(storage_.storage_->charge_->state, &storage_,
          &allnative::CatalogStorageBuilder::budgetFactory) != allnative::BudgetRetention::Existing) return false;
    storage_.storage_->arena_ = std::move(arena);
    outcomePointer_ = nullptr; outcomeSize_ = outcomeCapacity_ = 0;
    return true;
  } catch (...) { return false; }
}
CatalogPlanBuilder::WriteOutcome CatalogPlanBuilder::transact(
    HANDLE engine, const WriteApi &api,
    const std::shared_ptr<const allnative::CatalogSnapshot> &before,
    VerifyBeforeWrite verify, void *context) noexcept {
  if (!before) return {};
  return transactBody(engine,api,before,verify,context,false);
}
CatalogPlanBuilder::WriteOutcome CatalogPlanBuilder::transactInitial(
    HANDLE engine,const WriteApi &api,VerifyBeforeWrite verify,void *context) noexcept {
  return transactBody(engine,api,{},verify,context,true);
}
CatalogPlanBuilder::WriteOutcome CatalogPlanBuilder::transactBody(
    HANDLE engine,const WriteApi &api,const std::shared_ptr<const allnative::CatalogSnapshot> &before,
    VerifyBeforeWrite verify,void *context,bool initial) noexcept {
  WriteOutcome result;
  if (phase_ != Phase::Staged || !storage_.storage_ || writeAttempted_ ||
      !engine || !verify || !context || !api.begin || !api.commit ||
      !api.abort || !api.erase || !api.add)
    return result;
  const auto &after = *storage_.storage_;
  if (!after.binding_) return result;
  // El actor actual sólo admite APT1. Representar/cotejar APT2 no autoriza una
  // escritura: el puente de admisión original debe adquirir todas las condiciones
  // y precedencia antes de reemplazar esta guarda, también para borrar reglas.
  auto conditional = [](const auto &catalog) {
    return std::any_of(catalog.rules_.begin(), catalog.rules_.end(),
                       [](const auto &rule) { return rule.targetKind == 3; });
  };
  if (conditional(after) || (before && conditional(*before))) {
    result.error = ERROR_NOT_SUPPORTED;
    return result;
  }
  if (initial) {
    if (before || !initialCandidate_ || !after.arena_ || after.desired_ || after.generation_ != 1 ||
        !after.rules_.empty() || after.slots_.size() != 28) return result;
  } else if (!before || !before->binding_ ||
      after.binding_->epoch != before->binding_->epoch ||
      after.binding_->generation != before->binding_->generation ||
      before->desired_ == UINT64_MAX ||
      after.desired_ != before->desired_ + 1 ||
      after.provider_ != before->provider_ || after.sublayer_ != before->sublayer_)
    return result;
  // Consumir el intento antes de Begin: un fallo o excepción no habilita replay.
  writeAttempted_ = true;
  result.attempted = true;
  bool transaction = false;
  struct Abort {
    HANDLE engine; const WriteApi &api; bool &open; WriteOutcome &result;
    ~Abort() noexcept {
      if (open) {
        open = false;
        if (api.abort(engine) != ERROR_SUCCESS) result.cleanupUnknown = true;
      }
    }
  } abort{engine, api, transaction, result};
  try {
    result.error = api.begin(engine, 0);
    if (result.error != ERROR_SUCCESS) return result;
    transaction = true;
    // El owner verifica inventario A, objetos propios y lease duradero Prepared
    // dentro de esta transacción; HANDLE/DTO no sustituyen esas adquisiciones.
    if (!verify(context)) {
      result.error = ERROR_INVALID_STATE;
    } else {
      if (before) for (const auto &old : before->slots_) {
        GUID key{};
        std::memcpy(&key, old.key.data(), sizeof(key));
        result.error = api.erase(engine, &key);
        if (result.error != ERROR_SUCCESS) break;
      }
      recipe::RecipeWorkspace workspace{};
      for (std::size_t i = 0; result.error == ERROR_SUCCESS && i < after.slots_.size(); ++i) {
        recipe::ExpectedFilterView expected;
        if (after.expectedSlot(i, workspace, expected) != Reason::None) {
          result.error = ERROR_INVALID_DATA;
          break;
        }
        FWPM_FILTER0 filter{};
        auto provider = expected.provider;
        auto weight = expected.weight;
        filter.filterKey = expected.key;
        filter.displayData.name = const_cast<wchar_t *>(expected.name);
        filter.flags = expected.flags;
        filter.providerKey = &provider;
        filter.providerData = {static_cast<UINT32>(expected.providerData.size),
                              const_cast<UINT8 *>(expected.providerData.data)};
        filter.layerKey = expected.layer;
        filter.subLayerKey = expected.sublayer;
        filter.weight.type = expected.weightType;
        filter.weight.uint64 = &weight;
        filter.numFilterConditions = expected.conditionCount;
        filter.filterCondition = const_cast<FWPM_FILTER_CONDITION0 *>(expected.conditions);
        filter.action.type = expected.action;
        filter.action.filterType = expected.actionKey;
        filter.rawContext = expected.rawContext;
        // IDs retornados por Add son sólo hints: confirmInventory adquirirá los
        // IDs y metadata SDK verdaderos antes de freeze/receipt/AppliedCAS.
        UINT64 ignored = 0;
        result.error = api.add(engine, &filter, nullptr, &ignored);
      }
    }
    if (result.error == ERROR_SUCCESS) {
      result.error = api.commit(engine);
      if (result.error == ERROR_SUCCESS) {
        transaction = false;
        result.committed = true;
      }
    }
    if (transaction) {
      transaction = false;
      if (api.abort(engine) != ERROR_SUCCESS) result.cleanupUnknown = true;
    }
  } catch (...) {
    result.error = ERROR_INVALID_STATE;
    if (transaction) {
      transaction = false;
      if (api.abort(engine) != ERROR_SUCCESS) result.cleanupUnknown = true;
    }
  }
  return result;
}
Reason CatalogPlanBuilder::observe(const FWPM_FILTER0 *borrowed, recipe::ReadBytes read,
                                   recipe::RecipeWorkspace &workspace) noexcept {
  if (phase_ != Phase::Staged || !storage_.storage_)
    return Reason::StaleStamp;
  FWPM_FILTER0 header{};
  if (!read || !borrowed || !read(&header, borrowed, sizeof(header)))
    return fail(Reason::Unreadable);
  if (!header.filterId)
    return fail(Reason::InvalidEvent);
  auto &s = *storage_.storage_;
  std::size_t index = 0;
  const auto *row = s.byKey(allnative::guidBytes(header.filterKey), &index);
  if (!row)
    return fail(Reason::ForeignFilter);
  const auto bit = std::uint8_t(1u << (index % 8));
  if (seen_[index / 8] & bit)
    return fail(Reason::Ambiguous);
  recipe::ExpectedFilterView wanted;
  const auto built = s.expectedSlot(index, workspace, wanted);
  if (built != Reason::None)
    return fail(built);
  wanted.runtimeFilterId = header.filterId;
  wanted.runtimeLayerId = s.domain_[row->layer];
  const auto compared = recipe::compareFilter(borrowed, wanted, workspace, read);
  if (compared != Reason::None)
    return fail(compared);
  s.slots_[index].id = header.filterId;
  s.slots_[index].layerId = wanted.runtimeLayerId;
  seen_[index / 8] |= bit;
  ++observed_;
  return Reason::None;
}
std::shared_ptr<const allnative::CatalogSnapshot> CatalogPlanBuilder::freeze() noexcept {
  if (phase_ != Phase::Staged || !storage_.storage_ || observed_ != storage_.storage_->slots_.size())
    return {};
  auto result = storage_.freeze();
  if (!result) {
    fail(Reason::Ambiguous);
    return {};
  }
  phase_ = Phase::Frozen;
  return result;
}
Reason CatalogPlanBuilder::confirmInventory(HANDLE engine, const allnative::SdkApi &api,
                                            recipe::ReadBytes read) noexcept {
  return confirmInventoryBody(engine,api,read,true);
}
Reason CatalogPlanBuilder::confirmInventoryBody(HANDLE engine, const allnative::SdkApi &api,
                                               recipe::ReadBytes read, bool ownTransaction) noexcept {
  if (phase_ != Phase::Staged || !engine || !read || !api.begin || !api.abort ||
      !api.layer || !api.createEnum || !api.enumerate || !api.destroyEnum || !api.freeMemory)
    return fail(Reason::SourceGap);
  try {
    // Cada lectura coteja todos los slots; ningún seen de una lectura anterior la abrevia.
    seen_ = {}; observed_ = 0;
    auto &catalog = *storage_.storage_;
    recipe::RecipeWorkspace workspace{};
    std::array<std::uint8_t, (allnative::MaxCatalogSlots + 7) / 8> globalSeen{};
    bool cleanupFault = false, transaction = false;
    struct Cleanup {
      const allnative::SdkApi &api; HANDLE engine; bool &open, &fault;
      ~Cleanup() { if (open && api.abort(engine) != ERROR_SUCCESS) fault = true; }
    } cleanup{api, engine, transaction, cleanupFault};
    if (ownTransaction && api.begin(engine, FWPM_TXN_READ_ONLY) != ERROR_SUCCESS)
      return fail(Reason::SourceGap);
    transaction = ownTransaction;
    // Cotejar IDs de capa y soporte tipado en la misma transacción del inventario.
    for (std::uint8_t layer = 0; layer < 8; ++layer) {
      FWPM_LAYER0 *borrowed = nullptr;
      const auto result = api.layer(engine, catalog.domain_[layer], &borrowed);
      struct LayerMemory { const allnative::SdkApi &api; FWPM_LAYER0 *&value;
        ~LayerMemory() { if (value) api.freeMemory(reinterpret_cast<void **>(&value)); }
      } memory{api, borrowed};
      FWPM_LAYER0 header{};
      if (result != ERROR_SUCCESS || !borrowed || !read(&header, borrowed, sizeof(header)))
        return fail(Reason::Unreadable);
      if (header.layerId != catalog.domain_[layer] || header.numFields > 256 ||
          (header.numFields && !header.field) || allnative::guidBytes(header.layerKey) !=
          allnative::guidBytes(allnative::nativeLayerGuid(static_cast<allnative::NativeLayer8>(layer))))
        return fail(Reason::InvalidEvent);
      for (std::uint32_t i = 0; i < catalog.supportCount_; ++i) {
        const auto &support = catalog.support_[i];
        if (static_cast<std::uint8_t>(support.layer) != layer) continue;
        unsigned matches = 0;
        for (UINT32 j = 0; j < header.numFields; ++j) {
          FWPM_FIELD0 field{}; GUID key{};
          if (!read(&field, header.field + j, sizeof(field)) || !field.fieldKey ||
              !read(&key, field.fieldKey, sizeof(key))) return fail(Reason::Unreadable);
          if (allnative::guidBytes(key) == allnative::guidBytes(support.fieldKey)) {
            if (field.dataType != support.classifiedType || ++matches != 1) return fail(Reason::InvalidEvent);
          }
        }
        if (matches != 1) return fail(Reason::Unsupported);
      }
    }
    GUID provider{}; std::memcpy(&provider, catalog.provider_.data(), sizeof(provider));
    std::size_t domainPages = 0, globalCount = 0, globalOwn = 0;
    auto scan = [&](const GUID *layer) -> Reason {
      FWPM_FILTER_ENUM_TEMPLATE0 pattern{};
      if (layer) {
        pattern.providerKey = &provider; pattern.layerKey = *layer;
        pattern.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED;
        pattern.flags = FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;
        pattern.actionMask = 0xffffffffu;
      }
      HANDLE enumeration = nullptr;
      struct EnumCleanup { const allnative::SdkApi &api; HANDLE engine, &handle; bool &fault;
        ~EnumCleanup() { if (handle && api.destroyEnum(engine, handle) != ERROR_SUCCESS) fault = true; }
      } close{api, engine, enumeration, cleanupFault};
      if (api.createEnum(engine, layer ? &pattern : nullptr, &enumeration) != ERROR_SUCCESS || !enumeration)
        return Reason::SourceGap;
      bool terminal = false;
      for (std::size_t page = 0; !terminal; ++page) {
        if (layer ? (++domainPages > 1553) : (page >= 4097)) return Reason::Exhausted;
        FWPM_FILTER0 **rows = nullptr; UINT32 count = 0;
        struct RowsMemory { const allnative::SdkApi &api; FWPM_FILTER0 **&rows;
          ~RowsMemory() { if (rows) api.freeMemory(reinterpret_cast<void **>(&rows)); }
        } memory{api, rows};
        if (api.enumerate(engine, enumeration, 16, &rows, &count) != ERROR_SUCCESS ||
            count > 16 || (count && !rows)) return Reason::SourceGap;
        terminal = count < 16;
        for (UINT32 i = 0; i < count; ++i) {
          if (!layer && ++globalCount > 65536) return Reason::Exhausted;
          FWPM_FILTER0 *borrowed = nullptr; FWPM_FILTER0 header{}; GUID actualProvider{};
          if (!read(&borrowed, rows + i, sizeof(borrowed)) || !borrowed ||
              !read(&header, borrowed, sizeof(header))) return Reason::Unreadable;
          if (!header.providerKey) { if (layer) return Reason::ForeignFilter; continue; }
          if (!read(&actualProvider, header.providerKey, sizeof(actualProvider))) return Reason::Unreadable;
          if (allnative::guidBytes(actualProvider) != catalog.provider_) {
            if (layer) return Reason::ForeignFilter;
            continue;
          }
          const auto resolved = allnative::nativeLayer(header.layerKey);
          if (!resolved || (layer && allnative::guidBytes(header.layerKey) != allnative::guidBytes(*layer)))
            return Reason::ForeignFilter;
          if (layer) {
            const auto reason = observe(borrowed, read, workspace);
            if (reason != Reason::None) return reason;
          } else {
            std::size_t index = 0;
            const auto *slot = catalog.byKey(allnative::guidBytes(header.filterKey), &index);
            if (!slot || slot->id != header.filterId || slot->layer != static_cast<std::uint8_t>(*resolved))
              return Reason::ForeignFilter;
            const auto mask = std::uint8_t(1u << (index % 8));
            if (globalSeen[index / 8] & mask) return Reason::Ambiguous;
            recipe::ExpectedFilterView expected;
            auto reason = catalog.expectedSlot(index, workspace, expected);
            if (reason == Reason::None) reason = recipe::compareFilter(borrowed, expected, workspace, read);
            if (reason != Reason::None) return reason;
            globalSeen[index / 8] |= mask;
            if (++globalOwn > catalog.slots_.size()) return Reason::ForeignFilter;
          }
        }
      }
      const auto result = api.destroyEnum(engine, enumeration); enumeration = nullptr;
      return result == ERROR_SUCCESS ? Reason::None : Reason::SourceGap;
    };
    Reason result = Reason::None;
    for (std::uint8_t layer = 0; layer < 8 && result == Reason::None; ++layer)
      result = scan(&allnative::nativeLayerGuid(static_cast<allnative::NativeLayer8>(layer)));
    if (result == Reason::None && observed_ != catalog.slots_.size()) result = Reason::ForeignFilter;
    if (result == Reason::None) result = scan(nullptr);
    if (result == Reason::None && globalOwn != catalog.slots_.size()) result = Reason::ForeignFilter;
    if (ownTransaction && api.abort(engine) != ERROR_SUCCESS) cleanupFault = true;
    transaction = false;
    if (cleanupFault) result = Reason::SourceGap;
    return result == Reason::None ? result : fail(result);
  } catch (...) { return fail(Reason::SourceGap); }
}
} // namespace gb::decisions
