#pragma once
#include "../../../../common/wire_v1.h"
#include "../AllAppsMetadata.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <windows.h>

#include <fwpmu.h>

namespace gatebouncer::service::windows::allapps::native::recipe {
using Reason = gatebouncer::service::windows::allapps::Reason;
using ReadBytes = bool (*)(void *dst, const void *src,
                           std::size_t count) noexcept;
struct ByteView {
  const std::uint8_t *data = nullptr;
  std::size_t size = 0;
};
enum class NativeLayer8 : std::uint8_t {
  Connect4,
  Connect6,
  Receive4,
  Receive6,
  Listen4,
  Listen6,
  Resource4,
  Resource6
};
// Valores cerrados heredados del formato IV, nunca capacidades ni autoridad.
// El llamador retiene la arena fuerte del builder/snapshot durante la
// operación.
struct RuleView {
  gb::wire::Id ruleId{}, selectorId{};
  std::uint64_t ruleRevision = 0, targetRevision = 0, desired = 0,
                filterGeneration = 0;
  std::uint32_t recipeRevision = 1;
  std::uint8_t action = 1, direction = 1, mode = 0, origin = 1, scope = 2,
               packageMode = 1, targetKind = 1, slotMask = 0;
  ByteView app, user, package;
};
// Metadata copiada por el owner de cada capa y campo; no flag trusted.
struct SupportField {
  NativeLayer8 layer = NativeLayer8::Connect4;
  GUID layerKey{}, fieldKey{};
  FWP_DATA_TYPE classifiedType = FWP_EMPTY;
  FWP_MATCH_TYPE matchType = FWP_MATCH_EQUAL;
};
struct PrincipalSupportView {
  const SupportField *fields = nullptr;
  std::size_t count = 0;
};
struct SlotView {
  const RuleView *rule = nullptr; // nullptr identifica exclusivamente baseline.
  std::uint32_t ordinal = 0;
  NativeLayer8 layer = NativeLayer8::Connect4;
  GUID key{};
  std::uint64_t desired = 0, filterGeneration = 0, runtimeFilterId = 0;
  std::uint16_t runtimeLayerId = 0;
};
struct RecipeWorkspace {
  std::array<std::uint8_t, 104> sd{};
  std::array<std::uint8_t, 32> metadata{};
  std::array<FWPM_FILTER_CONDITION0, 32> conditions{};
  std::array<FWP_BYTE_BLOB, 32> blobs{};
  std::array<std::uint8_t, 4096> chunk{};
};
static_assert(sizeof(RecipeWorkspace) <= 64 * 1024);
struct ExpectedFilterView {
  GUID key{}, provider{}, sublayer{}, layer{}, actionKey{};
  std::uint64_t runtimeFilterId = 0, weight = 0, effectiveWeight = 0,
                rawContext = 0;
  std::uint16_t runtimeLayerId = 0;
  std::uint32_t flags = 0, conditionCount = 0;
  FWP_ACTION_TYPE action = FWP_ACTION_BLOCK;
  FWP_DATA_TYPE weightType = FWP_UINT64, effectiveWeightType = FWP_UINT64;
  const FWPM_FILTER_CONDITION0 *conditions = nullptr;
  ByteView providerData;
  const wchar_t *name =
      nullptr; // constante propia de receta; description siempre null.
};
// La vista esperada no sobrevive al mismo snapshot y workspace que la produjo.
Reason validateRule(const RuleView &, const PrincipalSupportView &) noexcept;
Reason slotCount(const RuleView &, std::uint32_t &outCount) noexcept;
Reason buildExpectedView(const SlotView &, RecipeWorkspace &,
                         ExpectedFilterView &) noexcept;
Reason compareFilter(const FWPM_FILTER0 *borrowed, const ExpectedFilterView &,
                     RecipeWorkspace &, ReadBytes) noexcept;
// Única derivación compartida: first16 SHA256(ruleId16 || slotLE32).
Reason deriveFilterKey(const gb::wire::Id &, std::uint32_t slot,
                       GUID &out) noexcept;
} // namespace gatebouncer::service::windows::allapps::native::recipe
