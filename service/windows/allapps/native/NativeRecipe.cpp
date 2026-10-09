#include "NativeRecipe.h"
#include <algorithm>
#include <bcrypt.h>
#include <cstring>
#include <limits>

namespace gatebouncer::service::windows::allapps::native::recipe {
namespace {
const GUID Provider = {0xeec4d47a,
                       0x91a5,
                       0x4f6c,
                       {0xba, 0x34, 0xb1, 0xc7, 0x8d, 0xaa, 0x82, 0x31}};
const GUID Sublayer = {0xa80c1782,
                       0x61a7,
                       0x4499,
                       {0xb7, 0x96, 0x5a, 0x3d, 0x3a, 0x28, 0x22, 0x39}};
const wchar_t Name[] = L"LGA GateBouncer directional policy";
const GUID *const Layers[] = {&FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                              &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                              &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                              &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                              &FWPM_LAYER_ALE_AUTH_LISTEN_V4,
                              &FWPM_LAYER_ALE_AUTH_LISTEN_V6,
                              &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
                              &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6};
bool same(const GUID &a, const GUID &b) noexcept {
  return std::memcmp(&a, &b, sizeof(GUID)) == 0;
}
bool empty(const GUID &g) noexcept { return same(g, GUID{}); }
gb::wire::Id baseline() noexcept {
  gb::wire::Id id{};
  id[0] = 0xab;
  return id;
}
bool zeroId(const gb::wire::Id &id) noexcept {
  return std::all_of(id.begin(), id.end(),
                     [](auto value) { return value == 0; });
}
void put(std::uint8_t *out, std::uint64_t value, std::size_t count) noexcept {
  for (std::size_t i = 0; i < count; ++i)
    out[i] = std::uint8_t(value >> (8 * i));
}
bool sid(ByteView b) noexcept {
  return b.data && b.size >= 8 && b.size <= 68 && b.data[0] == 1 &&
         b.data[1] <= 15 && b.size == 8u + 4u * b.data[1];
}
std::uint8_t mask(std::uint8_t direction) noexcept {
  return direction == 1   ? 0x03
         : direction == 2 ? 0x3c
         : direction == 3 ? 0x3f
                          : 0;
}
Reason structure(const RuleView &r) noexcept {
  if (zeroId(r.ruleId) || r.ruleId == baseline() || zeroId(r.selectorId) ||
      !r.ruleRevision || !r.targetRevision || r.desired == UINT64_MAX ||
      r.filterGeneration != r.desired + 1 || r.recipeRevision != 1 ||
      r.action < 1 || r.action > 2 || !mask(r.direction) ||
      r.slotMask != mask(r.direction))
    return Reason::InvalidEvent;
  const auto mode = r.action == 1 || r.direction == 2 ? 0
                    : r.direction == 1                ? 1
                                                      : 2;
  if (r.mode != mode)
    return Reason::InvalidEvent;
  if (!r.app.data || !r.app.size)
    return Reason::BadPresence;
  if (r.app.size > 65536 || r.user.size > 68 || r.package.size > 68)
    return Reason::Oversized;
  if (r.targetKind == 1) {
    if (r.origin != 1 || r.scope != 2 || r.packageMode < 1 || r.packageMode > 2)
      return Reason::InvalidEvent;
    if (!sid(r.user))
      return Reason::InvalidSid;
    if (r.packageMode == 2 ? !sid(r.package) : r.package.size != 0)
      return Reason::InvalidSid;
  } else if (r.targetKind != 2 || r.origin || r.scope != 1 || r.packageMode ||
             r.user.size || r.package.size)
    return Reason::InvalidEvent;
  return Reason::None;
}
Reason support(const PrincipalSupportView &s, unsigned layer, const GUID &key,
               FWP_DATA_TYPE expected) noexcept {
  const SupportField *found = nullptr;
  for (std::size_t i = 0; i < s.count; ++i) {
    const auto &f = s.fields[i];
    if (unsigned(f.layer) != layer || !same(f.fieldKey, key))
      continue;
    if (found)
      return Reason::Ambiguous;
    found = &f;
  }
  if (!found || !same(found->layerKey, *Layers[layer]) ||
      found->matchType != FWP_MATCH_EQUAL)
    return Reason::ScopeUnsupported;
  const auto type = found->classifiedType;
  const bool compatible = expected == FWP_SECURITY_DESCRIPTOR_TYPE
                              ? type == FWP_TOKEN_INFORMATION_TYPE ||
                                    type == FWP_TOKEN_ACCESS_INFORMATION_TYPE
                              : type == expected;
  return compatible ? Reason::None : Reason::ScopeUnsupported;
}
const void *offset(const void *data, std::size_t at,
                   std::size_t count) noexcept {
  const auto base = reinterpret_cast<std::uintptr_t>(data);
  const auto max = (std::numeric_limits<std::uintptr_t>::max)();
  if (!base || at > max - base || count > max - (base + at))
    return nullptr;
  return reinterpret_cast<const void *>(base + at);
}
Reason bytes(const void *actual, ByteView expected, RecipeWorkspace &w,
             ReadBytes read) noexcept {
  if (expected.size && !expected.data)
    return Reason::BadPresence;
  for (std::size_t at = 0; at < expected.size;) {
    const auto count = (std::min)(w.chunk.size(), expected.size - at);
    const auto source = offset(actual, at, count);
    if (!source || !read(w.chunk.data(), source, count))
      return Reason::Unreadable;
    if (std::memcmp(w.chunk.data(), expected.data + at, count))
      return Reason::ForeignFilter;
    at += count;
  }
  return Reason::None;
}
Reason condition(const FWP_CONDITION_VALUE0 &actual,
                 const FWP_CONDITION_VALUE0 &expected, RecipeWorkspace &w,
                 ReadBytes read) noexcept {
  if (actual.type != expected.type)
    return Reason::ForeignFilter;
  switch (expected.type) {
  case FWP_UINT8:
    return actual.uint8 == expected.uint8 ? Reason::None
                                          : Reason::ForeignFilter;
  case FWP_UINT32:
    return actual.uint32 == expected.uint32 ? Reason::None
                                            : Reason::ForeignFilter;
  case FWP_BYTE_BLOB_TYPE:
  case FWP_SECURITY_DESCRIPTOR_TYPE: {
    FWP_BYTE_BLOB blob{};
    const auto want =
        expected.type == FWP_BYTE_BLOB_TYPE ? expected.byteBlob : expected.sd;
    const auto borrowed =
        actual.type == FWP_BYTE_BLOB_TYPE ? actual.byteBlob : actual.sd;
    if (!want || !borrowed || !read(&blob, borrowed, sizeof(blob)))
      return Reason::Unreadable;
    const auto limit = expected.type == FWP_BYTE_BLOB_TYPE ? 65536u : 104u;
    if (blob.size > limit)
      return Reason::Oversized;
    if (blob.size != want->size)
      return Reason::ForeignFilter;
    return bytes(blob.data, {want->data, want->size}, w, read);
  }
  case FWP_SID: {
    std::uint8_t prefix[8]{};
    if (!actual.sid || !read(prefix, actual.sid, sizeof(prefix)))
      return Reason::Unreadable;
    if (prefix[0] != 1 || prefix[1] > 15)
      return Reason::InvalidSid;
    const auto expectedSid =
        reinterpret_cast<const std::uint8_t *>(expected.sid);
    if (!expectedSid)
      return Reason::BadPresence;
    const auto size = 8u + 4u * prefix[1];
    if (size != 8u + 4u * expectedSid[1])
      return Reason::ForeignFilter;
    return bytes(actual.sid, {expectedSid, size}, w, read);
  }
  default:
    return Reason::Unsupported;
  }
}
} // namespace

Reason deriveFilterKey(const gb::wire::Id &id, std::uint32_t slot,
                       GUID &out) noexcept {
  out = {};
  if (zeroId(id) || (id == baseline() ? slot >= 28 : slot >= 6))
    return Reason::InvalidEvent;
  std::array<std::uint8_t, 20> input{};
  std::copy(id.begin(), id.end(), input.begin());
  put(input.data() + 16, slot, 4);
  std::array<std::uint8_t, 32> digest{};
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  0) < 0)
    return Reason::IdentityFailure;
  const auto result =
      BCryptHash(algorithm, nullptr, 0, input.data(), ULONG(input.size()),
                 digest.data(), ULONG(digest.size()));
  const auto closed = BCryptCloseAlgorithmProvider(algorithm, 0);
  if (result < 0 || closed < 0)
    return Reason::IdentityFailure;
  std::memcpy(&out, digest.data(), sizeof(out));
  return empty(out) ? Reason::Ambiguous : Reason::None;
}
Reason slotCount(const RuleView &r, std::uint32_t &outCount) noexcept {
  outCount = 0;
  if (!mask(r.direction))
    return Reason::InvalidEvent;
  outCount = r.direction == 1 ? 2 : r.direction == 2 ? 4 : 6;
  return Reason::None;
}
Reason validateRule(const RuleView &r, const PrincipalSupportView &s) noexcept {
  const auto valid = structure(r);
  if (valid != Reason::None)
    return valid;
  if (s.count > 32)
    return Reason::Oversized;
  if (s.count && !s.fields)
    return Reason::BadPresence;
  for (unsigned layer = 0; layer < 6; ++layer) {
    if (!(r.slotMask & (1u << layer)))
      continue;
    const GUID *keys[] = {&FWPM_CONDITION_ALE_APP_ID,
                          &FWPM_CONDITION_ALE_USER_ID,
                          &FWPM_CONDITION_ALE_PACKAGE_ID,
                          &FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE};
    const FWP_DATA_TYPE types[] = {
        FWP_BYTE_BLOB_TYPE, FWP_SECURITY_DESCRIPTOR_TYPE, FWP_SID, FWP_UINT8};
    for (unsigned i = 0; i < 4; ++i) {
      if ((i == 1 && r.targetKind != 1) || (i == 2 && r.packageMode != 2) ||
          (i == 3 && (r.action != 2 || r.direction != 1)))
        continue;
      const auto result = support(s, layer, *keys[i], types[i]);
      if (result != Reason::None)
        return result;
    }
  }
  return Reason::None;
}
Reason buildExpectedView(const SlotView &s, RecipeWorkspace &w,
                         ExpectedFilterView &out) noexcept {
  out = {};
  if (unsigned(s.layer) >= 8 || s.desired == UINT64_MAX ||
      s.filterGeneration != s.desired + 1 ||
      ((s.runtimeFilterId == 0) != (s.runtimeLayerId == 0)))
    return Reason::InvalidEvent;
  auto id = baseline();
  std::uint8_t direction = 0, mode = 0, action = 1;
  std::uint64_t weight = 0;
  unsigned layer = 0;
  bool boot = false, raw = false, unicast = false;
  std::uint32_t promiscuous = 0;
  if (s.rule) {
    const auto result = structure(*s.rule);
    if (result != Reason::None)
      return result;
    const auto &r = *s.rule;
    if (s.ordinal >= 6 || !(r.slotMask & (1u << s.ordinal)) ||
        r.desired != s.desired || r.filterGeneration != s.filterGeneration)
      return Reason::InvalidEvent;
    layer = s.ordinal;
    id = r.ruleId;
    direction = r.direction;
    mode = r.mode;
    action = r.action;
    weight = action == 1 ? 200 : 100;
    unicast = action == 2 && direction == 1;
  } else {
    if (s.ordinal >= 28)
      return Reason::InvalidEvent;
    const auto local = s.ordinal % 14;
    boot = s.ordinal >= 14;
    if (local < 6)
      layer = local;
    else {
      layer = 6 + (local - 6) / 4;
      weight = 200;
      const auto kind = (local - 6) % 4;
      raw = kind == 0;
      if (!raw)
        promiscuous = 0x98000000u + kind;
    }
  }
  if (unsigned(s.layer) != layer)
    return Reason::InvalidEvent;
  GUID key{};
  const auto keyResult = deriveFilterKey(id, s.ordinal, key);
  if (keyResult != Reason::None)
    return keyResult;
  if (empty(s.key) || !same(key, s.key))
    return Reason::Ambiguous;
  w.conditions = {};
  w.blobs = {};
  w.sd = {};
  w.metadata = {};
  std::copy_n("GBF2", 4, w.metadata.begin());
  put(w.metadata.data() + 4, s.desired, 8);
  w.metadata[12] = direction;
  w.metadata[13] = mode;
  w.metadata[14] = std::uint8_t(s.ordinal);
  std::copy(id.begin(), id.end(), w.metadata.begin() + 16);
  std::uint32_t count = 0;
  auto scalar = [&](const GUID &field, FWP_MATCH_TYPE match, FWP_DATA_TYPE type,
                    std::uint32_t value) {
    auto &c = w.conditions[count++];
    c.fieldKey = field;
    c.matchType = match;
    c.conditionValue.type = type;
    if (type == FWP_UINT8)
      c.conditionValue.uint8 = std::uint8_t(value);
    else
      c.conditionValue.uint32 = value;
  };
  auto blob = [&](const GUID &field, FWP_DATA_TYPE type, ByteView bytes) {
    auto &c = w.conditions[count];
    auto &b = w.blobs[count++];
    c.fieldKey = field;
    c.matchType = FWP_MATCH_EQUAL;
    c.conditionValue.type = type;
    b = {UINT32(bytes.size), const_cast<UINT8 *>(bytes.data)};
    if (type == FWP_SECURITY_DESCRIPTOR_TYPE)
      c.conditionValue.sd = &b;
    else
      c.conditionValue.byteBlob = &b;
  };
  if (s.rule) {
    const auto &r = *s.rule;
    blob(FWPM_CONDITION_ALE_APP_ID, FWP_BYTE_BLOB_TYPE, r.app);
    if (r.targetKind == 1) {
      w.sd[0] = 1;
      put(w.sd.data() + 2, 0x8004, 2);
      put(w.sd.data() + 16, 20, 4);
      w.sd[20] = 2;
      put(w.sd.data() + 22, 16 + r.user.size, 2);
      put(w.sd.data() + 24, 1, 2);
      put(w.sd.data() + 30, 8 + r.user.size, 2);
      put(w.sd.data() + 32, 1, 4);
      std::copy_n(r.user.data, r.user.size, w.sd.data() + 36);
      blob(FWPM_CONDITION_ALE_USER_ID, FWP_SECURITY_DESCRIPTOR_TYPE,
           {w.sd.data(), 36 + r.user.size});
      if (r.packageMode == 2) {
        auto &c = w.conditions[count++];
        c.fieldKey = FWPM_CONDITION_ALE_PACKAGE_ID;
        c.matchType = FWP_MATCH_EQUAL;
        c.conditionValue.type = FWP_SID;
        c.conditionValue.sid =
            reinterpret_cast<SID *>(const_cast<std::uint8_t *>(r.package.data));
      }
    }
  }
  if (raw)
    scalar(FWPM_CONDITION_FLAGS, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT32,
           FWP_CONDITION_FLAG_IS_RAW_ENDPOINT);
  if (promiscuous)
    scalar(FWPM_CONDITION_ALE_PROMISCUOUS_MODE, FWP_MATCH_EQUAL, FWP_UINT32,
           promiscuous);
  if (unicast)
    scalar(FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE, FWP_MATCH_EQUAL,
           FWP_UINT8, 1);
  out.key = key;
  out.provider = Provider;
  out.sublayer = Sublayer;
  out.layer = *Layers[layer];
  out.flags = boot ? FWPM_FILTER_FLAG_BOOTTIME : FWPM_FILTER_FLAG_PERSISTENT;
  out.action = action == 1 ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
  out.runtimeFilterId = s.runtimeFilterId;
  out.runtimeLayerId = s.runtimeLayerId;
  out.weight = out.effectiveWeight = weight;
  out.conditions = w.conditions.data();
  out.conditionCount = count;
  out.providerData = {w.metadata.data(), w.metadata.size()};
  out.name = Name;
  return Reason::None;
}
Reason compareFilter(const FWPM_FILTER0 *borrowed, const ExpectedFilterView &e,
                     RecipeWorkspace &w, ReadBytes read) noexcept {
  if (!read || !e.runtimeFilterId || !e.runtimeLayerId ||
      e.conditionCount > 32 || (e.conditionCount && !e.conditions))
    return Reason::BadPresence;
  FWPM_FILTER0 f{};
  GUID provider{};
  if (!borrowed || !read(&f, borrowed, sizeof(f)))
    return Reason::Unreadable;
  // reserved pertenece al sistema: no comparar, dereferenciar ni conservar.
  f.reserved = nullptr;
  if (f.numFilterConditions > 32 || f.providerData.size > 32)
    return Reason::Oversized;
  if (!f.providerKey || !read(&provider, f.providerKey, sizeof(provider)))
    return Reason::Unreadable;
  if (!same(f.filterKey, e.key) || !same(provider, e.provider) ||
      !same(f.subLayerKey, e.sublayer) || !same(f.layerKey, e.layer) ||
      f.filterId != e.runtimeFilterId || f.flags != e.flags ||
      f.action.type != e.action || !same(f.action.filterType, e.actionKey) ||
      f.rawContext != e.rawContext || f.weight.type != e.weightType ||
      f.effectiveWeight.type != e.effectiveWeightType ||
      f.numFilterConditions != e.conditionCount ||
      f.providerData.size != e.providerData.size ||
      f.displayData.description != nullptr || !f.displayData.name ||
      e.name != Name)
    return Reason::ForeignFilter;
  std::uint64_t weight = 0, effective = 0;
  if (!f.weight.uint64 || !f.effectiveWeight.uint64 ||
      !read(&weight, f.weight.uint64, sizeof(weight)) ||
      !read(&effective, f.effectiveWeight.uint64, sizeof(effective)))
    return Reason::Unreadable;
  if (weight != e.weight || effective != e.effectiveWeight)
    return Reason::ForeignFilter;
  auto result = bytes(f.providerData.data, e.providerData, w, read);
  if (result != Reason::None)
    return result;
  result = bytes(f.displayData.name,
                 {reinterpret_cast<const std::uint8_t *>(Name), sizeof(Name)},
                 w, read);
  if (result != Reason::None)
    return result;
  for (std::uint32_t i = 0; i < e.conditionCount; ++i) {
    FWPM_FILTER_CONDITION0 actual{};
    const auto source =
        offset(f.filterCondition, sizeof(actual) * i, sizeof(actual));
    if (!source || !read(&actual, source, sizeof(actual)))
      return Reason::Unreadable;
    const auto &expected = e.conditions[i];
    if (!same(actual.fieldKey, expected.fieldKey) ||
        actual.matchType != expected.matchType)
      return Reason::ForeignFilter;
    result = condition(actual.conditionValue, expected.conditionValue, w, read);
    if (result != Reason::None)
      return result;
  }
  return Reason::None;
}
} // namespace gatebouncer::service::windows::allapps::native::recipe
