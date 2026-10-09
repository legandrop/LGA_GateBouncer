#include "engine_resource_iv.h"
#include "windows/allapps/native/NativeRead.h"
#include "windows/allapps/native/NativeCatalog.h"
#include <algorithm>
#include <bcrypt.h>
#include <cstring>
#include <mutex>

namespace gb::decisions {
struct EngineResource::Api {
  decltype(&FwpmEngineOpen0) open = &FwpmEngineOpen0;
  decltype(&FwpmEngineClose0) close = &FwpmEngineClose0;
  decltype(&FwpmSessionCreateEnumHandle0) create = &FwpmSessionCreateEnumHandle0;
  decltype(&FwpmSessionEnum0) enumerate = &FwpmSessionEnum0;
  decltype(&FwpmSessionDestroyEnumHandle0) destroy = &FwpmSessionDestroyEnumHandle0;
  decltype(&FwpmTransactionBegin0) begin = &FwpmTransactionBegin0;
  decltype(&FwpmTransactionAbort0) abort = &FwpmTransactionAbort0;
  decltype(&FwpmFreeMemory0) freeMemory = &FwpmFreeMemory0;
  decltype(&FwpmLayerGetByKey0) layer = &FwpmLayerGetByKey0;
  decltype(&BCryptGenRandom) random = &BCryptGenRandom;
  decltype(&GetCurrentProcessId) process = &GetCurrentProcessId;
  decltype(&gatebouncer::service::windows::allapps::native::guardedRead) read =
      &gatebouncer::service::windows::allapps::native::guardedRead;
};
struct EngineResource::State {
  const Api api;
  HANDLE engine = nullptr;
  mutable std::mutex mutex;
  explicit State(const Api &value) : api(value) {}
  ~State() {
    // No se afirma ausencia de sesión/efectos por el resultado del destructor.
    // El retiro explícito mantiene el recurso si el cierre falla.
    if (engine)
      api.close(engine);
  }
};
namespace {
template <class F> struct Exit {
  F action;
  ~Exit() noexcept { action(); }
};
template <class F> Exit<F> onExit(F action) { return {action}; }
bool nonzero(const wire::Id &id) noexcept {
  return std::any_of(id.begin(), id.end(), [](std::uint8_t value) { return value != 0; });
}
}
EngineResource::EngineResource(std::shared_ptr<State> state, wire::Id context,
                               std::uint64_t generation)
    : context_(context), generation_(generation), state_(std::move(state)) {}
EngineResource::~EngineResource() = default;
HANDLE EngineResource::handle() const noexcept {
  return state_ ? state_->engine : nullptr;
}
std::shared_ptr<void> EngineResource::pin() const noexcept { return state_; }
DWORD EngineResource::retire() noexcept {
  if (!state_)
    return ERROR_SUCCESS;
  // Un source en callback/stop conserva su pin; nunca cerrar debajo de él.
  if (state_.use_count() != 1)
    return ERROR_BUSY;
  try {
    std::lock_guard<std::mutex> lock(state_->mutex);
    if (!state_->engine)
      return ERROR_SUCCESS;
    const auto result = state_->api.close(state_->engine);
    if (result == ERROR_SUCCESS)
      state_->engine = nullptr;
    return result;
  } catch (...) {
    return ERROR_INVALID_STATE;
  }
}
std::shared_ptr<EngineResource> EngineResource::acquire(std::uint64_t generation) {
  return acquire(generation, Api{});
}
std::shared_ptr<EngineResource> EngineResource::acquire(std::uint64_t generation,
                                                       std::shared_ptr<EngineResource> *fault) {
  return acquire(generation, Api{}, fault);
}
std::shared_ptr<EngineResource>
EngineResource::acquire(std::uint64_t generation, const Api &api,
                        std::shared_ptr<EngineResource> *fault) {
  if (fault) fault->reset();
  if (!generation || !api.open || !api.close || !api.create || !api.enumerate ||
      !api.destroy || !api.begin || !api.abort || !api.freeMemory ||
      !api.random || !api.process || !api.read || !api.layer)
    return {};
  try {
    wire::Id context{};
    if (api.random(nullptr, context.data(), static_cast<ULONG>(context.size()),
                   BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 || !nonzero(context))
      return {};
    FWPM_SESSION0 requested{};
    std::memcpy(&requested.sessionKey, context.data(), context.size());
    requested.displayData.name = const_cast<wchar_t *>(L"LGA GateBouncer observation");
    requested.flags = FWPM_SESSION_FLAG_DYNAMIC;
    requested.txnWaitTimeoutInMSec = 1000;
    auto state = std::make_shared<State>(api);
    bool verified = false;
    auto closeFailed = onExit([&] {
      if (!verified && state && state->engine) {
        if (api.close(state->engine) == ERROR_SUCCESS)
          state->engine = nullptr;
        else if (fault) {
          try { *fault = std::shared_ptr<EngineResource>(new EngineResource(state, {}, 0)); }
          catch (...) { /* Sin identidad ni permiso: sólo cleanup best-effort bajo OOM. */ }
        }
      }
    });
    const auto opened = api.open(nullptr, RPC_C_AUTHN_WINNT, nullptr, &requested,
                                 &state->engine);
    if (opened != ERROR_SUCCESS || !state->engine || state->engine == INVALID_HANDLE_VALUE) {
      if (state->engine == INVALID_HANDLE_VALUE)
        state->engine = nullptr;
      return {};
    }
    if (api.begin(state->engine, FWPM_TXN_READ_ONLY) != ERROR_SUCCESS)
      return {};
    bool transaction = true;
    auto abort = onExit([&] { if (transaction) api.abort(state->engine); });
    HANDLE enumeration = nullptr;
    if (api.create(state->engine, nullptr, &enumeration) != ERROR_SUCCESS || !enumeration)
      return {};
    bool enumOpen = true;
    auto destroy = onExit([&] { if (enumOpen) api.destroy(state->engine, enumeration); });
    const DWORD process = api.process();
    if (!process)
      return {};
    unsigned matched = 0;
    std::size_t total = 0;
    bool ended = false;
    while (!ended && total <= 4096) {
      FWPM_SESSION0 **rows = nullptr;
      UINT32 count = 0;
      const auto result = api.enumerate(state->engine, enumeration, 32, &rows, &count);
      auto freeRows = onExit([&] { if (rows) api.freeMemory(reinterpret_cast<void **>(&rows)); });
      if (result != ERROR_SUCCESS || count > 32 || (count && !rows) ||
          count > 4096 - total)
        return {};
      ended = count == 0;
      for (UINT32 i = 0; i < count; ++i) {
        FWPM_SESSION0 *pointer = nullptr;
        FWPM_SESSION0 observed{};
        if (!api.read(&pointer, rows + i, sizeof(pointer)) || !pointer ||
            !api.read(&observed, pointer, sizeof(observed)))
          return {};
        if (std::memcmp(&observed.sessionKey, context.data(), context.size()) == 0) {
          if (observed.processId != process || observed.kernelMode ||
              observed.flags != requested.flags || ++matched != 1)
            return {};
        }
      }
      total += count;
    }
    if (!ended || matched != 1)
      return {};
    const auto destroyed = api.destroy(state->engine, enumeration);
    enumOpen = false;
    const auto aborted = api.abort(state->engine);
    transaction = false;
    if (destroyed != ERROR_SUCCESS || aborted != ERROR_SUCCESS)
      return {};
    verified = true;
    return std::shared_ptr<EngineResource>(new EngineResource(std::move(state), context, generation));
  } catch (...) {
    return {};
  }
}
gatebouncer::service::windows::allapps::Reason EngineResource::readDomain(
    std::array<std::uint16_t, 8> &domain,
    std::array<gatebouncer::service::windows::allapps::native::recipe::SupportField, 32> &support,
    std::size_t &supportCount) const noexcept {
  namespace native = gatebouncer::service::windows::allapps::native;
  using Reason = gatebouncer::service::windows::allapps::Reason;
  domain = {};
  support = {};
  supportCount = 0;
  if (!state_ || !state_->engine)
    return Reason::SourceGap;
  try {
    std::lock_guard<std::mutex> lock(state_->mutex);
    const auto &api = state_->api;
    if (api.begin(state_->engine, FWPM_TXN_READ_ONLY) != ERROR_SUCCESS)
      return Reason::SourceGap;
    bool transaction = true;
    auto abort = onExit([&] { if (transaction) api.abort(state_->engine); });
    std::array<std::uint16_t, 8> candidateDomain{};
    std::array<native::recipe::SupportField, 32> candidateSupport{};
    std::size_t count = 0;
    const GUID *fields[] = {&FWPM_CONDITION_ALE_APP_ID, &FWPM_CONDITION_ALE_USER_ID,
                            &FWPM_CONDITION_ALE_PACKAGE_ID, &FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE};
    for (std::uint8_t i = 0; i < 8; ++i) {
      const auto layerKey = native::nativeLayerGuid(static_cast<native::NativeLayer8>(i));
      FWPM_LAYER0 *borrowed = nullptr;
      const auto result = api.layer(state_->engine, &layerKey, &borrowed);
      auto freeLayer = onExit([&] { if (borrowed) api.freeMemory(reinterpret_cast<void **>(&borrowed)); });
      FWPM_LAYER0 header{};
      if (result != ERROR_SUCCESS || !borrowed || !api.read(&header, borrowed, sizeof(header)))
        return Reason::Unreadable;
      if (!header.layerId || std::memcmp(&header.layerKey, &layerKey, sizeof(layerKey)) ||
          header.numFields > 256 || (header.numFields && !header.field))
        return Reason::InvalidEvent;
      for (std::uint8_t j = 0; j < i; ++j)
        if (candidateDomain[j] == header.layerId)
          return Reason::Ambiguous;
      candidateDomain[i] = header.layerId;
      std::array<bool, 4> seen{};
      for (UINT32 j = 0; j < header.numFields; ++j) {
        FWPM_FIELD0 field{};
        GUID key{};
        if (!api.read(&field, header.field + j, sizeof(field)) || !field.fieldKey ||
            !api.read(&key, field.fieldKey, sizeof(key)))
          return Reason::Unreadable;
        for (std::size_t k = 0; k < 4; ++k)
          if (std::memcmp(&key, fields[k], sizeof(key)) == 0) {
            if (seen[k] || count == candidateSupport.size())
              return Reason::Ambiguous;
            seen[k] = true;
            candidateSupport[count++] = {static_cast<native::NativeLayer8>(i), layerKey,
                                         key, field.dataType, FWP_MATCH_EQUAL};
          }
      }
    }
    const auto aborted = api.abort(state_->engine);
    transaction = false;
    if (aborted != ERROR_SUCCESS)
      return Reason::SourceGap;
    domain = candidateDomain;
    support = candidateSupport;
    supportCount = count;
    return Reason::None;
  } catch (...) {
    return Reason::SourceGap;
  }
}
} // namespace gb::decisions
