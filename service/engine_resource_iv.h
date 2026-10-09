#pragma once
#include "../common/wire_iv.h"
#include <memory>
#include <windows.h>

#include <fwpmu.h>
#include "windows/allapps/native/NativeRecipe.h"

namespace gb::decisions {
class NativeRuntime;
// Identidad de generación: no es una capacidad de control ni prueba de filtro.
using ServiceContext = wire::iv::ServiceContext;
class EngineResource final {
  friend class NativeRuntime;
  struct Api;
  struct State;
  static std::shared_ptr<EngineResource> acquire(std::uint64_t generation);
  static std::shared_ptr<EngineResource> acquire(std::uint64_t generation,
                                                std::shared_ptr<EngineResource> *fault);
  static std::shared_ptr<EngineResource> acquire(std::uint64_t generation,
                                                const Api &api, std::shared_ptr<EngineResource> *fault = nullptr);
  explicit EngineResource(std::shared_ptr<State>, wire::Id, std::uint64_t);
  HANDLE handle() const noexcept;
  std::shared_ptr<void> pin() const noexcept;
  DWORD retire() noexcept;
  gatebouncer::service::windows::allapps::Reason readDomain(
      std::array<std::uint16_t, 8> &,
      std::array<gatebouncer::service::windows::allapps::native::recipe::SupportField, 32> &,
      std::size_t &) const noexcept;
  const wire::Id context_;
  const std::uint64_t generation_;
  std::shared_ptr<State> state_;
  EngineResource(const EngineResource &) = delete;
  EngineResource &operator=(const EngineResource &) = delete;
public:
  ~EngineResource();
};
} // namespace gb::decisions
