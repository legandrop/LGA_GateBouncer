#pragma once
#include "snapshot_iv.h"
#include "windows/allapps/native/NativeCatalog.h"
#include "windows/allapps/native/NativeSdk.h"

namespace gb::decisions {
namespace allnative = gatebouncer::service::windows::allapps::native;
class CatalogPlanBuilder final {
  friend class NativeRuntime;
  CatalogPlanBuilder(allnative::CatalogRegistry &, std::size_t arenaCapacity,
                     std::size_t maxRules, std::size_t maxSlots);
  gatebouncer::service::windows::allapps::Reason reservationStatus() const noexcept;
  static bool retainRead(void *, const principal::ByteView &) noexcept;
  bool retain(const principal::ByteView &) noexcept;
  gatebouncer::service::windows::allapps::Reason stage(const principal::ByteView &canonicalGBS4,
                         std::shared_ptr<const allnative::BindingState>,
                         std::uint64_t inventoryRevision,
                         const std::array<std::uint16_t, 8> &domain8,
                         const allnative::recipe::PrincipalSupportView &) noexcept;
  gatebouncer::service::windows::allapps::Reason expected(std::size_t slotIndex,
                            allnative::recipe::RecipeWorkspace &,
                            allnative::recipe::ExpectedFilterView &) const noexcept;
  gatebouncer::service::windows::allapps::Reason observe(const FWPM_FILTER0 *, allnative::recipe::ReadBytes,
                           allnative::recipe::RecipeWorkspace &) noexcept;
  std::shared_ptr<const allnative::CatalogSnapshot> freeze() noexcept;
  gatebouncer::service::windows::allapps::Reason confirmInventory(
      HANDLE, const allnative::SdkApi &, allnative::recipe::ReadBytes) noexcept;
  gatebouncer::service::windows::allapps::Reason fail(gatebouncer::service::windows::allapps::Reason) noexcept;
  allnative::CatalogStorageBuilder storage_;
  std::array<std::uint8_t, (allnative::MaxCatalogSlots + 7) / 8> seen_{};
  std::size_t observed_ = 0, maxRules_ = 0, maxSlots_ = 0;
  gatebouncer::service::windows::allapps::Reason reason_ = gatebouncer::service::windows::allapps::Reason::None;
  enum class Phase { Reserved, Staged, Failed, Frozen };
  Phase phase_ = Phase::Reserved;
  CatalogPlanBuilder(const CatalogPlanBuilder &) = delete;
  CatalogPlanBuilder &operator=(const CatalogPlanBuilder &) = delete;
};
} // namespace gb::decisions
