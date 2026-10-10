#pragma once
#include "snapshot_iv.h"
#include "principal_source_capture_vii.h"
#include "windows/allapps/native/NativeCatalog.h"
#include "windows/allapps/native/NativeSdk.h"

namespace gb { class WfpBackend; }
namespace gb::decisions {
namespace allnative = gatebouncer::service::windows::allapps::native;
class CatalogPlanBuilder final {
  friend class NativeRuntime;
  friend class MaintenanceRuntime;
  friend class gb::WfpBackend;
  struct WriteApi {
    decltype(&FwpmTransactionBegin0) begin = &FwpmTransactionBegin0;
    decltype(&FwpmTransactionCommit0) commit = &FwpmTransactionCommit0;
    decltype(&FwpmTransactionAbort0) abort = &FwpmTransactionAbort0;
    decltype(&FwpmFilterDeleteByKey0) erase = &FwpmFilterDeleteByKey0;
    decltype(&FwpmFilterAdd0) add = &FwpmFilterAdd0;
  };
  struct WriteOutcome {
    bool attempted = false, committed = false, cleanupUnknown = false;
    DWORD error = ERROR_INVALID_STATE;
  };
  using VerifyBeforeWrite = bool (*)(void *) noexcept;
  WriteOutcome transact(HANDLE writeEngine, const WriteApi &,
      const std::shared_ptr<const allnative::CatalogSnapshot> &before,
      VerifyBeforeWrite, void *) noexcept;
  WriteOutcome transactInitial(HANDLE, const WriteApi &, VerifyBeforeWrite, void *) noexcept;
  WriteOutcome transactBody(HANDLE, const WriteApi &,
      const std::shared_ptr<const allnative::CatalogSnapshot> &, VerifyBeforeWrite, void *, bool initial) noexcept;
  bool detachOutcomeArena() noexcept;
  bool attachOutcomeArena(const principal::ByteView &) noexcept;
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
  gatebouncer::service::windows::allapps::Reason confirmInventoryBody(
      HANDLE, const allnative::SdkApi &, allnative::recipe::ReadBytes, bool ownTransaction) noexcept;
  gatebouncer::service::windows::allapps::Reason fail(gatebouncer::service::windows::allapps::Reason) noexcept;
  allnative::CatalogStorageBuilder storage_;
  std::array<std::uint8_t, (allnative::MaxCatalogSlots + 7) / 8> seen_{};
  std::size_t observed_ = 0, maxRules_ = 0, maxSlots_ = 0;
  gatebouncer::service::windows::allapps::Reason reason_ = gatebouncer::service::windows::allapps::Reason::None;
  enum class Phase { Reserved, Staged, Failed, Frozen };
  Phase phase_ = Phase::Reserved;
  bool writeAttempted_ = false;
  bool initialCandidate_ = false;
  // Sólo NativeRuntime conserva aquí la captura/selección privadas admitidas;
  // ninguna ruta ordinaria ni payload de formato puede fijar estos originales.
  std::shared_ptr<PrincipalSourceCapture> conditionalSource_;
  std::shared_ptr<const PrincipalSourceCapture::Selection> conditionalSelection_;
  principal::ByteView conditionalTarget_, removedConditionalTarget_;
  std::filesystem::path conditionalImage_;
  Id conditionalRule_{};
  std::uint64_t conditionalDesired_=0;
  bool conditionalWriteCurrent(const allnative::CatalogSnapshot &,
      const std::shared_ptr<const allnative::CatalogSnapshot> &) const noexcept;
  const std::uint8_t *outcomePointer_ = nullptr;
  std::size_t outcomeSize_ = 0, outcomeCapacity_ = 0;
  CatalogPlanBuilder(const CatalogPlanBuilder &) = delete;
  CatalogPlanBuilder &operator=(const CatalogPlanBuilder &) = delete;
};
} // namespace gb::decisions
