#pragma once
#include "catalog_plan_iv.h"
#include "engine_resource_iv.h"
#include "store_iv.h"
#include "../controller/deployment_win.h"
namespace gb::controller { class GuestMaintenance; }
namespace gb::decisions {
// Owner administrativo de store/inventario detenido; no crea Source ni permisos.
class MaintenanceRuntime final {
    friend class gb::controller::GuestMaintenance;
    using Current = bool (*)(void *) noexcept;
    explicit MaintenanceRuntime(std::filesystem::path store, bool allowMissing, Current, void *,
                                controller::DeploymentMode);
    bool prepare();
    bool current() const;
    bool inspect(bool insideWrite);
    bool absent(bool insideWrite);
    bool objectSecurity() const;
    bool remove();
    bool missing() const { return read_.kind == principal::StoredImage::Missing; }
    DWORD error_ = ERROR_INVALID_STATE;
    bool attempted_ = false, committed_ = false, cleanupUnknown_ = false;
    Current check_; void *context_;
    bool allowMissing_;
    const controller::DeploymentMode mode_;
    directional::NativeSnapshotFile file_;
    allnative::CatalogRegistry registry_;
    std::unique_ptr<principal::SnapshotStore> store_;
    principal::StoreRead read_;
    std::unique_ptr<CatalogPlanBuilder> reserved_;
    std::shared_ptr<EngineResource> observation_, fault_;
    std::shared_ptr<const allnative::BindingState> binding_;
    std::array<std::uint16_t,8> domain_{};
    std::array<allnative::recipe::SupportField,32> support_{};
    std::size_t supportCount_ = 0;
    std::unique_ptr<CatalogPlanBuilder> plan_;
    allnative::SdkApi sdk_;
    HANDLE write_ = nullptr;
  public:
    ~MaintenanceRuntime();
};
} // namespace gb::decisions
