#pragma once
#include "deployment_prepare_win.h"
#include "../common/token_ii_win.h"
namespace gb::controller {
enum class MaintenanceOutcome { Rejected, Recovery, Pending, UpdatedPrepared, UninstalledRetained, PreparedFinalized };
enum class MaintenancePhase { Admission, Package, Marker, Stop, Store, Inventory, Switch, Filters, Service, Configuration, Complete };
struct MaintenanceResult {
    MaintenanceOutcome outcome = MaintenanceOutcome::Rejected;
    MaintenancePhase phase = MaintenancePhase::Admission;
    DWORD error = ERROR_INVALID_STATE;
    bool recoveryRecorded = false;
};
MaintenanceResult updateGuestDeployment(const std::filesystem::path &current,
    const std::filesystem::path &source, const std::filesystem::path &replacement);
MaintenanceResult uninstallGuestDeployment(const std::filesystem::path &current);
MaintenanceResult finalizeGuestDeployment(const std::filesystem::path &current);
namespace deployment_detail {
bool pinSource(const std::filesystem::path &, std::vector<native::Handle> &);
bool stagePackage(const std::filesystem::path &, const std::filesystem::path &,
                  std::shared_ptr<Deployment> &);
bool setString(HKEY, const wchar_t *, const std::wstring &);
bool setDword(HKEY, const wchar_t *, DWORD);
class AdministrativeLease;
bool mark(HKEY, DWORD state, DWORD expectedState, const AdministrativeLease &);
bool disjoint(const std::filesystem::path &, const std::filesystem::path &);
// Sólo operaciones administrativas; no es prueba de invitado o contención.
class AdministrativeLease {
  public:
    ~AdministrativeLease();
    bool acquire();
    bool current() const;
    bool ownsConfiguration(HKEY) const;
    HKEY gate() const { return gate_; }
    const std::filesystem::path &image() const { return image_; }
  private:
    native::Handle mutex_, token_;
    HKEY gate_ = nullptr;
    native::TokenEvidence actor_;
    std::filesystem::path image_;
    std::vector<native::Handle> source_;
    bool owns_ = false;
};
}
} // namespace gb::controller
