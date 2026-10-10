#pragma once
#include "../common/protected_file_win.h"
#include <map>
#include <memory>
#include <mutex>
namespace gb::controller {
// Inventory nativo cerrado, provisto por despliegue administrativo protegido.
using Inventory = std::map<std::wstring, wire::Digest>;
bool parseInventory(const wire::Bytes &bytes, Inventory &inventory);
bool encodeInventory(const Inventory &, wire::Bytes &);
enum class DeploymentRole { DecisionController, OrdinaryGui, Service, AssistantBroker };
enum class DeploymentMode { Laboratory, Product };
const wchar_t *deploymentService(DeploymentMode);
const wchar_t *deploymentRegistry(DeploymentMode);
const wchar_t *deploymentConfiguration(DeploymentMode);
std::wstring deploymentCommand(const std::filesystem::path &, DeploymentMode);
const std::vector<std::wstring> &deploymentFiles(DeploymentRole);
bool serviceDescriptor(PSECURITY_DESCRIPTOR);
bool serviceConfiguration(SC_HANDLE, const std::filesystem::path &, DWORD expectedPid = 0,
                          DeploymentMode = DeploymentMode::Laboratory);
// El mantenimiento exige su fase exacta; la admisión normal sigue AUTO_START.
bool serviceConfigurationPhase(SC_HANDLE, const std::filesystem::path &, DWORD startType,
                               DWORD expectedPid = 0, DeploymentMode = DeploymentMode::Laboratory);
bool maintenanceState(HKEY, bool &present, DWORD &state);
class Deployment {
  public:
    explicit Deployment(std::filesystem::path root, DeploymentMode = DeploymentMode::Laboratory);
    ~Deployment();
    bool verify(const std::filesystem::path &ownImage,
                DeploymentRole role = DeploymentRole::DecisionController);
    bool current() noexcept;
    bool matchesImage(const std::filesystem::path &, const BY_HANDLE_FILE_INFORMATION &) const;
    // Sólo el helper propio del broker, derivado del GBD1 original retenido.
    bool signatureHelperInventory(std::filesystem::path &, wire::Digest &);
    bool admitServiceConfiguration(wire::Bytes &account, std::filesystem::path &store,
                                   bool &provision);
    bool serviceAdmittedCurrent() noexcept;
    DeploymentMode mode() const { return mode_; }
    bool prepareEnvironment();
    const std::filesystem::path &root() const { return root_; }

  private:
    bool readFile(const std::filesystem::path &relative, wire::Bytes &bytes, std::size_t cap);
    bool enumerate(const std::filesystem::path &relative, unsigned depth,
                   std::vector<std::wstring> &files, bool retain = true);
    struct Registration;
    struct FilePin { std::filesystem::path path; BY_HANDLE_FILE_INFORMATION identity{};
                     std::size_t handle = 0; };
    std::filesystem::path root_;
    const DeploymentMode mode_;
    native::ProtectedDirectory directory_;
    std::vector<native::Handle> held_;
    std::vector<FilePin> files_;
    std::unique_ptr<Registration> registration_;
    Inventory inventory_;
    DeploymentRole role_ = DeploymentRole::DecisionController;
    bool verified_ = false;
    bool revoked_ = false;
    mutable std::recursive_mutex currentMutex_;
};
} // namespace gb::controller
