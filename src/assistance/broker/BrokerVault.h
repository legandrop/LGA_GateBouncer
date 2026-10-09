#pragma once
#include "BrokerPrimitives.h"
#include "BrokerWire.h"
#include "../configuration/ConfigurationContracts.h"
#include <functional>
#include <memory>

namespace Gate::Assistance::GroundedBridge { class GroundedBrokerRuntime; }
namespace Gate::Assistance { class WinHttpExplanationTransport; }
namespace Gate::Assistance::Configuration { class WindowsConfigurationStore; class NetworkPermit; class PrivateConfigurationStorageTest; }
namespace Gate::Assistance::Broker {
struct GeneralReservation { Failure failure=Failure::VaultUnavailable; bool committed=false; DWORD primaryError=0; };
class PrivateVaultTest;
class AssistantBrokerRuntime;
class ProductionActivation final {
public:
    static bool approved() noexcept { return false; }
private:
    ProductionActivation() = default;
};
class BrokerVault final {
public:
    static std::unique_ptr<BrokerVault> forCurrentUser();
    static std::unique_ptr<BrokerVault> forLocalConfiguration(std::shared_ptr<Configuration::WindowsConfigurationStore>);
    ~BrokerVault();
    BrokerVault(const BrokerVault &) = delete;
    BrokerVault &operator=(const BrokerVault &) = delete;
    quint8 status();
    Configuration::CredentialState localCredentialStatus();
private:
    friend class PrivateVaultTest;
    friend class Gate::Assistance::Configuration::PrivateConfigurationStorageTest;
    friend class AssistantBrokerRuntime;
    friend class Gate::Assistance::GroundedBridge::GroundedBrokerRuntime;
    friend class Gate::Assistance::WinHttpExplanationTransport;
    explicit BrokerVault(QString root, int protectedTail);
    Failure prepare();
    Failure configure(SensitiveBytes secret);
    Failure forget();
    Failure reserveAttempt();
    GeneralReservation reserveGeneral(Configuration::NetworkPermit &,const Configuration::Digest256 &,const Configuration::Digest256 &);
    Failure withSecret(const std::function<void(const unsigned char *, size_t)> &consumer);
    Failure withSecret(Configuration::NetworkPermit &,const Configuration::Digest256 &,const Configuration::Digest256 &,
        const std::function<void(const unsigned char *, size_t)> &consumer);
    static Failure validateRecord(SensitiveBytes &, const std::function<void(const unsigned char *, size_t)> &);
    Failure writeOwned(const QString &name, const unsigned char *bytes, size_t size);
    std::optional<SensitiveBytes> readOwned(const QString &name, size_t limit);
    struct Impl; std::unique_ptr<Impl> impl_;
};
}
