#pragma once
#include "ConfigurationController.h"
#include "ConfigurationPolicy.h"
namespace Gate::Assistance::Broker { class BrokerVault; struct GeneralReservation; }

namespace Gate::Assistance::Configuration {
class PrivateConfigurationStorageTest;
class WindowsConfigurationStore final {
public:
    static std::unique_ptr<WindowsConfigurationStore> forCurrentUser(ConfigurationController &);
    ~WindowsConfigurationStore();
    WindowsConfigurationStore(const WindowsConfigurationStore&)=delete;
    MutationResult apply(ConfigurationController &,MutationTicket);
    ConfigurationSnapshot reload(ConfigurationController &);
    bool withSecret(NetworkPermit &,const Digest256 &binding,const Digest256 &seal,
        const std::function<void(const unsigned char *,std::size_t)> &consumer);
private:
    friend class PrivateConfigurationStorageTest;
    friend class Gate::Assistance::Broker::BrokerVault;
    friend class ProviderEntitlementVerifier;
    bool facadeAvailable();
    CredentialState credentialStatus();
    Broker::GeneralReservation reserveGeneral(NetworkPermit &,const Digest256 &,const Digest256 &);
    explicit WindowsConfigurationStore(std::wstring root,std::shared_ptr<const LocalConfigurationPermission>,
        std::function<void(const std::wstring &)> beforePublication={});
    struct Impl;std::unique_ptr<Impl> impl_;
};
}
