#pragma once
#include "ConfigurationContracts.h"
#include "../broker/BrokerPrimitives.h"
#include <functional>
#include <memory>

namespace Gate::Assistance::General { class GeneralRuntime; }
namespace Gate::Assistance::Configuration {
class PrivateConfigurationTest;
class PrivateConfigurationStorageTest;
class WindowsConfigurationStore;
class ProviderEntitlementVerifier;
class NetworkActivationIssuer;
namespace Detail { struct Authority; struct MutationData; }
class LocalConfigurationPermission final {
public:
    LocalConfigurationPermission(const LocalConfigurationPermission&)=delete;
    bool current() const;
private:
    friend class ConfigurationController;
    friend class WindowsConfigurationStore;
    friend class PrivateConfigurationTest;
    friend class PrivateConfigurationStorageTest;
    enum class Purpose { CurrentUser, PrivateFixture };
    explicit LocalConfigurationPermission(Purpose p,std::function<bool()> proof):purpose_(p),proof_(std::move(proof)){}
    static std::shared_ptr<const LocalConfigurationPermission> currentUser();
    Purpose purpose_;
    std::function<bool()> proof_;
};
class MutationTicket final {
public:
    ~MutationTicket();
    MutationTicket(MutationTicket&&) noexcept;
    MutationTicket &operator=(MutationTicket&&) noexcept;
    MutationTicket(const MutationTicket&)=delete;
    ConfigurationSnapshot candidate() const;
private:
    friend class ConfigurationController;
    friend class WindowsConfigurationStore;
    friend class PrivateConfigurationTest;
    friend class PrivateConfigurationStorageTest;
    explicit MutationTicket(std::unique_ptr<Detail::MutationData>);
    std::unique_ptr<Detail::MutationData> data_;
};
class PublicationObservation final {
private:
    friend class WindowsConfigurationStore;
    friend class ConfigurationController;
    friend class PrivateConfigurationTest;
    friend class PrivateConfigurationStorageTest;
    PublicationObservation()=default;
    bool apiSuccess_=false,attributed_=false,exactCandidate_=false;
    std::uint32_t primaryError_=0;
    std::optional<ConfigurationSnapshot> observed_;
    std::uint64_t committedRevision_=0;
};
class ConfigurationController final {
public:
    static std::unique_ptr<ConfigurationController> forCurrentUser(Id128 connection);
    ~ConfigurationController();
    ConfigurationController(const ConfigurationController&)=delete;
    ConfigurationSnapshot snapshot() const;
    std::optional<ConfigurationIntent> intent(ConfigurationVerb,std::uint64_t expectedRevision);
    std::unique_ptr<MutationTicket> begin(ConfigurationIntent,const ConfigurationMutation &,
        Broker::SensitiveBytes secret,ConfigFailure &failure);
    MutationResult finish(MutationTicket,PublicationObservation);
    void invalidate();
private:
    friend class NetworkActivationIssuer;
    friend class WindowsConfigurationStore;
    friend class ProviderEntitlementVerifier;
    friend class Gate::Assistance::General::GeneralRuntime;
    friend class PrivateConfigurationTest;
    friend class PrivateConfigurationStorageTest;
    explicit ConfigurationController(std::shared_ptr<Detail::Authority>);
    void bindCurrentSearch(SearchBindingRef,ConsentReceipt notice);
    std::shared_ptr<Detail::Authority> authority_;
    std::shared_ptr<const LocalConfigurationPermission> permission_;
};
}
