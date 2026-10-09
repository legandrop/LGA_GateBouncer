#pragma once
#include "ConfigurationContracts.h"
#include <functional>
#include <memory>

namespace Gate::Assistance::General { class GeneralRuntime; }
namespace Gate::Assistance::Configuration {
class ConfigurationController;
class PrivateConfigurationTest;
namespace Detail { struct Authority; struct PermitLease; }
enum class ActivationStage : std::uint8_t { Admission, BeforeSecret, BeforeReserve, PreSend, BeforeCallback, AfterCallback, Snapshot };
enum class PermitCause : std::uint8_t { Current, MissingEvidence, Revoked, Expired, BindingMismatch, ScopeMismatch, AlreadyConsumed, AuthorityGone };
class BrokerJobAuthorization final {
public:
    BrokerJobAuthorization(BrokerJobAuthorization&&) noexcept=default;
    BrokerJobAuthorization(const BrokerJobAuthorization&)=delete;
private:
    friend class Gate::Assistance::General::GeneralRuntime;
    friend class PrivateConfigurationTest;
    friend class PrivateConfigurationStorageTest;
    friend class NetworkActivationIssuer;
    BrokerJobAuthorization(Digest256 binding,Digest256 seal,Epochs epochs,std::uint64_t deadline,
        std::shared_ptr<const void> approvalRecord,std::function<bool()> currentApproval,
        bool pending,bool serviceAvailable,bool sealed,std::uint64_t jobSerial);
    Digest256 binding_,seal_;
    Epochs epochs_;
    std::uint64_t deadline_,serial_;
    std::shared_ptr<const void> record_;
    std::function<bool()> current_;
    bool pending_,serviceAvailable_,sealed_;
};
class NetworkPermit final {
public:
    NetworkPermit(NetworkPermit&&) noexcept=default;
    NetworkPermit &operator=(NetworkPermit&&) noexcept=default;
    NetworkPermit(const NetworkPermit&)=delete;
    NetworkPermit &operator=(const NetworkPermit&)=delete;
    PermitCause cause(ActivationStage,const Digest256 &binding,const Digest256 &seal) const noexcept;
    bool current(ActivationStage s,const Digest256 &b,const Digest256 &p) const noexcept {return cause(s,b,p)==PermitCause::Current;}
    bool consumePreSend(const Digest256 &binding,const Digest256 &seal) noexcept;
private:
    friend class NetworkActivationIssuer;
    friend class WindowsConfigurationStore;
    explicit NetworkPermit(std::shared_ptr<Detail::PermitLease> lease):lease_(std::move(lease)){}
    std::shared_ptr<Detail::PermitLease> lease_;
};
struct PermitResult { ActivationCause cause=ActivationCause::EntitlementMissing; std::optional<NetworkPermit> permit; };
class NetworkActivationIssuer final {
public:
    explicit NetworkActivationIssuer(ConfigurationController &);
    NetworkActivationSnapshot snapshot() const;
    PermitResult evaluate(BrokerJobAuthorization);
private:
    friend class PrivateConfigurationTest;
    std::weak_ptr<Detail::Authority> authority_;
};
}
