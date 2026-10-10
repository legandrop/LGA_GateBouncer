#pragma once
#include "ConfigurationController.h"

namespace Gate::Assistance::Configuration {
enum class DisclosureSource : std::uint8_t { None, TrialRestricted };
enum class DisclosureCause : std::uint8_t {
    Available, NoCurrentDescriptor, NotFound, DescriptorMismatch,
    BodyDigestMismatch, ChangedDuringRead
};
struct ModelDisclosure {
    DisclosureSource source=DisclosureSource::None;
    DisclosureCause cause=DisclosureCause::NoCurrentDescriptor;
    EvidenceState evidence=EvidenceState::Missing;
    std::string body;
    ConsentReceipt descriptor;
    std::uint64_t viewRevision=0;
    ModelDisclosure(){descriptor.granted=false;descriptor.epoch=0;}
};
class ProductPublicDisclosure final {
public:
    static ModelDisclosure lookup(const ConsentReceipt &expected,EvidenceState evidence);
};

// Contrasta el aviso publico con la configuracion original vigente del broker.
// No verifica cuenta ni derechos productivos y no acepta certificados importados.
class ProviderEntitlementVerifier final {
public:
    static std::unique_ptr<ProviderEntitlementVerifier> forBroker(
        std::shared_ptr<WindowsConfigurationStore>,std::shared_ptr<ConfigurationController>);
    ~ProviderEntitlementVerifier();
    ProviderEntitlementVerifier(const ProviderEntitlementVerifier&)=delete;
    ModelDisclosure modelDisclosure() const;
private:
    struct State;
    explicit ProviderEntitlementVerifier(std::shared_ptr<State>);
    std::shared_ptr<State> state_;
};
}
