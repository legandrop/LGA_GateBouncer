#pragma once
#include "ConfigurationController.h"
#include <vector>

namespace Gate::Assistance::Configuration {
class PrivateProviderEntitlementTest;
class ProductProviderCatalog;
namespace Detail { struct EntitlementState; struct ReviewedSelection; struct EntitlementContext; }

enum class ReviewDecision : std::uint8_t { Restricted, PendingReview, Applicable };
enum class ReviewCause : std::uint8_t {
    EvidenceApplicable, TrialOnly, Malformed, TrustNotConfigured, UnknownPolicy,
    PinRejected, SignatureRejected, ScopeMismatch, CredentialSubjectUnverified,
    CredentialBindingChanged, ReviewExpired, Rollback, Revoked, LocalPublicationChanged,
    RevisionExhausted
};
struct EntitlementReviewResult {
    ReviewDecision decision=ReviewDecision::PendingReview;
    ReviewCause cause=ReviewCause::TrustNotConfigured;
    bool recognized=false, published=false, unchanged=false;
    Digest256 evidenceRevision{};
};
enum class DisclosureSource : std::uint8_t { None, TrialRestricted, ReviewedCatalog };
enum class DisclosureCause : std::uint8_t {
    Available, NoCurrentDescriptor, CatalogNotConfigured, NotFound,
    DescriptorMismatch, BodyDigestMismatch, Ambiguous, ChangedDuringRead
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

// Los objetos de confianza se producen en la composicion revisada del broker.
// Un candidato importado nunca puede suministrar filas ni pins.
class ReviewedProviderCatalog final {
public:
    static std::shared_ptr<const ReviewedProviderCatalog> currentProduct();
private:
    friend class ProductProviderCatalog;
    friend class PrivateProviderEntitlementTest;
    friend class ProviderEntitlementVerifier;
    friend class WindowsConfigurationStore;
    friend class ProductPublicDisclosure;
    struct Pin {
        std::uint16_t signer=0;
        std::uint32_t generation=0,minimumGeneration=0;
        std::array<unsigned char,64> xy{};
        std::uint64_t notBefore=0,notAfter=0;
        bool revoked=false;
        std::vector<std::pair<std::uint8_t,std::string>> policies;
    };
    struct Row {
        std::vector<unsigned char> canonical;
        std::string noticeBody;
        Id128 publicEvidence{};
        Digest256 publicSource{};
    };
    struct Revocation {
        std::uint8_t origin=0;
        std::string policy;
        Id128 evidence{},account{};
        std::uint64_t minimumReview=0,minimumRevocation=0;
        bool revoked=false;
    };
    ReviewedProviderCatalog()=default;
    bool fixture_=false;
    std::uint64_t generation_=1;
    std::vector<Pin> pins_;
    std::vector<Row> rows_;
    std::vector<Revocation> revocations_;
};
class ProductPublicDisclosure final {
public:
    static ModelDisclosure lookup(const ConsentReceipt &expected,EvidenceState evidence);
private:
    friend class ProviderEntitlementVerifier;
    friend class PrivateProviderEntitlementTest;
    static ModelDisclosure lookupIn(const std::shared_ptr<const ReviewedProviderCatalog> &,
        const ConsentReceipt &,EvidenceState);
};

class ProductProviderCatalog final {
public:
    using Pin=ReviewedProviderCatalog::Pin;
    using Row=ReviewedProviderCatalog::Row;
    using Revocation=ReviewedProviderCatalog::Revocation;
private:
    friend class Gate::Assistance::General::GeneralRuntime;
    friend class PrivateProviderEntitlementTest;
    // Solo la composicion revisada puede producir confianza, nunca el artifact/UI.
    static std::shared_ptr<const ReviewedProviderCatalog> fromReviewedBuild(
        std::uint64_t generation,std::vector<Pin>,std::vector<Row>,std::vector<Revocation>);
};

class ProviderEntitlementVerifier final {
public:
    static std::unique_ptr<ProviderEntitlementVerifier> forBroker(
        std::shared_ptr<WindowsConfigurationStore>,std::shared_ptr<ConfigurationController>);
    ~ProviderEntitlementVerifier();
    ProviderEntitlementVerifier(const ProviderEntitlementVerifier&)=delete;
    EntitlementReviewResult review(const std::vector<unsigned char> &envelope,bool explicitlySelect);
    ModelDisclosure modelDisclosure() const;
private:
    friend class PrivateProviderEntitlementTest;
    friend class Gate::Assistance::General::GeneralRuntime;
    friend class ProductProviderCatalog;
    struct State;
    explicit ProviderEntitlementVerifier(std::shared_ptr<State>);
    bool replaceCatalog(std::shared_ptr<const ReviewedProviderCatalog>);
    // Instalar en la composicion, antes de iniciar reviews concurrentes.
    void setChangedCallback(std::function<void()>);
    std::shared_ptr<State> state_;
};
}
