#pragma once
#include "ProviderEntitlementVerifier.h"
#include "ConfigurationAuthority.h"
#include <map>

namespace Gate::Assistance::Configuration::Detail {
struct ReviewArtifact {
    std::uint8_t origin=0,source=0,subject=0;
    std::uint16_t signer=0;
    std::uint32_t pinGeneration=0;
    std::string policy;
    std::uint64_t policyRevision=0,reviewRevision=0,credentialEpoch=0;
    std::uint64_t notBefore=0,notAfter=0,reviewedAt=0,nextReviewBy=0,revocation=0,policyReviewBy=0;
    Id128 evidence{},account{},credentialRef{},store{};
    Digest256 sourceDigest{},subjectBinding{},destination{},model{},scope{},quota{},revision{};
    ConsentReceipt notice;
    std::vector<unsigned char> canonical;
    std::array<unsigned char,64> signature{};
};
struct RuntimeFloor {
    std::uint64_t policy=0,review=0,revocation=0;
    std::vector<unsigned char> canonical;
};
struct EntitlementState {
    std::shared_ptr<const ReviewedProviderCatalog> catalog;
    std::uint64_t floorGeneration=1;
    std::map<std::string,RuntimeFloor> policies,evidences,accounts;
    std::optional<AuthorityImage> publishedImage;
    Digest256 publishedReview{};
};
struct EntitlementContext {
    std::weak_ptr<WindowsConfigurationStore> store;
    std::weak_ptr<Authority> authority;
    AuthorityImage image;
    Id128 capability{},pendingTicket{};
    ConfigurationVerb capabilityVerb=ConfigurationVerb::Mode;
    std::uint64_t capabilityExpiry=0,catalogGeneration=0,floorGeneration=0;
    std::uint64_t volume=0,size=0,writeTime=0,committedRevision=0;
    Id128 fileId{};
    Digest256 envelope{},integrity{};
    EntitlementContext(EntitlementContext&&)=default;
    EntitlementContext(const EntitlementContext&)=delete;
private:
    friend class Gate::Assistance::Configuration::WindowsConfigurationStore;
    EntitlementContext()=default;
};
struct ReviewedSelection {
    ReviewArtifact artifact;
    ProviderRecord provider;
    EntitlementReviewResult result;
    std::shared_ptr<const ReviewedProviderCatalog> catalog;
    std::uint64_t minimumReview=0,minimumRevocation=0;
    std::uint64_t checkedUtc=0,checkedTick=0;
};
bool entitlementFloorsCurrent(const EntitlementState &,const ReviewedSelection &);
bool advanceEntitlement(Authority &);
void rememberEntitlement(EntitlementState &,const ReviewedSelection &,const AuthorityImage &);
inline bool entitlementImageCurrent(const Authority &a,const EntitlementContext &p) {
    return a.alive&&!a.failureLatched&&image(a)==p.image&&a.capability==p.capability&&
        a.capabilityVerb==p.capabilityVerb&&a.capabilityExpiry==p.capabilityExpiry&&
        a.pendingTicket==p.pendingTicket&&!nonzero(a.pendingTicket)&&a.entitlement&&
        a.entitlement->floorGeneration==p.floorGeneration;
}
}
