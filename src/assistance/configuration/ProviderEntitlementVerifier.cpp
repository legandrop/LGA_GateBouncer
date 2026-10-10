#include "ProviderEntitlementVerifier.h"
#include "ConfigurationAuthority.h"
#include "WindowsConfigurationStore.h"

namespace Gate::Assistance::Configuration {
struct ProviderEntitlementVerifier::State {
    std::shared_ptr<WindowsConfigurationStore> store;
    std::shared_ptr<ConfigurationController> controller;
};
ProviderEntitlementVerifier::ProviderEntitlementVerifier(std::shared_ptr<State> s):state_(std::move(s)){}
ProviderEntitlementVerifier::~ProviderEntitlementVerifier()=default;
std::unique_ptr<ProviderEntitlementVerifier> ProviderEntitlementVerifier::forBroker(
    std::shared_ptr<WindowsConfigurationStore> store,std::shared_ptr<ConfigurationController> controller) {
    if(!store||!controller)return {};
    auto state=std::make_shared<State>();state->store=std::move(store);state->controller=std::move(controller);
    return std::unique_ptr<ProviderEntitlementVerifier>(new ProviderEntitlementVerifier(std::move(state)));
}
ModelDisclosure ProductPublicDisclosure::lookup(const ConsentReceipt &expected,EvidenceState evidence) {
    ModelDisclosure result;result.evidence=evidence;
    auto descriptor=expected;descriptor.granted=false;descriptor.epoch=0;
    if(!descriptor.noticeRevision||!nonzero(descriptor.noticeDigest)||descriptor.profileRef.empty()||
        !nonzero(descriptor.destinationPolicyBinding)||!validReceipt(descriptor,true))return result;
    if(evidence!=EvidenceState::Restricted){result.cause=DisclosureCause::NotFound;return result;}
    auto current=Detail::nvidiaTrial().notice;current.granted=false;current.epoch=0;
    if(!(descriptor==current)){result.cause=DisclosureCause::DescriptorMismatch;return result;}
    const auto &body=Detail::trialModelNoticeBody();
    const auto sum=digest("GB_MODEL_NOTICE_1",reinterpret_cast<const unsigned char *>(body.data()),body.size());
    if(sum!=descriptor.noticeDigest){result.cause=DisclosureCause::BodyDigestMismatch;return result;}
    result.source=DisclosureSource::TrialRestricted;result.cause=DisclosureCause::Available;
    result.body=body;result.descriptor=std::move(descriptor);return result;
}
ModelDisclosure ProviderEntitlementVerifier::modelDisclosure() const {
    const auto a=state_->controller->authority_;Detail::AuthorityImage before;std::function<bool()> ordinary;
    {std::lock_guard<std::mutex> lock(a->mutex);before=Detail::image(*a);ordinary=a->ordinary;}
    bool current=false;try{current=ordinary&&ordinary()&&state_->store->facadeAvailable();}catch(...){}
    ModelDisclosure result;
    if(current&&before.alive&&!before.latched)result=ProductPublicDisclosure::lookup(before.provider.notice,before.provider.evidence);
    {std::lock_guard<std::mutex> lock(a->mutex);
        if(!(Detail::image(*a)==before)) {
            result=ModelDisclosure{};result.cause=DisclosureCause::ChangedDuringRead;return result;
        }}
    result.viewRevision=before.snapshot.revision;return result;
}
}
