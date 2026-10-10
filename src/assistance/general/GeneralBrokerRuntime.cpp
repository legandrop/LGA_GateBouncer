#include "GeneralRuntimeState.h"
#include "GeneralModelTransport.h"
#include "configuration/ConfigurationAuthority.h"
#include <QThread>
namespace Gate::Assistance::General {
bool GeneralRuntime::initializeEntitlement(std::shared_ptr<Configuration::WindowsConfigurationStore> store) {
    const auto d=data_;
    if(d->closed||!store||!d->configuration||d->verifier||QThread::currentThread()!=thread())return false;
    auto verifier=Configuration::ProviderEntitlementVerifier::forBroker(std::move(store),d->configuration);
    if(!verifier)return false;
    d->verifier=std::shared_ptr<Configuration::ProviderEntitlementVerifier>(std::move(verifier));
    return true;
}
GeneralRuntime::GeneralRuntime(std::shared_ptr<SearchPort> search,std::shared_ptr<Broker::BrokerVault> vault,
    std::shared_ptr<Configuration::ConfigurationController> configuration,std::shared_ptr<GeneralJobRegistry> registry,
    GeneralCoordinator::Current current,GeneralCoordinator::Clock clock):GeneralRuntime(std::move(current),std::move(clock),nullptr) {
    const auto d=data_;d->configuration=std::move(configuration);d->registry=std::move(registry);
    if(!vault||!d->configuration||!d->registry){d->closed=true;return;}
    d->issuer=std::make_unique<Configuration::NetworkActivationIssuer>(*d->configuration);
    const std::weak_ptr<Data> weak=d;
    d->admission=[weak](const FullBinding& b){const auto owner=weak.lock();return owner&&admission(owner,b);};
    auto model=std::shared_ptr<ModelPort>(new GeneralModelTransport(std::move(vault),d->configuration,
        [weak](const FullBinding& b,const SealedGeneralPayload& p,const std::shared_ptr<const void>& token){
            const auto owner=weak.lock();return owner?authorize(owner,b,p,token):Configuration::PermitResult{Configuration::ActivationCause::SessionStale,{}};
        }));
    compose(std::move(search),std::move(model));
}
namespace {
bool matchesConfiguration(const FullBinding& b,const Configuration::ConfigurationSnapshot& s) {
    const auto &e=s.epochs;
    return s.search&&s.selectedProfileRef==Configuration::GeneralProfile&&
        e.session==b.sessionEpoch&&e.credential==b.credentialEpoch&&e.modelConsent==b.modelConsentEpoch&&
        e.webConsent==b.webConsentEpoch&&e.retrieval==b.retrievalEpoch&&e.providerPolicy==b.providerPolicyEpoch&&
        e.entitlement==b.entitlementPolicyEpoch&&s.search->provider==static_cast<std::uint8_t>(b.provider)&&
        s.search->configurationBinding==b.providerConfiguration&&std::string(s.search->instanceToken.data(),38)==b.providerInstance;
}
}
bool GeneralRuntime::admission(const std::shared_ptr<Data>& d,const FullBinding& b) {
    const auto job=d->job;
    auto current=[d,job,&b]{
        if(d->closed||!job||d->job!=job||d->approval!=job->record||job->record->binding()!=b)return false;
        const bool valid=job->record->isCurrent();
        return valid&&!d->closed&&d->job==job&&d->approval==job->record;
    };
    if(!d->configuration||!d->issuer||!current())return false;
    const auto snapshot=d->configuration->snapshot();
    if(!matchesConfiguration(b,snapshot)||!current())return false;
    const auto activation=d->issuer->snapshot();
    if(activation.cause!=Configuration::ActivationCause::Ready||!activation.technicallyAvailable||!current())return false;
    return !d->closed&&d->job==job&&d->configuration->snapshot()==snapshot;
}
void GeneralRuntime::bindSearch(Configuration::SearchBindingRef binding,Configuration::ConsentReceipt notice) {
    const auto d=data_;withdraw();if(!d->closed&&d->configuration)d->configuration->bindCurrentSearch(std::move(binding),std::move(notice));
}
Configuration::ConsentReceipt GeneralRuntime::modelNotice() const {
    const auto d=data_;if(d->closed||!d->configuration)return {};
    const auto authority=d->configuration->authority_;std::lock_guard<std::mutex> lock(authority->mutex);
    auto receipt=authority->provider.notice;receipt.granted=false;receipt.epoch=0;return receipt;
}
Configuration::ModelDisclosure GeneralRuntime::modelDisclosure() const {
    const auto d=data_;const auto verifier=d->verifier;
    return !d->closed&&verifier?verifier->modelDisclosure():Configuration::ModelDisclosure{};
}
GeneralRuntime::SearchPresentation GeneralRuntime::currentSearchPresentation() const {
    const auto d=data_;if(d->closed||!d->configuration)return {};
    const auto authority=d->configuration->authority_;std::lock_guard<std::mutex> lock(authority->mutex);
    auto notice=authority->searchNotice;notice.granted=false;notice.epoch=0;
    return {authority->currentSearch,std::move(notice)};
}
GeneralRuntime::GeneralRuntime(std::shared_ptr<SearchPort> search,Broker::BrokerVault& vault,
    std::shared_ptr<Configuration::ConfigurationController> configuration,GeneralCoordinator::Current current,
    GeneralCoordinator::Clock clock,QObject* parent):GeneralRuntime(std::move(current),std::move(clock),parent) {
    const auto d=data_;d->configuration=std::move(configuration);
    if(d->configuration)d->issuer=std::make_unique<Configuration::NetworkActivationIssuer>(*d->configuration);
    const std::weak_ptr<Data> weak=d;
    auto model=std::shared_ptr<ModelPort>(new GeneralModelTransport(vault,[weak](const FullBinding& b,const SealedGeneralPayload& p,const std::shared_ptr<const void>& token){
        const auto owner=weak.lock();return owner?authorize(owner,b,p,token):Configuration::PermitResult{Configuration::ActivationCause::SessionStale,{}};
    }));
    compose(std::move(search),std::move(model));
}
Configuration::PermitResult GeneralRuntime::authorize(const std::shared_ptr<Data>& d,
    const FullBinding& binding,const SealedGeneralPayload& seal,const std::shared_ptr<const void>& token) {
    const auto job=d->job;
    if(d->closed||!job||job->claimed||!token||!d->issuer||!d->configuration||job->record!=d->approval||job->record->binding()!=binding||!GeneralPayloadBuilder::validProfile(seal,binding))return {Configuration::ActivationCause::SessionStale,{}};
    job->claimed=true;job->modelToken=token;
    const std::weak_ptr<Data> weak=d;
    auto current=[weak,job]{
        const auto owner=weak.lock();if(!owner||owner->closed||owner->job!=job||owner->approval!=job->record)return false;
        const auto now=owner->clock();if(now<0||std::uint64_t(now)>=job->deadline)return false;
        const bool valid=job->record->isCurrent();return valid&&!owner->closed&&owner->job==job&&owner->approval==job->record;
    };
    if(!current())return {Configuration::ActivationCause::SessionStale,{}};
    const auto snapshot=d->configuration->snapshot();const auto &e=snapshot.epochs;
    if(!snapshot.search||snapshot.selectedProfileRef!=Configuration::GeneralProfile||
       e.session!=binding.sessionEpoch||e.credential!=binding.credentialEpoch||e.modelConsent!=binding.modelConsentEpoch||
       e.webConsent!=binding.webConsentEpoch||e.retrieval!=binding.retrievalEpoch||e.providerPolicy!=binding.providerPolicyEpoch||e.entitlement!=binding.entitlementPolicyEpoch||
       snapshot.search->provider!=static_cast<std::uint8_t>(binding.provider)||snapshot.search->configurationBinding!=binding.providerConfiguration||
       std::string(snapshot.search->instanceToken.data(),38)!=binding.providerInstance||!current())return {Configuration::ActivationCause::ProviderPolicyChanged,{}};
    // Un único evaluate por aprobación y trabajo, aun con reentrada o leases duplicables.
    auto issued=d->issuer->evaluate(Configuration::BrokerJobAuthorization(binding.canonicalDigest(),seal.payloadDigest(),e,
        job->deadline,job->record,current,true,true,true,job->serial));
    if(!current())return {Configuration::ActivationCause::SessionStale,{}};
    return issued;
}
}
