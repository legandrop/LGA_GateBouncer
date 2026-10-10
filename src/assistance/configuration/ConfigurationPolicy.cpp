#include "ConfigurationAuthority.h"
#include <windows.h>
#include <chrono>
#include <vector>

namespace Gate::Assistance::Configuration {
namespace Detail {
AuthorityImage image(const Authority &a) {return {a.snapshot,a.incarnation,a.connection,a.committedRevision,a.transitionBarrier,a.alive,a.failureLatched,a.provider,a.currentSearch,a.searchNotice};}
static bool noticeMatches(const ConsentReceipt &r,const ConsentReceipt &n) {
    return r.granted&&r.noticeRevision==n.noticeRevision&&r.noticeDigest==n.noticeDigest&&r.profileRef==n.profileRef&&r.destinationPolicyBinding==n.destinationPolicyBinding;
}
ActivationCause availability(const AuthorityImage &a,std::uint64_t) {
    const auto &s=a.snapshot;const auto &p=a.provider;
    if(!a.alive)return ActivationCause::SessionStale;
    if(a.latched||s.storage==StorageState::IoUncertain)return ActivationCause::LocalMutationUncertain;
    if(!validSnapshot(s)||s.storage==StorageState::Busy||s.storage==StorageState::UnsafeRoot||s.storage==StorageState::Unreadable)return ActivationCause::LocalConfigurationUnavailable;
    if(s.credential==CredentialState::Corrupt||s.storage==StorageState::Corrupt)return ActivationCause::CredentialCorrupt;
    if(s.credential!=CredentialState::Stored)return ActivationCause::CredentialMissing;
    if(s.serviceUse==ServiceUse::Unchosen)return ActivationCause::ServiceUseMissing;
    // La eleccion interna permite un intento sujeto a vault, consentimiento y presupuesto.
    // No convierte la key ni el proposito local en derechos de produccion del proveedor.
    if(s.serviceUse!=ServiceUse::InternalEvaluation)return ActivationCause::OperationalUseRestricted;
    if(!(p==nvidiaTrial())||p.profile!=s.selectedProfileRef)return ActivationCause::ProviderPolicyChanged;
    if(!noticeMatches(s.modelConsent,p.notice))return ActivationCause::ModelConsentMissing;
    if(!noticeMatches(s.webConsent,a.searchNotice))return ActivationCause::WebConsentMissing;
    if(!s.search||!a.search)return ActivationCause::SearchConfigurationMissing;
    const auto &x=*s.search;const auto &y=*a.search;
    if(x.provider!=y.provider||x.configurationBinding!=y.configurationBinding||x.instanceToken!=y.instanceToken||x.providerPolicyEpoch!=y.providerPolicyEpoch||x.providerPolicyEpoch!=s.epochs.providerPolicy||x.webConsentEpoch!=s.epochs.webConsent)return ActivationCause::ProviderPolicyChanged;
    return ActivationCause::Ready;
}
const std::string &trialModelNoticeBody() {
    static const std::string notice="For internal testing and evaluation only. Your API key does not verify production rights or remaining trial credits. Public application information, including the executable name, and approved search evidence are sent to NVIDIA. Approved public destination IP, port and protocol and retrieved registration, routing or public search evidence may also be sent. Internal and reserved addresses are excluded. Registration does not prove the final service, telemetry or safety; blocking impact may be unknown. Do not include personal, confidential or sensitive information. NVIDIA may collect requests and responses to operate and improve its services and AI models, and log use for security, fraud and abuse monitoring with third-party providers. Trial time and credit limits apply; production use requires a separate service subscription. Explanations can be wrong and never decide Allow or Block or establish that a file is safe. Review the NVIDIA API Trial Terms of Service before use: https://assets.ngc.nvidia.com/products/api-catalog/legal/NVIDIA%20API%20Trial%20Terms%20of%20Service.pdf";
    return notice;
}
ProviderRecord nvidiaTrial() {
    ProviderRecord p;
    const std::string destination="https://integrate.api.nvidia.com:443/v1/chat/completions|POST|TLS|no-redirect|"+p.model+"|InternalEvaluation|GB_GENERAL_SNIPPETS_ULTRA_1|2";
    p.destination=digest("GB_DESTINATION_MODEL_MODE_1",reinterpret_cast<const unsigned char *>(destination.data()),destination.size());
    const std::string trial="https://assets.ngc.nvidia.com/products/api-catalog/legal/NVIDIA%20API%20Trial%20Terms%20of%20Service.pdf|1.2|1.4|internal-testing-evaluation-only|production-subscription-pending";
    p.evidenceRevision=digest("GB_PROVIDER_EVIDENCE_REVISION_1",reinterpret_cast<const unsigned char *>(trial.data()),trial.size());
    const auto &notice=trialModelNoticeBody();
    p.notice.granted=true;p.notice.noticeRevision=4;p.notice.profileRef=p.profile;p.notice.destinationPolicyBinding=p.destination;
    p.notice.noticeDigest=digest("GB_MODEL_NOTICE_1",reinterpret_cast<const unsigned char *>(notice.data()),notice.size());return p;
}
static void number(std::vector<unsigned char> &v,std::uint64_t n,unsigned width) {for(unsigned i=0;i<width;++i)v.push_back(static_cast<unsigned char>(n>>(8*i)));}
template<class T> static void bytes(std::vector<unsigned char> &v,const T &value){v.insert(v.end(),value.begin(),value.end());}
static void text(std::vector<unsigned char> &v,const std::string &s){number(v,s.size(),2);bytes(v,s);}
static void receipt(std::vector<unsigned char> &v,const ConsentReceipt &r){number(v,r.granted,1);number(v,r.noticeRevision,4);bytes(v,r.noticeDigest);text(v,r.profileRef);bytes(v,r.destinationPolicyBinding);number(v,r.epoch,8);}
static Digest256 privateDigest(const PermitLease &l) {
    std::vector<unsigned char> v;const auto &a=l.image;const auto &s=a.snapshot;const auto &p=a.provider;const auto &e=s.epochs;
    bytes(v,s.storeInstance);bytes(v,a.incarnation);bytes(v,a.connection);number(v,a.committedRevision,8);number(v,s.revision,8);number(v,a.barrier,8);
    number(v,std::uint8_t(s.serviceUse),1);
    for(auto n:{e.configuration,e.credential,e.consent,e.modelConsent,e.webConsent,e.retrieval,e.providerPolicy,e.entitlement,e.session})number(v,n,8);
    text(v,p.profile);number(v,p.profileRevision,4);bytes(v,p.destination);text(v,p.model);number(v,std::uint8_t(p.modality),1);bytes(v,p.accountScope);
    receipt(v,s.modelConsent);receipt(v,s.webConsent);bytes(v,p.evidenceId);bytes(v,p.evidenceRevision);bytes(v,p.scope);number(v,std::uint8_t(p.evidence),1);number(v,p.notBefore,8);number(v,p.notAfter,8);number(v,l.deadline,8);bytes(v,l.binding);bytes(v,l.seal);number(v,l.serial,8);
    return digest("GB_CONFIGURATION_AUTHORITY_1",v.data(),v.size());
}
}
static std::uint64_t utcNow(){return std::uint64_t(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());}
BrokerJobAuthorization::BrokerJobAuthorization(Digest256 b,Digest256 s,Epochs e,std::uint64_t deadline,std::shared_ptr<const void> record,std::function<bool()> current,bool pending,bool available,bool sealed,std::uint64_t serial):binding_(b),seal_(s),epochs_(e),deadline_(deadline),serial_(serial),record_(std::move(record)),current_(std::move(current)),pending_(pending),serviceAvailable_(available),sealed_(sealed){}
NetworkActivationIssuer::NetworkActivationIssuer(ConfigurationController &c):authority_(c.authority_){}
NetworkActivationSnapshot NetworkActivationIssuer::snapshot() const {
    NetworkActivationSnapshot result;auto a=authority_.lock();if(!a){result.cause=ActivationCause::SessionStale;return result;}
    Detail::AuthorityImage copy;std::function<bool()> ordinary;{std::lock_guard<std::mutex> lock(a->mutex);copy=Detail::image(*a);ordinary=a->ordinary;}
    bool current=false;
    try {current=ordinary&&ordinary();}catch(...) {}
    // Ordinary puede reentrar, revocar o destruir el controlador: no publicar la imagen anterior.
    std::lock_guard<std::mutex> lock(a->mutex);
    if(!(Detail::image(*a)==copy)||!a->alive){result.cause=ActivationCause::SessionStale;return result;}
    result.cause=current?Detail::availability(copy,utcNow()):ActivationCause::LocalConfigurationUnavailable;
    result.technicallyAvailable=result.cause==ActivationCause::Ready;
    result.entitlementState=copy.provider.evidence;result.profileRef=copy.provider.profile;result.destinationModelModeBinding=copy.provider.destination;result.entitlementRevisionBinding=copy.provider.evidenceRevision;result.epochs=copy.snapshot.epochs;return result;
}
PermitResult NetworkActivationIssuer::evaluate(BrokerJobAuthorization job) {
    auto a=authority_.lock();if(!a)return {ActivationCause::SessionStale,{}};
    Detail::AuthorityImage copy;std::function<bool()> ordinary;{std::lock_guard<std::mutex> lock(a->mutex);copy=Detail::image(*a);ordinary=a->ordinary;}
    auto why=ordinary&&ordinary()?Detail::availability(copy,utcNow()):ActivationCause::LocalConfigurationUnavailable;
    if(why!=ActivationCause::Ready)return {why,{}};
    if(!job.pending_||!job.serviceAvailable_)return {ActivationCause::ServiceUnavailable,{}};
    if(!(job.epochs_==copy.snapshot.epochs))return {ActivationCause::SessionStale,{}};
    if(!job.sealed_||!nonzero(job.binding_)||!nonzero(job.seal_)||!job.serial_)return {ActivationCause::PayloadNotSealed,{}};
    const auto now=GetTickCount64();if(job.deadline_<=now||job.deadline_-now>45000)return {ActivationCause::TechnicalPrerequisitesMissing,{}};
    if(!job.record_||!job.current_)return {ActivationCause::PublicQueryApprovalMissing,{}};
    try{if(!job.current_())return {ActivationCause::PublicQueryApprovalMissing,{}};}catch(...){return {ActivationCause::PublicQueryApprovalMissing,{}};}
    {std::lock_guard<std::mutex> lock(a->mutex);if(!(Detail::image(*a)==copy))return {ActivationCause::SessionStale,{}};}
    auto lease=std::make_shared<Detail::PermitLease>();lease->authority=a;lease->image=std::move(copy);lease->binding=job.binding_;lease->seal=job.seal_;lease->deadline=job.deadline_;lease->serial=job.serial_;lease->record=std::move(job.record_);lease->currentApproval=std::move(job.current_);lease->privateDigest=Detail::privateDigest(*lease);
    if(!nonzero(lease->privateDigest))return {ActivationCause::TechnicalPrerequisitesMissing,{}};
    return {ActivationCause::Ready,NetworkPermit(std::move(lease))};
}
PermitCause NetworkPermit::cause(ActivationStage stage,const Digest256 &binding,const Digest256 &seal) const noexcept {
    try {
        const auto l=lease_;if(!l)return PermitCause::AuthorityGone;
        if(binding!=l->binding||seal!=l->seal)return PermitCause::BindingMismatch;
        if(std::uint8_t(stage)>6)return PermitCause::ScopeMismatch;
        auto a=l->authority.lock();if(!a)return PermitCause::AuthorityGone;
        Detail::AuthorityImage copy;std::function<bool()> ordinary;{std::lock_guard<std::mutex> lock(a->mutex);copy=Detail::image(*a);ordinary=a->ordinary;}
        if(!copy.alive||!ordinary||!ordinary())return PermitCause::AuthorityGone;
        if(copy.incarnation!=l->image.incarnation||copy.connection!=l->image.connection||copy.barrier!=l->image.barrier||copy.latched)return PermitCause::Revoked;
        if(!(copy==l->image)||Detail::privateDigest(*l)!=l->privateDigest)return PermitCause::ScopeMismatch;
        if(GetTickCount64()>=l->deadline)return PermitCause::Expired;
        if(Detail::availability(copy,utcNow())!=ActivationCause::Ready)return PermitCause::MissingEvidence;
        if(l->consumed.load()&&(stage==ActivationStage::Admission||stage==ActivationStage::BeforeSecret||stage==ActivationStage::BeforeReserve||stage==ActivationStage::PreSend))return PermitCause::AlreadyConsumed;
        if(!l->record||!l->currentApproval||!l->currentApproval())return PermitCause::Revoked;
        {std::lock_guard<std::mutex> lock(a->mutex);if(!(Detail::image(*a)==copy))return PermitCause::Revoked;}
        return PermitCause::Current;
    }catch(...){return PermitCause::Revoked;}
}
bool NetworkPermit::consumePreSend(const Digest256 &binding,const Digest256 &seal) noexcept {
    const auto lease=lease_;if(!lease||!current(ActivationStage::PreSend,binding,seal))return false;
    bool expected=false;return lease->consumed.compare_exchange_strong(expected,true);
}
}
