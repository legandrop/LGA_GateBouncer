#include "ConfigurationAuthority.h"
#include <windows.h>
#include <limits>

namespace Gate::Assistance::Configuration {
namespace Detail {
void revokeReceipts(ConfigurationSnapshot &s) {
    s.modelConsent={};s.modelConsent.epoch=s.epochs.modelConsent;
    s.webConsent={};s.webConsent.epoch=s.epochs.webConsent;
    if(s.search)s.search->webConsentEpoch=s.epochs.webConsent;
}
bool advance(Authority &a) {
    auto &s=a.snapshot;
    if(s.revision==UINT64_MAX||a.transitionBarrier==UINT64_MAX||s.epochs.configuration==UINT64_MAX||s.epochs.retrieval==UINT64_MAX||s.epochs.session==UINT64_MAX){a.alive=false;a.failureLatched=true;revokeReceipts(s);return false;}
    ++s.revision;++a.transitionBarrier;++s.epochs.configuration;++s.epochs.retrieval;++s.epochs.session;
    a.capability={};a.capabilityExpiry=0;return true;
}
static void abandon(MutationData &d) {
    if(auto a=d.authority.lock()){std::lock_guard<std::mutex> lock(a->mutex);if(a->pendingTicket==d.ticket){a->pendingTicket={};a->failureLatched=true;a->snapshot.storage=StorageState::IoUncertain;revokeReceipts(a->snapshot);advance(*a);}}
}
}
MutationTicket::MutationTicket(std::unique_ptr<Detail::MutationData> d):data_(std::move(d)){}
MutationTicket::~MutationTicket(){if(data_)Detail::abandon(*data_);}
MutationTicket::MutationTicket(MutationTicket &&o) noexcept:data_(std::move(o.data_)){}
MutationTicket &MutationTicket::operator=(MutationTicket &&o) noexcept {if(this!=&o){if(data_)Detail::abandon(*data_);data_=std::move(o.data_);}return *this;}
ConfigurationSnapshot MutationTicket::candidate() const {return data_?data_->candidate:ConfigurationSnapshot{};}
ConfigurationController::ConfigurationController(std::shared_ptr<Detail::Authority> a):authority_(std::move(a)){}
ConfigurationController::~ConfigurationController(){invalidate();std::lock_guard<std::mutex> lock(authority_->mutex);authority_->alive=false;}
bool LocalConfigurationPermission::current() const {try{return proof_&&proof_();}catch(...){return false;}}
std::shared_ptr<const LocalConfigurationPermission> LocalConfigurationPermission::currentUser() {
    Broker::TokenIdentity identity;if(!Broker::tokenIdentity(GetCurrentProcess(),identity)||!identity.ordinary)return {};
    return std::shared_ptr<const LocalConfigurationPermission>(new LocalConfigurationPermission(Purpose::CurrentUser,[identity=std::move(identity)]{Broker::TokenIdentity current;return Broker::tokenIdentity(GetCurrentProcess(),current)&&Broker::sameIdentity(identity,current);}));
}
std::unique_ptr<ConfigurationController> ConfigurationController::forCurrentUser(Id128 connection) {
    auto permission=LocalConfigurationPermission::currentUser();if(!permission||!nonzero(connection))return {};
    auto a=std::make_shared<Detail::Authority>();a->connection=connection;
    Id128 nonce{};if(!Broker::randomId(a->incarnation)||!Broker::randomId(a->snapshot.storeInstance)||!Broker::randomId(nonce))return {};
    std::uint64_t session=0;for(unsigned i=0;i<8;++i)session|=std::uint64_t(nonce[i])<<(8*i);if(!session)return {};
    a->snapshot.epochs.session=session;a->provider=Detail::nvidiaTrial();
    a->ordinary=[permission]{return permission->current();};
    auto controller=std::unique_ptr<ConfigurationController>(new ConfigurationController(std::move(a)));controller->permission_=std::move(permission);return controller;
}
ConfigurationSnapshot ConfigurationController::snapshot() const {std::lock_guard<std::mutex> lock(authority_->mutex);return authority_->snapshot;}
std::optional<ConfigurationIntent> ConfigurationController::intent(ConfigurationVerb verb,std::uint64_t revision) {
    auto a=authority_;std::lock_guard<std::mutex> lock(a->mutex);
    if(!a->alive||!a->ordinary||!a->ordinary()||nonzero(a->pendingTicket)||revision!=a->snapshot.revision||std::uint8_t(verb)<1||std::uint8_t(verb)>6)return {};
    if(!Broker::randomId(a->capability))return {};
    a->capabilityVerb=verb;a->capabilityExpiry=GetTickCount64()+5000;
    return ConfigurationIntent{a->capability,a->snapshot.revision,verb};
}
static bool sameNotice(const ConsentReceipt &r,const ConsentReceipt &notice) {
    return r.noticeRevision==notice.noticeRevision&&r.noticeDigest==notice.noticeDigest&&r.profileRef==notice.profileRef&&r.destinationPolicyBinding==notice.destinationPolicyBinding;
}
static bool sameSearch(const SearchBindingRef &s,const SearchBindingRef &current) {
    return s.provider==current.provider&&s.configurationBinding==current.configurationBinding&&s.instanceToken==current.instanceToken;
}
std::unique_ptr<MutationTicket> ConfigurationController::begin(ConfigurationIntent intent,const ConfigurationMutation &m,Broker::SensitiveBytes secret,ConfigFailure &failure) {
    failure=ConfigFailure::Malformed;
    if(m.verb==ConfigurationVerb::Store){if(!secret.size()||secret.size()>512)return {};for(std::size_t i=0;i<secret.size();++i)if(secret.data()[i]<33||secret.data()[i]>126)return {};}
    else if(secret.size())return {};
    auto a=authority_;std::lock_guard<std::mutex> lock(a->mutex);
    failure=ConfigFailure::Unauthorized;
    if(!a->alive||!a->ordinary||!a->ordinary()||!nonzero(a->capability)||intent.capability!=a->capability||intent.verb!=a->capabilityVerb||m.verb!=intent.verb||GetTickCount64()>a->capabilityExpiry)return {};
    if(intent.revision!=a->snapshot.revision){failure=ConfigFailure::Stale;return {};}
    if(nonzero(a->pendingTicket)){failure=ConfigFailure::Busy;return {};}
    if(a->snapshot.storage==StorageState::Busy){failure=ConfigFailure::Busy;return {};}
    if(a->snapshot.storage==StorageState::UnsafeRoot){failure=ConfigFailure::UnsafeRoot;return {};}
    if(a->snapshot.storage==StorageState::Unreadable){failure=ConfigFailure::Unreadable;return {};}
    if(a->snapshot.storage==StorageState::Corrupt&&m.verb!=ConfigurationVerb::Forget){failure=ConfigFailure::Corrupt;return {};}
    auto candidate=a->snapshot;failure=ConfigFailure::Malformed;
    if(m.verb==ConfigurationVerb::Consent&&(!validReceipt(m.receipt,true)||(m.target!=ConsentTarget::Model&&m.target!=ConsentTarget::Web)||(m.receipt.granted&&!sameNotice(m.receipt,m.target==ConsentTarget::Model?a->provider.notice:a->searchNotice))))return {};
    if(m.verb==ConfigurationVerb::Mode&&(m.mode!=ModeChoice::Manual&&m.mode!=ModeChoice::Automatic))return {};
    if(m.verb==ConfigurationVerb::Profile&&(m.profileRef!=a->provider.profile||m.profileRevision!=a->provider.profileRevision)){failure=ConfigFailure::UnsupportedProfile;return {};}
    if(m.verb==ConfigurationVerb::Search&&(!m.search||!validSearch(*m.search,true)||!a->currentSearch||!sameSearch(*m.search,*a->currentSearch)))return {};
    auto d=std::make_unique<Detail::MutationData>();d->precedent=a->observedRecord;d->precedentRevision=a->committedRevision;d->failureLatchedAtBegin=a->failureLatched;if(!Broker::randomId(d->ticket)){failure=ConfigFailure::Unreadable;return {};}
    if(a->committedRevision==UINT64_MAX||candidate.epochs.credential==UINT64_MAX||candidate.epochs.consent==UINT64_MAX||candidate.epochs.modelConsent==UINT64_MAX||candidate.epochs.webConsent==UINT64_MAX||candidate.epochs.entitlement==UINT64_MAX){a->alive=false;failure=ConfigFailure::RevisionExhausted;return {};}
    if(!Detail::advance(*a)){failure=ConfigFailure::RevisionExhausted;return {};}
    candidate.epochs=a->snapshot.epochs;candidate.revision=a->snapshot.revision;candidate.storage=StorageState::Ready;
    if(a->failureLatched)Detail::revokeReceipts(candidate);
    if(m.verb==ConfigurationVerb::Store||m.verb==ConfigurationVerb::Forget){
        candidate.credential=m.verb==ConfigurationVerb::Store?CredentialState::Stored:CredentialState::Absent;
        ++candidate.epochs.credential;++candidate.epochs.consent;++candidate.epochs.modelConsent;++candidate.epochs.webConsent;Detail::revokeReceipts(candidate);
        if(m.verb==ConfigurationVerb::Forget&&(!a->committedRevision||a->snapshot.storage==StorageState::Corrupt)){
            Id128 incarnation{},store{},nonce{};if(!Broker::randomId(incarnation)||!Broker::randomId(store)||!Broker::randomId(nonce)){a->alive=false;failure=ConfigFailure::Unreadable;return {};}
            a->incarnation=incarnation;candidate=ConfigurationSnapshot{};candidate.storeInstance=store;candidate.storage=StorageState::Ready;candidate.revision=a->snapshot.revision;
            std::uint64_t session=0;for(unsigned i=0;i<8;++i)session|=std::uint64_t(nonce[i])<<(8*i);if(!session){a->alive=false;return {};}
            candidate.epochs.session=session;a->committedRevision=0;
        }
    }else if(m.verb==ConfigurationVerb::Consent){
        ++candidate.epochs.consent;auto &epoch=m.target==ConsentTarget::Model?candidate.epochs.modelConsent:candidate.epochs.webConsent;++epoch;
        auto receipt=m.receipt;receipt.epoch=epoch;if(!receipt.granted){receipt={};receipt.epoch=epoch;}
        (m.target==ConsentTarget::Model?candidate.modelConsent:candidate.webConsent)=std::move(receipt);
    }else if(m.verb==ConfigurationVerb::Mode)candidate.mode=m.mode;
    else if(m.verb==ConfigurationVerb::Profile){candidate.selectedProfileRef=m.profileRef;++candidate.epochs.entitlement;++candidate.epochs.consent;++candidate.epochs.modelConsent;candidate.modelConsent={};candidate.modelConsent.epoch=candidate.epochs.modelConsent;}
    else if(m.verb==ConfigurationVerb::Search){candidate.search=a->currentSearch;candidate.epochs.providerPolicy=a->currentSearch->providerPolicyEpoch;++candidate.epochs.consent;++candidate.epochs.webConsent;candidate.webConsent={};candidate.webConsent.epoch=candidate.epochs.webConsent;}
    if(candidate.search)candidate.search->webConsentEpoch=candidate.epochs.webConsent;
    if(candidate.mode==ModeChoice::Unchosen&&candidate.credential==CredentialState::Stored&&candidate.modelConsent.granted&&candidate.webConsent.granted)candidate.mode=ModeChoice::Automatic;
    if(!validSnapshot(candidate)){a->failureLatched=true;a->snapshot.storage=StorageState::IoUncertain;Detail::revokeReceipts(a->snapshot);return {};}
    a->snapshot.epochs=candidate.epochs;a->snapshot.storage=StorageState::IoUncertain;Detail::revokeReceipts(a->snapshot);a->pendingTicket=d->ticket;
    d->authority=a;d->candidate=std::move(candidate);d->committedRevision=a->committedRevision+1;d->verb=m.verb;d->secret=std::move(secret);failure=ConfigFailure::None;
    return std::unique_ptr<MutationTicket>(new MutationTicket(std::move(d)));
}
MutationResult ConfigurationController::finish(MutationTicket ticket,PublicationObservation observation) {
    auto a=authority_;std::lock_guard<std::mutex> lock(a->mutex);
    if(!ticket.data_||ticket.data_->authority.lock()!=a||!a->alive||a->pendingTicket!=ticket.data_->ticket)return {ConfigFailure::Stale,a->snapshot,observation.primaryError_};
    const auto &d=*ticket.data_;a->pendingTicket={};
    const bool success=observation.apiSuccess_&&!observation.primaryError_&&observation.attributed_&&observation.exactCandidate_&&observation.observed_&&*observation.observed_==d.candidate&&observation.committedRevision_==d.committedRevision;
    if(success){a->snapshot=d.candidate;a->observedRecord=d.candidate;a->committedRevision=d.committedRevision;a->failureLatched=false;return {ConfigFailure::None,a->snapshot,0};}
    const auto epochs=a->snapshot.epochs;const auto revision=a->snapshot.revision;
    if(observation.observed_&&validSnapshot(*observation.observed_)){a->snapshot=*observation.observed_;a->observedRecord=*observation.observed_;a->committedRevision=observation.committedRevision_;}
    a->snapshot.epochs=epochs;a->snapshot.revision=revision;a->failureLatched=true;a->snapshot.storage=StorageState::IoUncertain;Detail::revokeReceipts(a->snapshot);
    return {ConfigFailure::IoUncertain,a->snapshot,observation.primaryError_};
}
void ConfigurationController::invalidate(){auto a=authority_;std::lock_guard<std::mutex> lock(a->mutex);if(nonzero(a->pendingTicket)){a->failureLatched=true;a->snapshot.storage=StorageState::IoUncertain;}Detail::advance(*a);a->pendingTicket={};Detail::revokeReceipts(a->snapshot);}
void ConfigurationController::bindCurrentSearch(SearchBindingRef search,ConsentReceipt notice) {
    if(!validSearch(search)||!validReceipt(notice)||notice.profileRef!=GeneralProfile)return;
    auto a=authority_;std::lock_guard<std::mutex> lock(a->mutex);if(!a->alive||!Detail::advance(*a))return;
    a->currentSearch=search;a->searchNotice=std::move(notice);a->snapshot.epochs.providerPolicy=search.providerPolicyEpoch;
    if(a->snapshot.epochs.webConsent==UINT64_MAX||a->snapshot.epochs.consent==UINT64_MAX){a->alive=false;return;}
    ++a->snapshot.epochs.webConsent;++a->snapshot.epochs.consent;a->snapshot.webConsent={};a->snapshot.webConsent.epoch=a->snapshot.epochs.webConsent;a->snapshot.search.reset();a->pendingTicket={};
}
}
