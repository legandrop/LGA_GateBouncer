#include "ProviderEntitlementInternal.h"
#include "WindowsConfigurationStore.h"
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>

namespace Gate::Assistance::Configuration {
namespace {
using Bytes=std::vector<unsigned char>;
constexpr std::uint64_t LastUtc=253402300799;
struct Reader {
    const unsigned char *data=nullptr;
    std::size_t size=0,offset=0;
    bool take(std::size_t n,const unsigned char *&p) {
        if(n>size-offset)return false;
        p=data+offset;offset+=n;return true;
    }
    bool number(unsigned width,std::uint64_t &value) {
        const unsigned char *p=nullptr;if(!take(width,p))return false;
        value=0;for(unsigned i=0;i<width;++i)value|=std::uint64_t(p[i])<<(8*i);
        return true;
    }
    template<class T> bool array(T &value) {
        const unsigned char *p=nullptr;if(!take(value.size(),p))return false;
        std::copy_n(p,value.size(),value.begin());return true;
    }
    bool text(std::string &value) {
        std::uint64_t n=0;const unsigned char *p=nullptr;
        if(!number(2,n)||!n||n>48||!take(std::size_t(n),p))return false;
        value.assign(reinterpret_cast<const char *>(p),std::size_t(n));return true;
    }
    bool end() const {return offset==size;}
};
void number(Bytes &b,std::uint64_t value,unsigned width) {
    for(unsigned i=0;i<width;++i)b.push_back(static_cast<unsigned char>(value>>(8*i)));
}
template<class T> void append(Bytes &b,const T &value){b.insert(b.end(),value.begin(),value.end());}
void text(Bytes &b,const std::string &value){number(b,value.size(),2);append(b,value);}
Digest256 hash(const char *domain,const Bytes &b){return digest(domain,b.data(),b.size());}
bool reference(const std::string &value) {
    if(value.empty()||value.size()>48)return false;
    for(unsigned char c:value)if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||
        (c>='0'&&c<='9')||c=='_'||c=='.'||c=='/'||c==':'||c=='-'))return false;
    return true;
}
bool notice(Reader &r,ConsentReceipt &n) {
    std::uint64_t revision=0;
    if(!r.number(4,revision)||!revision||!r.array(n.noticeDigest)||!nonzero(n.noticeDigest)||
        !r.text(n.profileRef)||n.profileRef!=GeneralProfile||!r.array(n.destinationPolicyBinding)||
        !nonzero(n.destinationPolicyBinding))return false;
    n.granted=true;n.epoch=1;n.noticeRevision=std::uint32_t(revision);return true;
}
bool parse(const Bytes &bytes,Detail::ReviewArtifact &a) {
    if(bytes.size()<81||bytes.size()>2128||std::memcmp(bytes.data(),"GBPEV1\0\0",8))return false;
    Reader header{bytes.data()+8,8};std::uint64_t schema=0,signer=0,length=0;
    if(!header.number(2,schema)||schema!=1||!header.number(2,signer)||!signer||
        !header.number(4,length)||!length||length>2048||bytes.size()!=80+length)return false;
    a.signer=std::uint16_t(signer);
    Reader payload{bytes.data()+16,std::size_t(length)};
    for(unsigned expected=1;expected<=26;++expected) {
        std::uint64_t tag=0,n=0;const unsigned char *p=nullptr;
        if(!payload.number(2,tag)||tag!=expected||!payload.number(2,n)||!payload.take(std::size_t(n),p))return false;
        const unsigned widths[]={0,1,1,0,8,8,4,16,32,16,16,1,32,16,8,32,32,32,32,0,8,8,8,8,8,8,1};
        if(widths[tag]&&n!=widths[tag])return false;
        Reader field{p,std::size_t(n)};std::uint64_t v=0;
        switch(tag) {
        case 1:field.number(1,v);a.origin=std::uint8_t(v);break;
        case 2:field.number(1,v);a.source=std::uint8_t(v);break;
        case 3:a.policy.assign(reinterpret_cast<const char *>(p),std::size_t(n));field.offset=field.size;break;
        case 4:field.number(8,a.policyRevision);break;
        case 5:field.number(8,a.reviewRevision);break;
        case 6:field.number(4,v);a.pinGeneration=std::uint32_t(v);break;
        case 7:field.array(a.evidence);break;
        case 8:field.array(a.sourceDigest);break;
        case 9:field.array(a.account);break;
        case 10:field.array(a.credentialRef);break;
        case 11:field.number(1,v);a.subject=std::uint8_t(v);break;
        case 12:field.array(a.subjectBinding);break;
        case 13:field.array(a.store);break;
        case 14:field.number(8,a.credentialEpoch);break;
        case 15:field.array(a.destination);break;
        case 16:field.array(a.model);break;
        case 17:field.array(a.scope);break;
        case 18:field.array(a.quota);break;
        case 19:if(!notice(field,a.notice))return false;break;
        case 20:field.number(8,a.notBefore);break;
        case 21:field.number(8,a.notAfter);break;
        case 22:field.number(8,a.reviewedAt);break;
        case 23:field.number(8,a.nextReviewBy);break;
        case 24:field.number(8,a.revocation);break;
        case 25:field.number(8,a.policyReviewBy);break;
        case 26:field.number(1,v);if(v!=1)return false;break;
        }
        if(!field.end())return false;
    }
    if(!payload.end()||!reference(a.policy)||!a.policyRevision||!a.reviewRevision||!a.pinGeneration||
        !a.revocation||!nonzero(a.evidence)||!nonzero(a.sourceDigest)||!nonzero(a.destination)||
        !nonzero(a.model)||!nonzero(a.scope)||!nonzero(a.quota))return false;
    for(auto t:{a.notBefore,a.notAfter,a.reviewedAt,a.nextReviewBy,a.policyReviewBy})if(!t||t>LastUtc)return false;
    if(a.notBefore>a.reviewedAt||a.reviewedAt>=a.notAfter||a.reviewedAt>=a.nextReviewBy||a.reviewedAt>=a.policyReviewBy)return false;
    if(a.origin==1) {
        if(a.source!=1||a.subject||nonzero(a.account)||nonzero(a.credentialRef)||
            nonzero(a.subjectBinding)||nonzero(a.store)||a.credentialEpoch)return false;
    } else if(a.origin==2) {
        if((a.source!=2&&a.source!=3)||!nonzero(a.account)||!nonzero(a.store)||!a.credentialEpoch)return false;
        if(a.subject==1) {if(!nonzero(a.credentialRef)||!nonzero(a.subjectBinding))return false;}
        else if(a.subject==2) {if(nonzero(a.credentialRef)||nonzero(a.subjectBinding))return false;}
        else return false;
    } else return false;
    a.canonical.assign(bytes.begin(),bytes.end()-64);
    std::copy_n(bytes.end()-64,64,a.signature.begin());
    a.revision=hash("GB_PROVIDER_REVIEW_REVISION_1",a.canonical);
    return nonzero(a.revision);
}
struct Policy {
    std::string ref;std::uint64_t revision=0,notBefore=0,reviewBy=0,minReview=0,minRevocation=0;
    std::uint8_t origin=0,use=0;
    std::uint16_t signer=0;std::uint32_t pin=0;
    Digest256 destination{},model{},privacy{},quota{},scope{};
    ConsentReceipt notice;
};
bool policy(const Bytes &canonical,Policy &p) {
    Reader r{canonical.data(),canonical.size()};std::uint64_t origin=0,provider=0,use=0,audience=0,privacy=0,signer=0,pin=0;
    if(!r.text(p.ref)||!reference(p.ref)||!r.number(8,p.revision)||!p.revision||!r.number(1,origin)||
        (origin!=1&&origin!=2)||!r.number(1,provider)||provider!=1||!r.array(p.destination)||
        !r.array(p.model)||!r.number(1,use)||(use!=1&&use!=2)||!r.number(1,audience)||
        (audience!=1&&audience!=2)||!r.number(1,privacy)||(privacy!=1&&privacy!=2)||
        !r.array(p.privacy)||!r.array(p.quota)||!notice(r,p.notice)||!r.number(8,p.notBefore)||
        !r.number(8,p.reviewBy)||!r.number(8,p.minReview)||!r.number(8,p.minRevocation)||
        !r.number(2,signer)||!r.number(4,pin)||!r.end())return false;
    p.origin=std::uint8_t(origin);p.use=std::uint8_t(use);p.signer=std::uint16_t(signer);p.pin=std::uint32_t(pin);
    if(!p.notBefore||p.notBefore>=p.reviewBy||p.reviewBy>LastUtc||!p.minReview||!p.minRevocation||
        !signer||!pin||!nonzero(p.privacy)||!nonzero(p.quota)||p.notice.destinationPolicyBinding!=p.destination)return false;
    const auto fixed=Detail::nvidiaTrial();
    Bytes model;text(model,GeneralProfile);number(model,1,4);text(model,fixed.model);number(model,1,1);
    const unsigned char half[]={0,0,0,0,0,0,0xe0,0x3f};model.insert(model.end(),half,half+8);
    number(model,0,1);number(model,512,4);number(model,0,1);
    if(p.destination!=fixed.destination||p.model!=hash("GB_PROVIDER_MODEL_SCOPE_1",model))return false;
    p.scope=hash("GB_PROVIDER_POLICY_SCOPE_1",canonical);return nonzero(p.scope);
}
bool validNoticeBody(const std::string &body,const ConsentReceipt &notice) {
    if(body.empty()||body.size()>2048)return false;
    for(std::size_t i=0;i<body.size();) {
        const auto first=static_cast<unsigned char>(body[i++]);unsigned count=0;
        std::uint32_t scalar=first,minimum=0;
        if(first>=0xc2&&first<=0xdf){count=1;scalar=first&31;minimum=0x80;}
        else if(first>=0xe0&&first<=0xef){count=2;scalar=first&15;minimum=0x800;}
        else if(first>=0xf0&&first<=0xf4){count=3;scalar=first&7;minimum=0x10000;}
        else if(first>=0x80)return false;
        if(count>body.size()-i)return false;
        for(unsigned remaining=count;remaining;--remaining) {
            const auto next=static_cast<unsigned char>(body[i++]);
            if((next&0xc0)!=0x80)return false;
            scalar=(scalar<<6)|(next&63);
        }
        if(scalar<minimum||scalar>0x10ffff||(scalar>=0xd800&&scalar<=0xdfff)||scalar==0xfeff||
            (scalar<32&&scalar!=10)||(scalar>=0x7f&&scalar<=0x9f))return false;
    }
    return digest("GB_MODEL_NOTICE_1",reinterpret_cast<const unsigned char *>(body.data()),body.size())==notice.noticeDigest;
}
bool descriptorMatches(const ConsentReceipt &a,const ConsentReceipt &b) {
    return a.noticeRevision==b.noticeRevision&&a.noticeDigest==b.noticeDigest&&
        a.profileRef==b.profileRef&&a.destinationPolicyBinding==b.destinationPolicyBinding;
}
bool scalar(const unsigned char *p) {
    static const unsigned char order[]={0xff,0xff,0xff,0xff,0,0,0,0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51};
    bool nonZero=false;for(unsigned i=0;i<32;++i)nonZero|=p[i]!=0;
    return nonZero&&std::lexicographical_compare(p,p+32,order,order+32);
}
bool fixturePoint(const std::array<unsigned char,64> &xy) {
    const unsigned char generator[]={
        0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
        0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,
        0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
        0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5};
    return !std::memcmp(xy.data(),generator,64);
}
struct PublicKey {
    BCRYPT_ALG_HANDLE algorithm=nullptr;BCRYPT_KEY_HANDLE key=nullptr;
    PublicKey()=default;
    PublicKey(const PublicKey&)=delete;
    PublicKey &operator=(const PublicKey&)=delete;
    ~PublicKey() {
        if(key)BCryptDestroyKey(key);
        if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);
    }
    bool import(const std::array<unsigned char,64> &xy) {
        if(!nonzero(xy)||BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_ECDSA_P256_ALGORITHM,nullptr,0)<0)return false;
        Bytes blob;number(blob,BCRYPT_ECDSA_PUBLIC_P256_MAGIC,4);number(blob,32,4);append(blob,xy);
        return BCryptImportKeyPair(algorithm,nullptr,BCRYPT_ECCPUBLIC_BLOB,&key,blob.data(),ULONG(blob.size()),0)>=0;
    }
};
bool signature(const std::array<unsigned char,64> &xy,const Detail::ReviewArtifact &a) {
    if(!scalar(a.signature.data())||!scalar(a.signature.data()+32))return false;
    PublicKey key;if(!key.import(xy))return false;
    auto hashed=hash("GB_PROVIDER_REVIEW_1",a.canonical);auto raw=a.signature;
    return BCryptVerifySignature(key.key,nullptr,hashed.data(),ULONG(hashed.size()),raw.data(),ULONG(raw.size()),0)>=0;
}
std::uint64_t utcNow() {
    return std::uint64_t(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}
std::string key(const Detail::ReviewArtifact &a,unsigned kind) {
    Bytes bytes;number(bytes,1,1);number(bytes,a.origin,1);text(bytes,a.policy);
    if(kind==1)append(bytes,a.evidence);
    if(kind)append(bytes,a.account);
    return {reinterpret_cast<const char *>(bytes.data()),bytes.size()};
}
Detail::ProviderRecord provider(const Detail::ReviewArtifact &a,const Policy &row,const Detail::AuthorityImage &image,
    std::uint64_t now,EntitlementReviewResult &result) {
    auto p=Detail::nvidiaTrial();p.notice=row.notice;p.destination=row.destination;
    p.evidenceId=a.evidence;p.evidenceRevision=a.revision;
    p.notBefore=std::max(a.notBefore,row.notBefore);p.notAfter=std::min({a.notAfter,a.nextReviewBy,row.reviewBy});
    result.recognized=true;result.evidenceRevision=a.revision;
    if(a.origin==2&&a.subject==2) {
        result.cause=ReviewCause::CredentialSubjectUnverified;p.evidence=EvidenceState::Missing;return p;
    }
    p.accountScope=a.account;
    if(a.origin==1) {
        Bytes b;number(b,a.origin,1);text(b,a.policy);number(b,a.policyRevision,8);append(b,a.evidence);append(b,a.scope);
        append(b,image.snapshot.storeInstance);number(b,image.snapshot.epochs.credential,8);append(b,image.incarnation);append(b,image.connection);
        const auto domain=hash("GB_PROVIDER_PUBLIC_AUTH_DOMAIN_1",b);std::copy_n(domain.begin(),16,p.accountScope.begin());
    }
    Bytes b;append(b,a.revision);append(b,a.scope);append(b,a.sourceDigest);append(b,a.account);append(b,a.subjectBinding);
    append(b,p.accountScope);append(b,image.snapshot.storeInstance);number(b,image.snapshot.epochs.credential,8);append(b,image.incarnation);append(b,image.connection);
    p.scope=hash("GB_PROVIDER_RUNTIME_SCOPE_1",b);
    if(!nonzero(p.accountScope)||!nonzero(p.scope)) {result.recognized=false;result.cause=ReviewCause::ScopeMismatch;return p;}
    if(now<a.reviewedAt||now<p.notBefore||now>=p.notAfter) {result.cause=ReviewCause::ReviewExpired;p.evidence=EvidenceState::Expired;}
    else if(row.use==1) {result.decision=ReviewDecision::Restricted;result.cause=ReviewCause::TrialOnly;p.evidence=EvidenceState::Restricted;}
    else {result.decision=ReviewDecision::Applicable;result.cause=ReviewCause::EvidenceApplicable;p.evidence=EvidenceState::Applicable;}
    return p;
}
}
namespace Detail {
bool entitlementFloorsCurrent(const EntitlementState &state,const ReviewedSelection &selection) {
    const auto &a=selection.artifact;
    if(a.reviewRevision<selection.minimumReview||a.revocation<selection.minimumRevocation)return false;
    const auto p=state.policies.find(key(a,0));
    if(p!=state.policies.end()&&a.policyRevision<p->second.policy)return false;
    const auto account=state.accounts.find(key(a,2));
    if(account!=state.accounts.end()&&a.revocation<account->second.revocation)return false;
    const auto e=state.evidences.find(key(a,1));
    if(e!=state.evidences.end()) {
        if(a.reviewRevision<e->second.review||a.revocation<e->second.revocation)return false;
        if(a.reviewRevision==e->second.review&&a.canonical!=e->second.canonical)return false;
    }
    return true;
}
bool advanceEntitlement(Authority &a) {
    auto &s=a.snapshot;const auto maximum=std::numeric_limits<std::uint64_t>::max();
    if(s.revision==maximum||s.epochs.entitlement==maximum||s.epochs.retrieval==maximum||a.transitionBarrier==maximum) {
        a.alive=false;return false;
    }
    ++s.revision;++s.epochs.entitlement;++s.epochs.retrieval;++a.transitionBarrier;
    a.capability={};a.capabilityExpiry=0;return true;
}
void rememberEntitlement(EntitlementState &state,const ReviewedSelection &selection,const AuthorityImage &image) {
    const auto &a=selection.artifact;
    auto &p=state.policies[key(a,0)];p.policy=std::max(p.policy,a.policyRevision);
    auto &account=state.accounts[key(a,2)];account.revocation=std::max(account.revocation,a.revocation);
    auto &e=state.evidences[key(a,1)];e.review=a.reviewRevision;e.revocation=std::max(e.revocation,a.revocation);e.canonical=a.canonical;
    ++state.floorGeneration;state.publishedImage=image;state.publishedReview=a.revision;
}
}
struct ProviderEntitlementVerifier::State {
    std::shared_ptr<WindowsConfigurationStore> store;
    std::shared_ptr<ConfigurationController> controller;
    std::function<std::uint64_t()> clock=utcNow;
    std::function<void()> duringReview,afterPublication;
};
std::shared_ptr<const ReviewedProviderCatalog> ReviewedProviderCatalog::currentProduct() {
    // Sin pin ni oferta revisada adquiridos: falta configuracion de confianza.
    // El adaptador consume filas/pins autenticos mediante ProductProviderCatalog.
    static const auto catalog=std::shared_ptr<const ReviewedProviderCatalog>(new ReviewedProviderCatalog);
    return catalog;
}
ProviderEntitlementVerifier::ProviderEntitlementVerifier(std::shared_ptr<State> state):state_(std::move(state)){}
ProviderEntitlementVerifier::~ProviderEntitlementVerifier()=default;
void ProviderEntitlementVerifier::setChangedCallback(std::function<void()> callback) {
    state_->afterPublication=std::move(callback);
}
std::shared_ptr<const ReviewedProviderCatalog> ProductProviderCatalog::fromReviewedBuild(
    std::uint64_t generation,std::vector<Pin> pins,std::vector<Row> rows,std::vector<Revocation> revocations) {
    if(!generation||pins.empty()||pins.size()>8||rows.empty()||rows.size()>64||revocations.size()>256)return {};
    std::map<std::pair<std::uint16_t,std::uint32_t>,const Pin *> known;
    for(const auto &pin:pins) {
        if(!pin.signer||pin.signer==60000||fixturePoint(pin.xy)||!nonzero(pin.xy)||!pin.generation||
            !pin.minimumGeneration||pin.generation<pin.minimumGeneration||!pin.notBefore||
            pin.notBefore>=pin.notAfter||pin.notAfter>LastUtc||pin.policies.empty()||pin.policies.size()>64||
            !known.emplace(std::make_pair(pin.signer,pin.generation),&pin).second)return {};
        for(const auto &scope:pin.policies)if((scope.first!=1&&scope.first!=2)||!reference(scope.second))return {};
        PublicKey key;if(!key.import(pin.xy))return {};
    }
    std::map<std::pair<unsigned,std::string>,bool> policies;
    for(const auto &row:rows) {
        Policy parsed;if(!policy(row.canonical,parsed)||!validNoticeBody(row.noticeBody,parsed.notice)||
            !policies.emplace(std::make_pair(parsed.origin,parsed.ref),true).second)return {};
        const auto found=known.find({parsed.signer,parsed.pin});if(found==known.end())return {};
        const auto &pin=*found->second;
        if(parsed.reviewBy>pin.notAfter||std::find(pin.policies.begin(),pin.policies.end(),
            std::make_pair(parsed.origin,parsed.ref))==pin.policies.end())return {};
        if(parsed.origin==1&&(!nonzero(row.publicEvidence)||!nonzero(row.publicSource)))return {};
        if(parsed.origin==2&&(nonzero(row.publicEvidence)||nonzero(row.publicSource)))return {};
    }
    for(const auto &r:revocations)if((r.origin!=1&&r.origin!=2)||!reference(r.policy)||!nonzero(r.evidence)||
        (r.origin==1?nonzero(r.account):!nonzero(r.account))||!policies.count({r.origin,r.policy}))return {};
    auto catalog=std::shared_ptr<ReviewedProviderCatalog>(new ReviewedProviderCatalog);
    catalog->generation_=generation;catalog->pins_=std::move(pins);catalog->rows_=std::move(rows);
    catalog->revocations_=std::move(revocations);return catalog;
}
std::unique_ptr<ProviderEntitlementVerifier> ProviderEntitlementVerifier::forBroker(
    std::shared_ptr<WindowsConfigurationStore> store,std::shared_ptr<ConfigurationController> controller) {
    if(!store||!controller)return {};
    auto state=std::make_shared<State>();state->store=std::move(store);state->controller=std::move(controller);
    const auto a=state->controller->authority_;
    {std::lock_guard<std::mutex> lock(a->mutex);
        if(!a->entitlement) {a->entitlement=std::make_shared<Detail::EntitlementState>();a->entitlement->catalog=ReviewedProviderCatalog::currentProduct();}}
    return std::unique_ptr<ProviderEntitlementVerifier>(new ProviderEntitlementVerifier(std::move(state)));
}
bool ProviderEntitlementVerifier::replaceCatalog(std::shared_ptr<const ReviewedProviderCatalog> catalog) {
    const auto state=state_;if(!catalog||!catalog->generation_)return false;
    auto context=state->store->captureEntitlementContext(*state->controller,state->store);
    if(!context||!state->store->replaceEntitlementCatalog(*state->controller,std::move(*context),std::move(catalog)))return false;
    try {if(state->afterPublication)state->afterPublication();}catch(...) {}
    return true;
}
ModelDisclosure ProductPublicDisclosure::lookup(const ConsentReceipt &expected,EvidenceState evidence) {
    return lookupIn(ReviewedProviderCatalog::currentProduct(),expected,evidence);
}
ModelDisclosure ProductPublicDisclosure::lookupIn(const std::shared_ptr<const ReviewedProviderCatalog> &catalog,
    const ConsentReceipt &expected,EvidenceState evidence) {
    ModelDisclosure result;result.evidence=evidence;
    auto descriptor=expected;descriptor.granted=false;descriptor.epoch=0;
    if(!descriptor.noticeRevision||!nonzero(descriptor.noticeDigest)||descriptor.profileRef.empty()||
        !nonzero(descriptor.destinationPolicyBinding)||!validReceipt(descriptor,true))return result;
    if(evidence==EvidenceState::Missing||evidence==EvidenceState::Conflict||std::uint8_t(evidence)>4) {
        result.cause=DisclosureCause::NotFound;return result;
    }
    if(evidence==EvidenceState::Restricted&&descriptorMatches(descriptor,Detail::nvidiaTrial().notice)) {
        result.source=DisclosureSource::TrialRestricted;result.cause=DisclosureCause::Available;
        result.body=Detail::trialModelNoticeBody();result.descriptor=std::move(descriptor);return result;
    }
    if(!catalog||catalog->pins_.empty()||catalog->rows_.empty()) {
        result.cause=DisclosureCause::CatalogNotConfigured;return result;
    }
    const auto now=utcNow();bool matched=false;
    for(const auto &row:catalog->rows_) {
        Policy parsed;if(!policy(row.canonical,parsed)||!descriptorMatches(descriptor,parsed.notice))continue;
        matched=true;
        if(now<parsed.notBefore||now>=parsed.reviewBy)continue;
        bool currentPin=false;
        for(const auto &pin:catalog->pins_)if(pin.signer==parsed.signer&&pin.generation==parsed.pin&&!pin.revoked&&
            now>=pin.notBefore&&now<pin.notAfter&&
            pin.generation>=pin.minimumGeneration&&parsed.reviewBy<=pin.notAfter&&
            std::find(pin.policies.begin(),pin.policies.end(),std::make_pair(parsed.origin,parsed.ref))!=pin.policies.end())currentPin=true;
        if(!currentPin)continue;
        bool revoked=false;
        for(const auto &revocation:catalog->revocations_)if(revocation.revoked&&revocation.origin==parsed.origin&&
            revocation.policy==parsed.ref&&revocation.evidence==row.publicEvidence)revoked=true;
        if(revoked)continue;
        if(!validNoticeBody(row.noticeBody,descriptor)) {result=ModelDisclosure{};result.evidence=evidence;result.cause=DisclosureCause::BodyDigestMismatch;return result;}
        if(!result.body.empty()&&result.body!=row.noticeBody) {result=ModelDisclosure{};result.evidence=evidence;result.cause=DisclosureCause::Ambiguous;return result;}
        result.body=row.noticeBody;
    }
    if(result.body.empty()){result.cause=matched?DisclosureCause::NotFound:DisclosureCause::DescriptorMismatch;return result;}
    result.source=DisclosureSource::ReviewedCatalog;result.cause=DisclosureCause::Available;
    result.descriptor=std::move(descriptor);return result;
}
ModelDisclosure ProviderEntitlementVerifier::modelDisclosure() const {
    const auto state=state_;const auto a=state->controller->authority_;
    Detail::AuthorityImage before;std::shared_ptr<Detail::EntitlementState> entitlement;
    std::shared_ptr<const ReviewedProviderCatalog> catalog;std::uint64_t floor=0;
    {std::lock_guard<std::mutex> lock(a->mutex);before=Detail::image(*a);entitlement=a->entitlement;
        if(entitlement){catalog=entitlement->catalog;floor=entitlement->floorGeneration;}}
    ModelDisclosure result;
    if(before.alive&&!before.latched)result=ProductPublicDisclosure::lookupIn(catalog,before.provider.notice,before.provider.evidence);
    {std::lock_guard<std::mutex> lock(a->mutex);
        if(!(Detail::image(*a)==before)||a->entitlement!=entitlement||
            (entitlement&&(entitlement->catalog!=catalog||entitlement->floorGeneration!=floor))) {
            result=ModelDisclosure{};result.cause=DisclosureCause::ChangedDuringRead;return result;
        }}
    result.viewRevision=before.snapshot.revision;return result;
}
EntitlementReviewResult ProviderEntitlementVerifier::review(const Bytes &envelope,bool explicitlySelect) {
    const auto state=state_;EntitlementReviewResult result;Detail::ReviewArtifact artifact;
    if(!parse(envelope,artifact)) {result.cause=ReviewCause::Malformed;return result;}
    auto context=state->store->captureEntitlementContext(*state->controller,state->store);
    if(!context) {result.cause=ReviewCause::LocalPublicationChanged;return result;}
    const auto a=state->controller->authority_;std::shared_ptr<const ReviewedProviderCatalog> catalog;
    {std::lock_guard<std::mutex> lock(a->mutex);catalog=a->entitlement->catalog;}
    if(catalog->pins_.empty()||catalog->rows_.empty())return result;
    Policy row;const ReviewedProviderCatalog::Row *trustedRow=nullptr;
    for(const auto &candidate:catalog->rows_) {
        Policy parsed;if(!policy(candidate.canonical,parsed))continue;
        if(parsed.ref==artifact.policy&&parsed.origin==artifact.origin) {
            if(trustedRow) {result.cause=ReviewCause::UnknownPolicy;return result;}
            row=std::move(parsed);trustedRow=&candidate;
        }
    }
    if(!trustedRow||row.revision!=artifact.policyRevision) {result.cause=ReviewCause::UnknownPolicy;return result;}
    if(row.scope!=artifact.scope||row.destination!=artifact.destination||row.model!=artifact.model||row.quota!=artifact.quota||
        !(row.notice==artifact.notice)||row.reviewBy!=artifact.policyReviewBy||row.notBefore>artifact.reviewedAt||
        row.signer!=artifact.signer||row.pin!=artifact.pinGeneration) {result.cause=ReviewCause::ScopeMismatch;return result;}
    if(artifact.origin==1&&(trustedRow->publicEvidence!=artifact.evidence||trustedRow->publicSource!=artifact.sourceDigest)) {
        result.cause=ReviewCause::ScopeMismatch;return result;
    }
    const auto now=state->clock();const ReviewedProviderCatalog::Pin *pin=nullptr;
    for(const auto &candidate:catalog->pins_)if(candidate.signer==artifact.signer&&candidate.generation==artifact.pinGeneration) {
        if(pin) {result.cause=ReviewCause::PinRejected;return result;}pin=&candidate;
    }
    if(!pin||pin->revoked||!pin->generation||pin->generation<pin->minimumGeneration||
        !pin->notBefore||pin->notAfter>LastUtc||now<pin->notBefore||now>=pin->notAfter||row.reviewBy>pin->notAfter||
        std::find(pin->policies.begin(),pin->policies.end(),std::make_pair(artifact.origin,artifact.policy))==pin->policies.end()) {
        result.cause=ReviewCause::PinRejected;return result;
    }
    if(!catalog->fixture_&&(artifact.signer==60000||fixturePoint(pin->xy))) {result.cause=ReviewCause::PinRejected;return result;}
    if(!signature(pin->xy,artifact)) {result.cause=ReviewCause::SignatureRejected;return result;}
    if(artifact.origin==2) {
        if(artifact.store!=context->image.snapshot.storeInstance||artifact.credentialEpoch!=context->image.snapshot.epochs.credential) {
            result.cause=ReviewCause::CredentialBindingChanged;return result;
        }
        if(artifact.subject==1) {
            Bytes subject;append(subject,artifact.sourceDigest);append(subject,artifact.account);append(subject,artifact.credentialRef);
            append(subject,artifact.store);number(subject,artifact.credentialEpoch,8);
            if(hash("GB_PROVIDER_SUBJECT_1",subject)!=artifact.subjectBinding) {result.cause=ReviewCause::ScopeMismatch;return result;}
        }
    }
    Detail::ReviewedSelection selection;selection.artifact=std::move(artifact);selection.catalog=catalog;
    selection.minimumReview=row.minReview;selection.minimumRevocation=row.minRevocation;
    for(const auto &revocation:catalog->revocations_)if(revocation.origin==selection.artifact.origin&&
        revocation.policy==selection.artifact.policy&&revocation.evidence==selection.artifact.evidence&&revocation.account==selection.artifact.account) {
        if(revocation.revoked) {result.cause=ReviewCause::Revoked;return result;}
        selection.minimumReview=std::max(selection.minimumReview,revocation.minimumReview);
        selection.minimumRevocation=std::max(selection.minimumRevocation,revocation.minimumRevocation);
    }
    try {if(state->duringReview)state->duringReview();}catch(...) {result.cause=ReviewCause::LocalPublicationChanged;return result;}
    selection.checkedUtc=state->clock();selection.checkedTick=GetTickCount64();
    selection.provider=provider(selection.artifact,row,context->image,selection.checkedUtc,result);selection.result=result;
    {std::lock_guard<std::mutex> lock(a->mutex);
        if(a->entitlement->catalog!=catalog||!Detail::entitlementFloorsCurrent(*a->entitlement,selection)) {
            result.recognized=false;result.decision=ReviewDecision::PendingReview;result.cause=ReviewCause::Rollback;return result;
        }}
    if(!result.recognized)return result;
    result=state->store->finishEntitlementReview(*state->controller,std::move(*context),std::move(selection),explicitlySelect);
    // Una notificacion fallida no borra el hecho de publicacion ya observado.
    try {if(result.published&&state->afterPublication)state->afterPublication();}catch(...) {}
    return result;
}
}
