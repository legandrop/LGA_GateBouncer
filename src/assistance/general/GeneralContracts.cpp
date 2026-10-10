#include "GeneralContracts.h"
#include "GeneralPayload.h"
#include "InferenceEncoding.h"
#include <QCryptographicHash>
#include <QStringDecoder>
#include "websearch/WebSearch.h"
#include <algorithm>
#include <cstring>
#include <tuple>
namespace Gate::Assistance::General {
namespace {
template<class T> bool nonzero(const T& b) { return std::any_of(b.begin(),b.end(),[](auto c){return c!=0;}); }
void number(std::string& out,std::uint64_t n,unsigned width) { for(unsigned i=0;i<width;++i)out.push_back(char(n>>(8*i))); }
void bytes(std::string& out,const void* p,std::size_t n) { out.append(static_cast<const char*>(p),n); }
void text(std::string& out,std::string_view s) { number(out,s.size(),2);out.append(s); }
Digest256 digest(std::string_view domain,std::string_view body) {
    QCryptographicHash h(QCryptographicHash::Sha256); h.addData(QByteArrayView(domain.data(),qsizetype(domain.size())));
    const char zero=0;h.addData(QByteArrayView(&zero,1));h.addData(QByteArrayView(body.data(),qsizetype(body.size())));
    Digest256 result{};const auto b=h.result();std::memcpy(result.data(),b.data(),32);return result;
}
bool uuid(std::string_view s) {
    if(s.size()!=38||s.front()!='{'||s.back()!='}')return false;
    for(std::size_t i=1;i<37;++i)if(i==9||i==14||i==19||i==24){if(s[i]!='-')return false;}
    else if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')||(s[i]>='A'&&s[i]<='F')))return false;
    return true;
}
}
bool FullBinding::operator==(const FullBinding& b) const {
    return std::tie(requestId,applicationToken,snapshotRevision,serviceEpoch,sessionEpoch,retrievalEpoch,
        providerPolicyEpoch,credentialEpoch,modelConsentEpoch,webConsentEpoch,generation,approvalEpoch,
        entitlementPolicyEpoch,localSnapshotToken,localSnapshotGeneration,provider,providerInstance,
        providerConfiguration,publicApprovalDigest,profileRevision)==
        std::tie(b.requestId,b.applicationToken,b.snapshotRevision,b.serviceEpoch,b.sessionEpoch,b.retrievalEpoch,
        b.providerPolicyEpoch,b.credentialEpoch,b.modelConsentEpoch,b.webConsentEpoch,b.generation,b.approvalEpoch,
        b.entitlementPolicyEpoch,b.localSnapshotToken,b.localSnapshotGeneration,b.provider,b.providerInstance,
        b.providerConfiguration,b.publicApprovalDigest,b.profileRevision);
}
bool Destination::operator==(const Destination& d) const {return std::tie(address,port,protocol,observedAtMs)==std::tie(d.address,d.port,d.protocol,d.observedAtMs);}
bool validDestination(const Destination& d,bool external) {
    namespace Web=gatebouncer::websearch;
    const auto canonical=Web::canonicalAddress(QString::fromUtf8(d.address));
    return d.address.size()<=45&&canonical&&canonical->toStdString()==d.address&&(d.protocol==6||d.protocol==17)&&d.observedAtMs&&d.observedAtMs<=std::uint64_t(INT64_MAX)&&
        (!external||Web::publicDestination({*canonical,d.port,d.protocol,d.observedAtMs}));
}
bool PublicFields::operator==(const PublicFields& b) const { return std::tie(product,publisher,query,destination)==std::tie(b.product,b.publisher,b.query,b.destination); }
bool safeText(std::string_view s,std::size_t cap,bool empty) {
    if(s.size()>cap||(!empty&&s.empty())||s.find('\0')!=s.npos)return false;
    QStringDecoder decoder(QStringDecoder::Utf8);const QString t=decoder(QByteArrayView(s.data(),qsizetype(s.size())));
    if(decoder.hasError())return false;
    for(auto c:t)if(c.category()==QChar::Other_Control||c.category()==QChar::Other_Format||c.isSurrogate()||c.unicode()==0x2028||c.unicode()==0x2029)return false;
    return true;
}
bool validBinding(const FullBinding& b,bool pending) {
    const std::uint64_t epochs[]={b.snapshotRevision,b.serviceEpoch,b.sessionEpoch,b.retrievalEpoch,b.providerPolicyEpoch,
        b.credentialEpoch,b.modelConsentEpoch,b.webConsentEpoch,b.generation,b.entitlementPolicyEpoch,b.localSnapshotGeneration};
    return safeText(b.requestId,128)&&nonzero(b.applicationToken)&&nonzero(b.localSnapshotToken)&&
        std::all_of(std::begin(epochs),std::end(epochs),[](auto n){return n!=0;})&&uuid(b.providerInstance)&&
        nonzero(b.providerConfiguration)&&b.profileRevision==2&&(b.provider==Provider::MwmblV2||b.provider==Provider::SearXng)&&
        (pending?(b.approvalEpoch==0&&!nonzero(b.publicApprovalDigest)):(b.approvalEpoch!=0&&nonzero(b.publicApprovalDigest)));
}
bool validPublicFields(const PublicFields& p) {
    auto name=[](const std::string& s){return safeText(s,96)&&!QString::fromUtf8(s).front().isSpace()&&!QString::fromUtf8(s).back().isSpace();};
    return name(p.product)&&(!p.publisher||name(*p.publisher))&&p.query==p.product+(p.publisher?" "+*p.publisher:"")&&
        gatebouncer::websearch::validPublicQuery(QString::fromUtf8(p.query))&&(!p.destination||validDestination(*p.destination,true));
}
std::string canonicalBinding(const FullBinding& b) {
    std::string out;out.reserve(367);text(out,b.requestId);bytes(out,b.applicationToken.data(),16);
    for(auto n:{b.snapshotRevision,b.serviceEpoch,b.sessionEpoch,b.retrievalEpoch,b.providerPolicyEpoch,b.credentialEpoch,
        b.modelConsentEpoch,b.webConsentEpoch,b.generation,b.approvalEpoch,b.entitlementPolicyEpoch})number(out,n,8);
    bytes(out,b.localSnapshotToken.data(),16);number(out,b.localSnapshotGeneration,8);number(out,std::uint8_t(b.provider),1);
    text(out,b.providerInstance);bytes(out,b.providerConfiguration.data(),32);bytes(out,b.publicApprovalDigest.data(),32);number(out,b.profileRevision,4);return out;
}
Digest256 FullBinding::canonicalDigest() const { return digest("GB_GENERAL_BINDING_1",canonicalBinding(*this)); }
Digest256 approvalDigest(const PublicFields& p,std::uint64_t epoch) {
    if(!validPublicFields(p)||!epoch)return {};
    std::string out;out.reserve(400);text(out,p.product);number(out,p.publisher?1:0,1);if(p.publisher)text(out,*p.publisher);text(out,p.query);number(out,epoch,8);
    number(out,p.destination?1:0,1);if(p.destination){text(out,p.destination->address);number(out,p.destination->port,2);
        number(out,p.destination->protocol,1);number(out,p.destination->observedAtMs,8);}
    return digest("GB_GENERAL_PUBLIC_APPROVAL_2",out);
}
ApprovalRecord::ApprovalRecord(FullBinding b,PublicFields p,Id128 connection,Id128 correlation,std::weak_ptr<const void> owner,std::function<bool()> current):
    binding_(std::move(b)),fields_(std::move(p)),connection_(connection),correlation_(correlation),owner_(std::move(owner)),current_(std::move(current)){}
bool ApprovalRecord::isCurrent() const {const auto live=owner_.lock();return live&&current_&&current_();}
View makeView(const Result& r) {
    View v;v.identityNotice="This executable's identity is unverified. Public names and offline signatures do not establish safety.";
    v.providerNotice=r.binding.provider==Provider::MwmblV2?"Mwmbl snippets; public index and third-party sources. Page update dates are unknown.":
        "SearXNG operator and search-engine snippets. Page update dates are unknown.";
    v.uncertainty="Public snippets are untrusted and may be incomplete or unrelated to this file.";
    if(r.failure==Failure::SearchRejected)v.providerNotice+=" Search could not start. Review the approved query and search settings.";
    else if(r.state==State::Uncertain)v.providerNotice+=" The model request outcome is uncertain; no retry was made.";
    else if(r.state!=State::Evidence)v.providerNotice+=" No current grounded explanation is available.";
    const bool citationsValid=GeneralPayloadBuilder::citationsJson(r.citations).has_value();
    if(citationsValid)v.citations=r.citations;
    if(citationsValid)for(const auto& c:r.citations)if(c.kind==1)v.networkOperator="Registration record: "+c.snippet;
    if(r.state==State::Evidence&&r.failure==Failure::None&&r.observedHttpStatus==200&&validBinding(r.binding)&&
        !r.citations.empty()&&citationsValid&&r.inference&&Detail::inferenceJson(*r.inference,r.citations)){
        v.purpose=r.inference->purpose;v.networkReason=r.inference->networkReason;v.uncertainty+=" "+r.inference->caution;v.sourceIds=r.inference->sourceIds;
        v.service=r.inference->service;v.impact=r.inference->impact;v.advice=r.inference->advice;
    }
    return v;
}
}
