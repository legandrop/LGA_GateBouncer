#include "PendingPresentationContext.h"
#include "broker/BrokerWire.h"
#include "GeneralWire.h"
#include <QUuid>
#include <algorithm>
#include <cstring>
namespace Gate::Assistance::General {
namespace {
bool nonzero(const Id128& id){return std::any_of(id.begin(),id.end(),[](auto v){return v!=0;});}
Id128 idAt(const QByteArray& b,int offset){Id128 id{};std::memcpy(id.data(),b.constData()+offset,16);return id;}
bool header(const QByteArray& b,int length){return b.size()==length&&Broker::number(b.left(2))==1&&Broker::number(b.mid(2,2))==0;}
void addId(QByteArray& b,const Id128& id){b.append(reinterpret_cast<const char*>(id.data()),16);}
}
bool PendingServiceContext::operator==(const PendingServiceContext& o) const {
    return serviceEpoch==o.serviceEpoch&&boot==o.boot&&engineContext==o.engineContext&&engineBindingGeneration==o.engineBindingGeneration;
}
bool validPendingService(const PendingServiceContext& s){return nonzero(s.serviceEpoch)&&nonzero(s.boot)&&nonzero(s.engineContext)&&s.engineBindingGeneration;}
bool validLocalFilePresentation(const LocalFilePresentation& f){
    return f.size<=256ULL*1024*1024&&f.modifiedAtMs<=253402300799999ULL&&f.checkedAtMs&&f.checkedAtMs<=253402300799999ULL&&
        unsigned(f.signature)<=unsigned(LocalSignatureStatus::Cancelled)&&safeText(f.publisher,1024,true)&&
        (f.signature==LocalSignatureStatus::VerifiedOffline||f.publisher.empty());
}
std::optional<Id128> pendingQuery(const QByteArray& b){if(!header(b,20))return {};auto id=idAt(b,4);return nonzero(id)?std::optional<Id128>(id):std::nullopt;}
std::optional<QByteArray> pendingQueryBytes(const Id128& id){if(!nonzero(id))return {};auto b=Broker::integer(1,2)+Broker::integer(0,2);addId(b,id);return b;}
std::optional<PendingPresentationContext> pendingPresentationContext(const QByteArray& b){
    const auto version=Broker::number(b.left(2));
    if(b.size()<141||b.size()>1250||(version!=2&&version!=3)||Broker::number(b.mid(2,2))!=0)return {};
    PendingServiceContext s{idAt(b,4),idAt(b,20),idAt(b,36),Broker::number(b.mid(52,8))};
    const auto request=idAt(b,60),selector=idAt(b,76),token=idAt(b,116);
    const auto revision=Broker::number(b.mid(92,8)),selectorRevision=Broker::number(b.mid(100,8)),
        profile=Broker::number(b.mid(108,8)),generation=Broker::number(b.mid(132,8));
    if(!validPendingService(s)||!nonzero(request)||!nonzero(selector)||!nonzero(token)||!revision||!selectorRevision||!profile||!generation)return {};
    const auto presence=Broker::number(b.mid(140,1));std::optional<Destination> destination;qsizetype end=141;
    if(presence>1)return {};
    if(presence){
        if(b.size()<153)return {};const auto length=Broker::number(b.mid(141,1));
        if(!length||length>45||b.size()<153+qsizetype(length))return {};
        Destination d{b.mid(142,length).toStdString(),std::uint16_t(Broker::number(b.mid(142+length,2))),
            std::uint8_t(Broker::number(b.mid(144+length,1))),Broker::number(b.mid(145+length,8))};
        if(!validDestination(d))return {};destination=std::move(d);end=153+qsizetype(length);
    }
    std::optional<LocalFilePresentation> localFile;
    if(version==3){
        if(b.size()<end+1)return {};const auto present=Broker::number(b.mid(end,1));++end;
        if(present>1)return {};
        if(present){
            if(b.size()<end+27)return {};
            LocalFilePresentation f{Broker::number(b.mid(end,8)),Broker::number(b.mid(end+8,8)),
                Broker::number(b.mid(end+16,8)),LocalSignatureStatus(Broker::number(b.mid(end+24,1))),{}};
            const auto length=Broker::number(b.mid(end+25,2));end+=27;
            if(length>1024||b.size()!=end+qsizetype(length))return {};
            f.publisher=b.mid(end,length).toStdString();end+=qsizetype(length);
            if(!validLocalFilePresentation(f))return {};localFile=std::move(f);
        }
    }
    if(b.size()!=end)return {};
    return PendingPresentationContext(s,request,selector,revision,selectorRevision,profile,token,generation,
        std::move(destination),std::move(localFile),std::uint16_t(version));
}
std::optional<QByteArray> pendingPresentationBytes(const PendingPresentationContext& p){
    if((p.presentationVersion()!=2&&p.presentationVersion()!=3)||(p.presentationVersion()==2&&p.localFile()))return {};
    auto b=Broker::integer(p.presentationVersion(),2)+Broker::integer(0,2);const auto &s=p.service();
    addId(b,s.serviceEpoch);addId(b,s.boot);addId(b,s.engineContext);b+=Broker::integer(s.engineBindingGeneration,8);
    addId(b,p.request());addId(b,p.selector());b+=Broker::integer(p.requestRevision(),8);
    b+=Broker::integer(p.selectorRevision(),8);b+=Broker::integer(p.profileGeneration(),8);
    addId(b,p.snapshotToken());b+=Broker::integer(p.snapshotGeneration(),8);
    b+=Broker::integer(p.destination()?1:0,1);
    if(p.destination()){const auto& d=*p.destination();if(!validDestination(d))return {};
        b+=Broker::integer(d.address.size(),1);b+=QByteArray::fromStdString(d.address);b+=Broker::integer(d.port,2);
        b+=Broker::integer(d.protocol,1);b+=Broker::integer(d.observedAtMs,8);}
    if(p.presentationVersion()==3){
        b+=Broker::integer(p.localFile()?1:0,1);
        if(p.localFile()){const auto& f=*p.localFile();if(!validLocalFilePresentation(f))return {};
            b+=Broker::integer(f.size,8);b+=Broker::integer(f.modifiedAtMs,8);b+=Broker::integer(f.checkedAtMs,8);
            b+=Broker::integer(unsigned(f.signature),1);b+=Broker::integer(f.publisher.size(),2);b+=QByteArray::fromStdString(f.publisher);}
    }
    return pendingPresentationContext(b)?std::optional<QByteArray>(std::move(b)):std::nullopt;
}
std::optional<FullBinding> pendingFullBinding(const PendingPresentationContext& pending,
    const PresentationContext& presentation,const ConfigurationView& configuration,const Id128& connection){
    if(!pendingPresentationBytes(pending)||!presentationBytes(presentation,configuration,connection)||
        !configuration.local.search||!presentation.searchReference())return {};
    const auto& search=*configuration.local.search;const auto& observed=*presentation.searchReference();
    if(search.provider!=observed.provider||search.configurationBinding!=observed.configurationBinding||
        search.instanceToken!=observed.instanceToken)return {};
    const auto& epochs=configuration.local.epochs;
    FullBinding result;
    result.requestId=QUuid::fromRfc4122(QByteArray(reinterpret_cast<const char*>(pending.request().data()),16)).toString().toStdString();
    result.applicationToken=pending.selector();result.snapshotRevision=pending.requestRevision();
    result.serviceEpoch=pending.service().engineBindingGeneration;result.generation=pending.profileGeneration();
    result.localSnapshotToken=pending.snapshotToken();result.localSnapshotGeneration=pending.snapshotGeneration();
    result.sessionEpoch=epochs.session;result.retrievalEpoch=epochs.retrieval;
    result.providerPolicyEpoch=epochs.providerPolicy;result.credentialEpoch=epochs.credential;
    result.modelConsentEpoch=epochs.modelConsent;result.webConsentEpoch=epochs.webConsent;
    result.entitlementPolicyEpoch=epochs.entitlement;result.provider=Provider(search.provider);
    result.providerConfiguration=search.configurationBinding;result.providerInstance=std::string(search.instanceToken.data(),38);
    return validBinding(result,true)?std::optional<FullBinding>(std::move(result)):std::nullopt;
}
}
