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
std::optional<Id128> pendingQuery(const QByteArray& b){if(!header(b,20))return {};auto id=idAt(b,4);return nonzero(id)?std::optional<Id128>(id):std::nullopt;}
std::optional<QByteArray> pendingQueryBytes(const Id128& id){if(!nonzero(id))return {};auto b=Broker::integer(1,2)+Broker::integer(0,2);addId(b,id);return b;}
std::optional<PendingPresentationContext> pendingPresentationContext(const QByteArray& b){
    if(b.size()<141||b.size()>198||Broker::number(b.left(2))!=2||Broker::number(b.mid(2,2))!=0)return {};
    PendingServiceContext s{idAt(b,4),idAt(b,20),idAt(b,36),Broker::number(b.mid(52,8))};
    const auto request=idAt(b,60),selector=idAt(b,76),token=idAt(b,116);
    const auto revision=Broker::number(b.mid(92,8)),selectorRevision=Broker::number(b.mid(100,8)),
        profile=Broker::number(b.mid(108,8)),generation=Broker::number(b.mid(132,8));
    if(!validPendingService(s)||!nonzero(request)||!nonzero(selector)||!nonzero(token)||!revision||!selectorRevision||!profile||!generation)return {};
    const auto presence=Broker::number(b.mid(140,1));std::optional<Destination> destination;
    if(presence>1)return {};
    if(presence){
        if(b.size()<153)return {};const auto length=Broker::number(b.mid(141,1));
        if(!length||length>45||b.size()!=153+qsizetype(length))return {};
        Destination d{b.mid(142,length).toStdString(),std::uint16_t(Broker::number(b.mid(142+length,2))),
            std::uint8_t(Broker::number(b.mid(144+length,1))),Broker::number(b.mid(145+length,8))};
        if(!validDestination(d))return {};destination=std::move(d);
    }else if(b.size()!=141)return {};
    return PendingPresentationContext(s,request,selector,revision,selectorRevision,profile,token,generation,std::move(destination));
}
std::optional<QByteArray> pendingPresentationBytes(const PendingPresentationContext& p){
    auto b=Broker::integer(2,2)+Broker::integer(0,2);const auto &s=p.service();
    addId(b,s.serviceEpoch);addId(b,s.boot);addId(b,s.engineContext);b+=Broker::integer(s.engineBindingGeneration,8);
    addId(b,p.request());addId(b,p.selector());b+=Broker::integer(p.requestRevision(),8);
    b+=Broker::integer(p.selectorRevision(),8);b+=Broker::integer(p.profileGeneration(),8);
    addId(b,p.snapshotToken());b+=Broker::integer(p.snapshotGeneration(),8);
    b+=Broker::integer(p.destination()?1:0,1);
    if(p.destination()){const auto& d=*p.destination();if(!validDestination(d))return {};
        b+=Broker::integer(d.address.size(),1);b+=QByteArray::fromStdString(d.address);b+=Broker::integer(d.port,2);
        b+=Broker::integer(d.protocol,1);b+=Broker::integer(d.observedAtMs,8);}
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
