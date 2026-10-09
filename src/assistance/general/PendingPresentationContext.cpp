#include "PendingPresentationContext.h"
#include "broker/BrokerWire.h"
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
    if(!header(b,140))return {};
    PendingServiceContext s{idAt(b,4),idAt(b,20),idAt(b,36),Broker::number(b.mid(52,8))};
    const auto request=idAt(b,60),selector=idAt(b,76),token=idAt(b,116);
    const auto revision=Broker::number(b.mid(92,8)),selectorRevision=Broker::number(b.mid(100,8)),
        profile=Broker::number(b.mid(108,8)),generation=Broker::number(b.mid(132,8));
    if(!validPendingService(s)||!nonzero(request)||!nonzero(selector)||!nonzero(token)||!revision||!selectorRevision||!profile||!generation)return {};
    return PendingPresentationContext(s,request,selector,revision,selectorRevision,profile,token,generation);
}
std::optional<QByteArray> pendingPresentationBytes(const PendingPresentationContext& p){
    auto b=Broker::integer(1,2)+Broker::integer(0,2);const auto &s=p.service();
    addId(b,s.serviceEpoch);addId(b,s.boot);addId(b,s.engineContext);b+=Broker::integer(s.engineBindingGeneration,8);
    addId(b,p.request());addId(b,p.selector());b+=Broker::integer(p.requestRevision(),8);
    b+=Broker::integer(p.selectorRevision(),8);b+=Broker::integer(p.profileGeneration(),8);
    addId(b,p.snapshotToken());b+=Broker::integer(p.snapshotGeneration(),8);
    return pendingPresentationContext(b)?std::optional<QByteArray>(std::move(b)):std::nullopt;
}
}
