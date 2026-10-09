#include "PresentationContext.h"
#include "GeneralWire.h"
#include <cstring>
#include <tuple>
namespace Gate::Assistance::General {
namespace C=Configuration;
namespace {
struct Reader {
    const QByteArray& bytes;qsizetype pos=0;bool good=true;
    QByteArray take(qsizetype count){if(count<0||count>bytes.size()-pos){good=false;return {};}auto out=bytes.mid(pos,count);pos+=count;return out;}
    std::uint64_t number(int width){return Broker::number(take(width));}
    template<std::size_t N> std::array<std::uint8_t,N> fixed(){std::array<std::uint8_t,N> result{};auto value=take(N);if(good)std::memcpy(result.data(),value.constData(),N);return result;}
    std::string text(){const auto length=number(2);if(length>96){good=false;return {};}auto value=take(qsizetype(length));return value.toStdString();}
};
C::ConsentReceipt readReceipt(Reader& r){C::ConsentReceipt value;value.granted=r.number(1);value.noticeRevision=std::uint32_t(r.number(4));value.noticeDigest=r.fixed<32>();value.profileRef=r.text();value.destinationPolicyBinding=r.fixed<32>();value.epoch=r.number(8);return value;}
C::SearchBindingRef readSearch(Reader& r){C::SearchBindingRef value;value.provider=std::uint8_t(r.number(1));value.configurationBinding=r.fixed<32>();auto token=r.take(38);if(r.good)std::memcpy(value.instanceToken.data(),token.constData(),38);value.providerPolicyEpoch=r.number(8);value.webConsentEpoch=r.number(8);return value;}
bool expected(const C::ConsentReceipt& r,const std::string& profile,const Digest256& destination){
    return !r.granted&&!r.epoch&&r.noticeRevision&&C::validReceipt(r,true)&&r.profileRef==profile&&r.destinationPolicyBinding==destination;
}
bool valid(const PresentationContext& p,const ConfigurationView& view,const Id128& connection){
    const auto &s=view.local;
    if(!configurationBytes(view)||!C::nonzero(connection)||p.connection()!=connection||p.storeInstance()!=s.storeInstance||
        p.configurationRevision()!=s.revision||p.sessionEpoch()!=s.epochs.session)return false;
    if(p.searchReference()){
        const auto &ref=*p.searchReference();
        if(!C::validSearch(ref)||ref.providerPolicyEpoch!=s.epochs.providerPolicy||ref.webConsentEpoch!=s.epochs.webConsent)return false;
    }
    if(p.expectedModel()&&!expected(*p.expectedModel(),s.selectedProfileRef,view.activation.destinationModelModeBinding))return false;
    if(p.expectedWeb()&&(!p.searchReference()||!expected(*p.expectedWeb(),s.selectedProfileRef,p.searchReference()->configurationBinding)))return false;
    return true;
}
void number(QByteArray& bytes,std::uint64_t value,int width){bytes+=Broker::integer(value,width);}
template<class T> void fixed(QByteArray& bytes,const T& value){bytes.append(reinterpret_cast<const char*>(value.data()),qsizetype(value.size()));}
void receipt(QByteArray& bytes,const C::ConsentReceipt& value){number(bytes,0,1);number(bytes,value.noticeRevision,4);fixed(bytes,value.noticeDigest);number(bytes,value.profileRef.size(),2);bytes+=QByteArray::fromStdString(value.profileRef);fixed(bytes,value.destinationPolicyBinding);number(bytes,0,8);}
void search(QByteArray& bytes,const C::SearchBindingRef& value){number(bytes,value.provider,1);fixed(bytes,value.configurationBinding);fixed(bytes,value.instanceToken);number(bytes,value.providerPolicyEpoch,8);number(bytes,value.webConsentEpoch,8);}
}
bool sameConfigurationView(const ConfigurationView& a,const ConfigurationView& b){
    const auto &x=a.activation,&y=b.activation;
    return a.local==b.local&&std::tie(x.cause,x.entitlementState,x.profileRef,x.destinationModelModeBinding,x.entitlementRevisionBinding,x.epochs,x.technicallyAvailable)==
        std::tie(y.cause,y.entitlementState,y.profileRef,y.destinationModelModeBinding,y.entitlementRevisionBinding,y.epochs,y.technicallyAvailable);
}
std::optional<PresentationContext> presentationContext(const QByteArray& bytes,const ConfigurationView& view,const Id128& connection){
    if(bytes.size()<53||bytes.size()>512)return {};
    Reader r{bytes};if(r.number(2)!=1||r.number(2)!=0)return {};
    const auto ownConnection=r.fixed<16>(),store=r.fixed<16>();const auto revision=r.number(8),session=r.number(8),flags=r.number(1);
    if(flags>7)return {};
    std::optional<C::SearchBindingRef> ref;std::optional<C::ConsentReceipt> model,web;
    if(flags&4)ref=readSearch(r);
    if(flags&1)model=readReceipt(r);
    if(flags&2)web=readReceipt(r);
    if(!r.good||r.pos!=bytes.size())return {};
    PresentationContext result(ownConnection,store,revision,session,std::move(ref),std::move(model),std::move(web));
    return valid(result,view,connection)?std::optional<PresentationContext>(std::move(result)):std::nullopt;
}
std::optional<QByteArray> presentationBytes(const PresentationContext& p,const ConfigurationView& view,const Id128& connection){
    if(!valid(p,view,connection))return {};
    QByteArray bytes;bytes.reserve(490);number(bytes,1,2);number(bytes,0,2);fixed(bytes,p.connection());fixed(bytes,p.storeInstance());
    number(bytes,p.configurationRevision(),8);number(bytes,p.sessionEpoch(),8);
    number(bytes,(p.expectedModel()?1:0)|(p.expectedWeb()?2:0)|(p.searchReference()?4:0),1);
    if(p.searchReference())search(bytes,*p.searchReference());
    if(p.expectedModel())receipt(bytes,*p.expectedModel());
    if(p.expectedWeb())receipt(bytes,*p.expectedWeb());
    return bytes.size()<=490?std::optional<QByteArray>(std::move(bytes)):std::nullopt;
}
}
