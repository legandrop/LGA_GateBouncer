#include "GeneralWire.h"
#include "InferenceEncoding.h"
#include "retrieval/StrictJson.h"
#include <algorithm>
#include <cstring>
#include <set>
#include "PendingPresentationContext.h"
namespace Gate::Assistance::General {
namespace {
using Broker::number;
struct Reader {
    const QByteArray& bytes;qsizetype pos=0;bool good=true;
    QByteArray take(qsizetype n){if(n<0||n>bytes.size()-pos){good=false;return {};}auto out=bytes.mid(pos,n);pos+=n;return out;}
    std::uint64_t n(unsigned width){return number(take(width));}
    template<std::size_t N> std::array<std::uint8_t,N> fixed(){std::array<std::uint8_t,N> out{};auto b=take(N);if(good)std::memcpy(out.data(),b.data(),N);return out;}
    std::string text(std::size_t cap,bool empty=false){const auto length=n(2);if(length>cap){good=false;return {};}auto b=take(qsizetype(length));std::string s=b.toStdString();if(!safeText(s,cap,empty))good=false;return s;}
    bool end() const {return good&&pos==bytes.size();}
};
template<class T> bool nonzero(const T& b){return std::any_of(b.begin(),b.end(),[](auto c){return c!=0;});}
bool tags(const Broker::Frame& f,std::set<quint16> required,std::set<quint16> optional={}){
    for(auto t:required)if(!f.fields.count(t))return false;
    for(const auto& [t,b]:f.fields){Q_UNUSED(b);if(!required.count(t)&&!optional.count(t))return false;}return true;
}
bool scalar(const Broker::Frame& f,quint16 t,int width,std::uint64_t min,std::uint64_t max){const auto it=f.fields.find(t);return it!=f.fields.end()&&it->second.size()==width&&number(it->second)>=min&&number(it->second)<=max;}
std::optional<FullBinding> readBinding(const QByteArray& bytes,bool pending){
    if(bytes.size()>768)return {};
    Reader r{bytes};FullBinding b;b.requestId=r.text(128);b.applicationToken=r.fixed<16>();
    std::uint64_t* epochs[]={&b.snapshotRevision,&b.serviceEpoch,&b.sessionEpoch,&b.retrievalEpoch,&b.providerPolicyEpoch,
        &b.credentialEpoch,&b.modelConsentEpoch,&b.webConsentEpoch,&b.generation,&b.approvalEpoch,&b.entitlementPolicyEpoch};
    for(auto p:epochs)*p=r.n(8);
    b.localSnapshotToken=r.fixed<16>();b.localSnapshotGeneration=r.n(8);b.provider=Provider(r.n(1));
    b.providerInstance=r.text(38);b.providerConfiguration=r.fixed<32>();b.publicApprovalDigest=r.fixed<32>();b.profileRevision=std::uint32_t(r.n(4));
    return r.end()&&validBinding(b,pending)?std::optional<FullBinding>(std::move(b)):std::nullopt;
}
std::optional<PublicFields> readPublic(const QByteArray& bytes){
    auto j=Retrieval::strictJson(bytes,512);if(!j||!j->exact({"product","publisher","query"}))return {};
    const auto product=j->get("product")->text(),query=j->get("query")->text();if(!product||!query)return {};
    PublicFields p{product->toUtf8().toStdString(),{},query->toUtf8().toStdString()};const auto* publisher=j->get("publisher");
    if(publisher->kind!=Retrieval::Json::Kind::Null){auto text=publisher->text();if(!text)return {};p.publisher=text->toUtf8().toStdString();}
    return GeneralPayloadBuilder::publicJson(p)?std::optional<PublicFields>(std::move(p)):std::nullopt;
}
std::optional<std::vector<Citation>> readCitations(const QByteArray& bytes){
    auto j=Retrieval::strictJson(bytes,4096);if(!j||j->kind!=Retrieval::Json::Kind::Array||j->array.size()>3)return {};
    std::vector<Citation> out;
    for(const auto& value:j->array){
        if(!value.exact({"id","url","title","snippet","origin","retrieved_at_ms","shortened"}))return {};
        const auto id=value.get("id")->integer(),at=value.get("retrieved_at_ms")->integer();const auto shortened=value.get("shortened")->boolean();
        if(!id||*id!=out.size()+1||!at||!*at||!shortened)return {};
        Citation c;c.id=std::uint8_t(*id);c.retrievedAtMs=*at;c.shortened=*shortened;
        std::string* destinations[]={&c.url,&c.title,&c.snippet,&c.origin};const char* keys[]={"url","title","snippet","origin"};
        for(int n=0;n<4;++n){const auto text=value.get(keys[n])->text();if(!text)return {};*destinations[n]=text->toUtf8().toStdString();}
        out.push_back(std::move(c));
    }
    return GeneralPayloadBuilder::citationsJson(out)?std::optional<std::vector<Citation>>(std::move(out)):std::nullopt;
}
struct Receipt {bool granted=false,complete=false;std::string profile;};
Receipt receipt(Reader& r,bool update){
    Receipt out;const auto grant=r.n(1),revision=r.n(4);const auto notice=r.fixed<32>();out.profile=r.text(96,true);const auto policy=r.fixed<32>();const auto epoch=r.n(8);
    out.granted=grant==1;out.complete=revision&&nonzero(notice)&&!out.profile.empty()&&nonzero(policy);
    const bool empty=!revision&&!nonzero(notice)&&out.profile.empty()&&!nonzero(policy);
    if(grant>1||(update?epoch!=0:epoch==0)||(out.granted?!out.complete:(!empty&&!out.complete)))r.good=false;
    return out;
}
void searchBinding(Reader& r,bool update){
    const auto provider=r.n(1);const auto digest=r.fixed<32>();const auto uuid=r.take(38);const auto policy=r.n(8),consent=r.n(8);
    bool validUuid=uuid.size()==38&&uuid.front()=='{'&&uuid.back()=='}';
    for(int n=1;validUuid&&n<37;++n){const char c=uuid[n];if(n==9||n==14||n==19||n==24)validUuid=c=='-';
        else validUuid=(c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');}
    if(provider<1||provider>2||!nonzero(digest)||!validUuid||(update?(policy!=0||consent!=0):(!policy||!consent)))r.good=false;
}
bool snapshot(const QByteArray& bytes){
    if(bytes.size()>1536)return false;
    Reader r{bytes};if(r.n(2)!=2||r.n(2)!=0)return false;
    const auto instance=r.fixed<16>();const auto revision=r.n(8),storage=r.n(1),credential=r.n(1),mode=r.n(1),serviceUse=r.n(1);const auto profile=r.text(96,storage==0);
    if(!nonzero(instance)||!revision||storage>6||credential>3||mode>2||serviceUse>2)return false;
    for(int n=0;n<9;++n)if(!r.n(8))return false;
    const auto model=receipt(r,false),web=receipt(r,false);const auto hasSearch=r.n(1);if(hasSearch>1)return false;if(hasSearch)searchBinding(r,false);
    const auto cause=r.n(2),evidence=r.n(1),available=r.n(1);const auto activationProfile=r.text(96,true);const auto scope=r.fixed<32>(),entitlement=r.fixed<32>();
    if(!r.end()||cause>18||evidence>4||available>1||(model.granted&&serviceUse!=1))return false;
    if((storage==0&&(credential!=0||model.granted||web.granted))||
        ((storage==2||storage==3||storage==5)&&(credential!=3||model.granted||web.granted))||
        (storage==4&&(credential!=2||model.granted||web.granted))||
        (storage==6&&(cause!=17||available||model.granted||web.granted)))return false;
    if(cause==0&&(!available||!nonzero(scope)||!nonzero(entitlement)))return false;
    if(available&&(storage!=1||credential!=1||cause!=0||serviceUse!=1||evidence!=2||!model.granted||!web.granted||!hasSearch||
        activationProfile!=profile||model.profile!=profile||web.profile!=profile))return false;
    return true;
}
bool update(const QByteArray& bytes){
    if(bytes.size()>1024)return false;
    Reader r{bytes};if(r.n(2)!=1||r.n(2)!=0)return false;const auto verb=r.n(1);
    switch(verb){
    case 3:{const auto target=r.n(1);receipt(r,true);if(target<1||target>2)return false;break;}
    case 4:{const auto mode=r.n(1);if(mode<1||mode>2)return false;break;}
    case 5:{r.text(96);if(!r.n(4))return false;break;}
    case 6:searchBinding(r,true);break;
    case 7:if(r.n(1)>2)return false;break;
    default:return false;
    }return r.end();
}
bool configuration(const Broker::Frame& f,unsigned type){
    switch(type){
    case 30:return tags(f,{},{76,77})&&(f.fields.empty()||scalar(f,76,2,1,1))&&
        (!f.fields.count(77)||pendingQuery(f.fields.at(77)).has_value());
    case 31:{
        if(!tags(f,{70},{76,77})||!snapshot(f.fields.at(70)))return false;
        if(!f.fields.count(76))return !f.fields.count(77);
        const auto canonical=configurationView(f.fields.at(70));
        return canonical&&presentationContext(f.fields.at(76),*canonical,f.connection).has_value()&&
            (!f.fields.count(77)||pendingPresentationContext(f.fields.at(77)).has_value());
    }
    case 32:return tags(f,{71,73})&&scalar(f,71,1,1,7)&&scalar(f,73,8,1,UINT64_MAX);
    case 33:return tags(f,{71,72,73})&&scalar(f,71,1,1,7)&&scalar(f,73,8,1,UINT64_MAX)&&f.fields.at(72).size()==16&&nonzero(f.fields.at(72));
    case 34:case 35:case 36:
        if(!tags(f,type==36?std::set<quint16>{72,73,74}:std::set<quint16>{72,73})||!scalar(f,73,8,1,UINT64_MAX)||f.fields.at(72).size()!=16||!nonzero(f.fields.at(72)))return false;
        return type!=36||update(f.fields.at(74));
    case 37:return tags(f,{70,75})&&scalar(f,75,2,0,10)&&snapshot(f.fields.at(70));
    default:return false;
    }
}
}
std::optional<FullBinding> frameBinding(const Broker::Frame& f,bool pending){const auto it=f.fields.find(60);return it==f.fields.end()?std::nullopt:readBinding(it->second,pending);}
std::optional<PublicFields> framePublicFields(const Broker::Frame& f){const auto it=f.fields.find(61);return it==f.fields.end()?std::nullopt:readPublic(it->second);}
std::optional<std::vector<Citation>> frameCitations(const Broker::Frame& f){const auto it=f.fields.find(62);return it==f.fields.end()?std::optional<std::vector<Citation>>(std::vector<Citation>{}):readCitations(it->second);}
bool validGeneralFrame(const Broker::Frame& f){
    if(!nonzero(f.connection)||!nonzero(f.correlation)||!f.sequence||f.fields.size()>32)return false;
    std::size_t bytes=64;for(const auto& [tag,value]:f.fields){Q_UNUSED(tag);if(bytes>8192-8||value.size()<0||std::size_t(value.size())>8192-bytes-8)return false;bytes+=8+std::size_t(value.size());}
    const auto type=unsigned(f.message);if(type!=34&&f.secret.size())return false;
    if(type==34){if(f.secret.size()<1||f.secret.size()>512||8+f.secret.size()>8192-bytes)return false;for(std::size_t n=0;n<f.secret.size();++n)if(f.secret.data()[n]<33||f.secret.data()[n]>126)return false;}
    if(type==1||type==2||type==5||type==6||type==11)return Broker::validFrame(f,Broker::WireVersion::Legacy1);
    if(type>=30&&type<=37)return configuration(f,type);
    if(type==20||type==23||type==24){
        if(!tags(f,type==24?std::set<quint16>{60,61,65}:std::set<quint16>{60,61}))return false;
        if(type==24&&!scalar(f,65,2,0,18))return false;
        const auto failure=type==24?number(f.fields.at(65)):0;
        if(type==24&&failure!=0&&failure!=3&&failure!=4&&failure!=5&&failure!=15)return false;
        auto b=frameBinding(f,type==23||(type==24&&failure));auto p=framePublicFields(f);if(!b||!p)return false;
        return type==23||failure||approvalDigest(*p,b->approvalEpoch)==b->publicApprovalDigest;
    }
    if(type==22)return tags(f,{60,64})&&frameBinding(f)&&scalar(f,64,1,1,2);
    if(type!=21||!tags(f,{60,64,65,66},{62,63})||!frameBinding(f)||!scalar(f,64,1,3,7)||!scalar(f,65,2,0,18)||!scalar(f,66,2,0,599))return false;
    const auto state=number(f.fields.at(64)),failure=number(f.fields.at(65)),http=number(f.fields.at(66));auto cs=frameCitations(f);if(!cs)return false;
    if(state==3)return failure==0&&http==200&&!cs->empty()&&f.fields.count(63)&&General3ResponseContract::parseInference(f.fields.at(63).toStdString(),*cs).has_value();
    if(f.fields.count(63))return false;
    if(state==4)return failure==0&&http==0;
    if(state==5)return failure==11&&http==0;
    if(state==7)return failure==14&&(http==0||http==202);
    return failure!=0&&failure!=11&&failure!=14&&(http==0||http==200||(http>=300&&http<=599));
}
std::optional<Result> frameResult(const Broker::Frame& f){
    if(unsigned(f.message)!=21||!validGeneralFrame(f))return {};
    auto b=frameBinding(f);auto cs=frameCitations(f);
    Result result{*b,State(number(f.fields.at(64))),Failure(number(f.fields.at(65))),int(number(f.fields.at(66))),std::move(*cs),{}};
    if(f.fields.count(63))result.inference=General3ResponseContract::parseInference(f.fields.at(63).toStdString(),result.citations);
    return result;
}
bool setFrameBinding(Broker::Frame& f,const FullBinding& b){if(!validBinding(b)&&!validBinding(b,true))return false;f.fields[60]=QByteArray::fromStdString(canonicalBinding(b));return true;}
bool setPublicFields(Broker::Frame& f,const PublicFields& p){auto bytes=GeneralPayloadBuilder::publicJson(p);if(!bytes)return false;f.fields[61]=QByteArray::fromStdString(*bytes);return true;}
bool setResult(Broker::Frame& f,const Result& r){
    auto citations=GeneralPayloadBuilder::citationsJson(r.citations);if(!citations)return false;std::optional<std::string> inference;
    if(r.inference){inference=Detail::inferenceJson(*r.inference,r.citations);if(!inference)return false;}
    if(!setFrameBinding(f,r.binding))return false;
    f.fields.erase(62);f.fields.erase(63);
    f.fields[64]=Broker::integer(unsigned(r.state),1);f.fields[65]=Broker::integer(unsigned(r.failure),2);f.fields[66]=Broker::integer(r.observedHttpStatus,2);
    if(!r.citations.empty())f.fields[62]=QByteArray::fromStdString(*citations);
    if(inference)f.fields[63]=QByteArray::fromStdString(*inference);
    return true;
}
namespace {
using Configuration::ConsentReceipt;
using Configuration::SearchBindingRef;
ConsentReceipt readReceipt(Reader& r){
    ConsentReceipt c;c.granted=r.n(1);c.noticeRevision=std::uint32_t(r.n(4));c.noticeDigest=r.fixed<32>();c.profileRef=r.text(96,true);c.destinationPolicyBinding=r.fixed<32>();c.epoch=r.n(8);return c;
}
SearchBindingRef readSearch(Reader& r){
    SearchBindingRef s;s.provider=std::uint8_t(r.n(1));s.configurationBinding=r.fixed<32>();const auto uuid=r.take(38);std::memcpy(s.instanceToken.data(),uuid.data(),38);s.providerPolicyEpoch=r.n(8);s.webConsentEpoch=r.n(8);return s;
}
void addNumber(QByteArray& b,std::uint64_t n,int width){b+=Broker::integer(n,width);}
template<class T> void addFixed(QByteArray& b,const T& v){b.append(reinterpret_cast<const char*>(v.data()),qsizetype(v.size()));}
void addText(QByteArray& b,const std::string& s){addNumber(b,s.size(),2);b.append(s.data(),qsizetype(s.size()));}
void addReceipt(QByteArray& b,const ConsentReceipt& c){addNumber(b,c.granted,1);addNumber(b,c.noticeRevision,4);addFixed(b,c.noticeDigest);addText(b,c.profileRef);addFixed(b,c.destinationPolicyBinding);addNumber(b,c.epoch,8);}
void addSearch(QByteArray& b,const SearchBindingRef& s){addNumber(b,s.provider,1);addFixed(b,s.configurationBinding);addFixed(b,s.instanceToken);addNumber(b,s.providerPolicyEpoch,8);addNumber(b,s.webConsentEpoch,8);}
}
std::optional<ConfigurationView> configurationView(const QByteArray& bytes){
    if(!snapshot(bytes))return {};
    Reader r{bytes};r.n(4);ConfigurationView view;auto &s=view.local;auto &a=view.activation;
    s.storeInstance=r.fixed<16>();s.revision=r.n(8);s.storage=Configuration::StorageState(r.n(1));s.credential=Configuration::CredentialState(r.n(1));s.mode=Configuration::ModeChoice(r.n(1));s.serviceUse=Configuration::ServiceUse(r.n(1));s.selectedProfileRef=r.text(96,true);
    std::uint64_t* epochs[]={&s.epochs.configuration,&s.epochs.credential,&s.epochs.consent,&s.epochs.modelConsent,&s.epochs.webConsent,&s.epochs.retrieval,&s.epochs.providerPolicy,&s.epochs.entitlement,&s.epochs.session};
    for(auto p:epochs)*p=r.n(8);
    s.modelConsent=readReceipt(r);s.webConsent=readReceipt(r);if(r.n(1))s.search=readSearch(r);
    a.cause=Configuration::ActivationCause(r.n(2));a.entitlementState=Configuration::EvidenceState(r.n(1));a.technicallyAvailable=r.n(1);a.profileRef=r.text(96,true);a.destinationModelModeBinding=r.fixed<32>();a.entitlementRevisionBinding=r.fixed<32>();a.epochs=s.epochs;
    return r.end()?std::optional<ConfigurationView>(std::move(view)):std::nullopt;
}
std::optional<QByteArray> configurationBytes(const ConfigurationView& view){
    const auto &s=view.local;const auto &a=view.activation;
    // Todos los strings se acotan antes de reservar; el máximo estructural cabe en 1536.
    if(!safeText(s.selectedProfileRef,96,true)||!safeText(a.profileRef,96,true)||!safeText(s.modelConsent.profileRef,96,true)||!safeText(s.webConsent.profileRef,96,true)||!(s.epochs==a.epochs))return {};
    QByteArray b;b.reserve(1536);addNumber(b,2,2);addNumber(b,0,2);addFixed(b,s.storeInstance);addNumber(b,s.revision,8);
    addNumber(b,unsigned(s.storage),1);addNumber(b,unsigned(s.credential),1);addNumber(b,unsigned(s.mode),1);addNumber(b,unsigned(s.serviceUse),1);addText(b,s.selectedProfileRef);
    const std::uint64_t epochs[]={s.epochs.configuration,s.epochs.credential,s.epochs.consent,s.epochs.modelConsent,s.epochs.webConsent,s.epochs.retrieval,s.epochs.providerPolicy,s.epochs.entitlement,s.epochs.session};
    for(auto e:epochs)addNumber(b,e,8);
    addReceipt(b,s.modelConsent);addReceipt(b,s.webConsent);addNumber(b,bool(s.search),1);if(s.search)addSearch(b,*s.search);
    addNumber(b,unsigned(a.cause),2);addNumber(b,unsigned(a.entitlementState),1);addNumber(b,a.technicallyAvailable,1);addText(b,a.profileRef);addFixed(b,a.destinationModelModeBinding);addFixed(b,a.entitlementRevisionBinding);
    return snapshot(b)?std::optional<QByteArray>(std::move(b)):std::nullopt;
}
std::optional<Configuration::ConfigurationMutation> configurationUpdate(const QByteArray& bytes){
    if(!update(bytes))return {};
    Reader r{bytes};r.n(4);Configuration::ConfigurationMutation m;m.verb=Configuration::ConfigurationVerb(r.n(1));
    switch(m.verb){
    case Configuration::ConfigurationVerb::Consent:m.target=Configuration::ConsentTarget(r.n(1));m.receipt=readReceipt(r);break;
    case Configuration::ConfigurationVerb::Mode:m.mode=Configuration::ModeChoice(r.n(1));break;
    case Configuration::ConfigurationVerb::Profile:m.profileRef=r.text(96);m.profileRevision=std::uint32_t(r.n(4));break;
    case Configuration::ConfigurationVerb::Search:m.search=readSearch(r);break;
    case Configuration::ConfigurationVerb::ServiceUse:m.serviceUse=Configuration::ServiceUse(r.n(1));break;
    default:return {};
    }return r.end()?std::optional<Configuration::ConfigurationMutation>(std::move(m)):std::nullopt;
}
std::optional<QByteArray> configurationBytes(const Configuration::ConfigurationMutation& m){
    if(!safeText(m.profileRef,96,true)||!safeText(m.receipt.profileRef,96,true))return {};
    QByteArray b;b.reserve(1024);addNumber(b,1,2);addNumber(b,0,2);addNumber(b,unsigned(m.verb),1);
    switch(m.verb){
    case Configuration::ConfigurationVerb::Consent:addNumber(b,unsigned(m.target),1);addReceipt(b,m.receipt);break;
    case Configuration::ConfigurationVerb::Mode:addNumber(b,unsigned(m.mode),1);break;
    case Configuration::ConfigurationVerb::Profile:addText(b,m.profileRef);addNumber(b,m.profileRevision,4);break;
    case Configuration::ConfigurationVerb::Search:if(!m.search)return {};addSearch(b,*m.search);break;
    case Configuration::ConfigurationVerb::ServiceUse:addNumber(b,unsigned(m.serviceUse),1);break;
    default:return {};
    }return update(b)?std::optional<QByteArray>(std::move(b)):std::nullopt;
}
}
