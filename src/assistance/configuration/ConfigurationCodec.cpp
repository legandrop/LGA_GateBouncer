#include "ConfigurationCodec.h"
#include <wincrypt.h>
#include <cstring>
#include <vector>

namespace Gate::Assistance::Configuration::Detail {
namespace {
constexpr std::size_t PlainLimit=4096,CipherLimit=16384;
struct Buffer {
    Broker::SensitiveBytes value{PlainLimit};std::size_t pos=0;bool ok=true;
    void bytes(const unsigned char *p,std::size_t n){if(!ok||n>PlainLimit-pos){ok=false;return;}if(n)std::memcpy(value.data()+pos,p,n);pos+=n;}
    template<class T> void bytes(const T &v){bytes(reinterpret_cast<const unsigned char *>(v.data()),v.size());}
    void number(std::uint64_t n,unsigned width){for(unsigned i=0;i<width;++i){const unsigned char b=static_cast<unsigned char>(n>>(8*i));bytes(&b,1);}}
    void text(const std::string &s){number(s.size(),2);bytes(s);}
    void receipt(const ConsentReceipt &r){number(r.granted,1);number(r.noticeRevision,4);bytes(r.noticeDigest);text(r.profileRef);bytes(r.destinationPolicyBinding);number(r.epoch,8);}
};
struct Reader {
    const unsigned char *data;std::size_t size,pos=0;bool ok=true;
    void bytes(unsigned char *out,std::size_t n){if(!ok||n>size-pos){ok=false;return;}if(n)std::memcpy(out,data+pos,n);pos+=n;}
    template<class T> void bytes(T &v){bytes(reinterpret_cast<unsigned char *>(v.data()),v.size());}
    std::uint64_t number(unsigned width){std::uint64_t n=0;for(unsigned i=0;i<width;++i){unsigned char b=0;bytes(&b,1);n|=std::uint64_t(b)<<(8*i);}return n;}
    bool boolean(){const auto n=number(1);if(n>1)ok=false;return n==1;}
    std::string text(){const auto n=number(2);if(n>96||n>size-pos){ok=false;return {};}std::string s(reinterpret_cast<const char *>(data+pos),std::size_t(n));pos+=std::size_t(n);return s;}
    ConsentReceipt receipt(){ConsentReceipt r;r.granted=boolean();r.noticeRevision=std::uint32_t(number(4));bytes(r.noticeDigest);r.profileRef=text();bytes(r.destinationPolicyBinding);r.epoch=number(8);return r;}
};
bool valid(const PersistentRecord &r){
    auto s=r.metadata;s.storage=StorageState::Ready;s.search.reset();s.webConsent.granted=false;
    if(!validSnapshot(s)||!r.committedRevision||r.profileRevision!=1||s.selectedProfileRef!=GeneralProfile||r.secret.size()>512)return false;
    if(r.metadata.credential!=(r.secret.size()?CredentialState::Stored:CredentialState::Absent))return false;
    for(std::size_t i=0;i<r.secret.size();++i)if(r.secret.data()[i]<33||r.secret.data()[i]>126)return false;
    if(!validReceipt(r.metadata.webConsent)||r.metadata.webConsent.epoch!=s.epochs.webConsent)return false;
    if(r.metadata.webConsent.granted&&r.metadata.webConsent.profileRef!=s.selectedProfileRef)return false;
    if(r.search&&(r.search->provider<1||r.search->provider>2||!nonzero(r.search->binding)||!r.search->policy))return false;
    if(r.evidence&&(!nonzero(r.evidence->id)||!nonzero(r.evidence->revision)))return false;
    return true;
}
struct DpapiOutput { DATA_BLOB blob{};~DpapiOutput(){if(blob.pbData){SecureZeroMemory(blob.pbData,blob.cbData);LocalFree(blob.pbData);}} };
}
std::optional<Broker::SensitiveBytes> encodeRecord(const PersistentRecord &r){
    if(!valid(r))return {};
    Buffer b;b.bytes(reinterpret_cast<const unsigned char *>("LGAGBCV2"),8);b.number(2,2);b.number(0,2);b.number(0,4);b.bytes(r.metadata.storeInstance);b.number(r.committedRevision,8);
    const auto &e=r.metadata.epochs;for(auto n:{e.configuration,e.credential,e.consent,e.modelConsent,e.webConsent})b.number(n,8);
    b.number(r.secret.size()!=0,1);b.number(r.secret.size(),2);b.bytes(r.secret.data(),r.secret.size());b.number(std::uint8_t(r.metadata.mode),1);b.text(r.metadata.selectedProfileRef);b.number(r.profileRevision,4);
    b.receipt(r.metadata.modelConsent);b.receipt(r.metadata.webConsent);b.number(bool(r.search),1);if(r.search){b.number(r.search->provider,1);b.bytes(r.search->binding);b.number(r.search->policy,8);}
    b.number(bool(r.evidence),1);if(r.evidence){b.bytes(r.evidence->id);b.bytes(r.evidence->revision);}
    if(!b.ok||b.pos>PlainLimit-32)return {};
    const auto total=b.pos+32;for(unsigned i=0;i<4;++i)b.value.data()[12+i]=static_cast<unsigned char>(total>>(8*i));
    const auto sum=digest("LGA_GATEBOUNCER_CONFIGURATION_V2",b.value.data(),b.pos);b.bytes(sum);
    Broker::SensitiveBytes result(total);std::memcpy(result.data(),b.value.data(),total);return result;
}
std::optional<PersistentRecord> decodeRecord(const Broker::SensitiveBytes &plain){
    if(plain.size()<283||plain.size()>PlainLimit||std::memcmp(plain.data(),"LGAGBCV2",8))return {};
    Reader r{plain.data(),plain.size()-32};r.pos=8;if(r.number(2)!=2||r.number(2)||r.number(4)!=plain.size())return {};
    PersistentRecord result;auto &s=result.metadata;r.bytes(s.storeInstance);result.committedRevision=r.number(8);s.revision=result.committedRevision;s.storage=StorageState::Ready;
    s.epochs.configuration=r.number(8);s.epochs.credential=r.number(8);s.epochs.consent=r.number(8);s.epochs.modelConsent=r.number(8);s.epochs.webConsent=r.number(8);
    const bool present=r.boolean();const auto n=r.number(2);if(n>512||present!=(n!=0)||n>r.size-r.pos)return {};
    result.secret=Broker::SensitiveBytes(std::size_t(n));r.bytes(result.secret.data(),std::size_t(n));s.credential=present?CredentialState::Stored:CredentialState::Absent;
    s.mode=ModeChoice(r.number(1));s.selectedProfileRef=r.text();result.profileRevision=std::uint32_t(r.number(4));s.modelConsent=r.receipt();s.webConsent=r.receipt();
    if(r.boolean()){SearchPreference p;p.provider=std::uint8_t(r.number(1));r.bytes(p.binding);p.policy=r.number(8);result.search=p;}
    if(r.boolean()){EvidencePreference p;r.bytes(p.id);r.bytes(p.revision);result.evidence=p;}
    if(!r.ok||r.pos!=r.size||!valid(result))return {};
    result.integrity=digest("LGA_GATEBOUNCER_CONFIGURATION_V2",plain.data(),r.size);unsigned difference=0;for(std::size_t i=0;i<32;++i)difference|=result.integrity[i]^plain.data()[r.size+i];
    if(difference)return {};
    return result;
}
std::optional<Broker::SensitiveBytes> protectRecord(const Broker::SensitiveBytes &plain){
    if(plain.size()>PlainLimit||!decodeRecord(plain))return {};
    DATA_BLOB input{DWORD(plain.size()),const_cast<unsigned char *>(plain.data())};DpapiOutput output;
    if(!CryptProtectData(&input,nullptr,nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&output.blob)||!output.blob.pbData||!output.blob.cbData||output.blob.cbData>CipherLimit)return {};
    Broker::SensitiveBytes result(16+output.blob.cbData);auto *d=result.data();std::memcpy(d,"LGAGBCE2",8);d[8]=2;for(unsigned i=0;i<4;++i)d[12+i]=static_cast<unsigned char>(output.blob.cbData>>(8*i));std::memcpy(d+16,output.blob.pbData,output.blob.cbData);return result;
}
std::optional<Broker::SensitiveBytes> unprotectRecord(const Broker::SensitiveBytes &envelope){
    if(envelope.size()<17||envelope.size()>16+CipherLimit||std::memcmp(envelope.data(),"LGAGBCE2",8))return {};
    Reader r{envelope.data(),16};r.pos=8;if(r.number(2)!=2||r.number(2))return {};const auto n=r.number(4);if(!n||n>CipherLimit||envelope.size()!=16+n)return {};
    DATA_BLOB input{DWORD(n),const_cast<unsigned char *>(envelope.data()+16)};DpapiOutput output;
    if(!CryptUnprotectData(&input,nullptr,nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&output.blob)||!output.blob.pbData||output.blob.cbData<283||output.blob.cbData>PlainLimit)return {};
    Broker::SensitiveBytes result(output.blob.cbData);std::memcpy(result.data(),output.blob.pbData,result.size());if(!decodeRecord(result))return {};return result;
}
}
