#include "ConfigurationContracts.h"
#include <QCryptographicHash>
#include <QString>
#include <QStringDecoder>
#include <limits>

namespace Gate::Assistance::Configuration {
static bool reference(const std::string &s,bool empty=false) {
    if(s.size()>96 || (!empty&&s.empty()) || s.find('\0')!=std::string::npos) return false;
    QStringDecoder decoder(QStringDecoder::Utf8); const QString text=decoder(QByteArrayView(s.data(),qsizetype(s.size())));
    if(decoder.hasError())return false;
    for(auto c:text)if(c.category()==QChar::Other_Control||c.category()==QChar::Other_Format||c.category()==QChar::Other_Surrogate||c.unicode()==0x2028||c.unicode()==0x2029)return false;
    return true;
}
bool validReceipt(const ConsentReceipt &r,bool update) {
    if((update?r.epoch!=0:r.epoch==0)||!reference(r.profileRef,true))return false;
    const bool blank=r.noticeRevision==0&&!nonzero(r.noticeDigest)&&r.profileRef.empty()&&!nonzero(r.destinationPolicyBinding);
    const bool complete=r.noticeRevision>0&&nonzero(r.noticeDigest)&&!r.profileRef.empty()&&nonzero(r.destinationPolicyBinding);
    return r.granted?complete:(blank||complete);
}
bool validSearch(const SearchBindingRef &s,bool update) {
    if(s.provider<1||s.provider>2||!nonzero(s.configurationBinding)||(update?(s.webConsentEpoch!=0||s.providerPolicyEpoch!=0):(!s.webConsentEpoch||!s.providerPolicyEpoch)))return false;
    for(std::size_t i=0;i<38;++i) {
        const char c=s.instanceToken[i];
        if(i==0){if(c!='{')return false;}else if(i==37){if(c!='}')return false;}
        else if(i==9||i==14||i==19||i==24){if(c!='-')return false;}
        else if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')))return false;
    }
    return true;
}
bool validSnapshot(const ConfigurationSnapshot &s) {
    if(!nonzero(s.storeInstance)||!s.revision||std::uint8_t(s.storage)>6||std::uint8_t(s.credential)>3||std::uint8_t(s.mode)>2||!reference(s.selectedProfileRef)||!validReceipt(s.modelConsent)||!validReceipt(s.webConsent))return false;
    const auto &e=s.epochs;if(!e.configuration||!e.credential||!e.consent||!e.modelConsent||!e.webConsent||!e.retrieval||!e.providerPolicy||!e.entitlement||!e.session)return false;
    if(s.modelConsent.epoch!=e.modelConsent||s.webConsent.epoch!=e.webConsent||(s.search&&!validSearch(*s.search)))return false;
    const bool granted=s.modelConsent.granted||s.webConsent.granted;
    if(s.storage==StorageState::Uninitialized&&(s.credential!=CredentialState::Absent||granted))return false;
    if((s.storage==StorageState::Busy||s.storage==StorageState::UnsafeRoot||s.storage==StorageState::Unreadable)&&(s.credential!=CredentialState::Unavailable||granted))return false;
    if(s.storage==StorageState::Corrupt&&(s.credential!=CredentialState::Corrupt||granted))return false;
    if(s.storage==StorageState::IoUncertain&&granted)return false;
    if(s.modelConsent.granted&&s.modelConsent.profileRef!=s.selectedProfileRef)return false;
    if(s.webConsent.granted&&(!s.search||s.webConsent.profileRef!=s.selectedProfileRef||s.search->webConsentEpoch!=e.webConsent))return false;
    return true;
}
Digest256 digest(const std::string &domain,const unsigned char *bytes,std::size_t size) {
    Digest256 result{};if(domain.empty()||domain.find('\0')!=std::string::npos||size>std::size_t(std::numeric_limits<qsizetype>::max())||(!bytes&&size))return result;
    QCryptographicHash hash(QCryptographicHash::Sha256);hash.addData(QByteArrayView(domain.data(),qsizetype(domain.size())));hash.addData(QByteArrayView("\0",1));hash.addData(QByteArrayView(reinterpret_cast<const char *>(bytes),qsizetype(size)));
    const auto value=hash.result();for(std::size_t i=0;i<result.size();++i)result[i]=static_cast<unsigned char>(value[qsizetype(i)]);return result;
}
}
