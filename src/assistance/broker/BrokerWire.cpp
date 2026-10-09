#include "BrokerWire.h"
#include "general/GeneralWire.h"
#include "retrieval/Contracts.h"
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QStringDecoder>
#include <cstring>
#include <set>

namespace Gate::Assistance::Broker {
quint64 number(const QByteArray &b) { quint64 n = 0; for (qsizetype i = 0; i < b.size() && i < 8; ++i) n |= quint64(static_cast<unsigned char>(b[i])) << (8*i); return n; }
QByteArray integer(quint64 n, size_t size) { QByteArray b(qsizetype(size), '\0'); for (size_t i = 0; i < size; ++i) b[qsizetype(i)] = char(n >> (8*i)); return b; }
static bool text(const QByteArray &b, int limit) {
    if (b.isEmpty() || b.size() > limit || b.contains('\0')) return false;
    QStringDecoder decoder(QStringDecoder::Utf8); const QString s = decoder(b);
    if (decoder.hasError()) return false;
    for (auto c : s) if (c.category() == QChar::Other_Control || c.category() == QChar::Other_Format || c.category() == QChar::Other_Surrogate || c.unicode() == 0x2028 || c.unicode() == 0x2029) return false;
    return true;
}
bool validFrame(const Frame &f,WireVersion version) {
    if(version==WireVersion::General3)return General::validGeneralFrame(f);
    if(version==WireVersion::Grounded2){
        if(f.message==Message::Configure||f.message==Message::ConfigureAck||f.message==Message::Forget||f.message==Message::ForgetAck)return validFrame(f,WireVersion::Legacy1);
        if(f.secret.size())return false;
        Retrieval::Frame grounded{quint16(f.message),f.connection,f.correlation,f.sequence,f.fields};return bool(Retrieval::encodeFrame(grounded));
    }
    if(version!=WireVersion::Legacy1)return false;
    if (!nonzero(f.connection) || !nonzero(f.correlation) || !f.sequence || f.fields.size() > 32) return false;
    std::set<quint16> required, optional;
    switch (f.message) {
    case Message::StatusRequest:
        if (f.fields.empty()) break;
        required = f.fields.count(33) ? std::set<quint16>{33} : std::set<quint16>{30,31,32}; break;
    case Message::StatusReply: required={1,2,3,4,5,6,7}; optional={34}; break;
    case Message::Explain: required={10,11,12,13,14,15,16,17,18,19,20}; break;
    case Message::Explanation: required={10,11,12,13,14,15,16,17,18,19,21,22,23}; optional={24}; break;
    case Message::Cancel: required={25}; break;
    case Message::CancelAck: required={21}; break;
    case Message::Configure: required={34}; if (f.secret.size()<1 || f.secret.size()>512) return false; break;
    case Message::ConfigureAck: case Message::ForgetAck: required={2,4,23}; break;
    case Message::Forget: required={34}; break;
    case Message::ErrorReply: required={23}; break;
    default: return false;
    }
    if (f.message != Message::Configure && f.secret.size()) return false;
    for (auto tag : required) if (!f.fields.count(tag)) return false;
    for (const auto &[tag,b] : f.fields) {
        if (!required.count(tag) && !optional.count(tag)) return false;
        switch (tag) {
        case 1: if (b.size()!=1 || number(b)>6) return false; break;
        case 2: if (b.size()!=1 || number(b)>2) return false; break;
        case 6: case 18: case 19: case 31: case 32: if (b.size()!=1 || number(b)>1) return false; break;
        case 7: if (b.size()!=2 || number(b)>63) return false; break;
        case 3: case 4: case 5: case 12: case 13: case 14: case 15: case 16: case 17: if (b.size()!=8) return false; break;
        case 10: if (!text(b,128)) return false; break;
        case 11: if (!text(b,512)) return false; break;
        case 20: if (b.size()!=4 || number(b)<1 || number(b)>2) return false; break;
        case 21: if (b.size()!=1 || number(b)<1 || number(b)>6) return false; break;
        case 22: { const auto n=number(b); if(b.size()!=2 || (n!=0 && n!=200 && n!=202 && (n<300 || n>599))) return false; break; }
        case 23: if (b.size()!=2 || number(b)>16) return false; break;
        case 24: {QStringDecoder decoder(QStringDecoder::Utf8);decoder(b);if (b.isEmpty() || b.size()>2048 || decoder.hasError() || !parseExplanationEnvelope(envelopeFromExplanation(b))) return false; break;}
        case 25: case 34: if(b.size()!=16) return false; { Id id{}; std::memcpy(id.data(),b.data(),16); if(!nonzero(id)) return false; } break;
        case 30: if (b.size()!=2 || number(b)!=1) return false; break;
        case 33: if (b.size()!=1 || number(b)<1 || number(b)>2) return false; break;
        default: return false;
        }
    }
    if (f.message == Message::CancelAck && number(f.fields.at(21))!=3 && number(f.fields.at(21))!=6) return false;
    if (f.message == Message::Explanation) {
        const auto outcome=number(f.fields.at(21)), http=number(f.fields.at(22)), error=number(f.fields.at(23));
        if (outcome==1) { if(http!=200 || error!=0 || !f.fields.count(24)) return false; }
        else if (f.fields.count(24) || error==0) return false;
        if (outcome==2 && (error!=14 || (http!=0 && http!=202))) return false;
        if (outcome==3 && (http!=0 || error!=11)) return false;
    }
    for (size_t i=0; i<f.secret.size(); ++i) if(f.secret.data()[i]<33 || f.secret.data()[i]>126) return false;
    return true;
}
std::optional<Frame> decodeFrame(const unsigned char *d, size_t n,WireVersion version) {
    if (n<64 || n>8192 || std::memcmp(d,"GBAS",4)) return {};
    auto num=[&](size_t pos,size_t len){return number(QByteArray(reinterpret_cast<const char *>(d+pos),qsizetype(len)));};
    if(num(4,2)!=quint16(version) || num(6,2)!=0 || num(10,2) || num(12,4)!=n-64 || num(56,8)) return {};
    Frame f; f.message=Message(num(8,2)); f.sequence=num(32,8); std::memcpy(f.connection.data(),d+16,16); std::memcpy(f.correlation.data(),d+40,16);
    size_t p=64, count=0;
    while(p<n) {
        if(n-p<8 || ++count>32) return {};
        const auto tag=quint16(num(p,2)); const auto flags=num(p+2,2), length=num(p+4,4); p+=8;
        if(flags!=1 || length>n-p || f.fields.count(tag) || (tag==26 && f.secret.size())) return {};
        if(tag==26) { if(length<1 || length>512) return {}; f.secret=SensitiveBytes(size_t(length)); std::memcpy(f.secret.data(),d+p,size_t(length)); }
        else f.fields.emplace(tag,QByteArray(reinterpret_cast<const char *>(d+p),qsizetype(length)));
        p+=size_t(length);
    }
    return validFrame(f,version) ? std::optional<Frame>(std::move(f)) : std::nullopt;
}
std::optional<SensitiveBytes> encodeFrame(const Frame &f,WireVersion version) {
    if(!validFrame(f,version)) return {};
    size_t size=64; for(const auto &[tag,b]:f.fields) { Q_UNUSED(tag); size+=8+size_t(b.size()); } if(f.secret.size()) size+=8+f.secret.size();
    if(size>8192) return {};
    SensitiveBytes bytes(size); auto *d=bytes.data();
    auto put=[&](size_t pos,quint64 value,size_t count){for(size_t i=0;i<count;++i)d[pos+i]=static_cast<unsigned char>(value>>(i*8));};
    std::memcpy(d,"GBAS",4); put(4,quint16(version),2); put(8,quint16(f.message),2); put(12,size-64,4); std::memcpy(d+16,f.connection.data(),16); put(32,f.sequence,8); std::memcpy(d+40,f.correlation.data(),16);
    size_t p=64; for(const auto &[tag,b]:f.fields) { put(p,tag,2); put(p+2,1,2); put(p+4,quint64(b.size()),4); p+=8; std::memcpy(d+p,b.data(),size_t(b.size())); p+=size_t(b.size()); }
    if(f.secret.size()) {put(p,26,2);put(p+2,1,2);put(p+4,f.secret.size(),4);std::memcpy(d+p+8,f.secret.data(),f.secret.size());}
    return bytes;
}
std::optional<RequestBinding> binding(const Frame &f) {
    if(f.message!=Message::Explain && f.message!=Message::Explanation) return {};
    if(!validFrame(f)) return {};
    RequestBinding b; b.context.requestId=QString::fromUtf8(f.fields.at(10)); b.context.applicationIdentity=QString::fromUtf8(f.fields.at(11));
    b.context.snapshotRevision=number(f.fields.at(12)); b.context.serviceEpoch=number(f.fields.at(13)); b.context.sessionEpoch=number(f.fields.at(14));
    b.consentEpoch=number(f.fields.at(15)); b.credentialEpoch=number(f.fields.at(16)); b.generation=number(f.fields.at(17)); b.context.pending=number(f.fields.at(18)); b.context.serviceAvailable=number(f.fields.at(19)); return b;
}
void setBinding(Frame &f,const RequestBinding &b) {
    f.fields[10]=b.context.requestId.toUtf8(); f.fields[11]=b.context.applicationIdentity.toUtf8();
    f.fields[12]=integer(b.context.snapshotRevision,8); f.fields[13]=integer(b.context.serviceEpoch,8); f.fields[14]=integer(b.context.sessionEpoch,8);
    f.fields[15]=integer(b.consentEpoch,8);f.fields[16]=integer(b.credentialEpoch,8);f.fields[17]=integer(b.generation,8);f.fields[18]=integer(b.context.pending,1);f.fields[19]=integer(b.context.serviceAvailable,1);
}
QByteArray envelopeFromExplanation(const QByteArray &json) {
    return QJsonDocument(QJsonObject{{"choices",QJsonArray{QJsonObject{{"finish_reason","stop"},{"message",QJsonObject{{"role","assistant"},{"content",QString::fromUtf8(json)}}}}}}}).toJson(QJsonDocument::Compact);
}
std::optional<QByteArray> boundedExplanation(const QByteArray &envelope) {
    const auto t=parseExplanationEnvelope(envelope); if(!t) return {};
    auto json=QJsonDocument(QJsonObject{{"possible_purpose",t->possiblePurpose},{"possible_network_reason",t->possibleNetworkReason},{"caution",t->caution},{"certainty",t->certainty==ExplanationText::Certainty::Possible?"possible":"unclear"}}).toJson(QJsonDocument::Compact);
    return json.size()<=2048 ? std::optional<QByteArray>(json) : std::nullopt;
}
bool FrameReader::feed(const unsigned char *b,size_t n) {
    if(failed_ || n>8192-count_) return !(failed_=true);
    std::memcpy(bytes_.data()+count_,b,n);count_+=n;
    if(count_>=64) {expected_=64+size_t(number(QByteArray(reinterpret_cast<const char *>(bytes_.data()+12),4))); if(expected_>8192) failed_=true;}
    return !failed_;
}
std::optional<Frame> FrameReader::take() {
    if(failed_ || count_<expected_) return {};
    auto f=decodeFrame(bytes_.data(),expected_,version_); if(!f){failed_=true;return {};}
    const auto left=count_-expected_; std::memmove(bytes_.data(),bytes_.data()+expected_,left); SecureZeroMemory(bytes_.data()+left,count_-left); count_=left;expected_=64;
    if(count_>=64) { expected_=64+size_t(number(QByteArray(reinterpret_cast<const char *>(bytes_.data()+12),4)));if(expected_>8192)failed_=true; }
    return f;
}
}
