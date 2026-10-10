#include "DestinationEvidence.h"
#include "WebSearch.h"
#include "assistance/retrieval/StrictJson.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QStringDecoder>
#include <algorithm>
#include <array>
#include <limits>
#ifdef Q_OS_WIN
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

namespace gatebouncer::websearch {
namespace {
struct Address { std::array<unsigned char,16> bytes{};unsigned bits=0;QString canonical; };
std::optional<Address> address(const QString& input) {
    if(input.isEmpty()||input.size()>45||input.contains('%')||input.contains('/')||input.contains('[')||input.contains(']'))return {};
    for(auto ch:input)if(!(ch.isDigit()||QStringLiteral("abcdefABCDEF:.").contains(ch)))return {};
#ifdef Q_OS_WIN
    Address out;const int family=input.contains(':')?AF_INET6:AF_INET;
    const auto wide=input.toStdWString();
    if(InetPtonW(family,wide.c_str(),out.bytes.data())!=1)return {};
    wchar_t rendered[46]{};
    if(!InetNtopW(family,out.bytes.data(),rendered,46))return {};
    out.bits=family==AF_INET?32:128;out.canonical=QString::fromWCharArray(rendered).toLower();return out;
#else
    return {};
#endif
}
bool prefix(const Address& value,const Address& network,unsigned bits) {
    if(value.bits!=network.bits||bits>value.bits)return false;
    for(unsigned n=0;n<bits;++n)if((value.bytes[n/8]&(0x80>>(n%8)))!=(network.bytes[n/8]&(0x80>>(n%8))))return false;
    return true;
}
bool special(const Address& value,const char* cidr) {
    const QString text=QString::fromLatin1(cidr);const auto parts=text.split('/');bool ok=false;
    const auto network=address(parts.front());const auto bits=parts.back().toUInt(&ok);
    return network&&ok&&prefix(value,*network,bits);
}
bool global(const Address& value) {
    if(value.bits==32){
        // Exclusión de espacio especial: privacidad, no definición de zonas del firewall.
        for(const auto* block:{"0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16",
            "172.16.0.0/12","192.0.0.0/24","192.0.2.0/24","192.31.196.0/24","192.52.193.0/24",
            "192.88.99.0/24","192.168.0.0/16","192.175.48.0/24","198.18.0.0/15","198.51.100.0/24",
            "203.0.113.0/24","224.0.0.0/4","240.0.0.0/4"})if(special(value,block))return false;
        return true;
    }
    return special(value,"2000::/3")&&!special(value,"2001::/23")&&!special(value,"2001:db8::/32")&&
        !special(value,"2002::/16")&&!special(value,"2620:4f:8000::/48")&&!special(value,"3fff::/20");
}
const std::array<const char*,5> Bases{{"https://rdap.arin.net/registry/","https://rdap.db.ripe.net/",
    "https://rdap.apnic.net/","https://rdap.lacnic.net/rdap/","https://rdap.afrinic.net/rdap/"}};
std::optional<QJsonObject> json(const QByteArray& bytes) {
    if(bytes.isEmpty()||bytes.size()>256*1024)return {};
    if(!Gate::Assistance::Retrieval::strictJson(bytes,256*1024))return {};
    QStringDecoder decoder(QStringDecoder::Utf8);decoder(bytes);if(decoder.hasError())return {};
    int depth=0;bool quoted=false,escaped=false;
    for(char ch:bytes){if(quoted){if(escaped)escaped=false;else if(ch=='\\')escaped=true;else if(ch=='"')quoted=false;}
        else if(ch=='"')quoted=true;else if(ch=='{'||ch=='['){if(++depth>12)return {};}
        else if(ch=='}'||ch==']'){if(--depth<0)return {};}}
    if(depth||quoted)return {};
    QJsonParseError error;const auto doc=QJsonDocument::fromJson(bytes,&error);
    return error.error==QJsonParseError::NoError&&doc.isObject()?std::optional<QJsonObject>(doc.object()):std::nullopt;
}
QString plain(QString value,int cap) {
    value.remove(QRegularExpression(QStringLiteral("[\\x00-\\x1f\\x7f<>]")));
    QString clean;for(auto c:value)if(c.category()!=QChar::Other_Control&&c.category()!=QChar::Other_Format&&!c.isSurrogate()&&c.unicode()!=0x2028&&c.unicode()!=0x2029)clean+=c;
    return clean.simplified().left(cap);
}
bool response(const HttpResponse& r,const QByteArray& expected) {
    const auto type=r.contentType.toLower().split(';').front().trimmed();
    return r.transportOk&&r.statusCode==200&&!r.body.isEmpty()&&r.body.size()<=256*1024&&
        (type==expected||(expected=="application/rdap+json"&&type=="application/json"))&&
        (r.contentEncoding.isEmpty()||r.contentEncoding.toLower().trimmed()=="identity");
}
}
bool Destination::operator==(const Destination& d) const {
    return address==d.address&&port==d.port&&protocol==d.protocol&&observedAtMs==d.observedAtMs;
}
std::optional<QString> canonicalAddress(const QString& input){const auto parsed=address(input);return parsed?std::optional<QString>(parsed->canonical):std::nullopt;}
bool publicDestination(const Destination& d){const auto parsed=address(d.address);return parsed&&parsed->canonical==d.address&&global(*parsed)&&d.observedAtMs&&d.observedAtMs<=quint64(INT64_MAX)&&(d.protocol==6||d.protocol==17);}
QUrl bootstrapUrl(const Destination& d){return publicDestination(d)?QUrl(d.address.contains(':')?"https://data.iana.org/rdap/ipv6.json":"https://data.iana.org/rdap/ipv4.json"):QUrl{};}
QUrl adobeEndpointsUrl(){return QUrl("https://helpx.adobe.com/business/enterprise/manage-services/configure-services/network-endpoints.html");}
std::optional<QUrl> registryUrl(const QByteArray& bytes,const Destination& d) {
    if(!publicDestination(d))return {};
    const auto value=address(d.address);const auto root=json(bytes);if(!root||root->value("version")!="1.0"||!root->value("services").isArray())return {};
    const auto services=root->value("services").toArray();if(services.isEmpty()||services.size()>1024)return {};
    int longest=-1;std::optional<QUrl> result;
    for(const auto& item:services){if(!item.isArray())return {};const auto pair=item.toArray();
        if(pair.size()!=2||!pair[0].isArray()||!pair[1].isArray())return {};
        const auto ranges=pair[0].toArray(),urls=pair[1].toArray();if(ranges.size()>1024||urls.size()>8)return {};
        for(const auto& range:ranges){if(!range.isString())return {};const auto parts=range.toString().split('/');bool ok=false;
            if(parts.size()!=2)return {};const auto base=address(parts[0]);const auto bits=parts[1].toUInt(&ok);
            if(!base||!ok||bits>base->bits)return {};
            if(!prefix(*value,*base,bits)||int(bits)<longest)continue;
            for(const auto& url:urls){if(!url.isString())return {};const auto encoded=url.toString().toUtf8();
                if(std::none_of(Bases.begin(),Bases.end(),[&](const char* known){return encoded==known;}))continue;
                const QUrl next(QString::fromUtf8(encoded)+"ip/"+d.address,QUrl::StrictMode);
                if(int(bits)==longest&&result&&*result!=next)return {};
                longest=int(bits);result=next;}
        }
    }
    return result;
}
bool validResource(Resource kind,const QUrl& url,const std::optional<Destination>& d) {
    if(!d||!publicDestination(*d)||!url.isValid()||url.hasQuery()||url.hasFragment()||url.scheme()!="https"||
        !url.userName().isEmpty()||!url.password().isEmpty()||url.port(443)!=443)return false;
    if(kind==Resource::Bootstrap4||kind==Resource::Bootstrap6)return url==bootstrapUrl(*d)&&
        (kind==Resource::Bootstrap6)==d->address.contains(':');
    if(kind==Resource::AdobeEndpoints)return url==adobeEndpointsUrl();
    if(kind!=Resource::Registry)return false;
    return std::any_of(Bases.begin(),Bases.end(),[&](const char* base){return url==QUrl(QString::fromLatin1(base)+"ip/"+d->address,QUrl::StrictMode);});
}
std::optional<Citation> registrationEvidence(const HttpResponse& r,const Destination& d,const QUrl& url,quint64 checked) {
    if(!checked||checked>quint64(INT64_MAX)||!validResource(Resource::Registry,url,d)||!response(r,"application/rdap+json"))return {};
    const auto root=json(r.body);if(!root||root->value("objectClassName")!="ip network")return {};
    const auto ip=address(d.address),start=address(root->value("startAddress").toString()),end=address(root->value("endAddress").toString());
    if(!ip||!start||!end||ip->bits!=start->bits||ip->bits!=end->bits||
        root->value("ipVersion").toString()!=(ip->bits==32?"v4":"v6"))return {};
    const auto bytes=ip->bits/8;
    if(std::lexicographical_compare(ip->bytes.begin(),ip->bytes.begin()+bytes,start->bytes.begin(),start->bytes.begin()+bytes)||
        std::lexicographical_compare(end->bytes.begin(),end->bytes.begin()+bytes,ip->bytes.begin(),ip->bytes.begin()+bytes))return {};
    QString organization;
    const auto entities=root->value("entities").toArray();if(entities.size()>64)return {};
    for(const auto& entry:entities){const auto entity=entry.toObject();const auto roles=entity.value("roles").toArray();bool registrant=false;
        for(const auto& role:roles)registrant|=role.toString()=="registrant";
        if(!registrant)continue;
        const auto vcard=entity.value("vcardArray").toArray();if(vcard.size()!=2||vcard[0]!="vcard"||!vcard[1].isArray())continue;
        const auto fields=vcard[1].toArray();if(fields.size()>128)return {};
        for(const auto& field:fields){const auto values=field.toArray();if(values.size()==4&&values[0]=="fn"&&values[2]=="text"&&values[3].isString()){
            const auto name=plain(values[3].toString(),96);if(organization.isEmpty())organization=name;else if(organization!=name)organization="Unknown (multiple registrants)";}}
    }
    if(organization.isEmpty())organization="Unknown";
    Citation citation;citation.title="IP network registration";citation.url=url;citation.origin="RDAP / "+url.host();
    citation.retrievalUtc=QDateTime::fromMSecsSinceEpoch(qint64(checked),Qt::UTC);citation.kind=1;citation.subject=d.address;
    citation.snippet="Registered organization: "+organization+". Block: "+start->canonical+" – "+end->canonical+
        ". Registration does not identify the final service, routing ASN, telemetry purpose or safety.";
    return citation;
}
std::optional<Citation> officialDestinationEvidence(const HttpResponse& r,const Destination& d,quint64 checked) {
    if(!checked||checked>quint64(INT64_MAX)||!publicDestination(d)||!response(r,"text/html"))return {};
    QStringDecoder decoder(QStringDecoder::Utf8);QString html=decoder(r.body);if(decoder.hasError())return {};
    html.remove(QRegularExpression("<(script|style|noscript)[^>]*>.*?</\\1>",QRegularExpression::CaseInsensitiveOption|QRegularExpression::DotMatchesEverythingOption));
    html.remove(QRegularExpression("<!--.*?-->",QRegularExpression::DotMatchesEverythingOption));
    html.remove(QRegularExpression("<[^>]*>"));html.replace("&amp;","&");html.replace("&nbsp;"," ");
    // Sólo coincidencia IP literal en documento oficial fijo; nunca reverse DNS ni empresa=servicio.
    const QRegularExpression literal("(?<![0-9A-Fa-f:.])"+QRegularExpression::escape(d.address)+"(?![0-9A-Fa-f:.])",QRegularExpression::CaseInsensitiveOption);
    const auto match=literal.match(html);if(!match.hasMatch())return {};
    auto excerpt=html.mid(std::max<qsizetype>(0,match.capturedStart()-180),400);
    excerpt.remove(QRegularExpression("<[^>]*>"));excerpt.replace("&amp;","&");excerpt.replace("&nbsp;"," ");
    Citation citation;citation.title="Adobe documented network endpoint";citation.url=adobeEndpointsUrl();citation.origin="Adobe official documentation";
    citation.retrievalUtc=QDateTime::fromMSecsSinceEpoch(qint64(checked),Qt::UTC);citation.kind=2;citation.subject=d.address;
    citation.snippet=plain(excerpt,320)+". Exact IP appears in this document; shared hosting and connection purpose remain uncertain.";
    return citation;
}
}
