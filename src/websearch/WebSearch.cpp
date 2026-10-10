#include "WebSearch.h"

#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QStringDecoder>
#include <QThread>
#include <QUuid>
#include <QPointer>
#include <cmath>

namespace gatebouncer::websearch {
namespace {
constexpr qsizetype BodyLimit = 256 * 1024;
class SteadyClock final : public MonotonicClock {
public:
    SteadyClock() { timer_.start(); }
    qint64 milliseconds() const override { return timer_.elapsed(); }
private:
    QElapsedTimer timer_;
};
bool plain(const QString &value, qsizetype limit)
{
    if (value.size() > limit) return false;
    for (const auto ch : value) {
        if (ch.isNull() || ch.category() == QChar::Other_Control
            || ch.category() == QChar::Other_Format || ch.isSurrogate()) return false;
    }
    return true;
}
QString text(const QString &value, qsizetype limit)
{
    QString result;
    for (const auto ch : value) {
        if (result.size() >= limit) break;
        if (ch.category() == QChar::Other_Control || ch.category() == QChar::Other_Format
            || ch.isSurrogate()) result += QLatin1Char(' ');
        else result += ch;
    }
    // Se entrega texto plano; el consumidor debe usar PlainText al mostrarlo.
    result.replace(QLatin1Char('<'), QChar(0x2039));
    result.replace(QLatin1Char('>'), QChar(0x203a));
    return result.simplified();
}
bool safeCitationUrl(const QUrl &url)
{
    return url.isValid() && (url.scheme() == QStringLiteral("https")
        || url.scheme() == QStringLiteral("http")) && !url.host().isEmpty()
        && url.userName().isEmpty() && url.password().isEmpty() && !url.authority().contains(QLatin1Char('@'))
        && url.toEncoded().size() <= 2048;
}
}
bool validConfiguration(const ProviderConfig &config)
{
    if (config.provider != Provider::MwmblV2 && config.provider != Provider::SearXng) return false;
    const auto &u = config.endpoint;
    if (!u.isValid() || u.scheme() != QStringLiteral("https") || u.hasQuery()
        || u.hasFragment() || !u.userName().isEmpty() || !u.password().isEmpty()
        || u.authority().contains(QLatin1Char('@'))
        || u.toEncoded().size() > 2048 || !plain(config.revision, 128)
        || config.revision.trimmed().isEmpty()) return false;
    if (config.provider == Provider::MwmblV2)
        return u.toEncoded() == QByteArrayLiteral("https://api.mwmbl.org/api/v2/search/");
    static const QRegularExpression host(QStringLiteral(
        "^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$"));
    static const QRegularExpression ip(QStringLiteral("^[0-9.]+$"));
    static const QRegularExpression path(QStringLiteral("^(?:/[A-Za-z0-9_-]+)*/search/?$"));
    return host.match(u.host()).hasMatch() && !ip.match(u.host()).hasMatch()
        && path.match(u.path(QUrl::FullyEncoded)).hasMatch()
        && u.port(443) > 0 && u.port(443) <= 65535;
}
bool validPublicQuery(const QString &query)
{
    if (query.trimmed().isEmpty() || !plain(query, 256)) return false;
    // No ejecutar bangs/filtros ni enviar paths, URLs o correos como consulta pública.
    for (const auto ch : query) {
        if (!(ch.isLetterOrNumber() || ch.isSpace() || QStringLiteral(".-_+()").contains(ch)))
            return false;
    }
    return QUrl::toPercentEncoding(query).size() <= 4096;
}
QByteArray configurationBinding(const ProviderConfig &config)
{
    if (!validConfiguration(config)) return {};
    const QByteArray material = QByteArray::number(int(config.provider)) + '\n'
        + config.endpoint.toEncoded() + '\n' + config.revision.toUtf8() + '\n'
        + QByteArrayLiteral("web-disclosure-v3|IANA-RDAP5|Adobe-fixed|destination-profile2");
    return QCryptographicHash::hash(material, QCryptographicHash::Sha256).toHex();
}
QString disclosure(const ProviderConfig &config)
{
    if (config.provider == Provider::MwmblV2)
        return QStringLiteral("Automatic explanations send the executable name observed for each current request to Mwmbl. "
            "An approved public destination IP is looked up through IANA and one of the five regional Internet registries. Internal or reserved addresses are never sent. "
            "Adobe endpoint evidence uses its fixed official network documentation; the destination itself is never contacted. "
            "The approved IP, port, protocol and retrieved registration or official evidence may be sent to NVIDIA under the separate model notice. Registration is not proof of a service or telemetry. "
            "The name can reveal which app you use; it does not verify the file's identity. Publisher is included only if you review it manually. "
            "Names and public search snippets are used for NVIDIA explanations under the separate model notice. Paths, file hashes, file contents and local signature details are not sent. "
            "Standard searches may be shared with external sources and TypeSafe AI; "
            "pages and query keywords may enter a public index. Your connection IP is processed. "
            "Coverage is limited. Results do not certify the safety of this executable. "
            "You can revoke this consent. Mwmbl terms and privacy policy apply.");
    return QStringLiteral("Automatic explanations send the executable name observed for each current request to your configured "
        "SearXNG server. Approved public destination IPs are looked up through IANA and one of the five regional Internet registries. Internal or reserved addresses are never sent. "
        "Adobe endpoint evidence uses its fixed official network documentation; the destination itself is never contacted. "
        "Approved IP, port, protocol and retrieved evidence may be sent to NVIDIA under the separate model notice. Registration is not proof of a service or telemetry. "
        "The name can reveal which app you use; it does not verify the file's identity. Publisher is included only if you review it manually. "
        "Names and public search snippets are used for NVIDIA explanations under the separate model notice. Paths, file hashes, file contents and local signature details are not sent. "
        "Searches use the configured "
        "SearXNG server and its search engines. The server operator can observe queries; "
        "upstream providers apply their own privacy policies and terms. Results do not "
        "certify the safety of this executable. You can revoke this consent.");
}
SearchResult parseResponse(const HttpResponse &response, SearchResult result,
                           const QDateTime &retrievalUtc)
{
    result.status = Status::Unavailable;
    result.citations.clear();
    if (result.provider != Provider::MwmblV2 && result.provider != Provider::SearXng) return result;
    const auto type = response.contentType.toLower().split(';');
    if (!response.transportOk || response.statusCode != 200 || response.body.size() > BodyLimit
        || type.isEmpty() || type.first().trimmed() != QByteArrayLiteral("application/json")
        || (!response.contentEncoding.isEmpty()
            && response.contentEncoding.toLower().trimmed() != QByteArrayLiteral("identity"))) return result;
    for (qsizetype i = 1; i < type.size(); ++i) {
        const auto parameter = type[i].trimmed();
        if (parameter.startsWith("charset=") && parameter != "charset=utf-8"
            && parameter != "charset=\"utf-8\"") return result;
    }
    QStringDecoder decoder(QStringDecoder::Utf8);
    const QString decoded = decoder.decode(response.body);
    if (decoder.hasError()) return result;
    // Acotar profundidad antes de que el parser reserve un árbol de datos.
    int depth = 0;
    bool quoted = false, escaped = false;
    for (const auto ch : decoded) {
        if (quoted) {
            if (escaped) escaped = false;
            else if (ch == QLatin1Char('\\')) escaped = true;
            else if (ch == QLatin1Char('"')) quoted = false;
        } else if (ch == QLatin1Char('"')) quoted = true;
        else if (ch == QLatin1Char('{') || ch == QLatin1Char('[')) { if (++depth > 12) return result; }
        else if (ch == QLatin1Char('}') || ch == QLatin1Char(']')) --depth;
    }
    QJsonParseError error;
    const auto doc = QJsonDocument::fromJson(response.body, &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject()) return result;
    const auto root = doc.object();
    if (!root.value(QStringLiteral("results")).isArray()) return result;
    if (result.provider == Provider::MwmblV2) {
        const auto count = root.value(QStringLiteral("number_of_results"));
        if (!root.value(QStringLiteral("query")).isString()
            || root.value(QStringLiteral("query")).toString() != result.input.publicQuery
            || !count.isDouble() || count.toDouble() < 0
            || std::floor(count.toDouble()) != count.toDouble()) return result;
    }
    const auto items = root.value(QStringLiteral("results")).toArray();
    if (items.size() > 100 || (result.provider == Provider::MwmblV2
        && root.value(QStringLiteral("number_of_results")).toDouble() != items.size())) return result;
    QVector<Citation> citations;
    for (const auto &item : items) {
        if (!item.isObject()) return result;
        const auto obj = item.toObject();
        if (!obj.value(QStringLiteral("url")).isString() || !obj.value(QStringLiteral("title")).isString()
            || (!obj.value(QStringLiteral("content")).isUndefined()
                && !obj.value(QStringLiteral("content")).isString())) return result;
        if (result.provider == Provider::MwmblV2
            && (!obj.value(QStringLiteral("content")).isString()
                || !obj.value(QStringLiteral("engine")).isString())) return result;
        const auto urlString = obj.value(QStringLiteral("url")).toString();
        const auto url = QUrl(urlString, QUrl::StrictMode);
        if (!plain(urlString, 2048) || !safeCitationUrl(url)) continue;
        const auto title = text(obj.value(QStringLiteral("title")).toString(), 160);
        if (title.isEmpty() || citations.size() >= 5) continue;
        bool duplicate = false;
        for (const auto &citation : citations) if (citation.url == url) duplicate = true;
        if (!duplicate) citations.push_back({title,
            text(obj.value(QStringLiteral("content")).toString(), 1200), url,
            (result.provider == Provider::MwmblV2 ? QStringLiteral("Mwmbl / ") : QStringLiteral("SearXNG / "))
                + text(obj.value(QStringLiteral("engine")).toString(), 64), retrievalUtc.toUTC()});
    }
    result.citations = std::move(citations);
    result.status = result.citations.isEmpty() ? Status::NoEvidence : Status::Evidence;
    return result;
}
SearchClient::SearchClient(std::shared_ptr<Transport> transport, QObject *parent,
                           std::shared_ptr<MonotonicClock> clock)
    : QObject(parent), transport_(std::move(transport)), instance_(QUuid::createUuid().toByteArray()),
      clock_(clock ? std::move(clock) : std::make_shared<SteadyClock>())
{
    qRegisterMetaType<SearchResult>();
    timer_.setInterval(25);
    connect(&timer_, &QTimer::timeout, this, &SearchClient::tick);
}
SearchClient::~SearchClient() { timer_.stop(); if (exchange_) exchange_->cancel(); }
bool SearchClient::configure(const ProviderConfig &config)
{
    if (QThread::currentThread() != thread() || !validConfiguration(config)) return false;
    const auto next = websearch::configurationBinding(config);
    if (next != binding_) { revokeConsent(); binding_ = next;destinationCache_.clear();bootstrap4_.clear();bootstrap6_.clear(); }
    config_ = config;
    return true;
}
QByteArray SearchClient::configurationBinding() const { return binding_; }
QByteArray SearchClient::instanceToken() const { return instance_; }
QString SearchClient::disclosure() const { return websearch::disclosure(config_); }
bool SearchClient::grantConsent(const QByteArray &binding)
{
    if (QThread::currentThread() != thread() || binding.isEmpty() || binding != binding_) return false;
    consent_ = binding;
    return true;
}
void SearchClient::revokeConsent() { consent_.clear(); cancel(); }
bool SearchClient::begin(const SearchInput &input,std::function<bool()> current)
{
    if (QThread::currentThread() != thread() || working_ || !transport_ || binding_.isEmpty()
        || consent_ != binding_ || !validPublicQuery(input.publicQuery)
        || !plain(input.requestId, 128) || input.requestId.isEmpty()
        || (input.destination&&(!current||!publicDestination(*input.destination)))) return false;
    const auto now = clock_->milliseconds();
    if(input.destination){const auto key=input.destination->address+'\n'+input.publicQuery;
        for(const auto& cached:destinationCache_)if(cached.key==key&&now>=cached.at&&now-cached.at<600000){
            active_={input,instance_,binding_,config_.provider,Status::Unavailable,cached.evidence};
            current_=std::move(current);working_=true;reusedDestinationCache_=true;
            finishEvidence();return true;
        }
    }
    while (!budget_.isEmpty() && now - budget_.first() >= 3600000) budget_.removeFirst();
    if (now - lastStart_ < 10000 || budget_.size() >= 30
        || (input.publicQuery == lastQuery_ && now - lastQueryAt_ < 600000)) return false;
    active_ = {input, instance_, binding_, config_.provider, Status::Unavailable, {}};
    current_=std::move(current);
    working_=true;reusedDestinationCache_=false;resource_=Resource::Search;resourceUrl_={};
    QPointer<SearchClient> self(this);if(!sourceCurrent()){if(self&&working_)complete(Status::Cancelled);return true;}if(!self)return true;
    lastStart_ = now;
    budget_.append(now);
    lastQuery_ = input.publicQuery;
    lastQueryAt_ = now;
    const auto transport=transport_;auto operation=transport->start({config_, input.publicQuery,Resource::Search,{},{}});
    if(!self){if(operation)operation->cancel();return true;}
    if(!sourceCurrent()){if(operation)operation->cancel();if(self&&working_)complete(Status::Cancelled);return true;}if(!self){if(operation)operation->cancel();return true;}
    exchange_=std::move(operation);
    if (!exchange_) {
        working_=false;current_={};const auto result = active_;
        QMetaObject::invokeMethod(this, [this, result] { emit finished(result); }, Qt::QueuedConnection);
        return true;
    }
    deadline_ = now + (input.destination?40000:15000);
    timer_.start();
    return true;
}
void SearchClient::complete(Status status)
{
    timer_.stop();
    working_=false;
    current_={};
    auto result = active_;
    result.status = status;
    result.citations.clear();
    const auto operation = std::move(exchange_);
    QMetaObject::invokeMethod(this, [this, result] { emit finished(result); }, Qt::QueuedConnection);
    if (operation) operation->cancel();
}
void SearchClient::cancel() { if (working_) complete(Status::Cancelled); }
bool SearchClient::sourceCurrent(){
    const auto proof=current_;const auto input=active_.input;const auto binding=binding_;QPointer<SearchClient> self(this);
    const bool valid=proof?proof():!input.destination;
    return self&&valid&&working_&&binding_==binding&&consent_==binding&&active_.input.requestId==input.requestId&&
        active_.input.generation==input.generation&&active_.input.publicQuery==input.publicQuery&&active_.input.destination==input.destination;
}
bool SearchClient::startResource(Resource kind,const QUrl& url) {
    if(!working_||exchange_||consent_!=binding_||!validResource(kind,url,active_.input.destination))return false;
    QPointer<SearchClient> self(this);if(!sourceCurrent()){if(self&&working_)complete(Status::Cancelled);return false;}if(!self)return false;
    const auto now=clock_->milliseconds();
    if(now<lastStart_||now>=deadline_)return false;
    while(!budget_.isEmpty()&&now-budget_.first()>=3600000)budget_.removeFirst();
    if(now-lastStart_<10000)return false;
    // Cada GET consume el mismo presupuesto y cooldown que la búsqueda; sin cupo nuevo.
    if(budget_.size()>=30){finishEvidence();return false;}
    lastStart_=now;budget_.append(now);resource_=kind;resourceUrl_=url;
    const auto transport=transport_;auto operation=transport->start({config_,active_.input.publicQuery,kind,url,active_.input.destination});
    if(!self){if(operation)operation->cancel();return false;}
    if(!sourceCurrent()){if(operation)operation->cancel();if(self&&working_)complete(Status::Cancelled);return false;}if(!self){if(operation)operation->cancel();return false;}
    exchange_=std::move(operation);
    if(!exchange_)finishEvidence();
    return bool(exchange_);
}
void SearchClient::finishEvidence() {
    if(!working_)return;
    QPointer<SearchClient> self(this);if(!sourceCurrent()){if(self&&working_)complete(Status::Cancelled);return;}if(!self)return;
    timer_.stop();working_=false;current_={};
    auto result=active_;result.status=result.citations.isEmpty()?Status::NoEvidence:Status::Evidence;
    if(result.citations.size()>3)result.citations.resize(3);
    if(result.input.destination&&!reusedDestinationCache_){QVector<Citation> evidence;
        for(const auto& c:result.citations)if(c.kind)evidence.push_back(c);
        if(!evidence.isEmpty()){const auto key=result.input.destination->address+'\n'+result.input.publicQuery;
            for(qsizetype n=destinationCache_.size();n>0;--n)if(destinationCache_[n-1].key==key)destinationCache_.removeAt(n-1);
            if(destinationCache_.size()>=32)destinationCache_.removeFirst();
            destinationCache_.push_back({key,std::move(evidence),clock_->milliseconds()});}}
    QMetaObject::invokeMethod(this,[this,result]{emit finished(result);},Qt::QueuedConnection);
}
void SearchClient::nextResource() {
    if(!working_||exchange_)return;
    if(consent_!=binding_){complete(Status::Cancelled);return;}
    const auto now=clock_->milliseconds();
    if(now<lastStart_||now>=deadline_){finishEvidence();return;}
    if(!active_.input.destination){finishEvidence();return;}
    const auto& destination=*active_.input.destination;
    const auto key=destination.address+'\n'+active_.input.publicQuery;
    if(resource_==Resource::Search){
        for(const auto& cached:destinationCache_)if(cached.key==key&&now>=cached.at&&now-cached.at<600000){
            for(qsizetype n=cached.evidence.size();n>0;--n)active_.citations.prepend(cached.evidence[n-1]);
            reusedDestinationCache_=true;
            finishEvidence();return;}
        const bool ipv6=destination.address.contains(':');const auto& data=ipv6?bootstrap6_:bootstrap4_;
        const auto at=ipv6?bootstrap6At_:bootstrap4At_;
        if(!data.isEmpty()&&now>=at&&now-at<86400000){const auto url=registryUrl(data,destination);
            if(url){startResource(Resource::Registry,*url);return;}}
        startResource(ipv6?Resource::Bootstrap6:Resource::Bootstrap4,bootstrapUrl(destination));return;
    }
    if(resource_==Resource::Bootstrap4||resource_==Resource::Bootstrap6){
        const auto& data=destination.address.contains(':')?bootstrap6_:bootstrap4_;
        const auto url=registryUrl(data,destination);if(!url){finishEvidence();return;}
        startResource(Resource::Registry,*url);return;
    }
    if(resource_==Resource::Registry){
        bool adobe=active_.input.publicQuery.contains("adobe",Qt::CaseInsensitive);
        for(const auto& c:active_.citations)adobe|=c.kind==1&&c.snippet.contains("adobe",Qt::CaseInsensitive);
        if(adobe){startResource(Resource::AdobeEndpoints,adobeEndpointsUrl());return;}
    }
    finishEvidence();
}
void SearchClient::tick()
{
    if(!working_)return;
    QPointer<SearchClient> self(this);if(!sourceCurrent()){if(self&&working_)complete(Status::Cancelled);return;}if(!self)return;
    if(!exchange_){nextResource();return;}
    if (clock_->milliseconds() >= deadline_) { complete(Status::Unavailable); return; }
    HttpResponse response;
    const auto operation=exchange_;if(!operation->poll(response))return;
    if(!self)return;if(!sourceCurrent()){if(self&&working_)complete(Status::Cancelled);return;}if(!self)return;
    exchange_.reset();
    const auto checked=QDateTime::currentDateTimeUtc();
    if(resource_==Resource::Search){
        const auto result=parseResponse(response,active_,checked);
        active_.citations=result.citations;
        if(!active_.input.destination){timer_.stop();working_=false;current_={};emit finished(result);return;}
    }else if(resource_==Resource::Bootstrap4||resource_==Resource::Bootstrap6){
        const auto type=response.contentType.toLower().split(';').front().trimmed();
        if(response.transportOk&&response.statusCode==200&&type=="application/json"&&
            (response.contentEncoding.isEmpty()||response.contentEncoding.toLower().trimmed()=="identity")&&
            registryUrl(response.body,*active_.input.destination)){
            auto& data=resource_==Resource::Bootstrap6?bootstrap6_:bootstrap4_;
            auto& at=resource_==Resource::Bootstrap6?bootstrap6At_:bootstrap4At_;
            data=response.body;at=clock_->milliseconds();
        }else{finishEvidence();return;}
    }else{
        const auto evidence=resource_==Resource::Registry
            ?registrationEvidence(response,*active_.input.destination,resourceUrl_,quint64(checked.toMSecsSinceEpoch()))
            :officialDestinationEvidence(response,*active_.input.destination,quint64(checked.toMSecsSinceEpoch()));
        if(evidence){if(evidence->kind==1)active_.citations.prepend(*evidence);
            else active_.citations.insert(std::min<qsizetype>(1,active_.citations.size()),*evidence);}
    }
    nextResource();
}
}
