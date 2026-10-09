#include "WebSearch.h"

#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QStringDecoder>
#include <QThread>
#include <QUuid>
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
        + QByteArrayLiteral("web-disclosure-v1");
    return QCryptographicHash::hash(material, QCryptographicHash::Sha256).toHex();
}
QString disclosure(const ProviderConfig &config)
{
    if (config.provider == Provider::MwmblV2)
        return QStringLiteral("Web search sends only public application names to Mwmbl. "
            "Standard searches may be shared with external sources and TypeSafe AI; "
            "pages and query keywords may enter a public index. Your connection IP is processed. "
            "Coverage is limited. Results do not certify the safety of this executable. "
            "You can revoke this consent. Mwmbl terms and privacy policy apply.");
    return QStringLiteral("Web search sends only public application names to your configured "
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
    if (next != binding_) { revokeConsent(); binding_ = next; }
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
bool SearchClient::begin(const SearchInput &input)
{
    if (QThread::currentThread() != thread() || exchange_ || !transport_ || binding_.isEmpty()
        || consent_ != binding_ || !validPublicQuery(input.publicQuery)
        || !plain(input.requestId, 128) || input.requestId.isEmpty()) return false;
    const auto now = clock_->milliseconds();
    while (!budget_.isEmpty() && now - budget_.first() >= 3600000) budget_.removeFirst();
    if (now - lastStart_ < 10000 || budget_.size() >= 30
        || (input.publicQuery == lastQuery_ && now - lastQueryAt_ < 600000)) return false;
    active_ = {input, instance_, binding_, config_.provider, Status::Unavailable, {}};
    lastStart_ = now;
    budget_.append(now);
    lastQuery_ = input.publicQuery;
    lastQueryAt_ = now;
    exchange_ = transport_->start({config_, input.publicQuery});
    if (!exchange_) {
        const auto result = active_;
        QMetaObject::invokeMethod(this, [this, result] { emit finished(result); }, Qt::QueuedConnection);
        return true;
    }
    deadline_ = now + 15000;
    timer_.start();
    return true;
}
void SearchClient::complete(Status status)
{
    timer_.stop();
    const auto operation = std::move(exchange_);
    if (operation) operation->cancel();
    auto result = active_;
    result.status = status;
    result.citations.clear();
    QMetaObject::invokeMethod(this, [this, result] { emit finished(result); }, Qt::QueuedConnection);
}
void SearchClient::cancel() { if (exchange_) complete(Status::Cancelled); }
void SearchClient::tick()
{
    if (!exchange_) return;
    if (clock_->milliseconds() >= deadline_) { complete(Status::Unavailable); return; }
    HttpResponse response;
    if (!exchange_->poll(response)) return;
    timer_.stop();
    exchange_.reset();
    const auto result = parseResponse(response, active_, QDateTime::currentDateTimeUtc());
    emit finished(result);
}
}
