#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QElapsedTimer>
#include <QObject>
#include <QString>
#include <QTimer>
#include <QUrl>
#include <QVector>
#include <memory>

namespace gatebouncer::websearch {
enum class Provider { MwmblV2, SearXng };
enum class Status { Evidence, NoEvidence, Unavailable, Cancelled, Rejected };
struct ProviderConfig {
    Provider provider = Provider::MwmblV2;
    QUrl endpoint = QUrl(QStringLiteral("https://api.mwmbl.org/api/v2/search/"));
    // Revisión de configuración del propietario; cambiarla revoca el consentimiento.
    QString revision;
};
struct SearchInput {
    QString requestId;
    quint64 generation = 0;
    QString publicQuery;
};
struct Citation {
    QString title;
    QString snippet;
    QUrl url;
    QString origin;
    QDateTime retrievalUtc;
};
struct SearchResult {
    SearchInput input;
    QByteArray instanceToken;
    QByteArray configurationBinding;
    Provider provider = Provider::MwmblV2;
    Status status = Status::Unavailable;
    QVector<Citation> citations;
};
struct HttpRequest { ProviderConfig config; QString query; };
struct HttpResponse {
    bool transportOk = false;
    int statusCode = 0;
    QByteArray contentType;
    QByteArray contentEncoding;
    QByteArray body;
};
class Exchange {
public:
    virtual ~Exchange() = default;
    virtual bool poll(HttpResponse &response) = 0;
    virtual void cancel() = 0;
};
class Transport {
public:
    virtual ~Transport() = default;
    virtual std::shared_ptr<Exchange> start(const HttpRequest &request) = 0;
};
class MonotonicClock {
public:
    virtual ~MonotonicClock() = default;
    virtual qint64 milliseconds() const = 0;
};
std::shared_ptr<Transport> makeWinHttpTransport();
bool validConfiguration(const ProviderConfig &config);
bool validPublicQuery(const QString &query);
QByteArray configurationBinding(const ProviderConfig &config);
QString disclosure(const ProviderConfig &config);
SearchResult parseResponse(const HttpResponse &response, SearchResult binding,
                           const QDateTime &retrievalUtc);

// El consumidor propietario controla configuración/consentimiento en el hilo de este objeto.
// No persiste preferencias, consulta identidad del ejecutable ni decide permisos de red.
class SearchClient final : public QObject {
    Q_OBJECT
public:
    explicit SearchClient(std::shared_ptr<Transport> transport, QObject *parent = nullptr,
                          std::shared_ptr<MonotonicClock> clock = {});
    ~SearchClient() override;
    bool configure(const ProviderConfig &config);
    QByteArray configurationBinding() const;
    QByteArray instanceToken() const;
    QString disclosure() const;
    bool grantConsent(const QByteArray &binding);
    void revokeConsent();
    bool begin(const SearchInput &input);
    void cancel();
signals:
    void finished(const gatebouncer::websearch::SearchResult &result);
private:
    void tick();
    void complete(Status status);
    std::shared_ptr<Transport> transport_;
    std::shared_ptr<Exchange> exchange_;
    ProviderConfig config_;
    QByteArray binding_;
    QByteArray consent_;
    QByteArray instance_;
    SearchResult active_;
    QTimer timer_;
    std::shared_ptr<MonotonicClock> clock_;
    qint64 lastStart_ = -10000;
    QVector<qint64> budget_;
    QString lastQuery_;
    qint64 lastQueryAt_ = -600000;
    qint64 deadline_ = 0;
};
}
Q_DECLARE_METATYPE(gatebouncer::websearch::SearchResult)
