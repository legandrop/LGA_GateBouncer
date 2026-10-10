#pragma once
#include "DestinationEvidence.h"

#include <QByteArray>
#include <QDateTime>
#include <QElapsedTimer>
#include <QObject>
#include <QString>
#include <QTimer>
#include <QUrl>
#include <QVector>
#include <memory>
#include <functional>

namespace gatebouncer::websearch {
enum class Provider { MwmblV2, SearXng };
enum class Status { Evidence, NoEvidence, Unavailable, Cancelled, Rejected };
enum class HttpStage { Unknown, OpenSession, Options, Connect, OpenRequest, Send, Receive, Headers, Read };
enum class LocalHttpFailure { None, Cancelled, Deadline, ResponseLimit, Rejected, Headless, Unsupported, InvalidResponse };
enum class NetworkFailure { Unknown, Cancelled, Timeout, Tls, Http, Transport, Local };
struct HttpDiagnostic {
    HttpStage stage = HttpStage::Unknown;
    std::optional<quint32> winHttpError;
    std::optional<quint64> asyncApi;
    std::optional<quint32> secureFailure;
    LocalHttpFailure local = LocalHttpFailure::None;
    bool failureObserved = false;
};
NetworkFailure networkFailure(const HttpDiagnostic &, int observedHttpStatus = 0);
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
    std::optional<Destination> destination;
};
struct Citation {
    QString title;
    QString snippet;
    QUrl url;
    QString origin;
    QDateTime retrievalUtc;
    quint8 kind=0; // 0 app, 1 registro RDAP, 2 asociación IP+app no verificada, 3 ASN anunciado RIS.
    QString subject;
};
struct SearchResult {
    SearchInput input;
    QByteArray instanceToken;
    QByteArray configurationBinding;
    Provider provider = Provider::MwmblV2;
    Status status = Status::Unavailable;
    QVector<Citation> citations;
    HttpDiagnostic diagnostic;
    int observedHttpStatus = 0;
};
struct HttpRequest { ProviderConfig config; QString query; Resource resource=Resource::Search;
    QUrl evidenceUrl;std::optional<Destination> destination; };
struct HttpResponse {
    bool transportOk = false;
    int statusCode = 0;
    QByteArray contentType;
    QByteArray contentEncoding;
    QByteArray body;
    HttpDiagnostic diagnostic;
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
    bool begin(const SearchInput &input,std::function<bool()> current={});
    void cancel();
signals:
    void finished(const gatebouncer::websearch::SearchResult &result);
private:
    void tick();
    void complete(Status status);
    bool startResource(Resource,const QUrl&);
    void nextResource();
    void finishEvidence();
    bool sourceCurrent();
    std::function<bool()> current_;
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
    bool working_=false;
    bool reusedDestinationCache_=false;
    unsigned requests_=0;
    Resource resource_=Resource::Search;
    QUrl resourceUrl_;
    QByteArray bootstrap4_,bootstrap6_;
    qint64 bootstrap4At_=0,bootstrap6At_=0;
    struct DestinationCache { QString key;QVector<Citation> evidence;qint64 at=0; };
    QVector<DestinationCache> destinationCache_;
    // Registro y routing dependen de IP; no repetirlos por cambiar el nombre de aplicación.
    QVector<DestinationCache> networkCache_;
};
}
Q_DECLARE_METATYPE(gatebouncer::websearch::SearchResult)
