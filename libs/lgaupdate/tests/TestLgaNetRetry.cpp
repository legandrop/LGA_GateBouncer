// Banco de pruebas de los reintentos de red de lgaupdate (`LgaNetRetry.h`).
//
// Corre el servicio y el fetcher de notas REALES contra un servidor HTTP propio en 127.0.0.1
// (QTcpServer) que sigue un guion por pedido: cortar la respuesta a la mitad, contestar 404 o
// 503, servir el manifiesto, las notas o el asset, honrar o ignorar el Range, redirigir como
// github.com. Para los cortes de HTTP/2 (RST_STREAM, GOAWAY) hay un segundo servidor, h2c minimo.
// Nunca sale a la red: el manager de prueba manda a 127.0.0.1 TODO pedido, tambien las URL de
// github.com que el servicio deriva del manifiesto (directo, o por un proxy HTTP que es el mismo
// servidor de prueba, para que los pedidos conserven su nombre de servidor).
//
// Nunca instala nada: en las descargas, `installBlockedReason` deja pasar solo la primera
// pregunta (el "Update now" del cartel) y frena la segunda, la de al terminar la descarga, que es
// la que precede al helper que lanza el instalador. En los demas casos la frena siempre.
//
// Uso, SIEMPRE por el runner de QA de la Base (nunca a mano):
//
//   run_headless.ps1 -Exe <build>\lgaupdate_tests\lgaupdate_retry_tests.exe
//                    -Arguments '<carpeta de trabajo> [caso]'
//
// Cada caso trabaja en `<carpeta de trabajo>\<caso>`, que no puede existir con contenido: para
// repetir una corrida se usa otra carpeta de trabajo, nunca se borra la anterior. El banco no
// borra nada (lo unico que se borra es lo que el propio servicio crea en su carpeta de updates).
// Sale con la cantidad de casos fallidos: 0 = todo bien.

#include "lgaupdate/LgaNetRetry.h"
#include "lgaupdate/LgaUpdateDialog.h"
#include "lgaupdate/LgaUpdateService.h"
#include "lgaupdate/LgaWhatsNew.h"

#include <QApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPointer>
#include <QProgressDialog>
#include <QPushButton>
#include <QStandardPaths>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QWidget>
#include <QtEndian>

#include <cstdio>
#include <functional>
#include <memory>

namespace {

// Espera entre intentos durante el banco: corta, pero mas larga que un ciclo del event loop, asi
// el estado "esperando el reintento" se puede mirar y cortar.
constexpr int kTestDelayMs = 300;

const QString kProductId = QStringLiteral("LGA_TestRetry");
const QString kReleaseSlug = QStringLiteral("legandrop/LGA_TestRetry_Release");
const QString kInstalledVersion = QStringLiteral("1.000");
const QString kOfferedVersion = QStringLiteral("9.999");
const QString kFakeSha = QString(64, QLatin1Char('a'));

// ---------------------------------------------------------------------------- utilidades

void out(const QString &line)
{
    std::fprintf(stdout, "%s\n", line.toUtf8().constData());
    std::fflush(stdout);
}

/// Corre el event loop hasta que `condition` da true o pasan `timeoutMs`.
bool waitUntil(const std::function<bool()> &condition, int timeoutMs)
{
    QElapsedTimer timer;
    timer.start();
    while (!condition()) {
        if (timer.elapsed() > timeoutMs) {
            return false;
        }
        QEventLoop loop;
        QTimer::singleShot(10, &loop, &QEventLoop::quit);
        loop.exec();
    }
    return true;
}

/// Corre el event loop `ms` milisegundos.
void pump(int ms)
{
    waitUntil([]() { return false; }, ms);
}

QString sha256Hex(const QByteArray &data)
{
    return QString::fromLatin1(QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex());
}

QByteArray deterministicContent(int size)
{
    QByteArray content(size, Qt::Uninitialized);
    for (int i = 0; i < size; ++i) {
        content[i] = char((i * 31 + 7) & 0xff);
    }
    return content;
}

QString installerAssetName(const QString &version)
{
#ifdef Q_OS_MAC
    return QStringLiteral("%1_Mac_v%2.zip").arg(kProductId, version);
#else
    return QStringLiteral("%1_Setup_v%2.exe").arg(kProductId, version);
#endif
}

/// Manifiesto de LGA_Updates con el release `version` del producto de prueba: el instalador de
/// esta plataforma con `installerSha` y, si se pasa `notesSha`, el whats_new.json.
QByteArray manifestJson(const QString &version, const QString &installerSha,
                        const QString &notesSha = QString())
{
    const QString tag = QStringLiteral("v") + version;
    QJsonArray assets;
    QJsonArray latest;
    assets.append(QJsonObject{{QStringLiteral("name"), installerAssetName(version)},
                              {QStringLiteral("digest"), QStringLiteral("sha256:") + installerSha}});
    latest.append(QJsonObject{{QStringLiteral("tag"), tag},
                              {QStringLiteral("name"), installerAssetName(version)},
                              {QStringLiteral("digest"), QStringLiteral("sha256:") + installerSha}});
    if (!notesSha.isEmpty()) {
        assets.append(QJsonObject{{QStringLiteral("name"), QStringLiteral("whats_new.json")},
                                  {QStringLiteral("digest"), QStringLiteral("sha256:") + notesSha}});
        latest.append(QJsonObject{{QStringLiteral("tag"), tag},
                                  {QStringLiteral("name"), QStringLiteral("whats_new.json")},
                                  {QStringLiteral("digest"), QStringLiteral("sha256:") + notesSha}});
    }
    const QJsonObject product{{QStringLiteral("tag"), tag},
                              {QStringLiteral("assets"), assets},
                              {QStringLiteral("assetLatest"), latest}};
    const QJsonObject root{{QStringLiteral("schemaVersion"), 1},
                           {QStringLiteral("products"), QJsonObject{{kReleaseSlug, product}}}};
    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

QByteArray notesJson()
{
    return QByteArrayLiteral(
        R"({"schemaVersion":1,"product":"legandrop/LGA_TestRetry_Release","name":"LGA Test Retry",)"
        R"("versions":[{"version":"1.000","date":"2026-11-04",)"
        R"("items":[{"kind":"new","text":"Prueba de reintentos."}]}]})");
}

QString readText(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return QString();
    }
    return QString::fromUtf8(file.readAll());
}

// ------------------------------------------------------------- servidor HTTP con guion

struct HttpRequestInfo {
    QByteArray method;
    QByteArray path;
    /// Nombres en minuscula.
    QHash<QByteArray, QByteArray> headers;
};

/// Servidor HTTP/1.1 minimo en 127.0.0.1. Por cada pedido completo llama al guion con el indice
/// del pedido (0 = el primero) y el socket para contestar.
class ScriptServer
{
public:
    using Handler = std::function<void(QTcpSocket *socket, int index, const HttpRequestInfo &)>;

    explicit ScriptServer(Handler handler)
        : m_handler(std::move(handler))
    {
        QObject::connect(&m_server, &QTcpServer::newConnection, &m_server, [this]() {
            while (QTcpSocket *socket = m_server.nextPendingConnection()) {
                ++connections;
                auto buffer = std::make_shared<QByteArray>();
                auto handled = std::make_shared<bool>(false);
                QObject::connect(socket, &QTcpSocket::readyRead, socket,
                                 [this, socket, buffer, handled]() {
                                     if (*handled) {
                                         socket->readAll();
                                         return;
                                     }
                                     *buffer += socket->readAll();
                                     const qsizetype end = buffer->indexOf("\r\n\r\n");
                                     if (end < 0) {
                                         return;
                                     }
                                     *handled = true;
                                     requests.append(parse(buffer->left(end)));
                                     m_handler(socket, int(requests.size() - 1), requests.last());
                                 });
                QObject::connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
            }
        });
    }

    bool listen() { return m_server.listen(QHostAddress::LocalHost, 0); }
    quint16 port() const { return m_server.serverPort(); }

    /// Cuantos pedidos llegaron a una ruta que termina en `suffix`.
    int countPath(const QByteArray &suffix) const
    {
        int n = 0;
        for (const HttpRequestInfo &request : requests) {
            if (request.path.endsWith(suffix)) {
                ++n;
            }
        }
        return n;
    }

    int connections = 0;
    QList<HttpRequestInfo> requests;

private:
    static HttpRequestInfo parse(const QByteArray &head)
    {
        HttpRequestInfo info;
        const QList<QByteArray> lines = head.split('\n');
        const QList<QByteArray> first = lines.value(0).trimmed().split(' ');
        info.method = first.value(0);
        info.path = first.value(1);
        for (qsizetype i = 1; i < lines.size(); ++i) {
            const QByteArray line = lines.at(i).trimmed();
            const qsizetype colon = line.indexOf(':');
            if (colon > 0) {
                info.headers.insert(line.left(colon).trimmed().toLower(), line.mid(colon + 1).trimmed());
            }
        }
        return info;
    }

    QTcpServer m_server;
    Handler m_handler;
};

void sendHead(QTcpSocket *socket, int status, const QByteArray &reason, qint64 contentLength,
              const QByteArray &extraHeaders = QByteArray())
{
    socket->write("HTTP/1.1 " + QByteArray::number(status) + ' ' + reason + "\r\n"
                  + "Content-Length: " + QByteArray::number(contentLength) + "\r\n"
                  + "Connection: close\r\n" + extraHeaders + "\r\n");
}

/// Respuesta completa y cierre ordenado.
void sendFull(QTcpSocket *socket, int status, const QByteArray &reason, const QByteArray &body,
              const QByteArray &extraHeaders = QByteArray())
{
    sendHead(socket, status, reason, body.size(), extraHeaders);
    socket->write(body);
    socket->disconnectFromHost();
}

/// Anuncia `contentLength` bytes, manda solo `partial` y corta. El cierre espera un poco para
/// que el cliente reciba lo mandado: ve un corte a MITAD de la respuesta (RemoteHostClosedError),
/// que Qt no reenvia por su cuenta como hace con un cierre antes de la respuesta.
void sendCut(QTcpSocket *socket, qint64 contentLength, const QByteArray &partial, int status = 200,
             const QByteArray &reason = "OK", const QByteArray &extraHeaders = QByteArray())
{
    sendHead(socket, status, reason, contentLength, extraHeaders);
    socket->write(partial);
    socket->flush();
    QTimer::singleShot(150, socket, [socket]() { socket->disconnectFromHost(); });
}

// ------------------------------------------------------------------- red de prueba

/// Lo que el cliente pidio: un elemento por INTENTO (cada `get()` del servicio o del fetcher).
struct NetLog {
    QList<QUrl> urls;
    QList<QByteArray> ranges;

    int countPath(const QString &suffix) const
    {
        int n = 0;
        for (const QUrl &url : urls) {
            if (url.path().endsWith(suffix)) {
                ++n;
            }
        }
        return n;
    }
};

/// Variantes de la red de prueba. Con los valores por defecto, todo va al servidor de `port`.
struct LoopbackOptions {
    /// Si no es 0, el instalador va a este otro puerto de 127.0.0.1 (el servidor HTTP/2).
    quint16 assetPort = 0;
    /// El instalador por HTTP/2 directo, sin TLS (h2c con conocimiento previo).
    bool assetHttp2 = false;
    /**
     * Todo por un proxy HTTP en 127.0.0.1:`port`, que es el servidor de prueba: los pedidos
     * conservan su servidor (github.com, el de los archivos) y `reply->url()` lo ve despues de
     * un redirect, que es lo que mira la cuenta por servidor. Qt no resuelve ni conecta a esos
     * nombres: con un proxy HTTP el que resuelve es el proxy, y la unica conexion que abre es a
     * 127.0.0.1. Nada sale de la maquina.
     */
    bool viaProxy = false;
};

/// Manager que manda TODO pedido a 127.0.0.1: el manifiesto ya apunta ahi; el asset y las notas,
/// que el servicio deriva para github.com, se reescriben al puerto del servidor de prueba (o, con
/// `viaProxy`, salen por el proxy de prueba). Sin TLS: el servidor de prueba no lo habla.
class LoopbackNetwork : public QNetworkAccessManager
{
public:
    LoopbackNetwork(quint16 port, NetLog *log, QObject *parent,
                    const LoopbackOptions &options = LoopbackOptions())
        : QNetworkAccessManager(parent)
        , m_port(port)
        , m_log(log)
        , m_options(options)
    {
        if (options.viaProxy) {
            setProxy(QNetworkProxy(QNetworkProxy::HttpProxy, QStringLiteral("127.0.0.1"), port));
        } else {
            setProxy(QNetworkProxy::NoProxy);
        }
    }

protected:
    QNetworkReply *createRequest(Operation op, const QNetworkRequest &original,
                                 QIODevice *outgoingData) override
    {
        QNetworkRequest request(original);
        QUrl url = request.url();
        if (m_options.viaProxy) {
            url.setScheme(QStringLiteral("http"));
        } else if (url.host() != QLatin1String("127.0.0.1")) {
            url.setScheme(QStringLiteral("http"));
            url.setHost(QStringLiteral("127.0.0.1"));
            url.setPort(m_port);
        }
        if (m_options.assetPort != 0 && !m_options.viaProxy
            && url.path().endsWith(installerAssetName(kOfferedVersion))) {
            url.setPort(m_options.assetPort);
            if (m_options.assetHttp2) {
                request.setAttribute(QNetworkRequest::Http2DirectAttribute, true);
            }
        }
        request.setUrl(url);
        m_log->urls.append(url);
        m_log->ranges.append(request.rawHeader("Range"));
        return QNetworkAccessManager::createRequest(op, request, outgoingData);
    }

private:
    quint16 m_port;
    NetLog *m_log;
    LoopbackOptions m_options;
};

// ------------------------------------------------- servidor HTTP/2 (h2c) con guion

// Lo minimo de HTTP/2 (RFC 9113) para cortar una descarga como lo hacen GitHub y los CDN: un
// RST_STREAM o un GOAWAY a mitad del cuerpo. Con HTTP/1.1 no se puede provocar: esos cortes
// solo existen en HTTP/2, y Qt los informa con errores distintos de un cierre de conexion.

namespace H2 {
constexpr quint8 kData = 0x0;
constexpr quint8 kHeaders = 0x1;
constexpr quint8 kRstStream = 0x3;
constexpr quint8 kSettings = 0x4;
constexpr quint8 kPing = 0x6;
constexpr quint8 kGoAway = 0x7;
constexpr quint8 kContinuation = 0x9;
constexpr quint8 kFlagEndStream = 0x1;
constexpr quint8 kFlagAck = 0x1;
constexpr quint8 kFlagEndHeaders = 0x4;
constexpr quint32 kInternalError = 0x2;
constexpr quint32 kCancel = 0x8;
constexpr qsizetype kMaxFrame = 16384; // SETTINGS_MAX_FRAME_SIZE por defecto
} // namespace H2

QByteArray be32(quint32 value)
{
    QByteArray bytes(4, Qt::Uninitialized);
    qToBigEndian(value, bytes.data());
    return bytes;
}

/// Un cuadro: largo de 24 bits, tipo, flags y stream de 31 bits, y el contenido.
QByteArray h2Frame(quint8 type, quint8 flags, quint32 streamId, const QByteArray &payload)
{
    const quint32 length = quint32(payload.size());
    QByteArray frame;
    frame.append(char((length >> 16) & 0xff));
    frame.append(char((length >> 8) & 0xff));
    frame.append(char(length & 0xff));
    frame.append(char(type));
    frame.append(char(flags));
    frame += be32(streamId & 0x7fffffff);
    frame += payload;
    return frame;
}

/// HEADERS de la respuesta. `:status` sale de la tabla estatica de HPACK (RFC 7541, apendice A:
/// 8 = 200, 10 = 206); el resto, como «literal sin indexar, nombre nuevo», sin Huffman (alcanza
/// para nombres y valores de menos de 127 bytes).
QByteArray h2Headers(quint32 streamId, int status, const QList<QPair<QByteArray, QByteArray>> &fields)
{
    QByteArray block;
    block.append(char(status == 206 ? 0x8a : 0x88));
    for (const auto &field : fields) {
        block.append(char(0x00));
        block.append(char(field.first.size()));
        block += field.first;
        block.append(char(field.second.size()));
        block += field.second;
    }
    return h2Frame(H2::kHeaders, H2::kFlagEndHeaders, streamId, block);
}

/// DATA en cuadros de hasta 16 KB; `endStream` cierra el stream con el ultimo.
QByteArray h2Data(quint32 streamId, const QByteArray &body, bool endStream)
{
    QByteArray frames;
    qsizetype offset = 0;
    do {
        const QByteArray chunk = body.mid(offset, H2::kMaxFrame);
        offset += chunk.size();
        const bool last = offset >= body.size();
        frames += h2Frame(H2::kData, (last && endStream) ? H2::kFlagEndStream : 0, streamId, chunk);
    } while (offset < body.size());
    return frames;
}

/**
 * Servidor h2c minimo en 127.0.0.1. Contesta el prefacio, los SETTINGS y los PING, y por cada
 * pedido completo (HEADERS con END_HEADERS) llama al guion con el stream y el numero de pedido
 * (0 = el primero, contando todas las conexiones). No decodifica el HPACK del pedido: lo que el
 * guion necesita saber (el Range) lo anota el manager de prueba en su `NetLog`.
 */
class H2Server
{
public:
    using Handler = std::function<void(QTcpSocket *socket, quint32 streamId, int index)>;

    explicit H2Server(Handler handler)
        : m_handler(std::move(handler))
    {
        QObject::connect(&m_server, &QTcpServer::newConnection, &m_server, [this]() {
            while (QTcpSocket *socket = m_server.nextPendingConnection()) {
                ++connections;
                // El prefacio del servidor es un SETTINGS (vacio: los valores por defecto), y
                // tiene que ser lo primero que manda.
                socket->write(h2Frame(H2::kSettings, 0, 0, QByteArray()));
                auto buffer = std::make_shared<QByteArray>();
                auto prefaceSeen = std::make_shared<bool>(false);
                QObject::connect(socket, &QTcpSocket::readyRead, socket,
                                 [this, socket, buffer, prefaceSeen]() {
                                     *buffer += socket->readAll();
                                     onBytes(socket, *buffer, *prefaceSeen);
                                 });
                QObject::connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
            }
        });
    }

    bool listen() { return m_server.listen(QHostAddress::LocalHost, 0); }
    quint16 port() const { return m_server.serverPort(); }

    int connections = 0;
    int requests = 0;
    /// Conexiones que no empezaron con el prefacio del cliente (el pedido no fue HTTP/2).
    int badPrefaces = 0;

private:
    void onBytes(QTcpSocket *socket, QByteArray &buffer, bool &prefaceSeen)
    {
        if (!prefaceSeen) {
            static const QByteArray preface("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            if (buffer.size() < preface.size()) {
                return;
            }
            if (!buffer.startsWith(preface)) {
                ++badPrefaces;
                buffer.clear();
                socket->abort();
                return;
            }
            buffer.remove(0, preface.size());
            prefaceSeen = true;
        }
        while (buffer.size() >= 9) {
            const quint32 length = (quint32(quint8(buffer.at(0))) << 16)
                | (quint32(quint8(buffer.at(1))) << 8) | quint32(quint8(buffer.at(2)));
            if (buffer.size() < 9 + qsizetype(length)) {
                return;
            }
            const quint8 type = quint8(buffer.at(3));
            const quint8 flags = quint8(buffer.at(4));
            const quint32 streamId = qFromBigEndian<quint32>(buffer.constData() + 5) & 0x7fffffff;
            const QByteArray payload = buffer.mid(9, length);
            buffer.remove(0, 9 + qsizetype(length));
            if (type == H2::kSettings && !(flags & H2::kFlagAck)) {
                socket->write(h2Frame(H2::kSettings, H2::kFlagAck, 0, QByteArray()));
            } else if (type == H2::kPing && !(flags & H2::kFlagAck)) {
                socket->write(h2Frame(H2::kPing, H2::kFlagAck, 0, payload));
            } else if ((type == H2::kHeaders || type == H2::kContinuation)
                       && (flags & H2::kFlagEndHeaders)) {
                ++requests;
                m_handler(socket, streamId, requests - 1);
            }
            // WINDOW_UPDATE, PRIORITY y los demas no cambian nada en este banco.
        }
    }

    QTcpServer m_server;
    Handler m_handler;
};

// --------------------------------------------------------------- arnes del servicio

struct DialogEntry {
    LgaUpdateDialogSpec::Kind kind;
    QString title;
    QString message;
    QString details;
};

/// La pregunta de "no se puede instalar ahora" en las descargas: la primera vez (al elegir
/// Update now) deja pasar; desde la segunda (al terminar la descarga, antes del helper) mira el
/// instalador ya commiteado y frena SIEMPRE.
struct InstallGate {
    int calls = 0;
    QString installerPath;
    QByteArray expected;
    bool fileChecked = false;
    bool fileMatched = false;
    /// Texto del dialogo de progreso al terminar la descarga (ya cerrado, todavia vivo): tiene
    /// que haber vuelto al de la descarga despues de un reintento que anduvo.
    QString labelAtFinish;
};

const QString kNeverInstall = QStringLiteral("Banco de pruebas: nunca se instala.");

struct Harness {
    QString caseDir;
    QString logPath;
    QWidget parent;
    NetLog net;
    QList<DialogEntry> dialogs;
    bool clickUpdate = false;
    InstallGate gate;
    int quitCalls = 0;
    int checkStarted = 0;
    int checkFinished = 0;
    LgaUpdateService *service = nullptr;

    /// `port` es el del manifiesto; el resto de los pedidos va al mismo puerto, salvo lo que
    /// cambie `options`.
    Harness(const QString &dir, quint16 port, bool downloads,
            const LoopbackOptions &options = LoopbackOptions())
        : caseDir(dir)
        , logPath(QDir(dir).filePath(QStringLiteral("Update.log")))
    {
        LgaUpdateConfig config;
        config.productId = kProductId;
        config.displayName = QStringLiteral("LGA Test Retry");
        config.releaseRepoSlug = kReleaseSlug;
        config.windowsExecutableName = QStringLiteral("lgaupdate_retry_tests.exe");
        config.manifestUrl = QStringLiteral("http://127.0.0.1:%1/versions.json").arg(port);
        config.settingsPath = QDir(dir).filePath(QStringLiteral("settings.ini"));
        config.updateCacheDir = QDir(dir).filePath(QStringLiteral("cache"));
        config.updateLogPath = logPath;
        config.periodicCheckIntervalMs = 0;
        config.checkTimeoutMs = 5000;
        config.downloadTimeoutMs = 10000;
        config.whatsNewWaitMs = 0;
        config.automaticChecksEnabled = []() { return false; };
        config.updateBlockedReason = []() { return QString(); };
        if (downloads) {
            gate.installerPath = QDir(LgaUpdateService::resolveUpdateDir(config.updateCacheDir))
                                     .filePath(installerAssetName(kOfferedVersion));
            config.installBlockedReason = [this]() -> QString {
                ++gate.calls;
                if (gate.calls == 1) {
                    return QString();
                }
                QFile file(gate.installerPath);
                if (file.open(QIODevice::ReadOnly)) {
                    gate.fileChecked = true;
                    gate.fileMatched = file.readAll() == gate.expected;
                }
                if (QProgressDialog *dialog = progressDialog()) {
                    gate.labelAtFinish = dialog->labelText();
                }
                return kNeverInstall;
            };
        } else {
            config.installBlockedReason = []() { return kNeverInstall; };
        }
        config.quitApplication = [this]() { ++quitCalls; };
        config.networkFactory = [this, port, options](QObject *owner) {
            return new LoopbackNetwork(port, &net, owner, options);
        };
        config.presentDialog = [this](QWidget *, const LgaUpdateDialogSpec &spec) {
            dialogs.append({spec.kind, spec.title, spec.messageHtml, spec.details});
            if (spec.kind == LgaUpdateDialogSpec::Kind::UpdatePrompt) {
                const int index = LgaUpdateDialog::indexOf(
                    spec, clickUpdate ? LgaUpdateDialogSpec::Role::Update
                                      : LgaUpdateDialogSpec::Role::Cancel);
                return index >= 0 ? index : spec.escapeIndex;
            }
            return spec.defaultIndex >= 0 ? spec.defaultIndex : 0;
        };
        service = new LgaUpdateService(config, &parent);
        QObject::connect(service, &LgaUpdateService::checkStarted, &parent,
                         [this]() { ++checkStarted; });
        QObject::connect(service, &LgaUpdateService::checkFinished, &parent,
                         [this]() { ++checkFinished; });
    }

    ~Harness() { delete service; }

    QString log() const { return readText(logPath); }

    const DialogEntry *firstOfKind(LgaUpdateDialogSpec::Kind kind) const
    {
        for (const DialogEntry &entry : dialogs) {
            if (entry.kind == kind) {
                return &entry;
            }
        }
        return nullptr;
    }

    const DialogEntry *firstResult() const { return firstOfKind(LgaUpdateDialogSpec::Kind::Result); }

    QProgressDialog *progressDialog() const
    {
        return parent.findChild<QProgressDialog *>(QStringLiteral("updateDownloadProgressDialog"));
    }

    /// Archivos que quedaron en la carpeta de updates (instalador, temporales de QSaveFile).
    QStringList updateDirFiles() const
    {
        return QDir(QFileInfo(gate.installerPath).absolutePath())
            .entryList(QDir::Files | QDir::Hidden | QDir::NoDotAndDotDot);
    }
};

// -------------------------------------------------------------------------- casos

struct CaseResult {
    bool ok = true;
    QStringList notes;
    QStringList failures;

    void expect(bool condition, const QString &what)
    {
        if (!condition) {
            ok = false;
            failures << what;
        }
    }
};

QString lastLines(const QString &text, int count)
{
    const QStringList lines = text.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    return lines.mid(qMax(0, int(lines.size()) - count)).join(QStringLiteral("\n    "));
}

// (1) El servidor corta las dos primeras respuestas a la mitad; la tercera sirve el manifiesto.
CaseResult caseManifestCutTwice(const QString &dir)
{
    CaseResult result;
    const QByteArray manifest = manifestJson(kInstalledVersion, kFakeSha);
    ScriptServer server([&](QTcpSocket *socket, int index, const HttpRequestInfo &) {
        if (index < 2) {
            sendCut(socket, manifest.size(), manifest.left(manifest.size() / 2));
        } else {
            sendFull(socket, 200, "OK", manifest, "Content-Type: application/json\r\n");
        }
    });
    if (!server.listen()) {
        result.expect(false, QStringLiteral("no se pudo escuchar en 127.0.0.1"));
        return result;
    }
    Harness h(dir, server.port(), /*downloads=*/false);
    QElapsedTimer timer;
    timer.start();
    h.service->checkForUpdates(/*manual=*/true);
    const bool done = waitUntil([&]() { return h.firstResult() != nullptr; }, 30000);
    const qint64 elapsed = timer.elapsed();
    result.expect(done, QStringLiteral("no termino el chequeo"));
    const DialogEntry *entry = h.firstResult();
    result.expect(entry && entry->message.contains(QStringLiteral("latest version")),
                  QStringLiteral("se esperaba \"You are running the latest version\", vino: %1")
                      .arg(entry ? entry->title + QStringLiteral(" / ") + entry->message
                                 : QStringLiteral("nada")));
    result.expect(h.net.countPath(QStringLiteral("/versions.json")) == 3,
                  QStringLiteral("intentos del cliente=%1, se esperaban 3")
                      .arg(h.net.countPath(QStringLiteral("/versions.json"))));
    result.expect(server.requests.size() == 3,
                  QStringLiteral("pedidos al servidor=%1, se esperaban 3").arg(server.requests.size()));
    result.expect(elapsed >= 2 * kTestDelayMs,
                  QStringLiteral("tardo %1 ms: no hubo las dos esperas").arg(elapsed));
    result.expect(h.checkStarted == 1 && h.checkFinished == 1,
                  QStringLiteral("checkStarted=%1 checkFinished=%2, se esperaba una sola fase")
                      .arg(h.checkStarted).arg(h.checkFinished));
    const QString log = h.log();
    result.expect(log.contains(QStringLiteral("intento 3 (3 de 4 en 127.0.0.1)")),
                  QStringLiteral("el log no tiene \"intento 3 (3 de 4 en 127.0.0.1)\""));
    result.notes << QStringLiteral("intentos=%1 pedidos=%2 tiempo=%3 ms")
                        .arg(h.net.urls.size()).arg(server.requests.size()).arg(elapsed);
    if (!result.ok) {
        result.notes << QStringLiteral("log:\n    ") + lastLines(log, 12);
    }
    return result;
}

// (2) Puerto cerrado: exactamente cuatro intentos y el cartel de error.
CaseResult caseClosedPort(const QString &dir)
{
    CaseResult result;
    quint16 closedPort = 0;
    {
        QTcpServer probe;
        if (!probe.listen(QHostAddress::LocalHost, 0)) {
            result.expect(false, QStringLiteral("no se pudo reservar un puerto"));
            return result;
        }
        closedPort = probe.serverPort();
        probe.close();
    }
    Harness h(dir, closedPort, /*downloads=*/false);
    QElapsedTimer timer;
    timer.start();
    h.service->checkForUpdates(/*manual=*/true);
    const bool done = waitUntil([&]() { return h.firstResult() != nullptr; }, 60000);
    const qint64 elapsed = timer.elapsed();
    result.expect(done, QStringLiteral("no termino el chequeo"));
    // Que no quede un quinto intento colgado despues del cartel.
    pump(3 * kTestDelayMs + 300);
    const DialogEntry *entry = h.firstResult();
    result.expect(entry && entry->title == QLatin1String("Update Check Failed"),
                  QStringLiteral("se esperaba \"Update Check Failed\", vino: %1")
                      .arg(entry ? entry->title : QStringLiteral("nada")));
    result.expect(entry && entry->details.contains(QStringLiteral("attempts=4")),
                  QStringLiteral("el detalle no dice attempts=4: %1")
                      .arg(entry ? entry->details : QString()));
    result.expect(h.net.urls.size() == 4,
                  QStringLiteral("intentos del cliente=%1, se esperaban 4").arg(h.net.urls.size()));
    result.expect(!h.service->isBusy(), QStringLiteral("el servicio sigue ocupado"));
    result.expect(h.checkFinished == 1, QStringLiteral("checkFinished=%1").arg(h.checkFinished));
    const QString log = h.log();
    result.expect(log.contains(QStringLiteral("intento 4 (4 de 4 en 127.0.0.1)")),
                  QStringLiteral("el log no tiene \"intento 4 (4 de 4 en 127.0.0.1)\""));
    result.notes << QStringLiteral("intentos=%1 tiempo=%2 ms").arg(h.net.urls.size()).arg(elapsed);
    if (!result.ok) {
        result.notes << QStringLiteral("log:\n    ") + lastLines(log, 12);
    }
    return result;
}

// (3) 404: respuesta definitiva, un solo intento.
CaseResult caseHttp404(const QString &dir)
{
    CaseResult result;
    ScriptServer server([](QTcpSocket *socket, int, const HttpRequestInfo &) {
        sendFull(socket, 404, "Not Found", "not found");
    });
    if (!server.listen()) {
        result.expect(false, QStringLiteral("no se pudo escuchar en 127.0.0.1"));
        return result;
    }
    Harness h(dir, server.port(), /*downloads=*/false);
    h.service->checkForUpdates(/*manual=*/true);
    const bool done = waitUntil([&]() { return h.firstResult() != nullptr; }, 15000);
    result.expect(done, QStringLiteral("no termino el chequeo"));
    pump(3 * kTestDelayMs + 300);
    const DialogEntry *entry = h.firstResult();
    result.expect(entry && entry->title == QLatin1String("Update Check Failed"),
                  QStringLiteral("se esperaba \"Update Check Failed\", vino: %1")
                      .arg(entry ? entry->title : QStringLiteral("nada")));
    result.expect(h.net.urls.size() == 1,
                  QStringLiteral("intentos del cliente=%1, se esperaba 1").arg(h.net.urls.size()));
    result.expect(server.requests.size() == 1,
                  QStringLiteral("pedidos al servidor=%1, se esperaba 1").arg(server.requests.size()));
    result.expect(!h.log().contains(QStringLiteral("se reintenta")),
                  QStringLiteral("el log anuncia un reintento"));
    result.notes << QStringLiteral("intentos=%1 pedidos=%2").arg(h.net.urls.size()).arg(server.requests.size());
    return result;
}

// (4) 503 dos veces y despues el manifiesto.
CaseResult caseHttp503Twice(const QString &dir)
{
    CaseResult result;
    const QByteArray manifest = manifestJson(kInstalledVersion, kFakeSha);
    ScriptServer server([&](QTcpSocket *socket, int index, const HttpRequestInfo &) {
        if (index < 2) {
            sendFull(socket, 503, "Service Unavailable", "try later");
        } else {
            sendFull(socket, 200, "OK", manifest, "Content-Type: application/json\r\n");
        }
    });
    if (!server.listen()) {
        result.expect(false, QStringLiteral("no se pudo escuchar en 127.0.0.1"));
        return result;
    }
    Harness h(dir, server.port(), /*downloads=*/false);
    h.service->checkForUpdates(/*manual=*/true);
    const bool done = waitUntil([&]() { return h.firstResult() != nullptr; }, 30000);
    result.expect(done, QStringLiteral("no termino el chequeo"));
    const DialogEntry *entry = h.firstResult();
    result.expect(entry && entry->message.contains(QStringLiteral("latest version")),
                  QStringLiteral("se esperaba \"latest version\", vino: %1")
                      .arg(entry ? entry->title + QStringLiteral(" / ") + entry->message
                                 : QStringLiteral("nada")));
    result.expect(h.net.urls.size() == 3,
                  QStringLiteral("intentos del cliente=%1, se esperaban 3").arg(h.net.urls.size()));
    result.expect(server.requests.size() == 3,
                  QStringLiteral("pedidos al servidor=%1, se esperaban 3").arg(server.requests.size()));
    result.notes << QStringLiteral("intentos=%1 pedidos=%2").arg(h.net.urls.size()).arg(server.requests.size());
    return result;
}

// (5a) El servicio muere mientras espera el reintento del chequeo: no sale ningun pedido mas.
CaseResult caseDestroyDuringWait(const QString &dir)
{
    CaseResult result;
    const QByteArray manifest = manifestJson(kInstalledVersion, kFakeSha);
    ScriptServer server([&](QTcpSocket *socket, int, const HttpRequestInfo &) {
        sendCut(socket, manifest.size(), manifest.left(manifest.size() / 2));
    });
    if (!server.listen()) {
        result.expect(false, QStringLiteral("no se pudo escuchar en 127.0.0.1"));
        return result;
    }
    Harness h(dir, server.port(), /*downloads=*/false);
    h.service->checkForUpdates(/*manual=*/true);
    const bool waiting =
        waitUntil([&]() { return h.log().contains(QStringLiteral("se reintenta")); }, 15000);
    result.expect(waiting, QStringLiteral("nunca entro en la espera del reintento"));
    result.expect(h.service->isBusy(), QStringLiteral("esperando el reintento no cuenta como ocupado"));
    delete h.service;
    h.service = nullptr;
    pump(3 * kTestDelayMs + 500);
    result.expect(h.net.urls.size() == 1,
                  QStringLiteral("intentos del cliente=%1, se esperaba 1").arg(h.net.urls.size()));
    result.expect(server.requests.size() == 1,
                  QStringLiteral("pedidos al servidor=%1, se esperaba 1").arg(server.requests.size()));
    result.expect(h.dialogs.isEmpty(), QStringLiteral("salio un cartel despues de destruir el servicio"));
    result.notes << QStringLiteral("intentos=%1 pedidos=%2").arg(h.net.urls.size()).arg(server.requests.size());
    return result;
}

// Servidor de las descargas: el manifiesto siempre bien; el asset segun `assetScript`, con el
// indice de pedido DEL ASSET (0 = el primero).
using AssetScript = std::function<void(QTcpSocket *, int assetIndex, const HttpRequestInfo &)>;

std::unique_ptr<ScriptServer> downloadServer(const QByteArray &manifest, AssetScript assetScript)
{
    auto assetCount = std::make_shared<int>(0);
    return std::make_unique<ScriptServer>(
        [manifest, assetScript, assetCount](QTcpSocket *socket, int, const HttpRequestInfo &request) {
            if (request.path.endsWith("/versions.json")) {
                sendFull(socket, 200, "OK", manifest, "Content-Type: application/json\r\n");
                return;
            }
            assetScript(socket, (*assetCount)++, request);
        });
}

qint64 rangeStart(const HttpRequestInfo &request)
{
    const QByteArray range = request.headers.value("range");
    if (!range.startsWith("bytes=")) {
        return -1;
    }
    bool ok = false;
    const qint64 start = range.mid(6, range.indexOf('-') - 6).toLongLong(&ok);
    return ok ? start : -1;
}

// (5b) Cancel del dialogo de progreso mientras la descarga espera el reintento.
CaseResult caseCancelDownloadDuringWait(const QString &dir)
{
    CaseResult result;
    const QByteArray content = deterministicContent(256 * 1024);
    auto server = downloadServer(manifestJson(kOfferedVersion, sha256Hex(content)),
                                 [&content](QTcpSocket *socket, int, const HttpRequestInfo &) {
                                     sendCut(socket, content.size(), content.left(content.size() / 2));
                                 });
    if (!server->listen()) {
        result.expect(false, QStringLiteral("no se pudo escuchar en 127.0.0.1"));
        return result;
    }
    Harness h(dir, server->port(), /*downloads=*/true);
    h.clickUpdate = true;
    h.gate.expected = content;
    h.service->checkForUpdates(/*manual=*/true);
    const bool waiting =
        waitUntil([&]() { return h.log().contains(QStringLiteral("Descarga cortada")); }, 20000);
    result.expect(waiting, QStringLiteral("la descarga nunca entro en la espera del reintento"));
    QProgressDialog *dialog = h.progressDialog();
    result.expect(dialog != nullptr, QStringLiteral("no hay dialogo de progreso durante la espera"));
    const QString label = dialog ? dialog->labelText() : QString();
    result.expect(label.contains(QStringLiteral("Retrying (attempt 2 of 4)")),
                  QStringLiteral("el dialogo no dice que reintenta: \"%1\"").arg(label));
    result.expect(h.service->isBusy(), QStringLiteral("esperando el reintento no cuenta como ocupado"));
    QPushButton *cancel = dialog ? dialog->findChild<QPushButton *>() : nullptr;
    result.expect(cancel != nullptr, QStringLiteral("el dialogo no tiene boton Cancel"));
    if (cancel) {
        cancel->click();
    }
    pump(3 * kTestDelayMs + 500);
    const int assetRequests = server->countPath(installerAssetName(kOfferedVersion).toUtf8());
    result.expect(assetRequests == 1,
                  QStringLiteral("pedidos del asset=%1, se esperaba 1").arg(assetRequests));
    result.expect(h.firstResult() == nullptr,
                  QStringLiteral("cancelar mostro un cartel: %1")
                      .arg(h.firstResult() ? h.firstResult()->title : QString()));
    result.expect(h.gate.calls == 1,
                  QStringLiteral("installBlockedReason llamado %1 veces, se esperaba 1").arg(h.gate.calls));
    result.expect(!h.service->isBusy(), QStringLiteral("el servicio sigue ocupado"));
    result.expect(h.progressDialog() == nullptr || !h.progressDialog()->isVisible(),
                  QStringLiteral("el dialogo de progreso sigue abierto"));
    result.expect(h.updateDirFiles().isEmpty(),
                  QStringLiteral("quedaron archivos en la carpeta de updates: %1")
                      .arg(h.updateDirFiles().join(QStringLiteral(", "))));
    result.expect(h.log().contains(QStringLiteral("mientras esperaba el reintento")),
                  QStringLiteral("el log no anota la cancelacion durante la espera"));
    result.expect(h.quitCalls == 0, QStringLiteral("se pidio cerrar la app"));
    result.notes << QStringLiteral("texto durante la espera=\"%1\" pedidos del asset=%2")
                        .arg(label).arg(assetRequests);
    if (!result.ok) {
        result.notes << QStringLiteral("log:\n    ") + lastLines(h.log(), 12);
    }
    return result;
}

// (6) Descarga cortada a la mitad: el segundo intento pide Range desde donde quedo y el
// instalador queda identico al original. Con `honorRange = false` el servidor ignora el Range
// y manda 200 con todo: el servicio tiene que empezar de cero y quedar igual de bien.
CaseResult caseDownloadResume(const QString &dir, bool honorRange)
{
    CaseResult result;
    const QByteArray content = deterministicContent(300 * 1024 + 123);
    qint64 resumedFrom = -2;
    QByteArray secondRange;
    auto server = downloadServer(
        manifestJson(kOfferedVersion, sha256Hex(content)),
        [&](QTcpSocket *socket, int assetIndex, const HttpRequestInfo &request) {
            if (assetIndex == 0) {
                sendCut(socket, content.size(), content.left(content.size() / 2));
                return;
            }
            secondRange = request.headers.value("range");
            resumedFrom = rangeStart(request);
            if (honorRange && resumedFrom >= 0 && resumedFrom < content.size()) {
                const QByteArray contentRange = "Content-Range: bytes " + QByteArray::number(resumedFrom)
                    + '-' + QByteArray::number(content.size() - 1) + '/'
                    + QByteArray::number(content.size()) + "\r\n";
                sendFull(socket, 206, "Partial Content", content.mid(resumedFrom), contentRange);
            } else {
                sendFull(socket, 200, "OK", content);
            }
        });
    if (!server->listen()) {
        result.expect(false, QStringLiteral("no se pudo escuchar en 127.0.0.1"));
        return result;
    }
    Harness h(dir, server->port(), /*downloads=*/true);
    h.clickUpdate = true;
    h.gate.expected = content;
    h.service->checkForUpdates(/*manual=*/true);

    // El dialogo de progreso REAL de la libreria se guarda en PNG en sus dos estados, para
    // mirarlo: descargando (primer intento) y reintentando (la espera). Con `-Platform windows`
    // del runner sale con las fuentes del sistema; en offscreen el texto puede no dibujarse.
    QString labelDuringWait;
    bool grabbedDownloading = false;
    const QString downloadingShot = QDir(dir).filePath(QStringLiteral("progreso_1_descargando.png"));
    const QString retryingShot = QDir(dir).filePath(QStringLiteral("progreso_2_reintentando.png"));
    const bool done = waitUntil(
        [&]() {
            QProgressDialog *dialog = h.progressDialog();
            if (dialog && !grabbedDownloading
                && dialog->labelText().startsWith(QStringLiteral("Downloading"))) {
                grabbedDownloading = true;
                dialog->grab().save(downloadingShot);
            }
            if (labelDuringWait.isEmpty() && h.log().contains(QStringLiteral("Descarga cortada"))) {
                if (dialog) {
                    labelDuringWait = dialog->labelText();
                    dialog->grab().save(retryingShot);
                }
            }
            return h.firstResult() != nullptr;
        },
        30000);
    result.expect(done, QStringLiteral("la descarga no termino"));
    const DialogEntry *entry = h.firstResult();
    result.expect(entry && entry->title == QLatin1String("Update Postponed"),
                  QStringLiteral("se esperaba \"Update Postponed\" (descarga buena, instalacion "
                                 "frenada), vino: %1 / %2 / %3")
                      .arg(entry ? entry->title : QStringLiteral("nada"),
                           entry ? entry->message : QString(), entry ? entry->details : QString()));
    const int assetRequests = server->countPath(installerAssetName(kOfferedVersion).toUtf8());
    result.expect(assetRequests == 2,
                  QStringLiteral("pedidos del asset=%1, se esperaban 2").arg(assetRequests));
    result.expect(resumedFrom > 0 && resumedFrom < content.size(),
                  QStringLiteral("el segundo intento no pidio Range desde donde quedo: \"%1\"")
                      .arg(QString::fromLatin1(secondRange)));
    result.expect(h.gate.fileChecked && h.gate.fileMatched,
                  QStringLiteral("el instalador bajado no es identico al original (leido=%1)")
                      .arg(h.gate.fileChecked));
    result.expect(labelDuringWait.contains(QStringLiteral("Retrying (attempt 2 of 4)")),
                  QStringLiteral("durante la espera el dialogo decia: \"%1\"").arg(labelDuringWait));
    result.expect(h.gate.labelAtFinish == QStringLiteral("Downloading LGA Test Retry 9.999..."),
                  QStringLiteral("al terminar el dialogo no volvio al texto de la descarga: \"%1\"")
                      .arg(h.gate.labelAtFinish));
    result.expect(grabbedDownloading && QFile::exists(downloadingShot) && QFile::exists(retryingShot),
                  QStringLiteral("no se guardaron las dos capturas del dialogo"));
    result.expect(h.quitCalls == 0, QStringLiteral("se pidio cerrar la app"));
    result.expect(h.gate.calls == 2,
                  QStringLiteral("installBlockedReason llamado %1 veces, se esperaban 2").arg(h.gate.calls));
    const QString log = h.log();
    result.expect(log.contains(QStringLiteral("SHA-256 verificado")),
                  QStringLiteral("el log no dice SHA-256 verificado"));
    result.expect(!QFile::exists(h.gate.installerPath),
                  QStringLiteral("el instalador frenado quedo en disco"));
    result.notes << QStringLiteral("Range del segundo intento=\"%1\" de %2 bytes; texto durante la "
                                   "espera=\"%3\"")
                        .arg(QString::fromLatin1(secondRange))
                        .arg(content.size())
                        .arg(labelDuringWait);
    if (!result.ok) {
        result.notes << QStringLiteral("log:\n    ") + lastLines(log, 14);
    }
    return result;
}

// (6c) El servidor del asset contesta 503 SIEMPRE: exactamente cuatro pedidos y el cartel de
// fallo, sin nada en disco. (6d) Contesta 503 una vez, ANTES del primer byte, y despues sirve: el
// segundo intento arranca de cero (sin Range) y la descarga queda buena.
CaseResult caseDownload503(const QString &dir, bool always)
{
    CaseResult result;
    const QByteArray content = deterministicContent(64 * 1024);
    QList<QByteArray> ranges;
    auto server = downloadServer(manifestJson(kOfferedVersion, sha256Hex(content)),
                                 [&](QTcpSocket *socket, int assetIndex, const HttpRequestInfo &request) {
                                     ranges << request.headers.value("range");
                                     if (always || assetIndex == 0) {
                                         sendFull(socket, 503, "Service Unavailable", "try later");
                                     } else {
                                         sendFull(socket, 200, "OK", content);
                                     }
                                 });
    if (!server->listen()) {
        result.expect(false, QStringLiteral("no se pudo escuchar en 127.0.0.1"));
        return result;
    }
    Harness h(dir, server->port(), /*downloads=*/true);
    h.clickUpdate = true;
    h.gate.expected = content;
    h.service->checkForUpdates(/*manual=*/true);
    const bool done = waitUntil([&]() { return h.firstResult() != nullptr; }, 30000);
    result.expect(done, QStringLiteral("la descarga no termino"));
    pump(3 * kTestDelayMs + 300);
    const DialogEntry *entry = h.firstResult();
    const int assetRequests = server->countPath(installerAssetName(kOfferedVersion).toUtf8());
    if (always) {
        result.expect(entry && entry->title == QLatin1String("Update Failed")
                          && entry->message.contains(QStringLiteral("rejected")),
                      QStringLiteral("se esperaba \"Update Failed\" / rejected, vino: %1 / %2")
                          .arg(entry ? entry->title : QStringLiteral("nada"),
                               entry ? entry->message : QString()));
        result.expect(assetRequests == 4,
                      QStringLiteral("pedidos del asset=%1, se esperaban 4").arg(assetRequests));
        result.expect(h.gate.calls == 1,
                      QStringLiteral("installBlockedReason llamado %1 veces, se esperaba 1")
                          .arg(h.gate.calls));
        result.expect(h.log().contains(QStringLiteral("Descarga fallida (intento 4 (4 de 4 en 127.0.0.1))")),
                      QStringLiteral("el log no dice \"Descarga fallida (intento 4 (4 de 4 en 127.0.0.1))\""));
    } else {
        result.expect(entry && entry->title == QLatin1String("Update Postponed"),
                      QStringLiteral("se esperaba \"Update Postponed\", vino: %1 / %2")
                          .arg(entry ? entry->title : QStringLiteral("nada"),
                               entry ? entry->details : QString()));
        result.expect(assetRequests == 2,
                      QStringLiteral("pedidos del asset=%1, se esperaban 2").arg(assetRequests));
        result.expect(ranges.size() == 2 && ranges.at(1).isEmpty(),
                      QStringLiteral("el segundo intento mando Range \"%1\" sin tener nada bajado")
                          .arg(QString::fromLatin1(ranges.value(1))));
        result.expect(h.gate.fileChecked && h.gate.fileMatched,
                      QStringLiteral("el instalador bajado no es identico al original"));
    }
    result.expect(h.updateDirFiles().isEmpty(),
                  QStringLiteral("quedaron archivos en la carpeta de updates: %1")
                      .arg(h.updateDirFiles().join(QStringLiteral(", "))));
    result.expect(!h.service->isBusy(), QStringLiteral("el servicio sigue ocupado"));
    result.expect(h.quitCalls == 0, QStringLiteral("se pidio cerrar la app"));
    result.notes << QStringLiteral("pedidos del asset=%1 cartel=\"%2\"")
                        .arg(assetRequests)
                        .arg(entry ? entry->title : QString());
    if (!result.ok) {
        result.notes << QStringLiteral("log:\n    ") + lastLines(h.log(), 14);
    }
    return result;
}

// (7) Historial de Help: el manifiesto contesta 503 una vez y las notas se cortan una vez.
CaseResult caseHistoryRetries(const QString &dir)
{
    CaseResult result;
    const QByteArray notes = notesJson();
    const QByteArray manifest = manifestJson(kInstalledVersion, kFakeSha, sha256Hex(notes));
    int manifestHits = 0;
    int notesHits = 0;
    ScriptServer server([&](QTcpSocket *socket, int, const HttpRequestInfo &request) {
        if (request.path.endsWith("/versions.json")) {
            if (manifestHits++ == 0) {
                sendFull(socket, 503, "Service Unavailable", "try later");
            } else {
                sendFull(socket, 200, "OK", manifest, "Content-Type: application/json\r\n");
            }
            return;
        }
        if (notesHits++ == 0) {
            sendCut(socket, notes.size(), notes.left(notes.size() / 2));
        } else {
            sendFull(socket, 200, "OK", notes, "Content-Type: application/json\r\n");
        }
    });
    if (!server.listen()) {
        result.expect(false, QStringLiteral("no se pudo escuchar en 127.0.0.1"));
        return result;
    }
    Harness h(dir, server.port(), /*downloads=*/false);
    h.service->showWhatsNewHistory(&h.parent);
    const bool done = waitUntil([&]() { return !h.dialogs.isEmpty(); }, 30000);
    result.expect(done, QStringLiteral("el historial no mostro nada"));
    const DialogEntry *whatsNew = h.firstOfKind(LgaUpdateDialogSpec::Kind::WhatsNew);
    result.expect(whatsNew != nullptr,
                  QStringLiteral("se esperaba el cartel What's New, vino: %1 / %2")
                      .arg(h.dialogs.isEmpty() ? QStringLiteral("nada") : h.dialogs.first().title,
                           h.dialogs.isEmpty() ? QString() : h.dialogs.first().details));
    result.expect(h.net.countPath(QStringLiteral("/versions.json")) == 2,
                  QStringLiteral("intentos del manifiesto=%1, se esperaban 2")
                      .arg(h.net.countPath(QStringLiteral("/versions.json"))));
    result.expect(h.net.countPath(QStringLiteral("/whats_new.json")) == 2,
                  QStringLiteral("intentos de las notas=%1, se esperaban 2")
                      .arg(h.net.countPath(QStringLiteral("/whats_new.json"))));
    const QString log = h.log();
    result.expect(log.contains(QStringLiteral("Manifiesto para las notas fallido (intento 1 de 4)")),
                  QStringLiteral("el log no anota el reintento del manifiesto"));
    result.expect(log.contains(QStringLiteral("Notas fallidas (intento 1 de 4)")),
                  QStringLiteral("el log no anota el reintento de las notas"));
    result.notes << QStringLiteral("manifiesto=%1 notas=%2")
                        .arg(h.net.countPath(QStringLiteral("/versions.json")))
                        .arg(h.net.countPath(QStringLiteral("/whats_new.json")));
    if (!result.ok) {
        result.notes << QStringLiteral("log:\n    ") + lastLines(log, 14);
    }
    return result;
}

// (5c) `cancel()` del fetcher de notas durante la espera: no sale el reintento ni `finished`.
CaseResult caseFetcherCancelDuringWait(const QString &dir)
{
    CaseResult result;
    const QByteArray notes = notesJson();
    ScriptServer server([&](QTcpSocket *socket, int, const HttpRequestInfo &) {
        sendCut(socket, notes.size(), notes.left(notes.size() / 2));
    });
    if (!server.listen()) {
        result.expect(false, QStringLiteral("no se pudo escuchar en 127.0.0.1"));
        return result;
    }
    NetLog net;
    QObject owner;
    auto *network = new LoopbackNetwork(server.port(), &net, &owner);
    auto *fetcher = new LgaWhatsNewFetcher(network, &owner);
    int finishedCount = 0;
    QObject::connect(fetcher, &LgaWhatsNewFetcher::finished, &owner,
                     [&finishedCount](const LgaWhatsNewFetchResult &) { ++finishedCount; });
    QStringList lines;
    LgaWhatsNewFetcher::Request request;
    request.repoSlug = kReleaseSlug;
    request.asset = LgaWhatsNew::AssetRef{QStringLiteral("v1.000"), sha256Hex(notes)};
    request.cacheDir = dir;
    request.timeoutMs = 5000;
    request.log = [&lines](const QString &message) { lines << message; };
    fetcher->fetch(request);
    const bool waiting = waitUntil(
        [&]() { return lines.join(QLatin1Char('\n')).contains(QStringLiteral("se reintenta")); },
        15000);
    result.expect(waiting, QStringLiteral("el fetcher nunca entro en la espera del reintento"));
    result.expect(fetcher->isRunning(), QStringLiteral("esperando el reintento no cuenta como en curso"));
    fetcher->cancel();
    pump(3 * kTestDelayMs + 500);
    result.expect(net.urls.size() == 1,
                  QStringLiteral("intentos del cliente=%1, se esperaba 1").arg(net.urls.size()));
    result.expect(server.requests.size() == 1,
                  QStringLiteral("pedidos al servidor=%1, se esperaba 1").arg(server.requests.size()));
    result.expect(finishedCount == 0, QStringLiteral("finished salio %1 veces despues de cancelar").arg(finishedCount));
    result.notes << QStringLiteral("intentos=%1 pedidos=%2").arg(net.urls.size()).arg(server.requests.size());
    if (!result.ok) {
        result.notes << QStringLiteral("log:\n    ") + lines.join(QStringLiteral("\n    "));
    }
    return result;
}

/// Inicio de un `Range: bytes=N-`, o -1 si no hay o no se entiende.
qint64 rangeStartOf(const QByteArray &range)
{
    if (!range.startsWith("bytes=")) {
        return -1;
    }
    bool ok = false;
    const qint64 start = range.mid(6, range.indexOf('-') - 6).toLongLong(&ok);
    return ok ? start : -1;
}

/// Valor de `Content-Range` para servir desde `from` hasta el final de `total` bytes.
QByteArray contentRangeField(qint64 from, qint64 total)
{
    return "bytes " + QByteArray::number(from) + '-' + QByteArray::number(total - 1) + '/'
        + QByteArray::number(total);
}

enum class H2Cut { RstInternalError, RstCancel, GoAway };

// (8) Descarga por HTTP/2 cortada a mitad del cuerpo, como lo hacen GitHub y los CDN: con un
// RST_STREAM (INTERNAL_ERROR o CANCEL) o con un GOAWAY. Qt no lo informa como un cierre de
// conexion sino como InternalServerError con status 200, ProtocolFailure o ContentReSendError
// (qhttp2protocolhandler.cpp y http2protocol.cpp de Qt 6.5.3). La descarga tiene que reintentar
// igual y reanudar por Range desde donde quedo.
CaseResult caseHttp2Cut(const QString &dir, H2Cut cut)
{
    CaseResult result;
    // Chico a proposito: los dos intentos juntos entran en la ventana de control de flujo por
    // defecto de HTTP/2 (64 KB), asi el servidor nunca tiene que esperar un WINDOW_UPDATE.
    const QByteArray content = deterministicContent(40 * 1024 + 11);
    const qsizetype cutAt = 15 * 1024 + 5;
    const NetLog *clientLog = nullptr;
    QByteArray secondRange;
    H2Server assetServer([&](QTcpSocket *socket, quint32 streamId, int index) {
        if (index == 0) {
            socket->write(h2Headers(streamId, 200,
                                    {{"content-length", QByteArray::number(content.size())}}));
            socket->write(h2Data(streamId, content.left(cutAt), /*endStream=*/false));
            if (cut == H2Cut::GoAway) {
                // last-stream-id 0 y NO_ERROR: «este stream no se proceso». Despues, el cierre.
                socket->write(h2Frame(H2::kGoAway, 0, 0, be32(0) + be32(0)));
                socket->flush();
                QTimer::singleShot(150, socket, [socket]() { socket->disconnectFromHost(); });
            } else {
                socket->write(h2Frame(
                    H2::kRstStream, 0, streamId,
                    be32(cut == H2Cut::RstCancel ? H2::kCancel : H2::kInternalError)));
            }
            return;
        }
        secondRange = (clientLog && !clientLog->ranges.isEmpty()) ? clientLog->ranges.last()
                                                                  : QByteArray();
        const qint64 from = rangeStartOf(secondRange);
        if (from > 0 && from < content.size()) {
            const QByteArray rest = content.mid(from);
            socket->write(h2Headers(streamId, 206,
                                    {{"content-length", QByteArray::number(rest.size())},
                                     {"content-range", contentRangeField(from, content.size())}}));
            socket->write(h2Data(streamId, rest, /*endStream=*/true));
        } else {
            socket->write(h2Headers(streamId, 200,
                                    {{"content-length", QByteArray::number(content.size())}}));
            socket->write(h2Data(streamId, content, /*endStream=*/true));
        }
    });
    const QByteArray manifest = manifestJson(kOfferedVersion, sha256Hex(content));
    ScriptServer manifestServer([&](QTcpSocket *socket, int, const HttpRequestInfo &) {
        sendFull(socket, 200, "OK", manifest, "Content-Type: application/json\r\n");
    });
    if (!assetServer.listen() || !manifestServer.listen()) {
        result.expect(false, QStringLiteral("no se pudo escuchar en 127.0.0.1"));
        return result;
    }
    LoopbackOptions options;
    options.assetPort = assetServer.port();
    options.assetHttp2 = true;
    Harness h(dir, manifestServer.port(), /*downloads=*/true, options);
    clientLog = &h.net;
    h.clickUpdate = true;
    h.gate.expected = content;
    h.service->checkForUpdates(/*manual=*/true);
    QString labelDuringWait;
    const bool done = waitUntil(
        [&]() {
            if (labelDuringWait.isEmpty() && h.log().contains(QStringLiteral("Descarga cortada"))) {
                if (QProgressDialog *dialog = h.progressDialog()) {
                    labelDuringWait = dialog->labelText();
                }
            }
            return h.firstResult() != nullptr;
        },
        30000);
    result.expect(done, QStringLiteral("la descarga no termino"));
    pump(3 * kTestDelayMs + 300);

    QNetworkReply::NetworkError expected = QNetworkReply::InternalServerError;
    if (cut == H2Cut::RstCancel) {
        expected = QNetworkReply::ProtocolFailure;
    } else if (cut == H2Cut::GoAway) {
        expected = QNetworkReply::ContentReSendError;
    }
    const QString expectedError =
        QStringLiteral("networkError=%1 ").arg(static_cast<int>(expected));
    const DialogEntry *entry = h.firstResult();
    result.expect(entry && entry->title == QLatin1String("Update Postponed"),
                  QStringLiteral("se esperaba \"Update Postponed\" (descarga buena, instalacion "
                                 "frenada), vino: %1 / %2 / %3")
                      .arg(entry ? entry->title : QStringLiteral("nada"),
                           entry ? entry->message : QString(), entry ? entry->details : QString()));
    result.expect(assetServer.badPrefaces == 0,
                  QStringLiteral("%1 conexion(es) al servidor del instalador no hablaron HTTP/2")
                      .arg(assetServer.badPrefaces));
    result.expect(assetServer.requests == 2,
                  QStringLiteral("pedidos del asset por HTTP/2=%1, se esperaban 2")
                      .arg(assetServer.requests));
    const qint64 resumedFrom = rangeStartOf(secondRange);
    result.expect(resumedFrom > 0 && resumedFrom <= cutAt,
                  QStringLiteral("el segundo intento no pidio Range desde donde quedo: \"%1\"")
                      .arg(QString::fromLatin1(secondRange)));
    result.expect(h.gate.fileChecked && h.gate.fileMatched,
                  QStringLiteral("el instalador bajado no es identico al original (leido=%1)")
                      .arg(h.gate.fileChecked));
    const QString log = h.log();
    result.expect(log.contains(expectedError),
                  QStringLiteral("el corte no llego como \"%1\" (el log no lo tiene)")
                      .arg(expectedError.trimmed()));
    result.expect(labelDuringWait.contains(QStringLiteral("Retrying (attempt 2 of 4)")),
                  QStringLiteral("durante la espera el dialogo decia: \"%1\"").arg(labelDuringWait));
    result.expect(h.gate.labelAtFinish == QStringLiteral("Downloading LGA Test Retry 9.999..."),
                  QStringLiteral("al terminar el dialogo no volvio al texto de la descarga: \"%1\"")
                      .arg(h.gate.labelAtFinish));
    result.expect(h.gate.calls == 2,
                  QStringLiteral("installBlockedReason llamado %1 veces, se esperaban 2").arg(h.gate.calls));
    result.expect(h.quitCalls == 0, QStringLiteral("se pidio cerrar la app"));
    result.expect(!QFile::exists(h.gate.installerPath),
                  QStringLiteral("el instalador frenado quedo en disco"));
    result.expect(!h.service->isBusy(), QStringLiteral("el servicio sigue ocupado"));
    result.notes << QStringLiteral("%1; Range del segundo intento=\"%2\" (corte en %3 de %4 bytes); "
                                   "conexiones h2=%5")
                        .arg(expectedError.trimmed(), QString::fromLatin1(secondRange))
                        .arg(cutAt)
                        .arg(content.size())
                        .arg(assetServer.connections);
    if (!result.ok) {
        result.notes << QStringLiteral("log:\n    ") + lastLines(log, 14);
    }
    return result;
}

// (9) Cuenta por servidor (`LgaNetRetry::Budget`), como una descarga real de GitHub: github.com
// contesta 503 al primer intento (un destino nuevo que el firewall frena) y despues redirige al
// servidor de los archivos, que corta tres veces seguidas a mitad del cuerpo. Con una sola cuenta
// de cuatro intentos la descarga fallaria en el cuarto; por servidor termina en el quinto, y cada
// intento reanuda por Range a traves del redirect. Va por el proxy de prueba en 127.0.0.1 para
// que los pedidos conserven sus nombres de servidor sin salir de la maquina.
CaseResult caseDownloadPerHost(const QString &dir)
{
    CaseResult result;
    const QByteArray content = deterministicContent(200 * 1024 + 77);
    const QByteArray manifest = manifestJson(kOfferedVersion, sha256Hex(content));
    int githubHits = 0;
    int otherHits = 0;
    QList<QByteArray> blobRanges;
    ScriptServer server([&](QTcpSocket *socket, int, const HttpRequestInfo &request) {
        if (request.path.endsWith("/versions.json")) {
            sendFull(socket, 200, "OK", manifest, "Content-Type: application/json\r\n");
            return;
        }
        if (request.path.contains("//github.com/")) {
            if (githubHits++ == 0) {
                sendFull(socket, 503, "Service Unavailable", "try later");
            } else {
                sendFull(socket, 302, "Found", QByteArray(),
                         "Location: http://objects.githubusercontent.com/blob/installer.bin\r\n");
            }
            return;
        }
        if (request.path.contains("//objects.githubusercontent.com/")) {
            const qsizetype blobIndex = blobRanges.size();
            const QByteArray range = request.headers.value("range");
            blobRanges << range;
            const qint64 from = qMax<qint64>(0, rangeStartOf(range));
            const QByteArray rest = content.mid(from);
            const bool partial = from > 0;
            const int status = partial ? 206 : 200;
            const QByteArray reason = partial ? "Partial Content" : "OK";
            const QByteArray extra = partial
                ? "Content-Range: " + contentRangeField(from, content.size()) + "\r\n"
                : QByteArray();
            if (blobIndex == 0) {
                sendCut(socket, rest.size(), rest.left(rest.size() / 2), status, reason, extra);
            } else if (blobIndex < 3) {
                sendCut(socket, rest.size(), rest.left(4096), status, reason, extra);
            } else {
                sendFull(socket, status, reason, rest, extra);
            }
            return;
        }
        ++otherHits;
        sendFull(socket, 404, "Not Found", "fuera del guion");
    });
    if (!server.listen()) {
        result.expect(false, QStringLiteral("no se pudo escuchar en 127.0.0.1"));
        return result;
    }
    LoopbackOptions options;
    options.viaProxy = true;
    Harness h(dir, server.port(), /*downloads=*/true, options);
    h.clickUpdate = true;
    h.gate.expected = content;
    h.service->checkForUpdates(/*manual=*/true);
    QStringList retryLabels;
    const bool done = waitUntil(
        [&]() {
            if (QProgressDialog *dialog = h.progressDialog()) {
                const QString label = dialog->labelText();
                if (label.contains(QStringLiteral("Retrying"))
                    && (retryLabels.isEmpty() || retryLabels.last() != label)) {
                    retryLabels << label;
                }
            }
            return h.firstResult() != nullptr;
        },
        40000);
    result.expect(done, QStringLiteral("la descarga no termino"));
    pump(3 * kTestDelayMs + 300);

    const DialogEntry *entry = h.firstResult();
    result.expect(entry && entry->title == QLatin1String("Update Postponed"),
                  QStringLiteral("se esperaba \"Update Postponed\", vino: %1 / %2 / %3")
                      .arg(entry ? entry->title : QStringLiteral("nada"),
                           entry ? entry->message : QString(), entry ? entry->details : QString()));
    result.expect(h.gate.fileChecked && h.gate.fileMatched,
                  QStringLiteral("el instalador bajado no es identico al original (leido=%1)")
                      .arg(h.gate.fileChecked));
    const int clientAttempts = h.net.countPath(installerAssetName(kOfferedVersion));
    result.expect(clientAttempts == 5,
                  QStringLiteral("intentos de la descarga=%1, se esperaban 5").arg(clientAttempts));
    result.expect(githubHits == 5,
                  QStringLiteral("pedidos a github.com=%1, se esperaban 5").arg(githubHits));
    result.expect(blobRanges.size() == 4,
                  QStringLiteral("pedidos al servidor de los archivos=%1, se esperaban 4")
                      .arg(blobRanges.size()));
    result.expect(otherHits == 0, QStringLiteral("%1 pedido(s) fuera del guion").arg(otherHits));
    bool rangesGrow = !blobRanges.isEmpty() && blobRanges.first().isEmpty();
    for (qsizetype i = 1; i < blobRanges.size(); ++i) {
        rangesGrow = rangesGrow && rangeStartOf(blobRanges.at(i)) > qMax<qint64>(0, rangeStartOf(blobRanges.at(i - 1)));
    }
    QStringList rangeTexts;
    for (const QByteArray &range : blobRanges) {
        rangeTexts << (range.isEmpty() ? QStringLiteral("-") : QString::fromLatin1(range));
    }
    result.expect(rangesGrow,
                  QStringLiteral("el Range no paso el redirect o no avanzo: %1")
                      .arg(rangeTexts.join(QStringLiteral(" | "))));
    const QString log = h.log();
    result.expect(log.contains(QStringLiteral("Descarga (intento 2 (2 de 4 en github.com))")),
                  QStringLiteral("el log no cuenta el reintento en github.com"));
    result.expect(log.contains(
                      QStringLiteral("Descarga (intento 5 (4 de 4 en objects.githubusercontent.com))")),
                  QStringLiteral("el log no cuenta los reintentos en el servidor de los archivos"));
    result.expect(!retryLabels.isEmpty()
                      && retryLabels.last().contains(QStringLiteral("Retrying (attempt 4 of 4)")),
                  QStringLiteral("textos del dialogo durante las esperas: %1")
                      .arg(retryLabels.join(QStringLiteral(" | "))));
    result.expect(h.gate.calls == 2,
                  QStringLiteral("installBlockedReason llamado %1 veces, se esperaban 2").arg(h.gate.calls));
    result.expect(h.quitCalls == 0, QStringLiteral("se pidio cerrar la app"));
    result.expect(!h.service->isBusy(), QStringLiteral("el servicio sigue ocupado"));
    result.expect(h.updateDirFiles().isEmpty(),
                  QStringLiteral("quedaron archivos en la carpeta de updates: %1")
                      .arg(h.updateDirFiles().join(QStringLiteral(", "))));
    result.notes << QStringLiteral("intentos=%1 github.com=%2 archivos=%3 Range=%4")
                        .arg(clientAttempts)
                        .arg(githubHits)
                        .arg(blobRanges.size())
                        .arg(rangeTexts.join(QStringLiteral(" | ")));
    if (!result.ok) {
        result.notes << QStringLiteral("log:\n    ") + lastLines(log, 20);
    }
    return result;
}

} // namespace

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QApplication::setOrganizationName(QStringLiteral("LGA_Test"));
    QApplication::setApplicationName(QStringLiteral("lgaupdate_retry_tests"));
    QApplication::setApplicationVersion(kInstalledVersion);
    // Cualquier ruta estandar que se colara va a la carpeta de pruebas de Qt, nunca a la de una
    // app real. La config de cada caso ya fija todas sus rutas dentro de la carpeta de trabajo.
    QStandardPaths::setTestModeEnabled(true);
    LgaNetRetry::delayMsOverrideForTests() = kTestDelayMs;

    const QStringList args = QCoreApplication::arguments();
    if (args.size() < 2 || args.at(1).trimmed().isEmpty()) {
        out(QStringLiteral("uso: lgaupdate_retry_tests <carpeta de trabajo> [caso]"));
        return 2;
    }
    const QString workDir = QDir::cleanPath(QFileInfo(args.at(1)).absoluteFilePath());
    const QString only = args.value(2);
    if (!QDir().mkpath(workDir)) {
        out(QStringLiteral("no se pudo crear la carpeta de trabajo %1").arg(workDir));
        return 2;
    }

    struct Case {
        QString name;
        std::function<CaseResult(const QString &)> run;
    };
    const QList<Case> cases = {
        {QStringLiteral("1_manifiesto_cortado_dos_veces"), caseManifestCutTwice},
        {QStringLiteral("2_puerto_cerrado"), caseClosedPort},
        {QStringLiteral("3_http_404"), caseHttp404},
        {QStringLiteral("4_http_503_dos_veces"), caseHttp503Twice},
        {QStringLiteral("5a_servicio_destruido_en_la_espera"), caseDestroyDuringWait},
        {QStringLiteral("5b_cancel_de_la_descarga_en_la_espera"), caseCancelDownloadDuringWait},
        {QStringLiteral("5c_cancel_del_fetcher_en_la_espera"), caseFetcherCancelDuringWait},
        {QStringLiteral("6_descarga_cortada_reanuda_por_range"),
         [](const QString &dir) { return caseDownloadResume(dir, /*honorRange=*/true); }},
        {QStringLiteral("6b_descarga_cortada_servidor_ignora_range"),
         [](const QString &dir) { return caseDownloadResume(dir, /*honorRange=*/false); }},
        {QStringLiteral("6c_descarga_503_siempre"),
         [](const QString &dir) { return caseDownload503(dir, /*always=*/true); }},
        {QStringLiteral("6d_descarga_503_antes_del_primer_byte"),
         [](const QString &dir) { return caseDownload503(dir, /*always=*/false); }},
        {QStringLiteral("7_historial_manifiesto_503_y_notas_cortadas"), caseHistoryRetries},
        {QStringLiteral("8a_http2_rst_stream_internal_error_reanuda"),
         [](const QString &dir) { return caseHttp2Cut(dir, H2Cut::RstInternalError); }},
        {QStringLiteral("8b_http2_rst_stream_cancel_reanuda"),
         [](const QString &dir) { return caseHttp2Cut(dir, H2Cut::RstCancel); }},
        {QStringLiteral("8c_http2_goaway_reanuda"),
         [](const QString &dir) { return caseHttp2Cut(dir, H2Cut::GoAway); }},
        {QStringLiteral("9_cuenta_por_servidor_redirect_de_github"), caseDownloadPerHost},
    };

    out(QStringLiteral("lgaupdate-retry-tests: espera entre intentos=%1 ms, reintentos=%2, "
                       "carpeta=%3")
            .arg(LgaNetRetry::delayMs())
            .arg(LgaNetRetry::kRetries)
            .arg(QDir::toNativeSeparators(workDir)));

    int ran = 0;
    int failed = 0;
    for (const Case &testCase : cases) {
        if (!only.isEmpty() && testCase.name != only) {
            continue;
        }
        ++ran;
        const QString caseDir = QDir(workDir).filePath(testCase.name);
        if (QDir(caseDir).exists()
            && !QDir(caseDir).entryList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden).isEmpty()) {
            ++failed;
            out(QStringLiteral("[FAIL] %1: la carpeta %2 ya tiene contenido (usar otra carpeta de "
                               "trabajo; el banco no borra nada)")
                    .arg(testCase.name, QDir::toNativeSeparators(caseDir)));
            continue;
        }
        QDir().mkpath(caseDir);
        // Marca en stderr: los avisos de Qt salen ahi, y asi se sabe de que caso es cada uno.
        std::fprintf(stderr, "== caso %s\n", testCase.name.toUtf8().constData());
        std::fflush(stderr);
        QElapsedTimer timer;
        timer.start();
        const CaseResult result = testCase.run(caseDir);
        // Lo que quedo con deleteLater (replies, sockets del servidor) se va antes del caso que sigue.
        pump(50);
        if (!result.ok) {
            ++failed;
        }
        out(QStringLiteral("[%1] %2 (%3 ms): %4")
                .arg(result.ok ? QStringLiteral("PASS") : QStringLiteral("FAIL"), testCase.name)
                .arg(timer.elapsed())
                .arg(result.notes.value(0)));
        for (const QString &failure : result.failures) {
            out(QStringLiteral("    - %1").arg(failure));
        }
        for (qsizetype i = 1; i < result.notes.size(); ++i) {
            out(QStringLiteral("    %1").arg(result.notes.at(i)));
        }
    }
    if (ran == 0) {
        out(QStringLiteral("no hay ningun caso llamado %1").arg(only));
        return 2;
    }
    out(QStringLiteral("lgaupdate-retry-tests: casos=%1 fallidos=%2").arg(ran).arg(failed));
    return failed;
}
