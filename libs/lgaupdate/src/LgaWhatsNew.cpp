#include "lgaupdate/LgaWhatsNew.h"

#include "lgaupdate/LgaNetRetry.h"
#include "lgaupdate/LgaVersionCompare.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSaveFile>
#include <QTimer>
#include <QVariant>
#include <QVersionNumber>

#include <algorithm>

namespace LgaWhatsNew {

namespace {

// Colores de las notas. Son los de `FM_DialogStyle` de FileManagerS3 (mismos valores), para
// que NEW / IMPROVED / FIXED se lean igual en todas las apps LGA: el cuerpo gris de los
// mensajes, el numero de version en blanco, la fecha en gris tenue y cada rotulo en su color.
constexpr const char *kBodyColor = "#A9A9AE";
constexpr const char *kVersionColor = "#F2F2F4";
constexpr const char *kDateColor = "#6E6E74";
constexpr const char *kFallbackKindColor = "#85858C";
constexpr const char *kNewColor = "#5CB85C";
constexpr const char *kImprovedColor = "#5FA8E8";
constexpr const char *kFixedColor = "#D4A437";

/**
 * La version con la regla CANONICA de `LgaVersionCompare` (la misma que decide si hay update),
 * o un `QVersionNumber` nulo si no es numerica.
 *
 * El major y el minor pasan por `VersionCompare::toVersionNumber()` con ancho 3: el minor se
 * rellena con ceros A LA DERECHA, como decimal (`1.15` -> `1.150`). Asi `1.015` y `1.15` son
 * versiones distintas, y `2.66 < 2.7`. Lo que sigue al minor (`X.Y.Z`) son enteros y los ceros
 * finales no cuentan: `0.910.0 == 0.910`. Una version de un solo numero vale `X.0`.
 */
QVersionNumber canonicalVersion(const QString &rawVersion)
{
    QString text = rawVersion.trimmed();
    if (text.startsWith(QLatin1Char('v'), Qt::CaseInsensitive)) {
        text = text.mid(1);
    }
    static const QRegularExpression kVersionRegex(QStringLiteral("^[0-9]+(\\.[0-9]+)*$"));
    if (text.isEmpty() || !kVersionRegex.match(text).hasMatch()) {
        return {};
    }
    const QStringList pieces = text.split(QLatin1Char('.'));
    const QString majorMinor = pieces.size() == 1
        ? pieces.at(0) + QStringLiteral(".0")
        : pieces.at(0) + QLatin1Char('.') + pieces.at(1);
    bool ok = false;
    const QVersionNumber head = LGA::Update::VersionCompare::toVersionNumber(
        majorMinor, LGA::Update::VersionCompare::kMinorWidthThreeDigits, &ok);
    if (!ok) {
        return {};  // desborde de int: no es una version que este codigo pueda comparar
    }
    QList<int> segments = head.segments();
    for (qsizetype i = 2; i < pieces.size(); ++i) {
        bool pieceOk = false;
        const int value = pieces.at(i).toInt(&pieceOk);
        if (!pieceOk) {
            return {};
        }
        segments.append(value);
    }
    // `normalized()` saca los ceros finales; si quedara vacia (`0.0`), se deja `0` para que
    // siga siendo una version valida y no se confunda con "no numerica".
    const QVersionNumber version = QVersionNumber(segments).normalized();
    return version.isNull() ? QVersionNumber(0) : version;
}

bool parseKind(const QString &text, Kind *out)
{
    if (text == QLatin1String("new")) {
        *out = Kind::New;
    } else if (text == QLatin1String("improved")) {
        *out = Kind::Improved;
    } else if (text == QLatin1String("fixed")) {
        *out = Kind::Fixed;
    } else {
        return false;
    }
    return true;
}

/// Lista de strings opcional. Ausente = vacia; presente y mal formada = error.
bool readStringList(const QJsonObject &object, const QString &key, QStringList *out)
{
    const QJsonValue value = object.value(key);
    if (value.isUndefined() || value.isNull()) {
        out->clear();
        return true;
    }
    if (!value.isArray()) {
        return false;
    }
    QStringList list;
    for (const QJsonValue &entry : value.toArray()) {
        if (!entry.isString()) {
            return false;
        }
        list.append(entry.toString().trimmed());
    }
    *out = list;
    return true;
}

bool itemMatches(const Item &item, const QString &platform, const QString &edition,
                 const std::optional<QStringList> &audiences)
{
    if (!item.platforms.isEmpty() && !item.platforms.contains(platform, Qt::CaseInsensitive)) {
        return false;
    }
    if (!edition.isEmpty() && !item.editions.isEmpty()
        && !item.editions.contains(edition, Qt::CaseInsensitive)) {
        return false;
    }
    if (audiences && !item.roles.isEmpty()) {
        for (const QString &role : item.roles) {
            if (audiences->contains(role, Qt::CaseInsensitive)) {
                return true;
            }
        }
        return false;
    }
    return true;
}

Notes invalid(const QString &reason)
{
    Notes notes;
    notes.valid = false;
    notes.error = reason;
    return notes;
}

} // namespace

Notes parse(const QByteArray &json)
{
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(json, &parseError);
    if (parseError.error != QJsonParseError::NoError) {
        return invalid(QStringLiteral("JSON invalido: %1").arg(parseError.errorString()));
    }
    if (!doc.isObject()) {
        return invalid(QStringLiteral("la raiz no es un objeto"));
    }
    const QJsonObject root = doc.object();
    // Un schema que esta app no conoce se trata como "sin notas": mostrar campos que
    // cambiaron de significado seria peor que no mostrar nada.
    const QJsonValue schema = root.value(QStringLiteral("schemaVersion"));
    if (!schema.isDouble() || schema.toInt(-1) != kSchemaVersion) {
        return invalid(QStringLiteral("schemaVersion no soportado: %1")
                           .arg(schema.toVariant().toString()));
    }
    const QJsonValue versionsValue = root.value(QStringLiteral("versions"));
    if (!versionsValue.isArray()) {
        return invalid(QStringLiteral("falta el array versions"));
    }

    Notes notes;
    notes.product = root.value(QStringLiteral("product")).toString();
    notes.name = root.value(QStringLiteral("name")).toString();

    const QJsonArray versions = versionsValue.toArray();
    for (qsizetype i = 0; i < versions.size(); ++i) {
        if (!versions.at(i).isObject()) {
            return invalid(QStringLiteral("versions[%1] no es un objeto").arg(i));
        }
        const QJsonObject versionObject = versions.at(i).toObject();
        VersionNotes entry;
        entry.version = versionObject.value(QStringLiteral("version")).toString().trimmed();
        if (!isValidVersion(entry.version)) {
            return invalid(QStringLiteral("versions[%1].version invalida").arg(i));
        }
        const QJsonValue dateValue = versionObject.value(QStringLiteral("date"));
        if (!dateValue.isUndefined() && !dateValue.isNull() && !dateValue.isString()) {
            return invalid(QStringLiteral("versions[%1].date no es texto").arg(i));
        }
        entry.date = dateValue.toString().trimmed();

        const QJsonValue itemsValue = versionObject.value(QStringLiteral("items"));
        if (!itemsValue.isArray()) {
            return invalid(QStringLiteral("versions[%1].items no es un array").arg(i));
        }
        const QJsonArray items = itemsValue.toArray();
        for (qsizetype j = 0; j < items.size(); ++j) {
            if (!items.at(j).isObject()) {
                return invalid(QStringLiteral("versions[%1].items[%2] no es un objeto").arg(i).arg(j));
            }
            const QJsonObject itemObject = items.at(j).toObject();
            Item item;
            if (!parseKind(itemObject.value(QStringLiteral("kind")).toString(), &item.kind)) {
                return invalid(QStringLiteral("versions[%1].items[%2].kind desconocido").arg(i).arg(j));
            }
            const QJsonValue textValue = itemObject.value(QStringLiteral("text"));
            item.text = textValue.toString().trimmed();
            if (!textValue.isString() || item.text.isEmpty()) {
                return invalid(QStringLiteral("versions[%1].items[%2].text vacio").arg(i).arg(j));
            }
            if (!readStringList(itemObject, QStringLiteral("for"), &item.roles)
                || !readStringList(itemObject, QStringLiteral("edition"), &item.editions)
                || !readStringList(itemObject, QStringLiteral("platform"), &item.platforms)) {
                return invalid(QStringLiteral("versions[%1].items[%2]: for/edition/platform "
                                              "no es una lista de textos").arg(i).arg(j));
            }
            entry.items.append(item);
        }
        notes.versions.append(entry);
    }

    // No se confia en el orden del archivo: la mas nueva primero, la escriba el script asi o no.
    std::stable_sort(notes.versions.begin(), notes.versions.end(),
                     [](const VersionNotes &a, const VersionNotes &b) {
                         return compareVersions(a.version, b.version) > 0;
                     });
    notes.valid = true;
    return notes;
}

int compareVersions(const QString &left, const QString &right, bool *okOut)
{
    const QVersionNumber a = canonicalVersion(left);
    const QVersionNumber b = canonicalVersion(right);
    const bool ok = !a.isNull() && !b.isNull();
    if (okOut) {
        *okOut = ok;
    }
    if (!ok) {
        return 0;
    }
    const int order = QVersionNumber::compare(a, b);
    return order < 0 ? -1 : (order > 0 ? 1 : 0);
}

bool isValidVersion(const QString &version)
{
    return !canonicalVersion(version).isNull();
}

QString currentPlatform()
{
#ifdef Q_OS_MAC
    return QStringLiteral("mac");
#else
    return QStringLiteral("win");
#endif
}

QList<VersionNotes> range(const Notes &notes,
                          const QString &installedExclusive,
                          const QString &offeredInclusive,
                          const QString &platform,
                          const QString &edition,
                          const std::optional<QStringList> &audiences)
{
    QList<VersionNotes> out;
    if (!notes.valid) {
        return out;
    }
    // Un piso o un techo que no son versiones no se pueden usar para cortar: devolver todo
    // mostraria notas de versiones que no corresponden, asi que no se devuelve nada.
    const bool hasFloor = !installedExclusive.trimmed().isEmpty();
    const bool hasCeiling = !offeredInclusive.trimmed().isEmpty();
    if ((hasFloor && !isValidVersion(installedExclusive))
        || (hasCeiling && !isValidVersion(offeredInclusive))) {
        return out;
    }

    for (const VersionNotes &entry : notes.versions) {
        if (hasFloor && compareVersions(entry.version, installedExclusive) <= 0) {
            continue;
        }
        if (hasCeiling && compareVersions(entry.version, offeredInclusive) > 0) {
            continue;
        }
        VersionNotes kept = entry;
        kept.items.clear();
        for (const Item &item : entry.items) {
            if (itemMatches(item, platform, edition, audiences)) {
                kept.items.append(item);
            }
        }
        if (!kept.items.isEmpty()) {
            out.append(kept);
        }
    }
    return out;
}

QList<VersionNotes> filtered(const Notes &notes,
                             const QString &platform,
                             const QString &edition,
                             const std::optional<QStringList> &audiences)
{
    return range(notes, QString(), QString(), platform, edition, audiences);
}

QString headline(const QList<VersionNotes> &versions)
{
    for (const VersionNotes &entry : versions) {
        if (!entry.items.isEmpty()) {
            return entry.items.first().text;
        }
    }
    return {};
}

int itemCount(const QList<VersionNotes> &versions)
{
    int count = 0;
    for (const VersionNotes &entry : versions) {
        count += static_cast<int>(entry.items.size());
    }
    return count;
}

QString kindTitle(Kind kind)
{
    switch (kind) {
    case Kind::New: return QStringLiteral("New");
    case Kind::Improved: return QStringLiteral("Improved");
    case Kind::Fixed: return QStringLiteral("Fixed");
    }
    return {};
}

QString toHtml(const QList<VersionNotes> &versions)
{
    const auto kindColorOf = [](Kind kind) {
        switch (kind) {
        case Kind::New: return QLatin1String(kNewColor);
        case Kind::Improved: return QLatin1String(kImprovedColor);
        case Kind::Fixed: return QLatin1String(kFixedColor);
        }
        return QLatin1String(kFallbackKindColor);
    };

    QString html = QStringLiteral("<div style='color:%1;'>").arg(QLatin1String(kBodyColor));
    bool firstVersion = true;
    for (const VersionNotes &entry : versions) {
        if (entry.items.isEmpty()) {
            continue;
        }
        const QString topMargin = firstVersion ? QStringLiteral("0") : QStringLiteral("14");
        firstVersion = false;
        QString heading = QStringLiteral("<span style='color:%1; font-weight:600;'>v%2</span>")
                              .arg(QLatin1String(kVersionColor), entry.version.toHtmlEscaped());
        if (!entry.date.isEmpty()) {
            heading += QStringLiteral("<span style='color:%1;'>&nbsp;&nbsp;%2</span>")
                           .arg(QLatin1String(kDateColor), entry.date.toHtmlEscaped());
        }
        html += QStringLiteral("<p style='margin-top:%1px; margin-bottom:2px;'>%2</p>")
                    .arg(topMargin, heading);

        for (const Kind kind : {Kind::New, Kind::Improved, Kind::Fixed}) {
            QString rows;
            for (const Item &item : entry.items) {
                if (item.kind != kind) {
                    continue;
                }
                rows += QStringLiteral("<tr><td width='14' valign='top'>&#8226;</td>"
                                       "<td valign='top'>%1</td></tr>")
                            .arg(item.text.toHtmlEscaped());
            }
            if (rows.isEmpty()) {
                continue;
            }
            html += QStringLiteral("<p style='margin-top:6px; margin-bottom:1px; color:%1; "
                                   "font-size:12px; font-weight:600;'>%2</p>")
                        .arg(QString(kindColorOf(kind)), kindTitle(kind).toUpper());
            html += QStringLiteral("<table cellspacing='0' cellpadding='1' width='100%'>%1</table>")
                        .arg(rows);
        }
    }
    html += QStringLiteral("</div>");
    return html;
}

QString normalizedSha256(const QString &digest)
{
    QString value = digest.trimmed();
    if (value.startsWith(QStringLiteral("sha256:"), Qt::CaseInsensitive)) {
        value.remove(0, 7);
    }
    value = value.toLower();
    static const QRegularExpression kDigestRegex(QStringLiteral("^[0-9a-f]{64}$"));
    return kDigestRegex.match(value).hasMatch() ? value : QString();
}

AssetRef assetFromManifestProduct(const QJsonObject &product)
{
    const QString assetName = QLatin1String(kAssetName);
    AssetRef best;
    // `assetLatest` es la fuente buena: el whats_new.json es una familia mas (nombre sin
    // version) y ahi esta el del release mas nuevo que lo tenga. No se confia en el orden.
    for (const QJsonValue &value : product.value(QStringLiteral("assetLatest")).toArray()) {
        const QJsonObject entry = value.toObject();
        if (entry.value(QStringLiteral("name")).toString() != assetName) {
            continue;
        }
        const QString tag = entry.value(QStringLiteral("tag")).toString().trimmed();
        const QString digest = normalizedSha256(entry.value(QStringLiteral("digest")).toString());
        if (tag.isEmpty() || digest.isEmpty()) {
            continue;
        }
        if (best.isValid() && compareVersions(tag, best.tag) <= 0) {
            continue;
        }
        best.tag = tag;
        best.sha256 = digest;
    }
    if (best.isValid()) {
        return best;
    }
    // Manifiesto sin `assetLatest`: el ultimo release, si trae el asset.
    const QString tag = product.value(QStringLiteral("tag")).toString().trimmed();
    for (const QJsonValue &value : product.value(QStringLiteral("assets")).toArray()) {
        const QJsonObject asset = value.toObject();
        if (asset.value(QStringLiteral("name")).toString() != assetName) {
            continue;
        }
        const QString digest = normalizedSha256(asset.value(QStringLiteral("digest")).toString());
        if (!tag.isEmpty() && !digest.isEmpty()) {
            return AssetRef{tag, digest};
        }
    }
    return {};
}

AssetRef assetFromManifest(const QByteArray &manifestJson, const QString &repoSlug)
{
    const QJsonDocument doc = QJsonDocument::fromJson(manifestJson);
    // Mismo criterio que el chequeo de updates: un manifiesto de otro formato no se lee.
    if (!doc.isObject() || doc.object().value(QStringLiteral("schemaVersion")).toInt(0) != 1) {
        return {};
    }
    const QJsonObject products = doc.object().value(QStringLiteral("products")).toObject();
    return assetFromManifestProduct(products.value(repoSlug.trimmed()).toObject());
}

QUrl assetUrl(const QString &repoSlug, const QString &tag)
{
    const QStringList parts = repoSlug.trimmed().split(QLatin1Char('/'), Qt::SkipEmptyParts);
    if (parts.size() != 2 || tag.trimmed().isEmpty()) {
        return {};
    }
    return QUrl(QStringLiteral("https://github.com/%1/%2/releases/download/%3/%4")
                    .arg(parts.at(0), parts.at(1), tag.trimmed(), QLatin1String(kAssetName)));
}

QString cacheFilePath(const QString &cacheDir, const QString &repoSlug)
{
    if (cacheDir.isEmpty() || repoSlug.trimmed().isEmpty()) {
        return {};
    }
    QString safe = repoSlug.trimmed();
    safe.replace(QRegularExpression(QStringLiteral("[^A-Za-z0-9._-]")), QStringLiteral("_"));
    return QDir(cacheDir).filePath(QStringLiteral("whats_new_%1.json").arg(safe));
}

} // namespace LgaWhatsNew

// ------------------------------------------------------------------------------- fetcher

namespace {

// Tope del JSON. El historial completo de un producto son decenas de KB; algo varios ordenes
// mas grande no es un whats_new.json y no se acumula en memoria.
constexpr qint64 kFetchMaxBytes = 2 * 1024 * 1024;

QString sha256Hex(const QByteArray &data)
{
    return QString::fromLatin1(QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex());
}

} // namespace

LgaWhatsNewFetcher::LgaWhatsNewFetcher(QNetworkAccessManager *network, QObject *parent)
    : QObject(parent)
    , m_network(network)
{
    qRegisterMetaType<LgaWhatsNewFetchResult>();
    // Al cerrarse la app no sale ningun reintento pendiente: la espera se corta y el fetch queda
    // sin terminar, como con `cancel()`.
    if (QCoreApplication *app = QCoreApplication::instance()) {
        connect(app, &QCoreApplication::aboutToQuit, this, [this]() {
            delete m_retryContext.data();
        });
    }
}

void LgaWhatsNewFetcher::logLine(const QString &message) const
{
    if (m_request.log) {
        m_request.log(message);
    } else {
        qInfo().noquote() << QStringLiteral("LgaWhatsNewFetcher: %1").arg(message);
    }
}

LgaWhatsNewFetcher::~LgaWhatsNewFetcher()
{
    cancel();
}

bool LgaWhatsNewFetcher::isRunning() const
{
    return m_running;
}

void LgaWhatsNewFetcher::cancel()
{
    m_running = false;
    // Un reintento que esperaba su turno no sale: nada de pedidos despues de cancelar.
    delete m_retryContext.data();
    if (m_deadline) {
        m_deadline->stop();
    }
    if (m_reply) {
        QNetworkReply *reply = m_reply;
        m_reply = nullptr;
        reply->disconnect(this);
        reply->abort();
        reply->deleteLater();
    }
    m_buffer.clear();
}

LgaWhatsNewFetchResult LgaWhatsNewFetcher::failedOrStale(const QString &detail) const
{
    if (m_request.allowStaleCache) {
        LgaWhatsNewFetchResult stale = readCache(/*requireDigest=*/false);
        if (stale.status == LgaWhatsNewFetchResult::Status::Ok) {
            stale.detail = detail;
            return stale;
        }
    }
    LgaWhatsNewFetchResult failed;
    failed.detail = detail;
    return failed;
}

LgaWhatsNewFetchResult LgaWhatsNewFetcher::readCache(bool requireDigest) const
{
    LgaWhatsNewFetchResult result;
    result.status = LgaWhatsNewFetchResult::Status::Failed;
    const QString path = LgaWhatsNew::cacheFilePath(m_request.cacheDir, m_request.repoSlug);
    if (path.isEmpty()) {
        result.detail = QStringLiteral("sin carpeta de cache");
        return result;
    }
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        result.detail = QStringLiteral("no hay cache en %1").arg(path);
        return result;
    }
    const QByteArray data = file.read(kFetchMaxBytes + 1);
    if (data.size() > kFetchMaxBytes) {
        result.detail = QStringLiteral("cache demasiado grande: %1").arg(path);
        return result;
    }
    if (requireDigest && sha256Hex(data) != m_request.asset.sha256) {
        result.detail = QStringLiteral("la cache tiene otro digest");
        return result;
    }
    result.notes = LgaWhatsNew::parse(data);
    if (!result.notes.valid) {
        result.detail = QStringLiteral("cache ilegible: %1").arg(result.notes.error);
        return result;
    }
    result.status = LgaWhatsNewFetchResult::Status::Ok;
    result.fromCache = true;
    result.stale = !requireDigest;
    return result;
}

void LgaWhatsNewFetcher::fetch(const Request &request)
{
    cancel();
    m_request = request;
    m_request.asset.sha256 = LgaWhatsNew::normalizedSha256(request.asset.sha256);
    m_running = true;
    m_tooLarge = false;
    m_timedOut = false;
    m_buffer.clear();

    // Todo desenlace sale por el event loop: un llamador que conecta `finished` DESPUES de
    // llamar a fetch() no se lo pierde, y nunca se le emite adentro de su propia llamada.
    const auto finishLater = [this](const LgaWhatsNewFetchResult &result) {
        QTimer::singleShot(0, this, [this, result]() {
            if (m_running) {
                finish(result);
            }
        });
    };

    if (!m_request.asset.isValid()) {
        if (m_request.allowStaleCache) {
            LgaWhatsNewFetchResult stale = readCache(/*requireDigest=*/false);
            if (stale.status == LgaWhatsNewFetchResult::Status::Ok) {
                finishLater(stale);
                return;
            }
        }
        LgaWhatsNewFetchResult none;
        none.status = LgaWhatsNewFetchResult::Status::NoNotes;
        none.detail = QStringLiteral("el manifiesto no publica %1 para %2")
                          .arg(QLatin1String(LgaWhatsNew::kAssetName), m_request.repoSlug);
        finishLater(none);
        return;
    }

    // Misma version de las notas ya bajada y verificada: no hay nada que bajar.
    const LgaWhatsNewFetchResult cached = readCache(/*requireDigest=*/true);
    if (cached.status == LgaWhatsNewFetchResult::Status::Ok) {
        finishLater(cached);
        return;
    }

    const QUrl url = LgaWhatsNew::assetUrl(m_request.repoSlug, m_request.asset.tag);
    if (!url.isValid() || !m_network) {
        finishLater(failedOrStale(QStringLiteral("URL invalida o sin red (repo=%1 tag=%2)")
                                      .arg(m_request.repoSlug, m_request.asset.tag)));
        return;
    }

    m_budget.reset();
    sendRequest();
}

void LgaWhatsNewFetcher::sendRequest()
{
    // Entre un intento y el siguiente el manager puede haber muerto (es de quien llama). En el
    // primero no pasa: `fetch()` ya lo miro, asi que esto nunca termina adentro de `fetch()`.
    if (!m_network) {
        finish(failedOrStale(QStringLiteral("sin network manager para el %1")
                                 .arg(m_budget.label())));
        return;
    }
    // Estado POR INTENTO: lo de un intento cortado no se mezcla con el siguiente.
    m_tooLarge = false;
    m_timedOut = false;
    m_buffer.clear();

    const QUrl url = LgaWhatsNew::assetUrl(m_request.repoSlug, m_request.asset.tag);
    QNetworkRequest networkRequest(url);
    if (!m_request.userAgent.isEmpty()) {
        networkRequest.setHeader(QNetworkRequest::UserAgentHeader, m_request.userAgent);
    }
    networkRequest.setAttribute(QNetworkRequest::CacheLoadControlAttribute,
                                QNetworkRequest::AlwaysNetwork);
    // Inactividad, ademas del tope TOTAL del timer: los dos, porque un servidor que gotea un
    // byte por segundo nunca dispara el de inactividad.
    networkRequest.setTransferTimeout(m_request.timeoutMs);
    logLine(QStringLiteral("Notas (%1): %2").arg(m_budget.label(), url.toString()));
    m_reply = m_network->get(networkRequest);
    connect(m_reply, &QNetworkReply::readyRead, this, &LgaWhatsNewFetcher::onReadyRead);
    connect(m_reply, &QNetworkReply::finished, this, &LgaWhatsNewFetcher::onReplyFinished);

    if (!m_deadline) {
        m_deadline = new QTimer(this);
        m_deadline->setSingleShot(true);
        connect(m_deadline, &QTimer::timeout, this, [this]() {
            if (m_reply) {
                m_timedOut = true;
                // abort() emite finished() sincronicamente y eso cierra el flujo.
                m_reply->abort();
            }
        });
    }
    m_deadline->start(m_request.timeoutMs);
}

void LgaWhatsNewFetcher::onReadyRead()
{
    if (!m_reply || m_tooLarge) {
        return;
    }
    m_buffer += m_reply->readAll();
    if (m_buffer.size() > kFetchMaxBytes) {
        m_tooLarge = true;
        // Diferido: abort() emite finished() sincronicamente, y adentro de readyRead eso anida
        // el cierre del flujo en la entrega de datos.
        QTimer::singleShot(0, this, [this]() {
            if (m_reply) {
                m_reply->abort();
            }
        });
    }
}

void LgaWhatsNewFetcher::onReplyFinished()
{
    QNetworkReply *reply = m_reply;
    m_reply = nullptr;
    if (!reply) {
        return;
    }
    if (m_deadline) {
        m_deadline->stop();
    }
    if (!m_tooLarge) {
        m_buffer += reply->readAll();
    }
    const QNetworkReply::NetworkError error = reply->error();
    const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QString errorString = reply->errorString();
    // Corte, timeout (el de Qt o el tope total de este fetcher) o 429/5xx. Un asset demasiado
    // grande no: ese `abort()` lo hizo este fetcher a proposito y el archivo no va a achicarse.
    const bool transient =
        !m_tooLarge && LgaNetRetry::shouldRetry(reply, /*cancelledOnPurpose=*/false);
    // El texto del intento que fallo, antes de que `allowRetry` cuente el siguiente. `allowRetry`
    // va ultimo: cuenta solo si de verdad se reintenta, en el servidor donde fallo
    // (`reply->url()`, despues de los redirects). `deleteLater` todavia no borro el reply.
    const QString failedAttempt = m_budget.label();
    const bool retry = transient && m_budget.allowRetry(reply);
    reply->deleteLater();

    if (retry) {
        // Un solo `arg()` con todo: un texto de error con un `%N` adentro no se come al resto.
        logLine(QStringLiteral("Notas fallidas (%1): httpStatus=%2 networkError=%3 (%4)%5; se "
                               "reintenta en %6 ms")
                    .arg(failedAttempt, QString::number(httpStatus),
                         QString::number(static_cast<int>(error)), errorString,
                         m_timedOut ? QStringLiteral(" timeout de %1 ms").arg(m_request.timeoutMs)
                                    : QString(),
                         QString::number(LgaNetRetry::delayMs())));
        m_buffer.clear();
        // Con contexto propio y no `this`: `cancel()` lo borra y el reintento no sale.
        QObject *context = new QObject(this);
        m_retryContext = context;
        QTimer::singleShot(LgaNetRetry::delayMs(), context, [this, context]() {
            m_retryContext.clear();
            context->deleteLater();
            if (m_running) {
                sendRequest();
            }
        });
        return;
    }

    const auto fallback = [this](const QString &detail) { finish(failedOrStale(detail)); };

    if (m_tooLarge || m_buffer.size() > kFetchMaxBytes) {
        fallback(QStringLiteral("el asset supera %1 bytes").arg(kFetchMaxBytes));
        return;
    }
    if (m_timedOut) {
        fallback(QStringLiteral("timeout de %1 ms (%2)")
                     .arg(QString::number(m_request.timeoutMs), failedAttempt));
        return;
    }
    if (error != QNetworkReply::NoError || httpStatus < 200 || httpStatus >= 300) {
        fallback(QStringLiteral("fallo de red httpStatus=%1 networkError=%2 (%3) (%4)")
                     .arg(QString::number(httpStatus), QString::number(static_cast<int>(error)),
                          errorString, failedAttempt));
        return;
    }

    const QString actual = sha256Hex(m_buffer);
    if (actual != m_request.asset.sha256) {
        // Nunca se muestran notas que no coinciden con el manifiesto, ni se guardan.
        fallback(QStringLiteral("SHA-256 no coincide: esperado=%1 recibido=%2")
                     .arg(m_request.asset.sha256, actual));
        return;
    }

    LgaWhatsNewFetchResult result;
    result.notes = LgaWhatsNew::parse(m_buffer);
    if (!result.notes.valid) {
        fallback(QStringLiteral("JSON invalido: %1").arg(result.notes.error));
        return;
    }

    // Se guarda recien con el digest verificado y el JSON parseado: la cache es siempre un
    // archivo que en su momento fue bueno. Son unos KB en la carpeta de datos de la app.
    const QString cachePath = LgaWhatsNew::cacheFilePath(m_request.cacheDir, m_request.repoSlug);
    if (!cachePath.isEmpty()) {
        QDir().mkpath(QFileInfo(cachePath).absolutePath());
        QSaveFile cacheFile(cachePath);
        if (cacheFile.open(QIODevice::WriteOnly)) {
            cacheFile.write(m_buffer);
            cacheFile.commit();
        }
    }
    result.status = LgaWhatsNewFetchResult::Status::Ok;
    finish(result);
}

void LgaWhatsNewFetcher::finish(const LgaWhatsNewFetchResult &result)
{
    if (!m_running) {
        return;
    }
    m_running = false;
    m_buffer.clear();
    emit finished(result);
}
