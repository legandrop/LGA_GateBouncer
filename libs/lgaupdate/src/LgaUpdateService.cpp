#include "lgaupdate/LgaUpdateService.h"

#include "lgaupdate/LgaNetRetry.h"
#include "lgaupdate/LgaUpdateI18n.h"
#include "lgaupdate/LgaVersionCompare.h"
#include "lgaupdate/LgaWhatsNew.h"

#include <QApplication>
#include <QCryptographicHash>
#include <QDateTime>
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
#include <QProcess>
#include <QProgressDialog>
#include <QRegularExpression>
#include <QSaveFile>
#include <QScopeGuard>
#include <QSettings>
#include <QSslError>
#include <QStandardPaths>
#include <QStorageInfo>
#include <QRandomGenerator>
#include <QTimer>
#include <QVariant>
#include <QVersionNumber>

#include <memory>

namespace {

// "Remind me later" calla el chequeo automatico este tiempo. Era una semana: demasiado para una
// version que el usuario solo queria posponer.
constexpr int kSnoozeDays = 1;

// Cada cuanto mira el reloj el chequeo periodico. Corto a proposito: es lo que tarda en correr un
// chequeo vencido al despertar de una suspension. Mirar el reloj no consulta la red.
constexpr int kPeriodicTickMs = 5 * 60 * 1000;

// Tope del log de updates antes de rotarlo a `Update.log.1`. Un update completo son unas 40
// lineas.
constexpr qint64 kUpdateLogMaxBytes = 1024 * 1024;

// Version del formato del manifiesto que este componente sabe leer. Si LGA_Updates publica una
// mayor, el chequeo falla con un mensaje claro en vez de leer campos que cambiaron de sentido.
constexpr int kManifestSchemaVersion = 1;

/// El reintento ya disparo: su contexto sale del holder (ya no es un reintento pendiente que
/// cortar) y se borra en el proximo ciclo del event loop, no adentro de su propia llamada.
void releaseRetryContext(QObject *context)
{
    context->setParent(nullptr);
    context->deleteLater();
}

/// `schemaVersion` del manifiesto, o 0 si no se puede leer (no parsea, o no trae el campo).
int manifestSchemaVersion(const QByteArray &payload)
{
    const QJsonDocument doc = QJsonDocument::fromJson(payload);
    if (!doc.isObject()) {
        return 0;
    }
    return doc.object().value(QStringLiteral("schemaVersion")).toInt(0);
}

/// Prefijos de los archivos que este servicio escribe para `productId` en la carpeta de updates:
/// el asset y los scripts helper. Un prefijo `<productId>` a secas tambien agarraba los de OTRA
/// edicion ("PipeSync" es prefijo de "PipeSync_Client_Setup_v...").
QStringList ownedFilePrefixes(const QString &productId)
{
    return {
        productId + QStringLiteral("_Mac_v"),
        productId + QStringLiteral("_Setup_v"),
        productId + QStringLiteral("_Update_Helper_"),
    };
}

bool isOwnedFile(const QString &fileName, const QStringList &prefixes)
{
    for (const QString &prefix : prefixes) {
        if (fileName.startsWith(prefix, Qt::CaseInsensitive)) {
            return true;
        }
    }
    return false;
}

/**
 * Prueba de escritura REAL sobre `dirPath` (creandolo si hace falta). `QFileInfo::isWritable()`
 * no alcanza: en Windows contesta que si sobre carpetas virtualizadas por UAC y sobre ACLs
 * heredadas que despues rechazan el `CreateFile`.
 */
bool directoryAcceptsWrites(const QString &dirPath)
{
    if (dirPath.isEmpty() || !QDir().mkpath(dirPath)) {
        return false;
    }
    QFile probe(QDir(dirPath).filePath(
        QStringLiteral(".lga_write_probe_%1").arg(QCoreApplication::applicationPid())));
    if (!probe.open(QIODevice::WriteOnly)) {
        return false;
    }
    const bool wrote = probe.write("lga", 3) == 3 && probe.flush();
    probe.close();
    probe.remove();
    return wrote;
}

#ifdef Q_OS_MAC
/// Texto que va adentro de comillas dobles en el helper de macOS: sin `"`, `$`, `` ` ``, `\` ni
/// saltos de linea, que lo sacarian de las comillas o cortarian el script entero.
QString shellSafeText(QString text)
{
    for (const QChar c : {QLatin1Char('"'), QLatin1Char('$'), QLatin1Char('`'), QLatin1Char('\\'),
                          QLatin1Char('\n'), QLatin1Char('\r')}) {
        text.remove(c);
    }
    return text;
}

/// Texto de una notificacion del helper de macOS: va entre comillas dobles de AppleScript dentro
/// de un `osascript -e '...'` de shell, asi que no puede llevar `'`, `"`, `\` ni saltos de linea.
QString notificationSafeText(QString text)
{
    for (const QChar c : {QLatin1Char('\''), QLatin1Char('"'), QLatin1Char('\\'),
                          QLatin1Char('\n'), QLatin1Char('\r')}) {
        text.remove(c);
    }
    return text;
}
#endif

/// Carpetas `updates/` del usuario (`CacheLocation` y `TempLocation`): el fallback de una
/// instalacion no escribible y donde quedaron instaladores de versiones anteriores.
QStringList userUpdateDirectories()
{
    QStringList dirs;
    for (const QStandardPaths::StandardLocation location :
         {QStandardPaths::CacheLocation, QStandardPaths::TempLocation}) {
        const QString root = QStandardPaths::writableLocation(location);
        if (root.isEmpty()) {
            continue;
        }
        const QString candidate = QDir::cleanPath(QDir(root).filePath(QStringLiteral("updates")));
        if (!dirs.contains(candidate)) {
            dirs.append(candidate);
        }
    }
    return dirs;
}

#ifdef Q_OS_WIN
// Texto para adentro de comillas simples de PowerShell. PowerShell toma como comilla simple tambien las tipograficas
// (U+2018 a U+201B), y como el script se escribe con BOM las lee como tales: se pasan a ' y despues se duplican todas.
QString powerShellSingleQuoted(QString text)
{
    for (const char16_t c : {u'‘', u'’', u'‚', u'‛'}) {
        text.replace(QChar(c), QLatin1Char('\''));
    }
    return text.replace(QLatin1Char('\''), QStringLiteral("''"));
}

// Lista de PowerShell: 'a','b','c'
QString powerShellQuotedList(const QStringList &values)
{
    QStringList quoted;
    quoted.reserve(values.size());
    for (const QString &value : values) {
        quoted << QStringLiteral("'%1'").arg(powerShellSingleQuoted(value));
    }
    return quoted.isEmpty() ? QStringLiteral("''") : quoted.join(QStringLiteral(","));
}

// Condicion -like encadenada con -or sobre la command line: ($_.CommandLine -like 'a' -or ...)
QString powerShellCommandLineMatch(const QStringList &patterns)
{
    if (patterns.isEmpty()) {
        return QStringLiteral("$false");
    }
    QStringList conditions;
    conditions.reserve(patterns.size());
    for (const QString &pattern : patterns) {
        conditions << QStringLiteral("$_.CommandLine -like '%1'").arg(powerShellSingleQuoted(pattern));
    }
    return conditions.join(QStringLiteral(" -or "));
}
#endif

// Datos del asset del release que se va a instalar.
struct ReleaseInfo {
    QString version;
    QUrl downloadUrl;
    QString assetName;
    QString assetDigest;
};

QString normalizedVersion(QString version)
{
    version = version.trimmed();
    if (version.startsWith(QLatin1Char('v'), Qt::CaseInsensitive)) {
        version.remove(0, 1);
    }
    return version;
}

bool isVersionNewer(const QString &remoteVersion, const QString &localVersion)
{
    // Las apps Qt de LGA versionan `X.YYY`, de ahi el ancho de 3. La regla completa y el
    // porque del zero-padding estan en LgaVersionCompare.h.
    return LGA::Update::VersionCompare::isNewer(
        remoteVersion, localVersion, LGA::Update::VersionCompare::kMinorWidthThreeDigits);
}

QString normalizedSha256Digest(QString digest)
{
    digest = digest.trimmed();
    if (digest.startsWith(QStringLiteral("sha256:"), Qt::CaseInsensitive)) {
        digest.remove(0, QStringLiteral("sha256:").size());
    }
    digest = digest.toLower();

    static const QRegularExpression digestPattern(QStringLiteral("^[0-9a-f]{64}$"));
    if (!digestPattern.match(digest).hasMatch()) {
        return {};
    }
    return digest;
}

// El asset que corresponde a esta plataforma, por nombre. El patron se arma con el productId:
// "LGA_FrameRev_Mac_v0.216.zip" / "LGA_FrameRev_Setup_v0.216.exe".
QRegularExpression expectedAssetPattern(const QString &productId)
{
#ifdef Q_OS_MAC
    const QString pattern = QStringLiteral("^%1_Mac_v[0-9]+(?:\\.[0-9]+)+\\.zip$")
                                .arg(QRegularExpression::escape(productId));
#else
    const QString pattern = QStringLiteral("^%1_Setup_v[0-9]+(?:\\.[0-9]+)+\\.exe$")
                                .arg(QRegularExpression::escape(productId));
#endif
    return QRegularExpression(pattern, QRegularExpression::CaseInsensitiveOption);
}

QString defaultAssetName(const QString &productId, const QString &version)
{
    const QString v = normalizedVersion(version);
#ifdef Q_OS_MAC
    return QStringLiteral("%1_Mac_v%2.zip").arg(productId, v);
#else
    return QStringLiteral("%1_Setup_v%2.exe").arg(productId, v);
#endif
}

// El nombre del asset viaja en el manifiesto, o sea que es entrada externa: si trae
// separadores de path podria escribir fuera de la carpeta de updates.
QString safeInstallerAssetName(QString assetName, const QString &productId, const QString &version)
{
    assetName = assetName.trimmed();
    if (assetName.isEmpty() || assetName.contains(QLatin1Char('/'))
        || assetName.contains(QLatin1Char('\\'))) {
        return defaultAssetName(productId, version);
    }
    return assetName;
}

QString currentPlatformLabel()
{
#ifdef Q_OS_MAC
    return QStringLiteral("macOS");
#elif defined(Q_OS_WIN)
    return QStringLiteral("Windows");
#else
    return QStringLiteral("this platform");
#endif
}

QString currentMacAppBundlePath()
{
#ifdef Q_OS_MAC
    const QDir appDir(QCoreApplication::applicationDirPath());
    const QString bundlePath =
        QFileInfo(appDir.filePath(QStringLiteral("../.."))).canonicalFilePath();
    if (!bundlePath.isEmpty() && bundlePath.endsWith(QStringLiteral(".app"), Qt::CaseInsensitive)) {
        return bundlePath;
    }
#endif
    return {};
}

void logSslErrors(const QList<QSslError> &errors)
{
    QStringList descriptions;
    descriptions.reserve(errors.size());
    for (const QSslError &error : errors) {
        descriptions.append(error.errorString());
    }
    qWarning().noquote() << QStringLiteral("Updater: errores SSL; Qt cancelara la conexion: %1")
                                .arg(descriptions.join(QStringLiteral(" | ")));
}

// Arma la URL de descarga de un asset. Se DERIVA del slug, el tag y el nombre en vez de venir
// en el manifiesto: guardarla ahi seria un segundo lugar donde el mismo dato puede quedar viejo,
// y el formato de esa URL es publico y estable.
QUrl assetDownloadUrl(const QString &releaseRepoSlug, const QString &tag, const QString &name)
{
    const QStringList slugParts = releaseRepoSlug.split(QLatin1Char('/'), Qt::SkipEmptyParts);
    if (slugParts.size() != 2 || tag.isEmpty() || name.isEmpty()) {
        return {};
    }
    return QUrl(QStringLiteral("https://github.com/%1/%2/releases/download/%3/%4")
                    .arg(slugParts.at(0), slugParts.at(1), tag, name));
}

// El asset de ESTA plataforma en el release MAS NUEVO que lo tenga, mirando `assetLatest`.
//
// Ese campo existe porque `tag`/`assets` describen el ULTIMO release del producto, y ese release
// puede no traer artefacto para esta plataforma. Elegir por posicion dejaria ciego a un
// usuario cuando el release mas nuevo solo contiene el instalador de la otra plataforma. Lo
// que corresponde ver es la ultima version QUE EXISTE PARA LA PLATAFORMA ACTUAL.
//
// El manifiesto no sabe nada de plataformas: publica, por producto, el asset mas nuevo de cada
// familia de artefacto. Quien decide cual le toca es la app, con el patron que ya tiene.
//
// Devuelve un info vacio si el manifiesto todavia no publica `assetLatest` (formato viejo) o si
// ninguna entrada matchea; el llamador cae al ultimo release en ese caso.
ReleaseInfo parseAssetLatest(const QJsonObject &product,
                             const QRegularExpression &assetPattern,
                             const QString &releaseRepoSlug)
{
    ReleaseInfo info;

    const QJsonArray entries = product.value(QStringLiteral("assetLatest")).toArray();
    for (const QJsonValue &entryValue : entries) {
        const QJsonObject entry = entryValue.toObject();
        const QString name = entry.value(QStringLiteral("name")).toString();
        if (!assetPattern.match(name).hasMatch()) {
            continue;
        }

        const QString entryTag = entry.value(QStringLiteral("tag")).toString().trimmed();
        const QString entryVersion = normalizedVersion(entryTag);
        if (entryVersion.isEmpty()) {
            continue;
        }
        // No se confia en el orden del array: gana la version mas alta, la ordene el
        // manifiesto o no.
        if (!info.version.isEmpty() && !isVersionNewer(entryVersion, info.version)) {
            continue;
        }

        const QUrl url = assetDownloadUrl(releaseRepoSlug, entryTag, name);
        if (!url.isValid()) {
            continue;
        }

        info.version = entryVersion;
        info.assetName = name;
        info.downloadUrl = url;
        info.assetDigest = normalizedSha256Digest(entry.value(QStringLiteral("digest")).toString());
    }

    return info;
}

// Saca del manifiesto la version y el asset de ESTA plataforma para ESTE producto.
//
// No hay guarda contra draft/prerelease como cuando se leia la API de GitHub: el manifiesto se
// arma con releases que ya excluyen ambos.
ReleaseInfo parseManifest(const QByteArray &payload,
                          const QString &productId,
                          const QString &releaseRepoSlug,
                          QString *failureReason)
{
    if (failureReason) {
        failureReason->clear();
    }
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(payload, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        if (failureReason) {
            *failureReason = QStringLiteral("JSON invalido: %1 (offset %2)")
                                 .arg(parseError.errorString())
                                 .arg(parseError.offset);
        }
        return {};
    }

    const QJsonObject root = doc.object();
    // Se valida ANTES de leer nada: si el formato cambia, el chequeo falla de forma visible en
    // vez de malinterpretar campos que ya no significan lo mismo. `assetLatest` es ADITIVO y no
    // mueve este numero: los consumidores que solo leen `tag`/`assets` siguen andando igual.
    if (root.value(QStringLiteral("schemaVersion")).toInt(0) != kManifestSchemaVersion) {
        if (failureReason) {
            *failureReason =
                QStringLiteral("schemaVersion incompatible: recibido=%1 esperado=%2")
                    .arg(root.value(QStringLiteral("schemaVersion")).toVariant().toString())
                    .arg(kManifestSchemaVersion);
        }
        return {};
    }

    const QJsonObject product = root.value(QStringLiteral("products")).toObject()
                                    .value(releaseRepoSlug).toObject();
    if (product.isEmpty()) {
        return {};
    }

    const QRegularExpression assetPattern = expectedAssetPattern(productId);

    const ReleaseInfo byPlatform = parseAssetLatest(product, assetPattern, releaseRepoSlug);
    if (byPlatform.downloadUrl.isValid()) {
        return byPlatform;
    }

    // Manifiesto sin `assetLatest`: el ultimo release del producto, como se leia hasta ahora.
    // Si ese release no trae artefacto para esta plataforma, `downloadUrl` queda invalida y el
    // llamador lo dice con todas las letras en vez de callarse.
    const QString tag = product.value(QStringLiteral("tag")).toString().trimmed();
    ReleaseInfo info;
    info.version = normalizedVersion(tag);
    if (info.version.isEmpty()) {
        return info;
    }

    const QJsonArray assets = product.value(QStringLiteral("assets")).toArray();
    for (const QJsonValue &assetValue : assets) {
        const QJsonObject asset = assetValue.toObject();
        const QString name = asset.value(QStringLiteral("name")).toString();
        if (!assetPattern.match(name).hasMatch()) {
            continue;
        }

        const QUrl url = assetDownloadUrl(releaseRepoSlug, tag, name);
        if (!url.isValid()) {
            continue;
        }

        info.assetName = name;
        info.downloadUrl = url;
        info.assetDigest = normalizedSha256Digest(asset.value(QStringLiteral("digest")).toString());
        break;
    }

    return info;
}

// Acceso al .ini de snooze/skip. Con `path` vacio se cae al QSettings nativo, que es lo que
// hace la app cuando no se puede resolver el directorio de configuracion.
std::unique_ptr<QSettings> openUpdateSettings(const QString &path)
{
    if (path.isEmpty()) {
        return std::make_unique<QSettings>(QApplication::organizationName(),
                                           QApplication::applicationName());
    }
    return std::make_unique<QSettings>(path, QSettings::IniFormat);
}

} // namespace

LgaUpdateService::LgaUpdateService(LgaUpdateConfig config, QWidget *parentWindow)
    : QObject(parentWindow)
    , m_config(std::move(config))
    , m_parentWindow(parentWindow)
{
    // El idioma que pidio la app, antes de cualquier texto: todos los tr() de la biblioteca se
    // resuelven al mostrarse.
    LgaUpdateI18n::setLanguage(m_config.language);
    if (m_config.networkFactory) {
        m_network = m_config.networkFactory(this);
    }
    if (m_network && m_network->thread() != thread()) {
        qWarning().noquote()
            << QStringLiteral("Updater: el manager de red recibido pertenece a otro hilo; "
                              "se usa el manager predeterminado");
        m_network = nullptr;
    }
    if (!m_network) {
        m_network = new QNetworkAccessManager(this);
    } else if (m_network->parent() != this) {
        m_network->setParent(this);
    }

    // Los reintentos de red esperan con `QTimer::singleShot` sobre un contexto hijo de este
    // holder: borrar el contexto corta el reintento. Al cerrarse la app se cortan todos, asi
    // ningun pedido sale despues de `aboutToQuit` (y morir el servicio se los lleva igual).
    m_retryHolder = new QObject(this);
    if (QCoreApplication *app = QCoreApplication::instance()) {
        connect(app, &QCoreApplication::aboutToQuit, this,
                &LgaUpdateService::cancelPendingRetries);
    }
}

QObject *LgaUpdateService::newRetryContext()
{
    return new QObject(m_retryHolder);
}

void LgaUpdateService::cancelPendingRetries()
{
    const QList<QObject *> pending = m_retryHolder->children();
    if (!pending.isEmpty()) {
        logUpdate(QStringLiteral("La app se cierra: se cortan %1 reintento(s) de red pendiente(s)")
                      .arg(pending.size()));
    }
    // Los QPointer de `m_checkRetry` y `m_downloadRetry` quedan en null solos.
    qDeleteAll(pending);
}

void LgaUpdateService::logNet(const QString &message) const
{
    logUpdate(message);
    if (m_config.updateLogPath.isEmpty()) {
        qInfo().noquote() << QStringLiteral("Updater: %1").arg(message);
    }
}

LgaUpdateService::~LgaUpdateService()
{
    // Los fetchers de notas se borran ANTES que el network manager. Los dos son hijos de este
    // objeto y el manager se creo primero, asi que Qt lo destruiria primero, llevandose las
    // replies en vuelo; el fetcher, al morir despues, cancelaria una reply ya liberada (crash
    // al cerrar la app con una descarga de notas en curso). El QPointer del fetcher es la otra
    // mitad de la defensa: ninguna de las dos depende de la otra.
    const QList<LgaWhatsNewFetcher *> fetchers =
        findChildren<LgaWhatsNewFetcher *>(Qt::FindDirectChildrenOnly);
    qDeleteAll(fetchers);
    // Cada uno puso su propio cursor de espera: se saca uno por cada uno que siga puesto.
    if (m_historyRunning) {
        QApplication::restoreOverrideCursor();
    }
    if (m_checkCursorActive) {
        QApplication::restoreOverrideCursor();
    }
    // Si la ventana muere con una descarga en curso, el parcial NO se commitea: se tira. Un
    // instalador a medio bajar en la carpeta de updates es peor que no tener ninguno.
    discardPartialDownload();
}

QWidget *LgaUpdateService::parentWindow() const
{
    QWidget *const owner = m_parentWindow.data();
    QWidget *const modal = QApplication::activeModalWidget();
    // isAncestorOf se limita a una misma ventana; Help es un dialogo con ventana propia.
    for (QWidget *parent = modal; owner && parent; parent = parent->parentWidget()) {
        if (parent == owner) return modal;
    }
    return owner;
}

int LgaUpdateService::presentDialog(QWidget *parent, const LgaUpdateDialogSpec &spec) const
{
    if (m_config.presentDialog) {
        return m_config.presentDialog(parent, spec);
    }
    return LgaUpdateDialog::presentFallback(parent, spec);
}

QString LgaUpdateService::emphasis(const QString &escapedText) const
{
    if (m_config.emphasizeHtml) {
        return m_config.emphasizeHtml(escapedText);
    }
    return QStringLiteral("<b>%1</b>").arg(escapedText);
}

void LgaUpdateService::logUpdate(const QString &message) const
{
    const QString path = m_config.updateLogPath;
    if (path.isEmpty()) {
        return;
    }
    QDir().mkpath(QFileInfo(path).absolutePath());

    const QFileInfo info(path);
    if (info.exists() && info.size() > kUpdateLogMaxBytes) {
        const QString previous = path + QStringLiteral(".1");
        QFile::remove(previous);
        QFile::rename(path, previous);
    }

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Append)) {
        // No corta nada: el log es diagnostico, el update sigue igual.
        qWarning().noquote() << QStringLiteral("Updater: no se pudo abrir el log de updates %1: %2")
                                    .arg(path, file.errorString());
        return;
    }

    // Mismo formato de fecha que el helper de macOS, para que las lineas de los dos se lean como
    // una sola secuencia. Las lineas de continuacion van indentadas.
    const QStringList lines = message.split(QLatin1Char('\n'));
    QString text = QStringLiteral("[%1] [app %2 pid %3] %4\n")
                       .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")),
                            QApplication::applicationVersion(),
                            QString::number(QCoreApplication::applicationPid()), lines.value(0));
    for (qsizetype i = 1; i < lines.size(); ++i) {
        text += QStringLiteral("    %1\n").arg(lines.at(i));
    }
    file.write(text.toUtf8());
}

QString LgaUpdateService::withUpdateLogPath(const QString &detail) const
{
    if (m_config.updateLogPath.isEmpty()) {
        return detail;
    }
    const QString path = QDir::toNativeSeparators(m_config.updateLogPath);
    return detail.isEmpty() ? QStringLiteral("log=%1").arg(path)
                            : QStringLiteral("%1\nlog=%2").arg(detail, path);
}

std::optional<QStringList> LgaUpdateService::currentWhatsNewAudiences() const
{
    if (!m_config.whatsNewAudiences) {
        return std::nullopt;
    }
    return m_config.whatsNewAudiences();
}

QVariant LgaUpdateService::readState(const QString LgaUpdateSettingsKeys::*key) const
{
    const std::unique_ptr<QSettings> settings = openUpdateSettings(m_config.settingsPath);
    const QString current = m_config.settingsKeys.*key;
    if (settings->contains(current) || !m_config.legacySettingsKeys) {
        return settings->value(current);
    }
    // Vacia o igual a la actual = sin clave anterior (`LgaUpdateSettingsKeys` trae defaults, asi
    // que un `legacySettingsKeys` armado a medias deja los demas campos en las claves actuales).
    const QString legacy = (*m_config.legacySettingsKeys).*key;
    return (legacy.isEmpty() || legacy == current) ? QVariant() : settings->value(legacy);
}

void LgaUpdateService::writeState(const QString LgaUpdateSettingsKeys::*key,
                                  const QVariant &value) const
{
    const std::unique_ptr<QSettings> settings = openUpdateSettings(m_config.settingsPath);
    settings->setValue(m_config.settingsKeys.*key, value);
}

void LgaUpdateService::removeState(const QString LgaUpdateSettingsKeys::*key) const
{
    const std::unique_ptr<QSettings> settings = openUpdateSettings(m_config.settingsPath);
    settings->remove(m_config.settingsKeys.*key);
    // La anterior tambien: si quedara, el fallback de `readState` la resucitaria.
    if (m_config.legacySettingsKeys && !((*m_config.legacySettingsKeys).*key).isEmpty()) {
        settings->remove((*m_config.legacySettingsKeys).*key);
    }
}

QString LgaUpdateService::defaultMacUpdateLogPath(const QString &productId)
{
#ifdef Q_OS_MAC
    return QDir::home().filePath(QStringLiteral("Library/Logs/LGA/%1/Update.log").arg(productId));
#else
    Q_UNUSED(productId);
    return {};
#endif
}

QString LgaUpdateService::resolveDownloadDir() const
{
    const QString preferred = resolveUpdateDir(m_config.updateCacheDir);
    if (!m_config.updateDirWriteFallback) {
        return (preferred.isEmpty() || !QDir().mkpath(preferred)) ? QString() : preferred;
    }
    if (directoryAcceptsWrites(preferred)) {
        return preferred;
    }
    if (!preferred.isEmpty()) {
        logUpdate(QStringLiteral("La carpeta de updates no acepta escrituras (%1); se usa la del "
                                 "usuario.").arg(preferred));
    }
    for (const QString &fallback : userUpdateDirectories()) {
        if (fallback != preferred && directoryAcceptsWrites(fallback)) {
            return fallback;
        }
    }
    return {};
}

bool LgaUpdateService::isBusy() const
{
    // Esperar un reintento tambien es estar ocupado: no hay reply en vuelo, pero el chequeo o la
    // descarga siguen en curso y otro pedido encima los pisaria.
    return m_checkReply || m_checkRetry || m_downloadReply || m_downloadRetry || m_promptVisible
        || m_resultDialogVisible || m_notesPending || m_whatsNewDialogVisible;
}

void LgaUpdateService::scheduleAutomaticCheck()
{
    if (m_automaticCheckScheduled) {
        return;
    }
    m_automaticCheckScheduled = true;

    // Primero lo que se instalo sin verlo: si el chequeo dispara mientras este paso todavia
    // busca notas, se pospone hasta que termine (ver `checkForUpdates`), asi nunca se apilan
    // el "What's New" y el "Update Available".
    m_afterUpdateRunning = true;
    QTimer::singleShot(m_config.whatsNewAfterUpdateDelayMs, this,
                       [this]() { runWhatsNewAfterUpdate(); });
    QTimer::singleShot(m_config.automaticCheckDelayMs, this, [this]() { checkForUpdates(false); });

    // Despues del chequeo del arranque, el periodico: FrameRev vive en el tray dias enteros y no
    // se enteraba nunca de una version nueva.
    if (m_config.periodicCheckIntervalMs > 0) {
        schedulePeriodicCheckIn(m_config.periodicCheckIntervalMs, /*withJitter=*/true);
        m_periodicTimer = new QTimer(this);
        m_periodicTimer->setTimerType(Qt::VeryCoarseTimer);
        m_periodicTimer->setInterval(qMin(kPeriodicTickMs, m_config.periodicCheckIntervalMs));
        connect(m_periodicTimer, &QTimer::timeout, this, &LgaUpdateService::onPeriodicTick);
        m_periodicTimer->start();
    }

    // Red de seguridad: el chequeo automatico NUNCA puede quedar esperando para siempre a las
    // notas. Cada paso de red tiene su timeout, pero si alguno no terminara, sin esto la app
    // dejaria de ofrecer updates en silencio. Con el cartel de notas abierto no se fuerza
    // nada: al cerrarlo, el propio paso libera el chequeo.
    //
    // Son dos pasos de red (manifiesto y notas), y cada uno puede gastar todos sus intentos
    // (`LgaNetRetry::kMaxAttempts`, sumando servidores) con su timeout y las esperas entre ellos:
    // el tope los cubre a los dos enteros.
    const int stepMs = LgaNetRetry::kMaxAttempts * m_config.checkTimeoutMs
        + (LgaNetRetry::kMaxAttempts - 1) * LgaNetRetry::delayMs();
    const int watchdogMs = m_config.whatsNewAfterUpdateDelayMs + 2 * stepMs + 5000;
    QTimer::singleShot(watchdogMs, this, [this]() {
        if (m_afterUpdateRunning && !m_whatsNewDialogVisible) {
            qWarning().noquote()
                << QStringLiteral("Updater: el paso de notas no termino a tiempo; el chequeo "
                                  "automatico sigue sin esperarlo");
            finishWhatsNewAfterUpdate();
        }
    });
}

void LgaUpdateService::schedulePeriodicCheckIn(qint64 delayMs, bool withJitter)
{
    qint64 jitterMs = 0;
    if (withJitter && m_config.periodicCheckJitterMs > 0) {
        const int span = m_config.periodicCheckJitterMs;
        jitterMs = QRandomGenerator::global()->bounded(2 * span + 1) - span;
    }
    m_nextPeriodicCheckUtc =
        QDateTime::currentDateTimeUtc().addMSecs(qMax<qint64>(0, delayMs + jitterMs));
}

void LgaUpdateService::onPeriodicTick()
{
    const QDateTime now = QDateTime::currentDateTimeUtc();

    // Un reloj que se atraso (a mano o por zona) dejaria el proximo chequeo a dias de distancia.
    const qint64 maxAheadMs =
        qint64(m_config.periodicCheckIntervalMs) + m_config.periodicCheckJitterMs;
    if (now.msecsTo(m_nextPeriodicCheckUtc) > maxAheadMs) {
        schedulePeriodicCheckIn(m_config.periodicCheckIntervalMs, /*withJitter=*/true);
        return;
    }
    if (now < m_nextPeriodicCheckUtc) {
        return;
    }

    // Con un cartel abierto, una descarga o un "What's new" en curso no se pisa nada: el tick
    // siguiente lo vuelve a intentar. El tick sigue corriendo dentro del event loop de un modal.
    if (isBusy() || m_afterUpdateRunning || m_historyRunning) {
        return;
    }

    schedulePeriodicCheckIn(m_config.periodicCheckIntervalMs, /*withJitter=*/true);
    m_periodicCheckActive = true;
    checkForUpdates(false);
    // Puede no haber arrancado nada (chequeo automatico deshabilitado, binario no actualizable).
    // El primer intento sale sincronico: sin reply ahora, no hubo chequeo.
    if (!m_checkReply) {
        m_periodicCheckActive = false;
    }
}

void LgaUpdateService::checkForUpdates(bool manual)
{
    if (!m_network) {
        return;
    }

    // El automatico no compite con un "What's new" en curso ni con un cartel de resultado
    // abierto (por ejemplo, "no se pudieron cargar las notas" del historial): se pospone y corre
    // cuando ese termina, en vez de perderse por `isBusy()` hasta el proximo chequeo.
    if (!manual && (m_afterUpdateRunning || m_historyRunning || m_whatsNewDialogVisible
                    || m_resultDialogVisible)) {
        m_automaticCheckDeferred = true;
        return;
    }

    if (isBusy()) {
        if (manual) {
            showResultDialog(tr("Updates"), tr("An update operation is already in progress."));
        }
        return;
    }

    // Antes que la preferencia del usuario: si este binario no se puede actualizar, el chequeo
    // no tiene a donde llegar, ni siquiera pedido a mano.
    if (m_config.updateBlockedReason) {
        const QString reason = m_config.updateBlockedReason();
        if (!reason.isEmpty()) {
            if (manual) {
                showResultDialog(tr("Updates"), reason);
            }
            return;
        }
    }

    if (!manual && m_config.automaticChecksEnabled && !m_config.automaticChecksEnabled()) {
        return;
    }

    m_manualCheckActive = manual;
    if (manual && m_config.busyCursorOnManualCheck && !m_checkCursorActive) {
        // Lo pidio un click: el chequeo y la espera de las notas pueden tardar unos segundos.
        // Se saca en `endCheckPhase()`, antes del cartel.
        QApplication::setOverrideCursor(Qt::BusyCursor);
        m_checkCursorActive = true;
    }
    startCheckRequest();
}

void LgaUpdateService::startCheckRequest()
{
    // Una sola fase por chequeo, aunque gaste varios intentos: `checkStarted` sale una vez y
    // `checkFinished` al final, asi un boton "Checking..." no parpadea entre reintentos.
    m_checkBudget.reset();
    sendCheckRequest();
    m_checkPhaseOpen = true;
    emit checkStarted();
}

void LgaUpdateService::sendCheckRequest()
{
    QNetworkRequest request{QUrl(m_config.manifestUrl)};
    request.setHeader(
        QNetworkRequest::UserAgentHeader,
        QStringLiteral("%1/%2").arg(m_config.productId, QApplication::applicationVersion()));
    request.setRawHeader("Accept", "application/json");
    // Pages ya sirve el manifiesto por CDN con su propio cache; el de Qt encima solo agregaria
    // una segunda capa que hace mas dificil saber que version se esta leyendo.
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute,
                         QNetworkRequest::AlwaysNetwork);
    // Sin timeout una conexion colgada deja el flujo esperando para siempre.
    request.setTransferTimeout(m_config.checkTimeoutMs);

    logNet(QStringLiteral("Chequeo %1 (%2): version instalada %3, manifiesto %4")
               .arg(m_manualCheckActive ? QStringLiteral("manual") : QStringLiteral("automatico"),
                    m_checkBudget.label(), QApplication::applicationVersion(),
                    m_config.manifestUrl));
    m_checkReply = m_network->get(request);
    connect(m_checkReply, &QNetworkReply::finished, this, &LgaUpdateService::onCheckFinished);
    connect(m_checkReply, &QNetworkReply::sslErrors, this,
            [](const QList<QSslError> &errors) { logSslErrors(errors); });
}

void LgaUpdateService::endCheckPhase()
{
    if (m_checkCursorActive) {
        m_checkCursorActive = false;
        QApplication::restoreOverrideCursor();
    }
    if (m_checkPhaseOpen) {
        m_checkPhaseOpen = false;
        emit checkFinished();
    }
}

void LgaUpdateService::onCheckFinished()
{
    QNetworkReply *reply = m_checkReply;
    m_checkReply = nullptr;

    // `checkFinished()` sale una sola vez por chequeo, por `endCheckPhase()`:
    //  - en los desenlaces con cartel, ANTES del cartel (lo hace `showResultDialog`);
    //  - en los que terminan callados, al salir de esta funcion (este guard);
    //  - cuando hay update, al terminar la espera de las notas (`promptWithNotes`), para que el
    //    boton siga en "Checking..." mientras tanto.
    //  - mientras espera un reintento, nunca: el chequeo sigue en curso.
    bool waitingForNotes = false;
    bool retrying = false;
    const auto checkPhaseGuard = qScopeGuard([this, &waitingForNotes, &retrying]() {
        if (!waitingForNotes && !retrying) {
            endCheckPhase();
        }
    });

    if (!reply) {
        return;
    }

    // Fallo de conexion, timeout o 429/5xx: se vuelve a mandar el mismo pedido despues de la
    // espera de la regla de red (GateBouncer bloquea el primer intento de cada programa y de
    // cada destino nuevo, y el Allow vale recien para el siguiente). Va ANTES de leer y limpiar
    // el estado del chequeo: el intento siguiente es el mismo chequeo (manual o no, periodico o
    // no). Nadie cancela este pedido a proposito; morir el servicio corta la conexion antes.
    // `allowRetry` va ultimo: cuenta el intento solo si de verdad se reintenta.
    const QString failedAttempt = m_checkBudget.label();
    if (LgaNetRetry::shouldRetry(reply, /*cancelledOnPurpose=*/false)
        && m_checkBudget.allowRetry(reply)) {
        // Un solo `arg()` con todo: un texto de error con un `%N` adentro no se come al resto.
        logNet(QStringLiteral("Chequeo fallido (%1): httpStatus=%2 networkError=%3 (%4); se "
                              "reintenta en %5 ms")
                   .arg(failedAttempt,
                        QString::number(
                            reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt()),
                        QString::number(static_cast<int>(reply->error())), reply->errorString(),
                        QString::number(LgaNetRetry::delayMs())));
        reply->deleteLater();
        retrying = true;
        QObject *context = newRetryContext();
        m_checkRetry = context;
        QTimer::singleShot(LgaNetRetry::delayMs(), context, [this, context]() {
            m_checkRetry.clear();
            releaseRetryContext(context);
            sendCheckRequest();
        });
        return;
    }

    const bool manual = m_manualCheckActive;
    const bool periodic = m_periodicCheckActive;
    m_manualCheckActive = false;
    m_periodicCheckActive = false;

    const QNetworkReply::NetworkError error = reply->error();
    const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QByteArray payload = reply->readAll();
    reply->deleteLater();

    // El chequeo automatico se calla en TODOS los desenlaces que no son "hay version nueva":
    // no interrumpe al usuario para decirle que esta al dia.
    if (error != QNetworkReply::NoError) {
        // Al despertar de una suspension la red suele tardar en levantar: el periodico que falla
        // se reintenta pronto en vez de esperar un intervalo entero. Este reintento largo va
        // DESPUES de los cortos de `LgaNetRetry`, que ya se gastaron para llegar aca.
        if (periodic && m_config.periodicCheckRetryMs > 0) {
            schedulePeriodicCheckIn(m_config.periodicCheckRetryMs, /*withJitter=*/false);
        }
        logNet(QStringLiteral("Chequeo fallido (%1): httpStatus=%2 networkError=%3 (%4)")
                   .arg(failedAttempt, QString::number(httpStatus),
                        QString::number(static_cast<int>(error)), reply->errorString()));
        if (manual) {
            // Sin el detalle crudo, un fallo de parseo y un proxy que devuelve HTML se
            // reportan igual que una caida de red, y no hay nada que copiar y mandar.
            showResultDialog(tr("Update Check Failed"),
                             tr("Could not check for updates. Please try again later."),
                             QStringLiteral("httpStatus=%1\nurl=%2\nnetworkError=%3\nattempts=%4\n"
                                            "body=%5")
                                 .arg(QString::number(httpStatus), m_config.manifestUrl,
                                      QString::number(static_cast<int>(error)),
                                      QString::number(m_checkBudget.attempt()),
                                      QString::fromUtf8(payload.left(2048))),
                             /*warning=*/true);
        }
        return;
    }

    // Un manifiesto de un formato MAS NUEVO no es "no hay update": es "esta version ya no sabe
    // leer la lista", y lo unico que lo arregla es reinstalar. "No installable update was found"
    // mandaria a esperar una version que en realidad ya esta publicada.
    const int schemaVersion = manifestSchemaVersion(payload);
    if (schemaVersion > kManifestSchemaVersion) {
        logUpdate(QStringLiteral("Manifiesto con schemaVersion=%1; esta version lee hasta %2")
                      .arg(schemaVersion)
                      .arg(kManifestSchemaVersion));
        if (manual) {
            showResultDialog(tr("Updates"),
                             tr("This version is too old to read the update list.\n"
                                "Reinstall %1 from a newer installer.")
                                 .arg(m_config.displayName),
                             QStringLiteral("url=%1\nschemaVersion=%2 (soportado %3)")
                                 .arg(m_config.manifestUrl)
                                 .arg(schemaVersion)
                                 .arg(kManifestSchemaVersion),
                             /*warning=*/true);
        }
        return;
    }

    QString manifestFailure;
    const ReleaseInfo info =
        parseManifest(payload, m_config.productId, m_config.releaseRepoSlug, &manifestFailure);
    if (info.version.isEmpty()) {
        logUpdate(manifestFailure.isEmpty()
                      ? QStringLiteral("El manifiesto no trae un release de %1 (repo=%2)")
                            .arg(m_config.productId, m_config.releaseRepoSlug)
                      : QStringLiteral("Manifiesto ilegible: %1").arg(manifestFailure));
        if (manual) {
            if (!manifestFailure.isEmpty()) {
                showResultDialog(tr("Update Check Failed"),
                                 tr("The update manifest could not be read safely."),
                                 QStringLiteral("%1\nhttpStatus=%2\nurl=%3\nbody=%4")
                                     .arg(manifestFailure, QString::number(httpStatus),
                                          m_config.manifestUrl,
                                          QString::fromUtf8(payload.left(2048))),
                                 /*warning=*/true);
            } else {
                showResultDialog(tr("Updates"), tr("No installable update was found."),
                                 QStringLiteral("httpStatus=%1\nurl=%2\nbody=%3")
                                     .arg(QString::number(httpStatus), m_config.manifestUrl,
                                          QString::fromUtf8(payload.left(2048))));
            }
        }
        return;
    }

    if (!info.downloadUrl.isValid()) {
        logUpdate(QStringLiteral("La %1 no trae asset para %2").arg(info.version, currentPlatformLabel()));
        if (manual) {
            showResultDialog(tr("Updates"),
                             tr("Release %1 does not contain an installable asset for %2.")
                                 .arg(info.version, currentPlatformLabel()));
        }
        return;
    }

    if (!isVersionNewer(info.version, QApplication::applicationVersion())) {
        logUpdate(QStringLiteral("Al dia: la ultima es %1").arg(info.version));
        if (manual) {
            showResultDialog(tr("Updates"), tr("You are running the latest version."));
        }
        return;
    }

    // Fail-closed: el manifiesto publica el SHA-256 que GitHub calcula para el asset. Si falta
    // o no tiene 64 hex, no se ofrece una descarga que despues no se podria autenticar.
    if (info.assetDigest.isEmpty()) {
        qWarning().noquote()
            << QStringLiteral("Updater: el release %1 no tiene un SHA-256 valido para %2")
                   .arg(info.version, info.assetName);
        logUpdate(QStringLiteral("La %1 no tiene SHA-256 valido para %2; no se ofrece")
                      .arg(info.version, info.assetName));
        if (manual) {
            showResultDialog(tr("Update Check Failed"),
                             tr("The published update is missing valid integrity information."),
                             QStringLiteral("version=%1\nasset=%2\nrepo=%3")
                                 .arg(info.version, info.assetName, m_config.releaseRepoSlug),
                             /*warning=*/true);
        }
        return;
    }

    logUpdate(QStringLiteral("Version nueva: %1 (%2)").arg(info.version, info.assetName));
    // Antes del skip y el snooze: el aviso que no interrumpe sigue valiendo para una version
    // pospuesta. Sin cartel, asi que no abre ningun event loop anidado aca adentro.
    emit updateAvailable(normalizedVersion(info.version));

    // El skip y el snooze valen solo para el chequeo automatico: si el usuario aprieta "Check
    // Now", quiere ver la respuesta aunque haya pospuesto esta version.
    if (!manual) {
        const QString skippedVersion = readState(&LgaUpdateSettingsKeys::skippedVersion).toString();
        const QString snoozeUntilText = readState(&LgaUpdateSettingsKeys::snoozeUntil).toString();

        if (normalizedVersion(skippedVersion) == normalizedVersion(info.version)) {
            logUpdate(QStringLiteral("Sin cartel: el usuario salteo la %1").arg(info.version));
            return;
        }

        const QDateTime snoozeUntil = QDateTime::fromString(snoozeUntilText, Qt::ISODate);
        if (snoozeUntil.isValid() && QDateTime::currentDateTime() < snoozeUntil) {
            logUpdate(QStringLiteral("Sin cartel: pospuesto hasta %1").arg(snoozeUntilText));
            return;
        }

        if (!m_sessionDismissedVersion.isEmpty()
            && m_sessionDismissedVersion == normalizedVersion(info.version)) {
            logUpdate(QStringLiteral("Sin cartel: la %1 se cerro con Cancel en esta sesion")
                          .arg(info.version));
            return;
        }
    }

    if (m_promptVisible) {
        return;
    }

    waitingForNotes = true;
    promptWithNotes(info.version, info.downloadUrl, info.assetName, info.assetDigest, payload);
}

void LgaUpdateService::promptWithNotes(const QString &version,
                                       const QUrl &downloadUrl,
                                       const QString &assetName,
                                       const QString &sha256Digest,
                                       const QByteArray &manifestPayload)
{
    const LgaWhatsNew::AssetRef notesAsset =
        LgaWhatsNew::assetFromManifest(manifestPayload, m_config.releaseRepoSlug);
    if (m_config.whatsNewWaitMs <= 0 || !notesAsset.isValid()) {
        endCheckPhase();
        promptForUpdate(version, downloadUrl, assetName, sha256Digest, QString());
        return;
    }

    // Las notas NUNCA demoran el update mas que `whatsNewWaitMs`: lo que llegue primero entre
    // las notas y ese tope muestra el cartel, y lo otro se ignora. La descarga sigue aunque
    // pierda la carrera (con su propio timeout), para dejar la cache lista para la proxima.
    const quint64 generation = ++m_notesGeneration;
    m_notesPending = true;
    const QString installed = normalizedVersion(QApplication::applicationVersion());
    const auto deliver = [this, generation, version, downloadUrl, assetName,
                          sha256Digest](const QString &notesHtml) {
        if (!m_notesPending || generation != m_notesGeneration) {
            return;
        }
        m_notesPending = false;
        endCheckPhase();
        promptForUpdate(version, downloadUrl, assetName, sha256Digest, notesHtml);
    };

    LgaWhatsNewFetcher *fetcher = startNotesFetch(notesAsset, /*allowStaleCache=*/false);
    connect(fetcher, &LgaWhatsNewFetcher::finished, this,
            [this, deliver, installed, version](const LgaWhatsNewFetchResult &result) {
                QString notesHtml;
                if (result.status == LgaWhatsNewFetchResult::Status::Ok) {
                    const QList<LgaWhatsNew::VersionNotes> notes = LgaWhatsNew::range(
                        result.notes, installed, version, LgaWhatsNew::currentPlatform(),
                        m_config.edition, currentWhatsNewAudiences());
                    notesHtml = notes.isEmpty() ? QString() : LgaWhatsNew::toHtml(notes);
                } else {
                    qWarning().noquote()
                        << QStringLiteral("Updater: el cartel sale sin notas: %1").arg(result.detail);
                }
                // Si el cartel ya salio sin notas por el tope, esto no hace nada: la descarga
                // solo dejo la cache lista.
                deliver(notesHtml);
            });
    QTimer::singleShot(m_config.whatsNewWaitMs, this, [deliver]() { deliver(QString()); });
}

void LgaUpdateService::promptForUpdate(const QString &version,
                                       const QUrl &downloadUrl,
                                       const QString &assetName,
                                       const QString &sha256Digest,
                                       const QString &notesHtml)
{
    if (m_promptVisible) {
        return;
    }

    if (m_config.prepareForUpdatePrompt) {
        m_config.prepareForUpdatePrompt();
    }

    enum class UpdateDialogAction {
        Cancel,
        Update,
        Snooze,
        Skip
    };

    m_promptVisible = true;
    using Role = LgaUpdateDialogSpec::Role;
    LgaUpdateDialogSpec spec;
    spec.kind = LgaUpdateDialogSpec::Kind::UpdatePrompt;
    spec.iconName = QStringLiteral("download");
    spec.version = normalizedVersion(version);
    spec.title = tr("Update Available");
    spec.messageHtml =
        tr("A new version of %1 is available: %2.<br><br>"
           "You are currently running version %3.<br><br>"
           "%4")
            .arg(m_config.displayName.toHtmlEscaped(),
                 emphasis(version.toHtmlEscaped()),
                 emphasis(QApplication::applicationVersion().toHtmlEscaped()),
                 emphasis(tr("Save your work and close every other %1 window before updating.")
                              .arg(m_config.displayName.toHtmlEscaped())));
    spec.hintHtml = tr("<b>U</b> Update now · <b>R</b> Remind me later · <b>S</b> Skip this version<br>"
                       "<b>Enter</b> / <b>Esc</b> / <b>C</b> Cancel");
    spec.buttons = {
        {Role::Update, tr("&Update now"), /*primary=*/true, Qt::Key_U},
        {Role::Snooze, tr("&Remind me later"), false, Qt::Key_R},
        {Role::Skip, tr("&Skip this version"), false, Qt::Key_S},
        {Role::Cancel, tr("&Cancel"), false, Qt::Key_C},
    };
    spec.defaultIndex = 3;
    spec.escapeIndex = 3;
    // Las notas de (instalada, ofrecida] van en la caja con scroll del cartel. Sin notas es el
    // cartel de siempre.
    spec.notesHtml = notesHtml;
    if (!notesHtml.isEmpty()) {
        // Se guarda ANTES de mostrar: lo que cuenta es que las notas se vieron, decida lo que
        // decida. Asi, despues de instalar esta version, no se vuelven a mostrar.
        storeWhatsNewLastSeen(normalizedVersion(version));
    }
    const int choice = presentDialog(parentWindow(), spec);
    m_promptVisible = false;

    // Por el rol del boton, no por su posicion: cada app los ordena a su manera.
    UpdateDialogAction action = UpdateDialogAction::Cancel;
    if (choice >= 0 && choice < spec.buttons.size()) {
        switch (spec.buttons.at(choice).role) {
        case Role::Update:
            action = UpdateDialogAction::Update;
            break;
        case Role::Snooze:
            action = UpdateDialogAction::Snooze;
            break;
        case Role::Skip:
            action = UpdateDialogAction::Skip;
            break;
        case Role::Cancel:
        case Role::Ok:
            break;
        }
    }

    // Mismo orden que `UpdateDialogAction`.
    static const char *const kActionNames[] = {"Cancel", "Update now", "Remind me later", "Skip"};
    logUpdate(QStringLiteral("Cartel de la %1: %2")
                  .arg(version, QLatin1String(kActionNames[static_cast<int>(action)])));

    // Cancel (o la X) es "ahora no": calla esta version hasta reiniciar la app. Sin esto el
    // chequeo periodico la volvia a ofrecer cada pocas horas.
    if (action == UpdateDialogAction::Cancel) {
        m_sessionDismissedVersion = normalizedVersion(version);
        return;
    }

    if (action == UpdateDialogAction::Update) {
        if (m_config.installBlockedReason) {
            const QString reason = m_config.installBlockedReason();
            if (!reason.isEmpty()) {
                logUpdate(QStringLiteral("Instalacion postergada al elegir Update now: %1").arg(reason));
                // Sin el log en Details: es un "ahora no", no un fallo que haya que reportar.
                showResultDialog(tr("Update Postponed"), reason, QString(),
                                 /*warning=*/true, /*attachUpdateLog=*/false);
                return;
            }
        }
        // Actualizar ahora limpia el snooze y el skip: la decision anterior quedo sin efecto y
        // no tiene que reaparecer si el update falla y se reintenta.
        removeState(&LgaUpdateSettingsKeys::snoozeUntil);
        removeState(&LgaUpdateSettingsKeys::skippedVersion);

        m_pendingVersion = normalizedVersion(version);
        downloadAndRunUpdate(downloadUrl, assetName, sha256Digest);
        return;
    }

    if (action == UpdateDialogAction::Snooze) {
        writeState(&LgaUpdateSettingsKeys::snoozeUntil,
                   QDateTime::currentDateTime().addDays(kSnoozeDays).toString(Qt::ISODate));
        return;
    }

    if (action == UpdateDialogAction::Skip) {
        writeState(&LgaUpdateSettingsKeys::skippedVersion, normalizedVersion(version));
    }
}

// ------------------------------------------------------------------ notas ("What's new")

QString LgaUpdateService::whatsNewCacheDir() const
{
    // La carpeta del .ini de la app y no la de cache de la instalacion: son unos KB y van con
    // el resto de la configuracion.
    if (!m_config.settingsPath.isEmpty()) {
        return QFileInfo(m_config.settingsPath).absolutePath();
    }
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
}

void LgaUpdateService::storeWhatsNewLastSeen(const QString &version)
{
    if (!LgaWhatsNew::isValidVersion(version)) {
        return;
    }
    const QString stored = readState(&LgaUpdateSettingsKeys::whatsNewLastSeen).toString().trimmed();
    bool comparable = false;
    const int order = LgaWhatsNew::compareVersions(stored, version, &comparable);
    if (comparable && order >= 0) {
        return;  // se guarda el MAXIMO: nunca se baja
    }
    writeState(&LgaUpdateSettingsKeys::whatsNewLastSeen, normalizedVersion(version));
}

void LgaUpdateService::runDeferredAutomaticCheck()
{
    if (!m_automaticCheckDeferred || m_afterUpdateRunning || m_historyRunning
        || m_whatsNewDialogVisible || m_resultDialogVisible) {
        return;
    }
    m_automaticCheckDeferred = false;
    QTimer::singleShot(0, this, [this]() { checkForUpdates(false); });
}

void LgaUpdateService::requestManifest(
    std::function<void(bool ok, const QByteArray &payload, const QString &detail)> onDone)
{
    if (!m_network) {
        QTimer::singleShot(0, this, [onDone]() {
            onDone(false, QByteArray(), QStringLiteral("sin network manager"));
        });
        return;
    }
    LgaNetRetry::Budget budget;
    budget.reset();
    sendManifestRequest(budget, std::move(onDone));
}

void LgaUpdateService::sendManifestRequest(
    LgaNetRetry::Budget budget,
    std::function<void(bool ok, const QByteArray &payload, const QString &detail)> onDone)
{
    QNetworkRequest request{QUrl(m_config.manifestUrl)};
    request.setHeader(
        QNetworkRequest::UserAgentHeader,
        QStringLiteral("%1/%2").arg(m_config.productId, QApplication::applicationVersion()));
    request.setRawHeader("Accept", "application/json");
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute,
                         QNetworkRequest::AlwaysNetwork);
    request.setTransferTimeout(m_config.checkTimeoutMs);
    logNet(QStringLiteral("Manifiesto para las notas (%1): %2")
               .arg(budget.label(), m_config.manifestUrl));
    QNetworkReply *reply = m_network->get(request);
    connect(reply, &QNetworkReply::sslErrors, this,
            [](const QList<QSslError> &errors) { logSslErrors(errors); });

    // `setTransferTimeout` es de INACTIVIDAD: un servidor que gotea un byte cada tanto no lo
    // dispara nunca, y quien espera este manifiesto (el historial con su cursor de espera, el
    // "What's new" de despues de instalar) tiene pospuesto el chequeo automatico mientras
    // tanto. Este tope es TOTAL por intento: al vencer aborta el reply, que termina por
    // `finished` y cuenta como un timeout (se reintenta).
    auto *deadline = new QTimer(reply);
    deadline->setSingleShot(true);
    connect(deadline, &QTimer::timeout, reply, [reply]() { reply->abort(); });
    deadline->start(m_config.checkTimeoutMs);

    connect(reply, &QNetworkReply::finished, this, [this, reply, deadline, budget, onDone]() {
        deadline->stop();
        // Fallo transitorio: el mismo pedido, despues de la espera de la regla de red. El abort
        // del tope de arriba es un timeout, no una cancelacion de nadie.
        const QString failedAttempt = budget.label();
        LgaNetRetry::Budget next = budget;
        if (LgaNetRetry::shouldRetry(reply, /*cancelledOnPurpose=*/false)
            && next.allowRetry(reply)) {
            logNet(QStringLiteral("Manifiesto para las notas fallido (%1): httpStatus=%2 "
                                  "networkError=%3 (%4); se reintenta en %5 ms")
                       .arg(failedAttempt,
                            QString::number(
                                reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt()),
                            QString::number(static_cast<int>(reply->error())),
                            reply->errorString(), QString::number(LgaNetRetry::delayMs())));
            reply->deleteLater();
            QObject *context = newRetryContext();
            QTimer::singleShot(LgaNetRetry::delayMs(), context, [this, context, next, onDone]() {
                releaseRetryContext(context);
                sendManifestRequest(next, onDone);
            });
            return;
        }
        const QNetworkReply::NetworkError error = reply->error();
        const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray payload = reply->readAll();
        const QString detail =
            QStringLiteral("manifiesto httpStatus=%1 networkError=%2 (%3) intentos=%4")
                .arg(QString::number(httpStatus), QString::number(static_cast<int>(error)),
                     reply->errorString(), QString::number(budget.attempt()));
        if (error != QNetworkReply::NoError) {
            logNet(QStringLiteral("Manifiesto para las notas fallido (%1): %2")
                       .arg(failedAttempt, detail));
        }
        reply->deleteLater();
        onDone(error == QNetworkReply::NoError, payload, detail);
    });
}

LgaWhatsNewFetcher *LgaUpdateService::startNotesFetch(const LgaWhatsNew::AssetRef &asset,
                                                      bool allowStaleCache)
{
    auto *fetcher = new LgaWhatsNewFetcher(m_network, this);
    connect(fetcher, &LgaWhatsNewFetcher::finished, fetcher, &QObject::deleteLater);
    LgaWhatsNewFetcher::Request request;
    request.repoSlug = m_config.releaseRepoSlug;
    request.asset = asset;
    request.cacheDir = whatsNewCacheDir();
    request.timeoutMs = m_config.checkTimeoutMs;
    request.userAgent =
        QStringLiteral("%1/%2").arg(m_config.productId, QApplication::applicationVersion());
    request.allowStaleCache = allowStaleCache;
    // Los intentos de la descarga de notas van al mismo log que los del chequeo. El fetcher es
    // hijo de este objeto, asi que `this` vive mientras el fetcher pueda llamar.
    request.log = [this](const QString &message) { logNet(message); };
    fetcher->fetch(request);
    return fetcher;
}

void LgaUpdateService::showWhatsNewDialog(QWidget *parent,
                                          const QString &title,
                                          const QString &message,
                                          const QString &notesHtml,
                                          const QString &version)
{
    LgaUpdateDialogSpec spec;
    spec.kind = LgaUpdateDialogSpec::Kind::WhatsNew;
    spec.version = version;
    spec.iconName = QStringLiteral("refresh");
    spec.title = title;
    spec.messageHtml = message;
    spec.notesHtml = notesHtml;
    spec.hintHtml = tr("<b>Enter</b> / <b>Esc</b> / <b>O</b> OK");
    spec.buttons = {{LgaUpdateDialogSpec::Role::Ok, tr("&OK"), /*primary=*/true, Qt::Key_O}};
    spec.defaultIndex = 0;
    spec.escapeIndex = 0;
    // Cuenta como ocupado mientras el modal corre su event loop: ahi adentro el chequeo
    // automatico podria disparar y apilar el "Update Available" encima.
    m_whatsNewDialogVisible = true;
    presentDialog(parent, spec);
    m_whatsNewDialogVisible = false;
}

void LgaUpdateService::finishWhatsNewAfterUpdate()
{
    m_afterUpdateRunning = false;
    runDeferredAutomaticCheck();
}

void LgaUpdateService::runWhatsNewAfterUpdate()
{
    // Un build que no se actualiza (el de desarrollo) comparte el .ini con la app instalada: si
    // anotara la version como vista, la app instalada dejaria de mostrar esas notas. No sale a la
    // red ni toca `Updates/WhatsNewLastSeen`.
    if (m_config.updateBlockedReason && !m_config.updateBlockedReason().isEmpty()) {
        finishWhatsNewAfterUpdate();
        return;
    }

    const QString current = normalizedVersion(QApplication::applicationVersion());
    if (!LgaWhatsNew::isValidVersion(current)) {
        finishWhatsNewAfterUpdate();
        return;
    }

    // Con fallback a la clave anterior: una app que viene de otro updater no pierde el "What's
    // new" del update que la trajo hasta aca.
    const QString lastSeen = readState(&LgaUpdateSettingsKeys::whatsNewLastSeen).toString().trimmed();
    if (!LgaWhatsNew::isValidVersion(lastSeen)) {
        // Instalacion nueva, o primera version con esta funcion: no hay forma de saber que vio
        // el usuario, asi que no se le muestra nada y se arranca a contar desde aca.
        writeState(&LgaUpdateSettingsKeys::whatsNewLastSeen, current);
        finishWhatsNewAfterUpdate();
        return;
    }
    if (LgaWhatsNew::compareVersions(current, lastSeen) <= 0) {
        // Misma version, o una anterior (downgrade): nada que contar. No se baja el registro.
        finishWhatsNewAfterUpdate();
        return;
    }

    requestManifest([this, current, lastSeen](bool manifestOk, const QByteArray &payload,
                                              const QString &manifestDetail) {
        const LgaWhatsNew::AssetRef asset = manifestOk
            ? LgaWhatsNew::assetFromManifest(payload, m_config.releaseRepoSlug)
            : LgaWhatsNew::AssetRef{};
        LgaWhatsNewFetcher *fetcher = startNotesFetch(asset, /*allowStaleCache=*/false);
        connect(fetcher, &LgaWhatsNewFetcher::finished, this,
                [this, current, lastSeen, manifestOk,
                 manifestDetail](const LgaWhatsNewFetchResult &result) {
                    QList<LgaWhatsNew::VersionNotes> notes;
                    if (result.status == LgaWhatsNewFetchResult::Status::Ok) {
                        notes = LgaWhatsNew::range(result.notes, lastSeen, current,
                                                   LgaWhatsNew::currentPlatform(),
                                                   m_config.edition, currentWhatsNewAudiences());
                    }
                    if (notes.isEmpty()) {
                        // Solo una respuesta DEFINITIVA cierra el aviso: notas leidas sin nada
                        // para esta plataforma, o un producto que no publica notas. Una falla
                        // (manifiesto o descarga: red caida, timeout, digest malo) no guarda
                        // nada, asi el proximo arranque lo reintenta. Sin manifiesto el fetcher
                        // devuelve NoNotes porque no tiene asset, por eso se mira `manifestOk`.
                        const bool definitive = manifestOk
                            && result.status != LgaWhatsNewFetchResult::Status::Failed;
                        if (definitive) {
                            storeWhatsNewLastSeen(current);
                        } else {
                            qWarning().noquote()
                                << QStringLiteral("Updater: What's new sin notas, se reintenta en "
                                                  "el proximo arranque: %1")
                                       .arg(manifestOk ? result.detail : manifestDetail);
                        }
                        finishWhatsNewAfterUpdate();
                        return;
                    }
                    if (isBusy()) {
                        // Un cartel de update ya esta en pantalla (el usuario apreto "Check now"
                        // en el primer segundo). No se apila otro: el registro no se toca y el
                        // "What's new" sale en el proximo arranque.
                        finishWhatsNewAfterUpdate();
                        return;
                    }
                    // Se guarda ANTES de mostrar: si la app se cierra con el cartel abierto,
                    // no se vuelve a mostrar. "Una vez" es una vez.
                    storeWhatsNewLastSeen(current);
                    // La residente puede haber arrancado oculta en la bandeja: el modal necesita
                    // un owner visible, igual que el cartel de version nueva.
                    if (m_config.prepareForUpdatePrompt) {
                        m_config.prepareForUpdatePrompt();
                    }
                    showWhatsNewDialog(
                        parentWindow(), tr("What's New"),
                        tr("%1 was updated to version %2.")
                            .arg(m_config.displayName.toHtmlEscaped(),
                                 emphasis(current.toHtmlEscaped())),
                        LgaWhatsNew::toHtml(notes), current);
                    finishWhatsNewAfterUpdate();
                });
    });
}

void LgaUpdateService::showWhatsNewHistory(QWidget *dialogParent)
{
    if (m_historyRunning || m_whatsNewDialogVisible) {
        return;
    }
    m_historyRunning = true;
    // Lo pide un click: sin el cursor de espera, la demora de la red (casi siempre menos de un
    // segundo, como mucho `checkTimeoutMs`) se ve como un boton que no hizo nada.
    QApplication::setOverrideCursor(Qt::BusyCursor);
    const QPointer<QWidget> requestedParent = dialogParent;

    requestManifest([this, requestedParent](bool manifestOk, const QByteArray &payload,
                                            const QString &manifestDetail) {
        const LgaWhatsNew::AssetRef asset = manifestOk
            ? LgaWhatsNew::assetFromManifest(payload, m_config.releaseRepoSlug)
            : LgaWhatsNew::AssetRef{};
        // Sin red el historial sale de la cache aunque no se pueda confirmar que sea la ultima:
        // fue verificada al guardarse, y es mejor que un cartel de error.
        LgaWhatsNewFetcher *fetcher = startNotesFetch(asset, /*allowStaleCache=*/true);
        connect(fetcher, &LgaWhatsNewFetcher::finished, this,
                [this, requestedParent, manifestOk,
                 manifestDetail](const LgaWhatsNewFetchResult &result) {
                    QApplication::restoreOverrideCursor();
                    m_historyRunning = false;
                    QWidget *const parent =
                        requestedParent ? requestedParent.data() : parentWindow();

                    if (result.status == LgaWhatsNewFetchResult::Status::Ok) {
                        const QList<LgaWhatsNew::VersionNotes> notes = LgaWhatsNew::filtered(
                            result.notes, LgaWhatsNew::currentPlatform(), m_config.edition,
                            currentWhatsNewAudiences());
                        if (!notes.isEmpty()) {
                            showWhatsNewDialog(
                                parent, tr("What's New"),
                                tr("Release notes of %1. You are running version %2.")
                                    .arg(m_config.displayName.toHtmlEscaped(),
                                         emphasis(
                                             QApplication::applicationVersion().toHtmlEscaped())),
                                LgaWhatsNew::toHtml(notes));
                        } else {
                            showResultDialog(tr("What's New"),
                                             tr("There are no release notes for %1 yet.")
                                                 .arg(m_config.displayName));
                        }
                    } else if (manifestOk
                               && result.status == LgaWhatsNewFetchResult::Status::NoNotes) {
                        showResultDialog(tr("What's New"),
                                         tr("There are no release notes for %1 yet.")
                                             .arg(m_config.displayName));
                    } else {
                        showResultDialog(tr("What's New"),
                                         tr("The release notes could not be loaded.\n"
                                            "Check your connection and try again."),
                                         manifestOk ? result.detail : manifestDetail);
                    }
                    runDeferredAutomaticCheck();
                });
    });
}

QString LgaUpdateService::resolveUpdateDir(const QString &updateCacheDir)
{
    QString cacheRoot = updateCacheDir.trimmed();
    if (cacheRoot.isEmpty()) {
        // Compatibilidad: un consumidor que no fije la carpeta sigue bajando donde bajaba.
        cacheRoot = QStandardPaths::writableLocation(QStandardPaths::CacheLocation);
    }
    if (cacheRoot.isEmpty()) {
        cacheRoot = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    }
    if (cacheRoot.isEmpty()) {
        return QString();
    }
    return QDir(cacheRoot).filePath(QStringLiteral("updates"));
}

void LgaUpdateService::sweepUpdateCache(const QString &productId, const QString &updateCacheDir)
{
    const QString ownDir = resolveUpdateDir(updateCacheDir);
    if (!ownDir.isEmpty()) {
        // Carpeta propia, adentro de la instalacion: se vacia entera. Al arrancar no hay
        // ninguna descarga en vuelo, y una descarga a medias no sirve —`QSaveFile` solo deja
        // el archivo final al terminar, asi que no hay nada que reanudar entre sesiones.
        const QFileInfoList entries =
            QDir(ownDir).entryInfoList(QDir::Files | QDir::NoDotAndDotDot | QDir::Hidden);
        for (const QFileInfo &entry : entries) {
            QFile::remove(entry.absoluteFilePath());
        }
    }

    if (productId.trimmed().isEmpty()) {
        return;
    }
    // Carpetas del usuario (`CacheLocation`, `TempLocation`): la ubicacion vieja y el fallback de
    // `updateDirWriteFallback`. Las comparten otras cosas, asi que se borra SOLO lo que escribe
    // este servicio para este producto (el instalador y sus scripts helper).
    const QStringList prefixes = ownedFilePrefixes(productId);
    for (const QString &userDir : userUpdateDirectories()) {
        if (userDir == QDir::cleanPath(ownDir)) {
            continue;
        }
        const QFileInfoList staleEntries =
            QDir(userDir).entryInfoList(QDir::Files | QDir::NoDotAndDotDot | QDir::Hidden);
        bool removedOwn = false;
        for (const QFileInfo &entry : staleEntries) {
            if (isOwnedFile(entry.fileName(), prefixes)) {
                removedOwn = QFile::remove(entry.absoluteFilePath()) || removedOwn;
            }
        }
        // Si quedo vacia despues de sacar lo nuestro, se saca tambien la carpeta. Solo en ese
        // caso: un `updates` vacio de `%TEMP%` puede ser de otro programa.
        if (removedOwn) {
            QDir().rmdir(userDir);
        }
    }
}

void LgaUpdateService::downloadAndRunUpdate(const QUrl &downloadUrl,
                                            const QString &assetName,
                                            const QString &sha256Digest)
{
    if (!m_network || m_downloadReply || m_downloadRetry) {
        return;
    }

    const QString fallbackVersion =
        m_pendingVersion.isEmpty() ? QApplication::applicationVersion() : m_pendingVersion;
    m_pendingAssetName = safeInstallerAssetName(assetName, m_config.productId, fallbackVersion);
    m_pendingAssetSha256 = normalizedSha256Digest(sha256Digest);
    if (m_pendingAssetSha256.isEmpty()) {
        // El chequeo ya no ofrece un release sin digest; esto es la segunda llave.
        logUpdate(QStringLiteral("Descarga rechazada: %1 no tiene SHA-256 valido")
                      .arg(m_pendingAssetName));
        showResultDialog(tr("Update Failed"),
                         tr("The published update is missing valid integrity information."),
                         QStringLiteral("asset=%1").arg(m_pendingAssetName), /*warning=*/true);
        return;
    }

    // El destino se resuelve ANTES de bajar nada: el asset se escribe al disco a medida que
    // llega, asi que el archivo tiene que existir antes del primer byte.
    const QString updateDir = resolveDownloadDir();
    if (updateDir.isEmpty()) {
        logUpdate(QStringLiteral("No se pudo crear la carpeta de updates (%1)")
                      .arg(resolveUpdateDir(m_config.updateCacheDir)));
        showResultDialog(tr("Update Failed"),
                         tr("The update cache directory could not be created."), QString(),
                         /*warning=*/true);
        return;
    }
    // La carpeta propia se vacia entera; una del usuario (el fallback) es compartida.
    const bool ownUpdateDir =
        QDir::cleanPath(updateDir) == QDir::cleanPath(resolveUpdateDir(m_config.updateCacheDir));
    // El discard va ANTES de fijar el destino: limpia todo el estado de una descarga previa,
    // incluido `m_downloadTargetPath`, asi que hacerlo despues dejaria el path en vacio y el
    // QSaveFile se construiria sin nombre.
    discardPartialDownload();
    m_downloadTargetPath = QDir(updateDir).filePath(m_pendingAssetName);

    // Barrer lo que quedo de updates anteriores. Nada borra el instalador despues de usarlo
    // —ni siquiera en el camino exitoso, que termina pidiendo el cierre de la app— asi que se
    // acumularia un instalador completo POR VERSION PUBLICADA en el cache del usuario. Se
    // barre aca y no al terminar porque en el camino exitoso la app ya no esta viva.
    //
    // Se conserva el asset en curso: puede ser una descarga parcial que se va a reanudar por
    // `Range`, y borrarla obligaria a bajar todo de nuevo.
    const QString currentAssetName = QFileInfo(m_downloadTargetPath).fileName();
    const QStringList prefixes = ownedFilePrefixes(m_config.productId);
    const QFileInfoList staleEntries =
        QDir(updateDir).entryInfoList(QDir::Files | QDir::NoDotAndDotDot);
    for (const QFileInfo &stale : staleEntries) {
        if (stale.fileName() == currentAssetName) {
            continue;
        }
        if (!ownUpdateDir && !isOwnedFile(stale.fileName(), prefixes)) {
            continue;
        }
        QFile::remove(stale.absoluteFilePath());
    }

    m_downloadFile = new QSaveFile(m_downloadTargetPath);
    if (!m_downloadFile->open(QIODevice::WriteOnly)) {
        const QString detail = m_downloadFile->errorString();
        discardPartialDownload();
        showResultDialog(tr("Update Failed"), tr("The update installer could not be saved."),
                         detail, /*warning=*/true);
        return;
    }
    m_downloadHash = new QCryptographicHash(QCryptographicHash::Sha256);
    m_downloadUrl = downloadUrl;
    m_downloadWritten = 0;
    m_downloadTotal = -1;
    m_downloadBudget.reset();
    m_downloadSpaceChecked = false;
    m_downloadUserCancelled = false;

    logUpdate(QStringLiteral("Descarga: %1\ndestino=%2").arg(downloadUrl.toString(), m_downloadTargetPath));
    m_downloadLabelText = tr("Downloading %1 %2...").arg(m_config.displayName, fallbackVersion);
    m_downloadShowingRetry = false;
    m_progressDialog = new QProgressDialog(m_downloadLabelText, tr("Cancel"), 0, 0, parentWindow());
    m_progressDialog->setObjectName(QStringLiteral("updateDownloadProgressDialog"));
    if (!m_config.progressDialogStyleSheet.isEmpty()) {
        m_progressDialog->setStyleSheet(m_config.progressDialogStyleSheet);
    }
    m_progressDialog->setWindowTitle(tr("Downloading Update"));
    m_progressDialog->setWindowModality(Qt::WindowModal);
    m_progressDialog->setMinimumDuration(0);
    m_progressDialog->setAutoClose(false);
    m_progressDialog->setAutoReset(false);
    m_progressDialog->show();

    connect(m_progressDialog, &QProgressDialog::canceled, this, [this]() {
        m_downloadUserCancelled = true;
        if (m_downloadReply) {
            m_downloadReply->abort();
        } else if (m_downloadRetry) {
            // Cancel durante la espera entre intentos: no hay reply que abortar (y que termine
            // por `onDownloadFinished`), asi que el reintento pendiente se corta aca y la
            // descarga se cierra como cualquier cancelacion: sin cartel y sin el parcial.
            logUpdate(QStringLiteral("Descarga cancelada por el usuario mientras esperaba el "
                                     "reintento"));
            closeProgressDialog();
            discardPartialDownload();
        }
    });

    startDownloadRequest(0);
}

void LgaUpdateService::startDownloadRequest(qint64 resumeFrom)
{
    if (!m_network || m_downloadReply || !m_downloadFile) {
        return;
    }

    QNetworkRequest request{m_downloadUrl};
    request.setHeader(
        QNetworkRequest::UserAgentHeader,
        QStringLiteral("%1/%2").arg(m_config.productId, QApplication::applicationVersion()));
    // Timeout de INACTIVIDAD, no total: una descarga lenta de 40 minutos no se corta mientras
    // fluyan bytes.
    request.setTransferTimeout(m_config.downloadTimeoutMs);
    if (resumeFrom > 0) {
        request.setRawHeader("Range", QStringLiteral("bytes=%1-").arg(resumeFrom).toLatin1());
    }

    // Estado POR PETICION: se reinicia en cada intento, incluidos los reintentos.
    m_downloadResponseChecked = false;
    m_downloadResumeOffset = resumeFrom;

    logNet(QStringLiteral("Descarga (%1)%2")
               .arg(m_downloadBudget.label(),
                    resumeFrom > 0 ? QStringLiteral(": reanuda desde el byte %1").arg(resumeFrom)
                                   : QString()));
    m_downloadReply = m_network->get(request);

    connect(m_downloadReply, &QNetworkReply::readyRead, this,
            &LgaUpdateService::onDownloadReadyRead);
    connect(m_downloadReply, &QNetworkReply::downloadProgress, this,
            [this](qint64 bytesReceived, qint64 bytesTotal) {
                // `bytesReceived` es de ESTA peticion; con resume hay que sumarle lo que ya
                // estaba escrito, o la barra arrancaria de cero en cada reintento.
                const qint64 base = m_downloadWritten - bytesReceived;
                const qint64 total = (bytesTotal > 0) ? (bytesTotal + qMax<qint64>(base, 0)) : -1;
                if (m_downloadFailure != DownloadFailure::None) {
                    return; // ya se decidio abortar: no se resucita estado
                }
                if (total > 0) {
                    m_downloadTotal = total;
                    if (!m_downloadSpaceChecked) {
                        m_downloadSpaceChecked = true;
                        if (!ensureFreeSpaceForDownload(total)) {
                            abortDownloadDeferred();
                            return;
                        }
                    }
                    if (m_progressDialog) {
                        m_progressDialog->setMaximum(static_cast<int>(total / 1024));
                        m_progressDialog->setValue(static_cast<int>(m_downloadWritten / 1024));
                    }
                }
            });
    connect(m_downloadReply, &QNetworkReply::finished, this,
            &LgaUpdateService::onDownloadFinished);
    connect(m_downloadReply, &QNetworkReply::sslErrors, this,
            [](const QList<QSslError> &errors) { logSslErrors(errors); });
}

bool LgaUpdateService::validateDownloadResponse()
{
    if (!m_downloadReply) {
        return false;
    }

    const int status = m_downloadReply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();

    if (m_downloadResumeOffset > 0) {
        // Se pidio un rango. Un servidor que lo IGNORA responde 200 con el cuerpo completo: si
        // se siguiera appendeando, el archivo quedaria con los primeros bytes duplicados y el
        // hash calculado sobre basura. Sin digest en el release eso se commitea y se lanza como
        // instalador. Por eso, ante un 200 se descarta lo bajado y se empieza de nuevo.
        if (status == 200) {
            if (!m_downloadFile->resize(0) || !m_downloadFile->seek(0)) {
                m_downloadFailure = DownloadFailure::Resume;
                m_downloadFailureDetail =
                    QStringLiteral("El servidor ignoro el Range (200) y no se pudo reiniciar el "
                                   "archivo parcial.\n%1")
                        .arg(m_downloadFile->errorString());
                return false;
            }
            if (m_downloadHash) {
                m_downloadHash->reset();
            }
            m_downloadWritten = 0;
            m_downloadResumeOffset = 0;
            // Se invalida el total: quedo calculado sumando el offset viejo y, hasta la proxima
            // emision de progreso, haria fallar el chequeo de completitud.
            m_downloadTotal = -1;
            return true;
        }

        if (status != 206) {
            m_downloadFailure = DownloadFailure::Http;
            m_downloadFailureDetail = QStringLiteral("httpStatus=%1 al reanudar desde el byte %2")
                                          .arg(QString::number(status),
                                               QString::number(m_downloadResumeOffset));
            return false;
        }

        // Con 206, el rango que manda el servidor tiene que arrancar EXACTAMENTE donde
        // quedamos. Un servidor que clampea el offset produce el mismo archivo corrupto.
        const QByteArray contentRange = m_downloadReply->rawHeader("Content-Range");
        const qsizetype spaceIndex = contentRange.indexOf(' ');
        const qsizetype dashIndex = contentRange.indexOf('-');
        bool parsedOk = false;
        qint64 rangeStart = -1;
        if (spaceIndex >= 0 && dashIndex > spaceIndex) {
            rangeStart = contentRange.mid(spaceIndex + 1, dashIndex - spaceIndex - 1)
                             .trimmed()
                             .toLongLong(&parsedOk);
        }
        if (!parsedOk || rangeStart != m_downloadResumeOffset) {
            m_downloadFailure = DownloadFailure::Resume;
            m_downloadFailureDetail =
                QStringLiteral("Content-Range inesperado al reanudar.\nesperado=%1\nrecibido=%2")
                    .arg(QString::number(m_downloadResumeOffset),
                         QString::fromLatin1(contentRange));
            return false;
        }
        return true;
    }

    // Peticion normal: cualquier cosa que no sea 200 es una pagina de error, y escribirla al
    // archivo la haria pasar por instalador.
    if (status != 200) {
        m_downloadFailure = DownloadFailure::Http;
        m_downloadFailureDetail = QStringLiteral("httpStatus=%1").arg(QString::number(status));
        return false;
    }
    return true;
}

void LgaUpdateService::onDownloadReadyRead()
{
    if (!m_downloadReply || !m_downloadFile) {
        return;
    }
    if (m_downloadFailure != DownloadFailure::None) {
        return; // ya se decidio abortar; no se escribe nada mas
    }

    if (!m_downloadResponseChecked) {
        m_downloadResponseChecked = true;
        if (!validateDownloadResponse()) {
            abortDownloadDeferred();
            return;
        }
        // El reintento anda: el dialogo deja de decir que se reintenta recien ahora, con datos
        // buenos llegando, y no al mandar el pedido (que puede volver a fallar).
        if (m_downloadShowingRetry) {
            m_downloadShowingRetry = false;
            if (m_progressDialog) {
                m_progressDialog->setLabelText(m_downloadLabelText);
            }
        }
    }

    // Se drena el reply en cada senal. Si no se lo drena, Qt acumula TODO el cuerpo en su
    // buffer interno y la memoria crece con el tamano del asset.
    const QByteArray chunk = m_downloadReply->readAll();
    if (chunk.isEmpty()) {
        return;
    }

    if (m_downloadFile->write(chunk) != chunk.size()) {
        // Sin cartel: se anota el motivo y decide `onDownloadFinished`. Un modal aca abre un
        // event loop anidado en medio de la entrega de datos.
        m_downloadFailure = DownloadFailure::Write;
        m_downloadFailureDetail = QStringLiteral("write fallo tras %1 bytes\n%2")
                                      .arg(QString::number(m_downloadWritten),
                                           m_downloadFile->errorString());
        abortDownloadDeferred();
        return;
    }

    if (m_downloadHash) {
        m_downloadHash->addData(chunk);
    }
    m_downloadWritten += chunk.size();
}

bool LgaUpdateService::ensureFreeSpaceForDownload(qint64 totalBytes)
{
    if (totalBytes <= 0 || m_downloadTargetPath.isEmpty()) {
        return true;
    }

    const QStorageInfo storage(QFileInfo(m_downloadTargetPath).absolutePath());
    if (!storage.isValid() || !storage.isReady()) {
        return true; // sin dato confiable no se bloquea la descarga
    }

    // Margen del 15%: ademas del zip hay que poder extraerlo y dejar respirar al disco.
    const qint64 needed = totalBytes + (totalBytes / 100 * 15);
    if (storage.bytesAvailable() >= needed) {
        return true;
    }

    const auto toMb = [](qint64 bytes) { return QString::number(bytes / (1024 * 1024)); };
    m_downloadFailure = DownloadFailure::DiskSpace;
    m_downloadFailureDetail =
        QStringLiteral("volumen=%1\nnecesario=%2 MB\ndisponible=%3 MB")
            .arg(storage.rootPath(), toMb(needed), toMb(storage.bytesAvailable()));
    return false;
}

void LgaUpdateService::abortDownloadDeferred()
{
    // `QNetworkReply::abort()` emite `finished()` SINCRONICAMENTE. Llamarlo desde un handler de
    // red hace correr `onDownloadFinished` —y su cartel modal— anidado dentro de la entrega de
    // datos, con el reply todavia en el stack: al desapilar, Qt sigue emitiendo senales sobre
    // un estado ya limpiado. Diferirlo al event loop corta ese anidamiento.
    QTimer::singleShot(0, this, [this]() {
        if (m_downloadReply) {
            m_downloadReply->abort();
        }
    });
}

void LgaUpdateService::showResultDialog(const QString &title,
                                        const QString &message,
                                        const QString &rawDetail,
                                        bool warning,
                                        bool attachUpdateLog)
{
    // Un cartel de resultado cierra la fase de chequeo ANTES de abrirse (ver `checkFinished`).
    endCheckPhase();
    // El flag cuenta como "ocupado" mientras el modal corre su event loop anidado: ahi adentro
    // el timer del chequeo automatico sigue disparando y podria apilar otro cartel.
    //
    // Se GUARDA y se restaura en vez de escribir `false` al salir: dentro del event loop de un
    // cartel se puede abrir otro (la descarga en curso termina mientras el usuario todavia no
    // cerro el aviso de "ya estas al dia"), y el de adentro, al cerrarse, apagaria el flag con
    // el de afuera todavia abierto. Ahi `isBusy()` mentiria y el chequeo automatico podria
    // apilar un tercer cartel encima.
    const bool wasResultDialogVisible = m_resultDialogVisible;
    m_resultDialogVisible = true;
    LgaUpdateDialogSpec spec;
    spec.kind = LgaUpdateDialogSpec::Kind::Result;
    spec.iconName = QStringLiteral("refresh");
    spec.title = title;
    spec.messageHtml =
        message.toHtmlEscaped().replace(QLatin1Char('\n'), QStringLiteral("<br>"));
    // En un fallo, el "Details" lleva la ruta del log: es el archivo que el usuario tiene que
    // mandar.
    spec.details = (warning && attachUpdateLog) ? withUpdateLogPath(rawDetail) : rawDetail;
    spec.warning = warning;
    spec.hintHtml = tr("<b>Enter</b> / <b>Esc</b> / <b>O</b> OK");
    spec.buttons = {{LgaUpdateDialogSpec::Role::Ok, tr("&OK"), /*primary=*/true, Qt::Key_O}};
    spec.defaultIndex = 0;
    spec.escapeIndex = 0;
    presentDialog(parentWindow(), spec);
    m_resultDialogVisible = wasResultDialogVisible;
    // Si el chequeo automatico se pospuso mientras este cartel estaba abierto, corre ahora.
    runDeferredAutomaticCheck();
}

void LgaUpdateService::closeProgressDialog()
{
    if (!m_progressDialog) {
        return;
    }
    // `QProgressDialog::closeEvent()` emite `canceled()`. Si se cierra con las conexiones
    // vivas, ese `canceled()` marca como cancelada por el usuario a una descarga que acaba de
    // terminar bien, y el instalador se descarta sin instalar ni avisar nada.
    m_progressDialog->disconnect(this);
    m_progressDialog->close();
    m_progressDialog->deleteLater();
    m_progressDialog = nullptr;
}

void LgaUpdateService::discardPartialDownload()
{
    // Un reintento pendiente de esta descarga no sale: el archivo al que iba a escribir se tira.
    delete m_downloadRetry.data();
    m_downloadShowingRetry = false;
    if (m_downloadFile) {
        // cancelWriting() borra el temporal: un parcial no se deja en disco haciendose pasar por
        // un instalador valido.
        m_downloadFile->cancelWriting();
        delete m_downloadFile;
        m_downloadFile = nullptr;
    }
    delete m_downloadHash;
    m_downloadHash = nullptr;
    m_downloadWritten = 0;
    m_downloadTotal = -1;
    m_downloadBudget.reset();
    m_downloadSpaceChecked = false;
    m_downloadUserCancelled = false;
    m_downloadResponseChecked = false;
    m_downloadResumeOffset = 0;
    m_downloadFailure = DownloadFailure::None;
    m_downloadFailureDetail.clear();
    m_downloadTargetPath.clear();
}

void LgaUpdateService::onDownloadFinished()
{
    QNetworkReply *reply = m_downloadReply;
    m_downloadReply = nullptr;

    if (!reply) {
        return;
    }

    // OJO: el dialogo de progreso NO se cierra aca. Cerrarlo emite `canceled()`, y si eso
    // ocurre antes de leer el flag de cancelacion, una descarga exitosa queda marcada como
    // cancelada por el usuario. Se cierra con closeProgressDialog(), y solo en los desenlaces
    // terminales: en un reintento tiene que seguir abierto.
    const QNetworkReply::NetworkError error = reply->error();

    // Lo que quedaba en el buffer: `finished` puede llegar con bytes sin drenar. Un fallo de
    // escritura aca NO se traga: se anota como los demas.
    if (m_downloadFile && m_downloadFailure == DownloadFailure::None
        && reply->bytesAvailable() > 0) {
        const QByteArray tail = reply->readAll();
        if (!tail.isEmpty()) {
            if (m_downloadFile->write(tail) != tail.size()) {
                m_downloadFailure = DownloadFailure::Write;
                m_downloadFailureDetail =
                    QStringLiteral("write del tramo final fallo tras %1 bytes\n%2")
                        .arg(QString::number(m_downloadWritten), m_downloadFile->errorString());
            } else {
                if (m_downloadHash) {
                    m_downloadHash->addData(tail);
                }
                m_downloadWritten += tail.size();
            }
        }
    }
    const QString replyErrorString = reply->errorString();
    // Si el motivo ya lo anoto este servicio (respuesta HTTP mala, disco, escritura...), el
    // `abort()` que vino despues fue a proposito, no un corte de red. Un 429/5xx igual se
    // reintenta: `shouldRetry` mira el status antes que el error.
    const bool abortedOnPurpose = m_downloadFailure != DownloadFailure::None;
    const bool transientFailure =
        LgaNetRetry::shouldRetry(reply, m_downloadUserCancelled || abortedOnPurpose);
    reply->deleteLater();

    // Cancelar es una decision del usuario, no un fallo: no lleva cartel, pero el parcial se
    // tira igual.
    if (m_downloadUserCancelled) {
        logUpdate(QStringLiteral("Descarga cancelada por el usuario"));
        closeProgressDialog();
        discardPartialDownload();
        return;
    }

    if (m_downloadFailure == DownloadFailure::None && error != QNetworkReply::NoError) {
        m_downloadFailure = DownloadFailure::Network;
        m_downloadFailureDetail = QStringLiteral("networkError=%1 (%2)\nurl=%3\nbytesWritten=%4")
                                      .arg(QString::number(static_cast<int>(error)),
                                           replyErrorString, m_downloadUrl.toString(),
                                           QString::number(m_downloadWritten));
    }

    // Un corte se reintenta con la regla de red (3 reintentos, 5 s entre uno y otro) y se reanuda
    // desde donde quedo en vez de empezar de cero: con assets de cientos de MB, reiniciar por un
    // corte al 90% es tirar todo. Un corte antes del primer byte (GateBouncer bloqueando el
    // primer intento hacia el servidor de los archivos, que es otro destino que github.com)
    // tambien se reintenta, desde cero. Se discrimina por el FLAG de cancelacion del usuario, no
    // por el codigo de error: el transfer timeout de Qt tambien produce OperationCanceledError,
    // y es justo el caso que mas conviene reanudar.
    //
    // NO se reintenta si ya se bajo todo. Un cierre sucio de conexion justo despues del ultimo
    // byte pedia `Range: bytes=<tamano total>-`, y el 416 que devuelve el servidor terminaba
    // tirando un archivo completo y valido.
    const bool alreadyComplete = m_downloadTotal > 0 && m_downloadWritten >= m_downloadTotal;

    // Si llego el archivo entero, un cierre sucio de la conexion NO es un fallo: el asset esta
    // completo y el SHA-256 lo va a confirmar. Tratarlo como error tiraba una descarga buena.
    if (alreadyComplete && m_downloadFailure == DownloadFailure::Network) {
        m_downloadFailure = DownloadFailure::None;
        m_downloadFailureDetail.clear();
    }

    // `Http` entra solo con un status transitorio (408/429/5xx, lo decide `transientFailure`):
    // un 404 o un 416 son definitivos. Nunca se reintentan `Write`, `DiskSpace`, `Integrity` ni
    // `Resume`: insistir no los arregla. `allowRetry` va ultimo: cuenta el intento (en el
    // servidor donde fallo, `reply->url()` despues de los redirects) solo si se reintenta.
    const QString failedAttempt = m_downloadBudget.label();
    const bool retriable = (m_downloadFailure == DownloadFailure::Network
                            || m_downloadFailure == DownloadFailure::Http)
        && transientFailure && !alreadyComplete && m_downloadBudget.allowRetry(reply);
    if (retriable) {
        // Un solo `arg()` con todo: un detalle con un `%N` adentro no se come al resto.
        logNet(QStringLiteral("Descarga cortada en %1 bytes (%2); se reintenta en %3 ms desde "
                              "ahi\n%4")
                   .arg(QString::number(m_downloadWritten), failedAttempt,
                        QString::number(LgaNetRetry::delayMs()), m_downloadFailureDetail));
        m_downloadFailure = DownloadFailure::None;
        m_downloadFailureDetail.clear();
        // El dialogo de progreso NO se cierra: la descarga sigue, y sin el el usuario se
        // quedaria sin barra y sin boton para cancelar. Durante la espera dice que reintenta;
        // vuelve al texto de la descarga cuando el intento nuevo trae datos. El numero es el del
        // servidor que fallo: si el pedido pasa a fallar en otro, la cuenta vuelve a empezar.
        if (m_progressDialog) {
            m_progressDialog->setLabelText(
                tr("Connection problem. Retrying (attempt %1 of %2)...")
                    .arg(m_downloadBudget.attemptOnHost())
                    .arg(LgaNetRetry::kRetries + 1));
        }
        m_downloadShowingRetry = true;
        QObject *context = newRetryContext();
        m_downloadRetry = context;
        QTimer::singleShot(LgaNetRetry::delayMs(), context, [this, context]() {
            m_downloadRetry.clear();
            releaseRetryContext(context);
            startDownloadRequest(m_downloadWritten);
        });
        return;
    }

    // Descarga completa pero mas corta de lo anunciado: hay que detectarlo antes de commitear.
    if (m_downloadFailure == DownloadFailure::None && m_downloadTotal > 0
        && m_downloadWritten != m_downloadTotal) {
        m_downloadFailure = DownloadFailure::Network;
        m_downloadFailureDetail = QStringLiteral("descarga incompleta: %1 de %2 bytes")
                                      .arg(QString::number(m_downloadWritten),
                                           QString::number(m_downloadTotal));
    }

    if (m_downloadFailure == DownloadFailure::None
        && (!m_downloadFile || m_downloadWritten <= 0)) {
        m_downloadFailure = DownloadFailure::Network;
        m_downloadFailureDetail = QStringLiteral("no se recibio ningun byte");
    }

    // Sin digest esperado no hay contra que verificar: no se instala (fail-closed).
    if (m_downloadFailure == DownloadFailure::None
        && (m_pendingAssetSha256.isEmpty() || !m_downloadHash)) {
        m_downloadFailure = DownloadFailure::Integrity;
        m_downloadFailureDetail = QStringLiteral("sin SHA-256 esperado para verificar");
    }
    if (m_downloadFailure == DownloadFailure::None) {
        const QString downloadedDigest = QString::fromLatin1(m_downloadHash->result().toHex());
        if (downloadedDigest.compare(m_pendingAssetSha256, Qt::CaseInsensitive) != 0) {
            m_downloadFailure = DownloadFailure::Integrity;
            m_downloadFailureDetail = QStringLiteral("esperado=%1\nobtenido=%2\nbytes=%3")
                                          .arg(m_pendingAssetSha256, downloadedDigest,
                                               QString::number(m_downloadWritten));
        }
    }

    if (m_downloadFailure == DownloadFailure::None && !m_downloadFile->commit()) {
        m_downloadFailure = DownloadFailure::Write;
        m_downloadFailureDetail =
            QStringLiteral("commit fallo\n%1").arg(m_downloadFile->errorString());
    }

    closeProgressDialog();

    // UN solo cartel por fallo, y siempre con el detalle crudo detras del boton Details.
    if (m_downloadFailure != DownloadFailure::None) {
        QString message;
        switch (m_downloadFailure) {
        case DownloadFailure::DiskSpace:
            message = tr("There is not enough free disk space to download the update.");
            break;
        case DownloadFailure::Write:
            message = tr("The update installer could not be saved to disk.");
            break;
        case DownloadFailure::Integrity:
            message = tr("The downloaded update failed integrity verification.");
            break;
        case DownloadFailure::Http:
            message = tr("The server rejected the update download.");
            break;
        case DownloadFailure::Resume:
            message = tr("The interrupted download could not be resumed safely.");
            break;
        case DownloadFailure::Network:
        case DownloadFailure::None:
            message = tr("The update installer could not be downloaded.");
            break;
        }
        const QString detail = m_downloadFailureDetail;
        logNet(QStringLiteral("Descarga fallida (%1): %2\n%3")
                   .arg(failedAttempt, message, detail));
        discardPartialDownload();
        showResultDialog(tr("Update Failed"), message, detail, /*warning=*/true);
        return;
    }

    logUpdate(QStringLiteral("Descarga completa: %1 bytes, SHA-256 verificado").arg(m_downloadWritten));
    const QString installerPath = m_downloadTargetPath;
    delete m_downloadFile;
    m_downloadFile = nullptr;
    delete m_downloadHash;
    m_downloadHash = nullptr;
    m_downloadWritten = 0;
    m_downloadTotal = -1;
    m_downloadBudget.reset();
    m_downloadSpaceChecked = false;
    m_downloadResponseChecked = false;
    m_downloadResumeOffset = 0;

    if (m_config.installBlockedReason) {
        const QString reason = m_config.installBlockedReason();
        if (!reason.isEmpty()) {
            logUpdate(QStringLiteral("Instalacion postergada al terminar la descarga: %1").arg(reason));
            QFile::remove(installerPath);
            m_downloadTargetPath.clear();
            showResultDialog(tr("Update Postponed"), reason, QString(),
                             /*warning=*/true, /*attachUpdateLog=*/false);
            return;
        }
    }

    QString launchError;
    if (!launchInstallerWithHelper(installerPath, &launchError)) {
        if (launchError.isEmpty()) {
            launchError = tr("The update installer could not be launched.");
        }
        logUpdate(QStringLiteral("No se pudo lanzar el helper: %1").arg(launchError));
        showResultDialog(tr("Update Failed"), launchError, QString(), /*warning=*/true);
        return;
    }

    if (m_config.quitApplication) {
        m_config.quitApplication();
    } else {
        QApplication::quit();
    }
}

bool LgaUpdateService::launchInstallerWithHelper(const QString &installerPath,
                                                 QString *errorMessage)
{
    auto setError = [errorMessage](const QString &message) {
        if (errorMessage) {
            *errorMessage = message;
        }
    };

#ifdef Q_OS_WIN
    const QFileInfo installerInfo(installerPath);
    const QString helperPath = QDir(installerInfo.absolutePath())
                                   .filePath(QStringLiteral("%1_Update_Helper_%2.ps1")
                                                 .arg(m_config.productId)
                                                 .arg(QDateTime::currentMSecsSinceEpoch()));

    const QString appDir = QDir::toNativeSeparators(QCoreApplication::applicationDirPath());
    const QString executableName = m_config.windowsExecutableName.isEmpty()
        ? QFileInfo(QCoreApplication::applicationFilePath()).fileName()
        : m_config.windowsExecutableName;

    // El script se parametriza por replace y NO por arg(): trae llaves y comodines que conviene
    // no pasar por el formateo de QString.
    const QString helperTemplate = QStringLiteral(
R"(param([string]$InstallerPath, [string]$AppDir, [string]$LogPath)

$ErrorActionPreference = 'SilentlyContinue'

# El helper se borra a si mismo antes de cualquier salida. Se nombra con un timestamp unico,
# asi que sin esto quedaria UNO POR INTENTO de update en el directorio de cache —incluidos los
# que abortan— acumulandose para siempre. PowerShell lee el script entero a memoria antes de
# ejecutarlo, asi que borrarse en vuelo es seguro.
$script:helperSelfPath = $MyInvocation.MyCommand.Path
function Remove-Self {
    if ($script:helperSelfPath) {
        Remove-Item -LiteralPath $script:helperSelfPath -Force -ErrorAction SilentlyContinue
    }
}

# Mismo archivo y mismo formato que el log de la app (`updateLogPath`). Sin ruta no escribe.
function Write-Log([string]$Message) {
    if ($LogPath) {
        $line = '[{0}] [helper {1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $PID, $Message
        Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    }
}

if (-not $InstallerPath -or -not (Test-Path -LiteralPath $InstallerPath)) {
    Write-Log "No existe el instalador: $InstallerPath"
    Remove-Self
    exit 1
}
Write-Log "Inicio del helper. instalador=$InstallerPath carpeta=$AppDir"

$sleepMs = 500
$appWaitLimitMs = 15000
$backendWaitLimitMs = 8000
$forceClose = $__FORCE_CLOSE__

function Normalize-Path([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }
    try {
        return [System.IO.Path]::GetFullPath($Path).TrimEnd('\').ToLowerInvariant()
    } catch {
        return $Path.TrimEnd('\').ToLowerInvariant()
    }
}

$appDirNorm = Normalize-Path $AppDir

function Test-InAppDir([string]$Path) {
    $norm = Normalize-Path $Path
    if (-not $appDirNorm -or -not $norm) {
        return $false
    }
    return ($norm -eq $appDirNorm) -or $norm.StartsWith($appDirNorm + '\')
}

function Test-CommandLineInAppDir($Process) {
    if (-not $appDirNorm -or -not $Process.CommandLine) {
        return $false
    }
    # El separador de cierre NO es decorativo: sin el, la carpeta de una edicion es PREFIJO de la
    # de la otra (`...\PipeSync` esta contenida en `...\PipeSync_Client`), y actualizar una
    # cerraba los procesos de fondo de la otra.
    $cmd = $Process.CommandLine.ToLowerInvariant()
    $dirBack = $appDirNorm + '\'
    $dirFwd = $appDirNorm.Replace('\', '/') + '/'
    return $cmd.Contains($dirBack) -or $cmd.Contains($dirFwd)
}

# Filtrar por directorio de instalacion evita tocar OTRA copia de la app que el usuario tenga
# abierta desde otra carpeta.
function Get-AppProcesses {
    Get-CimInstance Win32_Process |
        Where-Object {
            ($_.Name -ieq '__EXECUTABLE_NAME__') -and
            (Test-InAppDir $_.ExecutablePath)
        }
}

# Procesos de fondo de la app (`windowsRedisCommandLineMatches`, `windowsPythonProcessNames`).
function Get-BackendProcesses {
    Get-CimInstance Win32_Process |
        Where-Object {
            (
                ($_.Name -ieq 'redis-server.exe' -and (__REDIS_MATCH__)) -or
                (($_.Name -in @(__PYTHON_PROCESS_NAMES__)) -and (__PYTHON_MATCH__))
            ) -and
            ((Test-InAppDir $_.ExecutablePath) -or (Test-CommandLineInAppDir $_))
        }
}

function Wait-UntilGone([scriptblock]$Query, [int]$TimeoutMs) {
    $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
    while ((& $Query | Select-Object -First 1) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds $sleepMs
    }
    return -not (& $Query | Select-Object -First 1)
}

function Stop-Postponed([string]$What, [string]$PopupText) {
    # Nunca forzar el cierre en este modo: puede ser una instancia secundaria con trabajo sin
    # guardar. El usuario conserva su trabajo y puede reintentar despues de cerrar todo.
    Write-Log "Update postergado: $What sigue abierto"
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shell.Popup($PopupText, 0, '__POPUP_TITLE__', 48) | Out-Null
    } catch {}
    # La app que pidio el update ya se cerro: una residente la necesita de vuelta (ver
    # `LgaUpdateConfig::relaunchWhenUpdatePostponed`).
    if ($__RELAUNCH_WHEN_POSTPONED__) {
        try { Start-Process -FilePath (Join-Path $AppDir '__EXECUTABLE_NAME__') } catch {}
    }
    Remove-Self
    exit 3
}

if (-not (Wait-UntilGone { Get-AppProcesses } $appWaitLimitMs)) {
    if (-not $forceClose) {
        Stop-Postponed 'la app' '__POSTPONED_APP_TEXT__'
    }
    # `closePolicy = Force`: una app con procesos de fondo no puede quedar a medio actualizar.
    Write-Log 'La app sigue abierta despues de 15 s; se cierra a la fuerza'
    Get-AppProcesses | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
}

if (-not (Wait-UntilGone { Get-BackendProcesses } $backendWaitLimitMs)) {
    if (-not $forceClose) {
        Stop-Postponed 'un proceso de fondo' '__POSTPONED_BACKGROUND_TEXT__'
    }
    Write-Log 'Siguen procesos de fondo despues de 8 s; se cierran a la fuerza'
    Get-BackendProcesses | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
}

for ($i = 0; $i -lt 20; $i++) {
    try {
        # Mantener exactamente la carpeta de la instalacion que solicito el update.
        $dirArgument = '/DIR="' + $AppDir + '"'
        Start-Process -FilePath $InstallerPath -ArgumentList $dirArgument -ErrorAction Stop
        Write-Log 'Instalador lanzado'
        Remove-Self
        exit 0
    } catch {
        Start-Sleep -Milliseconds $sleepMs
    }
}

Write-Log 'No se pudo lanzar el instalador despues de 20 intentos'
Remove-Self
exit 2
)");

    QStringList pythonProcessNames = m_config.windowsPythonProcessNames;
    pythonProcessNames.removeDuplicates();

    QString helperScript = helperTemplate;
    // Los avisos del helper en el idioma de la app, dentro de comillas simples de PowerShell. Van
    // antes que __DISPLAY_NAME__: ya traen el nombre puesto.
    const auto psQuoted = [](const QString &text) { return powerShellSingleQuoted(text); };
    helperScript.replace(QStringLiteral("__POPUP_TITLE__"),
                         psQuoted(tr("%1 Update").arg(m_config.displayName)));
    helperScript.replace(
        QStringLiteral("__POSTPONED_APP_TEXT__"),
        psQuoted(tr("The update was postponed because another %1 window is still open. Save your "
                    "work, close every %1 window, and try again.")
                     .arg(m_config.displayName)));
    helperScript.replace(
        QStringLiteral("__POSTPONED_BACKGROUND_TEXT__"),
        psQuoted(tr("The update was postponed because %1 is still finishing work in the "
                    "background. Try again in a moment.")
                     .arg(m_config.displayName)));
    helperScript.replace(QStringLiteral("__EXECUTABLE_NAME__"), powerShellSingleQuoted(executableName));
    helperScript.replace(QStringLiteral("__DISPLAY_NAME__"), powerShellSingleQuoted(m_config.displayName));
    helperScript.replace(QStringLiteral("__RELAUNCH_WHEN_POSTPONED__"),
                         m_config.relaunchWhenUpdatePostponed ? QStringLiteral("true")
                                                              : QStringLiteral("false"));
    helperScript.replace(QStringLiteral("__FORCE_CLOSE__"),
                         m_config.closePolicy == LgaUpdateConfig::ClosePolicy::Force
                             ? QStringLiteral("true")
                             : QStringLiteral("false"));
    helperScript.replace(QStringLiteral("__PYTHON_PROCESS_NAMES__"),
                         powerShellQuotedList(pythonProcessNames));
    helperScript.replace(QStringLiteral("__REDIS_MATCH__"),
                         powerShellCommandLineMatch(m_config.windowsRedisCommandLineMatches));
    helperScript.replace(QStringLiteral("__PYTHON_MATCH__"),
                         powerShellCommandLineMatch(m_config.windowsPythonCommandLineMatches));

    QSaveFile helperFile(helperPath);
    // Con BOM: Windows PowerShell 5.1 lee un .ps1 sin BOM en la pagina de codigos ANSI, y un aviso
    // con acentos saldria roto.
    const QByteArray helperBytes = QByteArray("\xEF\xBB\xBF") + helperScript.toUtf8();
    if (!helperFile.open(QIODevice::WriteOnly)
        || helperFile.write(helperBytes) != helperBytes.size() || !helperFile.commit()) {
        setError(tr("Could not prepare update helper script."));
        return false;
    }

    QStringList arguments;
    arguments << "-NoProfile"
              << "-ExecutionPolicy"
              << "Bypass"
              << "-WindowStyle"
              << "Hidden"
              << "-File" << helperPath << installerPath << appDir
              << QDir::toNativeSeparators(m_config.updateLogPath);
    logUpdate(QStringLiteral("Lanzando helper: %1\ninstalador=%2\ncarpeta=%3")
                  .arg(helperPath, installerPath, appDir));
    if (!QProcess::startDetached("powershell", arguments)) {
        setError(tr("Could not launch update helper process."));
        return false;
    }

    return true;
#elif defined(Q_OS_MAC)
    // El destino es el bundle que esta corriendo, sea cual sea su nombre. NO se compara contra
    // `<productId>.app`: el nombre del bundle y el del asset no son necesariamente el mismo
    // contrato. `productId` identifica SOLO al asset del release.
    QString targetAppPath = currentMacAppBundlePath();
    if (targetAppPath.isEmpty()) {
        targetAppPath = QFileInfo(QDir(QCoreApplication::applicationDirPath())
                                      .filePath(QStringLiteral("../..")))
                            .absoluteFilePath();
    }
    if (targetAppPath.isEmpty()
        || !targetAppPath.endsWith(QStringLiteral(".app"), Qt::CaseInsensitive)) {
        setError(tr("Could not resolve the %1 app bundle for update.").arg(m_config.displayName));
        return false;
    }
    const QString bundleName = QFileInfo(targetAppPath).fileName();

    const QFileInfo targetParentInfo(QFileInfo(targetAppPath).absolutePath());
    // App Translocation: una app en cuarentena abierta con click derecho > Abrir corre desde una
    // copia de solo lectura en `.../AppTranslocation/`, que el update no puede reemplazar. Se
    // anota aparte porque es la primera sospecha cuando "a mi me anda y a otro no".
    logUpdate(QStringLiteral("Instalacion macOS: bundle=%1\ncarpeta=%2 existe=%3 escribible=%4\n"
                             "translocada=%5")
                  .arg(targetAppPath, targetParentInfo.absoluteFilePath(),
                       targetParentInfo.exists() ? QStringLiteral("si") : QStringLiteral("no"),
                       targetParentInfo.isWritable() ? QStringLiteral("si") : QStringLiteral("no"),
                       targetAppPath.contains(QStringLiteral("/AppTranslocation/"))
                           ? QStringLiteral("SI")
                           : QStringLiteral("no")));
    if (!targetParentInfo.exists() || !targetParentInfo.isWritable()) {
        setError(
            tr("%1 could not update automatically because this location is not writable:\n%2\n\n"
               "Please install the new macOS release manually and run:\n"
               "sudo xattr -cr /Applications/%3")
                .arg(m_config.displayName, targetAppPath, bundleName));
        return false;
    }

    const QString executableName = QFileInfo(QCoreApplication::applicationFilePath()).fileName();
    const QFileInfo installerInfo(installerPath);
    const QString helperPath = QDir(installerInfo.absolutePath())
                                   .filePath(QStringLiteral("%1_Update_Helper_%2.sh")
                                                 .arg(m_config.productId)
                                                 .arg(QDateTime::currentMSecsSinceEpoch()));

    const QString helperTemplate = QStringLiteral(
R"MACHELPER(#!/bin/bash
set -Eeuo pipefail

ARCHIVE_PATH="${1:-}"
TARGET_APP_PATH="${2:-}"
EXECUTABLE_NAME="${3:-}"
HELPER_PATH="$0"
TARGET_EXEC="$TARGET_APP_PATH/Contents/MacOS/$EXECUTABLE_NAME"
TARGET_PARENT_DIR="$(dirname "$TARGET_APP_PATH")"
UPDATE_LOG="__UPDATE_LOG__"
WORK_DIR=""
BACKUP_PATH=""
TARGET_SWAPPED=false
INSTALL_COMPLETE=false
RELAUNCH_ALLOWED=true
POSTPONED=false
FORCE_CLOSE=__FORCE_CLOSE__
STEP="inicio"

# El log se abre ANTES de cualquier salida: un helper que abortaba en la validacion de argumentos
# se iba sin dejar una sola linea. Es el mismo archivo en el que escribe la app.
mkdir -p "$(dirname "$UPDATE_LOG")" >/dev/null 2>&1 || true
touch "$UPDATE_LOG" >/dev/null 2>&1 || true
if [ -w "$UPDATE_LOG" ]; then
    exec >> "$UPDATE_LOG" 2>&1
fi

# A stderr y no a stdout: la trampa de ERR (`-E`) tambien corre adentro de cada `$(...)`, y una
# linea de log por stdout terminaria DENTRO de la variable capturada (un `mktemp` que falla dejaba
# el texto del error en WORK_DIR). stderr va al mismo log.
log() {
    printf '[%s] [helper %s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$$" "$*" >&2
}

step() {
    STEP="$*"
    log "Paso: $STEP"
}

# Con `set -e` el script se iba en silencio en el primer comando que fallaba, y el log solo decia
# "fallo (estado=1)". Esto deja escrito QUE comando fallo y en que paso. `-E` hace que la trampa
# alcance tambien a las funciones.
on_error() {
    log "ERROR en el paso '$STEP': fallo el comando [$2] (estado=$1, linea $3)"
}
trap 'on_error "$?" "$BASH_COMMAND" "$LINENO"' ERR

fail() {
    log "ERROR en el paso '$STEP': $*"
    exit 1
}

cleanup() {
    EXIT_STATUS=$?
    trap - EXIT ERR
    set +e
    if [ "$INSTALL_COMPLETE" != true ] && [ "$EXIT_STATUS" -eq 0 ]; then
        EXIT_STATUS=1
    fi
    if [ -n "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    fi
    if [ "$INSTALL_COMPLETE" != true ] && [ "$TARGET_SWAPPED" = true ]; then
        log "Restaurando el bundle anterior desde $BACKUP_PATH"
        rm -rf "$TARGET_APP_PATH"
        if [ -n "$BACKUP_PATH" ] && [ -d "$BACKUP_PATH" ]; then
            mv "$BACKUP_PATH" "$TARGET_APP_PATH" || log "ERROR: no se pudo restaurar el backup"
        fi
    fi
    if [ "$INSTALL_COMPLETE" = true ]; then
        [ -n "$BACKUP_PATH" ] && rm -rf "$BACKUP_PATH"
        log "Update completo."
    elif [ "$POSTPONED" = true ]; then
        log "Update postergado: otra ventana de la app sigue abierta (estado=$EXIT_STATUS)."
        if [ "$RELAUNCH_ALLOWED" = true ] && [ -x "$TARGET_EXEC" ]; then
            "$TARGET_EXEC" >/dev/null 2>&1 &
        fi
        /usr/bin/osascript -e 'display notification "__POSTPONED_APP_TEXT__" with title "__POPUP_TITLE__"' >/dev/null 2>&1 || true
    else
        log "Update fallido en el paso '$STEP' (estado=$EXIT_STATUS). Se reabre la app que funcionaba."
        if [ -x "$TARGET_EXEC" ]; then
            "$TARGET_EXEC" >/dev/null 2>&1 &
        fi
        /usr/bin/osascript -e 'display notification "__UPDATE_FAILED_TEXT__" with title "__POPUP_TITLE__"' >/dev/null 2>&1 || true
    fi
    # El asset se borra SIEMPRE, salga bien o mal: ya se extrajo, pesa cientos de MB y se puede
    # volver a bajar. El barrido del arranque siguiente es la red para cuando esto no corre.
    [ -n "$ARCHIVE_PATH" ] && rm -f "$ARCHIVE_PATH"
    rm -f "$HELPER_PATH"
    exit "$EXIT_STATUS"
}
trap cleanup EXIT

log "Inicio del update. archivo=$ARCHIVE_PATH destino=$TARGET_APP_PATH ejecutable=$EXECUTABLE_NAME"
# Entorno: lo que cambia de una maquina a otra y suele explicar "a mi me anda y a otro no".
log "Entorno: macOS $(/usr/bin/sw_vers -productVersion 2>/dev/null || echo '?') $(/usr/bin/uname -m 2>/dev/null || echo '?') usuario=$(/usr/bin/id -un 2>/dev/null || echo '?') grupos=$(/usr/bin/id -Gn 2>/dev/null || echo '?')"
log "Permisos: $(/bin/ls -ld "$TARGET_PARENT_DIR" 2>&1 || true) | $(/bin/ls -ld "$TARGET_APP_PATH" 2>&1 || true)"
log "Archivo descargado: $(/bin/ls -l "$ARCHIVE_PATH" 2>&1 || true)"
log "Atributos del bundle instalado: $(/usr/bin/xattr "$TARGET_APP_PATH" 2>&1 | /usr/bin/tr '\n' ' ' || true)"
log "Espacio libre: $(/bin/df -h "$TARGET_PARENT_DIR" 2>/dev/null | /usr/bin/tail -1 || true)"

step "validar argumentos"
if [ ! -f "$ARCHIVE_PATH" ]; then
    fail "no existe el archivo descargado: $ARCHIVE_PATH"
fi
if [ -z "$TARGET_APP_PATH" ] || [ -z "$EXECUTABLE_NAME" ]; then
    fail "faltan argumentos (destino='$TARGET_APP_PATH' ejecutable='$EXECUTABLE_NAME')"
fi

step "descomprimir el zip"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/__PRODUCT_ID___Update_XXXXXX")"
/usr/bin/ditto -x -k "$ARCHIVE_PATH" "$WORK_DIR"
# El .app se busca por glob y no por nombre: el nombre del asset no tiene por que predecir el
# del bundle.
NEW_APP_PATH="$(/usr/bin/find "$WORK_DIR" -maxdepth 1 -name '*.app' -print -quit)"
if [ -z "$NEW_APP_PATH" ] || [ ! -d "$NEW_APP_PATH" ]; then
    fail "el zip no trae un .app en su raiz. Contenido: $(/bin/ls "$WORK_DIR" 2>&1 | /usr/bin/tr '\n' ' ' || true)"
fi
if [ ! -x "$NEW_APP_PATH/Contents/MacOS/$EXECUTABLE_NAME" ]; then
    fail "el bundle nuevo no trae el ejecutable $EXECUTABLE_NAME. Trae: $(/bin/ls "$NEW_APP_PATH/Contents/MacOS" 2>&1 | /usr/bin/tr '\n' ' ' || true)"
fi
log "Bundle nuevo: $NEW_APP_PATH version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$NEW_APP_PATH/Contents/Info.plist" 2>/dev/null || echo '?')"

step "verificar la firma del bundle nuevo"
/usr/bin/codesign --verify --deep --strict "$NEW_APP_PATH"
if [ ! -d "$TARGET_PARENT_DIR" ] || [ ! -w "$TARGET_PARENT_DIR" ]; then
    fail "la carpeta destino no existe o no es escribible: $TARGET_PARENT_DIR"
fi

# Filtrar por path absoluto evita cerrar otros builds de la misma app.
find_target_pids() {
    CANDIDATE_PIDS="$(/usr/bin/pgrep -f "$EXECUTABLE_NAME" 2>/dev/null || true)"
    for candidate_pid in $CANDIDATE_PIDS; do
        [ "$candidate_pid" = "$$" ] && continue
        candidate_command="$(/bin/ps -p "$candidate_pid" -o command= 2>/dev/null || true)"
        case "$candidate_command" in
            "$TARGET_EXEC"|"$TARGET_EXEC "*) printf '%s\n' "$candidate_pid" ;;
        esac
    done
    return 0
}

# Un proceso de fondo de la app (`macBackendProcessPatterns`) sigue vivo. `pgrep -f` mira la
# linea de comandos entera, y la del helper lleva el path del .app y del .zip: sin excluirlo, un
# patron con el nombre de la app lo encontraba a el mismo y esperaba 20 s de mas. `--` deja pasar
# un patron que empiece con '-'.
backend_alive() {
    for backend_pid in $(/usr/bin/pgrep -f -- "$1" 2>/dev/null || true); do
        [ "$backend_pid" = "$$" ] && continue
        backend_command="$(/bin/ps -p "$backend_pid" -o command= 2>/dev/null || true)"
        case "$backend_command" in
            ""|*"$HELPER_PATH"*) continue ;;
        esac
        return 0
    done
    return 1
}

step "esperar a que cierre la app"
TARGET_PIDS="$(find_target_pids)"
for ((i = 0; i < 60; i++)); do
    [ -z "$TARGET_PIDS" ] && break
    sleep 0.5
    TARGET_PIDS="$(find_target_pids)"
done
if [ -n "$TARGET_PIDS" ]; then
    if [ "$FORCE_CLOSE" != true ]; then
        # Nunca mandar TERM/KILL en este modo. Reabrir la que se cerro solo si la app lo pide
        # (`relaunchWhenUpdatePostponed`): en una app de varias ventanas seria una de mas.
        log "La app sigue abierta despues de 30 s (pids: $(echo $TARGET_PIDS)); se posterga"
        POSTPONED=true
        RELAUNCH_ALLOWED=__RELAUNCH_WHEN_POSTPONED__
        exit 3
    fi
    # `closePolicy = Force`: una app con procesos de fondo no puede quedar sin actualizar.
    log "La app sigue abierta despues de 30 s (pids: $(echo $TARGET_PIDS)); se le manda TERM"
    for target_pid in $TARGET_PIDS; do
        kill -TERM "$target_pid" >/dev/null 2>&1 || true
    done
    for ((i = 0; i < 20; i++)); do
        [ -z "$(find_target_pids)" ] && break
        sleep 0.5
    done
    TARGET_PIDS="$(find_target_pids)"
    if [ -n "$TARGET_PIDS" ]; then
        log "La app no cerro con TERM (pids: $(echo $TARGET_PIDS)); se le manda KILL"
        for target_pid in $TARGET_PIDS; do
            kill -KILL "$target_pid" >/dev/null 2>&1 || true
        done
        sleep 1
    fi
    if [ -n "$(find_target_pids)" ]; then
        fail "la app sigue abierta aun despues de KILL"
    fi
fi

step "esperar a los procesos de fondo"
__BACKEND_WAIT__
step "reemplazar el bundle"
BACKUP_PATH="${TARGET_APP_PATH}.backup.$(date +%s).$$"
if [ -e "$TARGET_APP_PATH" ]; then
    mv "$TARGET_APP_PATH" "$BACKUP_PATH"
fi
TARGET_SWAPPED=true
/usr/bin/ditto "$NEW_APP_PATH" "$TARGET_APP_PATH"
if [ ! -x "$TARGET_EXEC" ]; then
    fail "despues de copiar no quedo el ejecutable $TARGET_EXEC"
fi

step "verificar la firma del bundle instalado"
/usr/bin/codesign --verify --deep --strict "$TARGET_APP_PATH"
xattr -dr com.apple.quarantine "$TARGET_APP_PATH" >/dev/null 2>&1 || true

step "abrir la version nueva"
"$TARGET_EXEC" >/dev/null 2>&1 &
INSTALL_COMPLETE=true
)MACHELPER");

    // Espera ACOTADA de los procesos de fondo, y solo si la app declaro alguno: un `while pgrep`
    // sin techo dejaria el helper colgado para siempre con la app ya cerrada. No corta el update
    // si el proceso sigue vivo (mover el bundle no lo molesta), pero queda en el log.
    QString backendWait;
    for (const QString &pattern : m_config.macBackendProcessPatterns) {
        QString quoted = pattern;
        quoted.replace(QLatin1Char('\''), QStringLiteral("'\\''"));
        backendWait += QStringLiteral(
                           "for ((i = 0; i < 40; i++)); do\n"
                           "    backend_alive '%1' || break\n"
                           "    sleep 0.5\n"
                           "done\n"
                           "if backend_alive '%1'; then\n"
                           "    log \"Sigue vivo despues de 20 s un proceso de fondo: %2\"\n"
                           "fi\n")
                           .arg(quoted, shellSafeText(pattern));
    }

    const QString updateLog = m_config.updateLogPath.isEmpty()
        ? defaultMacUpdateLogPath(m_config.productId)
        : m_config.updateLogPath;

    QString helperScript = helperTemplate;
    helperScript.replace(QStringLiteral("__BACKEND_WAIT__"), backendWait);
    helperScript.replace(QStringLiteral("__UPDATE_LOG__"),
                         shellSafeText(updateLog));
    helperScript.replace(QStringLiteral("__PRODUCT_ID__"), m_config.productId);
    // Los avisos del helper en el idioma de la app. Van antes que __DISPLAY_NAME__: ya traen el
    // nombre puesto.
    helperScript.replace(QStringLiteral("__POPUP_TITLE__"),
                         notificationSafeText(tr("%1 Update").arg(m_config.displayName)));
    helperScript.replace(
        QStringLiteral("__POSTPONED_APP_TEXT__"),
        notificationSafeText(tr("The update was postponed because another %1 window is still "
                                "open. Save your work, close every %1 window, and try again.")
                                 .arg(m_config.displayName)));
    helperScript.replace(
        QStringLiteral("__UPDATE_FAILED_TEXT__"),
        notificationSafeText(tr("The update could not finish. %1 was restored; details were "
                                "saved in the update log.")
                                 .arg(m_config.displayName)));
    helperScript.replace(QStringLiteral("__DISPLAY_NAME__"), m_config.displayName);
    helperScript.replace(QStringLiteral("__RELAUNCH_WHEN_POSTPONED__"),
                         m_config.relaunchWhenUpdatePostponed ? QStringLiteral("true")
                                                              : QStringLiteral("false"));
    helperScript.replace(QStringLiteral("__FORCE_CLOSE__"),
                         m_config.closePolicy == LgaUpdateConfig::ClosePolicy::Force
                             ? QStringLiteral("true")
                             : QStringLiteral("false"));

    QSaveFile helperFile(helperPath);
    const QByteArray helperBytes = helperScript.toUtf8();
    if (!helperFile.open(QIODevice::WriteOnly)
        || helperFile.write(helperBytes) != helperBytes.size() || !helperFile.commit()) {
        setError(tr("Could not prepare macOS update helper script."));
        return false;
    }

    QStringList arguments;
    arguments << helperPath << installerPath << targetAppPath << executableName;
    logUpdate(QStringLiteral("Lanzando helper: %1").arg(helperPath));
    if (!QProcess::startDetached("/bin/bash", arguments)) {
        setError(tr("Could not launch macOS update helper process."));
        return false;
    }

    return true;
#else
    if (!QProcess::startDetached(installerPath, QStringList())) {
        setError(tr("Could not launch installer process."));
        return false;
    }
    return true;
#endif
}
