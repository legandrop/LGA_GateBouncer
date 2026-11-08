#pragma once

#include "lgaupdate/LgaNetRetry.h"

#include <QByteArray>
#include <QList>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QStringList>
#include <QUrl>

#include <functional>
#include <optional>

class QJsonObject;
class QNetworkAccessManager;
class QNetworkReply;
class QTimer;

/**
 * Notas de version para el usuario ("What's new"), leidas del asset `whats_new.json` que
 * publica cada release. SIN UI: parsea, filtra, arma HTML y baja el archivo. Lo usa
 * `LgaUpdateService`.
 *
 * Adapta `FM_WhatsNew` de FileManagerS3: mismo formato, misma regla de versiones
 * (`LgaVersionCompare`, identica a `FM_VersionCompare`), mismos colores y, desde la rev 2, los
 * mismos filtros opcionales por edicion (Studio/Client) y por audiencia (`[for:]`). Es parte de
 * la pieza canonica `libs/lgaupdate` de LGA_Base_QT_C_Py (ver su README): un arreglo se hace
 * alla y se re-copia a cada app.
 *
 * El formato lo genera `build_whats_new.py` de LGA_RepoTools (diseno completo en
 * `Docs/WhatsNew_Sistema.md` de ese repo):
 *
 *     {"schemaVersion":1,"product":"legandrop/LGA_PipeSync_Release","name":"LGA PipeSync",
 *      "versions":[{"version":"1.015","date":"2026-10-02",
 *                   "items":[{"kind":"new","text":"...","text_en":"...","for":[...],
 *                             "edition":["studio"],"platform":["mac"]}]}]}
 *
 * `text` ya trae el rotulo de rol ("Coordinators and reviewers: ..."). `edition` y `platform`
 * ausentes = todas. `for` y `edition` filtran solo si la app los pide (ver `range()`).
 * `text_en` (rev 5, opcional) es el mismo item en ingles, solo en los productos bilingues: ver
 * `displayText()`.
 */
namespace LgaWhatsNew {

/// Nombre FIJO del asset en cada release, y de la familia en `assetLatest` del manifiesto.
inline constexpr const char *kAssetName = "whats_new.json";
/// Unico `schemaVersion` que este codigo sabe leer.
inline constexpr int kSchemaVersion = 1;

enum class Kind {
    New,
    Improved,
    Fixed,
};

struct Item {
    Kind kind = Kind::New;
    /// El texto base, en castellano.
    QString text;
    /// El mismo item en ingles (`text_en`). Vacio si el producto no es bilingue o el item no lo
    /// trae (lo publicado antes de que el producto lo fuera).
    QString textEn;
    /// "win" / "mac". Vacio = todas las plataformas.
    QStringList platforms;
    /// Audiencias del `[for:]`. Se filtran solo si el consumidor opta por audiencias.
    QStringList roles;
    /// "studio" / "client". Vacio = todas las ediciones.
    QStringList editions;
};

struct VersionNotes {
    QString version;
    /// ISO `AAAA-MM-DD`, puede venir vacia.
    QString date;
    QList<Item> items;
};

struct Notes {
    /// false si el JSON no parsea, trae otro `schemaVersion` o algun campo invalido. En ese
    /// caso el resto viene vacio y `error` dice por que (texto crudo para el log).
    bool valid = false;
    QString product;
    QString name;
    QList<VersionNotes> versions;
    QString error;
};

/**
 * Parsea el contenido de `whats_new.json`. Nunca tira ni crashea: ante cualquier problema
 * devuelve `valid = false`.
 *
 * Es ESTRICTO con la estructura (una version sin numero valido, un item sin texto o con un
 * `kind` desconocido invalidan TODO): mostrar notas a medias seria peor que no mostrar nada,
 * y "sin notas" deja el cartel de update exactamente como antes.
 */
Notes parse(const QByteArray &json);

/**
 * Compara dos versiones con la regla CANONICA de `LgaVersionCompare` (la misma que decide si
 * hay update): el minor se rellena a 3 cifras A LA DERECHA, como decimal. Asi `1.15 == 1.150`,
 * `1.015 < 1.15`, `2.66 < 2.7` y `0.99 < 0.991`. Lo que sigue al minor son enteros y los ceros
 * finales no cuentan: `0.910.0 == 0.910`, `1.2.1 > 1.2`. Acepta el prefijo `v`. `vtuple()` del
 * script que genera el JSON usa la misma regla, para que la app y el script corten los rangos
 * en el mismo lugar.
 *
 * @param okOut false si alguna de las dos no es una version numerica. En ese caso devuelve 0.
 */
int compareVersions(const QString &left, const QString &right, bool *okOut = nullptr);

/// true si `version` es numerica en el sentido de `compareVersions()`.
bool isValidVersion(const QString &version);

/// "win" o "mac" segun la plataforma en la que corre la app.
QString currentPlatform();

/**
 * Versiones en el rango (`installedExclusive`, `offeredInclusive`], con sus items filtrados
 * por plataforma, edicion y audiencia, de la mas nueva a la mas vieja. Las que quedan sin items
 * se omiten.
 *
 * - `installedExclusive` vacio = sin piso; `offeredInclusive` vacio = sin techo.
 * - `platform`: "win" | "mac". Un item con `platform` que no la incluye se oculta.
 * - `edition`: "studio" | "client" | "". Con "" no se filtra por edicion.
 * - `audiences`: ausente conserva todos los roles; lista vacia muestra solo generales. Con
 *   lista, un `[for:]` entra si alguna etiqueta coincide (sin distinguir mayusculas). La app
 *   resuelve sus capacidades; este modulo no conoce permisos.
 *
 * Una version publicada solo para la OTRA plataforma igual entra si cae en el rango: el JSON
 * es el historial completo y sus items generales valen para todos.
 */
QList<VersionNotes> range(const Notes &notes,
                          const QString &installedExclusive,
                          const QString &offeredInclusive,
                          const QString &platform,
                          const QString &edition = QString(),
                          const std::optional<QStringList> &audiences = std::nullopt);

/// El historial completo filtrado por plataforma, edicion y audiencia (lo que muestra Help).
QList<VersionNotes> filtered(const Notes &notes,
                             const QString &platform,
                             const QString &edition = QString(),
                             const std::optional<QStringList> &audiences = std::nullopt);

/**
 * El texto que se le muestra al usuario: el ingles si el updater esta en ingles
 * (`LgaUpdateI18n::language()`, que sale de `LgaUpdateConfig::language`) y el item lo trae; si
 * no, el castellano. Lo usan `headline()` y `toHtml()`.
 */
QString displayText(const Item &item);

/// Texto del primer item de la version mas nueva del rango, o vacio. Para avisos de una linea.
QString headline(const QList<VersionNotes> &versions);

/// Cantidad total de items del rango.
int itemCount(const QList<VersionNotes> &versions);

/// "New" / "Improved" / "Fixed".
QString kindTitle(Kind kind);

/**
 * HTML simple para un QTextBrowser: un bloque por version (numero y fecha), y adentro los
 * items agrupados por New / Improved / Fixed, cada rotulo en su color.
 *
 * Las vinetas van en una tabla de dos columnas y no en `<ul>`: el `<ul>` de QTextDocument
 * sangra con `indentWidth` (40 px por defecto) y cada consumidor tendria que acordarse de
 * achicarlo.
 */
QString toHtml(const QList<VersionNotes> &versions);

/// Referencia al asset de notas de UN release: tag y SHA-256 esperado (64 hex, minuscula).
struct AssetRef {
    QString tag;
    QString sha256;
    bool isValid() const { return !tag.isEmpty() && sha256.size() == 64; }
};

/**
 * El asset `whats_new.json` mas nuevo de un producto del manifiesto de `LGA_Updates`, leyendo
 * la familia de `assetLatest` (o `tag`/`assets` si el manifiesto es viejo). Vacio si el
 * producto no publica notas o el digest no es un SHA-256 valido.
 */
AssetRef assetFromManifestProduct(const QJsonObject &product);

/// Igual, desde el manifiesto entero y el slug del repo de release (`owner/repo`).
AssetRef assetFromManifest(const QByteArray &manifestJson, const QString &repoSlug);

/// `https://github.com/<repo>/releases/download/<tag>/whats_new.json` (no consume API).
QUrl assetUrl(const QString &repoSlug, const QString &tag);

/**
 * Archivo de cache de las notas de un repo dentro de `cacheDir`
 * (`<cacheDir>/whats_new_<owner>_<repo>.json`). Uno solo por repo: se reemplaza al cambiar el
 * digest, porque el JSON nuevo es siempre el historial completo.
 */
QString cacheFilePath(const QString &cacheDir, const QString &repoSlug);

/// SHA-256 en hex minuscula, sin prefijo. Acepta `sha256:` adelante. Vacio si no es valido.
QString normalizedSha256(const QString &digest);

} // namespace LgaWhatsNew

/// Resultado de `LgaWhatsNewFetcher::fetch()`.
struct LgaWhatsNewFetchResult {
    enum class Status {
        /// `notes` es valido.
        Ok,
        /// El producto no publica notas (no hay asset en el manifiesto). No es un error.
        NoNotes,
        /// Red caida, timeout, HTTP, digest que no coincide, JSON invalido.
        Failed,
    };
    Status status = Status::Failed;
    LgaWhatsNew::Notes notes;
    /// Las notas salieron de la cache con el MISMO digest (no hubo descarga).
    bool fromCache = false;
    /**
     * Las notas salieron de la cache SIN poder verificar que sean las ultimas (solo con
     * `allowStaleCache`). Fueron verificadas cuando se guardaron, pero pueden no tener la
     * version mas nueva.
     */
    bool stale = false;
    /// Detalle crudo para el log. No es un mensaje para el usuario.
    QString detail;
};

/**
 * Descarga asincrona de `whats_new.json` verificada por SHA-256, con cache en disco.
 *
 * - Si la cache tiene el MISMO digest, se usa sin bajar nada.
 * - Si no, baja de `github.com/<repo>/releases/download/<tag>/whats_new.json`, verifica el
 *   SHA-256 contra el del manifiesto y recien ahi guarda la cache y parsea. Un digest que no
 *   coincide descarta el archivo y termina en `Failed`: las notas nunca se muestran sin
 *   verificar.
 * - Timeout TOTAL acotado (`timeoutMs`, por intento) y tope de tamano: sin red termina en
 *   `Failed` sin bloquear nada.
 * - Un fallo de conexion, un timeout, un corte de HTTP/2 o un 408/429/5xx se reintentan con la
 *   regla de red de LGA (`LgaNetRetry.h`: 3 reintentos por servidor, 5 s entre uno y otro).
 *   `cancel()` corta tambien la espera.
 *
 * Emite `finished` UNA sola vez por `fetch()`, siempre asincrono (nunca dentro de la llamada).
 * Una instancia sirve para un fetch a la vez; para otro en paralelo, otra instancia.
 */
class LgaWhatsNewFetcher : public QObject
{
    Q_OBJECT

public:
    struct Request {
        /// Repo de release, `owner/repo`.
        QString repoSlug;
        /// Asset a bajar. Invalido = no hay notas publicadas (o no se pudo leer el manifiesto).
        LgaWhatsNew::AssetRef asset;
        /// Carpeta de la cache. Vacia = sin cache.
        QString cacheDir;
        int timeoutMs = 15000;
        QString userAgent;
        /**
         * Si la descarga falla (o no hay asset), devolver la cache que haya aunque su digest
         * no se pueda confirmar. Solo para el historial de Help: el cartel de update y el
         * "despues de instalar" necesitan las notas de la version exacta.
         */
        bool allowStaleCache = false;
        /**
         * Donde anotar cada intento de la descarga y cada reintento (el log de updates de
         * `LgaUpdateService`). Vacio = `qInfo`. Se llama solo mientras el fetch esta en curso.
         */
        std::function<void(const QString &message)> log;
    };

    explicit LgaWhatsNewFetcher(QNetworkAccessManager *network, QObject *parent = nullptr);
    ~LgaWhatsNewFetcher() override;

    void fetch(const Request &request);
    /// Corta lo que este en curso SIN emitir `finished`.
    void cancel();
    bool isRunning() const;

signals:
    void finished(const LgaWhatsNewFetchResult &result);

private:
    /// Un intento del GET de las notas (cuenta en `m_budget`), con su tope total.
    void sendRequest();
    /// `m_request.log`, o `qInfo` si el pedido no trae log.
    void logLine(const QString &message) const;
    void onReplyFinished();
    void onReadyRead();
    void finish(const LgaWhatsNewFetchResult &result);
    /// Cache valida para `m_request` (mismo digest), o un resultado `Failed` si no hay.
    LgaWhatsNewFetchResult readCache(bool requireDigest) const;
    /// `Failed` con `detail`, o la cache sin verificar si el pedido la acepta.
    LgaWhatsNewFetchResult failedOrStale(const QString &detail) const;

    QPointer<QNetworkAccessManager> m_network;
    /**
     * QPointer y no puntero crudo: la reply es hija del MANAGER, no del fetcher. Si los dos son
     * hijos del mismo objeto y el manager se creo antes (el caso de `LgaUpdateService`), Qt lo
     * destruye primero y con el se van sus replies; despues `~LgaWhatsNewFetcher()` ->
     * `cancel()` haria `disconnect`/`abort` sobre memoria liberada y la app se caeria al cerrar
     * con una descarga de notas en curso. Mismo arreglo que FileManagerS3 (4f5f1df1).
     */
    QPointer<QNetworkReply> m_reply;
    QTimer *m_deadline = nullptr;
    /**
     * Cuenta de intentos de este fetch, por servidor: las notas salen de github.com y siguen un
     * redirect al servidor de los archivos, y cada uno puede quedar bloqueado en su primer
     * intento (`LgaNetRetry::Budget`).
     */
    LgaNetRetry::Budget m_budget;
    /// Contexto del reintento pendiente: borrarlo lo corta (`cancel()`, cierre de la app).
    QPointer<QObject> m_retryContext;
    Request m_request;
    QByteArray m_buffer;
    bool m_running = false;
    bool m_tooLarge = false;
    bool m_timedOut = false;
};

Q_DECLARE_METATYPE(LgaWhatsNewFetchResult)
