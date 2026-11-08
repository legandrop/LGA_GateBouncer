#pragma once

#include "lgaupdate/LgaNetRetry.h"
#include "lgaupdate/LgaUpdateDialog.h"

#include <QDateTime>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QStringList>
#include <QUrl>

#include <functional>
#include <optional>

/**
 * Revision de la pieza canonica. Una app que necesita algo de una revision la exige con un
 * `#if LGAUPDATE_REVISION < N` / `#error`, asi un checkout viejo corta el build con un mensaje
 * claro en vez de compilar sin la funcion. Historia en el README.
 *
 *   1 — pieza canonica: carteles por `presentDialog`, fail-closed, `installBlockedReason`...
 *   2 — absorbe lo de `FM_UpdateService` (FileManagerS3 y PipeSync), todo opt-in: log de
 *       updates, `closePolicy`, procesos de fondo, fallback de carpeta escribible, claves del
 *       .ini configurables con fallback a las viejas, y notas por edicion y audiencia.
 *   3 — reintentos de red (`LgaNetRetry.h`): todo pedido que falla por conexion, timeout, corte
 *       de HTTP/2 o 408/429/5xx se vuelve a mandar 3 veces POR SERVIDOR (tope 10 en total), 5 s
 *       entre intentos (chequeo, manifiesto de las notas, notas y descarga, que ademas reanuda
 *       por `Range`).
 */
#define LGAUPDATE_REVISION 3

class QNetworkAccessManager;
class QNetworkReply;
class QProgressDialog;
class QSaveFile;
class QCryptographicHash;
class QTimer;
class QWidget;
class LgaWhatsNewFetcher;
namespace LgaWhatsNew {
struct AssetRef;
}

/**
 * Claves del .ini donde el updater guarda su estado. Los defaults son los de las apps de
 * `lgaupdate`; FileManagerS3 y PipeSync usaban otras (`updates/snooze_until`...), que se leen
 * como `legacySettingsKeys` para no perder nada al migrar.
 */
struct LgaUpdateSettingsKeys {
    QString snoozeUntil = QStringLiteral("Updates/SnoozeUntil");
    QString skippedVersion = QStringLiteral("Updates/SkippedVersion");
    /// Hasta que version vio el usuario las notas. Perderla es grave: sin ella se trata como
    /// instalacion nueva y el "What's new" del update que la perdio no se muestra nunca.
    QString whatsNewLastSeen = QStringLiteral("Updates/WhatsNewLastSeen");
};

/**
 * Que cambia de una app a otra en el flujo de updates. TODO lo demas —el orden de los pasos,
 * los textos, el snooze/skip, la verificacion del SHA-256, los scripts helper— es identico y
 * vive en el componente.
 */
struct LgaUpdateConfig {
    /**
     * Identidad del ASSET del release, sin espacios: "LGA_FrameRev". De aca sale el patron
     * que se busca en el release (`<productId>_Mac_v<x>.zip` en macOS,
     * `<productId>_Setup_v<x>.exe` en Windows) y el nombre del script helper.
     *
     * NO es necesariamente el nombre del bundle ni el del ejecutable. Esos se resuelven
     * aparte —el de mac en
     * runtime desde `applicationFilePath()`, el de Windows por `windowsExecutableName`—.
     */
    QString productId;
    /// Nombre para el usuario, con espacios si corresponde: "LGA FrameRev".
    QString displayName;
    /**
     * Manifiesto de versiones de LGA, servido por GitHub Pages desde `legandrop/LGA_Updates`.
     * Un workflow programado de ese repo consulta la API de GitHub y publica este archivo
     * estatico con el ultimo release de cada producto.
     *
     * NO se consulta `api.github.com` directamente: sin token esa API permite 60 requests por
     * hora y POR IP, asi que un estudio entero detras del mismo NAT se queda sin cuota; y si el
     * repo consultado deja de ser publico, responde 404 y el chequeo falla siempre.
     */
    QString manifestUrl = QStringLiteral("https://legandrop.github.io/LGA_Updates/versions.json");
    /**
     * Slug `owner/repo` del repo PUBLICO de releases ("legandrop/LGA_FrameRev_Release"). Es
     * la clave con la que se busca este producto dentro del manifiesto y la base de la URL de
     * descarga del asset, que se DERIVA del slug, el tag y el nombre en vez de venir en el
     * JSON: guardarla en el manifiesto seria un segundo lugar donde el mismo dato puede quedar
     * viejo, y el formato de esa URL es publico y estable.
     */
    QString releaseRepoSlug;
    /**
     * Nombre del ejecutable de Windows CON extension ("FrameRev.exe"). El helper espera a los
     * procesos de ese nombre antes de lanzar el instalador; si alguno sigue abierto posterga
     * el update sin cerrarlo a la fuerza.
     */
    QString windowsExecutableName;
    /**
     * Archivo .ini donde se guardan `Updates/SnoozeUntil` y `Updates/SkippedVersion`. Es el
     * mismo .ini de la app, asi que la preferencia del usuario y el estado del updater viven
     * juntos. Vacio => se cae al QSettings nativo de la organizacion/aplicacion.
     */
    QString settingsPath;

    /**
     * Carpeta donde se baja el instalador del update. En Windows tiene que estar DENTRO de la
     * instalacion: es un archivo pesado (decenas de MB) y la regla de rutas de las apps LGA
     * dice que lo pesado vive con la app, para que desinstalar se lo lleve. En macOS tiene que
     * quedar AFUERA del `.app`, porque escribir adentro invalida la firma.
     *
     * Vacio => se cae al `CacheLocation` del sistema, que es lo que se hacia antes. Ese
     * default se conserva para que un consumidor que no la setee siga funcionando igual; una
     * app nueva deberia setearla siempre.
     *
     * El componente crea adentro una subcarpeta `updates/` y la barre; ver `sweepUpdateCache`.
     */
    QString updateCacheDir;

    /// Demora del chequeo automatico despues del arranque.
    int automaticCheckDelayMs = 5000;
    /**
     * Cada cuanto se repite el chequeo automatico mientras la app sigue abierta. FrameRev vive en
     * el tray dias enteros y sin esto no se enteraba nunca de una version nueva. 0 = solo el
     * chequeo del arranque.
     *
     * Se mide contra el RELOJ de pared, no contra un timer largo: despues de una suspension el
     * chequeo vencido corre al despertar, sin esperar otras 3 horas.
     */
    int periodicCheckIntervalMs = 3 * 60 * 60 * 1000;
    /// Desfase al azar (+/-) de cada intervalo, para que las maquinas de un estudio no consulten
    /// todas en el mismo segundo.
    int periodicCheckJitterMs = 15 * 60 * 1000;
    /// Reintento de un chequeo periodico que fallo por red (tipico al despertar, con la red
    /// todavia sin levantar). Sin esto el siguiente intento quedaba a un intervalo entero. Corre
    /// DESPUES de los reintentos cortos de `LgaNetRetry` (cuatro intentos, 5 s entre uno y otro).
    int periodicCheckRetryMs = 10 * 60 * 1000;
    /**
     * Timeouts de red. NO son opcionales en la practica: sin ellos una conexion colgada deja
     * el flujo esperando para siempre y el usuario no se entera de nada. Valen POR INTENTO: un
     * timeout cuenta como fallo de red y se reintenta (`LgaNetRetry`).
     */
    int checkTimeoutMs = 15000;
    int downloadTimeoutMs = 300000;

    /// Fabrica opcional: manager del mismo hilo cuya propiedad pasa al servicio; nullptr usa el normal.
    std::function<QNetworkAccessManager *(QObject *)> networkFactory;

    /**
     * Si el chequeo AUTOMATICO esta habilitado. El manual corre igual. Es un callback porque
     * cada app lo lee de su propia configuracion.
     */
    std::function<bool()> automaticChecksEnabled;

    /**
     * Motivo por el que ESTE binario no se debe auto-actualizar, o vacio si se puede. Bloquea
     * los dos chequeos; el manual ademas muestra el motivo, porque un boton que no hace nada
     * parece roto.
     *
     * Existe por un caso concreto: corriendo desde el arbol de build, el helper de Windows le
     * pasa al instalador `/DIR="<directorio del ejecutable>"`, o sea que aceptar un update
     * INSTALARIA LA APP ENCIMA DEL BUILD. FrameRev le pasa
     * `LgaRegistry::runsFromDevelopmentTree`, el mismo criterio con el que ya evita registrarse
     * en el registro compartido de LGA.
     *
     * El componente no adivina nada: es la app la que sabe cuando no corresponde actualizarse.
     */
    std::function<QString()> updateBlockedReason;

    /**
     * Motivo TRANSITORIO por el que no se puede instalar ahora (por ejemplo, trabajo abierto).
     * Se reevalua al elegir "Update now" y otra vez al terminar la descarga: entre ambos puntos
     * el estado de la app puede haber cambiado.
     */
    std::function<QString()> installBlockedReason;

    /**
     * Prepara la UI justo antes del cartel de version nueva. Sirve para cerrar Settings y traer
     * al frente una ventana residente que arranco oculta en la bandeja.
     */
    std::function<void()> prepareForUpdatePrompt;

    /**
     * Camino de cierre propio de la app despues de lanzar el helper. FrameRev lo usa para
     * volcar sus guardados diferidos antes de salir; vacio conserva el fallback generico a
     * QApplication::quit().
     */
    std::function<void()> quitApplication;

    /**
     * Si el helper posterga el update porque otra instancia de la app sigue abierta (nunca la
     * cierra a la fuerza), vuelve a abrir la que se cerro para actualizar. Para una residente
     * —FrameRev en la bandeja, con sus atajos globales— cuyo cierre deja al usuario sin la app.
     * Default false: en una app de varias ventanas seria una instancia de mas.
     */
    bool relaunchWhenUpdatePostponed = false;

    // ------------------------------------------------------------------- carteles
    /**
     * Dibuja los carteles del updater con los dialogos de la app (ver `LgaUpdateDialog.h`).
     * Toda app LGA lo pasa: vacio cae a un `QMessageBox` sin el aspecto de la app.
     */
    LgaUpdateDialogPresenter presentDialog;
    /**
     * Resalta un dato dentro del mensaje (la version, el aviso de guardar el trabajo). Recibe
     * texto ya escapado y devuelve HTML. Vacio = `<b>texto</b>`.
     */
    std::function<QString(const QString &escapedText)> emphasizeHtml;
    /**
     * Cursor de espera mientras corre un chequeo MANUAL, hasta el cartel. Para una app sin un
     * boton que pase a "Checking..." (en el Shot Player, Preferences ya se cerro): sin esto, ese
     * rato se ve como un click que no hizo nada.
     */
    bool busyCursorOnManualCheck = false;
    /**
     * Hoja de estilo del dialogo de progreso de la descarga (`QProgressDialog` con objectName
     * `updateDownloadProgressDialog`). Vacia (default) = el estilo de la app.
     */
    QString progressDialogStyleSheet;

    // ------------------------------------------------------------ notas ("What's new")
    /**
     * Edicion de ESTA instalacion: "studio", "client" o "" (producto sin ediciones, el default).
     * Filtra los items de las notas marcados `[studio]`/`[client]`: un cliente externo no ve lo
     * del estudio.
     */
    QString edition;
    /**
     * Audiencias del usuario para los items `[for:]` de las notas. Ausente (default) = no se
     * filtran; lista vacia = solo las notas generales. Se consulta al PRESENTAR las notas, no al
     * configurar, porque los permisos pueden cambiar con la app abierta. No concede permisos ni
     * cambia el update.
     */
    std::function<QStringList()> whatsNewAudiences;
    /**
     * Cuanto espera el cartel de update a que lleguen las notas antes de mostrarse SIN ellas.
     * Las notas nunca bloquean ni demoran el update mas que esto. 0 = no buscar notas.
     */
    int whatsNewWaitMs = 4000;
    /// Demora, desde `scheduleAutomaticCheck()`, del "What's new" de despues de instalar.
    int whatsNewAfterUpdateDelayMs = 1500;

    // ---------------------------------------------------------------- estado en el .ini
    /// Claves del estado del updater en `settingsPath`. Default: las de siempre de lgaupdate.
    LgaUpdateSettingsKeys settingsKeys;
    /**
     * Claves ANTERIORES, para una app que viene de otro updater. Cada valor se lee de aca solo
     * si la clave actual no existe, y "Update now" borra las dos (si no, un skip viejo
     * resucitaria). Lo que se escribe va siempre a la actual. Ausente = sin claves anteriores.
     */
    std::optional<LgaUpdateSettingsKeys> legacySettingsKeys;

    // ----------------------------------------------------------------- log de updates
    /**
     * Archivo donde la app anota cada chequeo, descarga y lanzamiento del helper (con rotacion a
     * `.1` pasado 1 MB), y donde escribe el helper de macOS: un solo archivo cuenta el update
     * entero. Tambien se agrega al "Details" de los carteles de error, para que el usuario sepa
     * que mandar. Vacio (default) = la app no escribe log, y el helper de macOS usa
     * `defaultMacUpdateLogPath()`.
     */
    QString updateLogPath;

    // ---------------------------------------------------------- carpeta de la descarga
    /**
     * Si la carpeta de `updateCacheDir` no acepta escrituras (instalacion en `Program Files`,
     * carpeta de red de solo lectura), bajar el update al `CacheLocation` o al `TempLocation`
     * del usuario en vez de fallar. Se decide con una escritura REAL, no con `isWritable()`, que
     * en Windows miente con carpetas virtualizadas por UAC. Default false: falla como siempre.
     */
    bool updateDirWriteFallback = false;

    // -------------------------------------------------------------- cierre de la app
    enum class ClosePolicy {
        /// Si la app (o un proceso de fondo en Windows) sigue abierta pasado el plazo, el helper
        /// posterga el update con un aviso y no cierra nada. El default: nunca se pierde trabajo.
        Postpone,
        /**
         * Pasado el plazo, el helper cierra a la fuerza la app y sus procesos de fondo
         * (`Stop-Process -Force` en Windows; TERM y despues KILL en macOS). Para apps con
         * backends (Redis, Python) que dejarian archivos en uso para el instalador, y donde
         * postergar dejaria el update sin terminar nunca.
         */
        Force,
    };
    ClosePolicy closePolicy = ClosePolicy::Postpone;

    // ------------------------------------------------------------ procesos de fondo
    /**
     * Procesos de fondo de la app en Windows que el helper espera (hasta 8 s) antes de lanzar el
     * instalador: un `redis-server.exe` cuya linea de comandos matchee alguno de
     * `windowsRedisCommandLineMatches`, o un proceso de `windowsPythonProcessNames` que matchee
     * `windowsPythonCommandLineMatches` (patrones `-like` de PowerShell). Solo cuentan los que
     * corren desde la carpeta de la app. Si siguen vivos, se cierran a la fuerza o se posterga,
     * segun `closePolicy`. Vacios (default) = no se espera a ninguno.
     */
    QStringList windowsPythonProcessNames;
    QStringList windowsRedisCommandLineMatches;
    QStringList windowsPythonCommandLineMatches;
    /**
     * Patrones para `pgrep -f` de los procesos de fondo que el helper de macOS espera (hasta
     * 20 s) antes de tocar el bundle. No corta el update si siguen vivos (mover el bundle no
     * molesta a un proceso que lo tenga abierto), pero lo anota en el log. Vacio = ninguno.
     */
    QStringList macBackendProcessPatterns;
};

/**
 * Flujo de actualizacion compartido de las apps LGA: chequeo contra el manifiesto de versiones, cartel
 * de "Update Available" con sus cuatro caminos (actualizar / recordar en 1 dia / saltear esta
 * version / cancelar), descarga con progreso y cancelacion, verificacion del SHA-256 y
 * lanzamiento del instalador a traves de un script helper que espera a que la app se cierre.
 * Suma las notas para el usuario ("What's new", ver `LgaWhatsNew.h`): en el cartel de update,
 * una vez despues de instalar, y como historial completo a pedido.
 *
 * Portado del `FM_UpdateService` de FileManagerS3 —mismo mecanismo, mismas lecciones—, sin el
 * modo check-only del card central, los procesos redis/python ni el bloqueo por transferencias
 * S3, que son responsabilidades especificas de FileManager/PipeSync.
 *
 * Uso:
 *
 *     m_updateService = new LgaUpdateService(config, this);
 *     m_updateService->scheduleAutomaticCheck();   // una vez, al primer showEvent
 *     m_updateService->checkForUpdates(true);      // "Check Now" de Preferences
 *
 * El parent QObject es la ventana, asi que muere con ella.
 */
class LgaUpdateService : public QObject
{
    Q_OBJECT

public:
    LgaUpdateService(LgaUpdateConfig config, QWidget *parentWindow);
    ~LgaUpdateService() override;

    /**
     * Programa el chequeo automatico una sola vez (llamadas siguientes no hacen nada).
     * Respeta `automaticChecksEnabled` cuando dispara, no ahora. Despues del primero lo repite
     * cada `periodicCheckIntervalMs` mientras la app siga abierta.
     *
     * Programa tambien el "What's new" de DESPUES de instalar (`whatsNewAfterUpdateDelayMs`):
     * si la app corre una version mas nueva que la ultima de la que el usuario vio notas
     * (`Updates/WhatsNewLastSeen` del .ini), las muestra una vez. Instalacion nueva (sin esa
     * clave): no muestra nada y empieza a contar desde la version actual. El chequeo automatico
     * espera a que ese paso termine, asi nunca se apilan los dos carteles.
     */
    void scheduleAutomaticCheck();

    /**
     * Historial completo de notas (boton "What's new" de Help). Asincrono: baja el manifiesto
     * y las notas, y sin red cae a la ultima copia verificada que haya en cache. Si no hay
     * ninguna, avisa que no se pudieron cargar.
     *
     * @param dialogParent ventana sobre la que sale el cartel. Si se cierra antes de que
     *                     lleguen las notas, o es null, sale sobre la ventana principal.
     */
    void showWhatsNewHistory(QWidget *dialogParent = nullptr);

    /**
     * `manual = true` es el "Check Now" del usuario: informa TODOS los desenlaces, incluso "ya
     * tenes la ultima version", y se saltea el snooze y el skip. `manual = false` es el chequeo
     * de fondo: solo habla si hay una version nueva que el usuario no pospuso.
     */
    void checkForUpdates(bool manual);

    /// Hay un chequeo, una descarga o un cartel en curso.
    bool isBusy() const;

    /**
     * Carpeta donde queda el instalador bajado (`<updateCacheDir>/updates`, o el
     * `CacheLocation` del sistema si la config no la fija).
     */
    static QString resolveUpdateDir(const QString &updateCacheDir);

    /// Log del helper de macOS cuando la app no fija `updateLogPath`:
    /// `~/Library/Logs/LGA/<productId>/Update.log`. Vacio fuera de macOS.
    static QString defaultMacUpdateLogPath(const QString &productId);

    /**
     * Borra los restos de updates anteriores: el instalador —que en el camino exitoso nadie
     * borra, porque la app ya se cerro cuando el instalador arranca— y los scripts helper que
     * hayan quedado de un intento abortado. Barre tambien la ubicacion VIEJA (el
     * `CacheLocation` del sistema), asi una instalacion que ya bajo updates no se queda con un
     * instalador por version publicada afuera de la carpeta de la app.
     *
     * Pensado para llamarse una vez por arranque y FUERA del hilo de UI. En las ubicaciones del
     * usuario (`CacheLocation` y `TempLocation`, que es donde baja `updateDirWriteFallback`)
     * borra SOLO lo que escribe este servicio para `productId` —`<productId>_Mac_v*`,
     * `<productId>_Setup_v*` y `<productId>_Update_Helper_*`—: son carpetas compartidas, y un
     * prefijo `<productId>` a secas se llevaba los archivos de otra edicion ("PipeSync" y
     * "PipeSync_Client").
     */
    static void sweepUpdateCache(const QString &productId, const QString &updateCacheDir);

signals:
    /**
     * El chequeo arranco / termino. Existen SOLO para que la UI refleje ese estado —un boton
     * "Check now" que pasa a "Checking..." y vuelve—: el resultado lo informa el servicio con
     * sus propios carteles, asi que estas senales no llevan desenlace.
     *
     * `checkFinished()` se emite ANTES de cualquier cartel: un modal corre un event loop
     * anidado, y si se emitiera despues el boton se quedaria en "Checking..." todo el tiempo
     * que el usuario tarde en leer el cartel. Cuando hay update y se esperan sus notas (hasta
     * `whatsNewWaitMs`), se emite al terminar esa espera, justo antes del cartel: el boton
     * sigue en "Checking..." mientras tanto en vez de volver a "Check now" sin que pase nada.
     */
    void checkStarted();
    void checkFinished();

    /**
     * Un chequeo (automatico o manual) encontro una version instalable mas nueva que la que
     * corre, con su SHA-256 publicado. Sale ANTES de mirar el snooze, el skip y el Cancel de la
     * sesion, y sin cartel propio: es para un aviso que no interrumpe —un indicador en la
     * ventana— que sigue ahi aunque el usuario haya pospuesto el cartel. Ofrecer el update
     * sigue siendo `checkForUpdates(true)`. Las apps que no tienen ese aviso no la conectan.
     */
    void updateAvailable(const QString &version);

private:
    /// Abre la fase de chequeo y manda el primer intento. Comun al chequeo automatico y al manual.
    void startCheckRequest();
    /// Un intento del GET del manifiesto del chequeo (cuenta en `m_checkBudget`).
    void sendCheckRequest();
    void onCheckFinished();
    /**
     * Objeto de contexto de UN reintento pendiente (`QTimer::singleShot` con contexto): borrarlo
     * corta el reintento. Cuelga de `m_retryHolder`, asi el cierre de la app los corta todos.
     */
    QObject *newRetryContext();
    /// Corta todos los reintentos pendientes. Conectado a `QCoreApplication::aboutToQuit`.
    void cancelPendingRetries();
    /**
     * Anota un intento de red en el log de updates y, si la app no fijo `updateLogPath`, en el
     * de la app (`qInfo`): un primer intento bloqueado por un firewall por aplicacion tiene que
     * dejar rastro aunque despues ande.
     */
    void logNet(const QString &message) const;
    void onDownloadReadyRead();
    void onDownloadFinished();
    /// Arranca (o reanuda) el GET del instalador. `resumeFrom > 0` manda un header Range.
    void startDownloadRequest(qint64 resumeFrom);
    /// Cierra el archivo parcial y libera el hash. No commitea.
    void discardPartialDownload();
    /**
     * Cierra el dialogo de progreso SIN que su `canceled()` vuelva a entrar en el servicio.
     * `QProgressDialog::closeEvent()` emite `canceled()`, asi que cerrarlo con las conexiones
     * vivas marcaria como "cancelada por el usuario" a una descarga que termino bien.
     */
    void closeProgressDialog();
    /**
     * Muestra un cartel de RESULTADO marcando el servicio como ocupado mientras esta abierto.
     * Todos los desenlaces informativos pasan por aca para que ninguno se olvide del flag.
     * `rawDetail` va detras de un boton "Details", colapsado y seleccionable.
     */
    void showResultDialog(const QString &title,
                          const QString &message,
                          const QString &rawDetail = QString(),
                          bool warning = false,
                          bool attachUpdateLog = true);
    /**
     * Aborta la descarga en el proximo ciclo del event loop. `abort()` emite `finished()`
     * sincronicamente, asi que llamarlo desde un handler de red anida `onDownloadFinished`
     * —con su cartel— dentro de la entrega de datos.
     */
    void abortDownloadDeferred();
    /**
     * Valida el status HTTP y, cuando se pidio un rango, el `Content-Range`. Se llama una vez
     * por peticion, al llegar el primer dato. Devuelve false si hay que abortar.
     */
    bool validateDownloadResponse();
    /**
     * Verifica que entre el asset en el disco destino. Devuelve false y avisa si no entra. Se
     * llama al conocer el Content-Length, no antes: sin tamano no hay nada que comparar.
     */
    bool ensureFreeSpaceForDownload(qint64 totalBytes);
    /**
     * Busca las notas de (instalada, `version`] y despues muestra el cartel de update, con o
     * sin ellas. Espera como mucho `whatsNewWaitMs`; emite `checkFinished()` justo antes del
     * cartel.
     */
    void promptWithNotes(const QString &version,
                         const QUrl &downloadUrl,
                         const QString &assetName,
                         const QString &sha256Digest,
                         const QByteArray &manifestPayload);
    void promptForUpdate(const QString &version,
                         const QUrl &downloadUrl,
                         const QString &assetName,
                         const QString &sha256Digest,
                         const QString &notesHtml);
    /**
     * Cierra la fase de chequeo: emite `checkFinished()` (una sola vez por chequeo) y saca el
     * cursor de espera del chequeo manual.
     */
    void endCheckPhase();
    /// GET del manifiesto para el "What's new" (despues de instalar e historial).
    void requestManifest(
        std::function<void(bool ok, const QByteArray &payload, const QString &detail)> onDone);
    /// Un intento de `requestManifest`; ante un fallo transitorio programa el siguiente. La cuenta
    /// viaja por valor de un intento al otro: es la de ESTE pedido.
    void sendManifestRequest(
        LgaNetRetry::Budget budget,
        std::function<void(bool ok, const QByteArray &payload, const QString &detail)> onDone);
    /// Fetcher hijo de este objeto, que se borra solo al terminar.
    LgaWhatsNewFetcher *startNotesFetch(const LgaWhatsNew::AssetRef &asset, bool allowStaleCache);
    /// Cartel modal "What's New" con las notas ya en HTML.
    void showWhatsNewDialog(QWidget *parent,
                            const QString &title,
                            const QString &message,
                            const QString &notesHtml,
                            const QString &version = QString());
    void runWhatsNewAfterUpdate();
    void finishWhatsNewAfterUpdate();
    /// Corre el chequeo automatico que se pospuso mientras habia un "What's new" en curso.
    void runDeferredAutomaticCheck();
    /// Guarda `version` como la ultima de la que se vieron notas, si es mayor que la guardada.
    void storeWhatsNewLastSeen(const QString &version);
    /// Carpeta de la cache de notas: la del .ini de la app (`settingsPath`).
    QString whatsNewCacheDir() const;
    /// Tick del chequeo periodico: si ya vencio el proximo chequeo, lo corre.
    void onPeriodicTick();
    /// Fija el proximo chequeo periodico a `delayMs` (+/- el jitter si `withJitter`) de ahora.
    void schedulePeriodicCheckIn(qint64 delayMs, bool withJitter);
    void downloadAndRunUpdate(const QUrl &downloadUrl,
                              const QString &assetName,
                              const QString &sha256Digest);
    bool launchInstallerWithHelper(const QString &installerPath, QString *errorMessage);
    QWidget *parentWindow() const;
    /// Muestra `spec` con el presentador de la app (o el de respaldo) y devuelve el boton.
    int presentDialog(QWidget *parent, const LgaUpdateDialogSpec &spec) const;
    /// `emphasizeHtml` de la config, o `<b>` si no hay.
    QString emphasis(const QString &escapedText) const;
    /// Anota una linea en `updateLogPath`. No hace nada si la app no fijo log.
    void logUpdate(const QString &message) const;
    /// `detail` con la ruta del log al final, si hay log.
    QString withUpdateLogPath(const QString &detail) const;
    /// Audiencias de las notas en este momento (ausente si la app no las configuro).
    std::optional<QStringList> currentWhatsNewAudiences() const;
    /// Lee una clave del estado, con fallback a la anterior si la actual no existe.
    QVariant readState(const QString LgaUpdateSettingsKeys::*key) const;
    /// Escribe la clave actual.
    void writeState(const QString LgaUpdateSettingsKeys::*key, const QVariant &value) const;
    /// Borra la clave actual y la anterior.
    void removeState(const QString LgaUpdateSettingsKeys::*key) const;
    /// Carpeta donde bajar ahora, con el fallback de `updateDirWriteFallback`. Vacio si no hay.
    QString resolveDownloadDir() const;

    LgaUpdateConfig m_config;
    QPointer<QWidget> m_parentWindow;
    QNetworkAccessManager *m_network = nullptr;
    QNetworkReply *m_checkReply = nullptr;
    QNetworkReply *m_downloadReply = nullptr;
    QProgressDialog *m_progressDialog = nullptr;

    // ------------------------------------------------------------ reintentos de red
    /// Padre de los contextos de los reintentos pendientes (ver `newRetryContext`).
    QObject *m_retryHolder = nullptr;
    /// Cuenta de intentos del chequeo en curso, por servidor (`LgaNetRetry::Budget`).
    LgaNetRetry::Budget m_checkBudget;
    /**
     * Reintento pendiente del chequeo. Mientras espera no hay reply, pero el chequeo sigue en
     * curso: cuenta como ocupado y la fase (`checkFinished`) sigue abierta.
     */
    QPointer<QObject> m_checkRetry;
    /// Reintento pendiente de la descarga, con el dialogo de progreso abierto. Cuenta como ocupado.
    QPointer<QObject> m_downloadRetry;
    /// Texto de la descarga en el dialogo de progreso, para volver a el cuando el reintento anda.
    QString m_downloadLabelText;
    /// El dialogo de progreso dice que se esta reintentando.
    bool m_downloadShowingRetry = false;
    bool m_manualCheckActive = false;
    /**
     * Hay un cartel de RESULTADO abierto (chequeo fallido, ya estas al dia, descarga fallida).
     * Cuenta como "ocupado": el reply ya se puso en null al entrar al handler, pero el modal
     * corre un event loop anidado y ahi adentro el timer del chequeo automatico sigue
     * disparando. Sin esto, ese chequeo pasaba el guard de `isBusy()` y podia apilar el cartel
     * de "Update Available" encima del que el usuario todavia no cerro.
     */
    bool m_resultDialogVisible = false;
    bool m_automaticCheckScheduled = false;
    bool m_promptVisible = false;
    /// Hay un chequeo cuyo `checkFinished()` todavia no se emitio.
    bool m_checkPhaseOpen = false;
    /// El chequeo manual en curso puso el cursor de espera (ver `busyCursorOnManualCheck`).
    bool m_checkCursorActive = false;

    // ------------------------------------------------------------- notas ("What's new")
    /// Esperando las notas antes de mostrar el cartel de update. Cuenta como ocupado.
    bool m_notesPending = false;
    /// Identifica la espera en curso: la descarga o el timeout que llegan tarde se ignoran.
    quint64 m_notesGeneration = 0;
    /// Hay un cartel "What's New" abierto. Cuenta como ocupado.
    bool m_whatsNewDialogVisible = false;
    /// El "What's new" de despues de instalar todavia no termino: el automatico lo espera.
    bool m_afterUpdateRunning = false;
    /// El historial de Help esta buscando las notas (con el cursor de espera puesto).
    bool m_historyRunning = false;
    /// El chequeo automatico disparo mientras habia un "What's new" en curso.
    bool m_automaticCheckDeferred = false;

    // --------------------------------------------------------------- chequeo periodico
    /// Tick corto que compara el reloj contra `m_nextPeriodicCheckUtc`. Ver
    /// `LgaUpdateConfig::periodicCheckIntervalMs`.
    QTimer *m_periodicTimer = nullptr;
    QDateTime m_nextPeriodicCheckUtc;
    /// El chequeo en curso lo lanzo el tick periodico: si falla por red, se reintenta antes.
    bool m_periodicCheckActive = false;
    /**
     * Version que el usuario cerro con Cancel (o la X) en esta sesion. El chequeo automatico no
     * la vuelve a ofrecer hasta reiniciar la app: sin esto, con el chequeo periodico el cartel
     * reaparecia cada pocas horas. No se persiste, a diferencia del snooze y el skip.
     */
    QString m_sessionDismissedVersion;

    QString m_pendingVersion;
    QString m_pendingAssetName;
    QString m_pendingAssetSha256;

    // ------------------------------------------------------ descarga por streaming
    // El asset NO se acumula en RAM: se escribe al disco a medida que llega y el SHA-256 se
    // calcula incremental. Con `readAll()` el pico era ~2x el tamano del asset (el QByteArray
    // mas el buffer interno del reply, que nadie drenaba durante la transferencia).
    QSaveFile *m_downloadFile = nullptr;
    QCryptographicHash *m_downloadHash = nullptr;
    QString m_downloadTargetPath;
    QUrl m_downloadUrl;
    qint64 m_downloadWritten = 0;
    qint64 m_downloadTotal = -1;
    /**
     * Cuenta de intentos de ESTA descarga, por servidor (github.com y despues el de los archivos).
     * Una descarga que avanza y se vuelve a cortar NO la reinicia: es el mismo pedido.
     */
    LgaNetRetry::Budget m_downloadBudget;
    bool m_downloadSpaceChecked = false;
    bool m_downloadUserCancelled = false;

    /**
     * Motivo del fallo de la descarga. Los handlers de red (`readyRead`, `downloadProgress`)
     * NO muestran carteles: anotan el motivo y abortan. El unico que habla es
     * `onDownloadFinished`. Mostrar un modal desde un handler abria un event loop anidado en
     * medio de la entrega de datos y encadenaba hasta tres carteles por un solo fallo.
     */
    enum class DownloadFailure {
        None,
        Network,
        Http,
        Write,
        DiskSpace,
        Integrity,
        Resume,
    };
    DownloadFailure m_downloadFailure = DownloadFailure::None;
    QString m_downloadFailureDetail;

    // Estado de la peticion en curso (se resetea en cada intento, incluidos los reintentos).
    bool m_downloadResponseChecked = false;
    qint64 m_downloadResumeOffset = 0;
};
