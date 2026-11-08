#pragma once
// Núcleo del firewall: reglas guardadas, solicitudes pendientes e historial sobre el motor WFP.
// Una app sin regla queda bloqueada por el filtro por defecto; su bloqueo genera una solicitud pendiente.
// Allow o Block crea una regla persistente y el próximo intento de la app usa esa regla.
//
// Cuatro alcances de regla:
//  - Path: la ruta exacta del ejecutable (WFP filtra así).
//  - App: editor firmado + nombre del ejecutable, en cualquier carpeta («any version»).
//  - Publisher: todo ejecutable firmado por ese editor.
//  - Folder: todo ejecutable dentro de una carpeta y sus subcarpetas, o sólo los que tienen un nombre (folder_rule.h).
// WFP no sabe de firmas ni de carpetas: las reglas App, Publisher y Folder viven en el motor. Cuando una app sin regla
// de ruta se bloquea, el motor verifica su firma o dónde está de verdad y, si coincide con una de esas reglas, agrega el
// filtro de esa ruta (una «cobertura»). El primer intento igual se pierde; el siguiente pasa sin preguntar. Orden: la
// regla de la ruta, las reglas por destino, la de la app, la del editor y por último la de carpeta: una carpeta de
// confianza sólo decide por los programas que no tienen otra regla.
//
// Reglas por destino: cualquiera de los tres alcances puede llevar un destino (un host, «*.dominio» o una IP). Una app
// con reglas por destino está en «modo por destino»: no tiene filtro de app entera y cada servidor nuevo pregunta por
// separado. WFP filtra por IP, no por nombre: el motor ve qué nombre resolvió la app (DnsNames) y abre o cierra sólo
// esas IPs para esa app (un «permiso de destino»). Una regla de la app entera y las reglas por destino de esa misma
// identidad se excluyen: decidir una reemplaza a las otras.
#include "dns_names.h"
#include "folder_rule.h"
#include "name_wait.h"
#include "wfp_engine.h"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <map>
#include <string>
#include <thread>
#include <vector>

namespace gbe {

enum class Scope { Path, App, Publisher, Folder };

struct Rule {
    Scope scope = Scope::Path;
    std::wstring path;          // Path: la ruta; Folder: la carpeta (ruta final); App/Publisher: vacío
    std::wstring volume;        // Folder: la carpeta por su volumen («\\?\Volume{…}\…»), con la que se compara
    std::wstring signer;        // App/Publisher: el firmante tal como lo muestra Windows
    std::wstring name;          // App: nombre del ejecutable en minúsculas; Folder: ídem, o vacío para todos
    // Vacío: la app entera. Si no: «host.ejemplo.com», «*.ejemplo.com» (el dominio y sus subdominios) o una IP.
    std::wstring destination;
    Action action = Action::Allow;
    std::int64_t created = 0;   // segundos Unix UTC
    std::int64_t lastBlock = 0; // último bloqueo atribuido a la regla (sólo reglas Block)
    // Vencimiento: 0 permanente; >0 segundos Unix UTC en que se retira; UntilRestart: no se guarda y desaparece
    // cuando el motor vuelve a arrancar. Al vencer, la app vuelve a preguntar.
    std::int64_t expires = 0;
    std::vector<std::uint64_t> filters; // sólo reglas Path
};
constexpr std::int64_t UntilRestart = -1;

// Sello de un archivo verificado: hora de cambio de NTFS, id de archivo y tamaño. Detecta un reemplazo común sin leer
// el contenido; no es prueba contra quien lo falsifica a propósito, por eso además se re-verifica todo cada tanto.
struct FileStamp {
    std::int64_t change = 0;
    std::uint64_t size = 0;
    std::uint64_t idLow = 0, idHigh = 0;
    bool operator==(const FileStamp &o) const {
        return change == o.change && size == o.size && idLow == o.idLow && idHigh == o.idHigh;
    }
};

// Filtro de una ruta puesto por una regla App o Publisher, con el sello del archivo cuando se verificó su firma.
struct Covered {
    std::wstring path;
    std::wstring ruleKey;
    std::vector<std::uint64_t> filters;
    FileStamp stamp;
};

struct Pending {
    std::wstring path;
    std::wstring signer; // vacío: sin firma embebida válida
    std::int64_t first = 0, last = 0;
    std::uint32_t attempts = 0;
    std::wstring remoteAddress;
    std::uint16_t remotePort = 0;
    std::uint8_t protocol = 0;
    std::wstring host; // el nombre que la app resolvió para esa dirección; vacío si no se sabe
    // La app está en modo por destino: la decisión es sobre este destino, no sobre la app entera. Hay un pendiente
    // por cada dirección nueva.
    bool perDestination = false;
};

// Permiso de destino: el filtro de una app hacia una IP, puesto por una regla por destino. Se guarda para el próximo
// arranque y se retira si esa app no vuelve a esa IP en una semana.
struct Grant {
    std::wstring path, address, ruleKey;
    Action action = Action::Allow;
    std::vector<std::uint64_t> filters;
    FileStamp stamp; // reglas por firma: el archivo verificado
    std::int64_t lastSeen = 0;
};

// Una consulta DNS terminada: con reglas por destino, el permiso se pone antes de que la app se conecte.
struct DnsHint {
    std::wstring app, host;
    std::vector<std::wstring> addresses;
};

struct Activity {
    std::int64_t time = 0;
    std::wstring path;
    std::wstring kind; // texto fijo en inglés: lo muestra la interfaz
    std::wstring remoteAddress;
    std::uint16_t remotePort = 0;
    std::uint8_t protocol = 0;
};

struct CoreOptions {
    bool dynamic = false;               // pruebas: todo desaparece al cerrar
    std::vector<std::wstring> scope;    // vacío = toda la PC; si no, sólo estas apps (pruebas)
    std::wstring dataDir;               // reglas guardadas
    // Ventanas de GateBouncer de confianza (la instalada junto al motor): salen por HTTPS sin preguntar, para las
    // explicaciones con IA. Sólo con toda la PC en modo preguntar; en las pruebas acotadas no hace falta.
    std::vector<std::wstring> windows;
};

class FirewallCore {
  public:
    explicit FirewallCore(CoreOptions options);
    ~FirewallCore();

    bool start(std::wstring &error);
    void stop();

    // Modo ask: lo desconocido se bloquea y se pregunta. Modo off: sin bloqueo por defecto (las reglas siguen).
    bool setAsk(bool ask, std::wstring &error);
    // Red local (redes privadas, enlace local, multicast, Tailscale) sin preguntar. Por defecto, sí.
    bool setLocalNetwork(bool allow, std::wstring &error);
    // La firma se lee del archivo en el motor: nunca se confía en un editor que mande la ventana.
    // expires: 0 permanente, >0 momento Unix en que vence, UntilRestart hasta que el motor se reinicie.
    // destination vacío: la app entera; si no, sólo ese destino (y la app pasa a modo por destino).
    bool decide(const std::wstring &path, Action action, Scope scope, std::wstring &error, std::int64_t expires = 0,
                const std::wstring &destination = {});
    // Regla por carpeta: todo ejecutable dentro de folder y sus subcarpetas, o sólo los que se llaman name (vacío:
    // todos). La carpeta se valida y se resuelve acá (resolveTrustedFolder); los pedidos de adentro se cubren ya.
    bool decideFolder(const std::wstring &folder, const std::wstring &name, Action action, std::wstring &error,
                      std::int64_t expires = 0);
    // id: la ruta de una regla Path o la clave de una regla App/Publisher.
    bool removeRule(const std::wstring &id, std::wstring &error);

    struct Status {
        bool ask = true, dynamic = false, allApps = true, localNetwork = true;
        std::int64_t started = 0;
        std::size_t pending = 0, rules = 0;
        std::wstring lastError;
        std::wstring names; // estado de la escucha de DNS (diagnóstico)
    };
    Status status();
    std::vector<Pending> pending();
    std::vector<Rule> rules();
    std::vector<Covered> covered();
    std::vector<Grant> grants();
    std::vector<Activity> activity();

    static std::wstring key(const std::wstring &path);
    static std::wstring ruleKey(const Rule &rule);
    // La clave de la app entera de esa identidad (sin destino).
    static std::wstring identityKey(const Rule &rule);
    // Destino en forma canónica, o vacío si no es válido.
    static std::wstring normalizeDestination(const std::wstring &destination);
    static std::wstring fileName(const std::wstring &path); // en minúsculas
    static std::int64_t now();

  private:
    void onDrop(const DropEvent &drop);
    void verifyLoop();
    // waited: el bloqueo ya esperó el nombre de su destino (nameWait_); no se vuelve a retener.
    void classify(const DropEvent &drop, const std::wstring &signer, bool waited = false);
    void classifyDestination(const DropEvent &drop, const std::wstring &cached, bool waited);
    // Historial de un permiso de destino recién puesto o refrescado: lo que quedó de verdad para esa IP. Con mutex_.
    void addGrantActivity(std::int64_t t, const std::wstring &path, const std::wstring &address, const Rule &rule,
                          const std::wstring &remote, std::uint16_t port, std::uint8_t protocol);
    void recheckCoverage(bool full);
    // Vuelve a decidir cada archivo cubierto por una carpeta con la precedencia entera: una regla de firma que coincide
    // (con la firma verificada de nuevo) u otra carpeta que gana (más profunda, la misma con el nombre del exe) pasa a
    // cubrirlo, con su acción; el modo por destino de su identidad le saca la cobertura (el próximo intento se decide
    // por destino). Hace E/S: sin mutex_, en el hilo de verificación.
    void reviewFolderCoverage();
    // Pide esa revisión al hilo de verificación (después de guardar una regla). Con o sin mutex_.
    void requestFolderReview();
    void expireRules();
    // Retira los filtros de la regla (o de sus coberturas) y la borra. Con mutex_ tomado.
    bool dropRule(std::map<std::wstring, Rule>::iterator it, const std::wstring &reason, std::wstring &error);
    std::wstring cachedSigner(const std::wstring &path);
    const Rule *signerRuleFor(const std::wstring &path, const std::wstring &signer) const;
    bool matches(const Rule &rule, const std::wstring &path, const std::wstring &signer) const;
    // La regla por carpeta de un archivo ya ubicado (placeOf), o nada. Con mutex_ tomado.
    const Rule *folderRuleFor(const FinalPath &place, const std::wstring &name) const;
    bool hasFolderRules() const;
    // Una cobertura sigue valiendo: el archivo sigue firmado por quien pide la regla, o sigue dentro de la carpeta. Hace
    // E/S (firma o ruta final): mejor sin mutex_.
    bool coverValid(const Rule &rule, const std::wstring &path) const;
    // Modo por destino. any: la app tiene alguna regla por destino. Devuelve la regla que corresponde a ese destino
    // (la más específica; a igual especificidad, Block), o nada.
    const Rule *destinationRuleFor(const std::wstring &path, const std::wstring &signer, const std::wstring &host,
                                   const std::wstring &address, bool &any) const;
    bool identityMatches(const Rule &rule, const std::wstring &path, const std::wstring &signer) const;
    bool decideDestination(const std::wstring &path, Action action, Scope scope, const std::wstring &destination,
                           std::int64_t expires, std::wstring &error);
    // Pone el permiso de destino de una app hacia una dirección. Con mutex_ tomado.
    // changed: si se puso o cambió un filtro (no sólo se refrescó el último uso).
    bool grant(const std::wstring &path, const std::wstring &address, const Rule &rule, const FileStamp &stamp,
               std::wstring &error, bool *changed = nullptr);
    void eraseGrantsOf(const std::wstring &ruleKey);
    // Quita las reglas por destino de una identidad (cuando se decide sobre la app entera). Con mutex_ tomado.
    void dropDestinationRulesOf(const std::wstring &identity);
    void erasePendingOf(const std::wstring &pathKey);
    void applyHint(const DnsHint &hint);
    void onResolved(const std::wstring &app, const std::wstring &host, const std::vector<std::wstring> &addresses);
    // Pone el filtro de una ruta por una regla de firma o de carpeta (una cobertura) y deja el historial. Con mutex_.
    bool coverWith(const DropEvent &drop, const Rule &rule, const FileStamp &stamp, std::wstring &error);
    bool applyAskFilters(std::wstring &error);
    bool removeAskFilters(std::wstring &error);
    bool installRule(Rule &rule, std::wstring &error);
    void addActivity(Activity a);
    void load();
    bool save(std::wstring &error);

    CoreOptions options_;
    WfpEngine wfp_;
    std::mutex mutex_;
    bool ask_ = true;
    bool localNetwork_ = true;
    std::vector<std::uint64_t> localFilters_;
    DnsNames dns_;
    std::int64_t started_ = 0;
    std::wstring lastError_;
    std::vector<std::uint64_t> askFilters_, systemFilters_;
    std::map<std::wstring, Rule> rules_;       // clave: ruta en minúsculas o ruleKey()
    std::map<std::wstring, Covered> covered_;  // clave: ruta en minúsculas
    std::map<std::wstring, Pending> pending_;  // clave: ruta en minúsculas (+ \x1f + dirección en modo por destino)
    std::map<std::wstring, Grant> grants_;     // clave: ruta en minúsculas + \x1f + dirección
    std::atomic<int> destinationRules_{0};     // cuántas reglas por destino hay (para ignorar el DNS si no hay)
    std::deque<Activity> activity_;

    // Los bloqueos sin regla de ruta pasan por un hilo propio: verificar la firma lleva tiempo y el aviso de WFP no
    // debe esperar ni agregar filtros desde su propio hilo.
    struct SignerCache {
        FILETIME written{};
        std::uint64_t size = 0;
        std::wstring signer;
    };
    std::mutex verifyMutex_;
    std::condition_variable verifyWake_;
    std::deque<DropEvent> verifyQueue_;
    std::deque<DnsHint> hintQueue_;
    bool verifyStop_ = false;
    bool reviewFolders_ = false; // protegido por verifyMutex_
    std::thread verifyThread_;
    int recheckRound_ = 0; // sólo lo usa el hilo de verificación
    bool reviewAgain_ = false; // ídem: la última revisión de carpetas no pudo ubicar algún archivo
    // Bloqueos en modo por destino que llegaron antes que su consulta DNS: esperan el nombre antes de preguntar.
    // Sólo lo usa el hilo de verificación.
    NameWait<DropEvent> nameWait_{std::chrono::seconds(2), 1000};
    std::map<std::wstring, SignerCache> signers_; // clave: ruta en minúsculas; protegido por verifyMutex_
};

} // namespace gbe
