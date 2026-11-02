#pragma once
// Núcleo del firewall: reglas guardadas, solicitudes pendientes e historial sobre el motor WFP.
// Una app sin regla queda bloqueada por el filtro por defecto; su bloqueo genera una solicitud pendiente.
// Allow o Block crea una regla persistente y el próximo intento de la app usa esa regla.
//
// Tres alcances de regla:
//  - Path: la ruta exacta del ejecutable (WFP filtra así).
//  - App: editor firmado + nombre del ejecutable, en cualquier carpeta («any version»).
//  - Publisher: todo ejecutable firmado por ese editor.
// WFP no sabe de firmas: las reglas App y Publisher viven en el motor. Cuando una app sin regla de ruta se bloquea,
// el motor verifica su firma y, si coincide con una de esas reglas, agrega el filtro de esa ruta (una «cobertura»).
// El primer intento igual se pierde; el siguiente pasa sin preguntar.
#include "dns_names.h"
#include "wfp_engine.h"
#include <condition_variable>
#include <deque>
#include <map>
#include <string>
#include <thread>
#include <vector>

namespace gbe {

enum class Scope { Path, App, Publisher };

struct Rule {
    Scope scope = Scope::Path;
    std::wstring path;          // Path: la ruta; App/Publisher: vacío
    std::wstring signer;        // App/Publisher: el firmante tal como lo muestra Windows
    std::wstring name;          // App: nombre del ejecutable en minúsculas
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
    bool decide(const std::wstring &path, Action action, Scope scope, std::wstring &error, std::int64_t expires = 0);
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
    std::vector<Activity> activity();

    static std::wstring key(const std::wstring &path);
    static std::wstring ruleKey(const Rule &rule);
    static std::wstring fileName(const std::wstring &path); // en minúsculas
    static std::int64_t now();

  private:
    void onDrop(const DropEvent &drop);
    void verifyLoop();
    void classify(const DropEvent &drop, const std::wstring &signer);
    void recheckCoverage(bool full);
    void expireRules();
    // Retira los filtros de la regla (o de sus coberturas) y la borra. Con mutex_ tomado.
    bool dropRule(std::map<std::wstring, Rule>::iterator it, const std::wstring &reason, std::wstring &error);
    std::wstring cachedSigner(const std::wstring &path);
    const Rule *signerRuleFor(const std::wstring &path, const std::wstring &signer) const;
    bool matches(const Rule &rule, const std::wstring &path, const std::wstring &signer) const;
    bool cover(const std::wstring &path, const std::wstring &ruleKey, Action action, std::wstring &error);
    void uncover(const std::wstring &pathKey);
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
    std::map<std::wstring, Pending> pending_;  // clave: ruta en minúsculas
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
    bool verifyStop_ = false;
    std::thread verifyThread_;
    int recheckRound_ = 0; // sólo lo usa el hilo de verificación
    std::map<std::wstring, SignerCache> signers_; // clave: ruta en minúsculas; protegido por verifyMutex_
};

} // namespace gbe
