#pragma once
// Núcleo del firewall: reglas guardadas, solicitudes pendientes e historial sobre el motor WFP.
// Una app sin regla queda bloqueada por el filtro por defecto; su bloqueo genera una solicitud pendiente.
// Allow o Block crea una regla persistente y el próximo intento de la app usa esa regla.
#include "wfp_engine.h"
#include <deque>
#include <map>
#include <string>
#include <vector>

namespace gbe {

struct Rule {
    std::wstring path;
    Action action = Action::Allow;
    std::int64_t created = 0;  // segundos Unix UTC
    std::int64_t lastBlock = 0; // último bloqueo atribuido a la regla (sólo reglas Block)
    std::vector<std::uint64_t> filters;
};

struct Pending {
    std::wstring path;
    std::int64_t first = 0, last = 0;
    std::uint32_t attempts = 0;
    std::wstring remoteAddress;
    std::uint16_t remotePort = 0;
    std::uint8_t protocol = 0;
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
};

class FirewallCore {
  public:
    explicit FirewallCore(CoreOptions options);
    ~FirewallCore();

    bool start(std::wstring &error);
    void stop();

    // Modo ask: lo desconocido se bloquea y se pregunta. Modo off: sin bloqueo por defecto (las reglas siguen).
    bool setAsk(bool ask, std::wstring &error);
    bool decide(const std::wstring &path, Action action, std::wstring &error);
    bool removeRule(const std::wstring &path, std::wstring &error);

    struct Status {
        bool ask = true, dynamic = false, allApps = true;
        std::int64_t started = 0;
        std::size_t pending = 0, rules = 0;
        std::wstring lastError;
    };
    Status status();
    std::vector<Pending> pending();
    std::vector<Rule> rules();
    std::vector<Activity> activity();

    static std::wstring key(const std::wstring &path);
    static std::int64_t now();

  private:
    void onDrop(const DropEvent &drop);
    bool applyAskFilters(std::wstring &error);
    bool removeAskFilters(std::wstring &error);
    bool installRule(Rule &rule, std::wstring &error);
    void addActivity(Activity a);
    bool load(std::wstring &error);
    bool save(std::wstring &error);

    CoreOptions options_;
    WfpEngine wfp_;
    std::mutex mutex_;
    bool ask_ = true;
    std::int64_t started_ = 0;
    std::wstring lastError_;
    std::vector<std::uint64_t> askFilters_, systemFilters_;
    std::map<std::wstring, Rule> rules_;       // clave: ruta en minúsculas
    std::map<std::wstring, Pending> pending_;  // clave: ruta en minúsculas
    std::deque<Activity> activity_;
};

} // namespace gbe
