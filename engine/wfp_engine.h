#pragma once
// Motor de firewall sin driver: sólo la API de administración de WFP (fwpuclnt) desde modo usuario.
// Bloquea o permite por ejecutable en las capas ALE y avisa cada bloqueo propio por eventos de red.
// No retiene conexiones: el primer intento de una app sin regla se bloquea y el siguiente usa la regla nueva.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>
#include <cstdint>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace gbe {

enum class Action { Allow, Block };
enum class Direction { Outbound, Inbound, Both };

// Un bloqueo propio informado por WFP.
struct DropEvent {
    std::wstring appPath;      // ruta DOS cuando se puede traducir, si no la ruta de dispositivo
    std::wstring remoteAddress;
    std::uint16_t remotePort = 0;
    std::uint16_t localPort = 0;
    std::uint8_t protocol = 0;
    bool inbound = false;
    std::uint64_t filterId = 0;
    FILETIME time{};
};

class WfpEngine {
  public:
    using DropCallback = std::function<void(const DropEvent &)>;

    WfpEngine() = default;
    ~WfpEngine();
    WfpEngine(const WfpEngine &) = delete;
    WfpEngine &operator=(const WfpEngine &) = delete;

    // dynamic=true: todo lo que se agregue desaparece al cerrar la sesión (pruebas seguras).
    bool open(bool dynamic, std::wstring &error);
    void close();
    bool isOpen() const { return engine_ != nullptr; }
    bool dynamic() const { return dynamic_; }

    // Transacciones de WFP anidables: sólo la más externa confirma o aborta de verdad.
    bool begin(std::wstring &error);
    bool commit(std::wstring &error);
    void abort();

    // Proveedor y subcapa propios; idempotente.
    bool ensureObjects(std::wstring &error);

    // Filtro por ejecutable. Devuelve los ids de WFP creados (uno por capa).
    bool addAppFilter(const std::wstring &path, Action action, Direction direction, std::uint8_t weight,
                      std::vector<std::uint64_t> &ids, std::wstring &error);
    // Filtro sin condición de app: bloquea todo lo que no tenga una regla de peso mayor.
    bool addDefaultBlock(Direction direction, std::vector<std::uint64_t> &ids, std::wstring &error);
    // Permisos de base para que el bloqueo por defecto no rompa la PC: loopback y servicios del sistema.
    bool addSystemAllowances(std::vector<std::uint64_t> &ids, std::wstring &error);
    // La ventana de GateBouncer sale sólo por TCP 443 (las explicaciones con IA): HTTPS y nada más.
    bool addHttpsPermit(const std::wstring &path, std::vector<std::uint64_t> &ids, std::wstring &error);
    bool removeFilter(std::uint64_t id);
    // Borra todos los filtros del proveedor propio (desinstalar o reconstruir).
    bool removeAllOwnFilters(std::wstring &error);
    // Desinstalar: filtros, subcapa y proveedor propios.
    bool removeObjects(std::wstring &error);

    // Avisos de bloqueo. Sólo se informan los bloqueos hechos por filtros propios.
    bool subscribeDrops(DropCallback callback, std::wstring &error);
    void unsubscribe();
    void trackOwnFilters(const std::vector<std::uint64_t> &ids);
    void untrackOwnFilter(std::uint64_t id);

    static std::wstring devicePathToDos(const std::wstring &devicePath);
    static std::wstring withRealCase(const std::wstring &path);
    static std::wstring errorText(DWORD code);

  private:
    static void CALLBACK onEvent(void *context, const FWPM_NET_EVENT1 *event);
    bool addFilter(const GUID &layer, const wchar_t *name, FWP_ACTION_TYPE action, std::uint8_t weight,
                   FWPM_FILTER_CONDITION0 *conditions, UINT32 count, std::uint64_t &id, std::wstring &error);

    HANDLE engine_ = nullptr;
    HANDLE subscription_ = nullptr;
    bool dynamic_ = false;
    bool restoreCollection_ = false;
    int txnDepth_ = 0;
    bool txnFailed_ = false;
    // Filtros borrados dentro de la transacción abierta: dejan de contarse como propios recién al confirmarla.
    std::vector<std::uint64_t> untrackOnCommit_;
    DropCallback callback_;
    std::mutex mutex_;
    std::set<std::uint64_t> ownFilters_;
};

} // namespace gbe
