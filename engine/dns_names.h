#pragma once
// Nombres de los destinos. El motor escucha las consultas DNS que hacen las apps (proveedor ETW
// Microsoft-Windows-DNS-Client) y anota qué nombre resolvió cada una y qué direcciones recibió. Así el aviso puede
// decir «settings-win.data.microsoft.com» y no sólo una IP. No genera tráfico ni consulta a nadie: sólo escucha lo que
// las apps ya preguntaron. Una app que se conecta directo a una IP, o que resuelve por su cuenta (DNS sobre HTTPS),
// queda sin nombre.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <evntcons.h>
#include <evntrace.h>
#include <atomic>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <thread>

namespace gbe {

// Las sesiones ETW de las pruebas llevan el PID del motor detrás de este prefijo.
constexpr wchar_t TestSessionPrefix[] = L"LGA GateBouncer DNS test ";

class DnsNames {
  public:
    DnsNames() = default;
    ~DnsNames();
    DnsNames(const DnsNames &) = delete;
    DnsNames &operator=(const DnsNames &) = delete;

    // sessionName distinto para el servicio y para cada motor de prueba (TestSessionPrefix + PID): dos sesiones ETW con
    // el mismo nombre se pisan. Al arrancar se detienen las de prueba cuyo motor ya no existe.
    bool start(const std::wstring &sessionName, std::wstring &error);
    void stop();

    // El nombre que esa misma app resolvió para esa dirección en las últimas horas. Vacío si no se sabe: nunca el de
    // otra app. appKey: la ruta del ejecutable en minúsculas.
    std::wstring nameFor(const std::wstring &address, const std::wstring &appKey);

    // Dirección en texto normalizado (IPv4 mapeada en IPv6 queda como IPv4). Vacío si no es una dirección.
    static std::wstring normalize(const std::wstring &address);
    // Contadores para diagnóstico: eventos recibidos, consultas terminadas, ilegibles, guardadas y direcciones.
    std::wstring stats();

  private:
    static void WINAPI onRecord(PEVENT_RECORD record);
    void handle(PEVENT_RECORD record);
    std::wstring imageOf(DWORD pid);
    static void stopOrphanTestSessions();

    struct Entry {
        std::wstring name, app;
        ULONGLONG tick = 0;
    };
    std::mutex mutex_;
    std::map<std::wstring, std::deque<Entry>> byAddress_;
    // Sólo lo usa el hilo de ETW: ruta de cada proceso, para no abrirlo en cada consulta.
    std::map<DWORD, std::pair<std::wstring, ULONGLONG>> images_;
    std::atomic<std::uint64_t> events_{0}, completed_{0}, unreadable_{0}, stored_{0};
    std::atomic<bool> listening_{false};
    bool processStarts_ = false;
    ULONGLONG lastPrune_ = 0; // protegido por mutex_
    std::wstring sessionName_;
    TRACEHANDLE session_ = 0;
    TRACEHANDLE trace_ = INVALID_PROCESSTRACE_HANDLE;
    std::thread thread_;
};

} // namespace gbe
