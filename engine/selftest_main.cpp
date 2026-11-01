// Autoprueba real del motor sin driver, acotada y reversible.
// Usa una sesión WFP dinámica (todo se borra al cerrar) y filtros sólo para una COPIA de un cliente HTTP:
// el resto de la PC no se toca. Requiere administrador.
//
//   GateBouncerEngineSelfTest.exe <cliente_copia.exe> <cliente_sistema.exe> <url>
//
// Pasos: base sin filtros; «pendiente» (bloqueo de peso bajo) con aviso de bloqueo; Allow que le gana;
// Block explícito que le gana al Allow; cierre de sesión que borra todo.
#include "wfp_engine.h"
#include <condition_variable>
#include <fcntl.h>
#include <io.h>
#include <cstdio>
#include <string>
#include <vector>

namespace {

std::mutex eventsMutex;
std::condition_variable eventsChanged;
std::vector<gbe::DropEvent> events;
int failures = 0;

void report(const wchar_t *step, bool ok, const std::wstring &detail = L"") {
    if (!ok) ++failures;
    wprintf(L"%-58ls %ls%ls%ls\n", step, ok ? L"OK" : L"FALLA", detail.empty() ? L"" : L" — ", detail.c_str());
    fflush(stdout);
}

// Corre el cliente HTTP y devuelve su código de salida (0 = conectó; 7 = no pudo conectar).
DWORD runClient(const std::wstring &exe, const std::wstring &url) {
    std::wstring command = L"\"" + exe + L"\" -s -o NUL --max-time 8 " + url;
    STARTUPINFOW si{sizeof(si)};
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si,
                        &pi))
        return 0xFFFFFFFF;
    WaitForSingleObject(pi.hProcess, 20000);
    DWORD code = 0xFFFFFFFE;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code;
}

bool waitDropFor(const std::wstring &path, std::size_t from, DWORD ms, gbe::DropEvent &found) {
    std::unique_lock<std::mutex> lock(eventsMutex);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    for (;;) {
        for (std::size_t i = from; i < events.size(); ++i)
            if (_wcsicmp(events[i].appPath.c_str(), path.c_str()) == 0) {
                found = events[i];
                return true;
            }
        if (eventsChanged.wait_until(lock, deadline) == std::cv_status::timeout) return false;
    }
}

std::wstring code(DWORD c) { return L"código " + std::to_wstring(c); }

} // namespace

int wmain(int argc, wchar_t **argv) {
    if (argc != 4) {
        fwprintf(stderr, L"Uso: GateBouncerEngineSelfTest.exe <cliente_copia.exe> <cliente_sistema.exe> <url>\n");
        return 2;
    }
    _setmode(_fileno(stdout), _O_U8TEXT);
    const std::wstring client = argv[1], systemClient = argv[2], url = argv[3];

    DWORD c = runClient(client, url);
    report(L"1. Sin filtros: la copia del cliente conecta", c == 0, code(c));
    c = runClient(systemClient, url);
    report(L"1. Sin filtros: el cliente del sistema conecta", c == 0, code(c));

    gbe::WfpEngine engine;
    std::wstring error;
    bool ok = engine.open(true, error) && engine.ensureObjects(error);
    report(L"2. Sesión WFP dinámica, proveedor y subcapa", ok, error);
    if (!ok) return 1;
    ok = engine.subscribeDrops(
        [](const gbe::DropEvent &e) {
            std::lock_guard<std::mutex> lock(eventsMutex);
            events.push_back(e);
            eventsChanged.notify_all();
        },
        error);
    report(L"2. Suscripción a avisos de bloqueo", ok, error);

    // Permisos de base del modo producto (sólo permiten; sin el bloqueo general no cambian nada en la PC).
    std::vector<std::uint64_t> baseIds;
    ok = engine.addSystemAllowances(baseIds, error);
    report(L"2. Permisos de base: loopback y servicios de Windows", ok && baseIds.size() == 6,
           ok ? std::to_wstring(baseIds.size()) + L" filtros" : error);
    c = runClient(systemClient, url);
    report(L"2. Con los permisos de base, el cliente del sistema conecta", c == 0, code(c));

    // «Pendiente»: lo que en el producto hace el bloqueo por defecto, acotado a la copia del cliente.
    std::vector<std::uint64_t> askIds;
    ok = engine.addAppFilter(client, gbe::Action::Block, gbe::Direction::Outbound, 1, askIds, error);
    report(L"3. Bloqueo por defecto acotado a la copia", ok, error);
    c = runClient(client, url);
    report(L"3. La copia NO conecta", c != 0, code(c));
    c = runClient(systemClient, url);
    report(L"3. El cliente del sistema sigue conectando", c == 0, code(c));
    gbe::DropEvent drop;
    const bool got = waitDropFor(client, 0, 15000, drop);
    report(L"3. Llega el aviso de bloqueo con la ruta de la copia", got,
           got ? drop.appPath + L" → " + drop.remoteAddress + L":" + std::to_wstring(drop.remotePort) +
                     L" proto " + std::to_wstring(drop.protocol)
               : L"sin evento en 15 s");

    std::vector<std::uint64_t> allowIds;
    ok = engine.addAppFilter(client, gbe::Action::Allow, gbe::Direction::Outbound, 10, allowIds, error);
    report(L"4. Allow de la copia (peso mayor que el bloqueo)", ok, error);
    c = runClient(client, url);
    report(L"4. Con Allow, el siguiente intento conecta", c == 0, code(c));

    std::size_t before = 0;
    {
        std::lock_guard<std::mutex> lock(eventsMutex);
        before = events.size();
    }
    std::vector<std::uint64_t> blockIds;
    ok = engine.addAppFilter(client, gbe::Action::Block, gbe::Direction::Outbound, 15, blockIds, error);
    report(L"5. Block explícito (le gana al Allow)", ok, error);
    c = runClient(client, url);
    report(L"5. Con Block, la copia NO conecta", c != 0, code(c));
    const bool got2 = waitDropFor(client, before, 15000, drop);
    report(L"5. Aviso del bloqueo explícito", got2, got2 ? L"filtro " + std::to_wstring(drop.filterId) : L"sin evento");

    for (auto id : blockIds) engine.removeFilter(id);
    c = runClient(client, url);
    report(L"6. Quitado el Block, vuelve a valer el Allow", c == 0, code(c));

    engine.close();
    c = runClient(client, url);
    report(L"7. Sesión cerrada: la copia conecta (filtros borrados)", c == 0, code(c));

    gbe::WfpEngine check;
    if (check.open(false, error)) {
        // Si el proveedor dinámico siguiera vivo, ensureObjects devolvería ALREADY_EXISTS; se busca directo.
        HANDLE raw = nullptr;
        FWPM_SESSION0 s{};
        FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &s, &raw);
        FWPM_PROVIDER0 *p = nullptr;
        const GUID key = {0x5b1d6a2e, 0x3c47, 0x4e1f, {0x9a, 0x61, 0x2d, 0x8e, 0x77, 0x40, 0xc3, 0x15}};
        const DWORD r = FwpmProviderGetByKey0(raw, &key, &p);
        if (p) FwpmFreeMemory0(reinterpret_cast<void **>(&p));
        FwpmEngineClose0(raw);
        report(L"7. No queda el proveedor propio en WFP", r == FWP_E_PROVIDER_NOT_FOUND, gbe::WfpEngine::errorText(r));
    }

    wprintf(L"\nResultado: %ls (%d fallas)\n", failures ? L"FALLA" : L"OK", failures);
    return failures ? 1 : 0;
}
