// GateBouncerEngine.exe: el firewall sin driver.
//
//   --service                      lo usa Windows al arrancar el servicio LGAGateBouncer
//   --install [--ui <exe>]...      instala y arranca el servicio (administrador)
//   --uninstall                    detiene y borra el servicio, sus filtros y su proveedor (administrador)
//   --remove-filters               emergencia: borra todos los filtros propios y deja la red sin GateBouncer
//   --console [--dynamic] [--scope <exe>]... [--data <dir>] [--ui <exe>]... [--seconds <n>]
//                                  corre en primer plano (pruebas). --dynamic: nada sobrevive al cierre.
//                                  --scope: sólo esas apps quedan bajo «preguntar»; el resto de la PC no se toca.
#include "pipe_server.h"
#include <aclapi.h>
#include <shlobj.h>
#include <sddl.h>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <io.h>

#pragma comment(lib, "shell32.lib")

namespace {

constexpr wchar_t ServiceName[] = L"LGAGateBouncer";
SERVICE_STATUS_HANDLE serviceHandle = nullptr;
SERVICE_STATUS serviceStatus{};
HANDLE serviceStop = nullptr;

std::wstring moduleDir() {
    wchar_t path[MAX_PATH * 2] = {};
    GetModuleFileNameW(nullptr, path, DWORD(std::size(path)));
    std::wstring p = path;
    return p.substr(0, p.find_last_of(L'\\'));
}

std::wstring dataDir() {
    wchar_t *base = nullptr;
    std::wstring dir;
    // Un solo nivel bajo ProgramData: una carpeta intermedia creada por un usuario podría renombrar la nuestra.
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &base))) dir = std::wstring(base) + L"\\LGA GateBouncer";
    CoTaskMemFree(base);
    return dir;
}

// true si el dueño es SYSTEM, administradores o TrustedInstaller y nadie más tiene alguno de los permisos de writeMask.
bool privilegedOnly(const std::wstring &dir, DWORD writeMask, std::wstring &why) {
    const DWORD attributes = GetFileAttributesW(dir.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        why = dir + L" is not a plain folder";
        return false;
    }
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(dir.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                              &owner, nullptr, &dacl, nullptr, &sd) != ERROR_SUCCESS) {
        why = L"Cannot read the permissions of " + dir;
        return false;
    }
    PSID trustedInstaller = nullptr;
    ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &trustedInstaller);
    const auto privileged = [trustedInstaller](PSID sid) {
        return IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) ||
               (trustedInstaller && EqualSid(sid, trustedInstaller));
    };
    bool ok = owner && privileged(owner);
    if (!ok) why = dir + L" is not owned by SYSTEM or Administrators";
    for (DWORD i = 0; ok && dacl && i < dacl->AceCount; ++i) {
        ACE_HEADER *ace = nullptr;
        if (!GetAce(dacl, i, reinterpret_cast<void **>(&ace)) || ace->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        if (ace->AceFlags & INHERIT_ONLY_ACE) continue; // p. ej. CREATOR OWNER: no da acceso a la carpeta en sí
        auto *allowed = reinterpret_cast<ACCESS_ALLOWED_ACE *>(ace);
        if ((allowed->Mask & writeMask) && !privileged(&allowed->SidStart)) {
            ok = false;
            why = dir + L" can be changed by non-administrators";
        }
    }
    if (!dacl) {
        ok = false;
        why = dir + L" has no access list";
    }
    if (trustedInstaller) LocalFree(trustedInstaller);
    LocalFree(sd);
    return ok;
}

// true si sólo SYSTEM, administradores o TrustedInstaller pueden cambiar la carpeta, y nadie más puede reemplazarla
// desde arriba: en cada carpeta superior, un usuario común no puede borrar o renombrar lo que contiene ni tomar el
// control. Crear carpetas nuevas en ellas sí se acepta (ProgramData lo permite).
bool adminOnlyWritable(const std::wstring &dir, std::wstring &why) {
    constexpr DWORD writeMask = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_DELETE_CHILD |
                                FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
    if (!privilegedOnly(dir, writeMask, why)) return false;
    constexpr DWORD replaceMask = FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
    std::wstring parent = dir;
    for (;;) {
        while (!parent.empty() && (parent.back() == L'\\' || parent.back() == L'/')) parent.pop_back();
        const auto slash = parent.find_last_of(L"\\/");
        if (slash == std::wstring::npos) break;
        parent.erase(slash);
        // Raíz de la unidad: "C:" se consulta como "C:\".
        const std::wstring query = parent.size() == 2 && parent[1] == L':' ? parent + L"\\" : parent;
        if (!privilegedOnly(query, replaceMask, why)) return false;
        if (query.size() <= 3) break;
    }
    return true;
}

// Carpeta de datos: sólo SYSTEM y administradores. Si ya existe con otros permisos no se usa: podría tener reglas
// o clientes de confianza puestos por alguien sin permiso de administrador.
bool ensureDataDir(const std::wstring &dir, std::wstring &error) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1,
                                                         &sd, nullptr);
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
    const bool created = CreateDirectoryW(dir.c_str(), &sa) || GetLastError() == ERROR_ALREADY_EXISTS;
    if (!created) error = L"CreateDirectoryW " + dir + L": " + gbe::WfpEngine::errorText(GetLastError());
    LocalFree(sd);
    return created && adminOnlyWritable(dir, error);
}

std::vector<std::wstring> trustedClients(const std::wstring &dir) {
    std::vector<std::wstring> out{moduleDir() + L"\\GateBouncer.exe"};
    std::wifstream in(dir + L"\\ui.txt");
    std::wstring line;
    while (std::getline(in, line))
        if (!line.empty()) out.push_back(line);
    return out;
}

void setServiceState(DWORD state, DWORD exitCode = NO_ERROR) {
    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    serviceStatus.dwCurrentState = state;
    serviceStatus.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    serviceStatus.dwWin32ExitCode = exitCode;
    serviceStatus.dwWaitHint = state == SERVICE_RUNNING || state == SERVICE_STOPPED ? 0 : 10000;
    SetServiceStatus(serviceHandle, &serviceStatus);
}

DWORD WINAPI serviceControl(DWORD control, DWORD, void *, void *) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        setServiceState(SERVICE_STOP_PENDING);
        SetEvent(serviceStop);
    }
    return NO_ERROR;
}

void log(const std::wstring &dir, const std::wstring &text) {
    if (dir.empty()) return;
    std::wofstream out(dir + L"\\engine.log", std::ios::app);
    SYSTEMTIME t{};
    GetLocalTime(&t);
    wchar_t stamp[32];
    swprintf_s(stamp, L"%04d-%02d-%02d %02d:%02d:%02d ", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    out << stamp << text << L"\n";
}

void WINAPI serviceMain(DWORD, wchar_t **) {
    serviceHandle = RegisterServiceCtrlHandlerExW(ServiceName, serviceControl, nullptr);
    if (!serviceHandle) return;
    serviceStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    setServiceState(SERVICE_START_PENDING);
    std::wstring error;
    const std::wstring dir = dataDir();
    if (!ensureDataDir(dir, error)) {
        setServiceState(SERVICE_STOPPED, ERROR_ACCESS_DENIED);
        return;
    }
    gbe::CoreOptions options;
    options.dataDir = dir;
    gbe::FirewallCore core(options);
    if (!core.start(error)) {
        log(dir, L"No arrancó: " + error);
        setServiceState(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
        return;
    }
    gbe::PipeServer server(core, trustedClients(dir));
    if (!server.start(error)) log(dir, L"Sin canal con la ventana: " + error);
    const std::wstring warning = core.status().lastError;
    log(dir, warning.empty() ? L"Motor activo" : L"Motor activo. Aviso: " + warning);
    setServiceState(SERVICE_RUNNING);
    WaitForSingleObject(serviceStop, INFINITE);
    server.stop();
    // Los filtros persistentes quedan: con el servicio detenido lo desconocido sigue bloqueado y las reglas valen.
    core.stop();
    log(dir, L"Motor detenido");
    setServiceState(SERVICE_STOPPED);
}

int install(const std::vector<std::wstring> &uiPaths, bool allowUnprotected) {
    std::wstring error;
    // El servicio corre como SYSTEM y confía en la ventana de su carpeta: si un usuario común pudiera cambiar esos
    // archivos, tendría SYSTEM o reglas a voluntad.
    std::vector<std::wstring> folders{moduleDir()};
    for (const auto &p : uiPaths) folders.push_back(p.substr(0, p.find_last_of(L'\\')));
    for (const auto &folder : folders) {
        std::wstring why;
        if (!adminOnlyWritable(folder, why)) {
            if (!allowUnprotected) {
                fwprintf(stderr,
                         L"%ls.\nCopy GateBouncer to a folder only administrators can change, such as "
                         L"C:\\Program Files\\LGA GateBouncer, or add --allow-unprotected-folder to accept the risk.\n",
                         why.c_str());
                return 1;
            }
            fwprintf(stderr, L"Warning: %ls.\n", why.c_str());
        }
    }
    const std::wstring dir = dataDir();
    if (!ensureDataDir(dir, error)) {
        fwprintf(stderr, L"%ls\n", error.c_str());
        return 1;
    }
    if (!uiPaths.empty()) {
        std::wofstream out(dir + L"\\ui.txt", std::ios::trunc);
        for (const auto &p : uiPaths) out << p << L"\n";
    }
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        fwprintf(stderr, L"OpenSCManager: %ls\n", gbe::WfpEngine::errorText(GetLastError()).c_str());
        return 1;
    }
    wchar_t exe[MAX_PATH * 2] = {};
    GetModuleFileNameW(nullptr, exe, DWORD(std::size(exe)));
    const std::wstring command = L"\"" + std::wstring(exe) + L"\" --service";
    SC_HANDLE service = CreateServiceW(scm, ServiceName, L"LGA GateBouncer", SERVICE_ALL_ACCESS,
                                       SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                       command.c_str(), nullptr, nullptr, L"BFE\0\0", nullptr, nullptr);
    if (!service && GetLastError() == ERROR_SERVICE_EXISTS) service = OpenServiceW(scm, ServiceName, SERVICE_ALL_ACCESS);
    if (!service) {
        fwprintf(stderr, L"CreateService: %ls\n", gbe::WfpEngine::errorText(GetLastError()).c_str());
        CloseServiceHandle(scm);
        return 1;
    }
    SERVICE_DESCRIPTIONW description{const_cast<wchar_t *>(L"Per-application firewall: asks before unknown applications connect.")};
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description);
    const bool started = StartServiceW(service, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
    if (!started) fwprintf(stderr, L"StartService: %ls\n", gbe::WfpEngine::errorText(GetLastError()).c_str());
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    wprintf(started ? L"Service installed and running.\n" : L"Service installed, but it did not start.\n");
    return started ? 0 : 1;
}

int removeFilters(bool deleteObjects) {
    gbe::WfpEngine wfp;
    std::wstring error;
    bool ok = wfp.open(false, error) && (deleteObjects ? wfp.removeObjects(error) : wfp.removeAllOwnFilters(error));
    if (!ok) fwprintf(stderr, L"%ls\n", error.c_str());
    return ok ? 0 : 1;
}

int uninstall() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE service = OpenServiceW(scm, ServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
        if (service) {
            SERVICE_STATUS s{};
            ControlService(service, SERVICE_CONTROL_STOP, &s);
            bool stopped = false;
            for (int i = 0; i < 300; ++i) {
                stopped = QueryServiceStatus(service, &s) && s.dwCurrentState == SERVICE_STOPPED;
                if (stopped) break;
                Sleep(100);
            }
            // Con el servicio vivo no se tocan los filtros: podría volver a crearlos sin nadie que los administre.
            if (!stopped) {
                fwprintf(stderr, L"The service did not stop. Nothing was removed. Use --remove-filters to restore "
                                 L"network access now, then try again.\n");
                CloseServiceHandle(service);
                CloseServiceHandle(scm);
                return 1;
            }
            DeleteService(service);
            CloseServiceHandle(service);
        }
        CloseServiceHandle(scm);
    }
    const int r = removeFilters(true);
    wprintf(r == 0 ? L"Service and filters removed. Saved rules stay in ProgramData.\n"
                   : L"Not every filter could be removed.\n");
    return r;
}

HANDLE consoleStop = nullptr;
BOOL WINAPI consoleHandler(DWORD) {
    SetEvent(consoleStop);
    return TRUE;
}

int console(int argc, wchar_t **argv) {
    gbe::CoreOptions options;
    std::vector<std::wstring> ui;
    DWORD seconds = INFINITE;
    for (int i = 2; i < argc; ++i) {
        const std::wstring a = argv[i];
        const bool hasValue = i + 1 < argc;
        if (a == L"--dynamic") options.dynamic = true;
        else if (a == L"--scope" && hasValue) options.scope.push_back(argv[++i]);
        else if (a == L"--data" && hasValue) options.dataDir = argv[++i];
        else if (a == L"--ui" && hasValue) ui.push_back(argv[++i]);
        else if (a == L"--seconds" && hasValue) seconds = DWORD(_wtoi(argv[++i]));
        else {
            fwprintf(stderr, L"Unknown argument: %ls\n", a.c_str());
            return 2;
        }
    }
    if (!options.dynamic && !options.scope.empty()) {
        fwprintf(stderr, L"--scope requires --dynamic.\n");
        return 2;
    }
    std::wstring error;
    if (!options.dataDir.empty() && !CreateDirectoryW(options.dataDir.c_str(), nullptr) &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        fwprintf(stderr, L"Cannot create %ls\n", options.dataDir.c_str());
        return 1;
    }
    gbe::FirewallCore core(options);
    if (!core.start(error)) {
        fwprintf(stderr, L"Could not start: %ls\n", error.c_str());
        return 1;
    }
    gbe::PipeServer server(core, ui);
    if (!server.start(error)) {
        fwprintf(stderr, L"No local channel: %ls\n", error.c_str());
        return 1;
    }
    consoleStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(consoleHandler, TRUE);
    wprintf(L"Engine running%ls. Channel: %ls\n", options.dynamic ? L" (dynamic session)" : L"", gbe::PipeName);
    const std::wstring warning = core.status().lastError;
    if (!warning.empty()) wprintf(L"Warning: %ls\n", warning.c_str());
    fflush(stdout);
    WaitForSingleObject(consoleStop, seconds == 0 ? INFINITE : seconds * 1000);
    server.stop();
    core.stop();
    wprintf(L"Engine stopped.\n");
    return 0;
}

} // namespace

int wmain(int argc, wchar_t **argv) {
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stderr), _O_U8TEXT);
    const std::wstring mode = argc > 1 ? argv[1] : L"";
    if (mode == L"--service") {
        SERVICE_TABLE_ENTRYW table[] = {{const_cast<wchar_t *>(ServiceName), serviceMain}, {nullptr, nullptr}};
        return StartServiceCtrlDispatcherW(table) ? 0 : 1;
    }
    if (mode == L"--install") {
        std::vector<std::wstring> ui;
        bool allowUnprotected = false;
        for (int i = 2; i < argc; ++i) {
            const std::wstring a = argv[i];
            if (a == L"--ui" && i + 1 < argc) ui.push_back(argv[++i]);
            else if (a == L"--allow-unprotected-folder") allowUnprotected = true;
            else {
                fwprintf(stderr, L"Unknown argument: %ls\n", a.c_str());
                return 2;
            }
        }
        return install(ui, allowUnprotected);
    }
    if (mode == L"--uninstall") return uninstall();
    if (mode == L"--remove-filters") return removeFilters(false);
    if (mode == L"--console") return console(argc, argv);
    fwprintf(stderr, L"Usage: GateBouncerEngine.exe --install [--ui <exe>] [--allow-unprotected-folder] | --uninstall | "
                     L"--remove-filters | --console ...\n");
    return 2;
}
