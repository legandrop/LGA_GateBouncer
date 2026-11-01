// GateBouncerEngine.exe: el firewall sin driver.
//
//   --service                      lo usa Windows al arrancar el servicio LGAGateBouncer
//   --install [--ui <exe>]...      instala y arranca el servicio (administrador)
//   --uninstall                    detiene y borra el servicio, sus filtros y su proveedor (administrador)
//   --remove-filters               emergencia: borra todos los filtros propios y deja la red sin GateBouncer
//   --update <carpeta>             actualiza la instalación con los archivos de esa carpeta (administrador)
//   --send <campo>...              un pedido por el canal del servicio (DECIDE, REMOVE, MODE elevado; STATUS...)
//   --console [--dynamic] [--scope <exe>]... [--data <dir>] [--ui <exe>]... [--seconds <n>] [--pipe <nombre>]
//                                  corre en primer plano (pruebas). --dynamic: nada sobrevive al cierre.
//                                  --scope: sólo esas apps quedan bajo «preguntar»; el resto de la PC no se toca.
//   --signer <exe>                 muestra el firmante que usan las reglas por editor (no hace falta administrador)
#include "pipe_server.h"
#include "signature.h"
#include <aclapi.h>
#include <shlobj.h>
#include <sddl.h>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <io.h>
#include <vector>

#pragma comment(lib, "shell32.lib")

namespace {

constexpr wchar_t ServiceName[] = L"LGAGateBouncer";
// La ventana arranca con cada inicio de sesión: sin ella nadie ve los avisos (el servicio no tiene escritorio).
constexpr wchar_t RunKey[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t RunValue[] = L"LGA GateBouncer";
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
    options.windows = trustedClients(dir);
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
    bool protectedFolders = true;
    for (const auto &folder : folders) {
        std::wstring why;
        if (!adminOnlyWritable(folder, why)) {
            protectedFolders = false;
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
    // Para todos los usuarios (HKLM), y sólo desde una carpeta de administradores: si un usuario común pudiera cambiar
    // el exe, correría en el inicio de sesión de todos, administradores incluidos.
    const std::wstring window = uiPaths.empty() ? moduleDir() + L"\\GateBouncer.exe" : uiPaths.front();
    if (!protectedFolders) {
        fwprintf(stderr, L"The window was not registered at sign-in because its folder is not protected. Start "
                         L"GateBouncer.exe yourself to see requests.\n");
    } else if (GetFileAttributesW(window.c_str()) != INVALID_FILE_ATTRIBUTES) {
        const std::wstring run = L"\"" + window + L"\" --start-minimized";
        const LONG r = RegSetKeyValueW(HKEY_LOCAL_MACHINE, RunKey, RunValue, REG_SZ, run.c_str(),
                                       DWORD((run.size() + 1) * sizeof(wchar_t)));
        if (r == ERROR_SUCCESS) wprintf(L"GateBouncer window starts at sign-in, minimized to the tray.\n");
        else fwprintf(stderr, L"Could not register the window at sign-in: %ls\n", gbe::WfpEngine::errorText(r).c_str());
    } else {
        fwprintf(stderr, L"%ls not found: the window will not start at sign-in.\n", window.c_str());
    }
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
    const LONG run = RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, RunKey, RunValue);
    if (run != ERROR_SUCCESS && run != ERROR_FILE_NOT_FOUND)
        fwprintf(stderr, L"Could not remove the sign-in entry: %ls\n", gbe::WfpEngine::errorText(run).c_str());
    const int r = removeFilters(true);
    wprintf(r == 0 ? L"Service and filters removed. Saved rules stay in ProgramData.\n"
                   : L"Not every filter could be removed.\n");
    return r;
}

// Carpeta de la instalación: la del ejecutable que el servicio arranca.
std::wstring installedDir(SC_HANDLE service) {
    DWORD size = 0;
    QueryServiceConfigW(service, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    auto *config = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(buffer.data());
    if (!size || !QueryServiceConfigW(service, config, size, &size)) return {};
    std::wstring command = config->lpBinaryPathName;
    if (!command.empty() && command[0] == L'"') command = command.substr(1, command.find(L'"', 1) - 1);
    return command.substr(0, command.find_last_of(L'\\'));
}

bool waitFor(SC_HANDLE service, DWORD state) {
    SERVICE_STATUS s{};
    for (int i = 0; i < 300; ++i) {
        if (QueryServiceStatus(service, &s) && s.dwCurrentState == state) return true;
        Sleep(100);
    }
    return false;
}

// Copia el árbol de una carpeta. Un archivo en uso (la ventana abierta) se renombra a .old y se reemplaza: la ventana
// sigue con el viejo hasta que se reinicia. Los .old de una actualización anterior se borran si ya nadie los usa.
bool copyTree(const std::wstring &from, const std::wstring &to, std::wstring &error) {
    CreateDirectoryW(to.c_str(), nullptr);
    WIN32_FIND_DATAW item{};
    HANDLE find = FindFirstFileW((from + L"\\*").c_str(), &item);
    if (find == INVALID_HANDLE_VALUE) {
        error = L"Cannot read " + from;
        return false;
    }
    bool ok = true;
    do {
        const std::wstring name = item.cFileName;
        if (name == L"." || name == L"..") continue;
        if (item.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        const std::wstring source = from + L"\\" + name, target = to + L"\\" + name;
        if (item.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ok = copyTree(source, target, error);
            continue;
        }
        if (name.size() > 4 && (name.rfind(L".old") == name.size() - 4 || name.rfind(L".new") == name.size() - 4)) continue;
        DeleteFileW((target + L".old").c_str());
        // Igual tamaño y fecha: es el mismo archivo (las DLL de Qt casi nunca cambian) y no se toca.
        WIN32_FILE_ATTRIBUTE_DATA current{};
        if (GetFileAttributesExW(target.c_str(), GetFileExInfoStandard, &current) &&
            current.nFileSizeLow == item.nFileSizeLow && current.nFileSizeHigh == item.nFileSizeHigh &&
            CompareFileTime(&current.ftLastWriteTime, &item.ftLastWriteTime) == 0)
            continue;
        // Primero a un .new al lado y después un renombre: una copia cortada (disco lleno, antivirus) nunca deja un
        // ejecutable a medias en su lugar. Si el destino está en uso, el viejo pasa a .old y el nuevo toma su nombre.
        const std::wstring fresh = target + L".new";
        const bool copied = CopyFileW(source.c_str(), fresh.c_str(), FALSE);
        bool placed =
            copied && MoveFileExW(fresh.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        // El plan B sólo con una copia completa: un .new a medias nunca toma el lugar del exe.
        if (!placed && copied &&
            MoveFileExW(target.c_str(), (target + L".old").c_str(), MOVEFILE_REPLACE_EXISTING)) {
            placed = MoveFileExW(fresh.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH);
            if (!placed) MoveFileExW((target + L".old").c_str(), target.c_str(), 0);  // devuelve el viejo
        }
        if (!placed) {
            error = L"Cannot copy " + name + L": " + gbe::WfpEngine::errorText(GetLastError());
            DeleteFileW(fresh.c_str());
            ok = false;
        }
    } while (ok && FindNextFileW(find, &item));
    FindClose(find);
    return ok;
}

// Actualiza una instalación existente con los archivos de otra carpeta: detiene el servicio, copia y lo vuelve a
// arrancar. Las reglas no se tocan. Mientras está detenido, los filtros persistentes siguen: nada desconocido pasa.
int update(const std::wstring &from) {
    const DWORD a = GetFileAttributesW((from + L"\\GateBouncerEngine.exe").c_str());
    if (a == INVALID_FILE_ATTRIBUTES || GetFileAttributesW((from + L"\\GateBouncer.exe").c_str()) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"%ls does not contain GateBouncerEngine.exe and GateBouncer.exe.\n", from.c_str());
        return 2;
    }
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    SC_HANDLE service = scm ? OpenServiceW(scm, ServiceName, SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS |
                                                                 SERVICE_QUERY_CONFIG)
                            : nullptr;
    if (!service) {
        fwprintf(stderr, L"GateBouncer is not installed. Use --install.\n");
        if (scm) CloseServiceHandle(scm);
        return 1;
    }
    const std::wstring to = installedDir(service);
    std::wstring error;
    if (to.empty() || !adminOnlyWritable(to, error)) {
        fwprintf(stderr, L"The installation folder is not protected: %ls\n", error.c_str());
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    SERVICE_STATUS s{};
    ControlService(service, SERVICE_CONTROL_STOP, &s);
    if (!waitFor(service, SERVICE_STOPPED)) {
        fwprintf(stderr, L"The service did not stop. Nothing was copied.\n");
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    const bool copied = copyTree(from, to, error);
    if (!copied) fwprintf(stderr, L"%ls\n", error.c_str());
    // Arranca igual: con los archivos nuevos o, si la copia falló a medias, con lo que haya.
    const bool started = StartServiceW(service, 0, nullptr) && waitFor(service, SERVICE_RUNNING);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    wprintf(L"%ls %ls\n", copied ? L"Updated" : L"Update incomplete:", to.c_str());
    wprintf(started ? L"Service running.\n" : L"The service did not start. Use emergencia.ps1 or --remove-filters.\n");
    return copied && started ? 0 : 1;
}

// Un pedido por el canal del servicio, con los campos unidos por tabulaciones; muestra la respuesta. Elevado, el canal
// lo deja cambiar reglas (pruebas y administración sin abrir la ventana).
int send(int argc, wchar_t **argv) {
    std::string line;
    for (int i = 2; i < argc; ++i) {
        const int n = WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, nullptr, 0, nullptr, nullptr);
        std::string field(std::size_t(n > 0 ? n - 1 : 0), '\0');
        if (n > 1) WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, field.data(), n, nullptr, nullptr);
        line += (i > 2 ? "\t" : "") + field;
    }
    line += "\n";
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 50 && pipe == INVALID_HANDLE_VALUE; ++i) {
        pipe = CreateFileW(gbe::PipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) WaitNamedPipeW(gbe::PipeName, 200);
    }
    if (pipe == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"The engine is not running.\n");
        return 1;
    }
    DWORD done = 0;
    WriteFile(pipe, line.data(), DWORD(line.size()), &done, nullptr);
    std::string reply;
    char buffer[4096];
    while (reply.find("END\n") == std::string::npos && ReadFile(pipe, buffer, sizeof(buffer), &done, nullptr) && done)
        reply.append(buffer, done);
    CloseHandle(pipe);
    fwrite(reply.data(), 1, reply.size(), stdout);
    return reply.rfind("OK", 0) == 0 ? 0 : 1;
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
    std::wstring pipe = gbe::PipeName;
    for (int i = 2; i < argc; ++i) {
        const std::wstring a = argv[i];
        const bool hasValue = i + 1 < argc;
        if (a == L"--dynamic") options.dynamic = true;
        else if (a == L"--scope" && hasValue) options.scope.push_back(argv[++i]);
        else if (a == L"--data" && hasValue) options.dataDir = argv[++i];
        else if (a == L"--ui" && hasValue) ui.push_back(argv[++i]);
        else if (a == L"--seconds" && hasValue) seconds = DWORD(_wtoi(argv[++i]));
        else if (a == L"--pipe" && hasValue) pipe = std::wstring(L"\\\\.\\pipe\\") + argv[++i];
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
    options.windows = ui;
    gbe::FirewallCore core(options);
    if (!core.start(error)) {
        fwprintf(stderr, L"Could not start: %ls\n", error.c_str());
        return 1;
    }
    gbe::PipeServer server(core, ui, pipe);
    if (!server.start(error)) {
        fwprintf(stderr, L"No local channel: %ls\n", error.c_str());
        return 1;
    }
    consoleStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(consoleHandler, TRUE);
    wprintf(L"Engine running%ls. Channel: %ls\n", options.dynamic ? L" (dynamic session)" : L"", pipe.c_str());
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
    if (mode == L"--update" && argc == 3) return update(argv[2]);
    if (mode == L"--send" && argc >= 3) return send(argc, argv);
    if (mode == L"--remove-filters") return removeFilters(false);
    if (mode == L"--console") return console(argc, argv);
    if (mode == L"--signer" && argc == 3) {
        const std::wstring signer = gbe::signerOf(argv[2]);
        wprintf(L"%ls\n", signer.empty() ? L"(no valid embedded signature)" : signer.c_str());
        return signer.empty() ? 1 : 0;
    }
    fwprintf(stderr, L"Usage: GateBouncerEngine.exe --install [--ui <exe>] [--allow-unprotected-folder] | --uninstall | "
                     L"--remove-filters | --update <folder> | --send <field>... | --console ... | --signer <exe>\n");
    return 2;
}
