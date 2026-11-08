// Pruebas del motor que no tocan WFP ni la red: se pueden correr sin administrador y con el servicio instalado.
// Salida: una línea por caso y código 0 si pasan todos.
//
//   GateBouncerEngineUnitTest.exe [<carpeta de trabajo>]
//
// Las reglas por carpeta se prueban con carpetas, archivos y junctions reales que la prueba crea dentro de la carpeta
// de trabajo (por defecto, la del exe) y borra al terminar, uno por uno. Tiene que estar en un disco local fijo y fuera
// de Temp, Downloads y las demás carpetas en las que no se puede confiar.
#include "destination_match.h"
#include "folder_rule.h"
#include "folder_watch.h"
#include "name_wait.h"
#include <windows.h>
#include <sddl.h>
#include <winioctl.h>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <io.h>
#include <iterator>
#include <map>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(const wchar_t *name, bool ok) {
    std::wprintf(L"%ls  %ls\n", ok ? L"PASS" : L"FAIL", name);
    if (!ok) ++failures;
}

void skip(const wchar_t *name, const wchar_t *why) { std::wprintf(L"SKIP  %ls (%ls)\n", name, why); }

using Clock = gbe::NameWait<int>::Clock;
using std::chrono::milliseconds;

// Un bloqueo de una app en modo por destino, como lo ve el motor.
struct Drop {
    std::wstring address;
};

// Lo que el motor hace con un bloqueo cuando ya tiene (o no) el nombre: «allow» si la regla lo cubre, «ask» si no.
std::wstring verdict(const std::wstring &rule, const std::map<std::wstring, std::wstring> &names, const Drop &d) {
    const auto n = names.find(d.address);
    return gbe::destinationMatch(rule, n == names.end() ? std::wstring() : n->second, d.address) ? L"allow" : L"ask";
}

void destinationMatchNeedsTheName() {
    // La causa del pedido falso: con la regla ya guardada, el bloqueo llega sin nombre y no coincide.
    check(L"regla *.dominio sin nombre todavía: no coincide",
          gbe::destinationMatch(L"*.googleusercontent.com", L"", L"142.251.129.129") == 0);
    check(L"regla *.dominio con el nombre: coincide",
          gbe::destinationMatch(L"*.googleusercontent.com", L"doc-04-34-sheets.googleusercontent.com",
                                L"142.251.129.129") > 0);
    check(L"regla por IP: coincide sin nombre",
          gbe::destinationMatch(L"142.251.129.129", L"", L"142.251.129.129") > 0);
    check(L"regla *.dominio no cubre otro dominio",
          gbe::destinationMatch(L"*.googleusercontent.com", L"docs.google.com", L"142.251.129.129") == 0);
}

void nameWaitReleasesWhenTheNameArrives() {
    gbe::NameWait<Drop> wait(std::chrono::seconds(2), 10);
    const auto t0 = Clock::now();
    std::map<std::wstring, std::wstring> names;
    const auto named = [&](const Drop &d) { return names.count(d.address) > 0; };
    check(L"retiene el bloqueo sin nombre", wait.hold({L"142.251.129.129"}, t0));
    check(L"antes del nombre y de la espera no suelta nada", wait.release(t0 + milliseconds(300), named).empty());
    // El DNS de Windows llega ~1 s después del intento.
    names[L"142.251.129.129"] = L"doc-04-34-sheets.googleusercontent.com";
    const auto out = wait.release(t0 + milliseconds(900), named);
    check(L"al llegar el nombre lo suelta sin esperar el vencimiento", out.size() == 1);
    check(L"y con el nombre la regla lo resuelve: no se pregunta",
          out.size() == 1 && verdict(L"*.googleusercontent.com", names, out[0]) == L"allow");
    check(L"queda vacía", wait.size() == 0 && !wait.nextDeadline());
}

void nameWaitGivesUpAfterTheWait() {
    // Una app que se conecta directo a una IP (o con DNS propio) nunca trae nombre: pregunta al vencer la espera.
    gbe::NameWait<Drop> wait(std::chrono::seconds(2), 10);
    const auto t0 = Clock::now();
    const auto never = [](const Drop &) { return false; };
    wait.hold({L"203.0.113.7"}, t0);
    check(L"marca la hora de vencimiento", wait.nextDeadline() && *wait.nextDeadline() == t0 + std::chrono::seconds(2));
    check(L"un instante antes de vencer, sigue esperando", wait.release(t0 + milliseconds(1999), never).empty());
    const auto out = wait.release(t0 + std::chrono::seconds(2), never);
    check(L"al vencer lo suelta", out.size() == 1);
    check(L"sin nombre se pregunta, como antes", out.size() == 1 && verdict(L"*.example.com", {}, out[0]) == L"ask");
}

void nameWaitKeepsOrderAndLimit() {
    gbe::NameWait<Drop> wait(std::chrono::seconds(2), 3);
    const auto t0 = Clock::now();
    // Los ocho intentos de Python a las ocho direcciones de un mismo nombre, en el mismo segundo.
    int held = 0;
    for (int i = 0; i < 8; ++i) held += wait.hold({L"172.217.11" + std::to_wstring(i) + L".4"}, t0) ? 1 : 0;
    check(L"con la cola llena el resto se decide ya (no se pierde)", held == 3 && wait.size() == 3);
    std::map<std::wstring, std::wstring> names{{L"172.217.111.4", L"www.googleapis.com"}};
    const auto out = wait.release(t0 + milliseconds(500), [&](const Drop &d) { return names.count(d.address) > 0; });
    check(L"suelta sólo los que ya tienen nombre", out.size() == 1 && out[0].address == L"172.217.111.4");
    const auto rest = wait.release(t0 + std::chrono::seconds(3), [](const Drop &) { return false; });
    check(L"el resto sale al vencer, en orden de llegada",
          rest.size() == 2 && rest[0].address == L"172.217.110.4" && rest[1].address == L"172.217.112.4");
}

void theReportedSequence() {
    // 20:50:12 se guarda «Allow python.exe to *.googleusercontent.com». 20:51:57 el intento a 142.251.129.129 llega al
    // motor antes que la consulta DNS. Antes: pedido sin nombre, el DNS lo borraba un instante después y el aviso se
    // cerraba solo. Ahora: el bloqueo espera el nombre y se resuelve por la regla, sin pedido.
    const std::wstring rule = L"*.googleusercontent.com";
    std::map<std::wstring, std::wstring> names;
    const Drop drop{L"142.251.129.129"};
    check(L"secuencia reportada, sin espera: se preguntaba", verdict(rule, names, drop) == L"ask");
    gbe::NameWait<Drop> wait(std::chrono::seconds(2), 10);
    const auto t0 = Clock::now();
    wait.hold(drop, t0);
    names[drop.address] = L"doc-04-34-sheets.googleusercontent.com";
    const auto out = wait.release(t0 + milliseconds(1000), [&](const Drop &d) { return names.count(d.address) > 0; });
    check(L"secuencia reportada, con espera: lo resuelve la regla",
          out.size() == 1 && verdict(rule, names, out[0]) == L"allow");
}

// ---------------------------------------------------------------------------------------------------------------
// Reglas por carpeta.

// Lo que la prueba crea, para borrarlo al final de a uno y en orden inverso (nunca un borrado recursivo).
struct Scratch {
    struct Entry {
        std::wstring path;
        bool directory;
    };
    std::vector<Entry> made;
    bool dir(const std::wstring &path) {
        if (!CreateDirectoryW(path.c_str(), nullptr)) return false;
        made.push_back({path, true});
        return true;
    }
    bool file(const std::wstring &path) {
        HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        CloseHandle(h);
        made.push_back({path, false});
        return true;
    }
    // Un junction (punto de montaje), como «mklink /J»: no hace falta administrador.
    bool junction(const std::wstring &link, const std::wstring &target) {
        if (!dir(link)) return false;
        HANDLE h = CreateFileW(link.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        // REPARSE_DATA_BUFFER de un punto de montaje (no está en los encabezados de modo usuario): encabezado de 8 bytes,
        // cuatro WORD con los desplazamientos y los dos nombres terminados en cero.
        const std::wstring substitute = L"\\??\\" + target, print = target;
        const WORD subBytes = WORD(substitute.size() * sizeof(wchar_t)), printBytes = WORD(print.size() * sizeof(wchar_t));
        const WORD dataBytes = WORD(8 + subBytes + sizeof(wchar_t) + printBytes + sizeof(wchar_t));
        std::vector<BYTE> buffer(8 + dataBytes, 0);
        const DWORD tag = IO_REPARSE_TAG_MOUNT_POINT;
        const WORD fields[4] = {0, subBytes, WORD(subBytes + sizeof(wchar_t)), printBytes};
        std::memcpy(buffer.data(), &tag, 4);
        std::memcpy(buffer.data() + 4, &dataBytes, 2);
        std::memcpy(buffer.data() + 8, fields, sizeof(fields));
        std::memcpy(buffer.data() + 16, substitute.c_str(), subBytes);
        std::memcpy(buffer.data() + 16 + subBytes + sizeof(wchar_t), print.c_str(), printBytes);
        DWORD returned = 0;
        const bool ok = DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, buffer.data(), DWORD(buffer.size()), nullptr, 0,
                                        &returned, nullptr) != FALSE;
        CloseHandle(h);
        return ok;
    }
    // Un symlink de archivo: sólo con el modo de desarrollador o como administrador.
    bool symlink(const std::wstring &link, const std::wstring &target) {
        if (!CreateSymbolicLinkW(link.c_str(), target.c_str(), SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) return false;
        made.push_back({link, false});
        return true;
    }
    ~Scratch() {
        // Un junction se borra con RemoveDirectoryW: se va el enlace, no lo que hay en su destino.
        for (auto it = made.rbegin(); it != made.rend(); ++it)
            if (!(it->directory ? RemoveDirectoryW(it->path.c_str()) : DeleteFileW(it->path.c_str())))
                std::wprintf(L"NOTE  no se pudo borrar %ls\n", it->path.c_str());
    }
};

bool inside(const std::wstring &reported, const gbe::FinalPath &folder) {
    gbe::FinalPath place;
    return gbe::placeOf(reported, place) && gbe::volumePathInside(place.volume, folder.volume);
}

std::wstring envValue(const wchar_t *name) {
    wchar_t buffer[MAX_PATH * 2] = {};
    const DWORD n = GetEnvironmentVariableW(name, buffer, DWORD(std::size(buffer)));
    return n > 0 && n < std::size(buffer) ? std::wstring(buffer, n) : std::wstring();
}

void folderRulesOnDisk(const std::wstring &base) {
    Scratch s;
    const std::wstring run = base + L"\\run-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                             std::to_wstring(GetTickCount64());
    if (!s.dir(run)) {
        check(L"carpeta de trabajo para las pruebas por carpeta", false);
        return;
    }
    // El repo de confianza con un build, un worktree futuro, una carpeta afuera y una vecina con el mismo prefijo.
    const std::wstring trusted = run + L"\\LGA_Repo", outside = run + L"\\Outside", sibling = run + L"\\LGA_Repo2";
    const std::wstring build = trusted + L"\\build", worktree = trusted + L"\\.worktrees\\feature-x\\build";
    bool made = s.dir(trusted) && s.dir(build) && s.dir(trusted + L"\\.worktrees") &&
                s.dir(trusted + L"\\.worktrees\\feature-x") && s.dir(worktree) && s.dir(outside) && s.dir(sibling) &&
                s.file(build + L"\\App.exe") && s.file(worktree + L"\\DayTrace.exe") && s.file(outside + L"\\Evil.exe") &&
                s.file(sibling + L"\\App.exe");
    check(L"arma el árbol de prueba", made);
    if (!made) return;

    gbe::FinalPath folder;
    const std::wstring problem = gbe::resolveTrustedFolder(trusted, folder);
    check(L"se puede confiar en una carpeta de proyecto", problem.empty());
    if (!problem.empty()) {
        std::wprintf(L"      motivo: %ls\n", problem.c_str());
        return;
    }
    check(L"guarda la ruta final y el volumen por GUID",
          _wcsicmp(folder.dos.c_str(), trusted.c_str()) == 0 && folder.volume.rfind(L"\\\\?\\Volume{", 0) == 0);
    check(L"un exe del build queda adentro", inside(build + L"\\App.exe", folder));
    check(L"un exe de un worktree nuevo queda adentro", inside(worktree + L"\\DayTrace.exe", folder));
    check(L"una barra final en la carpeta da lo mismo",
          [&] {
              gbe::FinalPath again;
              return gbe::resolveTrustedFolder(trusted + L"\\", again).empty() && again.volume == folder.volume;
          }());
    check(L"un exe afuera no queda adentro", !inside(outside + L"\\Evil.exe", folder));
    check(L"una carpeta vecina con el mismo prefijo no queda adentro", !inside(sibling + L"\\App.exe", folder));
    check(L"la carpeta misma no es un programa de adentro", !inside(trusted, folder));

    // Un junction dentro de la carpeta que apunta afuera: no extiende la confianza.
    const std::wstring escape = trusted + L"\\escape";
    if (s.junction(escape, outside)) {
        gbe::FinalPath real;
        check(L"junction adentro hacia afuera: el exe no queda adentro", !inside(escape + L"\\Evil.exe", folder));
        check(L"junction adentro hacia afuera: su ruta final está afuera",
              gbe::finalPathOf(escape + L"\\Evil.exe", false, real) && !gbe::volumePathInside(real.volume, folder.volume));
        check(L"junction adentro hacia afuera: la ruta que pasa por el enlace no se cubre",
              !gbe::placeOf(escape + L"\\Evil.exe", real));
    } else {
        check(L"crea un junction sin administrador", false);
    }
    // Un junction afuera que apunta adentro: sólo cuenta la ruta real (la que informa WFP).
    const std::wstring shortcut = run + L"\\Shortcut";
    if (s.junction(shortcut, build)) {
        check(L"junction afuera hacia adentro: por el enlace no se cubre", !inside(shortcut + L"\\App.exe", folder));
        check(L"junction afuera hacia adentro: por la ruta real sí", inside(build + L"\\App.exe", folder));
    } else {
        check(L"crea un junction sin administrador", false);
    }
    // Confiar en un enlace: se rechaza con el destino real.
    const std::wstring linkToRepo = run + L"\\RepoLink";
    if (s.junction(linkToRepo, trusted)) {
        gbe::FinalPath linked;
        const std::wstring why = gbe::resolveTrustedFolder(linkToRepo, linked);
        check(L"no se confía en una carpeta que es un enlace", why.find(L"link") != std::wstring::npos);
    }
    // Un symlink de archivo adentro que apunta afuera.
    const std::wstring fileLink = build + L"\\Linked.exe";
    if (s.symlink(fileLink, outside + L"\\Evil.exe"))
        check(L"symlink de archivo adentro hacia afuera: no queda adentro", !inside(fileLink, folder));
    else
        skip(L"symlink de archivo adentro hacia afuera", L"crear symlinks necesita el modo de desarrollador");

    // Lo que no se puede confiar.
    gbe::FinalPath none;
    const std::wstring drive = run.substr(0, 3);
    check(L"rechaza la raíz de C:", !gbe::resolveTrustedFolder(L"C:\\", none).empty());
    check(L"rechaza «C:» sin barra", !gbe::resolveTrustedFolder(L"C:", none).empty());
    check(L"rechaza la raíz del disco de la prueba", !gbe::resolveTrustedFolder(drive, none).empty());
    check(L"rechaza una ruta que sube hasta la raíz",
          !gbe::resolveTrustedFolder(trusted + L"\\..\\..\\..\\..\\..\\..\\..\\..", none).empty());
    check(L"rechaza una ruta relativa", !gbe::resolveTrustedFolder(L"Portable\\LGA_Repo", none).empty());
    check(L"rechaza una ruta de red", !gbe::resolveTrustedFolder(L"\\\\localhost\\c$\\Portable", none).empty());
    check(L"rechaza «:» después de la unidad (un flujo de datos)",
          !gbe::resolveTrustedFolder(L"C:\\Windows::$INDEX_ALLOCATION", none).empty());
    check(L"una ruta de red no se resuelve", !gbe::finalPathOf(L"\\\\127.0.0.1\\c$\\Windows", true, none));
    check(L"una ruta «\\\\?\\» no se resuelve", !gbe::finalPathOf(L"\\\\?\\C:\\Windows", true, none));
    // El motor corre como SYSTEM: una ruta que escribe el usuario (sus Shell Folders, su TEMP) nunca lo conecta a una
    // pipe ajena. Con la pipe en modo sin espera, ConnectNamedPipe dice si alguien la abrió.
    const std::wstring pipeName = L"\\\\.\\pipe\\GateBouncerUnitTest-" + std::to_wstring(GetCurrentProcessId());
    HANDLE pipe = CreateNamedPipeW(pipeName.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_NOWAIT, 1, 512, 512, 0,
                                   nullptr);
    if (pipe != INVALID_HANDLE_VALUE) {
        gbe::FinalPath viaPipe;
        const bool resolved = gbe::finalPathOf(pipeName, false, viaPipe);
        const BOOL connected = ConnectNamedPipe(pipe, nullptr);
        const DWORD state = GetLastError();
        check(L"una pipe no se abre", !resolved && !connected && state == ERROR_PIPE_LISTENING);
        CloseHandle(pipe);
    } else {
        check(L"crea una pipe de prueba", false);
    }
    check(L"rechaza una carpeta que no existe", !gbe::resolveTrustedFolder(run + L"\\Missing", none).empty());
    check(L"rechaza un archivo", !gbe::resolveTrustedFolder(build + L"\\App.exe", none).empty());
    const std::wstring windows = envValue(L"SystemRoot");
    check(L"rechaza Windows", !gbe::resolveTrustedFolder(windows, none).empty());
    check(L"rechaza System32", !gbe::resolveTrustedFolder(windows + L"\\System32", none).empty());
    check(L"rechaza Program Files", !gbe::resolveTrustedFolder(envValue(L"ProgramFiles"), none).empty());
    check(L"rechaza ProgramData", !gbe::resolveTrustedFolder(envValue(L"ProgramData"), none).empty());
    const std::wstring home = envValue(L"USERPROFILE");
    check(L"rechaza la carpeta del usuario", !gbe::resolveTrustedFolder(home, none).empty());
    check(L"rechaza C:\\Users", !gbe::resolveTrustedFolder(home.substr(0, home.find_last_of(L'\\')), none).empty());
    wchar_t temp[MAX_PATH + 1] = {};
    GetTempPathW(MAX_PATH + 1, temp);
    check(L"rechaza %TEMP%", !gbe::resolveTrustedFolder(temp, none).empty());
    if (GetFileAttributesW((home + L"\\Downloads").c_str()) != INVALID_FILE_ATTRIBUTES)
        check(L"rechaza Downloads", !gbe::resolveTrustedFolder(home + L"\\Downloads", none).empty());
    if (GetFileAttributesW((home + L"\\AppData\\Local").c_str()) != INVALID_FILE_ATTRIBUTES)
        check(L"rechaza AppData\\Local", !gbe::resolveTrustedFolder(home + L"\\AppData\\Local", none).empty());
    const auto list = gbe::protectedFolders();
    check(L"dentro de Temp tampoco", !gbe::folderProblem(std::wstring(temp) + L"build", list).empty());
    check(L"dentro de Downloads tampoco", !gbe::folderProblem(home + L"\\Downloads\\tool", list).empty());
    check(L"dentro de Windows tampoco", !gbe::folderProblem(windows + L"\\Temp\\x", list).empty());
    check(L"un proyecto dentro del perfil sí", gbe::folderProblem(home + L"\\Projects\\MyApp", list).empty());
    check(L"una carpeta dentro de Program Files sí",
          gbe::folderProblem(envValue(L"ProgramFiles") + L"\\LGA GateBouncer", list).empty());
    check(L"C:\\Portable\\LGA_DayTrace sí", gbe::folderProblem(L"C:\\Portable\\LGA_DayTrace", list).empty());
    // TEMP en la raíz de una unidad (TEMP=T:\) protege toda esa unidad: antes se descartaba por ser una raíz.
    const std::wstring oldTemp = envValue(L"TEMP");
    SetEnvironmentVariableW(L"TEMP", drive.c_str());
    const auto rootTemp = gbe::protectedFolders();
    SetEnvironmentVariableW(L"TEMP", oldTemp.empty() ? nullptr : oldTemp.c_str());
    check(L"TEMP en la raíz de la unidad: nada de esa unidad", !gbe::folderProblem(trusted, rootTemp).empty());
    check(L"TEMP vuelve a ser el de antes", envValue(L"TEMP") == oldTemp);
}

void folderRulesWithoutDisk() {
    // Una carpeta que contiene a Downloads (movido a otro disco) tampoco: abriría todo lo descargado.
    const std::vector<gbe::ProtectedFolder> list{{L"D:\\Stuff\\Downloads", L"Downloads", true},
                                                 {L"D:\\Profiles\\me", L"A user profile", false}};
    check(L"rechaza una carpeta que contiene Downloads", !gbe::folderProblem(L"D:\\Stuff", list).empty());
    check(L"rechaza una carpeta dentro de Downloads", !gbe::folderProblem(L"D:\\Stuff\\Downloads\\x", list).empty());
    check(L"rechaza Downloads aunque se escriba distinto", !gbe::folderProblem(L"d:\\stuff\\DOWNLOADS\\", list).empty());
    check(L"acepta una vecina con el mismo prefijo", gbe::folderProblem(L"D:\\Stuffing", list).empty());
    check(L"acepta otra carpeta al lado de Downloads", gbe::folderProblem(L"D:\\Stuff\\Other", list).empty());
    check(L"rechaza el perfil mismo", !gbe::folderProblem(L"D:\\Profiles\\me", list).empty());
    check(L"acepta una carpeta dentro del perfil", gbe::folderProblem(L"D:\\Profiles\\me\\Code", list).empty());
    check(L"rechaza la raíz de una unidad", !gbe::folderProblem(L"E:\\", list).empty());
    // Contener cualquier carpeta protegida la confía entera (Documents movido adentro de OneDrive); estar dentro de una
    // exacta, no (un proyecto en Documents).
    const std::vector<gbe::ProtectedFolder> moved{{L"D:\\OneDrive\\Documents", L"Documents", false}};
    check(L"rechaza una carpeta que contiene Documents", !gbe::folderProblem(L"D:\\OneDrive", moved).empty());
    check(L"acepta un proyecto dentro de Documents",
          gbe::folderProblem(L"D:\\OneDrive\\Documents\\Code\\MyApp", moved).empty());
    // Una de subárbol en la raíz de una unidad: toda la unidad.
    const std::vector<gbe::ProtectedFolder> wholeDrive{{L"T:\\", L"Temp", true}};
    check(L"Temp en T:\\ rechaza cualquier carpeta de T:", !gbe::folderProblem(L"T:\\RotoWorker_tmp\\x", wholeDrive).empty());
    check(L"Temp en T:\\ no toca otra unidad", gbe::folderProblem(L"C:\\Portable\\LGA_DayTrace", wholeDrive).empty());
    // Mayúsculas fuera del ASCII: la misma carpeta.
    const std::vector<gbe::ProtectedFolder> accented{{L"D:\\Árbol\\Downloads", L"Downloads", true}};
    check(L"compara mayúsculas fuera del ASCII", !gbe::folderProblem(L"d:\\árbol\\downloads\\x", accented).empty());

    // El volumen se compara exacto, con mayúsculas, y con «\» después de la carpeta.
    const std::wstring repo = L"\\\\?\\Volume{0000-1}\\Portable\\LGA_DayTrace";
    check(L"ruta de volumen adentro", gbe::volumePathInside(repo + L"\\build\\DayTrace.exe", repo));
    check(L"otra carpeta con el mismo prefijo no", !gbe::volumePathInside(repo + L"2\\App.exe", repo));
    check(L"otro volumen no", !gbe::volumePathInside(L"\\\\?\\Volume{0000-2}\\Portable\\LGA_DayTrace\\a.exe", repo));
    check(L"otras mayúsculas no (carpetas que distinguen mayúsculas)",
          !gbe::volumePathInside(L"\\\\?\\Volume{0000-1}\\Portable\\lga_daytrace\\a.exe", repo));
    check(L"la carpeta misma no", !gbe::volumePathInside(repo, repo));
    // Lo guardado en rules.tsv: una carpeta, nunca un volumen entero.
    check(L"rules.tsv: un volumen entero no se carga", !gbe::validFolderVolume(L"\\\\?\\Volume{0000-1}\\"));
    check(L"rules.tsv: un volumen sin barra tampoco", !gbe::validFolderVolume(L"\\\\?\\Volume{0000-1}"));
    check(L"rules.tsv: con «:» tampoco", !gbe::validFolderVolume(repo + L"::$INDEX_ALLOCATION"));
    check(L"rules.tsv: una ruta DOS tampoco", !gbe::validFolderVolume(L"C:\\Portable\\LGA_DayTrace"));
    check(L"rules.tsv: una carpeta del volumen sí", gbe::validFolderVolume(repo));

    // Precedencia entre dos reglas por carpeta que cubren el mismo archivo.
    const std::wstring deep = repo + L"\\vendor";
    check(L"la carpeta más profunda gana", gbe::folderRuleBeats(deep, false, false, repo, false, true));
    check(L"la menos profunda pierde aunque bloquee", !gbe::folderRuleBeats(repo, false, true, deep, false, false));
    check(L"en la misma carpeta gana la que nombra el exe", gbe::folderRuleBeats(repo, true, false, repo, false, true));
    check(L"a igualdad gana Block", gbe::folderRuleBeats(repo, false, true, repo, false, false));
    check(L"a igualdad Allow no le gana a Block", !gbe::folderRuleBeats(repo, false, false, repo, false, true));

    // El nombre del exe de la regla.
    std::wstring name;
    check(L"sin nombre: todos los programas", gbe::normalizeFolderRuleName(L"", name) && name.empty());
    check(L"«*»: todos los programas", gbe::normalizeFolderRuleName(L"*", name) && name.empty());
    check(L"el nombre va en minúsculas", gbe::normalizeFolderRuleName(L" DayTrace.EXE ", name) && name == L"daytrace.exe");
    check(L"un nombre con carpeta no vale", !gbe::normalizeFolderRuleName(L"build\\DayTrace.exe", name));
    check(L"«..» no vale", !gbe::normalizeFolderRuleName(L"..", name));
    check(L"un comodín no vale", !gbe::normalizeFolderRuleName(L"Day*.exe", name));
    // Fuera del ASCII, la misma minúscula venga de la ventana (el nombre real) o de WFP (ya en minúsculas).
    check(L"nombre con acento en minúsculas", gbe::normalizeFolderRuleName(L"Éxito.EXE", name) && name == L"éxito.exe");
    check(L"el nombre de una ruta con acento", gbe::folderNameKey(L"C:\\Repo\\build\\ÉXITO.exe") == L"éxito.exe");
    check(L"la regla y el archivo coinciden", gbe::normalizeFolderRuleName(L"éxito.exe", name) &&
                                                 name == gbe::folderNameKey(L"D:\\Árbol\\Éxito.exe"));
}

// El vigía de carpetas con carpetas y archivos reales: avisa los .exe nuevos de adentro y nada más.
void folderWatchOnDisk(const std::wstring &base) {
    check(L"vigía: «.exe» en cualquier mayúscula", gbe::isExeName(L"DayTrace.exe") && gbe::isExeName(L"APP.EXE"));
    check(L"vigía: otras extensiones no", !gbe::isExeName(L"notes.txt") && !gbe::isExeName(L"a.exe.txt") &&
                                             !gbe::isExeName(L".exe") && !gbe::isExeName(L"aexe"));
    Scratch s;
    const std::wstring run = base + L"\\watch-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                             std::to_wstring(GetTickCount64());
    const std::wstring trusted = run + L"\\LGA_Repo", build = trusted + L"\\build", outside = run + L"\\Outside";
    if (!(s.dir(run) && s.dir(trusted) && s.dir(build) && s.dir(outside))) {
        check(L"vigía: arma el árbol de prueba", false);
        return;
    }
    gbe::FinalPath folder;
    if (!gbe::resolveTrustedFolder(trusted, folder).empty()) {
        check(L"vigía: la carpeta de prueba se puede confiar", false);
        return;
    }
    std::mutex m;
    std::vector<std::wstring> seen;
    const auto saw = [&](const std::wstring &tail) {
        std::lock_guard<std::mutex> lock(m);
        for (const auto &p : seen)
            if (p.size() >= tail.size() && _wcsicmp(p.c_str() + p.size() - tail.size(), tail.c_str()) == 0) return true;
        return false;
    };
    const auto waitFor = [&](const std::wstring &tail, int ms) {
        for (int i = 0; i < ms / 50 && !saw(tail); ++i) Sleep(50);
        return saw(tail);
    };
    gbe::FolderWatch watch([&](const std::wstring &path) {
        std::lock_guard<std::mutex> lock(m);
        seen.push_back(path);
    });
    watch.setFolders({folder.dos});
    for (int i = 0; i < 40 && watch.watching() != 1; ++i) Sleep(50);
    check(L"vigía: vigila la carpeta", watch.watching() == 1);
    const bool escape = s.junction(trusted + L"\\escape", outside);
    s.file(build + L"\\DayTrace.exe");
    s.file(build + L"\\notes.txt");
    s.file(outside + L"\\Evil.exe");
    // Escrito a través del junction que sale de la carpeta: el archivo real queda afuera.
    const bool via = escape && s.file(trusted + L"\\escape\\Via.exe");
    // Como lld: se escribe con otro nombre y se renombra al final.
    bool renamed = s.file(build + L"\\Linked.tmp") &&
                   MoveFileW((build + L"\\Linked.tmp").c_str(), (build + L"\\Linked.exe").c_str());
    if (renamed) s.made.back().path = build + L"\\Linked.exe";
    check(L"vigía: avisa un .exe nuevo en una subcarpeta", waitFor(L"\\build\\DayTrace.exe", 3000));
    check(L"vigía: avisa un .exe que llega por un cambio de nombre", renamed && waitFor(L"\\build\\Linked.exe", 3000));
    Sleep(500);
    check(L"vigía: un archivo que no es .exe no se avisa", !saw(L"notes.txt") && !saw(L"Linked.tmp"));
    check(L"vigía: un .exe en otra carpeta no se avisa", !saw(L"\\Outside\\Evil.exe"));
    if (via) {
        check(L"vigía: un .exe escrito por un junction que sale no se avisa", !saw(L"Via.exe"));
        check(L"enlaces: la ruta por el junction tiene un enlace", !gbe::linkFreePath(trusted + L"\\escape\\Via.exe"));
    } else {
        std::wprintf(L"SKIP  vigía por un junction (no se pudo crear)\n");
    }
    check(L"enlaces: una ruta sin enlaces pasa", gbe::linkFreePath(build + L"\\DayTrace.exe"));
    check(L"enlaces: una ruta de red o sin letra no pasa",
          !gbe::linkFreePath(L"\\\\server\\share\\x.exe") && !gbe::linkFreePath(L"\\\\.\\pipe\\x") &&
              !gbe::linkFreePath(L"x.exe"));
    // Lo que avise tiene que estar adentro de verdad: si llegara algo por el junction, el motor lo descarta igual.
    bool allInside = true;
    {
        std::lock_guard<std::mutex> lock(m);
        for (const auto &p : seen) allInside = allInside && inside(p, folder);
    }
    check(L"vigía: todo lo avisado está dentro de la carpeta por su ruta final", allInside);
    watch.setFolders({});
    for (int i = 0; i < 40 && watch.watching() != 0; ++i) Sleep(50);
    check(L"vigía: deja de vigilar una carpeta sin regla", watch.watching() == 0);
    s.file(build + L"\\Late.exe");
    Sleep(800);
    check(L"vigía: sin regla ya no avisa", !saw(L"Late.exe"));
    if (escape) {
        // Una carpeta de regla que pasó a ser un enlace (acá, el junction que sale) no se vigila.
        watch.setFolders({trusted + L"\\escape"});
        Sleep(500);
        check(L"vigía: una carpeta que es un enlace no se vigila", watch.watching() == 0);
    }
    watch.stop();
}

std::wstring currentUserSid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return {};
    std::vector<BYTE> buffer(256);
    DWORD size = 0;
    std::wstring out;
    if (GetTokenInformation(token, TokenUser, buffer.data(), DWORD(buffer.size()), &size)) {
        wchar_t *text = nullptr;
        if (ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(buffer.data())->User.Sid, &text)) {
            out = text;
            LocalFree(text);
        }
    }
    CloseHandle(token);
    return out;
}

// Las carpetas de un usuario se leen de su registro con sus variables, no con las del motor (que corre como SYSTEM).
void userVariablesExpand() {
    check(L"%USERPROFILE% sale del perfil",
          gbe::expandForUser(L"%USERPROFILE%\\Docs", L"", L"C:\\Users\\abc") == L"C:\\Users\\abc\\Docs");
    check(L"%LOCALAPPDATA% sale del perfil",
          gbe::expandForUser(L"%LOCALAPPDATA%\\Temp", L"", L"C:\\Users\\abc") == L"C:\\Users\\abc\\AppData\\Local\\Temp");
    check(L"una variable que nadie tiene queda como está",
          gbe::expandForUser(L"%GB_NO_EXISTE_7%\\x", L"", L"C:\\Users\\abc") == L"%GB_NO_EXISTE_7%\\x");
    const std::wstring sid = currentUserSid();
    const std::wstring drive = envValue(L"HOMEDRIVE"), path = envValue(L"HOMEPATH");
    if (sid.empty() || drive.empty() || path.empty()) {
        skip(L"%HOMEDRIVE%%HOMEPATH% de la sesión del usuario", L"esta sesión no tiene HOMEDRIVE y HOMEPATH");
        return;
    }
    // Sin las del proceso: así el resultado sólo puede venir de la sesión del usuario en su registro.
    SetEnvironmentVariableW(L"HOMEDRIVE", nullptr);
    SetEnvironmentVariableW(L"HOMEPATH", nullptr);
    const std::wstring expanded = gbe::expandForUser(L"%HOMEDRIVE%%HOMEPATH%\\Documents", sid, L"");
    SetEnvironmentVariableW(L"HOMEDRIVE", drive.c_str());
    SetEnvironmentVariableW(L"HOMEPATH", path.c_str());
    check(L"%HOMEDRIVE%%HOMEPATH% sale de la sesión del usuario, no del proceso",
          expanded == drive + path + L"\\Documents");
}

} // namespace

int wmain(int argc, wchar_t **argv) {
    _setmode(_fileno(stdout), _O_U8TEXT);
    destinationMatchNeedsTheName();
    nameWaitReleasesWhenTheNameArrives();
    nameWaitGivesUpAfterTheWait();
    nameWaitKeepsOrderAndLimit();
    theReportedSequence();
    folderRulesWithoutDisk();
    userVariablesExpand();
    std::wstring base;
    if (argc > 1) {
        base = argv[1];
    } else {
        wchar_t self[MAX_PATH * 2] = {};
        GetModuleFileNameW(nullptr, self, DWORD(std::size(self)));
        base = self;
        base = base.substr(0, base.find_last_of(L'\\'));
    }
    while (base.size() > 3 && base.back() == L'\\') base.pop_back();
    folderRulesOnDisk(base);
    folderWatchOnDisk(base);
    std::wprintf(failures ? L"\n%d FAILED\n" : L"\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
