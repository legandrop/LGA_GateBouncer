#include "folder_rule.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <algorithm>
#include <cwchar>
#include <cwctype>
#include <iterator>
#include <map>

namespace gbe {
namespace {

const wchar_t *const RootProblem = L"A whole drive cannot be trusted. Choose a folder inside it.";
const wchar_t *const LocalProblem = L"Choose a folder on a local drive: not a network, removable or optical drive.";

std::wstring trimmed(std::wstring s) {
    while (!s.empty() && std::iswspace(s.back())) s.pop_back();
    while (!s.empty() && std::iswspace(s.front())) s.erase(s.begin());
    return s;
}

// Sin barra final, salvo en la raíz («C:\»).
std::wstring withoutSlash(std::wstring s) {
    while (s.size() > 3 && (s.back() == L'\\' || s.back() == L'/')) s.pop_back();
    return s;
}

bool isDriveRoot(const std::wstring &dos) {
    return (dos.size() == 2 || (dos.size() == 3 && (dos[2] == L'\\' || dos[2] == L'/'))) && std::iswalpha(dos[0]) &&
           dos[1] == L':';
}

// «X:» o «X:\…»: una letra de unidad y nada más antes de la ruta (ni red, ni «\\?\», ni «\\.\pipe»).
bool hasDriveLetter(const std::wstring &path) {
    return path.size() >= 2 && std::iswalpha(path[0]) && path[1] == L':' && (path.size() == 2 || path[2] == L'\\');
}

// Igualdad sin distinguir mayúsculas, también fuera del ASCII (_wcsicmp sin setlocale sólo iguala A-Z).
bool sameText(const wchar_t *a, std::size_t na, const wchar_t *b, std::size_t nb) {
    return CompareStringOrdinal(a, int(na), b, int(nb), TRUE) == CSTR_EQUAL;
}
bool sameText(const std::wstring &a, const std::wstring &b) { return sameText(a.c_str(), a.size(), b.c_str(), b.size()); }

// a es b o está dentro de b, sin distinguir mayúsculas (rutas DOS, para las carpetas protegidas).
bool within(const std::wstring &a, const std::wstring &b) {
    if (b.empty() || a.size() < b.size() || !sameText(a.c_str(), b.size(), b.c_str(), b.size())) return false;
    return a.size() == b.size() || b.back() == L'\\' || a[b.size()] == L'\\';
}

// «\\?\Volume{GUID}\» sin nada después: el volumen entero (también uno montado en una carpeta, sin letra).
bool isVolumeRoot(const std::wstring &volume) {
    const auto rootEnd = volume.find(L'\\', 4);
    return rootEnd == std::wstring::npos || volume.size() <= rootEnd + 1;
}

bool finalName(HANDLE file, DWORD flags, std::wstring &out) {
    std::wstring buffer(MAX_PATH, L'\0');
    for (int i = 0; i < 3; ++i) {
        const DWORD n = GetFinalPathNameByHandleW(file, buffer.data(), DWORD(buffer.size()), FILE_NAME_NORMALIZED | flags);
        if (n == 0) return false;
        if (n < buffer.size()) {
            buffer.resize(n);
            out = buffer;
            return true;
        }
        buffer.assign(std::size_t(n) + 1, L'\0');
    }
    return false;
}

// Ruta absoluta sin «.» ni «..» (sólo texto: no sigue enlaces).
std::wstring fullPath(const std::wstring &path) {
    const DWORD n = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (n == 0) return path;
    std::wstring out(n, L'\0');
    const DWORD m = GetFullPathNameW(path.c_str(), n, out.data(), nullptr);
    if (m == 0 || m >= n) return path;
    out.resize(m);
    return out;
}

// Expande los nombres cortos 8.3 y nada más: un enlace en el medio de la ruta queda como está.
std::wstring longPath(const std::wstring &path) {
    const DWORD n = GetLongPathNameW(path.c_str(), nullptr, 0);
    if (n == 0) return path;
    std::wstring out(n, L'\0');
    const DWORD m = GetLongPathNameW(path.c_str(), out.data(), n);
    if (m == 0 || m >= n) return path;
    out.resize(m);
    return out;
}

std::wstring env(const wchar_t *name) {
    wchar_t buffer[MAX_PATH * 2] = {};
    const DWORD n = GetEnvironmentVariableW(name, buffer, DWORD(std::size(buffer)));
    return n > 0 && n < std::size(buffer) ? std::wstring(buffer, n) : std::wstring();
}

std::wstring expand(const std::wstring &value) {
    if (value.find(L'%') == std::wstring::npos) return value;
    wchar_t buffer[MAX_PATH * 2] = {};
    const DWORD n = ExpandEnvironmentStringsW(value.c_str(), buffer, DWORD(std::size(buffer)));
    return n > 0 && n <= std::size(buffer) ? std::wstring(buffer) : value;
}

// Un valor de texto del registro tal como está guardado (sin expandir), o vacío.
std::wstring regString(HKEY root, const std::wstring &subkey, const wchar_t *value) {
    DWORD bytes = 0;
    const DWORD flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
    if (RegGetValueW(root, subkey.c_str(), value, flags, nullptr, nullptr, &bytes) != ERROR_SUCCESS || bytes < 2)
        return {};
    std::wstring out(bytes / sizeof(wchar_t), L'\0');
    if (RegGetValueW(root, subkey.c_str(), value, flags, nullptr, out.data(), &bytes) != ERROR_SUCCESS) return {};
    out.resize(wcsnlen(out.c_str(), out.size()));
    return out;
}

std::vector<std::wstring> subkeys(HKEY root, const std::wstring &path) {
    std::vector<std::wstring> out;
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, path.empty() ? nullptr : path.c_str(), 0, KEY_ENUMERATE_SUB_KEYS, &key) != ERROR_SUCCESS)
        return out;
    for (DWORD i = 0;; ++i) {
        wchar_t name[256] = {};
        DWORD size = DWORD(std::size(name));
        const LONG r = RegEnumKeyExW(key, i, name, &size, nullptr, nullptr, nullptr, nullptr);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r == ERROR_SUCCESS) out.emplace_back(name, size);
    }
    RegCloseKey(key);
    return out;
}

// Sólo cuentas de personas: locales, de dominio (S-1-5-21-…) y de Entra ID (S-1-12-1-…). Los perfiles de los servicios
// viven dentro de Windows.
bool personSid(const std::wstring &sid) {
    return (sid.rfind(L"S-1-5-21-", 0) == 0 || sid.rfind(L"S-1-12-1-", 0) == 0) &&
           sid.find(L"_Classes") == std::wstring::npos;
}

// Una variable como la ve el usuario dueño del valor, no quien lee (el motor corre como SYSTEM): las de su sesión
// (Volatile Environment: HOMEDRIVE, HOMEPATH, USERNAME…), las suyas (Environment) y las que salen de su perfil. Vacío si
// no la tiene: queda para las de la máquina.
std::wstring userVariable(const std::wstring &sid, const std::wstring &home, const std::wstring &name) {
    if (!sid.empty())
        for (const wchar_t *keyName : {L"\\Volatile Environment", L"\\Environment"}) {
            const std::wstring value = regString(HKEY_USERS, sid + keyName, name.c_str());
            if (!value.empty()) return value;
        }
    if (home.empty()) return {};
    if (sameText(name, L"USERPROFILE")) return home;
    if (sameText(name, L"LOCALAPPDATA")) return home + L"\\AppData\\Local";
    if (sameText(name, L"APPDATA")) return home + L"\\AppData\\Roaming";
    return {};
}

// Expande las variables del usuario (también las que usan otras, hasta unos niveles) y después las de la máquina
// (%SystemDrive%, %ProgramData%). Lo que quede sin expandir deja una ruta que add() descarta o que no existe.
std::wstring expandFor(const std::wstring &value, const std::wstring &sid, const std::wstring &home, int depth = 0) {
    if (value.find(L'%') == std::wstring::npos) return value;
    std::wstring out;
    for (std::size_t at = 0; at < value.size();) {
        const auto open = value.find(L'%', at);
        const auto close = open == std::wstring::npos ? open : value.find(L'%', open + 1);
        if (close == std::wstring::npos) {
            out.append(value, at, std::wstring::npos);
            break;
        }
        out.append(value, at, open - at);
        const std::wstring name = value.substr(open + 1, close - open - 1);
        const std::wstring found = name.empty() ? std::wstring() : userVariable(sid, home, name);
        if (found.empty())
            out.append(value, open, close - open + 1);
        else
            out += depth < 4 ? expandFor(found, sid, home, depth + 1) : found;
        at = close + 1;
    }
    return expand(out);
}

// La carpeta está en el volumen de su letra de unidad, no en otro montado dentro de una carpeta de esa unidad.
bool onLetterVolume(const FinalPath &f) {
    const auto rootEnd = f.volume.find(L'\\', 4);
    if (f.dos.size() < 3 || rootEnd == std::wstring::npos) return false;
    const wchar_t root[] = {f.dos[0], L':', L'\\', L'\0'};
    wchar_t volume[64] = {};
    return GetVolumeNameForVolumeMountPointW(root, volume, DWORD(std::size(volume))) &&
           sameText(f.volume.substr(0, rootEnd + 1), volume);
}

} // namespace

bool finalPathOf(const std::wstring &path, bool directory, FinalPath &out) {
    // Antes de abrir nada: una letra de unidad de un disco local fijo. El motor corre como SYSTEM y algunas de estas
    // rutas las escribe el usuario (sus Shell Folders, su TEMP): una ruta de red haría que SYSTEM se conecte a otro
    // equipo, y una pipe, a un proceso del usuario.
    if (path.size() < 3 || !hasDriveLetter(path)) return false;
    const wchar_t root[] = {path[0], L':', L'\\', L'\0'};
    if (GetDriveTypeW(root) != DRIVE_FIXED) return false;
    // Sólo atributos: no choca con un archivo abierto en exclusiva (un linker que todavía escribe el exe). Sin
    // FILE_FLAG_OPEN_REPARSE_POINT: se siguen los enlaces hasta el archivo real. SQOS: si aun así fuera una pipe, su
    // servidor no podría hacerse pasar por SYSTEM.
    HANDLE file = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    FILE_BASIC_INFO basic{};
    FinalPath f;
    const bool ok = GetFileInformationByHandleEx(file, FileBasicInfo, &basic, sizeof(basic)) &&
                    ((basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) == directory &&
                    finalName(file, VOLUME_NAME_DOS, f.dos) && finalName(file, VOLUME_NAME_GUID, f.volume);
    CloseHandle(file);
    if (!ok || f.dos.rfind(L"\\\\?\\", 0) != 0 || f.dos.rfind(L"\\\\?\\UNC\\", 0) == 0) return false;
    f.dos.erase(0, 4);
    // «\\?\Volume{GUID}\resto»: sólo discos locales fijos.
    const auto rootEnd = f.volume.find(L'\\', 4);
    if (f.volume.rfind(L"\\\\?\\Volume{", 0) != 0 || rootEnd == std::wstring::npos) return false;
    UINT type = GetDriveTypeW(f.volume.substr(0, rootEnd + 1).c_str());
    if ((type == DRIVE_UNKNOWN || type == DRIVE_NO_ROOT_DIR) && f.dos.size() >= 3)
        type = GetDriveTypeW(f.dos.substr(0, 3).c_str());
    if (type != DRIVE_FIXED) return false;
    f.dos = withoutSlash(f.dos);
    if (f.volume.size() > rootEnd + 1) f.volume = withoutSlash(f.volume);
    out = std::move(f);
    return true;
}

bool placeOf(const std::wstring &reportedPath, FinalPath &out) {
    FinalPath f;
    if (!finalPathOf(reportedPath, false, f)) return false;
    // La ruta final no tiene enlaces: si la informada difiere (más allá de los nombres cortos), pasa por uno.
    if (!sameText(longPath(fullPath(reportedPath)), f.dos)) return false;
    out = std::move(f);
    return true;
}

std::wstring longPathOf(const std::wstring &path) { return longPath(path); }

std::wstring expandForUser(const std::wstring &value, const std::wstring &sid, const std::wstring &home) {
    return expandFor(value, sid, home);
}

std::wstring folderNameKey(const std::wstring &path) {
    const auto slash = path.find_last_of(L"\\/");
    std::wstring name = slash == std::wstring::npos ? path : path.substr(slash + 1);
    // En minúsculas con la tabla invariante: «Éxito.exe» y «éxito.exe» son el mismo nombre, venga de donde venga.
    if (!name.empty()) {
        std::wstring lower(name.size(), L'\0');
        const int n = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, name.c_str(), int(name.size()), lower.data(),
                                    int(lower.size()), nullptr, nullptr, 0);
        if (n == int(name.size())) return lower;
    }
    std::transform(name.begin(), name.end(), name.begin(), [](wchar_t c) { return wchar_t(std::towlower(c)); });
    return name;
}

bool volumePathInside(const std::wstring &fileVolume, const std::wstring &folderVolume) {
    return !folderVolume.empty() && fileVolume.size() > folderVolume.size() &&
           fileVolume.compare(0, folderVolume.size(), folderVolume) == 0 && fileVolume[folderVolume.size()] == L'\\';
}

bool folderRuleBeats(const std::wstring &volumeA, bool namedA, bool blockA, const std::wstring &volumeB, bool namedB,
                     bool blockB) {
    // Las dos cubren el mismo archivo, así que la más larga es la más profunda e iguales es la misma carpeta.
    if (volumeA.size() != volumeB.size()) return volumeA.size() > volumeB.size();
    if (namedA != namedB) return namedA;
    return blockA && !blockB;
}

std::vector<ProtectedFolder> protectedFolders() {
    std::vector<ProtectedFolder> out;
    const auto push = [&out](const std::wstring &path, const std::wstring &label, bool subtree) {
        if (!isDriveRoot(path)) {
            out.push_back({path, label, subtree});
        } else if (subtree) {
            // Una de subárbol que ocupa una unidad entera (TEMP=T:\) protege toda la unidad. Una exacta en la raíz no
            // agrega nada: la raíz ya se rechaza.
            out.push_back({std::wstring(1, path[0]) + L":\\", label, true});
        }
    };
    const auto add = [&push](std::wstring path, const std::wstring &label, bool subtree) {
        path = withoutSlash(trimmed(path));
        // Sólo rutas con letra de unidad: lo demás (red, «\\?\», una pipe) ni se guarda ni se abre.
        if (!hasDriveLetter(path)) return;
        push(path, label, subtree);
        // Si es un enlace (Downloads movido con un junction, «Documents and Settings»), también su destino.
        FinalPath real;
        if (!isDriveRoot(path) && finalPathOf(path, true, real) && !sameText(real.dos, path))
            push(real.dos, label, subtree);
    };
    wchar_t windows[MAX_PATH] = {};
    if (GetWindowsDirectoryW(windows, MAX_PATH)) add(windows, L"Windows", true);
    for (const wchar_t *name : {L"ProgramFiles", L"ProgramW6432", L"ProgramFiles(x86)"}) {
        const std::wstring folder = env(name);
        if (folder.empty()) continue;
        const bool x86 = std::wstring(name).find(L"x86") != std::wstring::npos;
        add(folder, x86 ? L"Program Files (x86)" : L"Program Files", false);
        add(folder + L"\\WindowsApps", L"WindowsApps", true);
    }
    add(env(L"ProgramData"), L"ProgramData", false);
    // La papelera de cada disco local: ahí cae lo que cualquiera borra.
    const DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (!(drives & (1u << i))) continue;
        const wchar_t root[] = {wchar_t(L'A' + i), L':', L'\\', L'\0'};
        if (GetDriveTypeW(root) == DRIVE_FIXED) add(std::wstring(root) + L"$Recycle.Bin", L"The Recycle Bin", true);
    }
    add(env(L"TEMP"), L"Temp", true);
    add(env(L"TMP"), L"Temp", true);

    const std::wstring list = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    add(expand(regString(HKEY_LOCAL_MACHINE, list, L"ProfilesDirectory")), L"Users", false);
    add(expand(regString(HKEY_LOCAL_MACHINE, list, L"Default")), L"A user profile", false);
    // Public la puede escribir cualquier usuario de la PC.
    add(expand(regString(HKEY_LOCAL_MACHINE, list, L"Public")), L"Public", true);
    std::map<std::wstring, std::wstring> homes; // SID -> perfil
    for (const auto &sid : subkeys(HKEY_LOCAL_MACHINE, list)) {
        if (!personSid(sid)) continue;
        const std::wstring home = withoutSlash(expand(regString(HKEY_LOCAL_MACHINE, list + L"\\" + sid, L"ProfileImagePath")));
        if (home.size() < 3) continue;
        homes[sid] = home;
        add(home, L"A user profile", false);
        add(home + L"\\AppData", L"AppData", false);
        add(home + L"\\AppData\\Local", L"AppData", false);
        add(home + L"\\AppData\\LocalLow", L"AppData", false);
        add(home + L"\\AppData\\Roaming", L"AppData", false);
        add(home + L"\\AppData\\Local\\Programs", L"AppData", false);
        add(home + L"\\AppData\\Local\\Packages", L"AppData", false);
        add(home + L"\\Desktop", L"Desktop", false);
        add(home + L"\\Documents", L"Documents", false);
        add(home + L"\\Downloads", L"Downloads", true);
        add(home + L"\\AppData\\Local\\Temp", L"Temp", true);
        add(home + L"\\AppData\\Local\\Microsoft\\WindowsApps", L"WindowsApps", true);
    }
    // Carpetas que el usuario movió de lugar y su Temp propio: sólo de quienes tienen el registro cargado (una sesión
    // abierta). User Shell Folders es la fuente (con variables del perfil); Shell Folders, la copia ya expandida.
    for (const auto &sid : subkeys(HKEY_USERS, {})) {
        if (!personSid(sid)) continue;
        const auto found = homes.find(sid);
        const std::wstring home = found == homes.end() ? std::wstring() : found->second;
        const std::wstring explorer = sid + L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\";
        for (const wchar_t *keyName : {L"User Shell Folders", L"Shell Folders"}) {
            const std::wstring shell = explorer + keyName;
            const auto folder = [&](const wchar_t *value) {
                return expandFor(regString(HKEY_USERS, shell, value), sid, home);
            };
            add(folder(L"{374DE290-123F-4565-9164-39C4925E467B}"), L"Downloads", true);
            add(folder(L"Desktop"), L"Desktop", false);
            add(folder(L"Personal"), L"Documents", false);
            add(folder(L"AppData"), L"AppData", false);
            add(folder(L"Local AppData"), L"AppData", false);
        }
        for (const wchar_t *name : {L"TEMP", L"TMP"})
            add(expandFor(regString(HKEY_USERS, sid + L"\\Environment", name), sid, home), L"Temp", true);
    }
    return out;
}

std::wstring folderProblem(const std::wstring &input, const std::vector<ProtectedFolder> &protectedList) {
    const std::wstring folder = withoutSlash(input);
    if (isDriveRoot(folder)) return RootProblem;
    // Primero la carpeta misma, después si está dentro de una prohibida y por último si contiene una: el mensaje nombra
    // lo más cercano («A user profile…» antes que «holds Temp»). Contener cualquier carpeta protegida la confiaría
    // entera (una carpeta de OneDrive con Desktop y Documents adentro), así que eso vale para todas; estar dentro, sólo
    // para las de subárbol (un proyecto dentro de Documents sí se puede).
    for (int pass = 0; pass < 3; ++pass)
        for (const auto &p : protectedList) {
            const std::wstring guard = withoutSlash(p.path);
            if (guard.size() < 3) continue;
            if (pass == 0 && sameText(folder, guard))
                return p.subtree ? p.label + L" cannot be trusted, nor anything inside it."
                                 : p.label + L" cannot be trusted as a whole. Choose a folder inside it.";
            if (pass == 1 && p.subtree && within(folder, guard)) return L"Folders inside " + p.label + L" cannot be trusted.";
            if (pass == 2 && within(guard, folder))
                return L"This folder holds " + p.label + L" (" + guard + L"), which cannot be trusted.";
        }
    return {};
}

std::wstring resolveTrustedFolder(const std::wstring &input, FinalPath &folder) {
    std::wstring path = trimmed(input);
    std::replace(path.begin(), path.end(), L'/', L'\\');
    if (path.empty()) return L"Choose a folder.";
    // «:» sólo después de la letra de unidad: más adelante sería un flujo de datos («…::$INDEX_ALLOCATION»).
    if (path.find_first_of(L"\t\r\n|*?\"<>") != std::wstring::npos || path.find(L':', 2) != std::wstring::npos)
        return L"This is not a valid folder path.";
    if (isDriveRoot(path)) return RootProblem;
    // Una letra de unidad y una ruta absoluta: ni rutas de red, ni relativas, ni de dispositivo.
    if (path.size() < 4 || !std::iswalpha(path[0]) || path[1] != L':' || path[2] != L'\\')
        return L"Choose a folder on a local drive, such as C:\\Projects\\MyApp.";
    path = withoutSlash(fullPath(path));
    if (isDriveRoot(path)) return RootProblem;
    // Antes de tocar el disco: una unidad de red que no responde congelaría la ventana, que valida mientras se escribe.
    const wchar_t root[] = {path[0], L':', L'\\', L'\0'};
    if (GetDriveTypeW(root) != DRIVE_FIXED) return LocalProblem;
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) return L"This folder does not exist.";
    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) return L"This is a file, not a folder.";
    if (!finalPathOf(path, true, folder)) return LocalProblem;
    // Un enlace (junction, symlink, unidad SUBST) se confía por su destino real o no se confía: así se ve qué se abre.
    if (!sameText(longPath(path), folder.dos))
        return L"This folder is a link to " + folder.dos + L". Trust the real folder instead.";
    // La raíz de un volumen es una unidad entera, también si está montado en una carpeta sin letra.
    if (isDriveRoot(folder.dos) || isVolumeRoot(folder.volume)) return RootProblem;
    // Dentro de un volumen montado en una carpeta: WFP nombra sus programas por dispositivo, sin letra de unidad, así que
    // la regla nunca cubriría nada.
    if (!onLetterVolume(folder))
        return L"This folder is on a drive mounted inside another folder. Use a drive letter for that drive instead.";
    return folderProblem(folder.dos, protectedFolders());
}

bool validFolderVolume(const std::wstring &volume) {
    return volume.rfind(L"\\\\?\\Volume{", 0) == 0 && !isVolumeRoot(volume) && volume.back() != L'\\' &&
           volume.find(L':', 4) == std::wstring::npos;
}

bool normalizeFolderRuleName(const std::wstring &name, std::wstring &out) {
    out.clear();
    const std::wstring n = trimmed(name);
    if (n.empty() || n == L"*") return true;
    if (n.size() > 255 || n == L"." || n == L".." || n.find_first_of(L"\\/:*?\"<>|\t\r\n") != std::wstring::npos)
        return false;
    out = folderNameKey(n);
    return true;
}

} // namespace gbe
