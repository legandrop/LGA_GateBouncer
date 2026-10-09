#include "deployment_win.h"
#include <algorithm>
#include <set>
namespace gb::controller {
namespace {
std::wstring lower(std::wstring s) {
    for (auto &c : s) {
        if (c >= L'A' && c <= L'Z')
            c += L'a' - L'A';
    }
    return s;
}
bool name(const std::wstring &s) {
    if (s.empty() || s.size() > 128 || s.front() == L'\\' || s.back() == L'\\' ||
        s.find(L"..") != std::wstring::npos || s.find(L"\\\\") != std::wstring::npos)
        return false;
    for (auto c : s)
        if (!((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') ||
              c == L'.' || c == L'_' || c == L'-' || c == L'\\'))
            return false;
    return true;
}
std::uint64_t number(const wire::Bytes &b, std::size_t at, unsigned n) {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < n; ++i)
        value |= std::uint64_t(b[at + i]) << (8 * i);
    return value;
}
} // namespace
bool parseInventory(const wire::Bytes &b, Inventory &out) {
    if (b.size() < 48 || b.size() > 32768 || !std::equal(b.begin(), b.begin() + 4, "GBD1") ||
        number(b, 4, 2) != 1 || number(b, 6, 2) != 0 || number(b, 8, 4) != b.size())
        return false;
    auto count = number(b, 12, 2);
    if (!count || count > 64 || number(b, 14, 2))
        return false;
    wire::Bytes hashed(b.begin(), b.end() - 32);
    auto hash = native::digest(hashed);
    if (!std::equal(hash.begin(), hash.end(), b.end() - 32))
        return false;
    Inventory records;
    std::set<std::wstring> folded;
    std::size_t at = 16;
    for (std::uint64_t i = 0; i < count; ++i) {
        if (at > hashed.size() || hashed.size() - at < 34)
            return false;
        auto size = number(b, at, 2);
        at += 2;
        wire::Digest digest{};
        std::copy_n(b.begin() + at, 32, digest.begin());
        at += 32;
        if (size > 128 || size > hashed.size() - at)
            return false;
        std::wstring file;
        for (std::size_t n = 0; n < size; ++n)
            file += wchar_t(b[at + n]);
        at += std::size_t(size);
        if (!name(file) || !folded.insert(lower(file)).second ||
            !records.emplace(file, digest).second)
            return false;
    }
    if (at != hashed.size())
        return false;
    out = std::move(records);
    return true;
}
bool Deployment::readFile(const std::filesystem::path &relative, wire::Bytes &out,
                          std::size_t cap) {
    auto path = root_ / relative;
    if (!name(relative.native()) || !native::fixedPath(path) || held_.size() >= 128)
        return false;
    native::Handle h(CreateFileW(path.c_str(), GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,
                                 FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    LARGE_INTEGER size{};
    if (!h || !native::protectedObject(h.value, false, false, true) ||
        !GetFileSizeEx(h.value, &size) || size.QuadPart < 0 || std::uint64_t(size.QuadPart) > cap)
        return false;
    wire::Bytes bytes(std::size_t(size.QuadPart));
    DWORD done = 0;
    if (!ReadFile(h.value, bytes.data(), DWORD(bytes.size()), &done, nullptr) ||
        done != bytes.size())
        return false;
    held_.push_back(std::move(h));
    out = std::move(bytes);
    return true;
}
bool Deployment::enumerate(const std::filesystem::path &relative, unsigned depth,
                           std::vector<std::wstring> &files) {
    if (depth > 4 || files.size() > 64 || held_.size() >= 128)
        return false;
    if (!relative.empty()) {
        native::Handle h(
            CreateFileW((root_ / relative).c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!h || !native::protectedObject(h.value, false, true, true))
            return false;
        held_.push_back(std::move(h));
    }
    WIN32_FIND_DATAW data{};
    auto found = FindFirstFileW((root_ / relative / L"*").c_str(), &data);
    if (found == INVALID_HANDLE_VALUE)
        return false;
    bool ok = true;
    do {
        std::wstring file = data.cFileName;
        if (file == L"." || file == L"..")
            continue;
        if (!name(file) || (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            ok = false;
            break;
        }
        auto next = relative / file;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!enumerate(next, depth + 1, files)) {
                ok = false;
                break;
            }
        } else {
            if (next.native() != L"deployment.gbd")
                files.push_back(next.native());
            if (files.size() > 64) {
                ok = false;
                break;
            }
        }
    } while (FindNextFileW(found, &data));
    auto error = GetLastError();
    FindClose(found);
    return ok && error == ERROR_NO_MORE_FILES;
}
bool Deployment::verify(const std::filesystem::path &own) {
    if (verified_ || own != root_ / L"GateBouncerDecisionBootstrap.exe" || !directory_.acquire())
        return false;
    wire::Bytes manifest;
    if (!readFile(L"deployment.gbd", manifest, 32768) || !parseInventory(manifest, inventory_))
        return false;
    const wchar_t *mandatory[] = {L"GateBouncerDecisionBootstrap.exe",
                                  L"GateBouncerDecisionStage.dll",
                                  L"Qt6Core.dll",
                                  L"Qt6Gui.dll",
                                  L"Qt6Widgets.dll",
                                  L"plugins\\platforms\\qwindows.dll",
                                  L"fonts\\Inter-Regular.ttf",
                                  L"fonts\\Inter-Medium.ttf",
                                  L"fonts\\Inter-SemiBold.ttf",
                                  L"qt.conf"};
    for (auto file : mandatory)
        if (!inventory_.count(file))
            return false;
    std::vector<std::wstring> files;
    if (!enumerate({}, 0, files) || files.size() != inventory_.size())
        return false;
    for (auto &file : files) {
        auto row = inventory_.find(file);
        wire::Bytes bytes;
        if (row == inventory_.end() || !readFile(file, bytes, 256 * 1024 * 1024) ||
            native::digest(bytes) != row->second)
            return false;
        if (file == L"qt.conf" &&
            bytes != wire::Bytes{'[', 'P', 'a', 't', 'h', 's',  ']', '\n', 'P', 'r', 'e',
                                 'f', 'i', 'x', '=', '.', '\n', 'P', 'l',  'u', 'g', 'i',
                                 'n', 's', '=', 'p', 'l', 'u',  'g', 'i',  'n', 's', '\n'})
            return false;
    }
    verified_ = true;
    return true;
}
bool Deployment::prepareEnvironment() {
    if (!verified_)
        return false;
    auto block = GetEnvironmentStringsW();
    if (!block)
        return false;
    std::vector<std::wstring> remove;
    for (auto line = block; *line; line += wcslen(line) + 1) {
        std::wstring s(line);
        auto equal = s.find(L'=');
        if (equal == std::wstring::npos || equal == 0)
            continue;
        auto key = s.substr(0, equal);
        auto folded = lower(key);
        if (folded.rfind(L"qt_", 0) == 0 || folded.rfind(L"qml", 0) == 0 ||
            folded.rfind(L"qtwebengine", 0) == 0)
            remove.push_back(key);
    }
    FreeEnvironmentStringsW(block);
    for (auto &key : remove)
        if (!SetEnvironmentVariableW(key.c_str(), nullptr))
            return false;
    wchar_t system[32768]{};
    auto size = GetSystemDirectoryW(system, 32768);
    if (!size || size >= 32768 || !SetEnvironmentVariableW(L"PATH", system) ||
        !SetCurrentDirectoryW(root_.c_str()) ||
        !SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS) ||
        !AddDllDirectory(root_.c_str()))
        return false;
    return SetEnvironmentVariableW(L"QT_PLUGIN_PATH", (root_ / L"plugins").c_str()) &&
           SetEnvironmentVariableW(L"QT_QPA_PLATFORM_PLUGIN_PATH",
                                   (root_ / L"plugins/platforms").c_str()) &&
           SetEnvironmentVariableW(L"QT_QPA_PLATFORM", L"windows") &&
           SetEnvironmentVariableW(L"QT_QPA_FONTDIR", (root_ / L"fonts").c_str());
}
} // namespace gb::controller
