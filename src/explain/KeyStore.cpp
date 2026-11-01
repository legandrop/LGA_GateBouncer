#include "KeyStore.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <dpapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <vector>

namespace Gate::Explain {
namespace {
// Entropía fija: un blob de DPAPI de otra app de esta cuenta no se descifra acá por error.
constexpr char Entropy[] = "LGA.GateBouncer.NvidiaKey.v1";
constexpr wchar_t FileName[] = L"\\nvidia.key";

std::wstring folderPath() {
    PWSTR base = nullptr;
    std::wstring out;
    if (SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &base) == S_OK)
        out = std::wstring(base) + L"\\LGA\\GateBouncer\\Explain";
    CoTaskMemFree(base);
    return out;
}

std::wstring userSid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return {};
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    std::wstring out;
    if (size && GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
        LPWSTR text = nullptr;
        if (ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(buffer.data())->User.Sid, &text)) {
            out = text;
            LocalFree(text);
        }
    }
    CloseHandle(token);
    return out;
}

bool isReparse(const std::wstring &path) {
    const DWORD a = GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_REPARSE_POINT);
}

// Crea la carpeta (y las de arriba) y le deja permisos sólo de esta cuenta y SYSTEM, sin herencia.
bool ensureFolder(const std::wstring &dir, QString &error) {
    if (dir.empty()) {
        error = "The local application data folder is not available.";
        return false;
    }
    std::wstring partial;
    for (std::size_t i = 0; i <= dir.size(); ++i) {
        if (i == dir.size() || (dir[i] == L'\\' && i > 2)) {
            partial = dir.substr(0, i);
            if (!CreateDirectoryW(partial.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
                error = "Could not create the key folder.";
                return false;
            }
        }
    }
    if (isReparse(dir)) {
        error = "The key folder is a link to another place; the key was not saved.";
        return false;
    }
    const std::wstring sid = userSid();
    if (sid.empty()) {
        error = "Could not read the current account.";
        return false;
    }
    const std::wstring sddl = L"D:P(A;OICI;FA;;;" + sid + L")(A;OICI;FA;;;SY)";
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
        error = "Could not prepare the key folder permissions.";
        return false;
    }
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = nullptr;
    GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted);
    const DWORD r = SetNamedSecurityInfoW(const_cast<LPWSTR>(dir.c_str()), SE_FILE_OBJECT,
                                          DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr,
                                          nullptr, dacl, nullptr);
    LocalFree(sd);
    if (r != ERROR_SUCCESS) {
        error = "Could not restrict the key folder to this account.";
        return false;
    }
    return true;
}

DATA_BLOB entropyBlob() {
    return DATA_BLOB{DWORD(sizeof(Entropy) - 1), reinterpret_cast<BYTE *>(const_cast<char *>(Entropy))};
}
} // namespace

QString KeyStore::folder() { return QString::fromStdWString(folderPath()); }

bool KeyStore::plausible(const QString &key) {
    if (!key.startsWith("nvapi-") || key.size() < 20 || key.size() > 200) return false;
    for (const QChar c : key)
        if (c.unicode() <= 0x20 || c.unicode() >= 0x7f) return false;
    return true;
}

bool KeyStore::has() {
    const std::wstring file = folderPath() + FileName;
    const DWORD a = GetFileAttributesW(file.c_str());
    return !folderPath().empty() && a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

bool KeyStore::save(const QString &key, QString &error) {
    if (!plausible(key)) {
        error = "This does not look like an NVIDIA API key (it starts with nvapi-).";
        return false;
    }
    const std::wstring dir = folderPath();
    if (!ensureFolder(dir, error)) return false;
    std::string plain = key.toStdString();
    DATA_BLOB in{DWORD(plain.size()), reinterpret_cast<BYTE *>(plain.data())};
    DATA_BLOB entropy = entropyBlob();
    DATA_BLOB out{};
    const BOOL sealed = CryptProtectData(&in, L"LGA GateBouncer NVIDIA key", &entropy, nullptr, nullptr,
                                         CRYPTPROTECT_UI_FORBIDDEN, &out);
    SecureZeroMemory(plain.data(), plain.size());
    if (!sealed) {
        error = "Windows could not encrypt the key.";
        return false;
    }
    const std::wstring file = dir + FileName, temp = file + L".tmp";
    HANDLE h = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD written = 0;
    const bool ok = h != INVALID_HANDLE_VALUE && WriteFile(h, out.pbData, out.cbData, &written, nullptr) &&
                    written == out.cbData && FlushFileBuffers(h);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    LocalFree(out.pbData);
    if (!ok || !MoveFileExW(temp.c_str(), file.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temp.c_str());
        error = "Could not save the key file.";
        return false;
    }
    return true;
}

bool KeyStore::clear(QString &error) {
    const std::wstring file = folderPath() + FileName;
    if (!DeleteFileW(file.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) {
        error = "Could not remove the key file.";
        return false;
    }
    return true;
}

bool KeyStore::withKey(const std::function<void(const std::string &)> &use, QString &error) {
    const std::wstring dir = folderPath();
    if (dir.empty() || isReparse(dir)) {
        error = "No NVIDIA API key is saved.";
        return false;
    }
    HANDLE h = CreateFileW((dir + FileName).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        error = "No NVIDIA API key is saved.";
        return false;
    }
    LARGE_INTEGER size{};
    std::vector<BYTE> blob;
    DWORD read = 0;
    const bool ok = GetFileSizeEx(h, &size) && size.QuadPart > 0 && size.QuadPart < 64 * 1024 &&
                    (blob.resize(std::size_t(size.QuadPart)), ReadFile(h, blob.data(), DWORD(blob.size()), &read, nullptr)) &&
                    read == blob.size();
    CloseHandle(h);
    if (!ok) {
        error = "The saved key could not be read.";
        return false;
    }
    DATA_BLOB in{DWORD(blob.size()), blob.data()};
    DATA_BLOB entropy = entropyBlob();
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        error = "The saved key belongs to another Windows account or is damaged. Save it again.";
        return false;
    }
    std::string key(reinterpret_cast<const char *>(out.pbData), out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    use(key);
    SecureZeroMemory(key.data(), key.size());
    return true;
}

} // namespace Gate::Explain
