#include "signature.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>
#include <shlobj.h>
#include <vector>
#include <string>

namespace gbe {
namespace {

// Apps de la Store y paquetes MSIX: vienen firmados como paquete, no en cada exe. Windows verifica esa firma al
// instalar y la carpeta WindowsApps sólo la escribe el sistema, así que un exe que de verdad vive ahí (ruta final
// del archivo abierto, no la que se pidió, para que un enlace no engañe) toma como firmante el editor del paquete,
// leído del AppxManifest.xml de la raíz del paquete. Sólo la WindowsApps de Program Files.
std::wstring packagePublisherOf(const std::wstring &path) {
    PWSTR programFiles = nullptr;
    std::wstring apps;
    if (SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, nullptr, &programFiles) == S_OK)
        apps = std::wstring(programFiles) + L"\\WindowsApps\\";
    CoTaskMemFree(programFiles);
    if (apps.size() < 16) return {};
    HANDLE file = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    wchar_t final[MAX_PATH * 2] = {};
    const DWORD n = GetFinalPathNameByHandleW(file, final, DWORD(std::size(final)), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    CloseHandle(file);
    if (n == 0 || n >= std::size(final)) return {};
    std::wstring real(final, n);
    if (real.rfind(L"\\\\?\\", 0) == 0) real.erase(0, 4);
    if (real.size() <= apps.size() ||
        CompareStringOrdinal(real.c_str(), int(apps.size()), apps.c_str(), int(apps.size()), TRUE) != CSTR_EQUAL)
        return {};
    const std::size_t rootEnd = real.find(L'\\', apps.size());
    if (rootEnd == std::wstring::npos) return {};
    HANDLE manifest = CreateFileW((real.substr(0, rootEnd) + L"\\AppxManifest.xml").c_str(), GENERIC_READ,
                                  FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (manifest == INVALID_HANDLE_VALUE) return {};
    std::string xml(256 * 1024, '\0');
    DWORD read = 0;
    const BOOL ok = ReadFile(manifest, xml.data(), DWORD(xml.size()), &read, nullptr);
    CloseHandle(manifest);
    if (!ok) return {};
    xml.resize(read);
    // <Identity Name="..." Publisher="CN=Microsoft Corporation, O=..., C=US" .../>: el CN es el editor.
    const std::size_t identity = xml.find("<Identity ");
    const std::size_t attribute = identity == std::string::npos ? identity : xml.find(" Publisher=\"", identity);
    const std::size_t close = identity == std::string::npos ? identity : xml.find('>', identity);
    if (attribute == std::string::npos || attribute > close) return {};
    const std::size_t start = attribute + 12, end = xml.find('"', start);
    if (end == std::string::npos) return {};
    std::string publisher = xml.substr(start, end - start);
    // Entidades de XML primero (&quot; &amp; ...), &amp; al final para no decodificar dos veces.
    const auto replaceAll = [&publisher](const std::string &from, const std::string &to) {
        for (std::size_t at = publisher.find(from); at != std::string::npos; at = publisher.find(from, at + to.size()))
            publisher.replace(at, from.size(), to);
    };
    replaceAll("&quot;", "\"");
    replaceAll("&apos;", "'");
    replaceAll("&lt;", "<");
    replaceAll("&gt;", ">");
    replaceAll("&amp;", "&");
    if (publisher.rfind("CN=", 0) != 0) return {};
    // Un CN con coma va entre comillas (CN="Dropbox, Inc", O=...); si no, termina en la primera coma.
    if (publisher.size() > 3 && publisher[3] == '"') {
        const std::size_t quote = publisher.find('"', 4);
        if (quote == std::string::npos) return {};
        publisher = publisher.substr(4, quote - 4);
    } else {
        publisher = publisher.substr(3, publisher.find(',') == std::string::npos ? std::string::npos : publisher.find(',') - 3);
    }
    if (publisher.empty() || publisher.size() > 200) return {};
    const int wide = MultiByteToWideChar(CP_UTF8, 0, publisher.data(), int(publisher.size()), nullptr, 0);
    std::wstring name(std::size_t(wide > 0 ? wide : 0), L'\0');
    if (wide > 0) MultiByteToWideChar(CP_UTF8, 0, publisher.data(), int(publisher.size()), name.data(), wide);
    return name;
}

// Corre WinVerifyTrust con lo que se le pase (archivo o catálogo) y devuelve el CN del firmante si la firma es válida.
std::wstring verifiedSigner(WINTRUST_DATA &data) {
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    // Sin red: el motor verifica dentro del aviso de bloqueo y no puede esperar descargas de listas de revocación.
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
    const LONG trust = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &data);
    std::wstring name;
    if (trust == ERROR_SUCCESS) {
        CRYPT_PROVIDER_DATA *provider = WTHelperProvDataFromStateData(data.hWVTStateData);
        CRYPT_PROVIDER_SGNR *signer = provider ? WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : nullptr;
        if (signer && signer->csCertChain && signer->pasCertChain && signer->pasCertChain[0].pCert) {
            wchar_t buffer[256] = {};
            if (CertGetNameStringW(signer->pasCertChain[0].pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buffer,
                                   DWORD(std::size(buffer))) > 1)
                name = buffer;
        }
    }
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &data);
    return name;
}

// Herramientas de Windows firmadas por catálogo (powershell.exe, certutil.exe): el hash del archivo figura en un .cat
// firmado del sistema. Se calcula sobre el archivo abierto sin permitir escrituras, así que se verifica lo mismo que
// se leyó.
std::wstring catalogSignerOf(const std::wstring &path) {
    HCATADMIN admin = nullptr;
    if (!CryptCATAdminAcquireContext2(&admin, nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) return {};
    std::wstring name;
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    std::vector<BYTE> hash;
    if (file != INVALID_HANDLE_VALUE) {
        DWORD size = 0;
        CryptCATAdminCalcHashFromFileHandle2(admin, file, &size, nullptr, 0);
        hash.resize(size);
        if (size == 0 || !CryptCATAdminCalcHashFromFileHandle2(admin, file, &size, hash.data(), 0)) hash.clear();
        CloseHandle(file);
    }
    HCATINFO catalog = hash.empty() ? nullptr
                                    : CryptCATAdminEnumCatalogFromHash(admin, hash.data(), DWORD(hash.size()), 0, nullptr);
    if (catalog) {
        CATALOG_INFO info{};
        info.cbStruct = sizeof(info);
        if (CryptCATCatalogInfoFromContext(catalog, &info, 0)) {
            std::wstring tag;
            wchar_t hex[3];
            for (const BYTE b : hash) {
                swprintf(hex, 3, L"%02X", b);
                tag += hex;
            }
            WINTRUST_CATALOG_INFO member{};
            member.cbStruct = sizeof(member);
            member.pcwszCatalogFilePath = info.wszCatalogFile;
            member.pcwszMemberFilePath = path.c_str();
            member.pcwszMemberTag = tag.c_str();
            member.pbCalculatedFileHash = hash.data();
            member.cbCalculatedFileHash = DWORD(hash.size());
            member.hCatAdmin = admin;
            WINTRUST_DATA data{};
            data.dwUnionChoice = WTD_CHOICE_CATALOG;
            data.pCatalog = &member;
            name = verifiedSigner(data);
        }
        CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
    }
    CryptCATAdminReleaseContext(admin, 0);
    return name;
}

} // namespace

std::wstring signerOf(const std::wstring &path) {
    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = path.c_str();
    WINTRUST_DATA data{};
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file;
    std::wstring name = verifiedSigner(data);
    if (name.empty()) name = catalogSignerOf(path);
    if (name.empty()) name = packagePublisherOf(path);
    // Un nombre con tabuladores o saltos rompería rules.tsv y el canal: se trata como sin firma.
    if (name.find_first_of(L"\t\r\n|") != std::wstring::npos) name.clear();
    return name;
}

bool publisherRuleAllowed(const std::wstring &signer) {
    return !signer.empty() && CompareStringOrdinal(signer.c_str(), signer.size() < 9 ? int(signer.size()) : 9,
                                                   L"Microsoft", 9, TRUE) != CSTR_EQUAL;
}

} // namespace gbe
