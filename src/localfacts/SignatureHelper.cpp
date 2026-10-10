#include "SignatureWire.h"
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <cerrno>
#include <cwchar>
#include <limits>

// Valor de WinTrust del SDK de Windows, ausente en algunos headers de MinGW.
#ifndef WTD_DISABLE_MD2_MD4
#define WTD_DISABLE_MD2_MD4 0x00002000
#endif

using gatebouncer::localfacts::detail::SignatureWire;
static bool parseHandle(const wchar_t* text, HANDLE& handle) {
    if (!text || !*text || *text == L'-' || *text == L'+') return false;
    for (auto p = text; *p; ++p) if (*p < L'0' || *p > L'9') return false;
    wchar_t* end = nullptr; errno = 0;
    auto value = wcstoull(text, &end, 10);
    if (errno || *end || !value || value >= std::numeric_limits<std::uintptr_t>::max()) return false;
    handle = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value)); return true;
}
int wmain(int argc, wchar_t** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)) return 1;
    HANDLE file = nullptr, mapping = nullptr;
    if (argc != 3 || !parseHandle(argv[1], file) || !parseHandle(argv[2], mapping) || file == mapping) return 1;
    auto wire = static_cast<SignatureWire*>(MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(SignatureWire)));
    if (!wire) return 1;
    SignatureWire response{};
    response.magic = gatebouncer::localfacts::detail::wireMagic;
    wchar_t path[512]{};
    auto count = GetFinalPathNameByHandleW(file, path, 512, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!count || count >= 512 || GetFileType(file) != FILE_TYPE_DISK) {
        *wire = response; UnmapViewOfFile(wire); return 0;
    }
    // Sin resolución por PATH ni directorio del binario; la entrada no se ejecuta.
    HMODULE trust = LoadLibraryExW(L"wintrust.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    HMODULE crypto = LoadLibraryExW(L"crypt32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!trust || !crypto) { *wire = response; UnmapViewOfFile(wire); return 0; }
    auto verify = reinterpret_cast<decltype(&WinVerifyTrust)>(GetProcAddress(trust, "WinVerifyTrust"));
    auto provider = reinterpret_cast<decltype(&WTHelperProvDataFromStateData)>(GetProcAddress(trust, "WTHelperProvDataFromStateData"));
    auto signer = reinterpret_cast<decltype(&WTHelperGetProvSignerFromChain)>(GetProcAddress(trust, "WTHelperGetProvSignerFromChain"));
    auto name = reinterpret_cast<decltype(&CertGetNameStringW)>(GetProcAddress(crypto, "CertGetNameStringW"));
    if (!verify || !provider || !signer || !name) { *wire = response; UnmapViewOfFile(wire); return 0; }
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN)) { *wire = response; UnmapViewOfFile(wire); return 0; }
    WINTRUST_FILE_INFO info{}; info.cbStruct = sizeof(info); info.pcwszFilePath = path; info.hFile = file;
    WINTRUST_DATA data{}; data.cbStruct = sizeof(data); data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE; data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &info; data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE | WTD_DISABLE_MD2_MD4;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = verify(nullptr, &action, &data);
    response.nativeStatus = status;
    if (status == ERROR_SUCCESS) {
        response.state = 0;
        auto p = provider(data.hWVTStateData);
        auto s = p ? signer(p, 0, FALSE, 0) : nullptr;
        if (s && s->csCertChain && s->pasCertChain[0].pCert) {
            const auto required = name(s->pasCertChain[0].pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
            if (required > 1 && required <= 256) {
                const auto actual = name(s->pasCertChain[0].pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                                        response.publisher, 256);
                if (actual == required) response.publisherLength = actual - 1;
            }
        }
    } else if (status == TRUST_E_NOSIGNATURE) response.state = 1;
    else if (status == TRUST_E_BAD_DIGEST || status == TRUST_E_EXPLICIT_DISTRUST
        || status == CERT_E_REVOKED || status == TRUST_E_SUBJECT_NOT_TRUSTED
        || status == CERT_E_EXPIRED || status == CERT_E_WRONG_USAGE) response.state = 2;
    // Cadena/raíz/cache desconocidas continúan Unavailable, nunca se certifican.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    verify(nullptr, &action, &data);
    *wire = response;
    UnmapViewOfFile(wire); FreeLibrary(crypto); FreeLibrary(trust);
    return 0;
}
