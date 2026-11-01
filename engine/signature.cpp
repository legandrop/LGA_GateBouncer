#include "signature.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

namespace gbe {

std::wstring signerOf(const std::wstring &path) {
    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = path.c_str();
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file;
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
    // Un nombre con tabuladores o saltos rompería rules.tsv y el canal: se trata como sin firma.
    if (name.find_first_of(L"\t\r\n|") != std::wstring::npos) name.clear();
    return name;
}

bool publisherRuleAllowed(const std::wstring &signer) {
    return !signer.empty() && CompareStringOrdinal(signer.c_str(), signer.size() < 9 ? int(signer.size()) : 9,
                                                   L"Microsoft", 9, TRUE) != CSTR_EQUAL;
}

} // namespace gbe
