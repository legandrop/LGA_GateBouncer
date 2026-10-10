#pragma once
#include "protected_file_win.h"
#include <string>

namespace gb::native {
struct TokenEvidence {
    wire::Bytes account, logon;
    DWORD session = 0, integrity = 0;
    bool administrator = false, elevated = false, uiAccess = false;
};
wire::Bytes tokenData(HANDLE token, TOKEN_INFORMATION_CLASS kind);
bool tokenEvidence(HANDLE token, TokenEvidence &evidence);
bool equalSidBytes(const wire::Bytes &a, const wire::Bytes &b);
wire::Id sidKey(const wire::Bytes &sid);
std::wstring sidString(const wire::Bytes &sid);
bool systemServiceToken(HANDLE token, const wchar_t *serviceName = L"LGAGateBouncerLab");
struct ProcessEvidence {
    Handle process;
    DWORD pid = 0;
    FILETIME created{};
    std::filesystem::path image;
    bool acquire(DWORD processId);
    bool current() const;
};
} // namespace gb::native
