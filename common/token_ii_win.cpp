#include "token_ii_win.h"
#include <algorithm>
#include <sddl.h>

namespace gb::native {
wire::Bytes tokenData(HANDLE h, TOKEN_INFORMATION_CLASS kind) {
    DWORD size = 0;
    GetTokenInformation(h, kind, nullptr, 0, &size);
    if (!size || size > 65536)
        return {};
    wire::Bytes b(size);
    if (!GetTokenInformation(h, kind, b.data(), size, &size))
        return {};
    b.resize(size);
    return b;
}
namespace {
wire::Bytes sidCopy(PSID sid) {
    if (!sid || !IsValidSid(sid))
        return {};
    auto n = GetLengthSid(sid);
    if (n > SECURITY_MAX_SID_SIZE)
        return {};
    auto p = static_cast<const std::uint8_t *>(sid);
    return {p, p + n};
}
bool sidShape(const wire::Bytes &s) {
    return s.size() >= 8 && s[0] == 1 && s[1] <= 15 && s.size() == 8 + std::size_t(s[1]) * 4;
}
} // namespace
bool equalSidBytes(const wire::Bytes &a, const wire::Bytes &b) {
    return sidShape(a) && sidShape(b) &&
           EqualSid(const_cast<std::uint8_t *>(a.data()), const_cast<std::uint8_t *>(b.data()));
}
wire::Id sidKey(const wire::Bytes &sid) {
    wire::Id out{};
    if (!sidShape(sid))
        return out;
    auto hash = digest(sid);
    std::copy_n(hash.begin(), 16, out.begin());
    return out;
}
std::wstring sidString(const wire::Bytes &sid) {
    if (!sidShape(sid))
        return {};
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(const_cast<std::uint8_t *>(sid.data()), &text))
        return {};
    std::wstring out(text);
    LocalFree(text);
    return out;
}
bool tokenEvidence(HANDLE h, TokenEvidence &out) {
    auto user = tokenData(h, TokenUser), groups = tokenData(h, TokenGroups),
         session = tokenData(h, TokenSessionId), il = tokenData(h, TokenIntegrityLevel),
         elevation = tokenData(h, TokenElevation), ui = tokenData(h, TokenUIAccess);
    if (user.size() < sizeof(TOKEN_USER) || groups.size() < sizeof(TOKEN_GROUPS) ||
        session.size() != 4 || il.size() < sizeof(TOKEN_MANDATORY_LABEL) ||
        elevation.size() != sizeof(TOKEN_ELEVATION) || ui.size() != 4)
        return false;
    TokenEvidence e;
    e.account = sidCopy(reinterpret_cast<TOKEN_USER *>(user.data())->User.Sid);
    e.session = *reinterpret_cast<DWORD *>(session.data());
    auto level = reinterpret_cast<TOKEN_MANDATORY_LABEL *>(il.data())->Label.Sid;
    if (!IsValidSid(level) || !*GetSidSubAuthorityCount(level))
        return false;
    e.integrity = *GetSidSubAuthority(level, *GetSidSubAuthorityCount(level) - 1);
    e.elevated = reinterpret_cast<TOKEN_ELEVATION *>(elevation.data())->TokenIsElevated != 0;
    e.uiAccess = *reinterpret_cast<DWORD *>(ui.data()) != 0;
    BYTE ba[SECURITY_MAX_SID_SIZE]{};
    DWORD size = sizeof(ba);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, ba, &size))
        return false;
    auto list = reinterpret_cast<TOKEN_GROUPS *>(groups.data());
    if (list->GroupCount > 4096 ||
        groups.size() < offsetof(TOKEN_GROUPS, Groups) +
                            std::size_t(list->GroupCount) * sizeof(SID_AND_ATTRIBUTES))
        return false;
    for (DWORD i = 0; i < list->GroupCount; ++i) {
        auto &g = list->Groups[i];
        if ((g.Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) {
            if (!e.logon.empty())
                return false;
            e.logon = sidCopy(g.Sid);
        }
        if ((g.Attributes & SE_GROUP_ENABLED) && !(g.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) &&
            EqualSid(g.Sid, ba))
            e.administrator = true;
    }
    if (e.account.empty() || e.logon.empty())
        return false;
    out = std::move(e);
    return true;
}
bool systemServiceToken(HANDLE token, const wchar_t *serviceName) {
    auto user = tokenData(token, TokenUser), groups = tokenData(token, TokenGroups);
    if (user.size() < sizeof(TOKEN_USER) || groups.size() < sizeof(TOKEN_GROUPS))
        return false;
    BYTE sy[SECURITY_MAX_SID_SIZE]{}, service[SECURITY_MAX_SID_SIZE]{};
    DWORD n = sizeof(sy);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, sy, &n) ||
        !EqualSid(reinterpret_cast<TOKEN_USER *>(user.data())->User.Sid, sy))
        return false;
    wchar_t domain[256]{};
    DWORD sidSize = sizeof(service), domainSize = 256;
    SID_NAME_USE use{};
    if (!serviceName || (wcscmp(serviceName,L"LGAGateBouncer") && wcscmp(serviceName,L"LGAGateBouncerLab"))) return false;
    const auto principal = std::wstring(L"NT SERVICE\\") + serviceName;
    if (!LookupAccountNameW(L".", principal.c_str(), service, &sidSize, domain,
                            &domainSize, &use))
        return false;
    auto list = reinterpret_cast<TOKEN_GROUPS *>(groups.data());
    if (list->GroupCount > 4096 ||
        groups.size() < offsetof(TOKEN_GROUPS, Groups) +
                            std::size_t(list->GroupCount) * sizeof(SID_AND_ATTRIBUTES))
        return false;
    for (DWORD i = 0; i < list->GroupCount; ++i) {
        auto &g = list->Groups[i];
        if ((g.Attributes & SE_GROUP_ENABLED) && !(g.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) &&
            EqualSid(g.Sid, service))
            return true;
    }
    return false;
}
bool ProcessEvidence::acquire(DWORD id) {
    process.reset(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, id));
    if (!process)
        return false;
    FILETIME exit{}, kernel{}, user{};
    wchar_t path[32768]{};
    DWORD n = 32768;
    if (!GetProcessTimes(process.value, &created, &exit, &kernel, &user) ||
        !QueryFullProcessImageNameW(process.value, 0, path, &n) || !n || n >= 32768)
        return false;
    pid = id;
    image = std::filesystem::path(std::wstring(path, n));
    return fixedPath(image) && current();
}
bool ProcessEvidence::current() const {
    FILETIME c{}, exit{}, kernel{}, user{};
    return process && WaitForSingleObject(process.value, 0) == WAIT_TIMEOUT &&
           GetProcessTimes(process.value, &c, &exit, &kernel, &user) &&
           CompareFileTime(&c, &created) == 0;
}
} // namespace gb::native
