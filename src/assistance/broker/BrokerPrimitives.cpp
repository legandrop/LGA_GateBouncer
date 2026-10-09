#include "BrokerPrimitives.h"
#include <aclapi.h>
#include <bcrypt.h>
#include <cstring>

namespace Gate::Assistance::Broker {
static bool tokenData(HANDLE token, TOKEN_INFORMATION_CLASS type, std::vector<unsigned char> &data) {
    DWORD count = 0; GetTokenInformation(token, type, nullptr, 0, &count);
    if (!count || count > 65536) return false;
    data.resize(count); return GetTokenInformation(token, type, data.data(), count, &count);
}
bool tokenIdentity(HANDLE process, TokenIdentity &out) {
    HANDLE raw = nullptr; if (!OpenProcessToken(process, TOKEN_QUERY, &raw)) return false;
    Handle token(raw);return identityFromToken(token.value,out);
}
bool identityFromToken(HANDLE token, TokenIdentity &out) {
    std::vector<unsigned char> user, groups, label;
    DWORD count = 0; TOKEN_ELEVATION elevated{}; TOKEN_ELEVATION_TYPE type{};
    if (!GetTokenInformation(token, TokenElevation, &elevated, sizeof(elevated), &count) ||
        !GetTokenInformation(token, TokenElevationType, &type, sizeof(type), &count) ||
        !GetTokenInformation(token, TokenSessionId, &out.session, sizeof(out.session), &count) ||
        !tokenData(token, TokenUser, user) || !tokenData(token, TokenGroups, groups) ||
        !tokenData(token, TokenIntegrityLevel, label)) return false;
    const PSID sid = reinterpret_cast<TOKEN_USER *>(user.data())->User.Sid;
    out.user.resize(GetLengthSid(sid)); if (!CopySid(DWORD(out.user.size()), out.user.data(), sid)) return false;
    const auto *list = reinterpret_cast<TOKEN_GROUPS *>(groups.data());
    for (DWORD i = 0; i < list->GroupCount; ++i) if ((list->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) {
        out.logon.resize(GetLengthSid(list->Groups[i].Sid));
        if (!CopySid(DWORD(out.logon.size()), out.logon.data(), list->Groups[i].Sid)) return false;
    }
    const PSID il = reinterpret_cast<TOKEN_MANDATORY_LABEL *>(label.data())->Label.Sid;
    const DWORD level = *GetSidSubAuthority(il, DWORD(*GetSidSubAuthorityCount(il) - 1));
    out.ordinary = !elevated.TokenIsElevated && type != TokenElevationTypeFull && level < SECURITY_MANDATORY_HIGH_RID;
    return !out.logon.empty();
}
bool sameIdentity(const TokenIdentity &a, const TokenIdentity &b) {
    return a.ordinary && b.ordinary && a.session == b.session && a.user == b.user && a.logon == b.logon;
}
bool processCreated(HANDLE process, quint64 &created) {
    FILETIME start{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(process, &start, &exit, &kernel, &user)) return false;
    created = (quint64(start.dwHighDateTime) << 32) | start.dwLowDateTime; return true;
}
bool randomId(Id &id) { return BCryptGenRandom(nullptr, id.data(), DWORD(id.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 && nonzero(id); }
bool nonzero(const Id &id) { unsigned char all = 0; for (auto b : id) all |= b; return all != 0; }
QString imagePath(HANDLE process) {
    std::array<wchar_t, 32768> buffer{}; DWORD count = DWORD(buffer.size());
    return QueryFullProcessImageNameW(process, 0, buffer.data(), &count) ? QString::fromWCharArray(buffer.data(), int(count)) : QString();
}
bool exactFileSecurity(HANDLE file, const TokenIdentity &identity) {
    PSID owner = nullptr; PACL acl = nullptr; PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        &owner, nullptr, &acl, nullptr, &sd) != ERROR_SUCCESS) return false;
    SECURITY_DESCRIPTOR_CONTROL control = 0; DWORD revision = 0;
    bool ok = owner && EqualSid(owner, const_cast<unsigned char *>(identity.user.data())) && acl &&
        GetSecurityDescriptorControl(sd, &control, &revision) && (control & SE_DACL_PROTECTED) && acl->AceCount == 2;
    unsigned char system[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(system); bool userFound = false, systemFound = false;
    ok = ok && CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &size);
    for (DWORD i = 0; ok && i < acl->AceCount; ++i) {
        void *raw = nullptr; ok = GetAce(acl, i, &raw);
        if (!ok) break;
        auto *ace = static_cast<ACCESS_ALLOWED_ACE *>(raw);
        ok = ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace->Header.AceFlags == 0 && ace->Mask == FILE_ALL_ACCESS;
        auto *sid = &ace->SidStart;
        if (EqualSid(sid, const_cast<unsigned char *>(identity.user.data()))) userFound = true;
        else if (EqualSid(sid, system)) systemFound = true; else ok = false;
    }
    if (sd) LocalFree(sd);
    return ok && userFound && systemFound;
}
}
