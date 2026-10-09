#include "profile_ii.h"
#include <wtsapi32.h>

namespace gb::decisions {
bool NativeProfile::refresh() {
    PWTS_SESSION_INFOW sessions = nullptr;
    DWORD count = 0;
    bool complete =
        WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count) != FALSE &&
        count <= 1024;
    unsigned matched = 0;
    Bytes logon;
    DWORD session = 0;
    bool active = false;
    for (DWORD i = 0; complete && i < count; ++i) {
        LPWSTR username = nullptr;
        DWORD n = 0;
        if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId,
                                         WTSUserName, &username, &n)) {
            complete = false;
            break;
        }
        bool logged = username && n >= 2 && *username;
        WTSFreeMemory(username);
        if (!logged)
            continue;
        native::Handle token;
        HANDLE raw = nullptr;
        if (!WTSQueryUserToken(sessions[i].SessionId, &raw)) {
            complete = false;
            break;
        }
        token.reset(raw);
        native::TokenEvidence evidence;
        if (!native::tokenEvidence(token.value, evidence)) {
            complete = false;
            break;
        }
        if (!native::equalSidBytes(evidence.account, account_))
            continue;
        ++matched;
        LPWSTR info = nullptr;
        DWORD bytes = 0;
        if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId,
                                         WTSSessionInfoEx, &info, &bytes) ||
            bytes < sizeof(WTSINFOEXW)) {
            if (info)
                WTSFreeMemory(info);
            complete = false;
            break;
        }
        auto ex = reinterpret_cast<WTSINFOEXW *>(info);
        bool unlocked =
            ex->Level == 1 && ex->Data.WTSInfoExLevel1.SessionFlags == WTS_SESSIONSTATE_UNLOCK;
        WTSFreeMemory(info);
        active = sessions[i].State == WTSActive && unlocked;
        logon = evidence.logon;
        session = evidence.session;
    }
    if (sessions)
        WTSFreeMemory(sessions);
    auto state = std::uint8_t(!complete ? 0 : matched > 1 ? 2 : matched == 1 && active ? 1 : 0);
    bool changed = state != profile_.state || session != session_ || logon != logon_;
    if (changed) {
        if (profile_.generation == UINT64_MAX) {
            profile_.state = 0;
            return false;
        }
        ++profile_.generation;
    }
    profile_.state = state;
    session_ = session;
    logon_ = std::move(logon);
    profile_.account = native::sidKey(account_);
    profile_.logon = native::sidKey(logon_);
    return state == 1;
}
bool NativeProfile::accepts(const native::TokenEvidence &peer, bool control) const {
    return profile_.state == 1 && native::equalSidBytes(peer.account, account_) &&
           native::equalSidBytes(peer.logon, logon_) && peer.session == session_ &&
           peer.integrity >= SECURITY_MANDATORY_MEDIUM_RID &&
           (!control || (peer.integrity >= SECURITY_MANDATORY_HIGH_RID && peer.administrator &&
                         peer.elevated && !peer.uiAccess));
}
VerifiedControl NativeProfile::authority(const native::TokenEvidence &peer, bool full) const {
    VerifiedControl out;
    out.account = profile_.account;
    out.logon = profile_.logon;
    out.profileGeneration = profile_.generation;
    out.highAdministrator = accepts(peer, true);
    out.fullServerToken = full;
    out.accountSid = peer.account;
    out.logonSid = peer.logon;
    out.sessionId = peer.session;
    return out;
}
} // namespace gb::decisions
