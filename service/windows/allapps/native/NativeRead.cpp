#include "NativeRead.h"
#include <cstring>

namespace gatebouncer::service::windows::allapps::native {
bool guardedRead(void* out, const void* in, std::size_t length) noexcept
{
    if (!out || !in) return false;
    __try { std::memcpy(out, in, length); return true; }
    __except ((GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ||
               GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    { return false; }
}
namespace {
Reason sid(const SID* borrowed, std::array<std::uint8_t, ai::MaximumSidBytes>& bytes, FieldView& field) noexcept
{
    std::uint8_t prefix[8];
    if (!guardedRead(prefix, borrowed, sizeof(prefix))) return Reason::Unreadable;
    if (prefix[0] != SID_REVISION || prefix[1] > SID_MAX_SUB_AUTHORITIES) return Reason::InvalidSid;
    const auto length = 8u + 4u * prefix[1];
    if (!guardedRead(bytes.data(), borrowed, length)) return Reason::Unreadable;
    if (std::memcmp(prefix, bytes.data(), sizeof(prefix))) return Reason::InvalidSid;
    field = {bytes.data(), length, length}; return Reason::None;
}
}
Reason copySdk(const FWPM_NET_EVENT3* borrowed, SdkWorkspace& w, std::uint64_t received) noexcept
{
    FWPM_NET_EVENT3 e{};
    w.view = {};
    if (!guardedRead(&e, borrowed, sizeof(e))) return Reason::Unreadable;
    if (e.type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP && e.type != FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW)
        return Reason::Unsupported;
    auto& v = w.view; v.profile = 3; v.type = static_cast<std::uint32_t>(e.type);
    v.flags = e.header.flags; v.ipVersion = static_cast<std::uint32_t>(e.header.ipVersion);
    v.receivedMonotonic = received;
    const auto timestamp = (static_cast<std::uint64_t>(e.header.timeStamp.dwHighDateTime) << 32) | e.header.timeStamp.dwLowDateTime;
    if (timestamp) v.timestamp = timestamp;
    std::uint32_t reauth = 0;
    if (e.type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP) {
        FWPM_NET_EVENT_CLASSIFY_DROP2 c{};
        if (!guardedRead(&c, e.classifyDrop, sizeof(c))) return Reason::Unreadable;
        v.filterId = c.filterId; v.layerId = c.layerId; v.rawDirection = c.msFwpDirection;
        v.loopback = c.isLoopback != FALSE; reauth = c.reauthReason;
    } else {
        FWPM_NET_EVENT_CLASSIFY_ALLOW0 c{};
        if (!guardedRead(&c, e.classifyAllow, sizeof(c))) return Reason::Unreadable;
        v.filterId = c.filterId; v.layerId = c.layerId; v.rawDirection = c.msFwpDirection;
        v.loopback = c.isLoopback != FALSE; reauth = c.reauthReason;
    }
    v.classifyPresent = true; v.classifyType = v.type;
    if (v.flags & FWPM_NET_EVENT_FLAG_REAUTH_REASON_SET) v.reauth = reauth;
    const auto n = e.header.appId.size;
    if (!(v.flags & AppSet)) { if (n) return Reason::BadPresence; }
    else {
        if (n > w.app.size()) return Reason::Oversized;
        if (!n || !guardedRead(w.app.data(), e.header.appId.data, n)) return Reason::Unreadable;
        v.app = {w.app.data(), n, n};
    }
    auto result = v.flags & UserSet ? sid(e.header.userId, w.user, v.user) : Reason::None;
    if (result == Reason::None && (v.flags & PackageSet)) result = sid(e.header.packageSid, w.package, v.package);
    return result;
}
} // namespace gatebouncer::service::windows::allapps::native
