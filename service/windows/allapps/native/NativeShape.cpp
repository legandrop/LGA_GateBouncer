#include "NativeShape.h"
#include <cstring>

namespace gatebouncer::service::windows::allapps::native {
Guid guidBytes(const GUID& g) noexcept { Guid bytes{}; std::memcpy(bytes.data(), &g, sizeof(g)); return bytes; }
Layer logicalLayer(const Guid& key) noexcept
{
    if (key == guidBytes(FWPM_LAYER_ALE_AUTH_CONNECT_V4)) return Layer::ConnectV4;
    if (key == guidBytes(FWPM_LAYER_ALE_AUTH_CONNECT_V6)) return Layer::ConnectV6;
    if (key == guidBytes(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4)) return Layer::ReceiveV4;
    if (key == guidBytes(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6)) return Layer::ReceiveV6;
    return Layer::Unknown;
}
namespace {
Reason value(const FWP_CONDITION_VALUE0& v, ai::Bytes& bytes)
{
    const void* p = nullptr; std::size_t length = 0; FWP_BYTE_BLOB blob{}; std::uint8_t prefix[8]{};
    switch (v.type) {
    case FWP_EMPTY: break;
    case FWP_UINT8: p = &v.uint8; length = sizeof(v.uint8); break;
    case FWP_UINT16: p = &v.uint16; length = sizeof(v.uint16); break;
    case FWP_UINT32: p = &v.uint32; length = sizeof(v.uint32); break;
    case FWP_UINT64: p = v.uint64; length = sizeof(UINT64); break;
    case FWP_BYTE_ARRAY16_TYPE: p = v.byteArray16; length = sizeof(FWP_BYTE_ARRAY16); break;
    case FWP_BYTE_BLOB_TYPE: case FWP_SECURITY_DESCRIPTOR_TYPE:
        if (!guardedRead(&blob, v.type == FWP_SECURITY_DESCRIPTOR_TYPE ? v.sd : v.byteBlob, sizeof(blob))) return Reason::Unreadable;
        p = blob.data; length = blob.size; break;
    case FWP_SID:
        if (!guardedRead(prefix, v.sid, sizeof(prefix))) return Reason::Unreadable;
        if (prefix[0] != SID_REVISION || prefix[1] > SID_MAX_SUB_AUTHORITIES) return Reason::InvalidSid;
        p = v.sid; length = 8u + 4u * prefix[1]; break;
    default: return Reason::Unsupported;
    }
    if (length > MaxProofBytes) return Reason::Oversized;
    bytes.resize(length);
    if (length && !guardedRead(bytes.data(), p, length)) return Reason::Unreadable;
    if (v.type == FWP_SID && std::memcmp(prefix, bytes.data(), sizeof(prefix))) return Reason::InvalidSid;
    return Reason::None;
}
}
Reason copyFilterShape(const FWPM_FILTER0* borrowed, FilterShape& out) noexcept
{
    try {
        FWPM_FILTER0 f{}; GUID provider{}; FilterShape result;
        if (!guardedRead(&f, borrowed, sizeof(f)) || !guardedRead(&provider, f.providerKey, sizeof(provider))) return Reason::Unreadable;
        if (f.numFilterConditions > MaxConditions) return Reason::Oversized;
        if (f.flags & FWPM_FILTER_FLAG_DISABLED) return Reason::ForeignFilter;
        if ((f.action.type != FWP_ACTION_BLOCK && f.action.type != FWP_ACTION_PERMIT) ||
            (f.flags & ~(FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_BOOTTIME | FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT |
                         FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT | FWPM_FILTER_FLAG_INDEXED))) return Reason::Unsupported;
        result.key = guidBytes(f.filterKey); result.provider = guidBytes(provider); result.layer = guidBytes(f.layerKey);
        result.sublayer = guidBytes(f.subLayerKey); result.flags = f.flags; result.id = f.filterId;
        result.action = f.action.type; result.actionKey = guidBytes(f.action.filterType);
        if (f.flags & FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT) result.contextKey = guidBytes(f.providerContextKey);
        else result.rawContext = f.rawContext;
        result.weightType = f.weight.type;
        if (f.weight.type == FWP_UINT8) result.weight = f.weight.uint8;
        else if (f.weight.type == FWP_UINT64) { if (!guardedRead(&result.weight, f.weight.uint64, sizeof(result.weight))) return Reason::Unreadable; }
        else if (f.weight.type != FWP_EMPTY) return Reason::Unsupported;
        result.conditions.reserve(f.numFilterConditions);
        std::size_t charged = sizeof(result) + result.conditions.capacity() * sizeof(ConditionShape);
        if (charged > MaxProofBytes) return Reason::Oversized;
        for (UINT32 i = 0; i < f.numFilterConditions; ++i) {
            FWPM_FILTER_CONDITION0 c{}; ConditionShape owned;
            const auto base = reinterpret_cast<std::uintptr_t>(f.filterCondition), offset = sizeof(c) * i;
            if (!base || base > std::numeric_limits<std::uintptr_t>::max() - offset ||
                !guardedRead(&c, reinterpret_cast<const void*>(base + offset), sizeof(c))) return Reason::Unreadable;
            owned.key = guidBytes(c.fieldKey); owned.match = c.matchType; owned.type = c.conditionValue.type;
            const auto r = value(c.conditionValue, owned.bytes); if (r != Reason::None) return r;
            if (owned.bytes.capacity() > MaxProofBytes - charged) return Reason::Oversized;
            charged += owned.bytes.capacity(); result.conditions.push_back(std::move(owned));
        }
        out = std::move(result); return Reason::None;
    } catch (...) { return Reason::SourceGap; }
}
bool sameShape(const FilterShape& a, const FilterShape& b) noexcept
{
    if (a.key != b.key || a.provider != b.provider || a.sublayer != b.sublayer || a.layer != b.layer || a.id != b.id ||
        a.flags != b.flags || a.action != b.action || a.actionKey != b.actionKey || a.contextKey != b.contextKey ||
        a.rawContext != b.rawContext || a.weightType != b.weightType || a.weight != b.weight || a.conditions.size() != b.conditions.size()) return false;
    for (std::size_t i = 0; i < a.conditions.size(); ++i) {
        const auto& x = a.conditions[i]; const auto& y = b.conditions[i];
        if (x.key != y.key || x.match != y.match || x.type != y.type || x.bytes != y.bytes) return false;
    }
    return true;
}
} // namespace gatebouncer::service::windows::allapps::native
