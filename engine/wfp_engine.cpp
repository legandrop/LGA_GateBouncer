#include "wfp_engine.h"
#include <ws2tcpip.h>
#include <sddl.h>
#include <cstring>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

namespace gbe {
namespace {

// Identidades propias. Distintas de las del motor anterior con driver para que nunca se mezclen.
const GUID ProviderKey = {0x5b1d6a2e, 0x3c47, 0x4e1f, {0x9a, 0x61, 0x2d, 0x8e, 0x77, 0x40, 0xc3, 0x15}};
const GUID SublayerKey = {0x7f2c9b10, 0x84d3, 0x4a6e, {0xb2, 0x05, 0x6c, 0x1f, 0x93, 0xe8, 0x5a, 0x27}};

// Pesos dentro de la subcapa propia: gana el mayor.
constexpr std::uint8_t WeightDefaultBlock = 1;
constexpr std::uint8_t WeightSystem = 14;

std::vector<GUID> layersFor(Direction direction) {
    std::vector<GUID> layers;
    if (direction != Direction::Inbound) {
        layers.push_back(FWPM_LAYER_ALE_AUTH_CONNECT_V4);
        layers.push_back(FWPM_LAYER_ALE_AUTH_CONNECT_V6);
    }
    if (direction != Direction::Outbound) {
        layers.push_back(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4);
        layers.push_back(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
    }
    return layers;
}

std::wstring formatAddress(const FWPM_NET_EVENT_HEADER1 &h) {
    wchar_t text[INET6_ADDRSTRLEN] = {};
    if (h.ipVersion == FWP_IP_VERSION_V4) {
        in_addr a{};
        a.S_un.S_addr = htonl(h.remoteAddrV4);
        InetNtopW(AF_INET, &a, text, INET6_ADDRSTRLEN);
    } else if (h.ipVersion == FWP_IP_VERSION_V6) {
        in6_addr a{};
        std::memcpy(&a, h.remoteAddrV6.byteArray16, 16);
        InetNtopW(AF_INET6, &a, text, INET6_ADDRSTRLEN);
    }
    return text;
}

} // namespace

WfpEngine::~WfpEngine() { close(); }

std::wstring WfpEngine::errorText(DWORD code) {
    wchar_t *buffer = nullptr;
    HMODULE fwp = GetModuleHandleW(L"fwpuclnt.dll");
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    if (fwp) flags |= FORMAT_MESSAGE_FROM_HMODULE;
    FormatMessageW(flags, fwp, code, 0, reinterpret_cast<wchar_t *>(&buffer), 0, nullptr);
    std::wstring text = buffer ? buffer : L"";
    if (buffer) LocalFree(buffer);
    while (!text.empty() && (text.back() == L'\n' || text.back() == L'\r')) text.pop_back();
    wchar_t hex[16];
    swprintf_s(hex, L"0x%08X", code);
    return text.empty() ? hex : text + L" (" + hex + L")";
}

bool WfpEngine::open(bool dynamic, std::wstring &error) {
    close();
    FWPM_SESSION0 session{};
    session.displayData.name = const_cast<wchar_t *>(L"LGA GateBouncer");
    session.flags = dynamic ? FWPM_SESSION_FLAG_DYNAMIC : 0;
    // Sin espera indefinida por la transacción de otro proveedor.
    session.txnWaitTimeoutInMSec = 5000;
    const DWORD r = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine_);
    if (r != ERROR_SUCCESS) {
        engine_ = nullptr;
        error = L"FwpmEngineOpen0: " + errorText(r);
        return false;
    }
    dynamic_ = dynamic;
    return true;
}

void WfpEngine::close() {
    unsubscribe();
    if (engine_ && txnDepth_ > 0) FwpmTransactionAbort0(engine_);
    txnDepth_ = 0;
    untrackOnCommit_.clear();
    if (engine_) {
        if (restoreCollection_) {
            FWP_VALUE0 off{};
            off.type = FWP_UINT32;
            off.uint32 = 0;
            FwpmEngineSetOption0(engine_, FWPM_ENGINE_COLLECT_NET_EVENTS, &off);
            restoreCollection_ = false;
        }
        FwpmEngineClose0(engine_);
        engine_ = nullptr;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    ownFilters_.clear();
}

bool WfpEngine::ensureObjects(std::wstring &error) {
    const DWORD persistent = dynamic_ ? 0 : 1;
    FWPM_PROVIDER0 provider{};
    provider.providerKey = ProviderKey;
    provider.displayData.name = const_cast<wchar_t *>(L"LGA GateBouncer");
    provider.displayData.description = const_cast<wchar_t *>(L"Per-application firewall rules");
    provider.flags = persistent ? FWPM_PROVIDER_FLAG_PERSISTENT : 0;
    DWORD r = FwpmProviderAdd0(engine_, &provider, nullptr);
    if (r != ERROR_SUCCESS && r != FWP_E_ALREADY_EXISTS) {
        error = L"FwpmProviderAdd0: " + errorText(r);
        return false;
    }
    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = SublayerKey;
    sublayer.displayData.name = const_cast<wchar_t *>(L"LGA GateBouncer");
    sublayer.providerKey = const_cast<GUID *>(&ProviderKey);
    sublayer.flags = persistent ? FWPM_SUBLAYER_FLAG_PERSISTENT : 0;
    sublayer.weight = 0x7c00;
    r = FwpmSubLayerAdd0(engine_, &sublayer, nullptr);
    if (r != ERROR_SUCCESS && r != FWP_E_ALREADY_EXISTS) {
        error = L"FwpmSubLayerAdd0: " + errorText(r);
        return false;
    }
    return true;
}

bool WfpEngine::addFilter(const GUID &layer, const wchar_t *name, FWP_ACTION_TYPE action, std::uint8_t weight,
                          FWPM_FILTER_CONDITION0 *conditions, UINT32 count, std::uint64_t &id, std::wstring &error) {
    FWPM_FILTER0 filter{};
    filter.displayData.name = const_cast<wchar_t *>(name);
    filter.flags = dynamic_ ? 0 : FWPM_FILTER_FLAG_PERSISTENT;
    filter.providerKey = const_cast<GUID *>(&ProviderKey);
    filter.layerKey = layer;
    filter.subLayerKey = SublayerKey;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = weight;
    filter.numFilterConditions = count;
    filter.filterCondition = conditions;
    filter.action.type = action;
    UINT64 newId = 0;
    const DWORD r = FwpmFilterAdd0(engine_, &filter, nullptr, &newId);
    if (r != ERROR_SUCCESS) {
        error = L"FwpmFilterAdd0: " + errorText(r);
        return false;
    }
    id = newId;
    return true;
}

bool WfpEngine::addAppFilter(const std::wstring &path, Action action, Direction direction, std::uint8_t weight,
                             std::vector<std::uint64_t> &ids, std::wstring &error) {
    FWP_BYTE_BLOB *appId = nullptr;
    DWORD r = FwpmGetAppIdFromFileName0(path.c_str(), &appId);
    if (r != ERROR_SUCCESS || !appId) {
        error = L"FwpmGetAppIdFromFileName0: " + errorText(r);
        return false;
    }
    FWPM_FILTER_CONDITION0 conditions[2]{};
    conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    conditions[0].conditionValue.byteBlob = appId;
    // Un Block nunca corta el tráfico dentro de la PC (loopback): no sale a la red, y apps como Nuke hablan consigo
    // mismas por 127.0.0.1 (Frame Server). El permiso de loopback no le gana a un Block de peso 15, así que se excluye
    // en el propio Block.
    conditions[1].fieldKey = FWPM_CONDITION_FLAGS;
    conditions[1].matchType = FWP_MATCH_FLAGS_NONE_SET;
    conditions[1].conditionValue.type = FWP_UINT32;
    conditions[1].conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
    const UINT32 conditionCount = action == Action::Block ? 2 : 1;
    const wchar_t *name = action == Action::Allow ? L"LGA GateBouncer allow" : L"LGA GateBouncer block";
    // Todo o nada: una regla a medias por capa sería engañosa.
    const bool began = begin(error);
    bool ok = began;
    std::vector<std::uint64_t> created;
    for (const GUID &layer : layersFor(direction)) {
        if (!ok) break;
        std::uint64_t id = 0;
        ok = addFilter(layer, name, action == Action::Allow ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK, weight, conditions,
                       conditionCount, id, error);
        if (ok) created.push_back(id);
    }
    if (ok) ok = commit(error);
    else if (began) abort();
    FwpmFreeMemory0(reinterpret_cast<void **>(&appId));
    if (!ok) return false;
    ids.insert(ids.end(), created.begin(), created.end());
    if (action == Action::Block) trackOwnFilters(created);
    return true;
}

bool WfpEngine::addAppAddressFilter(const std::wstring &path, const std::wstring &address, Action action,
                                    std::uint8_t weight, std::vector<std::uint64_t> &ids, std::wstring &error) {
    IN_ADDR v4{};
    IN6_ADDR v6{};
    const bool isV4 = InetPtonW(AF_INET, address.c_str(), &v4) == 1;
    if (!isV4 && InetPtonW(AF_INET6, address.c_str(), &v6) != 1) {
        error = L"Invalid address: " + address;
        return false;
    }
    FWP_BYTE_BLOB *appId = nullptr;
    const DWORD r = FwpmGetAppIdFromFileName0(path.c_str(), &appId);
    if (r != ERROR_SUCCESS || !appId) {
        error = L"FwpmGetAppIdFromFileName0: " + errorText(r);
        return false;
    }
    FWP_BYTE_ARRAY16 bytes16{};
    std::memcpy(bytes16.byteArray16, &v6, 16);
    FWPM_FILTER_CONDITION0 conditions[2]{};
    conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    conditions[0].conditionValue.byteBlob = appId;
    conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditions[1].matchType = FWP_MATCH_EQUAL;
    if (isV4) {
        conditions[1].conditionValue.type = FWP_UINT32;
        conditions[1].conditionValue.uint32 = ntohl(v4.S_un.S_addr); // WFP compara en orden de host
    } else {
        conditions[1].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
        conditions[1].conditionValue.byteArray16 = &bytes16;
    }
    std::uint64_t id = 0;
    const bool ok = addFilter(isV4 ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                              action == Action::Allow ? L"LGA GateBouncer allow destination"
                                                      : L"LGA GateBouncer block destination",
                              action == Action::Allow ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK, weight, conditions, 2, id,
                              error);
    FwpmFreeMemory0(reinterpret_cast<void **>(&appId));
    if (!ok) return false;
    ids.push_back(id);
    if (action == Action::Block) trackOwnFilters({id});
    return true;
}

bool WfpEngine::begin(std::wstring &error) {
    if (txnDepth_++ > 0) return true;
    const DWORD r = FwpmTransactionBegin0(engine_, 0);
    if (r != ERROR_SUCCESS) {
        txnDepth_ = 0;
        error = L"FwpmTransactionBegin0: " + errorText(r);
        return false;
    }
    txnFailed_ = false;
    untrackOnCommit_.clear();
    return true;
}

bool WfpEngine::commit(std::wstring &error) {
    if (txnDepth_ == 0) return false;
    if (--txnDepth_ > 0) return true;
    if (txnFailed_) {
        FwpmTransactionAbort0(engine_);
        untrackOnCommit_.clear();
        if (error.empty()) error = L"Transaction aborted";
        return false;
    }
    const DWORD r = FwpmTransactionCommit0(engine_);
    if (r != ERROR_SUCCESS) {
        untrackOnCommit_.clear();
        error = L"FwpmTransactionCommit0: " + errorText(r);
        return false;
    }
    for (auto id : untrackOnCommit_) untrackOwnFilter(id);
    untrackOnCommit_.clear();
    return true;
}

void WfpEngine::abort() {
    if (txnDepth_ == 0) return;
    // Dentro de otra transacción sólo se marca: la de afuera termina abortando todo.
    if (--txnDepth_ > 0) {
        txnFailed_ = true;
        return;
    }
    FwpmTransactionAbort0(engine_);
    untrackOnCommit_.clear();
}

bool WfpEngine::addDefaultBlock(Direction direction, std::vector<std::uint64_t> &ids, std::wstring &error) {
    // Las dos familias (IPv4 e IPv6) o ninguna: un bloqueo suelto sin rastrear no se podría quitar.
    if (!begin(error)) return false;
    std::vector<std::uint64_t> created;
    for (const GUID &layer : layersFor(direction)) {
        std::uint64_t id = 0;
        if (!addFilter(layer, L"LGA GateBouncer default block", FWP_ACTION_BLOCK, WeightDefaultBlock, nullptr, 0, id,
                       error)) {
            abort();
            return false;
        }
        created.push_back(id);
    }
    if (!commit(error)) return false;
    ids.insert(ids.end(), created.begin(), created.end());
    trackOwnFilters(created);
    return true;
}

bool WfpEngine::addHttpsPermit(const std::wstring &path, std::vector<std::uint64_t> &ids, std::wstring &error) {
    FWP_BYTE_BLOB *appId = nullptr;
    const DWORD r = FwpmGetAppIdFromFileName0(path.c_str(), &appId);
    if (r != ERROR_SUCCESS || !appId) {
        error = L"FwpmGetAppIdFromFileName0: " + errorText(r);
        return false;
    }
    FWPM_FILTER_CONDITION0 conditions[3]{};
    conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    conditions[0].conditionValue.byteBlob = appId;
    conditions[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[1].matchType = FWP_MATCH_EQUAL;
    conditions[1].conditionValue.type = FWP_UINT8;
    conditions[1].conditionValue.uint8 = IPPROTO_TCP;
    conditions[2].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conditions[2].matchType = FWP_MATCH_EQUAL;
    conditions[2].conditionValue.type = FWP_UINT16;
    conditions[2].conditionValue.uint16 = 443;
    const bool began = begin(error);
    bool ok = began;
    std::vector<std::uint64_t> created;
    for (const GUID &layer : layersFor(Direction::Outbound)) {
        if (!ok) break;
        std::uint64_t id = 0;
        ok = addFilter(layer, L"LGA GateBouncer window HTTPS", FWP_ACTION_PERMIT, WeightSystem, conditions, 3, id, error);
        if (ok) created.push_back(id);
    }
    if (ok) ok = commit(error);
    else if (began) abort();
    FwpmFreeMemory0(reinterpret_cast<void **>(&appId));
    if (!ok) return false;
    ids.insert(ids.end(), created.begin(), created.end());
    return true;
}

bool WfpEngine::addLocalNetworkPermit(std::vector<std::uint64_t> &ids, std::wstring &error) {
    // Varias condiciones sobre el mismo campo se combinan con O: una sola por capa alcanza.
    FWP_V4_ADDR_AND_MASK v4[] = {{0x0A000000, 0xFF000000},  // 10.0.0.0/8
                                 {0xAC100000, 0xFFF00000},  // 172.16.0.0/12
                                 {0xC0A80000, 0xFFFF0000},  // 192.168.0.0/16
                                 {0xA9FE0000, 0xFFFF0000},  // 169.254.0.0/16, enlace local
                                 {0x64400000, 0xFFC00000},  // 100.64.0.0/10, Tailscale
                                 {0xE0000000, 0xF0000000},  // 224.0.0.0/4, multicast
                                 {0xFFFFFFFF, 0xFFFFFFFF}}; // difusión
    FWP_V6_ADDR_AND_MASK v6[] = {{{0xfe, 0x80}, 10}, {{0xfc}, 7}, {{0xff}, 8}}; // enlace local, ULA (Tailscale), multicast
    std::vector<FWPM_FILTER_CONDITION0> c4(std::size(v4)), c6(std::size(v6));
    for (std::size_t i = 0; i < c4.size(); ++i) {
        c4[i].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        c4[i].matchType = FWP_MATCH_EQUAL;
        c4[i].conditionValue.type = FWP_V4_ADDR_MASK;
        c4[i].conditionValue.v4AddrMask = &v4[i];
    }
    for (std::size_t i = 0; i < c6.size(); ++i) {
        c6[i].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        c6[i].matchType = FWP_MATCH_EQUAL;
        c6[i].conditionValue.type = FWP_V6_ADDR_MASK;
        c6[i].conditionValue.v6AddrMask = &v6[i];
    }
    if (!begin(error)) return false;
    std::uint64_t id4 = 0, id6 = 0;
    if (!addFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, L"LGA GateBouncer local network", FWP_ACTION_PERMIT, WeightSystem,
                   c4.data(), UINT32(c4.size()), id4, error) ||
        !addFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V6, L"LGA GateBouncer local network", FWP_ACTION_PERMIT, WeightSystem,
                   c6.data(), UINT32(c6.size()), id6, error)) {
        abort();
        return false;
    }
    if (!commit(error)) return false;
    ids.push_back(id4);
    ids.push_back(id6);
    return true;
}

bool WfpEngine::addSystemAllowances(std::vector<std::uint64_t> &ids, std::wstring &error) {
    // Loopback: tráfico interno de la PC, nunca sale a la red.
    FWPM_FILTER_CONDITION0 loopback{};
    loopback.fieldKey = FWPM_CONDITION_FLAGS;
    loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
    loopback.conditionValue.type = FWP_UINT32;
    loopback.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
    if (!begin(error)) return false;
    std::vector<std::uint64_t> created;
    for (const GUID &layer : layersFor(Direction::Both)) {
        std::uint64_t id = 0;
        if (!addFilter(layer, L"LGA GateBouncer loopback", FWP_ACTION_PERMIT, WeightSystem, &loopback, 1, id, error)) {
            abort();
            return false;
        }
        created.push_back(id);
    }
    // Servicios de Windows (SYSTEM, LocalService, NetworkService): DNS, DHCP, actualizaciones y el kernel.
    // Una regla Block explícita del usuario tiene peso mayor y les gana.
    PSECURITY_DESCRIPTOR sd = nullptr;
    ULONG sdSize = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;CC;;;SY)(A;;CC;;;LS)(A;;CC;;;NS)",
                                                              SDDL_REVISION_1, &sd, &sdSize)) {
        error = L"ConvertStringSecurityDescriptorToSecurityDescriptorW: " + errorText(GetLastError());
        abort();
        return false;
    }
    FWP_BYTE_BLOB sdBlob{sdSize, static_cast<UINT8 *>(sd)};
    FWPM_FILTER_CONDITION0 services{};
    services.fieldKey = FWPM_CONDITION_ALE_USER_ID;
    services.matchType = FWP_MATCH_EQUAL;
    services.conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
    services.conditionValue.sd = &sdBlob;
    bool ok = true;
    for (const GUID &layer : layersFor(Direction::Outbound)) {
        std::uint64_t id = 0;
        ok = addFilter(layer, L"LGA GateBouncer Windows services", FWP_ACTION_PERMIT, WeightSystem, &services, 1, id,
                       error);
        if (!ok) break;
        created.push_back(id);
    }
    LocalFree(sd);
    if (!ok) {
        abort();
        return false;
    }
    if (!commit(error)) return false;
    ids.insert(ids.end(), created.begin(), created.end());
    return true;
}

bool WfpEngine::removeFilter(std::uint64_t id) {
    const DWORD r = FwpmFilterDeleteById0(engine_, id);
    if (r != ERROR_SUCCESS && r != FWP_E_FILTER_NOT_FOUND) return false;
    // Si la transacción se aborta el filtro sigue en WFP: tiene que seguir contándose como propio.
    if (txnDepth_ > 0)
        untrackOnCommit_.push_back(id);
    else
        untrackOwnFilter(id);
    return true;
}

bool WfpEngine::removeAllOwnFilters(std::wstring &error) {
    // Todo junto, y la enumeración dentro de la transacción: borrar uno por uno podía dejar el bloqueo general sin
    // los permisos de DNS y loopback, y un filtro agregado entre enumerar y borrar se escapaba.
    if (!begin(error)) return false;
    // Sin plantilla: una plantilla exige una capa (sin ella WFP responde FWP_E_LAYER_NOT_FOUND) y los filtros propios
    // están en varias. Se recorren todos y se eligen los del proveedor o la subcapa propios.
    HANDLE handle = nullptr;
    DWORD r = FwpmFilterCreateEnumHandle0(engine_, nullptr, &handle);
    if (r != ERROR_SUCCESS) {
        error = L"FwpmFilterCreateEnumHandle0: " + errorText(r);
        abort();
        return false;
    }
    std::vector<UINT64> found;
    for (;;) {
        FWPM_FILTER0 **rows = nullptr;
        UINT32 count = 0;
        r = FwpmFilterEnum0(engine_, handle, 256, &rows, &count);
        if (r != ERROR_SUCCESS) break;
        for (UINT32 i = 0; i < count; ++i) {
            const FWPM_FILTER0 *f = rows[i];
            if ((f->providerKey && IsEqualGUID(*f->providerKey, ProviderKey)) || IsEqualGUID(f->subLayerKey, SublayerKey))
                found.push_back(f->filterId);
        }
        FwpmFreeMemory0(reinterpret_cast<void **>(&rows));
        if (count < 256) break;
    }
    FwpmFilterDestroyEnumHandle0(engine_, handle);
    if (r != ERROR_SUCCESS) {
        error = L"FwpmFilterEnum0: " + errorText(r);
        abort();
        return false;
    }
    for (UINT64 id : found) {
        if (!removeFilter(id)) {
            error = L"FwpmFilterDeleteById0: could not remove filter " + std::to_wstring(id);
            abort();
            return false;
        }
    }
    return commit(error);
}

bool WfpEngine::removeObjects(std::wstring &error) {
    if (!begin(error)) return false;
    if (!removeAllOwnFilters(error)) {
        abort();
        return false;
    }
    DWORD r = FwpmSubLayerDeleteByKey0(engine_, &SublayerKey);
    if (r != ERROR_SUCCESS && r != FWP_E_SUBLAYER_NOT_FOUND) {
        error = L"FwpmSubLayerDeleteByKey0: " + errorText(r);
        abort();
        return false;
    }
    r = FwpmProviderDeleteByKey0(engine_, &ProviderKey);
    if (r != ERROR_SUCCESS && r != FWP_E_PROVIDER_NOT_FOUND) {
        error = L"FwpmProviderDeleteByKey0: " + errorText(r);
        abort();
        return false;
    }
    return commit(error);
}

void WfpEngine::trackOwnFilters(const std::vector<std::uint64_t> &ids) {
    std::lock_guard<std::mutex> lock(mutex_);
    ownFilters_.insert(ids.begin(), ids.end());
}

void WfpEngine::untrackOwnFilter(std::uint64_t id) {
    std::lock_guard<std::mutex> lock(mutex_);
    ownFilters_.erase(id);
}

bool WfpEngine::subscribeDrops(DropCallback callback, std::wstring &error) {
    // La colección de eventos de red es una opción global de BFE. Si estaba apagada se enciende
    // y se vuelve a apagar al cerrar.
    FWP_VALUE0 *current = nullptr;
    if (FwpmEngineGetOption0(engine_, FWPM_ENGINE_COLLECT_NET_EVENTS, &current) == ERROR_SUCCESS && current) {
        const bool on = current->type == FWP_UINT32 && current->uint32 != 0;
        FwpmFreeMemory0(reinterpret_cast<void **>(&current));
        if (!on) {
            FWP_VALUE0 value{};
            value.type = FWP_UINT32;
            value.uint32 = 1;
            const DWORD r = FwpmEngineSetOption0(engine_, FWPM_ENGINE_COLLECT_NET_EVENTS, &value);
            if (r != ERROR_SUCCESS) {
                error = L"FwpmEngineSetOption0(COLLECT_NET_EVENTS): " + errorText(r);
                return false;
            }
            restoreCollection_ = dynamic_;
        }
    }
    callback_ = std::move(callback);
    FWPM_NET_EVENT_ENUM_TEMPLATE0 tmpl{};
    FWPM_NET_EVENT_SUBSCRIPTION0 subscription{};
    subscription.enumTemplate = &tmpl;
    const DWORD r = FwpmNetEventSubscribe0(engine_, &subscription, &WfpEngine::onEvent, this, &subscription_);
    if (r != ERROR_SUCCESS) {
        subscription_ = nullptr;
        error = L"FwpmNetEventSubscribe0: " + errorText(r);
        return false;
    }
    return true;
}

void WfpEngine::unsubscribe() {
    if (subscription_ && engine_) FwpmNetEventUnsubscribe0(engine_, subscription_);
    subscription_ = nullptr;
}

void CALLBACK WfpEngine::onEvent(void *context, const FWPM_NET_EVENT1 *event) {
    auto *self = static_cast<WfpEngine *>(context);
    if (!self || !event || event->type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP || !event->classifyDrop) return;
    const UINT64 filterId = event->classifyDrop->filterId;
    {
        std::lock_guard<std::mutex> lock(self->mutex_);
        if (!self->ownFilters_.count(filterId)) return;
    }
    const FWPM_NET_EVENT_HEADER1 &h = event->header;
    DropEvent drop;
    drop.filterId = filterId;
    drop.time = h.timeStamp;
    drop.protocol = (h.flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET) ? h.ipProtocol : 0;
    drop.remotePort = (h.flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET) ? h.remotePort : 0;
    drop.localPort = (h.flags & FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET) ? h.localPort : 0;
    if (h.flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET) drop.remoteAddress = formatAddress(h);
    drop.inbound = event->classifyDrop->msFwpDirection == FWP_DIRECTION_INBOUND;
    if ((h.flags & FWPM_NET_EVENT_FLAG_APP_ID_SET) && h.appId.data && h.appId.size >= sizeof(wchar_t)) {
        std::wstring device(reinterpret_cast<const wchar_t *>(h.appId.data), h.appId.size / sizeof(wchar_t));
        while (!device.empty() && device.back() == L'\0') device.pop_back();
        drop.appPath = devicePathToDos(device);
    }
    if (self->callback_) self->callback_(drop);
}

std::wstring WfpEngine::devicePathToDos(const std::wstring &devicePath) {
    // WFP entrega "\device\harddiskvolume3\program files\app.exe" en minúsculas.
    wchar_t drives[512] = {};
    if (!GetLogicalDriveStringsW(511, drives)) return devicePath;
    for (const wchar_t *d = drives; *d; d += wcslen(d) + 1) {
        wchar_t letter[3] = {d[0], L':', 0};
        wchar_t target[MAX_PATH] = {};
        if (!QueryDosDeviceW(letter, target, MAX_PATH)) continue;
        const std::size_t n = wcslen(target);
        if (devicePath.size() > n && _wcsnicmp(devicePath.c_str(), target, n) == 0 && devicePath[n] == L'\\')
            return withRealCase(std::wstring(letter) + devicePath.substr(n));
    }
    return devicePath;
}

std::wstring WfpEngine::withRealCase(const std::wstring &path) {
    // Para mostrar y guardar la ruta como la ve el usuario; si el archivo ya no existe queda como vino.
    HANDLE file = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (file == INVALID_HANDLE_VALUE) return path;
    wchar_t buffer[MAX_PATH * 2] = {};
    const DWORD n = GetFinalPathNameByHandleW(file, buffer, DWORD(std::size(buffer)), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    CloseHandle(file);
    if (n == 0 || n >= std::size(buffer)) return path;
    std::wstring real(buffer, n);
    if (real.rfind(L"\\\\?\\UNC\\", 0) == 0) return path;
    if (real.rfind(L"\\\\?\\", 0) == 0) real.erase(0, 4);
    return _wcsicmp(real.c_str(), path.c_str()) == 0 ? real : path;
}

} // namespace gbe
