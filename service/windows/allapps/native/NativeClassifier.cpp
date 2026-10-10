#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <fwpsu.h>
#include "NativeClassifier.h"
#include <algorithm>
#include <cstring>
#include <cstddef>
#include <stdexcept>
static_assert(sizeof(GB_ACTIVITY_SNAPSHOT)==168);
static_assert(sizeof(GB_SCOPE_DECISION)==64 && sizeof(GB_SCOPE_RECEIPT)==104);
static_assert(offsetof(GB_ACTIVITY_SNAPSHOT,decision)==8 && offsetof(GB_ACTIVITY_SNAPSHOT,loss)==72);
static_assert(offsetof(GB_ACTIVITY_SNAPSHOT,authorizedUtc)==80 && offsetof(GB_ACTIVITY_SNAPSHOT,flow)==88);
static_assert(offsetof(GB_ACTIVITY_SNAPSHOT,outboundBytes)==96 && offsetof(GB_ACTIVITY_SNAPSHOT,inboundBytes)==128);
static_assert(offsetof(GB_ACTIVITY_SNAPSHOT,outboundPackets)==104 && offsetof(GB_ACTIVITY_SNAPSHOT,outboundUtc)==112 &&
    offsetof(GB_ACTIVITY_SNAPSHOT,outboundRevision)==120);
static_assert(offsetof(GB_ACTIVITY_SNAPSHOT,inboundPackets)==136 && offsetof(GB_ACTIVITY_SNAPSHOT,inboundUtc)==144 &&
    offsetof(GB_ACTIVITY_SNAPSHOT,inboundRevision)==152);
static_assert(offsetof(GB_ACTIVITY_SNAPSHOT,flags)==160 && offsetof(GB_ACTIVITY_SNAPSHOT,reserved)==164);
static_assert(sizeof(GB_PROCESS_IMAGE_FACTS)==88);
static_assert(offsetof(GB_PROCESS_IMAGE_FACTS,session)==8 && offsetof(GB_PROCESS_IMAGE_FACTS,cause)==16 &&
    offsetof(GB_PROCESS_IMAGE_FACTS,loss)==24 && offsetof(GB_PROCESS_IMAGE_FACTS,created)==32 &&
    offsetof(GB_PROCESS_IMAGE_FACTS,pid)==40 && offsetof(GB_PROCESS_IMAGE_FACTS,volumeSerialNumber)==48 &&
    offsetof(GB_PROCESS_IMAGE_FACTS,fileIndexHigh)==52 && offsetof(GB_PROCESS_IMAGE_FACTS,fileIndexLow)==56 &&
    offsetof(GB_PROCESS_IMAGE_FACTS,fileSizeHigh)==60 && offsetof(GB_PROCESS_IMAGE_FACTS,fileSizeLow)==64 &&
    offsetof(GB_PROCESS_IMAGE_FACTS,reserved0)==68 && offsetof(GB_PROCESS_IMAGE_FACTS,lastWrite)==72 &&
    offsetof(GB_PROCESS_IMAGE_FACTS,flags)==80 && offsetof(GB_PROCESS_IMAGE_FACTS,reserved1)==84);

namespace gatebouncer::service::windows::allapps::native {
namespace {
bool serviceCaller() noexcept {
    gb::native::Handle token; HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) return false;
    token.reset(raw); return gb::native::systemServiceToken(token.value);
}
bool equal(const GUID &a, const GUID &b) noexcept { return std::memcmp(&a, &b, sizeof(a)) == 0; }
struct Memory { void *p = nullptr; ~Memory() { if (p) FwpmFreeMemory0(&p); } };
BOOL classifierIo(HANDLE device,DWORD code,LPVOID input,DWORD inputBytes,LPVOID output,DWORD outputBytes,
    LPDWORD returned,LPOVERLAPPED) noexcept {
    gb::native::Handle event(CreateEventW(nullptr,TRUE,FALSE,nullptr));
    if(!event)return FALSE;
    OVERLAPPED operation{};operation.hEvent=event.value;
    const auto immediate=DeviceIoControl(device,code,input,inputBytes,output,outputBytes,nullptr,&operation);
    auto error=immediate ? ERROR_SUCCESS : GetLastError();
    BOOL finished=FALSE;
    if(immediate || error==ERROR_IO_PENDING) {
        finished=GetOverlappedResult(device,&operation,returned,TRUE);
        error=finished ? ERROR_SUCCESS : GetLastError();
    }
    event.reset();SetLastError(error);return finished;
}
bool validImage(const GB_PROCESS_IMAGE_FACTS &facts,const GB_CLASSIFIER_RECORD &record) noexcept {
    return facts.version==GB_PROCESS_IMAGE_VERSION && facts.bytes==sizeof(facts) &&
        facts.flags==GB_PROCESS_IMAGE_ORIGINAL && !facts.reserved0 && !facts.reserved1 &&
        facts.session==record.session && facts.cause==record.cause && facts.loss==record.loss &&
        facts.pid==record.pid && facts.created==record.created &&
        (facts.fileIndexHigh || facts.fileIndexLow) && facts.lastWrite && facts.lastWrite<=INT64_MAX;
}
}
std::shared_ptr<NativeClassifier> NativeClassifier::open() noexcept {
    try {
        if (!serviceCaller()) return {};
        auto owner = std::shared_ptr<NativeClassifier>(new NativeClassifier);
        owner->device_.reset(CreateFileW(GB_CLASSIFIER_DEVICE, GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED |
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
        if (!owner->device_) return {};
        return owner;
    } catch (...) { return {}; }
}
bool NativeClassifier::start() noexcept {
    std::lock_guard<std::mutex> lock(mutex_); DWORD bytes = 0;
    return device_ && serviceCaller() && classifierIo(device_.value, GB_CLASSIFIER_START,
        nullptr, 0, nullptr, 0, &bytes, nullptr);
}
bool NativeClassifier::scopeIoctl(DWORD code, const GB_SCOPE_DECISION &decision, GB_SCOPE_RECEIPT &receipt) noexcept {
    receipt = {};
    std::lock_guard<std::mutex> lock(mutex_);
    auto copy = decision; DWORD bytes = 0;
    return device_ && serviceCaller() && decision.version == GB_CLASSIFIER_VERSION &&
        decision.bytes == sizeof(decision) && decision.session == session_ &&
        classifierIo(device_.value, code, &copy, sizeof(copy), &receipt, sizeof(receipt), &bytes, nullptr) &&
        bytes == sizeof(receipt) && std::memcmp(&receipt.decision, &decision, sizeof(decision)) == 0 &&
        receipt.state >= GB_SCOPE_COMPLETING && receipt.state <= GB_SCOPE_CLOSED &&
        receipt.applied <= 1 && receipt.current <= 1 && !receipt.reserved &&
        (decision.scope == GB_SCOPE_DURATION ? receipt.deadline != 0 : receipt.deadline == 0) &&
        (!receipt.applied || receipt.observedAt != 0);
}
bool NativeClassifier::decide(const GB_SCOPE_DECISION &d, GB_SCOPE_RECEIPT &r) noexcept {
    return scopeIoctl(GB_CLASSIFIER_DECIDE,d,r);
}
bool NativeClassifier::readback(const GB_SCOPE_DECISION &d, GB_SCOPE_RECEIPT &r) noexcept {
    return scopeIoctl(GB_CLASSIFIER_READBACK,d,r);
}
bool NativeClassifier::activity(const ClassifierCause &cause,const GB_SCOPE_DECISION &decision,
    HANDLE engine,GB_ACTIVITY_SNAPSHOT &snapshot) const noexcept {
    snapshot={};
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        if(cause.owner_.get()!=this || !device_ || !serviceCaller() || decision.version!=GB_CLASSIFIER_VERSION ||
           decision.bytes!=sizeof(decision) || decision.session!=session_ || decision.session!=cause.record_.session ||
           decision.cause!=cause.record_.cause || cause.record_.loss!=loss_ || !decision.revision) return false;
        auto original=[&]() {
            gb::native::Handle token;HANDLE raw=nullptr;gb::native::TokenEvidence identity;
            if(!cause.process_.current() || !OpenProcessToken(cause.process_.process.value,TOKEN_QUERY,&raw))return false;
            token.reset(raw);
            wchar_t path[32768]{};DWORD n=32768;
            return gb::native::tokenEvidence(token.value,identity) && identity.account==cause.token_.account &&
                identity.logon==cause.token_.logon && identity.session==cause.token_.session &&
                QueryFullProcessImageNameW(cause.process_.process.value,0,path,&n) && n && n<32768 &&
                std::filesystem::path(std::wstring(path,n))==cause.process_.image && cause.process_.current();
        };
        if(!original() || !catalogCurrent(cause,engine))return false;
        auto copy=decision;DWORD bytes=0;GB_ACTIVITY_SNAPSHOT observed{};
        if(!classifierIo(device_.value,GB_CLASSIFIER_ACTIVITY,&copy,sizeof(copy),&observed,sizeof(observed),&bytes,nullptr) ||
           bytes!=sizeof(observed) || observed.version!=GB_ACTIVITY_VERSION || observed.bytes!=sizeof(observed) ||
           observed.reserved || (observed.flags & ~15u) || observed.loss!=cause.record_.loss ||
           std::memcmp(&observed.decision,&decision,sizeof(decision))!=0 ||
           ((observed.flags & (GB_ACTIVITY_OUTBOUND|GB_ACTIVITY_INBOUND)) && (!observed.flow || decision.action!=2)) ||
           ((observed.flags & GB_ACTIVITY_AUTH_UTC) ? !observed.authorizedUtc : observed.authorizedUtc!=0))return false;
        auto group=[](UINT32 flags,UINT32 bit,UINT64 bytes,UINT64 packets,UINT64 utc,UINT64 revision) {
            return (flags & bit) ? packets && utc && revision : !bytes && !packets && !utc && !revision;
        };
        if(!group(observed.flags,GB_ACTIVITY_OUTBOUND,observed.outboundBytes,observed.outboundPackets,observed.outboundUtc,observed.outboundRevision) ||
           !group(observed.flags,GB_ACTIVITY_INBOUND,observed.inboundBytes,observed.inboundPackets,observed.inboundUtc,observed.inboundRevision) ||
           !original() || !catalogCurrent(cause,engine))return false;
        snapshot=observed;return true;
    } catch(...) { snapshot={};return false; }
}
bool NativeClassifier::cancelIoctl(DWORD code, const GB_SCOPE_DECISION &decision, GB_CANCEL_RECEIPT &receipt) const noexcept {
    receipt = {}; std::lock_guard<std::mutex> lock(mutex_);
    auto copy = decision; DWORD bytes = 0;
    return device_ && serviceCaller() && decision.version == GB_CLASSIFIER_VERSION && decision.bytes == sizeof(decision) &&
        decision.session == session_ && decision.scope == 2 && !decision.durationMs &&
        classifierIo(device_.value, code, &copy, sizeof(copy), &receipt, sizeof(receipt), &bytes, nullptr) &&
        bytes == sizeof(receipt) && std::memcmp(&receipt.decision, &decision, sizeof(decision)) == 0 &&
        receipt.guarded == 1 && receipt.closed <= 1 && receipt.reauthDenied <= 1 && !receipt.reserved &&
        (receipt.reauthDenied ? receipt.deniedAt != 0 : receipt.deniedAt == 0);
}
bool NativeClassifier::cancel(const GB_SCOPE_DECISION &d, GB_CANCEL_RECEIPT &r) noexcept {
    return cancelIoctl(GB_CLASSIFIER_CANCEL,d,r);
}
bool NativeClassifier::cancelReadback(const GB_SCOPE_DECISION &d, GB_CANCEL_RECEIPT &r) const noexcept {
    return cancelIoctl(GB_CLASSIFIER_CANCEL_READBACK,d,r);
}
bool NativeClassifier::cancelledCurrent(const ClassifierCause &cause, const GB_SCOPE_DECISION &decision, HANDLE engine) const noexcept {
    if (cause.owner_.get() != this || cause.record_.session != decision.session || cause.record_.cause != decision.cause) return false;
    GB_CANCEL_RECEIPT before{}, after{};
    return cancelReadback(decision,before) && catalogCurrent(cause,engine) && cancelReadback(decision,after);
}
bool NativeClassifier::reset() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if(pendingApp_)pendingApp_->appState_.store(2);
    GB_CLASSIFIER_STATE state{}; DWORD bytes = 0;
    if (!device_ || !serviceCaller() || !classifierIo(device_.value, GB_CLASSIFIER_RESET, nullptr, 0,
        &state, sizeof(state), &bytes, nullptr) || bytes != sizeof(state) || !state.session || state.loss) return false;
    session_ = state.session; loss_ = state.loss; return true;
}
ClassifierCause::ClassifierCause(std::shared_ptr<NativeClassifier> owner, GB_CLASSIFIER_RECORD record,
    gb::native::ProcessEvidence process, gb::native::TokenEvidence token)
    : owner_(std::move(owner)), record_(record), process_(std::move(process)), token_(std::move(token)) {}
ClassifierCause::~ClassifierCause() { if (owner_) owner_->release({record_.session, record_.cause}); }
bool ClassifierCause::current() const noexcept { return owner_ && owner_->current(*this); }
std::shared_ptr<ClassifierCause> NativeClassifier::take(bool &lost) noexcept {
    lost = false;
    try {
        std::unique_lock<std::mutex> lock(mutex_);
        if(pendingApp_) {
            const auto state=pendingApp_->appState_.load();
            if(state==0)return {};
            if(state!=1 || !pendingApp_->appJob_ || !pendingApp_->appDeadline_ || GetTickCount64()>=pendingApp_->appDeadline_) {
                pendingApp_->appState_.store(2);lost=true;return {};
            }
            auto accepted=std::move(pendingApp_);lock.unlock();
            if(!accepted->current() || GetTickCount64()>=accepted->appDeadline_) {
                accepted->appState_.store(2);lock.lock();pendingApp_=std::move(accepted);lost=true;return {};
            }
            return accepted;
        }
        GB_CLASSIFIER_RECORD record{}; DWORD bytes = 0;
        if (!device_ || !serviceCaller()) { lost = true; return {}; }
        if (!classifierIo(device_.value, GB_CLASSIFIER_NEXT, nullptr, 0, &record, sizeof(record), &bytes, nullptr)) {
            lost = GetLastError() != ERROR_NO_MORE_ITEMS; return {};
        }
        gb::native::ProcessEvidence process;
        process.process.reset(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(record.processHandle)));
        GB_CLASSIFIER_QUERY query{record.session, record.cause};
        auto discard = [&] { DWORD ignored = 0;
            classifierIo(device_.value, GB_CLASSIFIER_RELEASE, &query, sizeof(query), nullptr, 0, &ignored, nullptr); };
        struct Delivery {
            decltype(discard) &drop;
            bool transferred = false;
            ~Delivery() noexcept { if (!transferred) drop(); }
        } delivery{discard};
        if (bytes != sizeof(record) || record.version != GB_CLASSIFIER_VERSION || record.bytes != sizeof(record) ||
            record.session != session_ || record.loss != loss_ || !record.cause || !process.process ||
            !record.endpoint || !record.filterId || !record.pid || record.pid > MAXDWORD || !record.created ||
            !record.timestamp || (record.family != 4 && record.family != 6) || (record.protocol != 6 && record.protocol != 17) ||
            (record.family == 4 ? record.layerId != FWPS_LAYER_ALE_AUTH_CONNECT_V4 && record.layerId != FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 :
                record.layerId != FWPS_LAYER_ALE_AUTH_CONNECT_V6 && record.layerId != FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6) ||
            (record.flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) || record.appBytes < 4 ||
            record.appBytes > GB_CLASSIFIER_APP_BYTES || (record.appBytes & 1) || record.userBytes < 8 ||
            record.userBytes > GB_CLASSIFIER_SID_BYTES || record.user[0] != 1 || record.user[1] > 15 ||
            record.userBytes != 8u + 4u * record.user[1] || record.app[record.appBytes - 1] || record.app[record.appBytes - 2]) {
            lost = true; return {};
        }
        process.pid = static_cast<DWORD>(record.pid);
        process.created = {static_cast<DWORD>(record.created), static_cast<DWORD>(record.created >> 32)};
        wchar_t path[32768]{}; DWORD n = 32768;
        if (GetProcessId(process.process.value) != process.pid || !process.current() ||
            !QueryFullProcessImageNameW(process.process.value, 0, path, &n) || !n || n >= 32768) {
            lost = true; return {};
        }
        process.image = std::filesystem::path(std::wstring(path, n));
        gb::native::Handle token; HANDLE raw = nullptr;
        gb::native::TokenEvidence identity;
        if (!gb::native::fixedPath(process.image) || !OpenProcessToken(process.process.value, TOKEN_QUERY, &raw)) {
            lost = true; return {};
        }
        token.reset(raw);
        if (!gb::native::tokenEvidence(token.value, identity) ||
            identity.account != gb::wire::Bytes(record.user, record.user + record.userBytes) || !process.current()) {
            lost = true; return {};
        }
        DWORD ignored = 0;
        if (!classifierIo(device_.value, GB_CLASSIFIER_CURRENT, &query, sizeof(query), nullptr, 0, &ignored, nullptr)) {
            lost = true; return {};
        }
        // Si falla el controlblock, shared_ptr destruye la causa y libera el
        // registry kernel; esa destrucción nunca reentra un mutex retenido.
        lock.unlock();
        auto accepted = std::shared_ptr<ClassifierCause>(new ClassifierCause(shared_from_this(), record,
            std::move(process), std::move(identity)));
        delivery.transferred = true;
        lock.lock();
        if(pendingApp_ || !device_ || record.session!=session_ || record.loss!=loss_) {
            lock.unlock();lost=true;return {};
        }
        pendingApp_=std::move(accepted);
        return {}; // Ninguna metadata/proof/fila se deriva de PendingAppId.
    } catch (...) { lost = true; return {}; }
}
void NativeClassifier::release(const GB_CLASSIFIER_QUERY &q) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    auto copy = q; DWORD bytes = 0;
    if (device_) classifierIo(device_.value, GB_CLASSIFIER_RELEASE, &copy, sizeof(copy), nullptr, 0, &bytes, nullptr);
}
bool NativeClassifier::current(const ClassifierCause &cause) const noexcept {
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        if (cause.appState_.load()!=1 || cause.owner_.get() != this || cause.record_.session != session_ || cause.record_.loss != loss_ ||
            !device_ || !serviceCaller() || !cause.process_.current()) return false;
        gb::native::Handle token; HANDLE raw = nullptr; gb::native::TokenEvidence fresh;
        if (!OpenProcessToken(cause.process_.process.value, TOKEN_QUERY, &raw)) return false;
        token.reset(raw);
        if (!gb::native::tokenEvidence(token.value, fresh) || fresh.account != cause.token_.account ||
            fresh.logon != cause.token_.logon || fresh.session != cause.token_.session) return false;
        wchar_t path[32768]{}; DWORD n = 32768;
        if (!QueryFullProcessImageNameW(cause.process_.process.value, 0, path, &n) || !n || n >= 32768 ||
            std::filesystem::path(std::wstring(path, n)) != cause.process_.image) return false;
        GB_CLASSIFIER_QUERY query{cause.record_.session, cause.record_.cause}; DWORD bytes = 0;
        return classifierIo(device_.value, GB_CLASSIFIER_CURRENT, &query, sizeof(query), nullptr, 0, &bytes, nullptr) &&
            cause.process_.current();
    } catch (...) { return false; }
}
bool NativeClassifier::filterCurrent(const ClassifierCause &cause, HANDLE engine) const noexcept {
    return current(cause) && catalogCurrent(cause,engine) && current(cause);
}
bool NativeClassifier::catalogCurrent(const ClassifierCause &cause, HANDLE engine) const noexcept {
    if (cause.owner_.get() != this || !engine) return false;
    Memory filter, callout;
    FWPM_FILTER0 f{}; FWPM_CALLOUT0 c{}; GUID provider{};
    const auto i = cause.record_.family == 4 ? 0 : 1;
    const bool inbound = cause.record_.layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 || cause.record_.layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
    const auto &layer = inbound ? (i == 0 ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 : FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6) :
        (i == 0 ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_CONNECT_V6);
    const auto &key = inbound ? GbInboundCallouts[i] : GbClassifierCallouts[i];
    const auto &filterKey = inbound ? GbInboundCallouts[i] : GbClassifierFilters[i];
    if (cause.record_.layerId != (inbound ? (i == 0 ? FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 : FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6) :
        (i == 0 ? FWPS_LAYER_ALE_AUTH_CONNECT_V4 : FWPS_LAYER_ALE_AUTH_CONNECT_V6))) return false;
    if (FwpmFilterGetById0(engine, cause.record_.filterId, reinterpret_cast<FWPM_FILTER0 **>(&filter.p)) != ERROR_SUCCESS ||
        !guardedRead(&f, filter.p, sizeof(f)) || !f.providerKey ||
        !guardedRead(&provider, f.providerKey, sizeof(provider)) || !equal(provider, GbClassifierProvider) ||
        !equal(f.filterKey, filterKey) || !equal(f.subLayerKey, GbPolicySublayer) ||
        !equal(f.layerKey, layer) || f.flags || f.action.type != FWP_ACTION_CALLOUT_UNKNOWN ||
        !equal(f.action.calloutKey, key) || f.rawContext || f.numFilterConditions ||
        f.providerData.size || f.weight.type != FWP_UINT64 || !f.weight.uint64) return false;
    UINT64 weight = 0;
    if (!guardedRead(&weight, f.weight.uint64, sizeof(weight)) || weight != 50 ||
        f.effectiveWeight.type != FWP_UINT64 || !f.effectiveWeight.uint64 ||
        !guardedRead(&weight, f.effectiveWeight.uint64, sizeof(weight)) || weight != 50) return false;
    if (FwpmCalloutGetByKey0(engine, &key, reinterpret_cast<FWPM_CALLOUT0 **>(&callout.p)) != ERROR_SUCCESS ||
        !guardedRead(&c, callout.p, sizeof(c)) || !c.providerKey ||
        !guardedRead(&provider, c.providerKey, sizeof(provider)) || !equal(provider, GbClassifierProvider) ||
        !equal(c.calloutKey, key) || !equal(c.applicableLayer, layer) ||
        c.flags != FWPM_CALLOUT_FLAG_REGISTERED) return false;
    const GUID *layers[6] = {&FWPM_LAYER_STREAM_PACKET_V4, &FWPM_LAYER_STREAM_PACKET_V6,
        &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4, &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
        &FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4, &FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6};
    for (unsigned n = 0; n < 6; ++n) {
        Memory scopeFilter, scopeCallout;
        FWPM_FILTER0 sf{}; FWPM_CALLOUT0 sc{}; UINT64 sw = 0;
        if (FwpmFilterGetByKey0(engine, &GbScopeCallouts[n], reinterpret_cast<FWPM_FILTER0 **>(&scopeFilter.p)) != ERROR_SUCCESS ||
            !guardedRead(&sf, scopeFilter.p, sizeof(sf)) || !sf.providerKey ||
            !guardedRead(&provider, sf.providerKey, sizeof(provider)) || !equal(provider, GbClassifierProvider) ||
            !equal(sf.filterKey, GbScopeCallouts[n]) || !equal(sf.layerKey, *layers[n]) ||
            !equal(sf.subLayerKey, GbClassifierSublayer) || sf.flags || sf.rawContext || sf.providerData.size || sf.numFilterConditions ||
            sf.action.type != (n < 2 ? FWP_ACTION_CALLOUT_UNKNOWN : FWP_ACTION_CALLOUT_INSPECTION) ||
            !equal(sf.action.calloutKey, GbScopeCallouts[n]) || sf.weight.type != FWP_UINT64 || !sf.weight.uint64 ||
            !guardedRead(&sw, sf.weight.uint64, sizeof(sw)) || sw != 50 ||
            sf.effectiveWeight.type != FWP_UINT64 || !sf.effectiveWeight.uint64 ||
            !guardedRead(&sw, sf.effectiveWeight.uint64, sizeof(sw)) || sw != 50 ||
            FwpmCalloutGetByKey0(engine, &GbScopeCallouts[n], reinterpret_cast<FWPM_CALLOUT0 **>(&scopeCallout.p)) != ERROR_SUCCESS ||
            !guardedRead(&sc, scopeCallout.p, sizeof(sc)) || !sc.providerKey ||
            !guardedRead(&provider, sc.providerKey, sizeof(provider)) || !equal(provider, GbClassifierProvider) ||
            !equal(sc.calloutKey, GbScopeCallouts[n]) || !equal(sc.applicableLayer, *layers[n]) ||
            sc.flags != FWPM_CALLOUT_FLAG_REGISTERED) return false;
    }
    for (unsigned n = 0; n < 2; ++n) {
        const auto &guardLayer = n == 0 ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_CONNECT_V6;
        Memory guardFilter, guardCallout;
        FWPM_FILTER0 gf{}; FWPM_CALLOUT0 gc{}; UINT64 gw = 0;
        if (FwpmFilterGetByKey0(engine, &GbHeldGuardCallouts[n], reinterpret_cast<FWPM_FILTER0 **>(&guardFilter.p)) != ERROR_SUCCESS ||
            !guardedRead(&gf, guardFilter.p, sizeof(gf)) || !gf.providerKey ||
            !guardedRead(&provider, gf.providerKey, sizeof(provider)) || !equal(provider, GbClassifierProvider) ||
            !equal(gf.filterKey, GbHeldGuardCallouts[n]) || !equal(gf.layerKey, guardLayer) ||
            !equal(gf.subLayerKey, GbPolicySublayer) || gf.flags || gf.rawContext || gf.providerData.size || gf.numFilterConditions ||
            gf.action.type != FWP_ACTION_CALLOUT_UNKNOWN || !equal(gf.action.calloutKey, GbHeldGuardCallouts[n]) ||
            gf.weight.type != FWP_UINT64 || !gf.weight.uint64 || !guardedRead(&gw, gf.weight.uint64, sizeof(gw)) || gw != 1000 ||
            gf.effectiveWeight.type != FWP_UINT64 || !gf.effectiveWeight.uint64 ||
            !guardedRead(&gw, gf.effectiveWeight.uint64, sizeof(gw)) || gw != 1000 ||
            FwpmCalloutGetByKey0(engine, &GbHeldGuardCallouts[n], reinterpret_cast<FWPM_CALLOUT0 **>(&guardCallout.p)) != ERROR_SUCCESS ||
            !guardedRead(&gc, guardCallout.p, sizeof(gc)) || !gc.providerKey ||
            !guardedRead(&provider, gc.providerKey, sizeof(provider)) || !equal(provider, GbClassifierProvider) ||
            !equal(gc.calloutKey, GbHeldGuardCallouts[n]) || !equal(gc.applicableLayer, guardLayer) ||
            gc.flags != FWPM_CALLOUT_FLAG_REGISTERED) return false;
    }
    const GUID *inboundLayers[6] = {&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        &FWPM_LAYER_ALE_AUTH_LISTEN_V4, &FWPM_LAYER_ALE_AUTH_LISTEN_V6};
    for (unsigned n = 0; n < 6; ++n) {
        Memory fm, cm; FWPM_FILTER0 nf{}; FWPM_CALLOUT0 nc{}; UINT64 w = 0;
        const auto &sub = n < 4 ? GbPolicySublayer : GbClassifierSublayer;
        const auto wanted = n >= 2 && n < 4 ? 1000u : 50u;
        if (FwpmFilterGetByKey0(engine, &GbInboundCallouts[n], reinterpret_cast<FWPM_FILTER0 **>(&fm.p)) != ERROR_SUCCESS ||
            !guardedRead(&nf, fm.p, sizeof(nf)) || !nf.providerKey ||
            !guardedRead(&provider, nf.providerKey, sizeof(provider)) || !equal(provider, GbClassifierProvider) ||
            !equal(nf.filterKey, GbInboundCallouts[n]) || !equal(nf.layerKey, *inboundLayers[n]) || !equal(nf.subLayerKey, sub) ||
            nf.flags || nf.rawContext || nf.numFilterConditions || nf.providerData.size ||
            nf.action.type != (n < 4 ? FWP_ACTION_CALLOUT_UNKNOWN : FWP_ACTION_CALLOUT_INSPECTION) ||
            !equal(nf.action.calloutKey, GbInboundCallouts[n]) || nf.weight.type != FWP_UINT64 || !nf.weight.uint64 ||
            !guardedRead(&w, nf.weight.uint64, sizeof(w)) || w != wanted ||
            nf.effectiveWeight.type != FWP_UINT64 || !nf.effectiveWeight.uint64 ||
            !guardedRead(&w, nf.effectiveWeight.uint64, sizeof(w)) || w != wanted ||
            FwpmCalloutGetByKey0(engine, &GbInboundCallouts[n], reinterpret_cast<FWPM_CALLOUT0 **>(&cm.p)) != ERROR_SUCCESS ||
            !guardedRead(&nc, cm.p, sizeof(nc)) || !nc.providerKey ||
            !guardedRead(&provider, nc.providerKey, sizeof(provider)) || !equal(provider, GbClassifierProvider) ||
            !equal(nc.calloutKey, GbInboundCallouts[n]) || !equal(nc.applicableLayer, *inboundLayers[n]) ||
            nc.flags != FWPM_CALLOUT_FLAG_REGISTERED) return false;
    }
    const GUID *datagramLayers[2] = {&FWPM_LAYER_DATAGRAM_DATA_V4, &FWPM_LAYER_DATAGRAM_DATA_V6};
    for (unsigned n = 0; n < 2; ++n) {
        Memory fm, cm; FWPM_FILTER0 nf{}; FWPM_CALLOUT0 nc{}; UINT64 w = 0;
        if (FwpmFilterGetByKey0(engine, &GbDatagramCallouts[n], reinterpret_cast<FWPM_FILTER0 **>(&fm.p)) != ERROR_SUCCESS ||
            !guardedRead(&nf, fm.p, sizeof(nf)) || !nf.providerKey ||
            !guardedRead(&provider, nf.providerKey, sizeof(provider)) || !equal(provider, GbClassifierProvider) ||
            !equal(nf.filterKey, GbDatagramCallouts[n]) || !equal(nf.layerKey, *datagramLayers[n]) ||
            !equal(nf.subLayerKey, GbClassifierSublayer) || nf.flags || nf.rawContext || nf.providerData.size || nf.numFilterConditions ||
            nf.action.type != FWP_ACTION_CALLOUT_UNKNOWN || !equal(nf.action.calloutKey, GbDatagramCallouts[n]) ||
            nf.weight.type != FWP_UINT64 || !nf.weight.uint64 || !guardedRead(&w, nf.weight.uint64, sizeof(w)) || w != 50 ||
            nf.effectiveWeight.type != FWP_UINT64 || !nf.effectiveWeight.uint64 ||
            !guardedRead(&w, nf.effectiveWeight.uint64, sizeof(w)) || w != 50 ||
            FwpmCalloutGetByKey0(engine, &GbDatagramCallouts[n], reinterpret_cast<FWPM_CALLOUT0 **>(&cm.p)) != ERROR_SUCCESS ||
            !guardedRead(&nc, cm.p, sizeof(nc)) || !nc.providerKey ||
            !guardedRead(&provider, nc.providerKey, sizeof(provider)) || !equal(provider, GbClassifierProvider) ||
            !equal(nc.calloutKey, GbDatagramCallouts[n]) || !equal(nc.applicableLayer, *datagramLayers[n]) ||
            nc.flags != FWPM_CALLOUT_FLAG_REGISTERED) return false;
    }
    return true;
}
bool NativeClassifier::originalProcess(const ClassifierCause &cause) const noexcept {
    try {
        if(cause.owner_.get()!=this || !serviceCaller() || !cause.process_.current())return false;
        gb::native::Handle token;HANDLE raw=nullptr;gb::native::TokenEvidence identity;
        if(!OpenProcessToken(cause.process_.process.value,TOKEN_QUERY,&raw))return false;
        token.reset(raw);wchar_t path[32768]{};DWORD n=32768;
        return gb::native::tokenEvidence(token.value,identity) && identity.account==cause.token_.account &&
            identity.logon==cause.token_.logon && identity.session==cause.token_.session &&
            QueryFullProcessImageNameW(cause.process_.process.value,0,path,&n) && n && n<32768 &&
            std::filesystem::path(std::wstring(path,n))==cause.process_.image && cause.process_.current();
    } catch(...) {return false;}
}
bool NativeClassifier::imageCurrent(const ClassifierCause &cause,HANDLE engine,GB_PROCESS_IMAGE_FACTS &facts) const noexcept {
    facts={};
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        if(cause.appState_.load()!=1 || !device_ || cause.owner_.get()!=this || cause.record_.session!=session_ || cause.record_.loss!=loss_ ||
           !originalProcess(cause) || !catalogCurrent(cause,engine))return false;
        auto query=GB_CLASSIFIER_QUERY{cause.record_.session,cause.record_.cause};DWORD bytes=0;GB_PROCESS_IMAGE_FACTS observed{};
        if(!classifierIo(device_.value,GB_CLASSIFIER_IMAGE_CURRENT,&query,sizeof(query),&observed,sizeof(observed),&bytes,nullptr) ||
           bytes!=sizeof(observed) || !validImage(observed,cause.record_) || !originalProcess(cause) ||
           !catalogCurrent(cause,engine))return false;
        facts=observed;return true;
    } catch(...) {return false;}
}
NativeImageWorker::NativeImageWorker():state_(std::make_shared<State>()) {
    state_->wake.reset(CreateEventW(nullptr,FALSE,FALSE,nullptr));
    if(!state_->wake)throw std::runtime_error("No se pudo crear el evento del productor de imagen");
    thread_=std::thread([state=state_]{run(state);});
}
NativeImageWorker::~NativeImageWorker() {stop();if(thread_.joinable())thread_.join();}
std::uint64_t NativeImageWorker::submit(const std::shared_ptr<ClassifierCause> &cause,std::uint64_t appDeadline) noexcept {
    try {
        if(!cause || !cause->owner_ || (cause->appState_.load()==0 && (!appDeadline || GetTickCount64()>=appDeadline)))return 0;
        std::uint64_t submitted=0;
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            if(state_->stop || state_->physical || state_->finishing || state_->queued || state_->sequence==UINT64_MAX)return 0;
        }
        auto operation=std::make_shared<Operation>();auto owner=cause->owner_;
        {
            std::lock_guard<std::mutex> lock(owner->mutex_);HANDLE duplicate=nullptr;
            if(!owner->device_ || !serviceCaller() || cause->record_.session!=owner->session_ || cause->record_.loss!=owner->loss_ ||
               !DuplicateHandle(GetCurrentProcess(),owner->device_.value,GetCurrentProcess(),&duplicate,0,FALSE,DUPLICATE_SAME_ACCESS))return 0;
            operation->device.reset(duplicate);
        }
        operation->event.reset(CreateEventW(nullptr,TRUE,FALSE,nullptr));if(!operation->event)return 0;
        operation->overlap.hEvent=operation->event.value;operation->query={cause->record_.session,cause->record_.cause};
        auto job=std::make_unique<Job>();job->cause=cause;job->operation=operation;
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            if(state_->stop || state_->physical || state_->finishing || state_->queued || state_->sequence==UINT64_MAX)return 0;
            job->id=++state_->sequence;submitted=job->id;state_->id=job->id;state_->eligible=true;state_->completed=false;state_->valid=false;
            if(cause->appState_.load()==0) {cause->appJob_=job->id;cause->appDeadline_=appDeadline;}
            state_->result={};state_->physical=operation;state_->queued=std::move(job);
        }
        state_->changed.notify_one();return submitted;
    } catch(...) {return 0;}
}
void NativeImageWorker::run(std::shared_ptr<State> state) noexcept {
    for(;;) {
        std::unique_ptr<Job> job;std::array<State::Retired,64> retired{};std::size_t count=0;
        {
            std::unique_lock<std::mutex> lock(state->mutex);
            state->changed.wait(lock,[&]{return state->stop || state->queued || state->retiredCount;});
            count=state->retiredCount;state->retiredCount=0;
            for(std::size_t i=0;i<count;++i)retired[i]=std::move(state->retired[i]);
            if(state->queued)job=std::move(state->queued);
            else if(state->stop && !count)break;
        }
        std::size_t released=0,releasedProcesses=0;
        for(std::size_t i=0;i<count;++i){released+=retired[i].charge;releasedProcesses+=retired[i].process;retired[i].owner.reset();}
        if(released) {
            {std::lock_guard<std::mutex> lock(state->mutex);state->releasedCharge+=released;state->releasedProcesses+=releasedProcesses;}
            SetEvent(state->wake.value);
        }
        if(!job)continue;
        bool eligible=false,valid=false;DWORD bytes=0;
        {std::lock_guard<std::mutex> lock(state->mutex);eligible=!state->stop && state->eligible && state->id==job->id;}
        const auto owner=job->cause->owner_;
        if(eligible && owner->originalProcess(*job->cause)) {
            FWP_BYTE_BLOB *app=nullptr;
            const auto answer=FwpmGetAppIdFromFileName0(job->cause->process_.image.c_str(),&app);
            bool sameApp=answer==ERROR_SUCCESS && app && app->data && app->size==job->cause->record_.appBytes &&
                std::equal(job->cause->record_.app,job->cause->record_.app+job->cause->record_.appBytes,app->data);
            if(app)FwpmFreeMemory0(reinterpret_cast<void **>(&app));
            sameApp=sameApp && owner->originalProcess(*job->cause);
            if(sameApp) {
                std::lock_guard<std::mutex> lock(owner->mutex_);DWORD ignored=0;
                sameApp=owner->device_ && owner->session_==job->cause->record_.session && owner->loss_==job->cause->record_.loss &&
                    classifierIo(owner->device_.value,GB_CLASSIFIER_CURRENT,&job->operation->query,
                        sizeof(job->operation->query),nullptr,0,&ignored,nullptr);
            }
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                unsigned pending=0;
                const bool admitted=sameApp && !state->stop && state->eligible && state->id==job->id;
                job->cause->appState_.compare_exchange_strong(pending,admitted ? 1u : 2u);
            }
            SetEvent(state->wake.value); // Pull del AppId requerido, previo a IMAGE FS.
            // La precondición AppId se publica antes de IMAGE FS opcional.
            if(job->cause->appState_.load()!=1)sameApp=false;
            if(sameApp) {
            auto &operation=*job->operation;
            const auto immediate=DeviceIoControl(operation.device.value,GB_CLASSIFIER_IMAGE_FACTS,&operation.query,sizeof(operation.query),
                &operation.facts,sizeof(operation.facts),nullptr,&operation.overlap);
            const auto error=immediate ? ERROR_SUCCESS : GetLastError();
            bool abandoned=false;
            {std::lock_guard<std::mutex> lock(state->mutex);abandoned=state->stop || !state->eligible || state->id!=job->id;}
            // Cerrar también la carrera de cancel antes del submit OS real.
            if(abandoned && (immediate || error==ERROR_IO_PENDING))CancelIoEx(operation.device.value,&operation.overlap);
            if(immediate || error==ERROR_IO_PENDING)
                valid=GetOverlappedResult(operation.device.value,&operation.overlap,&bytes,TRUE) && bytes==sizeof(operation.facts) &&
                    validImage(operation.facts,job->cause->record_) && owner->originalProcess(*job->cause);
            if(valid){std::lock_guard<std::mutex> lock(owner->mutex_);
                valid=owner->device_ && owner->session_==job->cause->record_.session && owner->loss_==job->cause->record_.loss;}
            }
        } else {
            unsigned pending=0;job->cause->appState_.compare_exchange_strong(pending,2u);
        }
        const auto id=job->id;const auto observed=job->operation->facts;std::shared_ptr<Operation> completed;
        {
            std::unique_lock<std::mutex> lock(state->mutex);
            state->changed.wait(lock,[&]{return state->cancelBorrows==0;});
            state->finishing=true;completed=std::move(state->physical);
        }
        // La destrucción final de cause y los préstamos físicos ocurre sin mutex.
        job.reset();completed.reset();
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->completed=true;state->finishing=false;
            state->valid=valid && !state->stop && state->eligible && state->id==id;
            state->result=state->valid ? observed : GB_PROCESS_IMAGE_FACTS{};
        }
        SetEvent(state->wake.value); // Completion física, sin callback/puntero Runtime.
    }
}
bool NativeImageWorker::result(std::uint64_t id,GB_PROCESS_IMAGE_FACTS &facts,bool &valid) noexcept {
    facts={};valid=false;std::lock_guard<std::mutex> lock(state_->mutex);
    if(state_->id!=id || !state_->completed)return false;
    valid=state_->valid;if(valid)facts=state_->result;return true;
}
void NativeImageWorker::abandon(std::uint64_t id) noexcept {
    std::shared_ptr<Operation> operation;
    {std::lock_guard<std::mutex> lock(state_->mutex);if(state_->id!=id)return;
        state_->eligible=false;operation=state_->physical;if(operation)++state_->cancelBorrows;}
    if(operation) {
        CancelIoEx(operation->device.value,&operation->overlap);operation.reset();
        {std::lock_guard<std::mutex> lock(state_->mutex);--state_->cancelBorrows;}
        state_->changed.notify_one();
    }
}
void NativeImageWorker::stop() noexcept {
    std::shared_ptr<Operation> operation;
    {std::lock_guard<std::mutex> lock(state_->mutex);state_->stop=true;state_->eligible=false;operation=state_->physical;
        if(operation)++state_->cancelBorrows;}
    if(operation) {
        CancelIoEx(operation->device.value,&operation->overlap);operation.reset();
        {std::lock_guard<std::mutex> lock(state_->mutex);--state_->cancelBorrows;}
    }
    state_->changed.notify_one();
}
bool NativeImageWorker::retire(std::shared_ptr<void> &owner,std::size_t charge,bool process) noexcept {
    {std::lock_guard<std::mutex> lock(state_->mutex);
        if(state_->stop || state_->retiredCount==state_->retired.size())return false;
        state_->retired[state_->retiredCount++]={std::move(owner),charge,process};}
    state_->changed.notify_one();return true;
}
std::size_t NativeImageWorker::releasedCharge(std::size_t &processes) noexcept {
    std::lock_guard<std::mutex> lock(state_->mutex);const auto charge=state_->releasedCharge;state_->releasedCharge=0;
    processes=state_->releasedProcesses;state_->releasedProcesses=0;return charge;
}
} // namespace gatebouncer::service::windows::allapps::native
