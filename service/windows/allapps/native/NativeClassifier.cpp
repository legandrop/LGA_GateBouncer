#include "NativeClassifier.h"
#include <algorithm>
#include <cstring>

namespace gatebouncer::service::windows::allapps::native {
namespace {
bool serviceCaller() noexcept {
    gb::native::Handle token; HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) return false;
    token.reset(raw); return gb::native::systemServiceToken(token.value);
}
bool equal(const GUID &a, const GUID &b) noexcept { return std::memcmp(&a, &b, sizeof(a)) == 0; }
struct Memory { void *p = nullptr; ~Memory() { if (p) FwpmFreeMemory0(&p); } };
}
std::shared_ptr<NativeClassifier> NativeClassifier::open() noexcept {
    try {
        if (!serviceCaller()) return {};
        auto owner = std::shared_ptr<NativeClassifier>(new NativeClassifier);
        owner->device_.reset(CreateFileW(GB_CLASSIFIER_DEVICE, GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
        DWORD bytes = 0;
        if (!owner->device_ || !DeviceIoControl(owner->device_.value, GB_CLASSIFIER_START, nullptr, 0,
            nullptr, 0, &bytes, nullptr) || !owner->reset()) return {};
        return owner;
    } catch (...) { return {}; }
}
bool NativeClassifier::reset() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    GB_CLASSIFIER_STATE state{}; DWORD bytes = 0;
    if (!device_ || !serviceCaller() || !DeviceIoControl(device_.value, GB_CLASSIFIER_RESET, nullptr, 0,
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
        GB_CLASSIFIER_RECORD record{}; DWORD bytes = 0;
        if (!device_ || !serviceCaller()) { lost = true; return {}; }
        if (!DeviceIoControl(device_.value, GB_CLASSIFIER_NEXT, nullptr, 0, &record, sizeof(record), &bytes, nullptr)) {
            lost = GetLastError() != ERROR_NO_MORE_ITEMS; return {};
        }
        gb::native::ProcessEvidence process;
        process.process.reset(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(record.processHandle)));
        GB_CLASSIFIER_QUERY query{record.session, record.cause};
        auto discard = [&] { DWORD ignored = 0;
            DeviceIoControl(device_.value, GB_CLASSIFIER_RELEASE, &query, sizeof(query), nullptr, 0, &ignored, nullptr); };
        struct Delivery {
            decltype(discard) &drop;
            bool transferred = false;
            ~Delivery() noexcept { if (!transferred) drop(); }
        } delivery{discard};
        if (bytes != sizeof(record) || record.version != GB_CLASSIFIER_VERSION || record.bytes != sizeof(record) ||
            record.session != session_ || record.loss != loss_ || !record.cause || !process.process ||
            !record.endpoint || !record.filterId || !record.pid || record.pid > MAXDWORD || !record.created ||
            !record.timestamp || (record.family != 4 && record.family != 6) || record.protocol != 6 ||
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
        FWP_BYTE_BLOB *app = nullptr;
        const auto appResult = FwpmGetAppIdFromFileName0(process.image.c_str(), &app);
        const bool sameApp = appResult == ERROR_SUCCESS && app && app->size == record.appBytes &&
            app->data && std::equal(record.app, record.app + record.appBytes, app->data);
        if (app) FwpmFreeMemory0(reinterpret_cast<void **>(&app));
        if (!sameApp || !gb::native::tokenEvidence(token.value, identity) ||
            identity.account != gb::wire::Bytes(record.user, record.user + record.userBytes) || !process.current()) {
            lost = true; return {};
        }
        DWORD ignored = 0;
        if (!DeviceIoControl(device_.value, GB_CLASSIFIER_CURRENT, &query, sizeof(query), nullptr, 0, &ignored, nullptr)) {
            lost = true; return {};
        }
        // Si falla el controlblock, shared_ptr destruye la causa y libera el
        // registry kernel; esa destrucción nunca reentra un mutex retenido.
        lock.unlock();
        auto accepted = std::shared_ptr<ClassifierCause>(new ClassifierCause(shared_from_this(), record,
            std::move(process), std::move(identity)));
        delivery.transferred = true;
        return accepted;
    } catch (...) { lost = true; return {}; }
}
void NativeClassifier::release(const GB_CLASSIFIER_QUERY &q) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    auto copy = q; DWORD bytes = 0;
    if (device_) DeviceIoControl(device_.value, GB_CLASSIFIER_RELEASE, &copy, sizeof(copy), nullptr, 0, &bytes, nullptr);
}
bool NativeClassifier::current(const ClassifierCause &cause) const noexcept {
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        if (cause.owner_.get() != this || cause.record_.session != session_ || cause.record_.loss != loss_ ||
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
        return DeviceIoControl(device_.value, GB_CLASSIFIER_CURRENT, &query, sizeof(query), nullptr, 0, &bytes, nullptr) &&
            cause.process_.current();
    } catch (...) { return false; }
}
bool NativeClassifier::filterCurrent(const ClassifierCause &cause, HANDLE engine) const noexcept {
    if (!current(cause) || !engine) return false;
    Memory filter, callout;
    FWPM_FILTER0 f{}; FWPM_CALLOUT0 c{}; GUID provider{};
    const auto i = cause.record_.family == 4 ? 0 : 1;
    const auto &layer = i == 0 ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    if (FwpmFilterGetById0(engine, cause.record_.filterId, reinterpret_cast<FWPM_FILTER0 **>(&filter.p)) != ERROR_SUCCESS ||
        !guardedRead(&f, filter.p, sizeof(f)) || !f.providerKey ||
        !guardedRead(&provider, f.providerKey, sizeof(provider)) || !equal(provider, GbClassifierProvider) ||
        !equal(f.filterKey, GbClassifierFilters[i]) || !equal(f.subLayerKey, GbClassifierSublayer) ||
        !equal(f.layerKey, layer) || f.flags || f.action.type != FWP_ACTION_CALLOUT_INSPECTION ||
        !equal(f.action.calloutKey, GbClassifierCallouts[i]) || f.rawContext || f.numFilterConditions ||
        f.providerData.size || f.weight.type != FWP_EMPTY) return false;
    if (FwpmCalloutGetByKey0(engine, &GbClassifierCallouts[i], reinterpret_cast<FWPM_CALLOUT0 **>(&callout.p)) != ERROR_SUCCESS ||
        !guardedRead(&c, callout.p, sizeof(c)) || !c.providerKey ||
        !guardedRead(&provider, c.providerKey, sizeof(provider)) || !equal(provider, GbClassifierProvider) ||
        !equal(c.calloutKey, GbClassifierCallouts[i]) || !equal(c.applicableLayer, layer) ||
        c.flags != FWPM_CALLOUT_FLAG_REGISTERED) return false;
    return current(cause);
}
} // namespace gatebouncer::service::windows::allapps::native
