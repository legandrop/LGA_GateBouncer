#include "maintenance_iv.h"
#include "windows/allapps/native/NativeSource.h"
#include "wfp_backend.h"
#include <algorithm>
#include <cstring>
namespace gb::decisions {
namespace {
using Reason = gatebouncer::service::windows::allapps::Reason;
bool same(const GUID &a,const GUID &b) { return std::memcmp(&a,&b,sizeof(a)) == 0; }
bool ownKeys(GUID &provider,GUID &sublayer) {
    allnative::recipe::RecipeWorkspace workspace;
    allnative::recipe::SlotView slot; slot.filterGeneration = 1;
    Id baseline{}; baseline[0] = 0xab;
    allnative::recipe::ExpectedFilterView expected;
    if (allnative::recipe::deriveFilterKey(baseline,0,slot.key) != Reason::None ||
        allnative::recipe::buildExpectedView(slot,workspace,expected) != Reason::None) return false;
    provider = expected.provider; sublayer = expected.sublayer; return true;
}
bool wfpDescriptor(PSECURITY_DESCRIPTOR sd) {
    if (!sd || !IsValidSecurityDescriptor(sd)) return false;
    BYTE sy[SECURITY_MAX_SID_SIZE]{}, ba[SECURITY_MAX_SID_SIZE]{}; DWORD sn = sizeof(sy), bn = sizeof(ba);
    if (!CreateWellKnownSid(WinLocalSystemSid,nullptr,sy,&sn) || !CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,ba,&bn)) return false;
    auto trusted = [&](PSID sid) { return sid && IsValidSid(sid) && (EqualSid(sid,sy) || EqualSid(sid,ba)); };
    PSID owner = nullptr; PACL acl = nullptr; BOOL present = FALSE, def = FALSE;
    SECURITY_DESCRIPTOR_CONTROL control = 0; DWORD revision = 0;
    if (!GetSecurityDescriptorOwner(sd,&owner,&def) || !trusted(owner) ||
        !GetSecurityDescriptorDacl(sd,&present,&acl,&def) || !present || !acl || !IsValidAcl(acl) ||
        !GetSecurityDescriptorControl(sd,&control,&revision) || !(control & SE_DACL_PROTECTED)) return false;
    GENERIC_MAPPING mapping{FWPM_GENERIC_READ,FWPM_GENERIC_WRITE,FWPM_GENERIC_EXECUTE,FWPM_GENERIC_ALL};
    bool fullSy = false, fullBa = false;
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        void *raw = nullptr; if (!GetAce(acl,i,&raw)) return false;
        auto header = static_cast<ACE_HEADER *>(raw);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceFlags) return false;
        auto ace = static_cast<ACCESS_ALLOWED_ACE *>(raw); DWORD mask = ace->Mask;
        if (!trusted(&ace->SidStart) || (mask & MAXIMUM_ALLOWED)) return false;
        MapGenericMask(&mask,&mapping);
        if ((mask & FWPM_GENERIC_ALL) == FWPM_GENERIC_ALL) {
            fullSy |= EqualSid(&ace->SidStart,sy) != FALSE; fullBa |= EqualSid(&ace->SidStart,ba) != FALSE;
        }
    }
    return fullSy && fullBa;
}
}
MaintenanceRuntime::MaintenanceRuntime(std::filesystem::path store,bool allowMissing,Current check,void *context,controller::DeploymentMode mode)
    : check_(check), context_(context), allowMissing_(allowMissing), mode_(mode), file_(std::move(store)) {}
MaintenanceRuntime::~MaintenanceRuntime() {
    plan_.reset(); reserved_.reset(); read_ = {}; store_.reset(); binding_.reset();
    if (observation_) observation_->retire();
    if (fault_) fault_->retire();
    if (write_) FwpmEngineClose0(write_);
}
bool MaintenanceRuntime::current() const {
    if (!check_ || !context_ || !check_(context_) || !store_ || store_->uncertain()) return false;
    if (missing()) return allowMissing_ && const_cast<directional::NativeSnapshotFile &>(file_).cleanForInitial(store_.get());
    bool sameBytes = false, exists = false;
    return read_.kind == principal::StoredImage::Principal &&
        const_cast<directional::NativeSnapshotFile &>(file_).compare(read_.snapshot.encoded.data(),
            read_.snapshot.encoded.size(),sameBytes,exists) && sameBytes && exists;
}
bool MaintenanceRuntime::prepare() {
    if (store_ || !check_ || !context_ || !check_(context_) || (mode_ == controller::DeploymentMode::Laboratory && !guestActivationAuthorized())) return false;
    try {
        reserved_.reset(new CatalogPlanBuilder(registry_,allnative::MaxPolicyArenaBytes,allnative::MaxCatalogRules,allnative::MaxCatalogSlots));
        auto file = std::shared_ptr<directional::SnapshotFile>(&file_,[](auto *) {});
        store_ = std::make_unique<principal::SnapshotStore>(std::move(file));
        if (!store_->loadRetained(read_,reserved_.get(),&CatalogPlanBuilder::retainRead) || !current()) return false;
        if (!missing() && read_.snapshot.storedState != State::Applied) {
            const auto &s = read_.snapshot;
            if (s.storedState != State::RecoveryRequired || s.sequence != 1 || s.desired || !zero(s.active) ||
                !s.rules.empty() || !s.entries.empty() || s.archive.size() || s.migrationBase ||
                s.effective || s.storedKnown || s.activeProjection != Digest{} || s.activeAdmission != Digest{} || s.archiveDigest != Digest{}) return false;
        }
        FWPM_SESSION0 session{}; session.txnWaitTimeoutInMSec = 1000;
        session.displayData.name = const_cast<wchar_t *>(L"LGA GateBouncer maintenance");
        error_ = FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,&session,&write_);
        if (error_ != ERROR_SUCCESS || !write_ || write_ == INVALID_HANDLE_VALUE) { write_ = nullptr; return false; }
        sdk_ = allnative::systemSdk();
        if (missing()) return absent(false);
        observation_ = EngineResource::acquire(1,&fault_);
        if (!observation_ || !sdk_.allocate) return false;
        LUID index{}; if (!sdk_.allocate(&index)) return false;
        const auto value = (std::uint64_t(static_cast<std::uint32_t>(index.HighPart)) << 32) | index.LowPart;
        if (!value || value == UINT64_MAX) return false;
        binding_.reset(new allnative::BindingState(observation_->context_,value,observation_->generation_));
        if (observation_->readDomain(domain_,support_,supportCount_) != Reason::None) return false;
        return inspect(false) && current();
    } catch (...) { error_ = ERROR_INVALID_STATE; return false; }
}
bool MaintenanceRuntime::objectSecurity() const {
    GUID provider{}, sublayer{}; if (!write_ || !ownKeys(provider,sublayer)) return false;
    FWPM_PROVIDER0 *p = nullptr; FWPM_SUBLAYER0 *s = nullptr;
    const auto a = FwpmProviderGetByKey0(write_,&provider,&p), b = FwpmSubLayerGetByKey0(write_,&sublayer,&s);
    bool ok = a == ERROR_SUCCESS && b == ERROR_SUCCESS && p && s && p->serviceName &&
        std::wcscmp(p->serviceName,controller::deploymentService(mode_)) == 0 && same(p->providerKey,provider) &&
        p->flags == FWPM_PROVIDER_FLAG_PERSISTENT && s->providerKey && same(*s->providerKey,provider) &&
        same(s->subLayerKey,sublayer) && s->flags == FWPM_SUBLAYER_FLAG_PERSISTENT && s->weight == 0x7d00;
    if (p) FwpmFreeMemory0(reinterpret_cast<void **>(&p));
    if (s) FwpmFreeMemory0(reinterpret_cast<void **>(&s));
    for (bool isProvider : {true,false}) {
        PSECURITY_DESCRIPTOR sd = nullptr;
        const auto query = isProvider ? &FwpmProviderGetSecurityInfoByKey0 : &FwpmSubLayerGetSecurityInfoByKey0;
        const auto result = query(write_,isProvider ? &provider : &sublayer,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,nullptr,nullptr,nullptr,nullptr,&sd);
        ok = ok && result == ERROR_SUCCESS && wfpDescriptor(sd);
        if (sd) FwpmFreeMemory0(reinterpret_cast<void **>(&sd));
    }
    return ok;
}
bool MaintenanceRuntime::inspect(bool insideWrite) {
    if (missing()) return absent(insideWrite);
    if (!current() || !observation_ || !binding_ || !objectSecurity()) return false;
    try {
        if (!plan_) {
            // Mismo builder que retuvo los bytes físicos y su arena/cargo en loadRetained.
            // Mover el unique_ptr conserva la identidad; nunca aceptar Existing ajeno.
            if (!reserved_) return false;
            plan_ = std::move(reserved_);
            if (plan_->stage(read_.snapshot.encoded,binding_,1,domain_,{support_.data(),supportCount_}) != Reason::None) return false;
        }
        // Cada confirmación reinicia seen/observed y lee TODO el inventario actual.
        // Dentro de write_ no abre otra transacción ni reutiliza resultados previos.
        if (plan_->confirmInventoryBody(write_,sdk_,&allnative::guardedRead,!insideWrite) != Reason::None) return false;
        return current() && objectSecurity();
    } catch (...) { return false; }
}
bool MaintenanceRuntime::absent(bool insideWrite) {
    GUID provider{}, sublayer{};
    if (!current() || !write_ || !ownKeys(provider,sublayer)) return false;
    bool transaction = false;
    if (!insideWrite) {
        error_ = FwpmTransactionBegin0(write_,FWPM_TXN_READ_ONLY);
        if (error_ != ERROR_SUCCESS) return false;
        transaction = true;
    }
    FWPM_PROVIDER0 *p = nullptr; FWPM_SUBLAYER0 *s = nullptr;
    auto a = FwpmProviderGetByKey0(write_,&provider,&p), b = FwpmSubLayerGetByKey0(write_,&sublayer,&s);
    bool ok = a == FWP_E_PROVIDER_NOT_FOUND && b == FWP_E_SUBLAYER_NOT_FOUND && !p && !s;
    if (p) FwpmFreeMemory0(reinterpret_cast<void **>(&p));
    if (s) FwpmFreeMemory0(reinterpret_cast<void **>(&s));
    HANDLE enumeration = nullptr;
    if (ok) ok = FwpmFilterCreateEnumHandle0(write_,nullptr,&enumeration) == ERROR_SUCCESS && enumeration;
    std::size_t total = 0; bool terminal = false;
    while (ok && !terminal) {
        FWPM_FILTER0 **rows = nullptr; UINT32 count = 0;
        const auto result = FwpmFilterEnum0(write_,enumeration,64,&rows,&count);
        ok = result == ERROR_SUCCESS && count <= 64 && (!count || rows) && count <= 65536-total;
        for (UINT32 i = 0; ok && i < count; ++i) {
            FWPM_FILTER0 *pointer = nullptr; FWPM_FILTER0 header{}; GUID owner{};
            ok = allnative::guardedRead(&pointer,rows+i,sizeof(pointer)) && pointer &&
                allnative::guardedRead(&header,pointer,sizeof(header));
            if (ok && header.providerKey) ok = allnative::guardedRead(&owner,header.providerKey,sizeof(owner)) && !same(owner,provider);
        }
        if (rows) FwpmFreeMemory0(reinterpret_cast<void **>(&rows));
        total += count; terminal = count < 64;
    }
    if (enumeration && FwpmFilterDestroyEnumHandle0(write_,enumeration) != ERROR_SUCCESS) ok = false;
    if (transaction && FwpmTransactionAbort0(write_) != ERROR_SUCCESS) { cleanupUnknown_ = true; ok = false; }
    return ok && terminal && current();
}
bool MaintenanceRuntime::remove() {
    if (attempted_ || !current() || !write_) return false;
    attempted_ = true;
    if (missing()) return absent(false);
    bool transaction = false;
    try {
        error_ = FwpmTransactionBegin0(write_,0);
        if (error_ != ERROR_SUCCESS) return false;
        transaction = true;
        if (!inspect(true)) error_ = ERROR_INVALID_STATE;
        if (error_ == ERROR_SUCCESS) {
            for (const auto &slot : plan_->storage_.storage_->slots_) {
                GUID key{}; std::memcpy(&key,slot.key.data(),sizeof(key));
                error_ = FwpmFilterDeleteByKey0(write_,&key); if (error_ != ERROR_SUCCESS) break;
            }
        }
        GUID provider{}, sublayer{};
        if (error_ == ERROR_SUCCESS && (!ownKeys(provider,sublayer) || !current())) error_ = ERROR_INVALID_STATE;
        if (error_ == ERROR_SUCCESS) error_ = FwpmSubLayerDeleteByKey0(write_,&sublayer);
        if (error_ == ERROR_SUCCESS) error_ = FwpmProviderDeleteByKey0(write_,&provider);
        if (error_ == ERROR_SUCCESS) {
            error_ = FwpmTransactionCommit0(write_);
            if (error_ == ERROR_SUCCESS) { transaction = false; committed_ = true; }
            else cleanupUnknown_ = true; // Un commit sin confirmar no admite DeleteService.
        }
        if (transaction) {
            transaction = false;
            if (FwpmTransactionAbort0(write_) != ERROR_SUCCESS) cleanupUnknown_ = true;
        }
        return committed_ && !cleanupUnknown_ && absent(false);
    } catch (...) {
        error_ = ERROR_INVALID_STATE;
        if (transaction && FwpmTransactionAbort0(write_) != ERROR_SUCCESS) cleanupUnknown_ = true;
        return false;
    }
}
} // namespace gb::decisions
