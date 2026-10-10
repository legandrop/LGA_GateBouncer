#include "deployment_maintenance_win.h"
#include "../service/maintenance_iv.h"
#include <aclapi.h>
#include <sddl.h>
#include <algorithm>
#include <set>
namespace gb::controller {
namespace {
constexpr wchar_t mutexName[] = L"Global\\LGA.GateBouncerLab.Maintenance.IX";
bool mutexSecurity(HANDLE handle) {
    PSECURITY_DESCRIPTOR sd = nullptr; PSID owner = nullptr; PACL acl = nullptr;
    const auto error = GetSecurityInfo(handle,SE_KERNEL_OBJECT,OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner,nullptr,&acl,nullptr,&sd);
    BYTE sy[SECURITY_MAX_SID_SIZE]{}, ba[SECURITY_MAX_SID_SIZE]{}; DWORD sn = sizeof(sy), bn = sizeof(ba), revision = 0;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    bool ok = error == ERROR_SUCCESS && sd && acl && IsValidAcl(acl) &&
        CreateWellKnownSid(WinLocalSystemSid,nullptr,sy,&sn) && CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,ba,&bn) &&
        owner && IsValidSid(owner) && (EqualSid(owner,sy) || EqualSid(owner,ba)) &&
        GetSecurityDescriptorControl(sd,&control,&revision) && (control & SE_DACL_PROTECTED);
    bool fullSy = false, fullBa = false;
    GENERIC_MAPPING mapping{STANDARD_RIGHTS_READ | SYNCHRONIZE,STANDARD_RIGHTS_WRITE | MUTEX_MODIFY_STATE,
        STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,MUTEX_ALL_ACCESS};
    for (DWORD i = 0; ok && i < acl->AceCount; ++i) {
        void *raw = nullptr; if (!GetAce(acl,i,&raw)) { ok = false; break; }
        auto header = static_cast<ACE_HEADER *>(raw);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceFlags) { ok = false; break; }
        auto ace = static_cast<ACCESS_ALLOWED_ACE *>(raw); DWORD mask = ace->Mask;
        if (!IsValidSid(&ace->SidStart) || (mask & MAXIMUM_ALLOWED) ||
            (!EqualSid(&ace->SidStart,sy) && !EqualSid(&ace->SidStart,ba))) { ok = false; break; }
        MapGenericMask(&mask,&mapping);
        if ((mask & MUTEX_ALL_ACCESS) == MUTEX_ALL_ACCESS) {
            fullSy |= EqualSid(&ace->SidStart,sy) != FALSE; fullBa |= EqualSid(&ace->SidStart,ba) != FALSE;
        }
    }
    if (sd) LocalFree(sd);
    return ok && fullSy && fullBa;
}
bool readString(HKEY key,const wchar_t *name,std::wstring &out) {
    wchar_t bytes[32768]{}; DWORD size = sizeof(bytes);
    if (RegGetValueW(key,nullptr,name,RRF_RT_REG_SZ,nullptr,bytes,&size) != ERROR_SUCCESS ||
        size < sizeof(wchar_t) || size > sizeof(bytes) || size % sizeof(wchar_t) ||
        bytes[size/sizeof(wchar_t)-1] || wcslen(bytes)+1 != size/sizeof(wchar_t)) return false;
    out = bytes; return !out.empty();
}
bool readDword(HKEY key,const wchar_t *name,DWORD &out) {
    DWORD size = sizeof(out);
    return RegGetValueW(key,nullptr,name,RRF_RT_REG_DWORD,nullptr,&out,&size) == ERROR_SUCCESS && size == sizeof(out);
}
bool status(SC_HANDLE service,SERVICE_STATUS_PROCESS &out) {
    DWORD count = 0;
    return QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE *>(&out),sizeof(out),&count) &&
        count == sizeof(out) && out.dwServiceType == SERVICE_WIN32_OWN_PROCESS;
}
}
namespace deployment_detail {
AdministrativeLease::~AdministrativeLease() {
    if (owns_) ReleaseMutex(mutex_.value);
    if (gate_) RegCloseKey(gate_);
    if (parent_) RegCloseKey(parent_);
}
bool AdministrativeLease::acquire(bool fresh) {
    if (owns_ || gate_ || token_) return false;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) return false;
    token_.reset(token);
    if (!native::tokenEvidence(token_.value,actor_) || !actor_.administrator || !actor_.elevated ||
        actor_.uiAccess || actor_.integrity < SECURITY_MANDATORY_HIGH_RID ||
        (fresh && mode_ != DeploymentMode::Product)) return false;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)",
        SDDL_REVISION_1,&sd,nullptr)) return false;
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),sd,FALSE};
    mutex_.reset(CreateMutexExW(&attributes,mode_ == DeploymentMode::Product ? L"Global\\LGA.GateBouncer.Maintenance" : mutexName,0,MUTEX_ALL_ACCESS)); LocalFree(sd);
    if (!mutex_ || !mutexSecurity(mutex_.value)) return false;
    const auto wait = WaitForSingleObject(mutex_.value,0);
    owns_ = wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED;
    if (wait != WAIT_OBJECT_0) return false; // No adoptar abandono ni esperar otro mantenimiento.
    wchar_t path[32768]{}; const auto count = GetModuleFileNameW(nullptr,path,32768);
    if (!count || count >= 32768) return false;
    image_ = std::filesystem::path(std::wstring(path,count));
    if (image_.filename() != L"GateBouncerService.exe" || !native::fixedPath(image_) ||
        !pinSource(image_.parent_path(),source_)) return false;
    // Crear sólo la raíz propia nueva, después del token y la fuente originales.
    if (fresh) {
        PSECURITY_DESCRIPTOR registry = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)",SDDL_REVISION_1,&registry,nullptr)) return false;
        SECURITY_ATTRIBUTES attributes{sizeof(attributes),registry,FALSE}; DWORD disposition = 0;
        auto error = RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\LGA",REG_OPTION_OPEN_LINK,
            KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY | READ_CONTROL,&parent_);
        if (error == ERROR_FILE_NOT_FOUND) {
            error = RegCreateKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\LGA",0,nullptr,REG_OPTION_NON_VOLATILE,
                KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY | READ_CONTROL,&attributes,&parent_,&disposition);
            if (disposition != REG_CREATED_NEW_KEY) error = ERROR_ALREADY_EXISTS;
        }
        DWORD bytes = 0;
        if (error != ERROR_SUCCESS || !native::protectedRegistry(parent_) ||
            RegQueryValueExW(parent_,L"SymbolicLinkValue",nullptr,nullptr,nullptr,&bytes) != ERROR_FILE_NOT_FOUND) {
            LocalFree(registry); return false;
        }
        error = RegCreateKeyExW(parent_,L"GateBouncer",0,nullptr,
            REG_OPTION_NON_VOLATILE,KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY | READ_CONTROL,
            &attributes,&gate_,&disposition);
        LocalFree(registry);
        if (error != ERROR_SUCCESS || disposition != REG_CREATED_NEW_KEY ||
            !native::protectedRegistry(gate_) || RegFlushKey(gate_) != ERROR_SUCCESS) return false;
    } else if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,deploymentRegistry(mode_),0,
        KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY | READ_CONTROL,&gate_) != ERROR_SUCCESS) return false;
    if (mode_ == DeploymentMode::Product && !parent_ &&
        RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\LGA",REG_OPTION_OPEN_LINK,
            KEY_QUERY_VALUE | READ_CONTROL,&parent_) != ERROR_SUCCESS) return false;
    return current();
}
bool AdministrativeLease::current() const {
    native::TokenEvidence fresh;
    DWORD enabled = 0;
    if (!owns_ || !token_ || !gate_ || !mutexSecurity(mutex_.value) ||
        !native::tokenEvidence(token_.value,fresh) || fresh.account != actor_.account || fresh.logon != actor_.logon ||
        fresh.session != actor_.session || !fresh.administrator || !fresh.elevated || fresh.uiAccess ||
        fresh.integrity < SECURITY_MANDATORY_HIGH_RID || !native::protectedRegistry(gate_) ||
        (mode_ == DeploymentMode::Laboratory && (!readDword(gate_,L"EnableWfp",enabled) || enabled != 1))) return false;
    HKEY repeated = nullptr;
    const auto opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE,deploymentRegistry(mode_),0,
        KEY_QUERY_VALUE | READ_CONTROL,&repeated);
    const bool sameGate = opened == ERROR_SUCCESS && compareObjectHandles(gate_,repeated);
    if (repeated) RegCloseKey(repeated);
    if (!sameGate) return false;
    if (mode_ == DeploymentMode::Product) {
        HKEY repeatedParent = nullptr; DWORD bytes = 0;
        const bool original = parent_ && native::protectedRegistry(parent_) &&
            RegQueryValueExW(parent_,L"SymbolicLinkValue",nullptr,nullptr,nullptr,&bytes) == ERROR_FILE_NOT_FOUND &&
            RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\LGA",REG_OPTION_OPEN_LINK,
                KEY_QUERY_VALUE | READ_CONTROL,&repeatedParent) == ERROR_SUCCESS && compareObjectHandles(parent_,repeatedParent);
        if (repeatedParent) RegCloseKey(repeatedParent);
        if (!original) return false;
    }
    for (const auto &handle : source_) {
        FILE_ATTRIBUTE_TAG_INFO shape{};
        if (!GetFileInformationByHandleEx(handle.value,FileAttributeTagInfo,&shape,sizeof(shape)) ||
            !native::protectedObject(handle.value,bool(shape.FileAttributes & FILE_ATTRIBUTE_DIRECTORY),
                bool(shape.FileAttributes & FILE_ATTRIBUTE_DIRECTORY),true)) return false;
    }
    wchar_t path[32768]{}; const auto count = GetModuleFileNameW(nullptr,path,32768);
    return count && count < 32768 && std::filesystem::path(std::wstring(path,count)) == image_;
}
bool AdministrativeLease::ownsConfiguration(HKEY key) const {
    if (!key || !current() || !native::protectedRegistry(key)) return false;
    HKEY gate = nullptr, configuration = nullptr;
    const auto opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE,deploymentRegistry(mode_),0,
        KEY_QUERY_VALUE | READ_CONTROL,&gate);
    bool ok = opened == ERROR_SUCCESS && compareObjectHandles(gate_,gate) &&
        RegOpenKeyExW(gate,deploymentConfiguration(mode_),0,KEY_QUERY_VALUE | READ_CONTROL,&configuration) == ERROR_SUCCESS &&
        compareObjectHandles(key,configuration) && native::protectedRegistry(configuration);
    if (configuration) RegCloseKey(configuration);
    if (gate) RegCloseKey(gate);
    return ok && current(); // El handle retenido debe seguir siendo el mismo objeto bajo el mismo gate.
}
}
class GuestMaintenance {
    const DeploymentMode mode_;
    deployment_detail::AdministrativeLease lease_;
    std::shared_ptr<Deployment> package_, replacement_;
    HKEY key_ = nullptr;
    SC_HANDLE manager_ = nullptr, service_ = nullptr;
    std::filesystem::path active_, store_, original_;
    std::wstring view_;
    std::wstring recoveryRoot_, recoveryOrdinary_;
    DWORD provision_ = 0, marker_ = 0, start_ = SERVICE_AUTO_START;
    bool hadMarker_ = false, mutated_ = false, closed_ = false;
    bool finalizing_ = false;
    std::unique_ptr<native::ProtectedDirectory> retainedStore_;
    native::ProcessEvidence process_;
    std::unique_ptr<decisions::MaintenanceRuntime> policy_;
    MaintenanceResult result_;
    bool tuple() const {
        bool present = false; DWORD state = 0, initial = 0;
        std::wstring root, ordinary, store, view;
        return key_ && native::protectedRegistry(key_) && lease_.current() &&
            (!(finalizing_ || mode_ == DeploymentMode::Product) || lease_.ownsConfiguration(key_)) &&
            (!finalizing_ || (retainedStore_ && retainedStore_->acquire())) &&
            maintenanceState(key_,present,state) && present == hadMarker_ && state == marker_ &&
            readString(key_,L"PackageRoot",root) && root == active_.native() &&
            readString(key_,L"OrdinaryImage",ordinary) && ordinary == (active_/L"GateBouncer.exe").native() &&
            readString(key_,L"StoreRoot",store) && store == store_.native() &&
            readString(key_,L"ViewSid",view) && view == view_ &&
            readDword(key_,L"ProvisionPrincipal",initial) && initial == provision_;
    }
    bool current() const {
        if (!tuple() || !package_ || !package_->current() || (replacement_ && !replacement_->current()) ||
            !service_ || !serviceConfigurationPhase(service_,active_/L"GateBouncerService.exe",start_,0,mode_)) return false;
        SERVICE_STATUS_PROCESS info{};
        if (!status(service_,info)) return false;
        if (closed_) return info.dwCurrentState == SERVICE_STOPPED && !info.dwProcessId &&
            (!process_.process || WaitForSingleObject(process_.process.value,0) == WAIT_OBJECT_0);
        return true;
    }
    static bool retained(void *raw) noexcept {
        try { return static_cast<GuestMaintenance *>(raw)->current(); } catch (...) { return false; }
    }
    bool recoveryCurrent() const {
        // Estado esperado de las escrituras propias ya confirmadas, incluso en un switch parcial.
        // No requiere un tuple operativo completo ni adopta valores ajenos.
        std::wstring root, ordinary, store, view; DWORD provision = 0;
        return key_ && lease_.ownsConfiguration(key_) && package_ && package_->current() &&
            (!replacement_ || replacement_->current()) &&
            readString(key_,L"PackageRoot",root) && root == recoveryRoot_ &&
            readString(key_,L"OrdinaryImage",ordinary) && ordinary == recoveryOrdinary_ &&
            readString(key_,L"StoreRoot",store) && store == store_.native() &&
            readString(key_,L"ViewSid",view) && view == view_ &&
            readDword(key_,L"ProvisionPrincipal",provision) && provision == provision_;
    }
    MaintenanceResult fail(DWORD error = ERROR_INVALID_STATE,bool pending = false) {
        result_.error = error == ERROR_SUCCESS ? ERROR_INVALID_STATE : error;
        result_.outcome = pending ? MaintenanceOutcome::Pending : mutated_ ? MaintenanceOutcome::Recovery : MaintenanceOutcome::Rejected;
        if (mutated_ && recoveryCurrent()) {
            result_.recoveryRecorded = deployment_detail::mark(key_,4,marker_,lease_);
            if (result_.recoveryRecorded) { marker_ = 4; hadMarker_ = true; }
        }
        return result_;
    }
    bool admit(const std::filesystem::path &root,bool finalization = false) {
        finalizing_ = finalization;
        if (!lease_.acquire() || !native::fixedPath(root) || !deployment_detail::disjoint(root,lease_.image().parent_path())) return false;
        active_ = original_ = root; recoveryRoot_ = root.native();
        recoveryOrdinary_ = (root/L"GateBouncer.exe").native(); package_ = std::make_shared<Deployment>(root,mode_);
        if (!package_->verify(root/L"GateBouncerService.exe",DeploymentRole::Service) || !package_->current() ||
            RegOpenKeyExW(lease_.gate(),deploymentConfiguration(mode_),0,KEY_QUERY_VALUE | READ_CONTROL |
                (finalization ? 0 : KEY_SET_VALUE),&key_) != ERROR_SUCCESS ||
            !native::protectedRegistry(key_) || !maintenanceState(key_,hadMarker_,marker_) || marker_ != 0 ||
            (mode_ == DeploymentMode::Product && !hadMarker_) ||
            (finalization && (!hadMarker_ || !lease_.ownsConfiguration(key_)))) return false;
        std::wstring store;
        if (!readString(key_,L"StoreRoot",store) || !readString(key_,L"ViewSid",view_) ||
            !readDword(key_,L"ProvisionPrincipal",provision_) || provision_ > 1) return false;
        store_ = store;
        native::ProtectedDirectory directory(store_);
        if (!deployment_detail::disjoint(root,store_) || !deployment_detail::disjoint(store_,lease_.image().parent_path()) || !directory.acquire()) return false;
        if (finalization) {
            retainedStore_ = std::make_unique<native::ProtectedDirectory>(store_);
            if (!retainedStore_->acquire()) return false;
        }
        PSID sid = nullptr; if (!ConvertStringSidToSidW(view_.c_str(),&sid)) return false;
        const auto valid = IsValidSid(sid) && native::sidString(wire::Bytes(static_cast<BYTE *>(sid),
            static_cast<BYTE *>(sid)+GetLengthSid(sid))) == view_; LocalFree(sid); if (!valid) return false;
        manager_ = OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
        if (!manager_) return false;
        service_ = OpenServiceW(manager_,deploymentService(mode_),SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS |
            SERVICE_CHANGE_CONFIG | READ_CONTROL | (finalization ? 0 : SERVICE_STOP | DELETE));
        if (finalization) {
            closed_ = true;
            // Sólo esta operación explícita admite Disabled; Auto requiere el mismo readback íntegro.
            start_ = serviceConfigurationPhase(service_,root/L"GateBouncerService.exe",SERVICE_DISABLED,0,mode_) ?
                SERVICE_DISABLED : SERVICE_AUTO_START;
        }
        return current(); // Legado sin marker sólo después del tuple/ACL/SCM/paquete completos.
    }
    bool begin(DWORD phase) {
        if (!current()) return false;
        // El primer marcador durable precede a cualquier configuración mutable.
        mutated_ = true;
        if (!hadMarker_) {
            if (!deployment_detail::setDword(key_,L"MaintenanceVersion",1) ||
                !deployment_detail::setDword(key_,L"MaintenanceState",phase)) return false;
            hadMarker_ = true; marker_ = phase;
        } else {
            if (!deployment_detail::mark(key_,phase,marker_,lease_)) return false;
            marker_ = phase;
        }
        if (!current() || !ChangeServiceConfigW(service_,SERVICE_NO_CHANGE,SERVICE_DISABLED,SERVICE_NO_CHANGE,
            nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr)) return false;
        start_ = SERVICE_DISABLED; return current();
    }
    bool stop() {
        if (!current()) return false;
        SERVICE_STATUS_PROCESS before{}; if (!status(service_,before)) return false;
        if (before.dwCurrentState == SERVICE_STOPPED && !before.dwProcessId) { closed_ = true; return current(); }
        if (before.dwCurrentState != SERVICE_RUNNING || !before.dwProcessId || !process_.acquire(before.dwProcessId) ||
            process_.image != active_/L"GateBouncerService.exe" || !current() ||
            !serviceConfigurationPhase(service_,active_/L"GateBouncerService.exe",SERVICE_DISABLED,process_.pid,mode_)) return false;
        HANDLE raw = nullptr; native::Handle token;
        if (!OpenProcessToken(process_.process.value,TOKEN_QUERY,&raw)) return false;
        token.reset(raw);
        if (!native::systemServiceToken(token.value,deploymentService(mode_)) || !process_.current()) return false;
        SERVICE_STATUS stopped{};
        if (!ControlService(service_,SERVICE_CONTROL_STOP,&stopped)) return false;
        const auto deadline = GetTickCount64()+10000;
        while (GetTickCount64() < deadline) {
            if (!current()) return false;
            SERVICE_STATUS_PROCESS info{}; if (!status(service_,info)) return false;
            const auto wait = WaitForSingleObject(process_.process.value,50);
            if (wait == WAIT_FAILED || (info.dwProcessId && info.dwProcessId != process_.pid)) return false;
            FILETIME created{}, exit{}, kernel{}, user{};
            if (!GetProcessTimes(process_.process.value,&created,&exit,&kernel,&user) || CompareFileTime(&created,&process_.created)) return false;
            if (wait == WAIT_OBJECT_0 && info.dwCurrentState == SERVICE_STOPPED && !info.dwProcessId) {
                closed_ = true; return current();
            }
            if (wait == WAIT_OBJECT_0) Sleep(25);
        }
        SetLastError(ERROR_TIMEOUT); return false;
    }
    bool loadPolicy() {
        if (!closed_ || !current() || policy_) return false;
        policy_.reset(new decisions::MaintenanceRuntime(store_,provision_ == 1,&retained,this,mode_));
        return policy_->prepare() && policy_->current();
    }
    bool removeConfiguration() {
        if (!tuple() || !key_ || !closed_) return false;
        const wchar_t *names[] = {L"PackageRoot",L"OrdinaryImage",L"StoreRoot",L"ViewSid",L"ProvisionPrincipal",L"MaintenanceState",L"MaintenanceVersion"};
        const std::wstring texts[] = {active_.native(),(active_/L"GateBouncer.exe").native(),store_.native(),view_};
        const DWORD numbers[] = {provision_,marker_,1};
        // El mutex impide otro mantenimiento propio; valores/subclaves extranjeros se preservan.
        for (unsigned i = 0; i < 7; ++i) {
            const auto *name = names[i]; std::wstring text; DWORD number = 0;
            const bool exact = i < 4 ? readString(key_,name,text) && text == texts[i] :
                readDword(key_,name,number) && number == numbers[i-4];
            if (!exact || !native::protectedRegistry(key_) || !lease_.current() || !package_->current() ||
                (mode_ == DeploymentMode::Product && !lease_.ownsConfiguration(key_)) ||
                RegDeleteValueW(key_,name) != ERROR_SUCCESS) return false;
            DWORD bytes = 0; if (RegQueryValueExW(key_,name,nullptr,nullptr,nullptr,&bytes) != ERROR_FILE_NOT_FOUND) return false;
        }
        if (RegFlushKey(key_) != ERROR_SUCCESS) return false;
        DWORD subkeys = 0, values = 0;
        if (RegQueryInfoKeyW(key_,nullptr,nullptr,nullptr,&subkeys,nullptr,nullptr,&values,nullptr,nullptr,nullptr,nullptr) != ERROR_SUCCESS) return false;
        if (subkeys || values) return true; // Registro contenedor con datos extranjeros: no DeleteTree.
        RegCloseKey(key_); key_ = nullptr;
        if (RegDeleteKeyW(lease_.gate(),deploymentConfiguration(mode_)) != ERROR_SUCCESS || RegFlushKey(lease_.gate()) != ERROR_SUCCESS) return false;
        HKEY probe = nullptr; const auto query = RegOpenKeyExW(lease_.gate(),deploymentConfiguration(mode_),0,KEY_QUERY_VALUE,&probe);
        if (probe) RegCloseKey(probe);
        return query == ERROR_FILE_NOT_FOUND;
    }
  public:
    explicit GuestMaintenance(DeploymentMode mode = DeploymentMode::Laboratory) : mode_(mode), lease_(mode) {}
    ~GuestMaintenance() {
        policy_.reset(); if (service_) CloseServiceHandle(service_);
        if (manager_) CloseServiceHandle(manager_); if (key_) RegCloseKey(key_);
    }
    MaintenanceResult finalize(const std::filesystem::path &root) {
        // Un resultado incierto preserva marker0: nunca usar fail(), que registra otro marcador.
        const auto recovery = [this](DWORD error = ERROR_INVALID_STATE) {
            result_.outcome = MaintenanceOutcome::Recovery;
            result_.error = error == ERROR_SUCCESS ? ERROR_INVALID_STATE : error;
            return result_;
        };
        try {
            if (!admit(root,true)) return recovery();
            result_.phase = MaintenancePhase::Store;
            if (!loadPolicy()) return recovery(policy_ ? policy_->error_ : ERROR_INVALID_STATE);
            result_.phase = MaintenancePhase::Inventory;
            if (!current() || !policy_->current() || !policy_->inspect(false) || !current()) return recovery();
            result_.phase = MaintenancePhase::Service;
            if (start_ == SERVICE_DISABLED) {
                if (!ChangeServiceConfigW(service_,SERVICE_NO_CHANGE,SERVICE_AUTO_START,SERVICE_NO_CHANGE,
                    nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr)) return recovery(GetLastError());
                start_ = SERVICE_AUTO_START;
            }
            if (!current() || !policy_->current() || !policy_->inspect(false) ||
                !current() || !policy_->current()) return recovery();
            result_.phase = MaintenancePhase::Complete;
            result_.outcome = MaintenanceOutcome::PreparedFinalized;
            result_.error = ERROR_SUCCESS; return result_;
        } catch (...) { return recovery(); }
    }
    MaintenanceResult update(const std::filesystem::path &root,const std::filesystem::path &source,const std::filesystem::path &replacement) {
        try {
            if (!admit(root) || lease_.image() != source/L"GateBouncerService.exe" ||
                !deployment_detail::disjoint(root,replacement) || !deployment_detail::disjoint(store_,replacement)) return fail();
            result_.phase = MaintenancePhase::Package;
            if (!deployment_detail::stagePackage(source,replacement,replacement_,mode_) || !current()) return fail();
            result_.phase = MaintenancePhase::Marker; if (!begin(2)) return fail(GetLastError());
            result_.phase = MaintenancePhase::Stop; if (!stop()) return fail(GetLastError());
            result_.phase = MaintenancePhase::Store; if (!loadPolicy()) return fail(policy_ ? policy_->error_ : ERROR_INVALID_STATE);
            result_.phase = MaintenancePhase::Switch;
            if (!current() || !policy_->current() || !replacement_->current()) return fail();
            const auto command = deploymentCommand(replacement/L"GateBouncerService.exe",mode_);
            if (!ChangeServiceConfigW(service_,SERVICE_NO_CHANGE,SERVICE_DISABLED,SERVICE_NO_CHANGE,command.c_str(),
                nullptr,nullptr,nullptr,nullptr,nullptr,nullptr)) return fail(GetLastError());
            if (!serviceConfigurationPhase(service_,replacement/L"GateBouncerService.exe",SERVICE_DISABLED,0,mode_) ||
                !lease_.current() || !package_->current() || !replacement_->current() || !tuple()) return fail();
            // Durante el switch el callback normal se cierra por tuple discordante; no llama Runtime/Initial.
            if (!deployment_detail::setString(key_,L"PackageRoot",replacement.native())) return fail();
            recoveryRoot_ = replacement.native();
            if (!deployment_detail::setString(key_,L"OrdinaryImage",(replacement/L"GateBouncer.exe").native())) return fail();
            recoveryOrdinary_ = (replacement/L"GateBouncer.exe").native();
            active_ = replacement;
            if (!policy_->missing()) {
                if (!deployment_detail::setDword(key_,L"ProvisionPrincipal",0)) return fail();
                provision_ = 0;
            }
            if (RegFlushKey(key_) != ERROR_SUCCESS || !current() || !policy_->current() ||
                !deployment_detail::mark(key_,0,marker_,lease_)) return fail();
            marker_ = 0;
            if (!current() || !ChangeServiceConfigW(service_,SERVICE_NO_CHANGE,SERVICE_AUTO_START,SERVICE_NO_CHANGE,
                nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr)) return fail(GetLastError());
            start_ = SERVICE_AUTO_START;
            if (!current() || !policy_->current()) return fail();
            result_.phase = MaintenancePhase::Complete; result_.outcome = MaintenanceOutcome::UpdatedPrepared;
            result_.error = ERROR_SUCCESS; return result_;
        } catch (...) { return fail(); }
    }
    MaintenanceResult uninstall(const std::filesystem::path &root) {
        try {
            if (!admit(root)) return fail();
            result_.phase = MaintenancePhase::Marker; if (!begin(3)) return fail(GetLastError());
            result_.phase = MaintenancePhase::Stop; if (!stop()) return fail(GetLastError());
            result_.phase = MaintenancePhase::Store; if (!loadPolicy()) return fail(policy_ ? policy_->error_ : ERROR_INVALID_STATE);
            result_.phase = MaintenancePhase::Filters;
            if (!policy_->remove()) return fail(policy_->error_);
            result_.phase = MaintenancePhase::Service;
            if (!current() || !policy_->current() || !DeleteService(service_)) return fail(GetLastError());
            // Este owner nunca adquirió Deployment::Registration. Cerrar TODO SC_HANDLE propio al servicio.
            CloseServiceHandle(service_); service_ = nullptr;
            const auto deadline = GetTickCount64()+2000; DWORD error = ERROR_SERVICE_MARKED_FOR_DELETE;
            do {
                if (!tuple() || !package_->current()) return fail();
                SC_HANDLE probe = OpenServiceW(manager_,deploymentService(mode_),SERVICE_QUERY_STATUS);
                error = probe ? ERROR_SERVICE_MARKED_FOR_DELETE : GetLastError();
                if (probe) CloseServiceHandle(probe);
                if (error == ERROR_SERVICE_DOES_NOT_EXIST) break;
                if (error != ERROR_SERVICE_MARKED_FOR_DELETE) return fail(error);
                Sleep(25);
            } while (GetTickCount64() < deadline);
            if (error != ERROR_SERVICE_DOES_NOT_EXIST) return fail(error,true);
            result_.phase = MaintenancePhase::Configuration;
            if (!removeConfiguration()) return fail(GetLastError());
            result_.phase = MaintenancePhase::Complete; result_.outcome = MaintenanceOutcome::UninstalledRetained;
            result_.error = ERROR_SUCCESS; return result_;
        } catch (...) { return fail(); }
    }
};
MaintenanceResult updateGuestDeployment(const std::filesystem::path &root,const std::filesystem::path &source,const std::filesystem::path &replacement) {
    GuestMaintenance owner; return owner.update(root,source,replacement);
}
MaintenanceResult uninstallGuestDeployment(const std::filesystem::path &root) {
    GuestMaintenance owner; return owner.uninstall(root);
}
MaintenanceResult finalizeGuestDeployment(const std::filesystem::path &root) {
    GuestMaintenance owner; return owner.finalize(root);
}
MaintenanceResult updateProductDeployment(const std::filesystem::path &root,const std::filesystem::path &source,const std::filesystem::path &replacement) {
    GuestMaintenance owner(DeploymentMode::Product); return owner.update(root,source,replacement);
}
MaintenanceResult uninstallProductDeployment(const std::filesystem::path &root) {
    GuestMaintenance owner(DeploymentMode::Product); return owner.uninstall(root);
}
MaintenanceResult finalizeProductDeployment(const std::filesystem::path &root) {
    GuestMaintenance owner(DeploymentMode::Product); return owner.finalize(root);
}
} // namespace gb::controller
