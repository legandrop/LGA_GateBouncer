#include "deployment_maintenance_win.h"
#include "../service/maintenance_iv.h"
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <algorithm>
#include <set>
#include <cstring>
namespace gb {
bool guestActivationAuthorized(){
    // Marcador administrativo del harness invitado. No se escribe desde el producto.
    DWORD enabled=0,size=sizeof(enabled);auto e=RegGetValueW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\LGA\\GateBouncerLab",L"EnableWfp",RRF_RT_REG_DWORD,nullptr,&enabled,&size);
    return e==ERROR_SUCCESS&&enabled==1&&IsUserAnAdmin();
}
}
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
    // pcbBytesNeeded sólo está definido por Windows en ERROR_INSUFFICIENT_BUFFER.
    // Conservar la guarda de tamaño en ese probe sobre el mismo SC_HANDLE original.
    if (QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,nullptr,0,&count) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || count != sizeof(out)) return false;
    return QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE *>(&out),sizeof(out),&count) &&
        out.dwServiceType == SERVICE_WIN32_OWN_PROCESS;
}
struct DriverRetirement {
    DWORD version = 1, state = 1, restart = 0;
    wire::Id boot{};
    wchar_t inf[MAX_PATH]{}, published[MAX_PATH]{};
    // FileIDs de los outputs Windows originales: directorio, SYS/INF/CAT y OEM INF.
    DWORD identities[5][3]{};
    DWORD provision = 0, userRemoval = 0;
    wchar_t package[MAX_PATH]{}, store[MAX_PATH]{}, view[184]{};
    DWORD packageIdentity[3]{};
    wire::Digest inventory{};
};
static_assert(sizeof(DriverRetirement) == 2588);
bool readRetirement(HKEY key,DriverRetirement &out) {
    DWORD size = sizeof(out);
    return RegGetValueW(key,nullptr,L"DriverRetirement",RRF_RT_REG_BINARY,nullptr,&out,&size) == ERROR_SUCCESS &&
        size == sizeof(out) && out.version == 1 && out.state >= 1 && out.state <= 3 && out.restart <= 1 && out.provision <= 1 && out.userRemoval <= 1 &&
        (out.state != 1 || (!out.restart && !out.userRemoval)) && (out.state == 3 || !out.userRemoval) &&
        wcsnlen(out.inf,MAX_PATH) < MAX_PATH && wcsnlen(out.published,MAX_PATH) < MAX_PATH &&
        wcsnlen(out.package,MAX_PATH) < MAX_PATH && wcsnlen(out.store,MAX_PATH) < MAX_PATH && wcsnlen(out.view,184) < 184 &&
        out.package[0] && out.store[0] && out.view[0] && out.inf[0] && out.published[0] &&
        std::any_of(out.boot.begin(),out.boot.end(),[](auto v) { return v != 0; });
}
bool sameIdentity(const BY_HANDLE_FILE_INFORMATION &id,const DWORD (&record)[3]) {
    return id.dwVolumeSerialNumber == record[0] && id.nFileIndexHigh == record[1] && id.nFileIndexLow == record[2];
}
void recordIdentity(const BY_HANDLE_FILE_INFORMATION &id,DWORD (&record)[3]) {
    record[0] = id.dwVolumeSerialNumber; record[1] = id.nFileIndexHigh; record[2] = id.nFileIndexLow;
}
bool remainingString(HKEY key,const wchar_t *name,const std::wstring &expected) {
    DWORD size = 0; const auto query = RegQueryValueExW(key,name,nullptr,nullptr,nullptr,&size);
    std::wstring text; return query == ERROR_FILE_NOT_FOUND || (query == ERROR_SUCCESS && readString(key,name,text) && text == expected);
}
bool remainingDword(HKEY key,const wchar_t *name,DWORD expected) {
    DWORD size = 0, number = 0; const auto query = RegQueryValueExW(key,name,nullptr,nullptr,nullptr,&size);
    return query == ERROR_FILE_NOT_FOUND || (query == ERROR_SUCCESS && readDword(key,name,number) && number == expected);
}
bool writeRetirement(HKEY key,const DriverRetirement &value,const deployment_detail::AdministrativeLease &lease) {
    DriverRetirement repeated{};
    return lease.ownsConfiguration(key) && RegSetValueExW(key,L"DriverRetirement",0,REG_BINARY,
        reinterpret_cast<const BYTE *>(&value),sizeof(value)) == ERROR_SUCCESS && RegFlushKey(key) == ERROR_SUCCESS &&
        readRetirement(key,repeated) && std::memcmp(&value,&repeated,sizeof(value)) == 0 && lease.ownsConfiguration(key);
}
struct ReplacementPlan {
    DWORD version = 1, phase = 1, restart = 0;
    wire::Id installBoot{};
    wchar_t oldRoot[MAX_PATH]{}, newRoot[MAX_PATH]{};
    DWORD oldIdentity[3]{}, newIdentity[3]{};
    wire::Digest oldInventory{}, newInventory{};
};
bool readReplacement(HKEY key,ReplacementPlan &plan) {
    DWORD size = sizeof(plan);
    return RegGetValueW(key,nullptr,L"DriverReplacement",RRF_RT_REG_BINARY,nullptr,&plan,&size) == ERROR_SUCCESS &&
        size == sizeof(plan) && plan.version == 1 && plan.phase >= 1 && plan.phase <= 3 && plan.restart <= 1 && plan.oldRoot[0] && plan.newRoot[0] &&
        wcsnlen(plan.oldRoot,MAX_PATH) < MAX_PATH && wcsnlen(plan.newRoot,MAX_PATH) < MAX_PATH &&
        (plan.phase == 3 ? std::any_of(plan.installBoot.begin(),plan.installBoot.end(),[](auto v) { return v != 0; }) : plan.restart == 0);
}
bool packageIdentity(Deployment &package,DWORD (&identity)[3],wire::Digest &inventory,bool original) {
    if (!package.current()) return false;
    native::Handle root(CreateFileW(package.root().c_str(),FILE_READ_ATTRIBUTES | READ_CONTROL,FILE_SHARE_READ,
        nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,nullptr));
    BY_HANDLE_FILE_INFORMATION id{};
    native::Handle file(CreateFileW((package.root()/L"deployment.gbd").c_str(),GENERIC_READ | READ_CONTROL,FILE_SHARE_READ,
        nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    LARGE_INTEGER size{}; DWORD count = 0;
    if (!root || !file || !native::protectedObject(root.value,true,true,true) || !GetFileInformationByHandle(root.value,&id) ||
        !package.matchesCreatedFile(package.root()/L"deployment.gbd",file.value) || !GetFileSizeEx(file.value,&size) || size.QuadPart <= 0 || size.QuadPart > 65536) return false;
    wire::Bytes bytes(static_cast<std::size_t>(size.QuadPart));
    if (!ReadFile(file.value,bytes.data(),DWORD(bytes.size()),&count,nullptr) || count != bytes.size() || !package.current()) return false;
    const auto digest = native::digest(bytes);
    if (!original) return sameIdentity(id,identity) && digest == inventory;
    recordIdentity(id,identity); inventory = digest; return true;
}
bool writeReplacement(HKEY key,const ReplacementPlan &plan,const deployment_detail::AdministrativeLease &lease) {
    ReplacementPlan repeated{};
    return lease.ownsConfiguration(key) && RegSetValueExW(key,L"DriverReplacement",0,REG_BINARY,
        reinterpret_cast<const BYTE *>(&plan),sizeof(plan)) == ERROR_SUCCESS && RegFlushKey(key) == ERROR_SUCCESS &&
        readReplacement(key,repeated) && std::memcmp(&plan,&repeated,sizeof(plan)) == 0 && lease.ownsConfiguration(key);
}
struct DriverMaintenanceModule {
    HMODULE value;
    explicit DriverMaintenanceModule(const wchar_t *name) : value(LoadLibraryExW(name,nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32)) {}
    ~DriverMaintenanceModule() { if (value) FreeLibrary(value); }
    DriverMaintenanceModule(const DriverMaintenanceModule &) = delete;
    DriverMaintenanceModule &operator=(const DriverMaintenanceModule &) = delete;
};
}
namespace deployment_detail {
bool replacementCurrent(Deployment &package,HKEY key) {
    ReplacementPlan plan{}; DriverRetirement receipt{};
    return native::protectedRegistry(key) && readRetirement(key,receipt) && receipt.state == 3 && readReplacement(key,plan) && plan.phase >= 2 &&
        package.root().native() == plan.newRoot && packageIdentity(package,plan.newIdentity,plan.newInventory,false);
}
AdministrativeLease::~AdministrativeLease() {
    if (owns_) ReleaseMutex(mutex_.value);
    if (boot_) RegCloseKey(boot_);
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
        !pinSource(image_.parent_path(),source_,mode_)) return false;
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
    if (boot_) {
        HKEY repeatedBoot = nullptr; wire::Id id{}; DWORD size = sizeof(id), symbolic = 0;
        const bool original = native::protectedRegistry(boot_) &&
            RegQueryValueExW(boot_,L"SymbolicLinkValue",nullptr,nullptr,nullptr,&symbolic) == ERROR_FILE_NOT_FOUND &&
            RegOpenKeyExW(gate_,L"BootSession",REG_OPTION_OPEN_LINK,KEY_QUERY_VALUE | READ_CONTROL,&repeatedBoot) == ERROR_SUCCESS &&
            compareObjectHandles(boot_,repeatedBoot) &&
            RegGetValueW(boot_,nullptr,L"Id",RRF_RT_REG_BINARY,nullptr,id.data(),&size) == ERROR_SUCCESS && size == sizeof(id) && id == bootId_;
        if (repeatedBoot) RegCloseKey(repeatedBoot);
        if (!original) return false;
    }
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
bool AdministrativeLease::bootIdentity(wire::Id &out) {
    if (mode_ != DeploymentMode::Product || !current()) return false;
    if (!boot_) {
        auto error = RegOpenKeyExW(gate_,L"BootSession",REG_OPTION_OPEN_LINK,KEY_QUERY_VALUE | READ_CONTROL,&boot_);
        if (error == ERROR_FILE_NOT_FOUND) {
            PSECURITY_DESCRIPTOR sd = nullptr;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)",SDDL_REVISION_1,&sd,nullptr)) return false;
            SECURITY_ATTRIBUTES attributes{sizeof(attributes),sd,FALSE}; DWORD disposition = 0;
            error = RegCreateKeyExW(gate_,L"BootSession",0,nullptr,REG_OPTION_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE | READ_CONTROL,&attributes,&boot_,&disposition);
            LocalFree(sd);
            if (error != ERROR_SUCCESS || disposition != REG_CREATED_NEW_KEY || !native::protectedRegistry(boot_)) return false;
            bootId_ = native::randomIdentity();
            if (!std::any_of(bootId_.begin(),bootId_.end(),[](auto v) { return v != 0; }) ||
                RegSetValueExW(boot_,L"Id",0,REG_BINARY,bootId_.data(),DWORD(bootId_.size())) != ERROR_SUCCESS) return false;
        } else if (error != ERROR_SUCCESS) return false;
        DWORD size = sizeof(bootId_);
        if (!native::protectedRegistry(boot_) || RegGetValueW(boot_,nullptr,L"Id",RRF_RT_REG_BINARY,nullptr,
            bootId_.data(),&size) != ERROR_SUCCESS || size != sizeof(bootId_) ||
            !std::any_of(bootId_.begin(),bootId_.end(),[](auto v) { return v != 0; })) return false;
    }
    if (!current()) return false;
    out = bootId_; return true;
}
}
bool Deployment::retiredProductDriverCurrent(deployment_detail::AdministrativeLease &lease,HKEY key,bool &reboot) {
    const std::lock_guard<std::recursive_mutex> lock(currentMutex_); reboot = false;
    bool present = false; DWORD marker = 0; DriverRetirement receipt{}; wire::Id boot{};
    std::wstring root;
    const auto ownRoot = [&]() {
        if (!readString(key,L"PackageRoot",root)) return receipt.state == 3 && receipt.userRemoval == 1 &&
            root_.native() == receipt.package && remainingString(key,L"PackageRoot",root_.native()) &&
            packageIdentity(*this,receipt.packageIdentity,receipt.inventory,false);
        if (root == root_.native()) return true;
        ReplacementPlan plan{};
        return marker == 2 && readReplacement(key,plan) && plan.phase == 2 && root_.native() == plan.oldRoot &&
            root == plan.newRoot && packageIdentity(*this,plan.oldIdentity,plan.oldInventory,false);
    };
    if (mode_ != DeploymentMode::Product || role_ != DeploymentRole::Service || driver_ || !current() ||
        !lease.ownsConfiguration(key) || !readRetirement(key,receipt) ||
        root_.native() != receipt.package || !packageIdentity(*this,receipt.packageIdentity,receipt.inventory,false) ||
        (!(maintenanceState(key,present,marker) && present && (marker == 2 || marker == 3)) &&
            !(receipt.state == 3 && receipt.userRemoval == 1 && remainingDword(key,L"MaintenanceVersion",1) && remainingDword(key,L"MaintenanceState",3))) ||
        !ownRoot() ||
        !lease.bootIdentity(boot)) return false;
    // Sólo ausencia completa tras el receipt de la operación original; ACCESS_DENIED no es ausencia.
    wchar_t windows[MAX_PATH]{}; const auto count = GetWindowsDirectoryW(windows,MAX_PATH);
    if (!count || count >= MAX_PATH) return false;
    const std::filesystem::path inf(receipt.inf), published(receipt.published);
    const std::filesystem::path systemRoot(std::wstring(windows,count));
    const auto repository = systemRoot/L"System32"/L"DriverStore"/L"FileRepository";
    const auto name = published.filename().native();
    if (!native::fixedPath(inf) || !native::fixedPath(published) ||
        inf.filename() != L"GateBouncerClassifier.inf" || _wcsicmp(inf.parent_path().parent_path().c_str(),repository.c_str()) ||
        _wcsicmp(published.parent_path().c_str(),(systemRoot/L"INF").c_str()) || name.size() < 8 ||
        _wcsnicmp(name.c_str(),L"oem",3) || _wcsicmp(name.c_str()+name.size()-4,L".inf") ||
        !std::all_of(name.begin()+3,name.end()-4,[](wchar_t c) { return c >= L'0' && c <= L'9'; })) return false;
    if (receipt.state != 1 && receipt.restart && boot == receipt.boot) {
        reboot = true; return lease.ownsConfiguration(key) && current();
    }
    DriverRegistration custody;
    // Retener todos los ancestros originales protegidos antes de consultar hojas ausentes.
    for (const auto &parent : {repository,published.parent_path()}) {
        std::vector<std::filesystem::path> ancestors;
        for (auto p = parent; !p.empty(); p = p.parent_path()) { ancestors.push_back(p); if (p == p.parent_path()) break; }
        for (auto p = ancestors.rbegin(); p != ancestors.rend(); ++p) if (!custody.hold(*p,true)) return false;
    }
    const auto pinsCurrent = [&]() { for (auto &p : custody.pins) if (!DriverRegistration::inspect(p,false)) return false; return true; };
    const auto absent = [&](const std::filesystem::path &path) {
        if (!pinsCurrent() || !lease.ownsConfiguration(key) || !current()) return false;
        native::Handle probe(CreateFileW(path.c_str(),FILE_READ_ATTRIBUTES | READ_CONTROL,FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,nullptr));
        const auto error = probe ? ERROR_ALREADY_EXISTS : GetLastError();
        return !probe && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) && pinsCurrent();
    };
    SC_HANDLE manager = OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
    if (!manager) return false;
    SC_HANDLE kernel = OpenServiceW(manager,L"LGAGateBouncerClassifier",SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL);
    const auto error = kernel ? ERROR_SERVICE_EXISTS : GetLastError();
    if (kernel) CloseServiceHandle(kernel); CloseServiceHandle(manager);
    if (error != ERROR_SERVICE_DOES_NOT_EXIST) return false;
    const auto directoryIndex = custody.pins.size();
    if (custody.hold(inf.parent_path(),true)) {
        if (!sameIdentity(custody.pins[directoryIndex].identity,receipt.identities[0])) return false;
        for (const auto &leaf : {L"GateBouncerClassifier.sys",L"GateBouncerClassifier.inf",L"GateBouncerClassifier.cat"})
            if (!absent(inf.parent_path()/leaf)) return false;
    } else {
        const auto directoryError = GetLastError();
        if (directoryError != ERROR_FILE_NOT_FOUND && directoryError != ERROR_PATH_NOT_FOUND) return false;
        if (!absent(inf.parent_path())) return false;
    }
    if (!absent(published) ||
        !pinsCurrent() || !lease.ownsConfiguration(key) || !current()) return false;
    // El intent state1 puede sobrevivir al efecto Windows sin resultado durable.
    // Ausencia total original no implica unload: resultado desconocido exige otro BootSession.
    if (receipt.state == 1 && boot == receipt.boot) {
        reboot = true; return pinsCurrent() && current() && lease.ownsConfiguration(key);
    }
    if (receipt.state != 3) { receipt.state = 3; if (!writeRetirement(key,receipt,lease)) return false; }
    return current() && lease.ownsConfiguration(key); // No afirma FileID de imagen cargada ni CI.
}
bool Deployment::retireProductDriver(deployment_detail::AdministrativeLease &lease,HKEY key,bool &reboot) {
    const std::lock_guard<std::recursive_mutex> lock(currentMutex_); reboot = false;
    bool present = false; DWORD marker = 0; std::wstring root;
    const auto ownRoot = [&]() {
        if (!readString(key,L"PackageRoot",root)) return false;
        if (root == root_.native()) return true;
        ReplacementPlan plan{};
        return marker == 2 && readReplacement(key,plan) && plan.phase == 2 && root_.native() == plan.oldRoot &&
            root == plan.newRoot && packageIdentity(*this,plan.oldIdentity,plan.oldInventory,false);
    };
    const auto admitted = [&]() { return mode_ == DeploymentMode::Product && role_ == DeploymentRole::Service && !driver_ &&
        current() && lease.ownsConfiguration(key) && maintenanceState(key,present,marker) && present && (marker == 2 || marker == 3) &&
        ownRoot(); };
    if (!admitted()) return false;
    DriverRetirement receipt{}; DWORD bytes = 0;
    const auto prior = RegQueryValueExW(key,L"DriverRetirement",nullptr,nullptr,nullptr,&bytes);
    if (prior == ERROR_SUCCESS) {
        if (!readRetirement(key,receipt)) return false;
        if (receipt.state >= 2) return retiredProductDriverCurrent(lease,key,reboot);
        // Primero resolver el intent original ya completado. Si todavía están todos
        // los outputs originales, sólo acquire + comparación íntegra permite retomar la API.
        if (retiredProductDriverCurrent(lease,key,reboot)) return true;
    } else if (prior != ERROR_FILE_NOT_FOUND) return false;
    DriverRegistration original;
    if (!original.acquire(*this,true) || !admitted()) return false;
    const auto count = original.pins.size(); if (count < 4) return false;
    const auto infPath = original.pins[count-2].path;
    DriverMaintenanceModule setup(L"setupapi.dll"), api(L"newdev.dll");
    using Published = BOOL (WINAPI *)(PCWSTR,PWSTR,DWORD,PDWORD);
    using Uninstall = BOOL (WINAPI *)(HWND,LPCWSTR,DWORD,PBOOL);
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4191)
#endif
    const auto publishedName = setup.value ? reinterpret_cast<Published>(GetProcAddress(setup.value,"SetupGetInfPublishedNameW")) : nullptr;
    const auto uninstall = api.value ? reinterpret_cast<Uninstall>(GetProcAddress(api.value,"DiUninstallDriverW")) : nullptr;
#ifdef _MSC_VER
#pragma warning(pop)
#endif
    DriverRetirement expected{}; DWORD required = 0;
    if (!publishedName || !uninstall || infPath.native().size() >= MAX_PATH ||
        !publishedName(infPath.c_str(),expected.published,MAX_PATH,&required) || required <= 1 || required > MAX_PATH ||
        expected.published[required-1] || wcsnlen(expected.published,MAX_PATH)+1 != required) return false;
    std::copy(infPath.native().begin(),infPath.native().end(),expected.inf);
    wchar_t windows[MAX_PATH]{}; const auto windowCount = GetWindowsDirectoryW(windows,MAX_PATH);
    const std::filesystem::path published(expected.published), infParent = std::filesystem::path(windows)/L"INF";
    const auto name = published.filename().native();
    if (!windowCount || windowCount >= MAX_PATH || !native::fixedPath(published) ||
        _wcsicmp(published.parent_path().c_str(),infParent.c_str()) || name.size() < 8 || _wcsnicmp(name.c_str(),L"oem",3) ||
        _wcsicmp(name.c_str()+name.size()-4,L".inf") ||
        !std::all_of(name.begin()+3,name.end()-4,[](wchar_t c) { return c >= L'0' && c <= L'9'; }) ||
        !original.hold(infParent,true)) return false;
    wire::Bytes publishedBytes;
    if (!original.hold(published,false,&publishedBytes) || native::digest(publishedBytes) != inventory_.at(L"driver\\GateBouncerClassifier.inf") ||
        !original.current() || !admitted() || !lease.bootIdentity(expected.boot)) return false;
    std::wstring store, view; DWORD provision = 0;
    if (!readString(key,L"StoreRoot",store) || !readString(key,L"ViewSid",view) || !readDword(key,L"ProvisionPrincipal",provision) ||
        provision > 1 || root_.native().size() >= MAX_PATH || store.size() >= MAX_PATH || view.size() >= 184 ||
        !packageIdentity(*this,expected.packageIdentity,expected.inventory,true)) return false;
    expected.provision = provision;
    std::copy(root_.native().begin(),root_.native().end(),expected.package);
    std::copy(store.begin(),store.end(),expected.store); std::copy(view.begin(),view.end(),expected.view);
    recordIdentity(original.pins[count-4].identity,expected.identities[0]);
    for (unsigned i = 0; i < 3; ++i) recordIdentity(original.pins[count-3+i].identity,expected.identities[i+1]);
    recordIdentity(original.pins.back().identity,expected.identities[4]);
    if (prior == ERROR_SUCCESS) {
        // Un intent sin resultado sólo puede retomarse con los mismos outputs originales aún presentes.
        expected.boot = receipt.boot;
        if (std::memcmp(&expected,&receipt,sizeof(receipt))) return false;
    } else if (!writeRetirement(key,expected,lease)) return false;
    if (!original.current() || !admitted()) return false;
    BOOL needReboot = FALSE;
    const auto wasRunning = original.state != SERVICE_STOPPED;
    // Reopen bajo custodia de los handles/ACL originales. SY/BA/TI son TCB sólo filesystem/instalación.
    const bool removed = uninstall(nullptr,infPath.c_str(),0,&needReboot) != FALSE;
    const auto error = GetLastError();
    // Retener identidad y bytes originales aun si Windows desvinculó los nombres durante su operación.
    bool originals = true;
    for (auto &pin : original.pins) {
        BY_HANDLE_FILE_INFORMATION now{};
        originals = originals && GetFileInformationByHandle(pin.handle.value,&now) &&
            now.dwVolumeSerialNumber == pin.identity.dwVolumeSerialNumber && now.nFileIndexHigh == pin.identity.nFileIndexHigh &&
            now.nFileIndexLow == pin.identity.nFileIndexLow && native::protectedObject(pin.handle.value,true,pin.directory,true) &&
            (pin.directory || (now.nFileSizeHigh == pin.identity.nFileSizeHigh && now.nFileSizeLow == pin.identity.nFileSizeLow &&
                CompareFileTime(&now.ftLastWriteTime,&pin.identity.ftLastWriteTime) == 0));
    }
    if (!removed || !originals || !admitted()) { SetLastError(!removed && error ? error : ERROR_INVALID_STATE); return false; }
    expected.state = 2; expected.restart = needReboot || wasRunning;
    if (!writeRetirement(key,expected,lease)) return false;
    // Cerrar el handle kernel propio: DeleteService diferido no se confirma manteniéndolo abierto.
    CloseServiceHandle(original.service); original.service = nullptr;
    reboot = expected.restart != 0;
    if (reboot) return admitted();
    return retiredProductDriverCurrent(lease,key,reboot);
}
class GuestMaintenance {
    const DeploymentMode mode_;
    deployment_detail::AdministrativeLease lease_;
    std::shared_ptr<Deployment> package_, replacement_, previous_;
    ReplacementPlan replacementPlan_{};
    bool haveReplacement_ = false;
    DriverRetirement retirement_{};
    bool cleanupReceipt_ = false, userGone_ = false;
    bool reinstall_ = false, restoring_ = false;
    HKEY key_ = nullptr;
    SC_HANDLE manager_ = nullptr, service_ = nullptr;
    std::filesystem::path active_, store_, original_;
    std::wstring view_;
    std::wstring recoveryRoot_, recoveryOrdinary_;
    DWORD provision_ = 0, marker_ = 0, start_ = SERVICE_AUTO_START;
    bool hadMarker_ = false, mutated_ = false, closed_ = false;
    bool finalizing_ = false, pendingRemoval_ = false, resumingDriver_ = false, driverGone_ = false, policyRemoval_ = false;
    std::unique_ptr<native::ProtectedDirectory> retainedStore_;
    native::ProcessEvidence process_;
    std::unique_ptr<decisions::MaintenanceRuntime> policy_;
    MaintenanceResult result_;
    bool tuple() const {
        if (cleanupReceipt_) {
            DriverRetirement original{};
            return marker_ == 3 && retirement_.state == 3 && retirement_.userRemoval == 1 &&
                lease_.ownsConfiguration(key_) && readRetirement(key_,original) && std::memcmp(&original,&retirement_,sizeof(original)) == 0 &&
                retainedStore_ && retainedStore_->acquire() &&
                remainingString(key_,L"PackageRoot",active_.native()) &&
                remainingString(key_,L"OrdinaryImage",(active_/L"GateBouncer.exe").native()) &&
                remainingString(key_,L"StoreRoot",store_.native()) && remainingString(key_,L"ViewSid",view_) &&
                remainingDword(key_,L"ProvisionPrincipal",provision_) && remainingDword(key_,L"MaintenanceVersion",1) &&
                (restoring_ && haveReplacement_ && replacementPlan_.phase == 1 ?
                    remainingDword(key_,L"MaintenanceState",3) || remainingDword(key_,L"MaintenanceState",2) :
                    remainingDword(key_,L"MaintenanceState",3));
        }
        bool present = false; DWORD state = 0, initial = 0;
        std::wstring root, ordinary, store, view;
        return key_ && native::protectedRegistry(key_) && lease_.current() &&
            (!(finalizing_ || mode_ == DeploymentMode::Product) || lease_.ownsConfiguration(key_)) &&
            (!(finalizing_ || pendingRemoval_ || resumingDriver_) || (retainedStore_ && retainedStore_->acquire())) &&
            maintenanceState(key_,present,state) && present == hadMarker_ && state == marker_ &&
            readString(key_,L"PackageRoot",root) &&
            (haveReplacement_ && marker_ == 2 && replacementPlan_.phase == 2 ?
                root == replacementPlan_.oldRoot || root == replacementPlan_.newRoot : root == active_.native()) &&
            readString(key_,L"OrdinaryImage",ordinary) &&
            (haveReplacement_ && marker_ == 2 && replacementPlan_.phase == 2 ?
                ordinary == (std::filesystem::path(replacementPlan_.oldRoot)/L"GateBouncer.exe").native() ||
                ordinary == (std::filesystem::path(replacementPlan_.newRoot)/L"GateBouncer.exe").native() : ordinary == (active_/L"GateBouncer.exe").native()) &&
            readString(key_,L"StoreRoot",store) && store == store_.native() &&
            readString(key_,L"ViewSid",view) && view == view_ &&
            readDword(key_,L"ProvisionPrincipal",initial) && initial == provision_;
    }
    bool current() const {
        if (!tuple() || !package_ || !package_->current() || (replacement_ && !replacement_->current()) ||
            (previous_ && !previous_->current())) return false;
        if (userGone_) {
            if (!cleanupReceipt_ || !closed_ || service_ || !manager_) return false;
            SC_HANDLE probe = OpenServiceW(manager_,deploymentService(mode_),SERVICE_QUERY_STATUS);
            const auto error = probe ? ERROR_SERVICE_EXISTS : GetLastError();
            if (probe) CloseServiceHandle(probe);
            return error == ERROR_SERVICE_DOES_NOT_EXIST && tuple();
        }
        if (!service_) return false;
        const bool serviceExact = haveReplacement_ && marker_ == 2 && replacementPlan_.phase == 2 ?
            serviceConfigurationPhase(service_,std::filesystem::path(replacementPlan_.oldRoot)/L"GateBouncerService.exe",SERVICE_DISABLED,0,mode_) ||
            serviceConfigurationPhase(service_,std::filesystem::path(replacementPlan_.newRoot)/L"GateBouncerService.exe",SERVICE_DISABLED,0,mode_) :
            serviceConfigurationPhase(service_,active_/L"GateBouncerService.exe",start_,0,mode_);
        if (!serviceExact) return false;
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
        result_.outcome = pending ? MaintenanceOutcome::Pending :
            (mutated_ || resumingDriver_ || cleanupReceipt_ || (haveReplacement_ && marker_ == 2)) ?
                MaintenanceOutcome::Recovery : MaintenanceOutcome::Rejected;
        // Los receipts Product de retiro conservan marker2/3; nunca convertirlos en marker4 genérico.
        if (mutated_ && !resumingDriver_ && !driverGone_ &&
            !(mode_ == DeploymentMode::Product && (haveReplacement_ || marker_ == 2 || marker_ == 3)) && recoveryCurrent()) {
            result_.recoveryRecorded = deployment_detail::mark(key_,4,marker_,lease_);
            if (result_.recoveryRecorded) { marker_ = 4; hadMarker_ = true; }
        }
        return result_;
    }
    bool admit(const std::filesystem::path &root,bool finalization = false,bool uninstallOnly = false,bool updateOnly = false) {
        if (finalization && uninstallOnly) return false;
        finalizing_ = finalization;
        if (!lease_.acquire() || !native::fixedPath(root) || !deployment_detail::disjoint(root,lease_.image().parent_path())) return false;
        active_ = original_ = root; recoveryRoot_ = root.native();
        recoveryOrdinary_ = (root/L"GateBouncer.exe").native();
        if (RegOpenKeyExW(lease_.gate(),deploymentConfiguration(mode_),0,KEY_QUERY_VALUE | READ_CONTROL |
                (finalization && mode_ == DeploymentMode::Laboratory ? 0 : KEY_SET_VALUE),&key_) != ERROR_SUCCESS ||
            !native::protectedRegistry(key_)) return false;
        const bool terminal = mode_ == DeploymentMode::Product && readRetirement(key_,retirement_) &&
            retirement_.state == 3 && retirement_.userRemoval == 1;
        ReplacementPlan terminalPlan{}; DWORD terminalSize = 0;
        const auto terminalPlanQuery = RegQueryValueExW(key_,L"DriverReplacement",nullptr,nullptr,nullptr,&terminalSize);
        const bool terminalPlanPresent = terminalPlanQuery == ERROR_SUCCESS && readReplacement(key_,terminalPlan) &&
            terminalPlan.oldRoot == std::wstring(retirement_.package);
        bool markerPresent = false; DWORD terminalMarker = 0;
        const bool knownMarker = maintenanceState(key_,markerPresent,terminalMarker);
        reinstall_ = terminal && ((updateOnly && (terminalPlanQuery == ERROR_FILE_NOT_FOUND || terminalPlanPresent)) ||
            (finalization && terminalPlanPresent && terminalPlan.phase == 3 && knownMarker && markerPresent && terminalMarker == 0));
        restoring_ = reinstall_ && updateOnly && (!terminalPlanPresent || terminalPlan.phase == 1) &&
            ((!knownMarker && remainingDword(key_,L"MaintenanceVersion",1) &&
              (remainingDword(key_,L"MaintenanceState",3) || (terminalPlanPresent && remainingDword(key_,L"MaintenanceState",2)))) ||
             (knownMarker && (!markerPresent || terminalMarker == 3 || (terminalPlanPresent && terminalMarker == 2))));
        cleanupReceipt_ = terminal && (uninstallOnly || restoring_);
        if (cleanupReceipt_) {
            if (root.native() != retirement_.package || !lease_.ownsConfiguration(key_) ||
                !remainingDword(key_,L"MaintenanceVersion",1) ||
                !(remainingDword(key_,L"MaintenanceState",3) || (restoring_ && terminalPlanPresent && remainingDword(key_,L"MaintenanceState",2)))) return false;
            hadMarker_ = true; marker_ = 3;
        } else if (!maintenanceState(key_,hadMarker_,marker_) || (mode_ == DeploymentMode::Product && !hadMarker_)) return false;
        if (finalization && (!hadMarker_ || !lease_.ownsConfiguration(key_))) return false;
        ReplacementPlan pendingPlan{};
        const bool stagedBeforeIntent = mode_ == DeploymentMode::Product && updateOnly && marker_ == 0 &&
            readReplacement(key_,pendingPlan) && pendingPlan.phase == 1;
        if (mode_ == DeploymentMode::Product && updateOnly && (marker_ == 2 || stagedBeforeIntent ||
                (reinstall_ && terminalPlanPresent))) {
            if (!readReplacement(key_,replacementPlan_) || !native::fixedPath(replacementPlan_.oldRoot) ||
                !native::fixedPath(replacementPlan_.newRoot) || (root.native() != replacementPlan_.oldRoot && root.native() != replacementPlan_.newRoot) ||
                !deployment_detail::disjoint(replacementPlan_.oldRoot,replacementPlan_.newRoot)) return false;
            haveReplacement_ = true;
            active_ = replacementPlan_.phase == 3 ? replacementPlan_.newRoot : replacementPlan_.oldRoot;
            original_ = replacementPlan_.oldRoot;
        }
        package_ = std::make_shared<Deployment>(active_,mode_);
        if (!package_->verify(active_/L"GateBouncerService.exe",DeploymentRole::Service) || !package_->current()) return false;
        if (cleanupReceipt_ && !packageIdentity(*package_,retirement_.packageIdentity,retirement_.inventory,false)) return false;
        if (haveReplacement_) {
            auto other = std::make_shared<Deployment>(replacementPlan_.phase == 3 ? replacementPlan_.oldRoot : replacementPlan_.newRoot,mode_);
            if (!other->verify(other->root()/L"GateBouncerService.exe",DeploymentRole::Service)) return false;
            auto &oldPackage = replacementPlan_.phase == 3 ? *other : *package_;
            auto &newPackage = replacementPlan_.phase == 3 ? *package_ : *other;
            if (!packageIdentity(oldPackage,replacementPlan_.oldIdentity,replacementPlan_.oldInventory,false) ||
                !packageIdentity(newPackage,replacementPlan_.newIdentity,replacementPlan_.newInventory,false)) return false;
            if (reinstall_ && !packageIdentity(oldPackage,retirement_.packageIdentity,retirement_.inventory,false)) return false;
            if (replacementPlan_.phase == 3) previous_ = std::move(other); else replacement_ = std::move(other);
        }
        if (reinstall_ && finalization) {
            if (root.native() != terminalPlan.newRoot ||
                !packageIdentity(*package_,terminalPlan.newIdentity,terminalPlan.newInventory,false)) return false;
            auto original = std::make_shared<Deployment>(retirement_.package,mode_);
            if (!original->verify(original->root()/L"GateBouncerService.exe",DeploymentRole::Service) ||
                !packageIdentity(*original,retirement_.packageIdentity,retirement_.inventory,false) ||
                !packageIdentity(*original,terminalPlan.oldIdentity,terminalPlan.oldInventory,false)) return false;
            previous_ = std::move(original);
        }
        if (reinstall_) { policyRemoval_ = true; driverGone_ = true; }
        // Sólo desmontaje del tuple Product íntegro retenido antes de instalar el driver.
        pendingRemoval_ = uninstallOnly && mode_ == DeploymentMode::Product && hadMarker_ && marker_ == 1;
        DriverRetirement receipt{};
        DWORD receiptBytes = 0;
        const auto receiptQuery = RegQueryValueExW(key_,L"DriverRetirement",nullptr,nullptr,nullptr,&receiptBytes);
        resumingDriver_ = mode_ == DeploymentMode::Product && hadMarker_ &&
            ((uninstallOnly && marker_ == 3) || (updateOnly && (marker_ == 2 || restoring_))) &&
            (readRetirement(key_,receipt) || receiptQuery == ERROR_FILE_NOT_FOUND);
        if (marker_ != 0 && !pendingRemoval_ && !resumingDriver_) return false;
        std::wstring store;
        if (cleanupReceipt_) { store = retirement_.store; view_ = retirement_.view; provision_ = retirement_.provision; }
        else if (!readString(key_,L"StoreRoot",store) || !readString(key_,L"ViewSid",view_) ||
            !readDword(key_,L"ProvisionPrincipal",provision_) || provision_ > 1 ||
            (pendingRemoval_ && provision_ != 1)) return false;
        if (reinstall_ && (store != retirement_.store || view_ != retirement_.view || provision_ > retirement_.provision)) return false;
        store_ = store;
        native::ProtectedDirectory directory(store_);
        if (!deployment_detail::disjoint(root,store_) || !deployment_detail::disjoint(store_,lease_.image().parent_path()) || !directory.acquire()) return false;
        if (finalization || pendingRemoval_ || resumingDriver_ || reinstall_) {
            retainedStore_ = std::make_unique<native::ProtectedDirectory>(store_);
            if (!retainedStore_->acquire()) return false;
        }
        PSID sid = nullptr; if (!ConvertStringSidToSidW(view_.c_str(),&sid)) return false;
        const auto valid = IsValidSid(sid) && native::sidString(wire::Bytes(static_cast<BYTE *>(sid),
            static_cast<BYTE *>(sid)+GetLengthSid(sid))) == view_; LocalFree(sid); if (!valid) return false;
        manager_ = OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT | (restoring_ ? SC_MANAGER_CREATE_SERVICE : 0));
        if (!manager_) return false;
        service_ = OpenServiceW(manager_,deploymentService(mode_),SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS |
            SERVICE_CHANGE_CONFIG | READ_CONTROL | (finalization ? 0 : SERVICE_STOP | DELETE) |
            (restoring_ ? WRITE_DAC | WRITE_OWNER : 0));
        if (!service_ && cleanupReceipt_ && GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) userGone_ = true;
        if (restoring_) { closed_ = true; start_ = SERVICE_DISABLED; return tuple() && package_->current(); }
        if (pendingRemoval_ || resumingDriver_) {
            // Un tuple deshabilitado completo exige STOPPED/PID0; el intent anterior a Disable
            // sólo puede detener el mismo servicio original, nunca habilitarlo.
            closed_ = true;
            start_ = SERVICE_DISABLED;
            if (resumingDriver_ && (!haveReplacement_ || replacementPlan_.phase == 1) &&
                serviceConfigurationPhase(service_,active_/L"GateBouncerService.exe",SERVICE_AUTO_START,0,mode_)) {
                // Crash entre marker durable y Disable: sólo el mismo tuple original del intent.
                start_ = SERVICE_AUTO_START; closed_ = false;
            }
        } else if (finalization || (reinstall_ && haveReplacement_ && replacementPlan_.phase == 3 && marker_ == 0)) {
            closed_ = true;
            // Sólo esta operación explícita admite Disabled; Auto requiere el mismo readback íntegro.
            start_ = serviceConfigurationPhase(service_,active_/L"GateBouncerService.exe",SERVICE_DISABLED,0,mode_) ?
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
        // El tuple completo y el driver nuevo son el testigo después de consumir los receipts.
        // La lectura sólo acepta inventario exacto o ausencia total; no recrea filtros ni admite protección.
        const bool completedInstallation = mode_ == DeploymentMode::Product && finalizing_ && marker_ == 0 &&
            package_->driverInstalledCurrent();
        return ((policyRemoval_ && driverGone_ && (marker_ == 3 || reinstall_)) || completedInstallation ?
            policy_->prepareAfterRemoval() : policy_->prepare()) && policy_->current();
    }
    bool policyInventory() {
        return policy_ && policy_->current() && (policy_->resumeRemoval_ && policy_->removedInventory_ ?
            policy_->absent(false) : policy_->inspect(false));
    }
    bool restorationService(SC_HANDLE created = nullptr) {
        if (!restoring_ || !cleanupReceipt_ || !haveReplacement_ || replacementPlan_.phase != 1 ||
            !tuple() || !package_->current() || !replacement_ || !replacement_->current() || !service_) return false;
        DWORD needed = 0, done = 0;
        QueryServiceConfigW(service_,nullptr,0,&needed);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed < sizeof(QUERY_SERVICE_CONFIGW) || needed > 65536) return false;
        wire::Bytes bytes(needed);
        if (!QueryServiceConfigW(service_,reinterpret_cast<QUERY_SERVICE_CONFIGW *>(bytes.data()),needed,&done)) return false;
        const auto row = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(bytes.data());
        const auto text = [&](const wchar_t *value,const std::wstring &expected) {
            const auto begin = reinterpret_cast<std::uintptr_t>(bytes.data()), at = reinterpret_cast<std::uintptr_t>(value);
            if (!value || at < begin || at-begin >= bytes.size() || at % alignof(wchar_t)) return false;
            const auto cap = (bytes.size()-(at-begin))/sizeof(wchar_t);
            std::size_t length = 0; while (length < cap && value[length]) ++length;
            return length < cap && std::wstring(value,length) == expected;
        };
        SERVICE_STATUS_PROCESS state{}; SERVICE_SID_INFO sid{};
        if (row->dwServiceType != SERVICE_WIN32_OWN_PROCESS || row->dwStartType != SERVICE_DISABLED ||
            row->dwErrorControl != SERVICE_ERROR_NORMAL || !text(row->lpBinaryPathName,deploymentCommand(active_/L"GateBouncerService.exe",mode_)) ||
            !text(row->lpServiceStartName,L"LocalSystem") || !text(row->lpDependencies,L"") || !text(row->lpLoadOrderGroup,L"") ||
            !text(row->lpDisplayName,L"LGA GateBouncer") || !status(service_,state) || state.dwCurrentState != SERVICE_STOPPED || state.dwProcessId ||
            !QueryServiceConfig2W(service_,SERVICE_CONFIG_SERVICE_SID_INFO,reinterpret_cast<BYTE *>(&sid),sizeof(sid),&done) ||
            (sid.dwServiceSidType != SERVICE_SID_TYPE_NONE && sid.dwServiceSidType != SERVICE_SID_TYPE_UNRESTRICTED)) return false;
        if (created && created == service_) return tuple() && package_->current() && replacement_->current();
        needed = 0;
        QueryServiceObjectSecurity(service_,OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,nullptr,0,&needed);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !needed || needed > 65536) return false;
        bytes.resize(needed);
        if (!QueryServiceObjectSecurity(service_,OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,bytes.data(),needed,&done)) return false;
        if (serviceDescriptor(bytes.data())) return tuple() && package_->current() && replacement_->current();
        // Sólo la forma inicial documentada de CreateService, ligada al plan/receipt original.
        // No se admite aquí operación, StartService, parser ni tráfico.
        PSID owner = nullptr; PACL acl = nullptr; BOOL present = FALSE, defaulted = FALSE;
        BYTE sy[SECURITY_MAX_SID_SIZE]{}, ba[SECURITY_MAX_SID_SIZE]{}, au[SECURITY_MAX_SID_SIZE]{}, iu[SECURITY_MAX_SID_SIZE]{};
        DWORD sn = sizeof(sy), bn = sizeof(ba), an = sizeof(au), in = sizeof(iu);
        native::Handle token; HANDLE raw = nullptr; native::TokenEvidence actor;
        if (!GetSecurityDescriptorOwner(bytes.data(),&owner,&defaulted) || !owner || !IsValidSid(owner) ||
            !GetSecurityDescriptorDacl(bytes.data(),&present,&acl,&defaulted) || !present || !acl || !IsValidAcl(acl) ||
            !CreateWellKnownSid(WinLocalSystemSid,nullptr,sy,&sn) || !CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,ba,&bn) ||
            !CreateWellKnownSid(WinAuthenticatedUserSid,nullptr,au,&an) || !CreateWellKnownSid(WinInteractiveSid,nullptr,iu,&in) ||
            !OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw)) return false;
        token.reset(raw);
        if (!native::tokenEvidence(token.value,actor) || !actor.administrator || !actor.elevated ||
            (!EqualSid(owner,sy) && !EqualSid(owner,ba) && !EqualSid(owner,actor.account.data()))) return false;
        constexpr DWORD readable = READ_CONTROL | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_INTERROGATE |
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_USER_DEFINED_CONTROL;
        GENERIC_MAPPING mapping{STANDARD_RIGHTS_READ | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS,
            STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG,STANDARD_RIGHTS_EXECUTE | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_USER_DEFINED_CONTROL,SERVICE_ALL_ACCESS};
        bool administrator = false, system = false;
        for (DWORD i = 0; i < acl->AceCount; ++i) {
            void *entry = nullptr; if (!GetAce(acl,i,&entry)) return false;
            const auto header = static_cast<ACE_HEADER *>(entry);
            if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceFlags) return false;
            const auto ace = static_cast<ACCESS_ALLOWED_ACE *>(entry); DWORD mask = ace->Mask;
            if (!IsValidSid(&ace->SidStart) || (mask & MAXIMUM_ALLOWED)) return false;
            MapGenericMask(&mask,&mapping);
            if (EqualSid(&ace->SidStart,ba)) { if (mask != SERVICE_ALL_ACCESS) return false; administrator = true; }
            else if (EqualSid(&ace->SidStart,sy)) {
                if (mask != SERVICE_ALL_ACCESS && mask != (readable | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE)) return false;
                system = true;
            } else if ((EqualSid(&ace->SidStart,au) || EqualSid(&ace->SidStart,iu)) && mask == readable) {}
            else return false;
        }
        return administrator && system && tuple() && package_->current() && replacement_->current();
    }
    bool restoreTerminal(const std::filesystem::path &source,const std::filesystem::path &replacement) {
        if (!restoring_ || !cleanupReceipt_ || !closed_ || active_.native() != retirement_.package || !tuple() ||
            !packageIdentity(*package_,retirement_.packageIdentity,retirement_.inventory,false)) return false;
        bool reboot = false;
        if (!package_->retiredProductDriverCurrent(lease_,key_,reboot) || reboot) return false;
        if (!haveReplacement_) {
            // El servicio antiguo está ausente; ningún SCM por nombre se adopta sin plan previo.
            if (!userGone_ || service_ || !current() || replacement.native().size() >= MAX_PATH || active_.native().size() >= MAX_PATH ||
                !deployment_detail::stagePackage(source,replacement,replacement_,mode_) || !current()) return false;
            std::copy(active_.native().begin(),active_.native().end(),replacementPlan_.oldRoot);
            std::copy(replacement.native().begin(),replacement.native().end(),replacementPlan_.newRoot);
            if (!packageIdentity(*package_,replacementPlan_.oldIdentity,replacementPlan_.oldInventory,true) ||
                !packageIdentity(*replacement_,replacementPlan_.newIdentity,replacementPlan_.newInventory,true) ||
                !writeReplacement(key_,replacementPlan_,lease_)) return false;
            haveReplacement_ = true;
        }
        if (replacementPlan_.phase != 1 || replacement.native() != replacementPlan_.newRoot ||
            !replacement_ || !replacement_->current() || !tuple()) return false;
        SC_HANDLE created = nullptr;
        if (!service_) {
            if (!userGone_ || !current()) return false;
            const auto command = deploymentCommand(active_/L"GateBouncerService.exe",mode_);
            service_ = CreateServiceW(manager_,deploymentService(mode_),L"LGA GateBouncer",
                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | SERVICE_STOP | DELETE |
                    READ_CONTROL | WRITE_DAC | WRITE_OWNER,
                SERVICE_WIN32_OWN_PROCESS,SERVICE_DISABLED,SERVICE_ERROR_NORMAL,command.c_str(),nullptr,nullptr,nullptr,L"LocalSystem",nullptr);
            if (!service_) return false;
            created = service_; // Handle original devuelto por CreateService en esta llamada, no reapertura.
        }
        if (!restorationService(created)) return false;
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;BU)",
            SDDL_REVISION_1,&descriptor,nullptr)) return false;
        const bool secured = SetServiceObjectSecurity(service_,OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,descriptor) != FALSE;
        LocalFree(descriptor);
        SERVICE_SID_INFO sid{SERVICE_SID_TYPE_UNRESTRICTED};
        if (!secured || !restorationService() || !ChangeServiceConfig2W(service_,SERVICE_CONFIG_SERVICE_SID_INFO,&sid) ||
            !serviceConfigurationPhase(service_,active_/L"GateBouncerService.exe",SERVICE_DISABLED,0,mode_) || !tuple()) return false;
        userGone_ = false;
        if (!current() || !deployment_detail::setString(key_,L"PackageRoot",active_.native()) || !current() ||
            !deployment_detail::setString(key_,L"OrdinaryImage",(active_/L"GateBouncer.exe").native()) || !current() ||
            !deployment_detail::setString(key_,L"StoreRoot",store_.native()) || !current() ||
            !deployment_detail::setString(key_,L"ViewSid",view_) || !current() ||
            !deployment_detail::setDword(key_,L"ProvisionPrincipal",provision_) || !current() ||
            !deployment_detail::setDword(key_,L"MaintenanceVersion",1) || !current() ||
            !deployment_detail::setDword(key_,L"MaintenanceState",2) || !current() || RegFlushKey(key_) != ERROR_SUCCESS) return false;
        marker_ = 2; cleanupReceipt_ = false; restoring_ = false; resumingDriver_ = true;
        return current(); // Receipt original sigue durable durante todas las fases posteriores.
    }
    bool completeReceipts() {
        if (mode_ != DeploymentMode::Product || marker_ != 0 || !current() || !package_->driverInstalledCurrent() ||
            !policy_ || !policyInventory()) return false;
        DWORD size = 0;
        const auto retirementQuery = RegQueryValueExW(key_,L"DriverRetirement",nullptr,nullptr,nullptr,&size);
        const auto replacementQuery = RegQueryValueExW(key_,L"DriverReplacement",nullptr,nullptr,nullptr,&size);
        if ((retirementQuery != ERROR_SUCCESS && retirementQuery != ERROR_FILE_NOT_FOUND) ||
            (replacementQuery != ERROR_SUCCESS && replacementQuery != ERROR_FILE_NOT_FOUND)) return false;
        if (replacementQuery == ERROR_SUCCESS) {
            ReplacementPlan plan{};
            if (!readReplacement(key_,plan) || plan.phase != 3 || active_.native() != plan.newRoot ||
                !packageIdentity(*package_,plan.newIdentity,plan.newInventory,false)) return false;
        }
        if (retirementQuery == ERROR_SUCCESS) {
            DriverRetirement receipt{};
            if (!readRetirement(key_,receipt) || receipt.state != 3) return false;
            if (receipt.userRemoval) {
                ReplacementPlan plan{};
                if (replacementQuery != ERROR_SUCCESS || !readReplacement(key_,plan) || plan.phase != 3 ||
                    plan.oldRoot != std::wstring(receipt.package) ||
                    std::memcmp(plan.oldIdentity,receipt.packageIdentity,sizeof(plan.oldIdentity)) ||
                    plan.oldInventory != receipt.inventory) return false;
            }
            Deployment original(receipt.package,DeploymentMode::Product);
            if (!original.verify(original.root()/L"GateBouncerService.exe",DeploymentRole::Service) ||
                !packageIdentity(original,receipt.packageIdentity,receipt.inventory,false)) return false;
        }
        // Marker0 + AUTO + driver/policy originales ya confirmados: limpiar sólo los receipts propios.
        for (const auto &entry : {std::make_pair(L"DriverRetirement",retirementQuery),std::make_pair(L"DriverReplacement",replacementQuery)}) {
            if (entry.second == ERROR_FILE_NOT_FOUND) continue;
            if (!current() || !lease_.ownsConfiguration(key_) || RegDeleteValueW(key_,entry.first) != ERROR_SUCCESS ||
                RegQueryValueExW(key_,entry.first,nullptr,nullptr,nullptr,&size) != ERROR_FILE_NOT_FOUND) return false;
        }
        return RegFlushKey(key_) == ERROR_SUCCESS && current();
    }
    MaintenanceResult rebootRequired() {
        result_.phase = MaintenancePhase::Service; result_.outcome = MaintenanceOutcome::RebootRequired;
        result_.error = ERROR_SUCCESS_REBOOT_REQUIRED; result_.recoveryRecorded = true; return result_;
    }
    bool retireDriver(bool &reboot) {
        if (!closed_ || !current() || mode_ != DeploymentMode::Product || (marker_ != 2 && marker_ != 3)) return false;
        // A partir del intent durable, todos los fallos preservan marker2/3 y su tuple.
        resumingDriver_ = true;
        if (!retainedStore_) { retainedStore_ = std::make_unique<native::ProtectedDirectory>(store_); if (!retainedStore_->acquire()) return false; }
        if (!(cleanupReceipt_ ? package_->retiredProductDriverCurrent(lease_,key_,reboot) : package_->retireProductDriver(lease_,key_,reboot)) || !current()) return false;
        driverGone_ = !reboot;
        return true;
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
            DWORD size = 0;
            const bool alreadyAbsent = cleanupReceipt_ && RegQueryValueExW(key_,name,nullptr,nullptr,nullptr,&size) == ERROR_FILE_NOT_FOUND;
            if ((!exact && !alreadyAbsent) || !native::protectedRegistry(key_) || !lease_.current() || !package_->current() ||
                (mode_ == DeploymentMode::Product && !lease_.ownsConfiguration(key_)) ||
                (!alreadyAbsent && RegDeleteValueW(key_,name) != ERROR_SUCCESS)) return false;
            DWORD bytes = 0; if (RegQueryValueExW(key_,name,nullptr,nullptr,nullptr,&bytes) != ERROR_FILE_NOT_FOUND) return false;
        }
        if (RegFlushKey(key_) != ERROR_SUCCESS) return false;
        if (cleanupReceipt_) {
            // Conclusión terminal idempotente: conservar el receipt original driverGone/userRemoval.
            // Quitar el último testigo antes de cerrar/borrar el contenedor perdería la recuperación.
            bool reboot = false;
            return current() && package_->retiredProductDriverCurrent(lease_,key_,reboot) && !reboot && current();
        }
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
            if (mode_ == DeploymentMode::Product && (!package_->admitProductDriver() || !package_->driverInstalledCurrent())) {
                // Sólo el SCM/DriverStore original admitido permite finalizar el tuple usuario.
                result_.phase = MaintenancePhase::Service;
                result_.outcome = MaintenanceOutcome::Pending;
                result_.error = ERROR_NOT_SUPPORTED;
                return result_;
            }
            result_.phase = MaintenancePhase::Store;
            if (!loadPolicy()) return recovery(policy_ ? policy_->error_ : ERROR_INVALID_STATE);
            result_.phase = MaintenancePhase::Inventory;
            if (!current() || !policyInventory() || !current()) return recovery();
            result_.phase = MaintenancePhase::Service;
            if (start_ == SERVICE_DISABLED) {
                if (!ChangeServiceConfigW(service_,SERVICE_NO_CHANGE,SERVICE_AUTO_START,SERVICE_NO_CHANGE,
                    nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr)) return recovery(GetLastError());
                start_ = SERVICE_AUTO_START;
            }
            if (!current() || !policyInventory() ||
                !current() || !policy_->current()) return recovery();
            if (mode_ == DeploymentMode::Product && !completeReceipts()) return recovery();
            result_.phase = MaintenancePhase::Complete;
            result_.outcome = MaintenanceOutcome::PreparedFinalized;
            result_.error = ERROR_SUCCESS; return result_;
        } catch (...) { return recovery(); }
    }
    MaintenanceResult update(const std::filesystem::path &root,const std::filesystem::path &source,const std::filesystem::path &replacement) {
        try {
            if (!admit(root,false,false,true) || lease_.image() != source/L"GateBouncerService.exe" ||
                !deployment_detail::disjoint(root,replacement) || !deployment_detail::disjoint(store_,replacement)) return fail();
            if (mode_ == DeploymentMode::Product) {
                result_.phase = MaintenancePhase::Package;
                if (restoring_ && !restoreTerminal(source,replacement)) return fail(GetLastError());
                if (haveReplacement_) {
                    if (replacement.native() != replacementPlan_.newRoot || !deployment_detail::disjoint(store_,replacement)) return fail();
                } else {
                    DWORD bytes = 0;
                    if (replacement.native().size() >= MAX_PATH || active_.native().size() >= MAX_PATH ||
                        RegQueryValueExW(key_,L"DriverReplacement",nullptr,nullptr,nullptr,&bytes) != ERROR_FILE_NOT_FOUND ||
                        RegQueryValueExW(key_,L"DriverRetirement",nullptr,nullptr,nullptr,&bytes) != ERROR_FILE_NOT_FOUND ||
                        !deployment_detail::stagePackage(source,replacement,replacement_,mode_) || !current()) return fail();
                    std::copy(active_.native().begin(),active_.native().end(),replacementPlan_.oldRoot);
                    std::copy(replacement.native().begin(),replacement.native().end(),replacementPlan_.newRoot);
                    if (!packageIdentity(*package_,replacementPlan_.oldIdentity,replacementPlan_.oldInventory,true) ||
                        !packageIdentity(*replacement_,replacementPlan_.newIdentity,replacementPlan_.newInventory,true) ||
                        !writeReplacement(key_,replacementPlan_,lease_)) return fail();
                    haveReplacement_ = true;
                }
                if (replacementPlan_.phase < 3) {
                    result_.phase = MaintenancePhase::Marker;
                    if ((!resumingDriver_ || !closed_) && !begin(2)) return fail(GetLastError());
                    result_.phase = MaintenancePhase::Stop; if (!closed_ && !stop()) return fail(GetLastError());
                    result_.phase = MaintenancePhase::Store; if (!loadPolicy()) return fail(policy_ ? policy_->error_ : ERROR_INVALID_STATE);
                    bool reboot = false;
                    result_.phase = MaintenancePhase::Service;
                    if (!retireDriver(reboot)) return fail(GetLastError());
                    if (reboot) return rebootRequired();
                    // Journal de los outputs NT-relative propios antes de cualquier switch mutable.
                    replacementPlan_.phase = 2;
                    if (!writeReplacement(key_,replacementPlan_,lease_) || !current() || !policy_->current()) return fail();
                    result_.phase = MaintenancePhase::Switch;
                    const auto command = deploymentCommand(replacement/L"GateBouncerService.exe",mode_);
                    if (!ChangeServiceConfigW(service_,SERVICE_NO_CHANGE,SERVICE_DISABLED,SERVICE_NO_CHANGE,command.c_str(),
                        nullptr,nullptr,nullptr,nullptr,nullptr,nullptr) || !current() ||
                        !deployment_detail::setString(key_,L"PackageRoot",replacement.native()) || !current() ||
                        !deployment_detail::setString(key_,L"OrdinaryImage",(replacement/L"GateBouncer.exe").native()) || !current() ||
                        RegFlushKey(key_) != ERROR_SUCCESS) return fail(GetLastError());
                    if (!policy_->missing() && provision_ != 0) {
                        if (!deployment_detail::setDword(key_,L"ProvisionPrincipal",0)) return fail(GetLastError());
                        provision_ = 0;
                        if (RegFlushKey(key_) != ERROR_SUCCESS || !current() || !policy_->current()) return fail();
                    }
                    previous_ = std::move(package_); package_ = std::move(replacement_); active_ = replacement;
                    replacementPlan_.phase = 3; replacementPlan_.restart = 1;
                    if (!lease_.bootIdentity(replacementPlan_.installBoot) || !writeReplacement(key_,replacementPlan_,lease_) || !current()) return fail();
                } else {
                    result_.phase = MaintenancePhase::Store;
                    if (!loadPolicy()) return fail(policy_ ? policy_->error_ : ERROR_INVALID_STATE);
                }
                result_.phase = MaintenancePhase::Service;
                if (!package_->admitProductDriver()) {
                    // No se adopta ningún driver por nombre: install exige namespace ausente y el plan original.
                    if (!package_->installProductDriver(lease_,key_)) {
                        if (GetLastError() == ERROR_SUCCESS_REBOOT_REQUIRED) return rebootRequired();
                        return fail(GetLastError());
                    }
                    replacementPlan_.restart = 0;
                    if (!writeReplacement(key_,replacementPlan_,lease_)) return fail();
                } else if (replacementPlan_.restart) {
                    wire::Id boot{};
                    if (!lease_.bootIdentity(boot)) return fail();
                    if (boot == replacementPlan_.installBoot) return rebootRequired();
                    replacementPlan_.restart = 0;
                    if (!writeReplacement(key_,replacementPlan_,lease_)) return fail();
                }
                if (!package_->driverInstalledCurrent() || !current() || !policyInventory() ||
                    !deployment_detail::mark(key_,0,marker_,lease_)) return fail();
                marker_ = 0;
                if (!current() || !ChangeServiceConfigW(service_,SERVICE_NO_CHANGE,SERVICE_AUTO_START,SERVICE_NO_CHANGE,
                    nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr)) return fail(GetLastError());
                start_ = SERVICE_AUTO_START;
                if (!current() || !policy_->current() || !completeReceipts()) return fail();
                result_.phase = MaintenancePhase::Complete; result_.outcome = MaintenanceOutcome::UpdatedPrepared;
                result_.error = ERROR_SUCCESS; return result_;
            }
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
            if (!admit(root,false,true)) return fail();
            if (mode_ == DeploymentMode::Product && pendingRemoval_) {
                SC_HANDLE kernel = OpenServiceW(manager_,L"LGAGateBouncerClassifier",SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL);
                const auto error = kernel ? ERROR_SERVICE_EXISTS : GetLastError();
                const auto absent = !kernel && error == ERROR_SERVICE_DOES_NOT_EXIST;
                if (kernel) CloseServiceHandle(kernel);
                if (!absent) {
                    // Driver Windows parcial/genuino retenido: conservar su tuple, no borrar por nombre.
                    result_.phase = MaintenancePhase::Service;
                    result_.outcome = MaintenanceOutcome::Pending;
                    result_.error = error;
                    return result_;
                }
            }
            if (pendingRemoval_) {
                // Store físicamente Missing y catálogo ausente, leídos por el owner original.
                // Un marker1 con snapshot o filtros no corresponde a esta preparación pendiente.
                result_.phase = MaintenancePhase::Store;
                if (!loadPolicy() || !policy_->missing()) return fail(policy_ ? policy_->error_ : ERROR_INVALID_STATE);
            }
            result_.phase = MaintenancePhase::Marker; if ((!resumingDriver_ || !closed_) && !begin(3)) return fail(GetLastError());
            result_.phase = MaintenancePhase::Stop; if (!closed_ && !stop()) return fail(GetLastError());
            if (mode_ == DeploymentMode::Product && !pendingRemoval_) {
                bool reboot = false;
                if (!retireDriver(reboot)) return fail(GetLastError());
                if (reboot) return rebootRequired();
                // Receipt driverGone durable: después de un crash sólo PRESENT exacto
                // o catálogo completamente AUSENTE readonly, nunca inventario parcial.
                policyRemoval_ = true;
            }
            result_.phase = MaintenancePhase::Store;
            if ((!policy_ && !loadPolicy()) || !policy_ || !policy_->current())
                return fail(policy_ ? policy_->error_ : ERROR_INVALID_STATE);
            result_.phase = MaintenancePhase::Filters;
            if (!policy_->remove()) return fail(policy_->error_);
            result_.phase = MaintenancePhase::Service;
            if (!current() || !policy_->current()) return fail();
            if (driverGone_ && !cleanupReceipt_) {
                if (!readRetirement(key_,retirement_) || retirement_.state != 3) return fail();
                retirement_.userRemoval = 1;
                if (!writeRetirement(key_,retirement_,lease_)) return fail();
                cleanupReceipt_ = true;
            }
            if (!userGone_ && (!current() || !DeleteService(service_))) return fail(GetLastError());
            // Este owner nunca adquirió Deployment::Registration. Cerrar TODO SC_HANDLE propio al servicio.
            if (service_) CloseServiceHandle(service_); service_ = nullptr;
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
            userGone_ = true;
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
