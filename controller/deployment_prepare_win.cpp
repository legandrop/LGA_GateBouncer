#include "deployment_maintenance_win.h"
#include "../common/token_ii_win.h"
#include <algorithm>
#include <set>
#include <sddl.h>
namespace gb::controller {
namespace {
struct Descriptor {
    PSECURITY_DESCRIPTOR value = nullptr;
    explicit Descriptor(const wchar_t *text) {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(text, SDDL_REVISION_1, &value, nullptr);
    }
    ~Descriptor() { if (value) LocalFree(value); }
};
struct Key { HKEY value = nullptr; ~Key() { if (value) RegCloseKey(value); } };
struct Service { SC_HANDLE value = nullptr; ~Service() { if (value) CloseServiceHandle(value); } };
bool sourceClosure(const std::filesystem::path &root,const std::filesystem::path &relative,
    const std::set<std::wstring> &expected,std::set<std::wstring> &seen,std::vector<native::Handle> &held,unsigned depth = 0) {
    if (depth > 4 || seen.size() > 64 || held.size() >= 128) return false;
    if (!relative.empty()) {
        native::Handle h(CreateFileW((root/relative).c_str(),READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        if (!h || !native::protectedObject(h.value,false,true,true)) return false;
        held.push_back(std::move(h));
    }
    WIN32_FIND_DATAW row{};
    const auto search = FindFirstFileW((root/relative/L"*").c_str(),&row);
    if (search == INVALID_HANDLE_VALUE) return false;
    bool ok = true;
    do {
        const std::wstring name = row.cFileName;
        if (name == L"." || name == L"..") continue;
        if (row.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) { ok = false; break; }
        const auto path = relative/name;
        if (row.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            const auto prefix = path.native()+L"\\";
            const auto relevant = std::any_of(expected.begin(),expected.end(),[&](const auto &s) { return s.rfind(prefix,0) == 0; });
            if (!relevant || !sourceClosure(root,path,expected,seen,held,depth+1)) { ok = false; break; }
        } else if (!expected.count(path.native()) || !seen.insert(path.native()).second) { ok = false; break; }
    } while (FindNextFileW(search,&row));
    const auto error = GetLastError(); FindClose(search);
    return ok && error == ERROR_NO_MORE_FILES;
}
bool parents(const std::filesystem::path &p, std::vector<native::Handle> &held) {
    if (!native::fixedPath(p) || p == p.root_path()) return false;
    std::vector<std::filesystem::path> paths;
    for (auto path = p.parent_path(); !path.empty(); path = path.parent_path()) {
        paths.push_back(path); if (path == path.parent_path()) break;
    }
    for (auto i = paths.rbegin(); i != paths.rend(); ++i) {
        native::Handle h(CreateFileW(i->c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!h || !native::protectedObject(h.value,true,true,true)) return false;
        held.push_back(std::move(h));
    }
    return true;
}
bool createDirectory(const std::filesystem::path &path, PSECURITY_DESCRIPTOR descriptor,
                     std::vector<native::Handle> &held, bool readable) {
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),descriptor,FALSE};
    if (!CreateDirectoryW(path.c_str(), &attributes)) return false; // Existente jamás se adopta.
    native::Handle h(CreateFileW(path.c_str(),READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    if (!h || !native::protectedObject(h.value,false,true,readable)) return false;
    held.push_back(std::move(h)); return true;
}
bool sourceFile(const std::filesystem::path &path, native::Handle &h, wire::Bytes &out) {
    h.reset(CreateFileW(path.c_str(),GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,FILE_SHARE_READ,
        nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    LARGE_INTEGER size{};
    if (!h || !native::protectedObject(h.value,false,false,true) ||
        !GetFileSizeEx(h.value,&size) || size.QuadPart <= 0 || size.QuadPart > 256 * 1024 * 1024) return false;
    out.resize(static_cast<std::size_t>(size.QuadPart)); DWORD done = 0;
    return ReadFile(h.value,out.data(),static_cast<DWORD>(out.size()),&done,nullptr) && done == out.size();
}
bool createFile(const std::filesystem::path &path, const wire::Bytes &bytes,
                PSECURITY_DESCRIPTOR descriptor, std::vector<native::Handle> &held) {
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),descriptor,FALSE};
    native::Handle h(CreateFileW(path.c_str(),GENERIC_READ | GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES,
        0,&attributes,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,nullptr));
    DWORD done = 0; LARGE_INTEGER begin{};
    bool same = false;
    auto reader = [](void *p,std::uint8_t *b,std::uint32_t n,std::uint32_t &actual) {
        DWORD done = 0; const auto ok = ReadFile(static_cast<HANDLE>(p),b,n,&done,nullptr); actual = done; return ok != FALSE;
    };
    if (!h || !native::protectedObject(h.value,false,false,true) || bytes.size() > UINT32_MAX ||
        !WriteFile(h.value,bytes.data(),static_cast<DWORD>(bytes.size()),&done,nullptr) || done != bytes.size() ||
        !FlushFileBuffers(h.value) || !SetFilePointerEx(h.value,begin,nullptr,FILE_BEGIN) ||
        // El comparador del store tiene cota32MiB; los recursos de Qt deben caber en ella.
        !native::compareStream(bytes.data(),bytes.size(),h.value,reader,same) || !same) return false;
    h.reset();
    native::Handle retained(CreateFileW(path.c_str(),GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    if (!retained || !native::protectedObject(retained.value,false,false,true)) return false;
    held.push_back(std::move(retained)); return true;
}
bool stringValue(HKEY key,const wchar_t *name,const std::wstring &value) {
    if (value.empty() || value.size() >= 32768) return false;
    if (RegSetValueExW(key,name,0,REG_SZ,reinterpret_cast<const BYTE *>(value.c_str()),
        static_cast<DWORD>((value.size()+1)*sizeof(wchar_t))) != ERROR_SUCCESS) return false;
    wchar_t actual[32768]{}; DWORD size = sizeof(actual);
    return RegGetValueW(key,nullptr,name,RRF_RT_REG_SZ,nullptr,actual,&size) == ERROR_SUCCESS &&
        size == (value.size()+1)*sizeof(wchar_t) && std::equal(value.begin(),value.end(),actual) && !actual[value.size()];
}
bool stringMatches(HKEY key,const wchar_t *name,const std::wstring &value) {
    wchar_t actual[32768]{}; DWORD size = sizeof(actual);
    return RegGetValueW(key,nullptr,name,RRF_RT_REG_SZ,nullptr,actual,&size) == ERROR_SUCCESS &&
        size == (value.size()+1)*sizeof(wchar_t) && std::equal(value.begin(),value.end(),actual) && !actual[value.size()];
}
}
namespace deployment_detail {
bool setString(HKEY key,const wchar_t *name,const std::wstring &value) { return stringValue(key,name,value); }
bool setDword(HKEY key,const wchar_t *name,DWORD value) {
    DWORD read = 0, size = sizeof(read);
    return native::protectedRegistry(key) &&
        RegSetValueExW(key,name,0,REG_DWORD,reinterpret_cast<const BYTE *>(&value),sizeof(value)) == ERROR_SUCCESS &&
        RegFlushKey(key) == ERROR_SUCCESS &&
        RegGetValueW(key,nullptr,name,RRF_RT_REG_DWORD,nullptr,&read,&size) == ERROR_SUCCESS &&
        size == sizeof(read) && read == value && native::protectedRegistry(key);
}
bool mark(HKEY key,DWORD state,DWORD expectedState,const AdministrativeLease &lease) {
    bool present = false; DWORD prior = 0;
    return state <= 4 && maintenanceState(key,present,prior) && present &&
        prior == expectedState && lease.ownsConfiguration(key) &&
        setDword(key,L"MaintenanceState",state);
}
bool disjoint(const std::filesystem::path &a,const std::filesystem::path &b) {
    if (!native::fixedPath(a) || !native::fixedPath(b) || a == a.root_path() || b == b.root_path()) return false;
    auto x = a.native(), y = b.native();
    for (auto *text : {&x,&y}) for (auto &c : *text) if (c >= L'A' && c <= L'Z') c += L'a'-L'A';
    return x != y && x.rfind(y+L"\\",0) != 0 && y.rfind(x+L"\\",0) != 0;
}
bool pinSource(const std::filesystem::path &source,std::vector<native::Handle> &inputs) {
    native::ProtectedDirectory root(source,true);
    const auto &names = deploymentFiles(DeploymentRole::Service);
    const std::set<std::wstring> expected(names.begin(),names.end());
    std::set<std::wstring> seen;
    if (!root.acquire() || !parents(source,inputs) ||
        !sourceClosure(source,{},expected,seen,inputs) || seen != expected) return false;
    native::Handle directory(CreateFileW(source.c_str(),READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    if (!directory || !native::protectedObject(directory.value,false,true,true)) return false;
    inputs.push_back(std::move(directory));
    for (const auto &name : names) {
        native::Handle h; wire::Bytes bytes;
        if (!sourceFile(source/name,h,bytes)) return false;
        inputs.push_back(std::move(h));
    }
    return true;
}
bool stagePackage(const std::filesystem::path &source,const std::filesystem::path &package,
                  std::shared_ptr<Deployment> &owner) {
    if (owner || !disjoint(source,package)) return false;
    std::vector<native::Handle> held, inputs;
    if (!parents(package,held) || !pinSource(source,inputs)) return false;
    const auto attr = GetFileAttributesW(package.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES || GetLastError() != ERROR_FILE_NOT_FOUND) return false;
    Descriptor readable(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)");
    if (!readable.value || !createDirectory(package,readable.value,held,true)) return false;
    const auto &names = deploymentFiles(DeploymentRole::Service);
    std::set<std::filesystem::path> directories; Inventory inventory;
    // pinSource conserva todos los files al final, después de los directorios.
    const auto first = inputs.size()-names.size();
    for (std::size_t i = 0; i < names.size(); ++i) {
        const auto relative = std::filesystem::path(names[i]);
        std::vector<std::filesystem::path> dirs;
        for (auto p = relative.parent_path(); !p.empty(); p = p.parent_path()) dirs.push_back(p);
        for (auto p = dirs.rbegin(); p != dirs.rend(); ++p)
            if (directories.insert(*p).second && !createDirectory(package / *p,readable.value,held,true)) return false;
        LARGE_INTEGER begin{}, size{}; DWORD done = 0;
        auto &input = inputs[first+i];
        if (!native::protectedObject(input.value,false,false,true) ||
            !SetFilePointerEx(input.value,begin,nullptr,FILE_BEGIN) ||
            !GetFileSizeEx(input.value,&size) || size.QuadPart <= 0 || size.QuadPart > 32*1024*1024) return false;
        wire::Bytes bytes(static_cast<std::size_t>(size.QuadPart));
        if (!ReadFile(input.value,bytes.data(),static_cast<DWORD>(bytes.size()),&done,nullptr) || done != bytes.size() ||
            !createFile(package/relative,bytes,readable.value,held)) return false;
        inventory.emplace(names[i],native::digest(bytes));
    }
    wire::Bytes manifest;
    if (!encodeInventory(inventory,manifest) || !createFile(package/L"deployment.gbd",manifest,readable.value,held)) return false;
    auto candidate = std::make_shared<Deployment>(package);
    if (!candidate->verify(package/L"GateBouncerService.exe",DeploymentRole::Service) || !candidate->current()) return false;
    owner = std::move(candidate); return true;
}
}
bool prepareGuestDeployment(const std::filesystem::path &source,const std::filesystem::path &package,
    const std::filesystem::path &store,const std::wstring &accountSid) {
    try {
        deployment_detail::AdministrativeLease lease;
        if (!lease.acquire() || lease.image() != source/L"GateBouncerService.exe") return false;
        native::Handle token; HANDLE raw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw)) return false;
        token.reset(raw); native::TokenEvidence identity;
        if (!native::tokenEvidence(token.value,identity) || !identity.administrator || !identity.elevated ||
            identity.uiAccess || identity.integrity < SECURITY_MANDATORY_HIGH_RID) return false;
        Key gate;
        DWORD enabled = 0, enabledSize = sizeof(enabled);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\LGA\\GateBouncerLab",0,
            KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY | READ_CONTROL,&gate.value) != ERROR_SUCCESS ||
            !native::protectedRegistry(gate.value) ||
            RegGetValueW(gate.value,nullptr,L"EnableWfp",RRF_RT_REG_DWORD,nullptr,&enabled,&enabledSize) != ERROR_SUCCESS || enabled != 1)
            return false; // El comando nunca crea su propio gate invitado.
        if (!native::fixedPath(source) || !native::fixedPath(package) || !native::fixedPath(store) ||
            source == package || source == store || package == store || source == source.root_path() ||
            package == package.root_path() || store == store.root_path()) return false;
        const auto overlaps = [](const auto &a,const auto &b) {
            auto text = b.native(); const auto prefix = a.native() + L"\\";
            return text.size() >= prefix.size() && _wcsnicmp(text.c_str(),prefix.c_str(),prefix.size()) == 0;
        };
        if (overlaps(source,package) || overlaps(package,source) || overlaps(source,store) ||
            overlaps(store,source) || overlaps(package,store) || overlaps(store,package)) return false;
        PSID account = nullptr;
        if (!ConvertStringSidToSidW(accountSid.c_str(),&account) || !IsValidSid(account)) return false;
        const auto accountText = native::sidString(wire::Bytes(static_cast<BYTE *>(account),
            static_cast<BYTE *>(account) + GetLengthSid(account))); LocalFree(account);
        if (accountText != accountSid) return false;
        native::ProtectedDirectory sourceRoot(source,true);
        std::vector<native::Handle> held;
        if (!sourceRoot.acquire() || !parents(package,held) || !parents(store,held)) return false;
        const auto absent = [](const auto &p) { const auto attr = GetFileAttributesW(p.c_str());
            return attr == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND; };
        if (!absent(package) || !absent(store)) return false;
        Key old;
        const auto oldKey = RegOpenKeyExW(gate.value,L"DeploymentVIII",0,KEY_QUERY_VALUE,&old.value);
        if (oldKey != ERROR_FILE_NOT_FOUND) return false;
        Service manager, service;
        manager.value = OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
        if (!manager.value) return false;
        service.value = OpenServiceW(manager.value,L"LGAGateBouncerLab",SERVICE_QUERY_CONFIG);
        if (service.value || GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) return false;
        Descriptor readable(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)");
        Descriptor privateObject(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)");
        Descriptor registry(L"O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)");
        Descriptor scm(L"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;BU)");
        if (!readable.value || !privateObject.value || !registry.value || !scm.value) return false;
        std::shared_ptr<Deployment> packageOwner;
        if (!deployment_detail::stagePackage(source,package,packageOwner) ||
            !createDirectory(store,privateObject.value,held,false)) return false;
        const auto command = L"\"" + (package/L"GateBouncerService.exe").native() + L"\" --service --guest-wfp";
        Key configuration; DWORD disposition = 0;
        SECURITY_ATTRIBUTES attributes{sizeof(attributes),registry.value,FALSE};
        if (!lease.current() || RegCreateKeyExW(gate.value,L"DeploymentVIII",0,nullptr,REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE | READ_CONTROL,&attributes,&configuration.value,&disposition) != ERROR_SUCCESS ||
            disposition != REG_CREATED_NEW_KEY || !native::protectedRegistry(configuration.value) ||
            !deployment_detail::setDword(configuration.value,L"MaintenanceVersion",1) ||
            !deployment_detail::setDword(configuration.value,L"MaintenanceState",1)) return false;
        service.value = CreateServiceW(manager.value,L"LGAGateBouncerLab",L"LGA GateBouncer laboratory",
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
            SERVICE_WIN32_OWN_PROCESS,SERVICE_DISABLED,SERVICE_ERROR_NORMAL,command.c_str(),nullptr,nullptr,nullptr,L"LocalSystem",nullptr);
        SERVICE_SID_INFO sid{SERVICE_SID_TYPE_UNRESTRICTED};
        if (!service.value || !ChangeServiceConfig2W(service.value,SERVICE_CONFIG_SERVICE_SID_INFO,&sid) ||
            !SetServiceObjectSecurity(service.value,OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,scm.value) ||
            !serviceConfigurationPhase(service.value,package/L"GateBouncerService.exe",SERVICE_DISABLED) || !packageOwner->current()) return false;
        if (!native::protectedRegistry(configuration.value) ||
            !stringValue(configuration.value,L"PackageRoot",package.native()) ||
            !stringValue(configuration.value,L"OrdinaryImage",(package/L"GateBouncer.exe").native()) ||
            !stringValue(configuration.value,L"StoreRoot",store.native()) ||
            !stringValue(configuration.value,L"ViewSid",accountSid) ||
            !serviceConfigurationPhase(service.value,package/L"GateBouncerService.exe",SERVICE_DISABLED) || !packageOwner->current() ||
            !native::protectedRegistry(gate.value)) return false;
        DWORD initial = 1, repeated = 0, repeatedSize = sizeof(repeated);
        const bool recorded = RegSetValueExW(configuration.value,L"ProvisionPrincipal",0,REG_DWORD,
            reinterpret_cast<const BYTE *>(&initial),sizeof(initial)) == ERROR_SUCCESS &&
            RegFlushKey(configuration.value) == ERROR_SUCCESS &&
            RegGetValueW(configuration.value,nullptr,L"ProvisionPrincipal",RRF_RT_REG_DWORD,nullptr,&repeated,&repeatedSize) == ERROR_SUCCESS &&
            repeated == 1 && repeatedSize == sizeof(repeated) && native::protectedRegistry(configuration.value) &&
            packageOwner->current() && lease.current();
        DWORD marker = 1;
        if (recorded && deployment_detail::mark(configuration.value,0,marker,lease)) marker = 0;
        else return false; // Flush/readback incierto: no escribir otro marker ni reintentar.
        if (!ChangeServiceConfigW(service.value,SERVICE_NO_CHANGE,SERVICE_AUTO_START,SERVICE_NO_CHANGE,
                nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr) ||
            !serviceConfiguration(service.value,package/L"GateBouncerService.exe") || !lease.current() || !packageOwner->current()) {
            DWORD actual = 0, size = sizeof(actual);
            if (packageOwner->current() && lease.ownsConfiguration(configuration.value) &&
                stringMatches(configuration.value,L"PackageRoot",package.native()) &&
                stringMatches(configuration.value,L"OrdinaryImage",(package/L"GateBouncer.exe").native()) &&
                stringMatches(configuration.value,L"StoreRoot",store.native()) &&
                stringMatches(configuration.value,L"ViewSid",accountSid) &&
                RegGetValueW(configuration.value,nullptr,L"ProvisionPrincipal",RRF_RT_REG_DWORD,nullptr,&actual,&size) == ERROR_SUCCESS &&
                size == sizeof(actual) && actual == 1)
                deployment_detail::mark(configuration.value,4,marker,lease);
            return false;
        }
        return true;
    } catch (...) { return false; }
}
}
