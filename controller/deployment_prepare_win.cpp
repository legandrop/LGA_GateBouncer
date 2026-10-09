#include "deployment_prepare_win.h"
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
}
bool prepareGuestDeployment(const std::filesystem::path &source,const std::filesystem::path &package,
    const std::filesystem::path &store,const std::wstring &accountSid) {
    try {
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
        // Leer/pinear todas las entradas constantes ANTES de crear un destino.
        const auto &names = deploymentFiles(DeploymentRole::Service);
        const std::set<std::wstring> expected(names.begin(),names.end());
        std::set<std::wstring> seen;
        if (!sourceClosure(source,{},expected,seen,held) || seen != expected) return false;
        std::vector<native::Handle> inputs;
        for (const auto &name : names) {
            native::Handle h; wire::Bytes bytes;
            if (!sourceFile(source/name,h,bytes)) return false;
            inputs.push_back(std::move(h));
        }
        if (!createDirectory(package,readable.value,held,true) ||
            !createDirectory(store,privateObject.value,held,false)) return false;
        std::set<std::filesystem::path> directories;
        Inventory inventory;
        for (std::size_t i = 0; i < names.size(); ++i) {
            const auto relative = std::filesystem::path(names[i]);
            std::vector<std::filesystem::path> parents;
            for (auto p = relative.parent_path(); !p.empty(); p = p.parent_path()) parents.push_back(p);
            for (auto p = parents.rbegin(); p != parents.rend(); ++p)
                if (directories.insert(*p).second && !createDirectory(package / *p,readable.value,held,true)) return false;
            LARGE_INTEGER begin{}, size{}; DWORD done = 0;
            if (!SetFilePointerEx(inputs[i].value,begin,nullptr,FILE_BEGIN) ||
                !GetFileSizeEx(inputs[i].value,&size) || size.QuadPart <= 0 || size.QuadPart > 32 * 1024 * 1024)
                return false;
            wire::Bytes bytes(static_cast<std::size_t>(size.QuadPart));
            if (!ReadFile(inputs[i].value,bytes.data(),static_cast<DWORD>(bytes.size()),&done,nullptr) || done != bytes.size() ||
                !createFile(package/relative,bytes,readable.value,held)) return false;
            inventory.emplace(names[i],native::digest(bytes));
        }
        wire::Bytes manifest;
        if (!encodeInventory(inventory,manifest) || !createFile(package/L"deployment.gbd",manifest,readable.value,held)) return false;
        auto packageOwner = std::make_shared<Deployment>(package);
        if (!packageOwner->verify(package/L"GateBouncerService.exe",DeploymentRole::Service) || !packageOwner->current()) return false;
        const auto command = L"\"" + (package/L"GateBouncerService.exe").native() + L"\" --service --guest-wfp";
        service.value = CreateServiceW(manager.value,L"LGAGateBouncerLab",L"LGA GateBouncer laboratory",
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
            SERVICE_WIN32_OWN_PROCESS,SERVICE_AUTO_START,SERVICE_ERROR_NORMAL,command.c_str(),nullptr,nullptr,nullptr,L"LocalSystem",nullptr);
        SERVICE_SID_INFO sid{SERVICE_SID_TYPE_UNRESTRICTED};
        if (!service.value || !ChangeServiceConfig2W(service.value,SERVICE_CONFIG_SERVICE_SID_INFO,&sid) ||
            !SetServiceObjectSecurity(service.value,OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,scm.value) ||
            !serviceConfiguration(service.value,package/L"GateBouncerService.exe") || !packageOwner->current()) return false;
        Key configuration; DWORD disposition = 0;
        SECURITY_ATTRIBUTES attributes{sizeof(attributes),registry.value,FALSE};
        if (RegCreateKeyExW(gate.value,L"DeploymentVIII",0,nullptr,REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE | READ_CONTROL,&attributes,&configuration.value,&disposition) != ERROR_SUCCESS ||
            disposition != REG_CREATED_NEW_KEY || !native::protectedRegistry(configuration.value) ||
            !stringValue(configuration.value,L"PackageRoot",package.native()) ||
            !stringValue(configuration.value,L"OrdinaryImage",(package/L"GateBouncer.exe").native()) ||
            !stringValue(configuration.value,L"StoreRoot",store.native()) ||
            !stringValue(configuration.value,L"ViewSid",accountSid) ||
            !serviceConfiguration(service.value,package/L"GateBouncerService.exe") || !packageOwner->current() ||
            !native::protectedRegistry(gate.value)) return false;
        DWORD initial = 1, repeated = 0, repeatedSize = sizeof(repeated);
        return RegSetValueExW(configuration.value,L"ProvisionPrincipal",0,REG_DWORD,
            reinterpret_cast<const BYTE *>(&initial),sizeof(initial)) == ERROR_SUCCESS &&
            RegFlushKey(configuration.value) == ERROR_SUCCESS &&
            RegGetValueW(configuration.value,nullptr,L"ProvisionPrincipal",RRF_RT_REG_DWORD,nullptr,&repeated,&repeatedSize) == ERROR_SUCCESS &&
            repeated == 1 && native::protectedRegistry(configuration.value) && packageOwner->current();
    } catch (...) { return false; }
}
}
