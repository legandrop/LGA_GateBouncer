#include "deployment_maintenance_win.h"
#include "../common/token_ii_win.h"
#include <algorithm>
#include <set>
#include <sddl.h>
#include <cstddef>
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
struct OutputPin {
    native::Handle handle;
    BY_HANDLE_FILE_INFORMATION identity{};
    bool directory = true, ancestor = false, readable = true;
};
using OutputPins = std::map<std::filesystem::path,OutputPin>;
bool sameFile(const BY_HANDLE_FILE_INFORMATION &a,const BY_HANDLE_FILE_INFORMATION &b) {
    return a.dwVolumeSerialNumber == b.dwVolumeSerialNumber &&
        a.nFileIndexHigh == b.nFileIndexHigh && a.nFileIndexLow == b.nFileIndexLow;
}
bool inspectOutput(const std::filesystem::path &path,OutputPin &pin,bool initial) {
    BY_HANDLE_FILE_INFORMATION now{}; wchar_t final[32768]{};
    if (!pin.handle || !native::protectedObject(pin.handle.value,pin.ancestor,pin.directory,pin.readable) ||
        !GetFileInformationByHandle(pin.handle.value,&now) ||
        bool(now.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != pin.directory ||
        (now.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
    const auto count = GetFinalPathNameByHandleW(pin.handle.value,final,32768,FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    const auto expected = L"\\\\?\\"+path.native();
    if (!count || count >= 32768 || _wcsicmp(final,expected.c_str()) != 0 ||
        (!initial && (!sameFile(pin.identity,now) || (!pin.directory &&
            (pin.identity.nFileSizeHigh != now.nFileSizeHigh || pin.identity.nFileSizeLow != now.nFileSizeLow ||
             CompareFileTime(&pin.identity.ftLastWriteTime,&now.ftLastWriteTime)))))) return false;
    if (initial) pin.identity = now;
    return true;
}
bool outputsCurrent(OutputPins &pins) {
    for (auto &row : pins) if (!inspectOutput(row.first,row.second,false)) return false;
    return true;
}
bool pinOutputParents(const std::filesystem::path &path,OutputPins &pins) {
    if (!native::fixedPath(path) || path == path.root_path()) return false;
    std::vector<std::filesystem::path> paths;
    for (auto p = path.parent_path(); !p.empty(); p = p.parent_path()) {
        paths.push_back(p); if (p == p.parent_path()) break;
    }
    for (auto p = paths.rbegin(); p != paths.rend(); ++p) {
        if (pins.count(*p)) continue;
        if (pins.size() >= 128 || !outputsCurrent(pins)) return false;
        OutputPin pin; pin.ancestor = true;
        pin.handle.reset(CreateFileW(p->c_str(),READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
            FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        if (!inspectOutput(*p,pin,true)) return false;
        pins.emplace(*p,std::move(pin));
    }
    return outputsCurrent(pins);
}
struct NativeName { USHORT length, maximum; PWSTR buffer; };
struct NativeAttributes {
    ULONG length; HANDLE root; NativeName *name; ULONG attributes;
    PSECURITY_DESCRIPTOR descriptor; void *quality;
};
struct NativeStatus { union { LONG status; void *pointer; }; ULONG_PTR information; };
static_assert(sizeof(void *) == 4 || sizeof(void *) == 8,"ABI Windows requerida");
static_assert(sizeof(NativeName) == (sizeof(void *) == 8 ? 16 : 8),"ABI UNICODE_STRING");
static_assert(sizeof(NativeAttributes) == (sizeof(void *) == 8 ? 48 : 24),"ABI OBJECT_ATTRIBUTES");
static_assert(sizeof(NativeStatus) == 2*sizeof(void *),"ABI IO_STATUS_BLOCK");
static_assert(offsetof(NativeAttributes,root) == (sizeof(void *) == 8 ? 8 : 4),"ABI RootDirectory");
static_assert(offsetof(NativeStatus,information) == sizeof(void *),"ABI Information");
using CreateRelative = LONG (NTAPI *)(HANDLE *,ACCESS_MASK,NativeAttributes *,NativeStatus *,LARGE_INTEGER *,
                                     ULONG,ULONG,ULONG,ULONG,void *,ULONG);
bool createOutput(const std::filesystem::path &path,PSECURITY_DESCRIPTOR descriptor,
                  OutputPins &pins,bool directory,bool readable) {
    const auto leaf = path.filename().native();
    if (!native::fixedPath(path) || leaf.empty() || leaf.size() > 128 || leaf == L"." || leaf == L".." ||
        leaf.back() == L'.' || leaf.back() == L' ' || pins.count(path) || pins.size() >= 128) return false;
    for (auto c : leaf) if (c < 0x20 || c > 0x7e || wcschr(L"\\/:*?\"<>|",c)) return false;
    const auto parent = pins.find(path.parent_path());
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto create = module ? reinterpret_cast<CreateRelative>(GetProcAddress(module,"NtCreateFile")) : nullptr;
    if (parent == pins.end() || !parent->second.directory || !descriptor || !create || !outputsCurrent(pins)) return false;
    NativeName name{static_cast<USHORT>(leaf.size()*sizeof(wchar_t)),
        static_cast<USHORT>((leaf.size()+1)*sizeof(wchar_t)),const_cast<PWSTR>(leaf.c_str())};
    NativeAttributes attributes{sizeof(NativeAttributes),parent->second.handle.value,&name,0x1040,descriptor,nullptr};
    NativeStatus status{}; HANDLE raw = nullptr;
    // OBJ_DONT_REPARSE; FILE_CREATE; RootDirectory original y una sola hoja, sin fallback por path.
    const auto result = create(&raw,directory ? READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE :
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,&attributes,&status,nullptr,
        directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ,2,
        directory ? 0x21 : 0x200062,nullptr,0);
    OutputPin pin; pin.handle.reset(raw); pin.directory = directory; pin.readable = readable;
    if (result != 0 || status.status != 0 || status.information != 2 ||
        !inspectOutput(path,pin,true) || !outputsCurrent(pins)) return false;
    pins.emplace(path,std::move(pin));
    return outputsCurrent(pins);
}
bool createDirectory(const std::filesystem::path &path,PSECURITY_DESCRIPTOR descriptor,
                     OutputPins &held,bool readable) {
    return createOutput(path,descriptor,held,true,readable);
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
bool createFile(const std::filesystem::path &path,const wire::Bytes &bytes,
                PSECURITY_DESCRIPTOR descriptor,OutputPins &held) {
    if (bytes.size() > UINT32_MAX || !createOutput(path,descriptor,held,false,true)) return false;
    auto &pin = held.at(path); const auto created = pin.identity;
    DWORD done = 0; LARGE_INTEGER begin{};
    bool same = false;
    auto reader = [](void *p,std::uint8_t *b,std::uint32_t n,std::uint32_t &actual) {
        DWORD done = 0; const auto ok = ReadFile(static_cast<HANDLE>(p),b,n,&done,nullptr); actual = done; return ok != FALSE;
    };
    if (!outputsCurrent(held) || !WriteFile(pin.handle.value,bytes.data(),static_cast<DWORD>(bytes.size()),&done,nullptr) || done != bytes.size() ||
        !FlushFileBuffers(pin.handle.value) || !SetFilePointerEx(pin.handle.value,begin,nullptr,FILE_BEGIN) ||
        // El comparador del store tiene cota32MiB; los recursos de Qt deben caber en ella.
        !native::compareStream(bytes.data(),bytes.size(),pin.handle.value,reader,same) || !same ||
        !inspectOutput(path,pin,true) || !sameFile(created,pin.identity) || !outputsCurrent(held)) return false;
    // ReOpenFile trabaja sobre el objeto original. El puente leído conserva su FileID
    // al soltar el acceso escritor; el pin final vuelve a negar escritores y Delete.
    OutputPin bridge; bridge.directory = false;
    bridge.handle.reset(ReOpenFile(pin.handle.value,GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,FILE_FLAG_OPEN_REPARSE_POINT));
    if (!inspectOutput(path,bridge,true) || !sameFile(pin.identity,bridge.identity)) return false;
    pin.handle.reset();
    pin.handle.reset(ReOpenFile(bridge.handle.value,GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,FILE_FLAG_OPEN_REPARSE_POINT));
    // El último cierre escritor puede publicar timestamps de nuestra escritura.
    // FileID no cambia; capturar metadata final y releer los mismos bytes originales.
    if (!inspectOutput(path,pin,true) || !sameFile(created,pin.identity) ||
        !inspectOutput(path,bridge,true) || !sameFile(created,bridge.identity) ||
        !SetFilePointerEx(pin.handle.value,begin,nullptr,FILE_BEGIN) ||
        !native::compareStream(bytes.data(),bytes.size(),pin.handle.value,reader,same) || !same) return false;
    return outputsCurrent(held);
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
bool pinSource(const std::filesystem::path &source,std::vector<native::Handle> &inputs,DeploymentMode mode) {
    native::ProtectedDirectory root(source,true);
    const auto &names = deploymentFiles(DeploymentRole::Service,mode);
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
    if (mode == DeploymentMode::Product) {
        // La firma se exige antes de crear raíces administrativas o archivos de staging.
        const auto first = inputs.size()-names.size();
        const auto handle = [&](const wchar_t *name) {
            const auto row = std::find(names.begin(),names.end(),name);
            return row == names.end() ? INVALID_HANDLE_VALUE : inputs[first+std::size_t(row-names.begin())].value;
        };
        const auto cat = handle(L"driver\\GateBouncerClassifier.cat");
        LARGE_INTEGER zero{}, size{}; DWORD done = 0;
        if (cat == INVALID_HANDLE_VALUE || !SetFilePointerEx(cat,zero,nullptr,FILE_BEGIN) ||
            !GetFileSizeEx(cat,&size) || size.QuadPart <= 0 || size.QuadPart > 32*1024*1024) return false;
        wire::Bytes bytes(static_cast<std::size_t>(size.QuadPart));
        if (!ReadFile(cat,bytes.data(),DWORD(bytes.size()),&done,nullptr) || done != bytes.size() ||
            !driverPackageSignature(handle(L"driver\\GateBouncerClassifier.sys"),handle(L"driver\\GateBouncerClassifier.inf"),bytes)) return false;
    }
    return true;
}
static bool stagePackageRetained(const std::filesystem::path &source,const std::filesystem::path &package,
                  std::shared_ptr<Deployment> &owner, OutputPins &held, DeploymentMode mode) {
    if (owner || !disjoint(source,package)) return false;
    std::vector<native::Handle> inputs;
    if (!pinOutputParents(package,held) || !pinSource(source,inputs,mode)) return false;
    const auto attr = GetFileAttributesW(package.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES || GetLastError() != ERROR_FILE_NOT_FOUND) return false;
    Descriptor readable(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)");
    if (!readable.value || !createDirectory(package,readable.value,held,true)) return false;
    const auto &names = deploymentFiles(DeploymentRole::Service,mode);
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
    auto candidate = std::make_shared<Deployment>(package,mode);
    if (!outputsCurrent(held) || !candidate->verify(package/L"GateBouncerService.exe",DeploymentRole::Service) ||
        !candidate->current() || !outputsCurrent(held)) return false;
    for (const auto &row : held) if (!row.second.directory &&
        !candidate->matchesCreatedFile(row.first,row.second.handle.value)) return false;
    if (!candidate->current() || !outputsCurrent(held)) return false;
    owner = std::move(candidate); return true;
}
bool stagePackage(const std::filesystem::path &source,const std::filesystem::path &package,
                  std::shared_ptr<Deployment> &owner, DeploymentMode mode) {
    OutputPins held;
    return stagePackageRetained(source,package,owner,held,mode);
}
}
static bool prepareDeployment(DeploymentMode mode, const std::filesystem::path &source,const std::filesystem::path &package,
    const std::filesystem::path &store,const std::wstring &accountSid) {
    try {
        deployment_detail::AdministrativeLease lease(mode);
        if (!lease.acquire(mode == DeploymentMode::Product) || lease.image() != source/L"GateBouncerService.exe") return false;
        native::Handle token; HANDLE raw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw)) return false;
        token.reset(raw); native::TokenEvidence identity;
        if (!native::tokenEvidence(token.value,identity) || !identity.administrator || !identity.elevated ||
            identity.uiAccess || identity.integrity < SECURITY_MANDATORY_HIGH_RID) return false;
        const auto gate = lease.gate();
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
        OutputPins held;
        if (!sourceRoot.acquire() || !pinOutputParents(package,held) || !pinOutputParents(store,held)) return false;
        const auto absent = [](const auto &p) { const auto attr = GetFileAttributesW(p.c_str());
            return attr == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND; };
        if (!absent(package) || !absent(store)) return false;
        Key old;
        const auto oldKey = RegOpenKeyExW(gate,deploymentConfiguration(mode),0,KEY_QUERY_VALUE,&old.value);
        if (oldKey != ERROR_FILE_NOT_FOUND) return false;
        Service manager, service;
        manager.value = OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
        if (!manager.value) return false;
        service.value = OpenServiceW(manager.value,deploymentService(mode),SERVICE_QUERY_CONFIG);
        if (service.value || GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) return false;
        Descriptor readable(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)");
        Descriptor privateObject(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)");
        Descriptor registry(L"O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)");
        Descriptor scm(L"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;BU)");
        if (!readable.value || !privateObject.value || !registry.value || !scm.value) return false;
        std::shared_ptr<Deployment> packageOwner;
        if (!deployment_detail::stagePackageRetained(source,package,packageOwner,held,mode) ||
            !createDirectory(store,privateObject.value,held,false)) return false;
        const auto command = deploymentCommand(package/L"GateBouncerService.exe",mode);
        Key configuration; DWORD disposition = 0;
        SECURITY_ATTRIBUTES attributes{sizeof(attributes),registry.value,FALSE};
        if (!lease.current() || !outputsCurrent(held) || RegCreateKeyExW(gate,deploymentConfiguration(mode),0,nullptr,REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE | READ_CONTROL,&attributes,&configuration.value,&disposition) != ERROR_SUCCESS ||
            disposition != REG_CREATED_NEW_KEY || !native::protectedRegistry(configuration.value) ||
            !deployment_detail::setDword(configuration.value,L"MaintenanceVersion",1) ||
            !deployment_detail::setDword(configuration.value,L"MaintenanceState",1)) return false;
        service.value = CreateServiceW(manager.value,deploymentService(mode),mode == DeploymentMode::Product ? L"LGA GateBouncer" : L"LGA GateBouncer laboratory",
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
            SERVICE_WIN32_OWN_PROCESS,SERVICE_DISABLED,SERVICE_ERROR_NORMAL,command.c_str(),nullptr,nullptr,nullptr,L"LocalSystem",nullptr);
        SERVICE_SID_INFO sid{SERVICE_SID_TYPE_UNRESTRICTED};
        if (!service.value || !ChangeServiceConfig2W(service.value,SERVICE_CONFIG_SERVICE_SID_INFO,&sid) ||
            !SetServiceObjectSecurity(service.value,OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,scm.value) ||
            !serviceConfigurationPhase(service.value,package/L"GateBouncerService.exe",SERVICE_DISABLED,0,mode) ||
            !packageOwner->current() || !outputsCurrent(held)) return false;
        if (!native::protectedRegistry(configuration.value) ||
            !stringValue(configuration.value,L"PackageRoot",package.native()) ||
            !stringValue(configuration.value,L"OrdinaryImage",(package/L"GateBouncer.exe").native()) ||
            !stringValue(configuration.value,L"StoreRoot",store.native()) ||
            !stringValue(configuration.value,L"ViewSid",accountSid) ||
            !serviceConfigurationPhase(service.value,package/L"GateBouncerService.exe",SERVICE_DISABLED,0,mode) || !packageOwner->current() ||
            !native::protectedRegistry(gate) || !outputsCurrent(held)) return false;
        DWORD initial = 1, repeated = 0, repeatedSize = sizeof(repeated);
        const bool recorded = RegSetValueExW(configuration.value,L"ProvisionPrincipal",0,REG_DWORD,
            reinterpret_cast<const BYTE *>(&initial),sizeof(initial)) == ERROR_SUCCESS &&
            RegFlushKey(configuration.value) == ERROR_SUCCESS &&
            RegGetValueW(configuration.value,nullptr,L"ProvisionPrincipal",RRF_RT_REG_DWORD,nullptr,&repeated,&repeatedSize) == ERROR_SUCCESS &&
            repeated == 1 && repeatedSize == sizeof(repeated) && native::protectedRegistry(configuration.value) &&
            packageOwner->current() && lease.current() && outputsCurrent(held);
        DWORD marker = 1;
        if (recorded && mode == DeploymentMode::Product) {
            // Custodia de staging original hasta el último readback; fallo conserva marker1/Disabled.
            if (!outputsCurrent(held) || !serviceConfigurationPhase(service.value,package/L"GateBouncerService.exe",SERVICE_DISABLED,0,mode) ||
                !packageOwner->installProductDriver(lease,configuration.value) || !packageOwner->driverInstalledCurrent() ||
                !lease.current() || !outputsCurrent(held) ||
                !serviceConfigurationPhase(service.value,package/L"GateBouncerService.exe",SERVICE_DISABLED,0,mode)) return false;
        }
        if (recorded && deployment_detail::mark(configuration.value,0,marker,lease)) marker = 0;
        else return false; // Flush/readback incierto: no escribir otro marker ni reintentar.
        if (!outputsCurrent(held) || !ChangeServiceConfigW(service.value,SERVICE_NO_CHANGE,SERVICE_AUTO_START,SERVICE_NO_CHANGE,
                nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr) ||
            !serviceConfiguration(service.value,package/L"GateBouncerService.exe",0,mode) || !lease.current() ||
            !packageOwner->current() || !outputsCurrent(held)) {
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
bool prepareGuestDeployment(const std::filesystem::path &source,const std::filesystem::path &package,
    const std::filesystem::path &store,const std::wstring &accountSid) {
    return prepareDeployment(DeploymentMode::Laboratory,source,package,store,accountSid);
}
bool prepareProductDeployment(const std::filesystem::path &source,const std::filesystem::path &package,
    const std::filesystem::path &store,const std::wstring &accountSid) {
    return prepareDeployment(DeploymentMode::Product,source,package,store,accountSid);
}
}
