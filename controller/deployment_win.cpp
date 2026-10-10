#include "deployment_win.h"
#include "../driver/package_identity.h"
#include <algorithm>
#include <set>
#include <aclapi.h>
#include <sddl.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
// Constante del SDK, ausente en algunas versiones de los headers MinGW.
#ifndef WTD_DISABLE_MD2_MD4
#define WTD_DISABLE_MD2_MD4 0x00002000
#endif
namespace gb::controller {
namespace {
std::wstring lower(std::wstring s) {
    for (auto &c : s) {
        if (c >= L'A' && c <= L'Z')
            c += L'a' - L'A';
    }
    return s;
}
bool name(const std::wstring &s) {
    if (s.empty() || s.size() > 128 || s.front() == L'\\' || s.back() == L'\\' ||
        s.find(L"..") != std::wstring::npos || s.find(L"\\\\") != std::wstring::npos)
        return false;
    for (auto c : s)
        if (!((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') ||
              c == L'.' || c == L'_' || c == L'-' || c == L'+' || c == L'\\'))
            return false;
    return true;
}
std::uint64_t number(const wire::Bytes &b, std::size_t at, unsigned n) {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < n; ++i)
        value |= std::uint64_t(b[at + i]) << (8 * i);
    return value;
}
} // namespace
bool compareObjectHandles(HANDLE first, HANDLE second) {
    const auto module = LoadLibraryExW(L"KernelBase.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) return false;
    // El tipo conserva exactamente el ABI declarado por handleapi.h.
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4191)
#endif
    const auto compare = reinterpret_cast<decltype(&CompareObjectHandles)>(GetProcAddress(module,"CompareObjectHandles"));
#ifdef _MSC_VER
#pragma warning(pop)
#endif
    const BOOL result = compare ? compare(first,second) : FALSE;
    const auto error = GetLastError();
    if (!FreeLibrary(module)) return false;
    SetLastError(error);
    return result != FALSE;
}
const wchar_t *deploymentService(DeploymentMode mode) {
    return mode == DeploymentMode::Product ? L"LGAGateBouncer" : L"LGAGateBouncerLab";
}
const wchar_t *deploymentRegistry(DeploymentMode mode) {
    return mode == DeploymentMode::Product ? L"SOFTWARE\\LGA\\GateBouncer" : L"SOFTWARE\\LGA\\GateBouncerLab";
}
const wchar_t *deploymentConfiguration(DeploymentMode mode) {
    return mode == DeploymentMode::Product ? L"Deployment" : L"DeploymentVIII";
}
std::wstring deploymentCommand(const std::filesystem::path &image, DeploymentMode mode) {
    return L"\"" + image.native() + (mode == DeploymentMode::Product ? L"\" --service" : L"\" --service --guest-wfp");
}
const std::vector<std::wstring> &deploymentFiles(DeploymentRole role, DeploymentMode mode) {
    static const std::vector<std::wstring> decision = {
        L"GateBouncerDecisionBootstrap.exe", L"GateBouncerDecisionStage.dll", L"Qt6Core.dll",
        L"Qt6Gui.dll", L"Qt6Widgets.dll", L"libgcc_s_seh-1.dll", L"libstdc++-6.dll",
        L"libwinpthread-1.dll", L"plugins\\platforms\\qwindows.dll", L"fonts\\Inter-Regular.ttf",
        L"fonts\\Inter-Medium.ttf", L"fonts\\Inter-SemiBold.ttf", L"qt.conf"};
    static const std::vector<std::wstring> product = [] {
        auto result = decision;
        result.insert(result.end(), {L"GateBouncer.exe", L"GateBouncerGuiStage.dll",
            L"GateBouncerService.exe", L"GateBouncerAssistant.exe", L"GateBouncerSignatureHelper.exe"});
        return result;
    }();
    static const std::vector<std::wstring> withDriver = [] {
        auto result = product;
        result.insert(result.end(), {L"driver\\GateBouncerClassifier.sys",
            L"driver\\GateBouncerClassifier.inf", L"driver\\GateBouncerClassifier.cat"});
        return result;
    }();
    return role == DeploymentRole::DecisionController ? decision :
        mode == DeploymentMode::Product ? withDriver : product;
}
bool encodeInventory(const Inventory &inventory, wire::Bytes &out) {
    if (inventory.empty() || inventory.size() > 64) return false;
    wire::Bytes bytes{'G','B','D','1',1,0,0,0,0,0,0,0,
        std::uint8_t(inventory.size()),0,0,0};
    for (const auto &row : inventory) {
        if (!name(row.first)) return false;
        bytes.push_back(std::uint8_t(row.first.size())); bytes.push_back(0);
        bytes.insert(bytes.end(), row.second.begin(), row.second.end());
        for (auto c : row.first) bytes.push_back(std::uint8_t(c));
    }
    if (bytes.size() + 32 > 32768) return false;
    const auto length = bytes.size() + 32;
    for (unsigned i = 0; i < 4; ++i) bytes[8+i] = std::uint8_t(length >> (8*i));
    const auto hash = native::digest(bytes);
    bytes.insert(bytes.end(), hash.begin(), hash.end());
    Inventory checked;
    if (!parseInventory(bytes, checked) || checked != inventory) return false;
    out = std::move(bytes); return true;
}
bool serviceDescriptor(PSECURITY_DESCRIPTOR descriptor) {
    if (!descriptor || !IsValidSecurityDescriptor(descriptor)) return false;
    BYTE sy[SECURITY_MAX_SID_SIZE]{}, ba[SECURITY_MAX_SID_SIZE]{};
    DWORD sn = sizeof(sy), bn = sizeof(ba), revision = 0;
    PSID owner = nullptr; PACL acl = nullptr; BOOL present = FALSE, def = FALSE;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, sy, &sn) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, ba, &bn)) return false;
    const auto trusted = [&](PSID sid) { return sid && IsValidSid(sid) &&
        (EqualSid(sid, sy) || EqualSid(sid, ba)); };
    if (!GetSecurityDescriptorOwner(descriptor, &owner, &def) || !trusted(owner) ||
        !GetSecurityDescriptorDacl(descriptor, &present, &acl, &def) || !present || !acl || !IsValidAcl(acl) ||
        !GetSecurityDescriptorControl(descriptor, &control, &revision) || !(control & SE_DACL_PROTECTED)) return false;
    GENERIC_MAPPING mapping{STANDARD_RIGHTS_READ | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS |
        SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS, STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG,
        STANDARD_RIGHTS_EXECUTE | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE |
        SERVICE_USER_DEFINED_CONTROL, SERVICE_ALL_ACCESS};
    constexpr DWORD unsafe = SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE |
        SERVICE_USER_DEFINED_CONTROL | DELETE | WRITE_DAC | WRITE_OWNER;
    bool fullSy = false, fullBa = false;
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        void *raw = nullptr; if (!GetAce(acl, i, &raw)) return false;
        auto header = static_cast<ACE_HEADER *>(raw);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceFlags) return false;
        auto ace = static_cast<ACCESS_ALLOWED_ACE *>(raw); auto mask = ace->Mask;
        if (!IsValidSid(&ace->SidStart) || (mask & MAXIMUM_ALLOWED)) return false;
        MapGenericMask(&mask, &mapping);
        if (!trusted(&ace->SidStart) && (mask & unsafe)) return false;
        if ((mask & SERVICE_ALL_ACCESS) == SERVICE_ALL_ACCESS) {
            fullSy |= EqualSid(&ace->SidStart, sy) != FALSE;
            fullBa |= EqualSid(&ace->SidStart, ba) != FALSE;
        }
    }
    return fullSy && fullBa;
}
bool serviceConfiguration(SC_HANDLE service, const std::filesystem::path &image, DWORD pid, DeploymentMode mode) {
    return serviceConfigurationPhase(service,image,SERVICE_AUTO_START,pid,mode);
}
bool serviceConfigurationPhase(SC_HANDLE service, const std::filesystem::path &image, DWORD startType, DWORD pid, DeploymentMode mode) {
    if (!service || !native::fixedPath(image)) return false;
    DWORD needed = 0;
    QueryServiceConfigW(service, nullptr, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed < sizeof(QUERY_SERVICE_CONFIGW) || needed > 65536)
        return false;
    wire::Bytes bytes(needed);
    if (!QueryServiceConfigW(service, reinterpret_cast<QUERY_SERVICE_CONFIGW *>(bytes.data()), needed, &needed))
        return false;
    auto config = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(bytes.data());
    const auto text = [&](const wchar_t *p, const std::wstring &expected) {
        const auto first = reinterpret_cast<std::uintptr_t>(bytes.data()), at = reinterpret_cast<std::uintptr_t>(p);
        if (!p || at < first || at - first >= bytes.size() || at % alignof(wchar_t)) return false;
        const auto count = (bytes.size() - (at - first)) / sizeof(wchar_t);
        std::size_t n = 0; while (n < count && p[n]) ++n;
        return n < count && std::wstring(p, n) == expected;
    };
    SERVICE_SID_INFO sid{}; SERVICE_STATUS_PROCESS status{}; DWORD done = 0;
    if ((startType != SERVICE_AUTO_START && startType != SERVICE_DISABLED) ||
        config->dwServiceType != SERVICE_WIN32_OWN_PROCESS || config->dwStartType != startType ||
        !text(config->lpBinaryPathName, deploymentCommand(image,mode)) ||
        !text(config->lpServiceStartName, L"LocalSystem") ||
        !QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, reinterpret_cast<BYTE *>(&sid), sizeof(sid), &done) ||
        sid.dwServiceSidType != SERVICE_SID_TYPE_UNRESTRICTED ||
        !QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE *>(&status), sizeof(status), &done) ||
        status.dwServiceType != SERVICE_WIN32_OWN_PROCESS ||
        (pid && (status.dwProcessId != pid ||
         (status.dwCurrentState != SERVICE_RUNNING && status.dwCurrentState != SERVICE_START_PENDING)))) return false;
    constexpr DWORD information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    needed = 0; QueryServiceObjectSecurity(service, information, nullptr, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !needed || needed > 65536) return false;
    bytes.resize(needed);
    return QueryServiceObjectSecurity(service, information, bytes.data(), needed, &done) && serviceDescriptor(bytes.data());
}
bool maintenanceState(HKEY key, bool &present, DWORD &state) {
    DWORD version = 0, vSize = sizeof(version), sSize = sizeof(state);
    state = 0; present = false;
    const auto v = RegGetValueW(key,nullptr,L"MaintenanceVersion",RRF_RT_REG_DWORD,nullptr,&version,&vSize);
    const auto s = RegGetValueW(key,nullptr,L"MaintenanceState",RRF_RT_REG_DWORD,nullptr,&state,&sSize);
    if (v == ERROR_FILE_NOT_FOUND && s == ERROR_FILE_NOT_FOUND) { state = 0; return true; }
    if (v != ERROR_SUCCESS || s != ERROR_SUCCESS || vSize != sizeof(version) ||
        sSize != sizeof(state) || version != 1 || state > 4) return false;
    present = true; return true;
}
bool driverPackageSignature(HANDLE sys, HANDLE inf, const wire::Bytes &catalog) {
    if (catalog.empty() || catalog.size() > 32*1024*1024 ||
        !native::protectedObject(sys,false,false,true) || !native::protectedObject(inf,false,false,true)) return false;
    // La confianza del CAT no autoriza instrucciones de otro INF, aunque esté firmado.
    LARGE_INTEGER infBegin{}, infSize{}; DWORD read = 0;
    if (!GetFileSizeEx(inf,&infSize) || infSize.QuadPart != static_cast<LONGLONG>(driver_package::infSize) ||
        !SetFilePointerEx(inf,infBegin,nullptr,FILE_BEGIN)) return false;
    wire::Bytes infBytes(driver_package::infSize);
    if (!ReadFile(inf,infBytes.data(),DWORD(infBytes.size()),&read,nullptr) || read != infBytes.size()) return false;
    const auto infHash = native::digest(infBytes); constexpr char infHex[] = "0123456789ABCDEF";
    for (std::size_t i = 0; i < infHash.size(); ++i)
        if (driver_package::infSha256[2*i] != infHex[infHash[i] >> 4] ||
            driver_package::infSha256[2*i+1] != infHex[infHash[i] & 15]) return false;
    struct Libraries {
        HMODULE trust = LoadLibraryExW(L"wintrust.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
        HMODULE crypto = LoadLibraryExW(L"crypt32.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
        ~Libraries() { if (crypto) FreeLibrary(crypto); if (trust) FreeLibrary(trust); }
    } libraries;
    if (!libraries.trust || !libraries.crypto) return false;
    const auto verify = reinterpret_cast<decltype(&WinVerifyTrust)>(GetProcAddress(libraries.trust,"WinVerifyTrust"));
    const auto acquire = reinterpret_cast<decltype(&CryptCATAdminAcquireContext2)>(GetProcAddress(libraries.trust,"CryptCATAdminAcquireContext2"));
    const auto release = reinterpret_cast<decltype(&CryptCATAdminReleaseContext)>(GetProcAddress(libraries.trust,"CryptCATAdminReleaseContext"));
    const auto hash = reinterpret_cast<decltype(&CryptCATAdminCalcHashFromFileHandle2)>(GetProcAddress(libraries.trust,"CryptCATAdminCalcHashFromFileHandle2"));
    const auto context = reinterpret_cast<decltype(&CertCreateCTLContext)>(GetProcAddress(libraries.crypto,"CertCreateCTLContext"));
    const auto freeContext = reinterpret_cast<decltype(&CertFreeCTLContext)>(GetProcAddress(libraries.crypto,"CertFreeCTLContext"));
    if (!verify || !acquire || !release || !hash || !context || !freeContext) return false;
    // El CTL firmado se decodifica desde bytes originales: ningún CAT se reabre por path.
    const auto ctl = context(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,catalog.data(),DWORD(catalog.size()));
    if (!ctl) return false;
    HCATADMIN admin = nullptr; GUID action = DRIVER_ACTION_VERIFY;
    bool ok = acquire(&admin,&action,L"SHA256",nullptr,0) != FALSE;
    for (const auto member : {sys,inf}) {
        if (!ok) break;
        LARGE_INTEGER zero{}; DWORD size = 32; BYTE digest[32]{};
        if (!SetFilePointerEx(member,zero,nullptr,FILE_BEGIN) ||
            !hash(admin,member,&size,digest,0) || size != sizeof(digest)) { ok = false; break; }
        wchar_t tag[65]{}; constexpr wchar_t hex[] = L"0123456789ABCDEF";
        for (unsigned i = 0; i < 32; ++i) { tag[2*i] = hex[digest[i] >> 4]; tag[2*i+1] = hex[digest[i] & 15]; }
        WINTRUST_CATALOG_INFO info{}; info.cbStruct = sizeof(info); info.pcwszMemberTag = tag;
        info.hMemberFile = member; info.pbCalculatedFileHash = digest; info.cbCalculatedFileHash = size;
        info.pcCatalogContext = ctl; info.hCatAdmin = admin;
        WINTRUST_DATA data{}; data.cbStruct = sizeof(data); data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN; data.dwUnionChoice = WTD_CHOICE_CATALOG;
        data.pCatalog = &info; data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
            WTD_USE_DEFAULT_OSVER_CHECK | WTD_DISABLE_MD2_MD4;
        ok = verify(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE),&action,&data) == ERROR_SUCCESS;
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        if (verify(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE),&action,&data) != ERROR_SUCCESS) ok = false;
    }
    if (admin && !release(admin,0)) ok = false;
    if (!freeContext(ctl)) ok = false;
    // Sólo confianza offline de miembros bajo política driver, nunca imagen cargada/CI/protección.
    return ok;
}
struct Deployment::Registration {
    HKEY key = nullptr, gate = nullptr, parent = nullptr;
    SC_HANDLE service = nullptr;
    std::filesystem::path root, store, ordinary;
    wire::Bytes account;
    std::wstring sid;
    bool provision = false;
    bool marker = false;
    DeploymentMode mode = DeploymentMode::Laboratory;
    ~Registration() { if (key) RegCloseKey(key); if (gate) RegCloseKey(gate); if (parent) RegCloseKey(parent); if (service) CloseServiceHandle(service); }
    bool read(const wchar_t *name, std::wstring &out) const {
        wchar_t text[32768]{}; DWORD size = sizeof(text);
        if (RegGetValueW(key, nullptr, name, RRF_RT_REG_SZ, nullptr, text, &size) != ERROR_SUCCESS ||
            size < 2 || size > sizeof(text) || size % sizeof(wchar_t) ||
            text[size/sizeof(wchar_t)-1] || wcslen(text)+1 != size/sizeof(wchar_t)) return false;
        out = text; return true;
    }
    bool current() const {
        if (mode == DeploymentMode::Product) {
            HKEY repeated = nullptr; DWORD bytes = 0;
            const bool originalParent = parent && native::protectedRegistry(parent) &&
                RegQueryValueExW(parent,L"SymbolicLinkValue",nullptr,nullptr,nullptr,&bytes) == ERROR_FILE_NOT_FOUND &&
                RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\LGA",REG_OPTION_OPEN_LINK,
                    KEY_QUERY_VALUE | READ_CONTROL,&repeated) == ERROR_SUCCESS && compareObjectHandles(parent,repeated);
            if (repeated) RegCloseKey(repeated);
            if (!originalParent) return false;
        }
        HKEY reopenedGate = nullptr, reopenedKey = nullptr;
        const bool original = RegOpenKeyExW(HKEY_LOCAL_MACHINE,deploymentRegistry(mode),0,
            KEY_QUERY_VALUE | READ_CONTROL,&reopenedGate) == ERROR_SUCCESS &&
            compareObjectHandles(gate,reopenedGate) &&
            RegOpenKeyExW(reopenedGate,deploymentConfiguration(mode),0,
                KEY_QUERY_VALUE | READ_CONTROL,&reopenedKey) == ERROR_SUCCESS && compareObjectHandles(key,reopenedKey);
        if (reopenedKey) RegCloseKey(reopenedKey);
        if (reopenedGate) RegCloseKey(reopenedGate);
        if (!original) return false;
        DWORD enabled = 0, size = sizeof(enabled), initial = 0, initialSize = sizeof(initial);
        bool present = false; DWORD state = 0;
        std::wstring packageText, storeText, ordinaryText, sidText;
        return native::protectedRegistry(key) && native::protectedRegistry(gate) &&
            maintenanceState(key,present,state) && present == marker && !state &&
            (mode != DeploymentMode::Product || present) &&
            (mode == DeploymentMode::Product || (RegGetValueW(gate,nullptr,L"EnableWfp",RRF_RT_REG_DWORD,nullptr,&enabled,&size) == ERROR_SUCCESS && enabled == 1)) &&
            RegGetValueW(key,nullptr,L"ProvisionPrincipal",RRF_RT_REG_DWORD,nullptr,&initial,&initialSize) == ERROR_SUCCESS &&
            initial == (provision ? 1u : 0u) && read(L"PackageRoot", packageText) && packageText == root.native() &&
            read(L"StoreRoot", storeText) && storeText == store.native() &&
            read(L"OrdinaryImage", ordinaryText) && ordinaryText == ordinary.native() &&
            read(L"ViewSid", sidText) && sidText == sid &&
            serviceConfiguration(service, root / L"GateBouncerService.exe", GetCurrentProcessId(),mode);
    }
};
Deployment::Deployment(std::filesystem::path root, DeploymentMode mode) : root_(std::move(root)), mode_(mode), directory_(root_, true) {}
Deployment::~Deployment() = default;
bool parseInventory(const wire::Bytes &b, Inventory &out) {
    if (b.size() < 48 || b.size() > 32768 || !std::equal(b.begin(), b.begin() + 4, "GBD1") ||
        number(b, 4, 2) != 1 || number(b, 6, 2) != 0 || number(b, 8, 4) != b.size())
        return false;
    auto count = number(b, 12, 2);
    if (!count || count > 64 || number(b, 14, 2))
        return false;
    wire::Bytes hashed(b.begin(), b.end() - 32);
    auto hash = native::digest(hashed);
    if (!std::equal(hash.begin(), hash.end(), b.end() - 32))
        return false;
    Inventory records;
    std::set<std::wstring> folded;
    std::size_t at = 16;
    for (std::uint64_t i = 0; i < count; ++i) {
        if (at > hashed.size() || hashed.size() - at < 34)
            return false;
        auto size = number(b, at, 2);
        at += 2;
        wire::Digest digest{};
        std::copy_n(b.begin() + at, 32, digest.begin());
        at += 32;
        if (size > 128 || size > hashed.size() - at)
            return false;
        std::wstring file;
        for (std::size_t n = 0; n < size; ++n)
            file += wchar_t(b[at + n]);
        at += std::size_t(size);
        if (!name(file) || !folded.insert(lower(file)).second ||
            !records.emplace(file, digest).second)
            return false;
    }
    if (at != hashed.size())
        return false;
    out = std::move(records);
    return true;
}
bool Deployment::readFile(const std::filesystem::path &relative, wire::Bytes &out,
                          std::size_t cap) {
    auto path = root_ / relative;
    if (!name(relative.native()) || !native::fixedPath(path) || held_.size() >= 128)
        return false;
    native::Handle h(CreateFileW(path.c_str(), GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,
                                 FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    LARGE_INTEGER size{};
    if (!h || !native::protectedObject(h.value, false, false, true) ||
        !GetFileSizeEx(h.value, &size) || size.QuadPart < 0 || std::uint64_t(size.QuadPart) > cap)
        return false;
    wire::Bytes bytes(std::size_t(size.QuadPart));
    BY_HANDLE_FILE_INFORMATION identity{};
    if (!GetFileInformationByHandle(h.value, &identity)) return false;
    DWORD done = 0;
    if (!ReadFile(h.value, bytes.data(), DWORD(bytes.size()), &done, nullptr) ||
        done != bytes.size())
        return false;
    files_.push_back({relative, identity, held_.size()});
    held_.push_back(std::move(h));
    out = std::move(bytes);
    return true;
}
bool Deployment::enumerate(const std::filesystem::path &relative, unsigned depth,
                           std::vector<std::wstring> &files, bool retain) {
    if (depth > 4 || files.size() > 64 || (retain && held_.size() >= 128))
        return false;
    if (!relative.empty()) {
        native::Handle h(
            CreateFileW((root_ / relative).c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!h || !native::protectedObject(h.value, false, true, true))
            return false;
        if (retain) held_.push_back(std::move(h));
    }
    WIN32_FIND_DATAW data{};
    auto found = FindFirstFileW((root_ / relative / L"*").c_str(), &data);
    if (found == INVALID_HANDLE_VALUE)
        return false;
    bool ok = true;
    do {
        std::wstring file = data.cFileName;
        if (file == L"." || file == L"..")
            continue;
        if (!name(file) || (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            ok = false;
            break;
        }
        auto next = relative / file;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!enumerate(next, depth + 1, files, retain)) {
                ok = false;
                break;
            }
        } else {
            if (next.native() != L"deployment.gbd")
                files.push_back(next.native());
            if (files.size() > 64) {
                ok = false;
                break;
            }
        }
    } while (FindNextFileW(found, &data));
    auto error = GetLastError();
    FindClose(found);
    return ok && error == ERROR_NO_MORE_FILES;
}
bool Deployment::verify(const std::filesystem::path &own, DeploymentRole role) {
    const auto expected = role == DeploymentRole::DecisionController ? L"GateBouncerDecisionBootstrap.exe" :
        role == DeploymentRole::OrdinaryGui ? L"GateBouncer.exe" :
        role == DeploymentRole::AssistantBroker ? L"GateBouncerAssistant.exe" : L"GateBouncerService.exe";
    if (verified_ || revoked_ || !held_.empty() || own != root_ / expected || !directory_.acquire())
        return false;
    wire::Bytes manifest;
    if (!readFile(L"deployment.gbd", manifest, 32768) || !parseInventory(manifest, inventory_))
        return false;
    // Los lectores ordinarios admiten los conjuntos cerrados; el servicio Product exige driver.
    const auto &expectedFiles = role == DeploymentRole::DecisionController &&
        inventory_.size() == deploymentFiles(role).size() ? deploymentFiles(role) :
        deploymentFiles(DeploymentRole::Service, mode_ == DeploymentMode::Product ||
            (role != DeploymentRole::Service && inventory_.size() == deploymentFiles(DeploymentRole::Service,DeploymentMode::Product).size()) ?
            DeploymentMode::Product : DeploymentMode::Laboratory);
    if (inventory_.size() != expectedFiles.size()) return false;
    for (const auto &file : expectedFiles) if (!inventory_.count(file)) return false;
    for (const auto &file : deploymentFiles(role,mode_))
        if (!inventory_.count(file))
            return false;
    std::vector<std::wstring> files;
    if (!enumerate({}, 0, files) || files.size() != inventory_.size())
        return false;
    for (auto &file : files) {
        auto row = inventory_.find(file);
        wire::Bytes bytes;
        if (row == inventory_.end() || !readFile(file, bytes, 256 * 1024 * 1024) ||
            native::digest(bytes) != row->second)
            return false;
        if (file == L"qt.conf" &&
            bytes != wire::Bytes{'[', 'P', 'a', 't', 'h', 's',  ']', '\n', 'P', 'r', 'e',
                                 'f', 'i', 'x', '=', '.', '\n', 'P', 'l',  'u', 'g', 'i',
                                 'n', 's', '=', 'p', 'l', 'u',  'g', 'i',  'n', 's', '\n'})
            return false;
    }
    verified_ = true;
    role_ = role;
    if (mode_ == DeploymentMode::Product && role == DeploymentRole::Service && !driverPackageSigned()) {
        revoked_ = true; verified_ = false; return false;
    }
    return true;
}
bool Deployment::matchesImage(const std::filesystem::path &path, const BY_HANDLE_FILE_INFORMATION &identity) const {
    const std::lock_guard<std::recursive_mutex> lock(currentMutex_);
    if (!verified_ || revoked_ || path.parent_path() != root_) return false;
    const auto row = std::find_if(files_.begin(), files_.end(), [&](const auto &p) { return root_ / p.path == path; });
    return row != files_.end() && row->identity.dwVolumeSerialNumber == identity.dwVolumeSerialNumber &&
        row->identity.nFileIndexHigh == identity.nFileIndexHigh && row->identity.nFileIndexLow == identity.nFileIndexLow &&
        row->identity.nFileSizeHigh == identity.nFileSizeHigh && row->identity.nFileSizeLow == identity.nFileSizeLow &&
        CompareFileTime(&row->identity.ftLastWriteTime, &identity.ftLastWriteTime) == 0;
}
bool Deployment::matchesCreatedFile(const std::filesystem::path &path, HANDLE original) const {
    const std::lock_guard<std::recursive_mutex> lock(currentMutex_);
    if (!verified_ || revoked_ || !native::protectedObject(original,false,false,true)) return false;
    const auto row = std::find_if(files_.begin(),files_.end(),[&](const auto &p) { return root_/p.path == path; });
    BY_HANDLE_FILE_INFORMATION identity{};
    return row != files_.end() && GetFileInformationByHandle(original,&identity) &&
        row->identity.dwVolumeSerialNumber == identity.dwVolumeSerialNumber &&
        row->identity.nFileIndexHigh == identity.nFileIndexHigh && row->identity.nFileIndexLow == identity.nFileIndexLow &&
        row->identity.nFileSizeHigh == identity.nFileSizeHigh && row->identity.nFileSizeLow == identity.nFileSizeLow &&
        CompareFileTime(&row->identity.ftLastWriteTime,&identity.ftLastWriteTime) == 0;
}
bool Deployment::current() noexcept {
    std::unique_lock<std::recursive_mutex> lock(currentMutex_, std::defer_lock);
    try { lock.lock(); } catch (...) { return false; }
    if (!verified_ || revoked_) return false;
    try {
        bool ok = directory_.acquire();
        for (const auto &h : held_) {
            FILE_ATTRIBUTE_TAG_INFO shape{};
            if (!GetFileInformationByHandleEx(h.value, FileAttributeTagInfo, &shape, sizeof(shape)) ||
                !native::protectedObject(h.value, false, bool(shape.FileAttributes & FILE_ATTRIBUTE_DIRECTORY), true)) {
                ok = false; break;
            }
        }
        for (const auto &file : files_) {
            BY_HANDLE_FILE_INFORMATION now{};
            const auto &was = file.identity;
            if (!GetFileInformationByHandle(held_[file.handle].value, &now) ||
                now.dwVolumeSerialNumber != was.dwVolumeSerialNumber || now.nFileIndexHigh != was.nFileIndexHigh ||
                now.nFileIndexLow != was.nFileIndexLow || now.nFileSizeHigh != was.nFileSizeHigh ||
                now.nFileSizeLow != was.nFileSizeLow || CompareFileTime(&now.ftLastWriteTime, &was.ftLastWriteTime)) {
                ok = false; break;
            }
        }
        std::vector<std::wstring> names;
        if (!enumerate({},0,names,false) || names.size() != inventory_.size()) ok = false;
        for (const auto &n : names) if (!inventory_.count(n)) ok = false;
        if (registration_ && !registration_->current()) ok = false;
        if (!ok) revoked_ = true;
        return ok;
    } catch (...) { revoked_ = true; return false; }
}
bool Deployment::signatureHelperInventory(std::filesystem::path &path, wire::Digest &hash) {
    const std::lock_guard<std::recursive_mutex> lock(currentMutex_);
    if (role_ != DeploymentRole::AssistantBroker || !current()) return false;
    const auto row = inventory_.find(L"GateBouncerSignatureHelper.exe");
    if (row == inventory_.end()) return false;
    path = root_ / row->first;
    hash = row->second;
    return true;
}
bool Deployment::admitServiceConfiguration(wire::Bytes &account, std::filesystem::path &store, bool &provision) {
    if (role_ != DeploymentRole::Service || registration_ || !current()) return false;
    auto candidate = std::make_unique<Registration>();
    candidate->mode = mode_;
    if (mode_ == DeploymentMode::Product && RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\LGA",
        REG_OPTION_OPEN_LINK,KEY_QUERY_VALUE | READ_CONTROL,&candidate->parent) != ERROR_SUCCESS) return false;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,deploymentRegistry(mode_),0,KEY_QUERY_VALUE | READ_CONTROL,&candidate->gate) != ERROR_SUCCESS ||
        RegOpenKeyExW(candidate->gate,deploymentConfiguration(mode_),0,KEY_QUERY_VALUE | READ_CONTROL,&candidate->key) != ERROR_SUCCESS ||
        !native::protectedRegistry(candidate->gate) || !native::protectedRegistry(candidate->key)) return false;
    std::wstring root, ordinary, storeText;
    DWORD initial = 0, size = sizeof(initial);
    DWORD state = 0;
    if (!maintenanceState(candidate->key,candidate->marker,state) || state ||
        (mode_ == DeploymentMode::Product && !candidate->marker)) return false;
    if (!candidate->read(L"PackageRoot",root) || root != root_.native() ||
        !candidate->read(L"OrdinaryImage",ordinary) || ordinary != (root_ / L"GateBouncer.exe").native() ||
        !candidate->read(L"StoreRoot",storeText) || !candidate->read(L"ViewSid",candidate->sid) ||
        RegGetValueW(candidate->key,nullptr,L"ProvisionPrincipal",RRF_RT_REG_DWORD,nullptr,&initial,&size) != ERROR_SUCCESS || initial > 1)
        return false;
    candidate->root = root_; candidate->ordinary = ordinary; candidate->store = storeText; candidate->provision = initial == 1;
    native::ProtectedDirectory protectedStore(candidate->store);
    if (!native::fixedPath(candidate->store) || candidate->store == root_ || !protectedStore.acquire()) return false;
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(candidate->sid.c_str(), &sid) || !IsValidSid(sid)) return false;
    candidate->account.assign(static_cast<BYTE *>(sid),static_cast<BYTE *>(sid) + GetLengthSid(sid)); LocalFree(sid);
    SC_HANDLE manager = OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
    if (!manager) return false;
    candidate->service = OpenServiceW(manager,deploymentService(mode_),SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL);
    CloseServiceHandle(manager);
    if (!candidate->current()) return false;
    account = candidate->account; store = candidate->store; provision = candidate->provision;
    registration_ = std::move(candidate); return true;
}
bool Deployment::serviceAdmittedCurrent() noexcept {
    try {
        const std::lock_guard<std::recursive_mutex> lock(currentMutex_);
        return role_ == DeploymentRole::Service && registration_ && current();
    } catch (...) { return false; }
}
bool Deployment::driverPackageSigned() {
    const std::lock_guard<std::recursive_mutex> lock(currentMutex_);
    if (mode_ != DeploymentMode::Product || !current()) return false;
    const auto handle = [&](const wchar_t *name) {
        const auto row = std::find_if(files_.begin(),files_.end(),[&](const auto &p) { return p.path == name; });
        return row == files_.end() ? INVALID_HANDLE_VALUE : held_[row->handle].value;
    };
    const auto cat = handle(L"driver\\GateBouncerClassifier.cat");
    LARGE_INTEGER zero{}, size{}; DWORD done = 0;
    if (cat == INVALID_HANDLE_VALUE || !SetFilePointerEx(cat,zero,nullptr,FILE_BEGIN) ||
        !GetFileSizeEx(cat,&size) || size.QuadPart <= 0 || size.QuadPart > 32*1024*1024) return false;
    wire::Bytes bytes(static_cast<std::size_t>(size.QuadPart));
    return ReadFile(cat,bytes.data(),DWORD(bytes.size()),&done,nullptr) && done == bytes.size() &&
        driverPackageSignature(handle(L"driver\\GateBouncerClassifier.sys"),handle(L"driver\\GateBouncerClassifier.inf"),bytes) && current();
}
bool Deployment::prepareEnvironment() {
    if (!current())
        return false;
    auto block = GetEnvironmentStringsW();
    if (!block)
        return false;
    std::vector<std::wstring> remove;
    for (auto line = block; *line; line += wcslen(line) + 1) {
        std::wstring s(line);
        auto equal = s.find(L'=');
        if (equal == std::wstring::npos || equal == 0)
            continue;
        auto key = s.substr(0, equal);
        auto folded = lower(key);
        if (folded.rfind(L"qt_", 0) == 0 || folded.rfind(L"qml", 0) == 0 ||
            folded.rfind(L"qtwebengine", 0) == 0)
            remove.push_back(key);
    }
    FreeEnvironmentStringsW(block);
    for (auto &key : remove)
        if (!SetEnvironmentVariableW(key.c_str(), nullptr))
            return false;
    wchar_t system[32768]{};
    auto size = GetSystemDirectoryW(system, 32768);
    if (!size || size >= 32768 || !SetEnvironmentVariableW(L"PATH", system) ||
        !SetCurrentDirectoryW(root_.c_str()) ||
        !SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS) ||
        !AddDllDirectory(root_.c_str()))
        return false;
    return SetEnvironmentVariableW(L"QT_PLUGIN_PATH", (root_ / L"plugins").c_str()) &&
           SetEnvironmentVariableW(L"QT_QPA_PLATFORM_PLUGIN_PATH",
                                   (root_ / L"plugins/platforms").c_str()) &&
           SetEnvironmentVariableW(L"QT_QPA_PLATFORM", L"windows") &&
           SetEnvironmentVariableW(L"QT_QPA_FONTDIR", (root_ / L"fonts").c_str());
}
} // namespace gb::controller
