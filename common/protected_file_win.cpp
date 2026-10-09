#include "protected_file_win.h"
#include <aclapi.h>
#include <bcrypt.h>
#include <climits>
#include <cwchar>
#include <sddl.h>
#include <stdexcept>

namespace gb::native {
wire::Digest digest(const wire::Bytes &b) {
    wire::Digest d{};
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (b.size() > ULONG_MAX ||
        BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        throw std::runtime_error("Integridad no disponible");
    auto status = BCryptHash(algorithm, nullptr, 0, const_cast<PUCHAR>(b.data()),
                             static_cast<ULONG>(b.size()), d.data(), 32);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0)
        throw std::runtime_error("Integridad no disponible");
    return d;
}
wire::Id randomIdentity() {
    wire::Id id{};
    if (BCryptGenRandom(nullptr, id.data(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
        wire::zero(id))
        throw std::runtime_error("Identidad no disponible");
    return id;
}
bool fixedPath(const std::filesystem::path &p) {
    auto s = p.native();
    return p.is_absolute() && p == p.lexically_normal() && s.size() >= 3 && s[1] == L':' &&
           s[2] == L'\\' && GetDriveTypeW(s.substr(0, 3).c_str()) == DRIVE_FIXED;
}
bool protectedRegistry(HKEY key) {
    BYTE system[SECURITY_MAX_SID_SIZE]{}, administrators[SECURITY_MAX_SID_SIZE]{};
    DWORD systemSize = sizeof(system), adminSize = sizeof(administrators);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &systemSize) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, administrators, &adminSize))
        return false;
    auto trusted = [&](PSID sid) {
        return sid && IsValidSid(sid) && (EqualSid(sid, system) || EqualSid(sid, administrators));
    };
    PSID owner = nullptr;
    PACL acl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    auto error = GetSecurityInfo(key, SE_REGISTRY_KEY,
                                 OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
                                 nullptr, &acl, nullptr, &descriptor);
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    bool ok = error == ERROR_SUCCESS && trusted(owner) && acl && IsValidAcl(acl) &&
              GetSecurityDescriptorControl(descriptor, &control, &revision) &&
              (control & SE_DACL_PROTECTED);
    GENERIC_MAPPING mapping{KEY_READ, KEY_WRITE, KEY_EXECUTE, KEY_ALL_ACCESS};
    constexpr DWORD unsafe = KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE | WRITE_DAC | WRITE_OWNER;
    for (DWORD i = 0; ok && i < acl->AceCount; ++i) {
        void *raw = nullptr;
        if (!GetAce(acl, i, &raw)) {
            ok = false;
            break;
        }
        auto header = static_cast<ACE_HEADER *>(raw);
        if (header->AceFlags & INHERIT_ONLY_ACE)
            continue;
        if (header->AceType == ACCESS_DENIED_ACE_TYPE)
            continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            ok = false;
            break;
        }
        auto ace = static_cast<ACCESS_ALLOWED_ACE *>(raw);
        auto mask = ace->Mask;
        MapGenericMask(&mask, &mapping);
        if (!IsValidSid(&ace->SidStart) || (mask & MAXIMUM_ALLOWED) ||
            (!trusted(&ace->SidStart) && (mask & unsafe)))
            ok = false;
    }
    if (descriptor)
        LocalFree(descriptor);
    return ok;
}
bool protectedObject(HANDLE h, bool ancestor, bool directory, bool readableLeaf) {
    FILE_ATTRIBUTE_TAG_INFO shape{};
    if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &shape, sizeof(shape)) ||
        (shape.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        bool(shape.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != directory)
        return false;
    BYTE sy[SECURITY_MAX_SID_SIZE]{}, ba[SECURITY_MAX_SID_SIZE]{};
    DWORD sn = sizeof(sy), bn = sizeof(ba);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, sy, &sn) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, ba, &bn))
        return false;
    PSID ti = nullptr;
    if (ancestor && !ConvertStringSidToSidW(
                        L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &ti))
        return false;
    auto trusted = [&](PSID sid) {
        return sid && IsValidSid(sid) &&
               (EqualSid(sid, sy) || EqualSid(sid, ba) || (ti && EqualSid(sid, ti)));
    };
    PSID owner = nullptr;
    PACL acl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    auto error =
        GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        &owner, nullptr, &acl, nullptr, &sd);
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD rev = 0;
    bool ok = error == ERROR_SUCCESS && trusted(owner) && acl && IsValidAcl(acl) &&
              GetSecurityDescriptorControl(sd, &control, &rev) &&
              (ancestor || (control & SE_DACL_PROTECTED));
    constexpr DWORD unsafe = FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                             FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;
    GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE,
                            FILE_ALL_ACCESS};
    bool fullSy = false, fullBa = false;
    for (DWORD i = 0; ok && i < acl->AceCount; ++i) {
        void *raw = nullptr;
        if (!GetAce(acl, i, &raw)) {
            ok = false;
            break;
        }
        auto header = static_cast<ACE_HEADER *>(raw);
        if (header->AceFlags & INHERIT_ONLY_ACE)
            continue;
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) {
            if (!ancestor)
                ok = false;
            continue;
        }
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            ok = false;
            break;
        }
        auto ace = static_cast<ACCESS_ALLOWED_ACE *>(raw);
        PSID sid = &ace->SidStart;
        auto mask = ace->Mask;
        if (!IsValidSid(sid) || (mask & MAXIMUM_ALLOWED)) {
            ok = false;
            break;
        }
        MapGenericMask(&mask, &mapping);
        if (!trusted(sid) && (mask & (unsafe | (ancestor ? 0 : FILE_APPEND_DATA))))
            ok = false;
        if (!ancestor && !readableLeaf && !trusted(sid))
            ok = false;
        if ((mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS) {
            fullSy |= EqualSid(sid, sy) != FALSE;
            fullBa |= EqualSid(sid, ba) != FALSE;
        }
    }
    if (!ancestor)
        ok = ok && fullSy && fullBa;
    if (sd)
        LocalFree(sd);
    if (ti)
        LocalFree(ti);
    return ok;
}
bool ProtectedDirectory::acquire() {
    if (!fixedPath(root_))
        return false;
    if (!ancestors_.empty()) {
        for (std::size_t i = 0; i < ancestors_.size(); ++i)
            if (!protectedObject(ancestors_[i].value, i + 1 < ancestors_.size(), true, readable_))
                return false;
        return true;
    }
    std::vector<std::filesystem::path> paths;
    for (auto p = root_; !p.empty(); p = p.parent_path()) {
        paths.push_back(p);
        if (p == p.parent_path())
            break;
    }
    std::vector<Handle> held;
    for (auto it = paths.rbegin(); it != paths.rend(); ++it) {
        Handle h(CreateFileW(it->c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                             FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!h || !protectedObject(h.value, std::next(it) != paths.rend(), true, readable_))
            return false;
        held.push_back(std::move(h));
    }
    ancestors_ = std::move(held);
    return true;
}
bool ProtectedDirectory::leafName(const wchar_t *leaf) const {
    if (!leaf || !*leaf || std::wcslen(leaf) > 80)
        return false;
    for (auto p = leaf; *p; ++p)
        if (!((*p >= L'a' && *p <= L'z') || (*p >= L'0' && *p <= L'9') || *p == L'-' || *p == L'.'))
            return false;
    return std::wstring(leaf).find(L"..") == std::wstring::npos;
}
bool ProtectedDirectory::read(const wchar_t *leaf, std::size_t cap, wire::Bytes &out,
                              bool &exists) {
    exists = false;
    if (!leafName(leaf) || !acquire())
        return false;
    Handle f(CreateFileW((root_ / leaf).c_str(), GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,
                         FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT,
                         nullptr));
    if (!f)
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    exists = true;
    LARGE_INTEGER size{};
    if (!protectedObject(f.value, false, false) || !GetFileSizeEx(f.value, &size) ||
        size.QuadPart < 0 || static_cast<std::uint64_t>(size.QuadPart) > cap ||
        size.QuadPart > ULONG_MAX)
        return false;
    wire::Bytes b(static_cast<std::size_t>(size.QuadPart));
    DWORD done = 0;
    if (!ReadFile(f.value, b.data(), static_cast<DWORD>(b.size()), &done, nullptr) ||
        done != b.size())
        return false;
    out = std::move(b);
    return true;
}
bool ProtectedDirectory::replace(const wchar_t *leaf, const wire::Bytes &b) {
    if (!leafName(leaf) || b.size() > ULONG_MAX || !acquire())
        return false;
    auto final = root_ / leaf, backup = root_ / (std::wstring(leaf) + L".previous");
    for (auto &path : {final, backup}) {
        Handle old(CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                               FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!old) {
            if (GetLastError() != ERROR_FILE_NOT_FOUND)
                return false;
        } else if (!protectedObject(old.value, false, false))
            return false;
    }
    auto text = wire::hex(randomIdentity());
    auto temp = root_ / (L"journal-prepared-" + std::wstring(text.begin(), text.end()) + L".bin");
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &sd, nullptr))
        return false;
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
    Handle f(CreateFileW(temp.c_str(), GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES, 0, &sa,
                         CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                         nullptr));
    LocalFree(sd);
    if (!f || !protectedObject(f.value, false, false))
        return false;
    DWORD done = 0;
    if (!WriteFile(f.value, b.data(), static_cast<DWORD>(b.size()), &done, nullptr) ||
        done != b.size() || !FlushFileBuffers(f.value))
        return false;
    f.reset();
    auto attributes = GetFileAttributesW(final.c_str());
    bool ok = attributes == INVALID_FILE_ATTRIBUTES
                  ? (GetLastError() == ERROR_FILE_NOT_FOUND &&
                     MoveFileExW(temp.c_str(), final.c_str(), MOVEFILE_WRITE_THROUGH))
                  : ReplaceFileW(final.c_str(), temp.c_str(), backup.c_str(), 0, nullptr,
                                 nullptr) != FALSE;
    if (!ok)
        return false;
    Handle committed(CreateFileW(final.c_str(), GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES,
                                 0, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr));
    return committed && protectedObject(committed.value, false, false) &&
           FlushFileBuffers(committed.value);
}
} // namespace gb::native
