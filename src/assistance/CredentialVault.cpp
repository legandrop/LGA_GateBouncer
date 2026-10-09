#include "CredentialVault.h"
#include <aclapi.h>
#include <sddl.h>
#include <wincrypt.h>
#include <QCryptographicHash>
#include <QDir>
#include <QRegularExpression>
#include <QUuid>
#include <algorithm>
#include <cstring>

namespace Gate::Assistance {
namespace {
struct Handle {
    HANDLE h = INVALID_HANDLE_VALUE;
    Handle() = default;
    explicit Handle(HANDLE value) : h(value) {}
    ~Handle() { if (h != INVALID_HANDLE_VALUE && h) CloseHandle(h); }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    Handle(Handle &&o) noexcept : h(o.h) { o.h = INVALID_HANDLE_VALUE; }
    explicit operator bool() const { return h && h != INVALID_HANDLE_VALUE; }
};
struct LocalMemory {
    void *p = nullptr;
    ~LocalMemory() { if (p) LocalFree(p); }
};
const char *fixtureValue(SyntheticCredential fixture) {
    return fixture == SyntheticCredential::Alpha ? "synthetic-not-a-credential-alpha"
                                                 : "synthetic-not-a-credential-beta";
}
QByteArray digest(const unsigned char *data, size_t size) {
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(QByteArrayView("LGA GateBouncer vault v1"));
    hash.addData(QByteArrayView(reinterpret_cast<const char *>(data), qsizetype(size)));
    return hash.result();
}
bool noReparse(HANDLE handle) {
    FILE_ATTRIBUTE_TAG_INFO info{};
    return GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &info, sizeof(info)) &&
           !(info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
}
bool exactSecurity(HANDLE handle, PSID userSid) {
    PSID owner = nullptr; PACL acl = nullptr; PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        &owner, nullptr, &acl, nullptr, &descriptor) != ERROR_SUCCESS) return false;
    LocalMemory memory{descriptor};
    SECURITY_DESCRIPTOR_CONTROL control = 0; DWORD revision = 0;
    if (!owner || !EqualSid(owner, userSid) || !acl ||
        !GetSecurityDescriptorControl(descriptor, &control, &revision) ||
        !(control & SE_DACL_PROTECTED) || acl->AceCount != 2) return false;
    unsigned char systemBuffer[SECURITY_MAX_SID_SIZE]; DWORD systemSize = sizeof(systemBuffer);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemBuffer, &systemSize)) return false;
    bool userFound = false, systemFound = false;
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        void *raw = nullptr; if (!GetAce(acl, i, &raw)) return false;
        const auto *ace = static_cast<ACCESS_ALLOWED_ACE *>(raw);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
            ace->Header.AceFlags != 0 || ace->Mask != FILE_ALL_ACCESS) return false;
        const auto sid = const_cast<DWORD *>(&ace->SidStart);
        if (EqualSid(sid, userSid)) userFound = true;
        else if (EqualSid(sid, systemBuffer)) systemFound = true;
        else return false;
    }
    return userFound && systemFound;
}
Handle openChecked(const QString &path, DWORD access, bool directory, PSID userSid, bool checkAcl) {
    const auto wide = path.toStdWString();
    Handle handle(CreateFileW(wide.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT |
                             (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0), nullptr));
    if (!handle || !noReparse(handle.h) || (checkAcl && !exactSecurity(handle.h, userSid))) return {};
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle.h, &info) ||
        bool(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != directory) return {};
    return handle;
}
}
struct SyntheticCredentialVault::Impl {
    QString root, file;
    std::vector<unsigned char> tokenInfo;
    PSID sid = nullptr;
    LocalMemory descriptor;
    std::vector<Handle> directories;
    bool prepared = false;
    explicit Impl(QString value) : root(std::move(value)) {}
};
SyntheticCredentialVault::SyntheticCredentialVault(QString root) : impl_(std::make_unique<Impl>(std::move(root))) {}
SyntheticCredentialVault::~SyntheticCredentialVault() = default;
VaultResult SyntheticCredentialVault::prepare() {
    if (impl_->prepared) return exactSecurity(impl_->directories.back().h, impl_->sid)
                                    ? VaultResult::Ok : VaultResult::AccessDenied;
    const auto raw = QDir::fromNativeSeparators(impl_->root);
    const auto parts = raw.split('/');
    if (raw.isEmpty() || !QRegularExpression("^[A-Za-z]:/").match(raw).hasMatch() ||
        parts.contains("..") || parts.contains(".") || raw.contains("//") ||
        !QRegularExpression("^synthetic-vault-[a-z0-9-]{8,}$").match(parts.last()).hasMatch())
        return VaultResult::InvalidRoot;
    impl_->root = QDir::toNativeSeparators(QDir::cleanPath(raw));
    impl_->file = impl_->root + QStringLiteral("\\credential.blob");
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken)) return VaultResult::AccessDenied;
    Handle token(rawToken);
    DWORD bytes = 0; GetTokenInformation(token.h, TokenUser, nullptr, 0, &bytes);
    if (!bytes || bytes > 16384) return VaultResult::AccessDenied;
    impl_->tokenInfo.resize(bytes);
    if (!GetTokenInformation(token.h, TokenUser, impl_->tokenInfo.data(), bytes, &bytes)) return VaultResult::AccessDenied;
    impl_->sid = reinterpret_cast<TOKEN_USER *>(impl_->tokenInfo.data())->User.Sid;
    LPWSTR sidText = nullptr;
    if (!ConvertSidToStringSidW(impl_->sid, &sidText)) return VaultResult::AccessDenied;
    LocalMemory sidMemory{sidText};
    const std::wstring sidString(sidText);
    const std::wstring sddl = L"O:" + sidString + L"D:P(A;;FA;;;" + sidString + L")(A;;FA;;;SY)";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
        return VaultResult::AccessDenied;
    if (impl_->descriptor.p) LocalFree(impl_->descriptor.p);
    impl_->descriptor.p = descriptor;
    impl_->directories.clear();
    QString current = parts.front() + "/";
    // Mantener abiertos los ancestros sin FILE_SHARE_DELETE impide renombrarlos durante el uso.
    for (int i = 1; i < parts.size(); ++i) {
        auto parent = openChecked(QDir::toNativeSeparators(current), GENERIC_READ | READ_CONTROL,
                                  true, impl_->sid, false);
        if (!parent) return VaultResult::AccessDenied;
        impl_->directories.push_back(std::move(parent));
        current += (i == 1 ? "" : "/") + parts[i];
    }
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    const auto rootWide = impl_->root.toStdWString();
    if (!CreateDirectoryW(rootWide.c_str(), &attributes) && GetLastError() != ERROR_ALREADY_EXISTS)
        return VaultResult::IoError;
    auto rootHandle = openChecked(impl_->root, GENERIC_READ | READ_CONTROL, true, impl_->sid, true);
    if (!rootHandle) return VaultResult::AccessDenied;
    impl_->directories.push_back(std::move(rootHandle)); impl_->prepared = true;
    return VaultResult::Ok;
}
SecretBuffer SyntheticCredentialVault::record(SyntheticCredential fixture) {
    const auto value = fixtureValue(fixture); const size_t size = std::strlen(value);
    SecretBuffer result(12 + size + 32);
    std::memcpy(result.bytes_.data(), "LGAGBKV1", 8);
    result.bytes_[8] = 1; result.bytes_[9] = 0;
    result.bytes_[10] = static_cast<unsigned char>(size & 255);
    result.bytes_[11] = static_cast<unsigned char>(size >> 8);
    std::memcpy(result.bytes_.data() + 12, value, size);
    const auto sum = digest(result.bytes_.data(), 12 + size);
    std::memcpy(result.bytes_.data() + 12 + size, sum.constData(), 32);
    return result;
}
VaultResult SyntheticCredentialVault::validate(SecretBuffer &record,
                    const std::function<void(const unsigned char *, size_t)> &consumer) {
    const auto &bytes = record.bytes_;
    if (bytes.size() < 45 || bytes.size() > 556 ||
        std::memcmp(bytes.data(), "LGAGBKV1", 8) != 0 || bytes[8] != 1 || bytes[9] != 0)
        return VaultResult::Corrupt;
    const size_t size = size_t(bytes[10]) | (size_t(bytes[11]) << 8);
    if (!size || size > 512 || bytes.size() != 12 + size + 32) return VaultResult::Corrupt;
    for (size_t i = 12; i < 12 + size; ++i) if (bytes[i] < 33 || bytes[i] > 126) return VaultResult::Corrupt;
    const auto sum = digest(bytes.data(), 12 + size);
    unsigned int difference = 0;
    for (size_t i = 0; i < 32; ++i) difference |= bytes[12 + size + i] ^ static_cast<unsigned char>(sum[i]);
    if (difference) return VaultResult::Corrupt;
    if (consumer) consumer(bytes.data() + 12, size);
    return VaultResult::Ok;
}
VaultResult SyntheticCredentialVault::configure(SyntheticCredential fixture) {
    const auto ready = prepare(); if (ready != VaultResult::Ok) return ready;
    if (status() == VaultState::Unavailable) return VaultResult::AccessDenied;
    auto plain = record(fixture);
    DATA_BLOB input{DWORD(plain.bytes_.size()), plain.bytes_.data()}, encrypted{};
    if (!CryptProtectData(&input, L"LGA GateBouncer synthetic vault", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &encrypted)) return VaultResult::IoError;
    LocalMemory encryptedMemory{encrypted.pbData};
    if (!encrypted.cbData || encrypted.cbData > 16376) return VaultResult::IoError;
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), impl_->descriptor.p, FALSE};
    const auto temp = impl_->root + "\\pending-" + QUuid::createUuid().toString(QUuid::Id128) + ".blob";
    const auto wideTemp = temp.toStdWString();
    Handle file(CreateFileW(wideTemp.c_str(), GENERIC_WRITE | READ_CONTROL | DELETE, 0,
                           &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file || !exactSecurity(file.h, impl_->sid)) return VaultResult::AccessDenied;
    const unsigned char header[8]{'G','B','E','1',
        static_cast<unsigned char>(encrypted.cbData), static_cast<unsigned char>(encrypted.cbData >> 8),
        static_cast<unsigned char>(encrypted.cbData >> 16), static_cast<unsigned char>(encrypted.cbData >> 24)};
    DWORD written = 0;
    if (!WriteFile(file.h, header, sizeof(header), &written, nullptr) || written != sizeof(header) ||
        !WriteFile(file.h, encrypted.pbData, encrypted.cbData, &written, nullptr) ||
        written != encrypted.cbData || !FlushFileBuffers(file.h)) return VaultResult::IoError;
    // El temporal queda en la carpeta protegida si falla el reemplazo; se conserva el anterior.
    CloseHandle(file.h); file.h = INVALID_HANDLE_VALUE;
    const auto wideDest = impl_->file.toStdWString();
    const DWORD attributesOld = GetFileAttributesW(wideDest.c_str());
    const BOOL moved = attributesOld == INVALID_FILE_ATTRIBUTES
        ? MoveFileExW(wideTemp.c_str(), wideDest.c_str(), MOVEFILE_WRITE_THROUGH)
        : ReplaceFileW(wideDest.c_str(), wideTemp.c_str(), nullptr, 0, nullptr, nullptr);
    if (!moved) return VaultResult::IoError;
    auto result = openChecked(impl_->file, GENERIC_READ | READ_CONTROL, false, impl_->sid, true);
    return result ? VaultResult::Ok : VaultResult::AccessDenied;
}
VaultResult SyntheticCredentialVault::withSecret(const std::function<void(const unsigned char *, size_t)> &consumer) {
    const auto ready = prepare(); if (ready != VaultResult::Ok) return ready;
    auto file = openChecked(impl_->file, GENERIC_READ | READ_CONTROL, false, impl_->sid, true);
    if (!file) return VaultResult::AccessDenied;
    LARGE_INTEGER size{}; if (!GetFileSizeEx(file.h, &size) || size.QuadPart < 9 ||
                            size.QuadPart > 16384) return VaultResult::Corrupt;
    std::vector<unsigned char> envelope(size_t(size.QuadPart));
    DWORD read = 0;
    if (!ReadFile(file.h, envelope.data(), DWORD(envelope.size()), &read, nullptr) ||
        read != envelope.size() || std::memcmp(envelope.data(), "GBE1", 4) != 0) return VaultResult::Corrupt;
    const DWORD length = DWORD(envelope[4]) | (DWORD(envelope[5]) << 8) |
                         (DWORD(envelope[6]) << 16) | (DWORD(envelope[7]) << 24);
    if (!length || length > 16376 || envelope.size() != 8 + size_t(length)) return VaultResult::Corrupt;
    DATA_BLOB input{length, envelope.data() + 8}, output{};
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &output)) return VaultResult::Corrupt;
    LocalMemory outputMemory{output.pbData};
    if (!output.pbData) return VaultResult::Corrupt;
    if (output.cbData < 45 || output.cbData > 556) { SecureZeroMemory(output.pbData, output.cbData); return VaultResult::Corrupt; }
    SecretBuffer plain(output.cbData); std::memcpy(plain.bytes_.data(), output.pbData, output.cbData);
    SecureZeroMemory(output.pbData, output.cbData);
    return validate(plain, consumer);
}
VaultState SyntheticCredentialVault::status() {
    if (prepare() != VaultResult::Ok) return VaultState::Unavailable;
    const auto wide = impl_->file.toStdWString();
    if (GetFileAttributesW(wide.c_str()) == INVALID_FILE_ATTRIBUTES)
        return GetLastError() == ERROR_FILE_NOT_FOUND ? VaultState::Absent : VaultState::Unavailable;
    return withSecret({}) == VaultResult::Ok ? VaultState::Present : VaultState::Unavailable;
}
VaultResult SyntheticCredentialVault::forget() {
    const auto ready = prepare(); if (ready != VaultResult::Ok) return ready;
    if (status() == VaultState::Absent) return VaultResult::Ok;
    auto file = openChecked(impl_->file, GENERIC_READ | READ_CONTROL | DELETE, false, impl_->sid, true);
    if (!file) return VaultResult::AccessDenied;
    FILE_DISPOSITION_INFO disposition{TRUE};
    return SetFileInformationByHandle(file.h, FileDispositionInfo, &disposition, sizeof(disposition))
        ? VaultResult::Ok : VaultResult::IoError;
}
bool SyntheticVaultBroker::matches(SyntheticCredential expected) {
    bool match = false;
    const auto result = vault_.withSecret([&](const unsigned char *data, size_t size) {
        const auto expectedValue = fixtureValue(expected);
        match = size == std::strlen(expectedValue) &&
                std::memcmp(data, expectedValue, size) == 0;
    });
    return result == VaultResult::Ok && match;
}
bool SyntheticVaultProbe::corruptPlaintextRejected(SyntheticCorruption corruption) {
    auto record = SyntheticCredentialVault::record(SyntheticCredential::Alpha);
    switch (corruption) {
    case SyntheticCorruption::Magic: record.bytes_[0] ^= 1; break;
    case SyntheticCorruption::Schema: record.bytes_[8] = 2; break;
    case SyntheticCorruption::Length: record.bytes_[11] = 255; break;
    case SyntheticCorruption::Digest: record.bytes_.back() ^= 1; break;
    case SyntheticCorruption::Trailing: record.bytes_.push_back(0); break;
    }
    bool consumed = false;
    const auto result = SyntheticCredentialVault::validate(record, [&](const unsigned char *, size_t) { consumed = true; });
    return result == VaultResult::Corrupt && !consumed;
}
} // namespace Gate::Assistance
