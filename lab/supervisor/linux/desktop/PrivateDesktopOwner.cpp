#include "PrivateDesktopOwner.hpp"
#include "../helper/OwnedSuspendedProcess.hpp"
#include "../WindowsNativeOwnedLaunchContext.hpp"
#include <bcrypt.h>
#include <limits>
#include <stdexcept>
#include <string>
namespace gb {
std::mutex PrivateDesktopOwner::registryMutex_;
std::map<PrivateDesktopOwner*, std::shared_ptr<PrivateDesktopOwner>> PrivateDesktopOwner::retained_;
PrivateDesktopOwner::DedicatedCreatorGuard::DedicatedCreatorGuard() : thread_(GetCurrentThreadId()) {}
namespace {
constexpr DWORD stationAccess = 0x2000A, desktopAccess = 0x20083;
bool SidInside(const std::vector<BYTE>& data, PSID sid) {
    const auto begin = reinterpret_cast<std::uintptr_t>(data.data());
    const auto address = reinterpret_cast<std::uintptr_t>(sid);
    if (address < begin || address - begin > data.size() || data.size() - (address - begin) < 8) return false;
    const auto length = 8u + static_cast<unsigned>(static_cast<SID*>(sid)->SubAuthorityCount) * 4u;
    return length <= data.size() - (address - begin) && IsValidSid(sid) && GetLengthSid(sid) == length;
}
bool TokenData(HANDLE token, TOKEN_INFORMATION_CLASS kind, std::vector<BYTE>& data) {
    DWORD size = 0, returned = 0;
    if (GetTokenInformation(token, kind, nullptr, 0, &size) || GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        size < sizeof(DWORD) || size > 65536) return false;
    data.resize(size);
    if (!GetTokenInformation(token, kind, data.data(), size, &returned) || returned > size) return false;
    data.resize(returned); return true;
}
bool Security(SECURITY_DESCRIPTOR& sd, std::vector<BYTE>& bytes, PSID owner, PSID logon, DWORD mask) {
    bytes.resize(sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(logon));
    auto acl = reinterpret_cast<PACL>(bytes.data());
    return InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) &&
        InitializeAcl(acl, static_cast<DWORD>(bytes.size()), ACL_REVISION) &&
        AddAccessAllowedAceEx(acl, ACL_REVISION, 0, mask, logon) &&
        SetSecurityDescriptorOwner(&sd, owner, FALSE) && SetSecurityDescriptorDacl(&sd, TRUE, acl, FALSE) &&
        SetSecurityDescriptorControl(&sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED);
}
}
std::shared_ptr<PrivateDesktopOwner> PrivateDesktopOwner::CreateOwn(const DedicatedCreatorGuard& entry) {
    auto owner = std::shared_ptr<PrivateDesktopOwner>(new PrivateDesktopOwner);
    { std::lock_guard<std::mutex> registry(registryMutex_); retained_.emplace(owner.get(), owner); }
    {
        std::lock_guard<std::recursive_mutex> lock(owner->mutex_);
        owner->thread_ = entry.thread_;
        owner->acquiring_ = true;
        try {
            if (entry.thread_ != GetCurrentThreadId() || !owner->AcquireOwn() || owner->revoked_)
                owner->RevokeLocked();
        } catch (...) { owner->RevokeLocked(); }
        owner->acquiring_ = false;
    }
    if (owner->InspectOwn().revoked) owner->CloseOwn();
    return owner;
}
bool PrivateDesktopOwner::AcquireOwn() {
    oldStation_ = GetProcessWindowStation(); oldDesktop_ = GetThreadDesktop(thread_);
    if (!oldStation_ || !oldDesktop_ || !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token_)) return false;
    if (!TokenData(token_, TokenUser, user_) || user_.size() < sizeof(TOKEN_USER) ||
        !TokenData(token_, TokenGroups, groups_) || groups_.size() < offsetof(TOKEN_GROUPS, Groups)) return false;
    userSid_ = reinterpret_cast<TOKEN_USER*>(user_.data())->User.Sid;
    if (!SidInside(user_, userSid_)) return false;
    const auto groups = reinterpret_cast<TOKEN_GROUPS*>(groups_.data());
    if (groups->GroupCount > (groups_.size() - offsetof(TOKEN_GROUPS, Groups)) / sizeof(SID_AND_ATTRIBUTES)) return false;
    for (DWORD i = 0; i < groups->GroupCount; ++i) {
        if ((groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) {
            if (logonSid_ || !SidInside(groups_, groups->Groups[i].Sid)) return false;
            logonSid_ = groups->Groups[i].Sid;
        }
    }
    if (!logonSid_ || !CloseHandle(token_)) return false;
    token_ = nullptr;
    SECURITY_DESCRIPTOR stationSD{}, desktopSD{}; std::vector<BYTE> stationAcl, desktopAcl;
    if (!Security(stationSD, stationAcl, userSid_, logonSid_, stationAccess) ||
        !Security(desktopSD, desktopAcl, userSid_, logonSid_, desktopAccess) || revoked_) return false;
    SECURITY_ATTRIBUTES stationSA{sizeof(SECURITY_ATTRIBUTES), &stationSD, FALSE};
    SECURITY_ATTRIBUTES desktopSA{sizeof(SECURITY_ATTRIBUTES), &desktopSD, FALSE};
    station_ = CreateWindowStationW(nullptr, CWF_CREATE_ONLY, stationAccess, &stationSA);
    if (!station_) return false;
    state_ = State::StationOwned;
    if (revoked_ || !ReadSecurityOwn(station_, stationAccess)) return false;
    if (revoked_ || !SetProcessWindowStation(station_) ||
        GetProcessWindowStation() != station_ || revoked_) return false;
    BYTE random[16]{};
    if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0 || revoked_) return false;
    std::wstring name = L"GBD_"; constexpr wchar_t hex[] = L"0123456789abcdef";
    for (BYTE byte : random) { name += hex[byte >> 4]; name += hex[byte & 15]; }
    desktop_ = CreateDesktopW(name.c_str(), nullptr, nullptr, 0, desktopAccess, &desktopSA);
    if (!desktop_ || revoked_ || !ReadSecurityOwn(desktop_, desktopAccess)) return false;
    state_ = State::DesktopOwned; return true;
}
bool PrivateDesktopOwner::ReadSecurityOwn(HANDLE object, DWORD mask) {
    SECURITY_INFORMATION requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    DWORD size = 0, returned = 0;
    if (!object || GetUserObjectSecurity(object, &requested, nullptr, 0, &size) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || size < SECURITY_DESCRIPTOR_MIN_LENGTH || size > 65536) return false;
    std::vector<BYTE> data(size);
    if (!GetUserObjectSecurity(object, &requested, data.data(), size, &returned) || returned > size ||
        returned < SECURITY_DESCRIPTOR_MIN_LENGTH || !IsValidSecurityDescriptor(data.data()) ||
        GetSecurityDescriptorLength(data.data()) > returned) return false;
    data.resize(returned);
    PSID owner = nullptr; PACL acl = nullptr; BOOL defaulted = FALSE, present = FALSE;
    SECURITY_DESCRIPTOR_CONTROL control = 0; DWORD revision = 0;
    if (!GetSecurityDescriptorOwner(data.data(), &owner, &defaulted) || defaulted || !owner ||
        !GetSecurityDescriptorDacl(data.data(), &present, &acl, &defaulted) || !present || defaulted || !acl ||
        !GetSecurityDescriptorControl(data.data(), &control, &revision) || !(control & SE_DACL_PROTECTED) ||
        !IsValidAcl(acl) || acl->AceCount != 1 || !SidInside(data, owner) || !EqualSid(owner, userSid_)) return false;
    void* raw = nullptr;
    if (!GetAce(acl, 0, &raw) || !raw) return false;
    const auto ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
    return ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace->Header.AceFlags == 0 &&
        ace->Mask == mask && SidInside(data, &ace->SidStart) && EqualSid(&ace->SidStart, logonSid_);
}
void PrivateDesktopOwner::RevokeLocked() {
    if (!revoked_) {
        revoked_ = true;
        if (generation_ != std::numeric_limits<std::uint64_t>::max()) ++generation_;
    }
    if (state_ != State::Closed) state_ = State::ClosePending;
}
PrivateDesktopOwner::Snapshot PrivateDesktopOwner::InspectOwn() {
    std::lock_guard<std::recursive_mutex> lock(mutex_); return ViewLocked();
}
PrivateDesktopOwner::Snapshot PrivateDesktopOwner::CancelOwn() {
    cancelRequested_.store(true);
    std::lock_guard<std::recursive_mutex> lock(mutex_); RevokeLocked(); return ViewLocked();
}
PrivateDesktopOwner::Guard::Guard(std::shared_ptr<PrivateDesktopOwner> owner, std::uint64_t generation)
    : owner_(std::move(owner)), lock_(owner_->mutex_) {
    if (GetCurrentThreadId() != owner_->thread_ || owner_->revoked_ || owner_->cancelRequested_.load() || owner_->state_ != State::DesktopOwned ||
        owner_->generation_ != generation || owner_->acquiring_ || owner_->closing_)
        throw std::runtime_error("DesktopGuardUnavailable");
    if (GetProcessWindowStation() != owner_->station_ || !owner_->ReadSecurityOwn(owner_->station_, stationAccess) ||
        !owner_->ReadSecurityOwn(owner_->desktop_, desktopAccess) || owner_->revoked_ ||
        owner_->state_ != State::DesktopOwned) {
        owner_->RevokeLocked(); throw std::runtime_error("DesktopObservationLost");
    }
    ++owner_->guards_;
}
PrivateDesktopOwner::Guard::~Guard() { --owner_->guards_; }
PrivateDesktopOwner::Guard PrivateDesktopOwner::GuardOwn(std::uint64_t generation) {
    return Guard(shared_from_this(), generation);
}
void PrivateDesktopOwner::ReleaseClosed(const std::shared_ptr<PrivateDesktopOwner>& owner) {
    std::shared_ptr<PrivateDesktopOwner> release;
    { std::lock_guard<std::mutex> registry(registryMutex_);
      auto found = retained_.find(owner.get());
      if (found != retained_.end()) { release = std::move(found->second); retained_.erase(found); } }
    release.reset();
}
std::wstring PrivateDesktopOwner::NamespaceOwn() {
    auto name = [](HANDLE object) {
        DWORD bytes = 0, returned = 0;
        if (GetUserObjectInformationW(object, UOI_NAME, nullptr, 0, &bytes) ||
            GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes < sizeof(wchar_t) ||
            bytes > 1024 || bytes % sizeof(wchar_t)) throw std::runtime_error("DesktopNameUnknown");
        std::vector<wchar_t> data(bytes / sizeof(wchar_t), L'\0');
        if (!GetUserObjectInformationW(object, UOI_NAME, data.data(), bytes, &returned) ||
            returned != bytes || data.back() != L'\0') throw std::runtime_error("DesktopNameUnknown");
        std::wstring value(data.data());
        if (value.empty() || value.size() + 1 != data.size() || value.find(L'\\') != std::wstring::npos)
            throw std::runtime_error("DesktopNameUnknown");
        return value;
    };
    if (cancelRequested_.load() || revoked_ || GetCurrentThreadId() != thread_ ||
        GetProcessWindowStation() != station_) throw std::runtime_error("DesktopCurrentLost");
    return name(station_) + L"\\" + name(desktop_);
}
bool PrivateDesktopOwner::ReleaseChildOwn() {
    if (!child_) return !childJob_;
    // Orden unico: desktop -> Job -> hoja. NoJob se adquiere antes del desktop.
    if (!childJob_) return false;
    std::lock_guard<std::recursive_mutex> jobLock(childJob_->mutex_);
    if (childJob_->acquiring_) return false;
    child_->CancelOwn(); child_->CloseOwn();
    std::lock_guard<std::recursive_mutex> childLock(child_->mutex_);
    if (child_->state_ != OwnedSuspendedProcess::State::Closed || child_->process_ || child_->thread_ ||
        !(childJob_->state_ == WindowsNativeOwnedLaunchContext::State::Closed || childJob_->ReadMemberOwn())) return false;
    childJob_->member_.reset(); childJob_->assigned_ = false;
    child_.reset(); childJob_.reset();
    return true;
}
PrivateDesktopOwner::Snapshot PrivateDesktopOwner::CloseOwn() {
    cancelRequested_.store(true);
    const auto live = shared_from_this(); Snapshot result{};
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (state_ == State::Closed) return ViewLocked();
        RevokeLocked();
        if (GetCurrentThreadId() != thread_ || acquiring_ || closing_ || guards_) return ViewLocked();
        closing_ = true;
        if (!ReleaseChildOwn()) { closing_ = false; return ViewLocked(); }
        const bool restored = !station_ || (SetProcessWindowStation(oldStation_) &&
            GetProcessWindowStation() == oldStation_ && SetThreadDesktop(oldDesktop_) &&
            GetThreadDesktop(thread_) == oldDesktop_);
        if (restored && (!desktop_ || CloseDesktop(desktop_))) {
            desktop_ = nullptr;
            if (!station_ || CloseWindowStation(station_)) {
                station_ = nullptr;
                if (!token_ || CloseHandle(token_)) { token_ = nullptr; state_ = State::Closed; }
            }
        }
        closing_ = false; result = ViewLocked();
    }
    if (result.state == State::Closed) ReleaseClosed(live);
    return result;
}
}
