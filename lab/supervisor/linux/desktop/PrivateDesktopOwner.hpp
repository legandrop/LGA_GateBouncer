#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <vector>
namespace gb {
class DesktopWorkerEntry;
class LinuxSshCreator;
class PrivateDesktopOwner final : public std::enable_shared_from_this<PrivateDesktopOwner> {
public:
    enum class State { Creating, StationOwned, DesktopOwned, ClosePending, Closed };
    struct Snapshot { State state; std::uint64_t generation; bool revoked; };
    ~PrivateDesktopOwner() noexcept = default;
    PrivateDesktopOwner(const PrivateDesktopOwner&) = delete;
    PrivateDesktopOwner& operator=(const PrivateDesktopOwner&) = delete;
    PrivateDesktopOwner(PrivateDesktopOwner&&) = delete;
    PrivateDesktopOwner& operator=(PrivateDesktopOwner&&) = delete;
    Snapshot InspectOwn();
    Snapshot CancelOwn();
    Snapshot CloseOwn();
private:
    friend class DesktopWorkerEntry;
    friend class LinuxSshCreator;
    class DedicatedCreatorGuard {
        friend class DesktopWorkerEntry;
        friend class PrivateDesktopOwner;
        DedicatedCreatorGuard();
        DWORD thread_;
    };
    class Guard {
        friend class PrivateDesktopOwner;
        Guard(std::shared_ptr<PrivateDesktopOwner>, std::uint64_t);
        std::shared_ptr<PrivateDesktopOwner> owner_;
        std::unique_lock<std::recursive_mutex> lock_;
    public:
        ~Guard();
        Guard(const Guard&) = delete;
        Guard(Guard&&) = delete;
    };
    PrivateDesktopOwner() = default;
    static std::shared_ptr<PrivateDesktopOwner> CreateOwn(const DedicatedCreatorGuard&);
    static void ReleaseClosed(const std::shared_ptr<PrivateDesktopOwner>&);
    Guard GuardOwn(std::uint64_t);
    bool AcquireOwn();
    bool ReadSecurityOwn(HANDLE, DWORD);
    void RevokeLocked();
    Snapshot ViewLocked() const { return {state_, generation_, revoked_}; }
    std::recursive_mutex mutex_;
    State state_ = State::Creating;
    std::uint64_t generation_ = 1;
    DWORD thread_ = 0;
    HWINSTA oldStation_ = nullptr, station_ = nullptr;
    HDESK oldDesktop_ = nullptr, desktop_ = nullptr;
    HANDLE token_ = nullptr;
    std::vector<BYTE> user_, groups_;
    PSID userSid_ = nullptr, logonSid_ = nullptr;
    bool revoked_ = false, acquiring_ = false, closing_ = false;
    unsigned guards_ = 0;
    static std::mutex registryMutex_;
    static std::map<PrivateDesktopOwner*, std::shared_ptr<PrivateDesktopOwner>> retained_;
};
}
