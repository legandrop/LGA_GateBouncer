#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
namespace gb {
class OwnedHelperLaunchAdapter;
class GuestNoJobObserver;
class LinuxSshCreator;
class PrivateDesktopOwner;
class WindowsNativeOwnedLaunchContext;
class FixedGuestBrokerSource;
class OwnedSuspendedProcess final : public std::enable_shared_from_this<OwnedSuspendedProcess> {
public:
    enum class State { Creating, Suspended, Running, ClosePending, Closed };
    enum class Cause { None, InputInvalid, CreateFailed, IdentityUnconfirmed,
        Cancelled, TerminateUnconfirmed, ExitUnconfirmed, CloseUnconfirmed, ResumeUnconfirmed };
    struct Snapshot { State state; Cause cause; DWORD pid; std::uint64_t creation;
        bool revoked; bool exitObserved; };
    ~OwnedSuspendedProcess() noexcept = default;
    OwnedSuspendedProcess(const OwnedSuspendedProcess&) = delete;
    OwnedSuspendedProcess& operator=(const OwnedSuspendedProcess&) = delete;
    OwnedSuspendedProcess(OwnedSuspendedProcess&&) = delete;
    OwnedSuspendedProcess& operator=(OwnedSuspendedProcess&&) = delete;
    Snapshot InspectOwn();
    Snapshot CancelOwn();
    Snapshot CloseOwn();
private:
    friend class OwnedHelperLaunchAdapter;
    friend class GuestNoJobObserver;
    friend class LinuxSshCreator;
    friend class PrivateDesktopOwner;
    friend class WindowsNativeOwnedLaunchContext;
    friend class FixedGuestBrokerSource;
    OwnedSuspendedProcess() = default;
    // Hoja sin entry productivo: el adapter debe aportar guards y sello admitidos.
    static std::shared_ptr<OwnedSuspendedProcess> CreateSuspendedOwn(
        const std::wstring&, std::vector<wchar_t>, const std::vector<wchar_t>&,
        const std::wstring&);
    static void ReleaseClosed(const std::shared_ptr<OwnedSuspendedProcess>&);
    bool ReadIdentityOwn() const;
    void RevokeLocked(Cause);
    Snapshot ViewLocked() const;
    std::recursive_mutex mutex_;
    std::atomic<bool> cancelRequested_{false};
    State state_ = State::Creating;
    Cause cause_ = Cause::None;
    HANDLE process_ = nullptr, thread_ = nullptr;
    DWORD pid_ = 0;
    std::uint64_t creation_ = 0;
    bool revoked_ = false, acquiring_ = false, closing_ = false, exitObserved_ = false;
    unsigned noJobObservers_ = 0;
    static std::mutex registryMutex_;
    static std::map<OwnedSuspendedProcess*, std::shared_ptr<OwnedSuspendedProcess>> retained_;
};
}
