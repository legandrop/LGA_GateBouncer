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
namespace gb {
class OwnedSuspendedProcess;
class FixedGuestBrokerSource;
class LinuxSshCreator;
class GuestNoJobObserver final : public std::enable_shared_from_this<GuestNoJobObserver> {
public:
    enum class State { Observing, Observed, ClosePending, Closed };
    enum class Cause { None, DuplicateUnconfirmed, IdentityUnconfirmed, JobQueryFailed,
        AlreadyInJob, Cancelled, WrongThread, CloseUnconfirmed };
    struct Snapshot { State state; Cause cause; bool revoked; };
    ~GuestNoJobObserver() noexcept = default;
    GuestNoJobObserver(const GuestNoJobObserver&) = delete;
    GuestNoJobObserver& operator=(const GuestNoJobObserver&) = delete;
    Snapshot InspectOwn();
    Snapshot CancelOwn();
    Snapshot CloseOwn();
private:
    friend class FixedGuestBrokerSource;
    friend class LinuxSshCreator;
    class Guard final {
        friend class GuestNoJobObserver;
        explicit Guard(std::shared_ptr<GuestNoJobObserver>);
        std::shared_ptr<GuestNoJobObserver> owner_;
        std::unique_lock<std::recursive_mutex> lock_;
        std::unique_lock<std::recursive_mutex> childLock_;
    public:
        ~Guard();
        Guard(const Guard&) = delete;
        Guard(Guard&&) = delete;
    };
    GuestNoJobObserver() = default;
    static std::shared_ptr<GuestNoJobObserver> ObserveCreatorOwn();
    static std::shared_ptr<GuestNoJobObserver> ObserveChildOwn(
        const std::shared_ptr<OwnedSuspendedProcess>&);
    static void ReleaseClosed(const std::shared_ptr<GuestNoJobObserver>&);
    Guard GuardOwn();
    bool ReadActualOwn();
    bool CheckActualOwn();
    void RevokeLocked(Cause);
    Snapshot ViewLocked() const { return {state_, cause_, revoked_}; }
    std::recursive_mutex mutex_;
    std::atomic<bool> cancelRequested_{false};
    State state_ = State::Observing;
    Cause cause_ = Cause::None;
    DWORD thread_ = 0, pid_ = 0;
    std::uint64_t creation_ = 0;
    HANDLE creator_ = nullptr;
    HANDLE childProcess_ = nullptr;
    std::shared_ptr<OwnedSuspendedProcess> child_;
    bool revoked_ = false, acquiring_ = false, closing_ = false, childUse_ = false;
    unsigned guards_ = 0;
    static std::mutex registryMutex_;
    static std::map<GuestNoJobObserver*, std::shared_ptr<GuestNoJobObserver>> retained_;
};
}
