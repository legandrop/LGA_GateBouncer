#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <atomic>
#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
namespace gb {
class OwnedHelperLaunchAdapter;
class OwnedSuspendedProcess;
class OwnedHelperContainer final : public std::enable_shared_from_this<OwnedHelperContainer> {
public:
    enum class State { Creating, ContainerOwned, ClosePending, Closed };
    enum class Cause { None, CreateFailed, LimitsUnconfirmed, AccountingUnconfirmed,
        MemberUnknown, MemberBudgetExceeded, Cancelled, TerminateUnconfirmed,
        CloseUnconfirmed, GenerationExhausted, AssignUnconfirmed, MemberExitUnconfirmed };
    struct Snapshot { State state; Cause cause; std::uint64_t generation;
        bool revoked; bool accountingObserved; DWORD activeProcesses; };
    static std::shared_ptr<OwnedHelperContainer> CreateOwn();
    ~OwnedHelperContainer() noexcept = default;
    OwnedHelperContainer(const OwnedHelperContainer&) = delete;
    OwnedHelperContainer& operator=(const OwnedHelperContainer&) = delete;
    OwnedHelperContainer(OwnedHelperContainer&&) = delete;
    OwnedHelperContainer& operator=(OwnedHelperContainer&&) = delete;
    Snapshot InspectOwn();
    Snapshot CancelOwn();
    Snapshot CloseOwn();
private:
    friend class OwnedHelperLaunchAdapter;
    class Guard final {
        friend class OwnedHelperContainer;
        Guard(std::shared_ptr<OwnedHelperContainer>, std::uint64_t);
        std::shared_ptr<OwnedHelperContainer> owner_;
        std::unique_lock<std::recursive_mutex> lock_;
    public:
        Guard(const Guard&) = delete;
        Guard& operator=(const Guard&) = delete;
        Guard(Guard&&) = delete;
        Guard& operator=(Guard&&) = delete;
        ~Guard();
    };
    OwnedHelperContainer() = default;
    Guard GuardOwn(std::uint64_t);
    bool ReadLimitsOwn() const;
    bool ReadAccountingOwn();
    bool ConfirmMembersOwn();
    void RevokeLocked(Cause);
    Snapshot ViewLocked() const;
    static void ReleaseClosed(const std::shared_ptr<OwnedHelperContainer>&);
    static std::mutex registryMutex_;
    static std::map<OwnedHelperContainer*, std::shared_ptr<OwnedHelperContainer>> retained_;
    std::recursive_mutex mutex_;
    std::atomic<bool> cancelRequested_{false};
    HANDLE job_ = nullptr;
    State state_ = State::Creating;
    Cause cause_ = Cause::None;
    std::uint64_t generation_ = 1;
    bool revoked_ = false, accountingObserved_ = false, acquiring_ = false, closing_ = false;
    DWORD activeProcesses_ = 0;
    unsigned guards_ = 0;
    struct Member { std::shared_ptr<OwnedSuspendedProcess> owner; bool assigned = false; };
    std::array<Member, 2> members_{};
};
}
