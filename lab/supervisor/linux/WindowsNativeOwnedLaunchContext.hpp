#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>

namespace gb {
class LinuxSshCreator;
class WindowsNativeOwnedLaunchContext final
    : public std::enable_shared_from_this<WindowsNativeOwnedLaunchContext> {
public:
    enum class State { CreatingJob, JobOwned, Revoked, ClosePending, Closed };
    enum class Cause { None, CreateFailed, LimitsUnconfirmed, Cancelled,
        CancelUnconfirmed, AccountingUnconfirmed, CloseUnconfirmed, GenerationExhausted };
    struct Snapshot { State state; Cause cause; std::uint64_t generation; };
    static std::shared_ptr<WindowsNativeOwnedLaunchContext> CreateJobOwn();
    ~WindowsNativeOwnedLaunchContext() noexcept;
    WindowsNativeOwnedLaunchContext(const WindowsNativeOwnedLaunchContext&) = delete;
    WindowsNativeOwnedLaunchContext& operator=(const WindowsNativeOwnedLaunchContext&) = delete;
    WindowsNativeOwnedLaunchContext(WindowsNativeOwnedLaunchContext&&) = delete;
    WindowsNativeOwnedLaunchContext& operator=(WindowsNativeOwnedLaunchContext&&) = delete;
    Snapshot InspectOwn();
    Snapshot CancelOwn();
    Snapshot CloseOwn();
private:
    friend class LinuxSshCreator;
    class Guard final {
        friend class WindowsNativeOwnedLaunchContext;
        explicit Guard(std::shared_ptr<WindowsNativeOwnedLaunchContext>, std::uint64_t);
        std::shared_ptr<WindowsNativeOwnedLaunchContext> owner_;
        std::unique_lock<std::mutex> lock_;
    public:
        Guard(const Guard&) = delete;
        Guard& operator=(const Guard&) = delete;
        Guard(Guard&&) = delete;
        Guard& operator=(Guard&&) = delete;
        ~Guard() = default;
    };
    WindowsNativeOwnedLaunchContext() = default;
    Guard GuardCurrent(std::uint64_t);
    bool ReadLimitsOwn() const;
    void RevokeLocked(Cause);
    Snapshot ViewLocked() const;
    static void Retain(const std::shared_ptr<WindowsNativeOwnedLaunchContext>&);
    static void ReleaseClosed(const std::shared_ptr<WindowsNativeOwnedLaunchContext>&);
    static std::mutex registryMutex_;
    static std::map<WindowsNativeOwnedLaunchContext*, std::shared_ptr<WindowsNativeOwnedLaunchContext>> retained_;
    std::mutex mutex_;
    HANDLE job_ = nullptr;
    State state_ = State::CreatingJob;
    Cause cause_ = Cause::None;
    std::uint64_t generation_ = 0;
    bool revoked_ = false;
};
}
