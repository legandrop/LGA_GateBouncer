#pragma once
#include "WindowsNativeOwnedLaunchContext.hpp"
#include "desktop/PrivateDesktopOwner.hpp"
#include "guestbroker/GuestNoJobObserver.hpp"
#include "helper/OwnedSuspendedProcess.hpp"
#include "../files/RetainedFile.hpp"
namespace gb {
class FixedGuestBrokerSource;
// Operacion privada preparada; el broker debe entregar admision guest viva antes de invocarla.
class LinuxSshCreator final : public std::enable_shared_from_this<LinuxSshCreator> {
public:
    enum class State { Preparing, Running, ClosePending, Closed };
    struct Snapshot { State state; bool resumeSubmitted; bool cancelled; };
    Snapshot InspectOwn();
    Snapshot CancelOwn();
    Snapshot CloseOwn();
    ~LinuxSshCreator() noexcept = default;
private:
    friend class FixedGuestBrokerSource;
    LinuxSshCreator() = default;
    static std::shared_ptr<LinuxSshCreator> StartPreparedOwn(
        const std::shared_ptr<PrivateDesktopOwner>&,
        const std::shared_ptr<WindowsNativeOwnedLaunchContext>&,
        const std::shared_ptr<GuestNoJobObserver>&,
        const std::array<std::array<BYTE, 32>, 4>&, const std::wstring&, const std::wstring&);
    bool CurrentOwn();
    bool CreateAssignResumeOwn();
    void RevokeOwn();
    Snapshot ViewOwn() const;
    std::recursive_mutex mutex_;
    std::atomic<bool> cancelled_{false};
    State state_ = State::Preparing;
    bool active_ = false, resumeSubmitted_ = false;
    std::shared_ptr<PrivateDesktopOwner> desktop_;
    std::shared_ptr<WindowsNativeOwnedLaunchContext> job_;
    std::shared_ptr<GuestNoJobObserver> helper_;
    std::shared_ptr<OwnedSuspendedProcess> child_;
    std::shared_ptr<GuestNoJobObserver> childNoJob_;
    std::array<std::shared_ptr<RetainedFile>, 4> files_{};
    std::array<HANDLE, 3> inherited_{};
    std::array<HANDLE, 2> reads_{};
    std::wstring desktopName_, temporary_, address_;
    std::uint64_t desktopGeneration_ = 0, jobGeneration_ = 0;
    static std::mutex registryMutex_;
    static std::map<LinuxSshCreator*, std::shared_ptr<LinuxSshCreator>> retained_;
};
}
