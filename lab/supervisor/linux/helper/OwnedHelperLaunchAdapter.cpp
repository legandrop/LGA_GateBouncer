#include "OwnedHelperLaunchAdapter.hpp"
namespace gb {
namespace {
class AcquisitionPin final {
public:
    explicit AcquisitionPin(bool& value) : value_(value), previous_(value) { value_ = true; }
    ~AcquisitionPin() { value_ = previous_; }
private:
    bool& value_;
    bool previous_;
};
std::uint64_t MemberStamp(const FILETIME& time) {
    return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}
}
bool OwnedHelperLaunchAdapter::CurrentMemberOwn(
    const std::shared_ptr<OwnedSuspendedProcess>& member, HANDLE job, bool assigned, DWORD& alive) {
    std::lock_guard<std::recursive_mutex> memberLock(member->mutex_);
    alive = 0;
    if (!member->process_) return member->state_ == OwnedSuspendedProcess::State::Closed;
    AcquisitionPin pin(member->acquiring_);
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!member->pid_ || !member->creation_ || member->cancelRequested_.load() || member->revoked_ ||
        GetProcessId(member->process_) != member->pid_ || member->cancelRequested_.load() || member->revoked_ ||
        !GetProcessTimes(member->process_, &creation, &exit, &kernel, &user) ||
        member->cancelRequested_.load() || member->revoked_ || MemberStamp(creation) != member->creation_) return false;
    const DWORD waited = WaitForSingleObject(member->process_, 0);
    if (member->cancelRequested_.load() || member->revoked_) return false;
    if (waited == WAIT_OBJECT_0) return true;
    if (waited != WAIT_TIMEOUT || member->revoked_ || member->cancelRequested_.load() ||
        member->state_ != OwnedSuspendedProcess::State::Suspended) return false;
    if (assigned) {
        BOOL inOwnJob = FALSE;
        if (!IsProcessInJob(member->process_, job, &inOwnJob) || !inOwnJob ||
            member->revoked_ || member->cancelRequested_.load()) return false;
    }
    alive = 1;
    return true;
}
bool OwnedHelperLaunchAdapter::CloseMemberOwn(const std::shared_ptr<OwnedSuspendedProcess>& member) {
    member->CancelOwn();
    member->CloseOwn();
    std::lock_guard<std::recursive_mutex> memberLock(member->mutex_);
    return member->state_ == OwnedSuspendedProcess::State::Closed &&
        !member->process_ && !member->thread_;
}
std::shared_ptr<OwnedSuspendedProcess> OwnedHelperLaunchAdapter::AcquireSuspendedMemberOwn(
    const std::shared_ptr<OwnedHelperContainer>& container, const std::wstring& image,
    std::vector<wchar_t> command, const std::vector<wchar_t>& environment, const std::wstring& cwd) {
    if (!container) return {};
    const auto retained = container;
    std::unique_lock<std::recursive_mutex> containerLock(retained->mutex_);
    if (retained->revoked_ || retained->cancelRequested_.load() ||
        retained->state_ != OwnedHelperContainer::State::ContainerOwned || retained->guards_ ||
        retained->acquiring_ || retained->closing_) return {};
    for (const auto& existing : retained->members_) {
        if (!existing.owner) continue;
        std::lock_guard<std::recursive_mutex> memberLock(existing.owner->mutex_);
        if (existing.owner->noJobObservers_) return {};
    }
    auto* slot = &retained->members_[0];
    if (slot->owner) slot = &retained->members_[1];
    if (slot->owner) { retained->RevokeLocked(OwnedHelperContainer::Cause::MemberBudgetExceeded); return {}; }
    AcquisitionPin containerPin(retained->acquiring_);
    if (!retained->ReadLimitsOwn() || !retained->ConfirmMembersOwn() ||
        retained->cancelRequested_.load() || retained->revoked_) {
        retained->RevokeLocked(OwnedHelperContainer::Cause::AssignUnconfirmed); return {};
    }
    std::shared_ptr<OwnedSuspendedProcess> member;
    try { member = OwnedSuspendedProcess::CreateSuspendedOwn(image, std::move(command), environment, cwd); }
    catch (...) { retained->RevokeLocked(OwnedHelperContainer::Cause::AssignUnconfirmed); throw; }
    // Slot fuerte antes de Assign; incluso resultado tardío/fallido queda retenido.
    slot->owner = member;
    std::lock_guard<std::recursive_mutex> memberLock(member->mutex_);
    AcquisitionPin memberPin(member->acquiring_);
    DWORD alive = 0;
    bool valid = !retained->revoked_ && !retained->cancelRequested_.load() &&
        member->process_ && member->thread_ && !member->revoked_ && !member->cancelRequested_.load() &&
        member->state_ == OwnedSuspendedProcess::State::Suspended && !member->noJobObservers_ &&
        CurrentMemberOwn(member, retained->job_, false, alive) && alive == 1 &&
        !retained->revoked_ && !member->revoked_ &&
        !retained->cancelRequested_.load() && !member->cancelRequested_.load() && !member->noJobObservers_;
    if (valid) {
        const BOOL assigned = AssignProcessToJobObject(retained->job_, member->process_);
        slot->assigned = assigned != FALSE;
        valid = assigned && !retained->revoked_ && !retained->cancelRequested_.load() &&
            !member->revoked_ && !member->cancelRequested_.load() && !member->noJobObservers_ &&
            CurrentMemberOwn(member, retained->job_, true, alive) && alive == 1 &&
            !retained->revoked_ && !retained->cancelRequested_.load() &&
            retained->ReadLimitsOwn() && retained->ConfirmMembersOwn() &&
            !retained->revoked_ && !retained->cancelRequested_.load() &&
            !member->revoked_ && !member->cancelRequested_.load() && !member->noJobObservers_;
    }
    if (!valid) {
        retained->RevokeLocked(OwnedHelperContainer::Cause::AssignUnconfirmed);
        member->CancelOwn();
    }
    // La referencia devuelta no concede permiso de ejecutar una imagen ni Start/SSH.
    return member;
}
}
