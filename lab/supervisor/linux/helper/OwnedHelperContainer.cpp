#include "OwnedHelperContainer.hpp"
#include "OwnedHelperLaunchAdapter.hpp"
#include <limits>
#include <stdexcept>
namespace gb {
std::mutex OwnedHelperContainer::registryMutex_;
std::map<OwnedHelperContainer*, std::shared_ptr<OwnedHelperContainer>> OwnedHelperContainer::retained_;
namespace {
constexpr DWORD outerFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_JOB_MEMORY;
constexpr SIZE_T outerMemory = 536870912;
static_assert(outerFlags == 0x2208, "Unexpected outer job profile");
}
OwnedHelperContainer::Snapshot OwnedHelperContainer::ViewLocked() const {
    return {state_, cause_, generation_, revoked_, accountingObserved_, activeProcesses_};
}
void OwnedHelperContainer::RevokeLocked(Cause cause) {
    if (!revoked_) {
        revoked_ = true;
        if (generation_ != std::numeric_limits<std::uint64_t>::max()) ++generation_;
        else cause = Cause::GenerationExhausted;
    }
    cause_ = cause;
    if (state_ != State::Closed) state_ = State::ClosePending;
}
void OwnedHelperContainer::ReleaseClosed(const std::shared_ptr<OwnedHelperContainer>& owner) {
    std::shared_ptr<OwnedHelperContainer> release;
    {
        std::lock_guard<std::mutex> registryLock(registryMutex_);
        auto found = retained_.find(owner.get());
        if (found != retained_.end()) {
            release = std::move(found->second);
            retained_.erase(found);
        }
    }
    release.reset();
}
std::shared_ptr<OwnedHelperContainer> OwnedHelperContainer::CreateOwn() {
    auto owner = std::shared_ptr<OwnedHelperContainer>(new OwnedHelperContainer);
    {
        // Registro fuerte previo al primer HANDLE; fallo de reserva no adquiere SDK.
        std::lock_guard<std::mutex> registryLock(registryMutex_);
        retained_.emplace(owner.get(), owner);
    }
    bool cleanup = false;
    {
        std::lock_guard<std::recursive_mutex> lock(owner->mutex_);
        owner->acquiring_ = true;
        owner->job_ = CreateJobObjectW(nullptr, nullptr);
        if (!owner->job_) {
            owner->RevokeLocked(Cause::CreateFailed);
            cleanup = true;
        } else if (owner->cancelRequested_.load() || owner->revoked_) {
            owner->RevokeLocked(Cause::Cancelled);
            cleanup = true;
        } else {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
            limits.BasicLimitInformation.LimitFlags = outerFlags;
            limits.BasicLimitInformation.ActiveProcessLimit = 2;
            limits.JobMemoryLimit = outerMemory;
            JOBOBJECT_BASIC_UI_RESTRICTIONS ui{0};
            if (!SetInformationJobObject(owner->job_, JobObjectExtendedLimitInformation,
                    &limits, sizeof(limits)) || owner->cancelRequested_.load() || owner->revoked_ ||
                !SetInformationJobObject(owner->job_, JobObjectBasicUIRestrictions, &ui, sizeof(ui)) ||
                owner->cancelRequested_.load() || owner->revoked_ || !owner->ReadLimitsOwn()) {
                owner->RevokeLocked(Cause::LimitsUnconfirmed);
                cleanup = true;
            } else if (!owner->ConfirmMembersOwn() || owner->cancelRequested_.load() || owner->revoked_) {
                if (!owner->revoked_) owner->RevokeLocked(Cause::Cancelled);
                cleanup = true;
            } else owner->state_ = State::ContainerOwned;
        }
        owner->acquiring_ = false;
    }
    if (cleanup) owner->CloseOwn();
    return owner;
}
bool OwnedHelperContainer::ReadLimitsOwn() const {
    if (!job_) return false;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
    if (!QueryInformationJobObject(job_, JobObjectExtendedLimitInformation,
            &limits, sizeof(limits), nullptr) ||
        cancelRequested_.load() || revoked_ ||
        !QueryInformationJobObject(job_, JobObjectBasicUIRestrictions, &ui, sizeof(ui), nullptr) ||
        cancelRequested_.load() || revoked_) return false;
    return limits.BasicLimitInformation.LimitFlags == outerFlags &&
        limits.BasicLimitInformation.ActiveProcessLimit == 2 &&
        limits.JobMemoryLimit == outerMemory && ui.UIRestrictionsClass == 0;
}
bool OwnedHelperContainer::ReadAccountingOwn() {
    accountingObserved_ = false;
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
    if (!job_ || !QueryInformationJobObject(job_, JobObjectBasicAccountingInformation,
            &accounting, sizeof(accounting), nullptr)) return false;
    activeProcesses_ = accounting.ActiveProcesses;
    accountingObserved_ = true;
    return true;
}
bool OwnedHelperContainer::ConfirmMembersOwn() {
    DWORD expected = 0;
    for (const auto& member : members_) {
        DWORD alive = 0;
        if (member.owner && !OwnedHelperLaunchAdapter::CurrentMemberOwn(member.owner, job_, member.assigned, alive)) {
            RevokeLocked(Cause::MemberUnknown); return false;
        }
        expected += member.assigned ? alive : 0;
    }
    if (!ReadAccountingOwn()) { RevokeLocked(Cause::AccountingUnconfirmed); return false; }
    if (activeProcesses_ > 2) { RevokeLocked(Cause::MemberBudgetExceeded); return false; }
    // Conteo exacto de referencias y HANDLEs observados; nunca <=2 como autoridad.
    if (activeProcesses_ != expected) { RevokeLocked(Cause::MemberUnknown); return false; }
    return true;
}
OwnedHelperContainer::Snapshot OwnedHelperContainer::InspectOwn() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (state_ == State::ContainerOwned) {
        ++guards_;
        if (cancelRequested_.load()) RevokeLocked(Cause::Cancelled);
        else if (!ReadLimitsOwn()) RevokeLocked(Cause::LimitsUnconfirmed);
        else ConfirmMembersOwn();
        if (cancelRequested_.load() && !revoked_) RevokeLocked(Cause::Cancelled);
        --guards_;
    }
    return ViewLocked();
}
OwnedHelperContainer::Guard::Guard(std::shared_ptr<OwnedHelperContainer> owner, std::uint64_t generation)
    : owner_(std::move(owner)), lock_(owner_->mutex_) {
    if (owner_->revoked_ || owner_->cancelRequested_.load() ||
        owner_->state_ != State::ContainerOwned || owner_->generation_ != generation)
        throw std::runtime_error("ContainerGuardRevoked");
    ++owner_->guards_;
    try {
    if (!owner_->ReadLimitsOwn()) {
        owner_->RevokeLocked(Cause::LimitsUnconfirmed);
        throw std::runtime_error("ContainerLimitsUnconfirmed");
    }
    if (!owner_->ConfirmMembersOwn() || owner_->revoked_ || owner_->cancelRequested_.load() ||
        owner_->state_ != State::ContainerOwned || owner_->generation_ != generation) {
        if (!owner_->revoked_) owner_->RevokeLocked(Cause::Cancelled);
        throw std::runtime_error("ContainerCurrentUnconfirmed");
    }
    } catch (...) { --owner_->guards_; throw; }
}
OwnedHelperContainer::Guard::~Guard() { --owner_->guards_; }
OwnedHelperContainer::Guard OwnedHelperContainer::GuardOwn(std::uint64_t generation) {
    return Guard(shared_from_this(), generation);
}
OwnedHelperContainer::Snapshot OwnedHelperContainer::CancelOwn() {
    // Petición visible aun si otro thread conserva el guard/mutex.
    cancelRequested_.store(true);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (state_ == State::Closed) return ViewLocked();
    RevokeLocked(Cause::Cancelled);
    if (!acquiring_ && !closing_ && !guards_ && job_) {
        closing_ = true;
        if (!TerminateJobObject(job_, ERROR_CANCELLED)) cause_ = Cause::TerminateUnconfirmed;
        closing_ = false;
    }
    return ViewLocked();
}
OwnedHelperContainer::Snapshot OwnedHelperContainer::CloseOwn() {
    const auto live = shared_from_this();
    cancelRequested_.store(true);
    Snapshot result{};
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (state_ != State::Closed) {
            RevokeLocked(cause_ == Cause::None ? Cause::Cancelled : cause_);
            if (acquiring_ || closing_ || guards_) return ViewLocked();
            closing_ = true;
            bool membersClosed = true;
            for (const auto& member : members_) {
                if (member.owner && !OwnedHelperLaunchAdapter::CloseMemberOwn(member.owner)) membersClosed = false;
            }
            if (!membersClosed) cause_ = Cause::MemberExitUnconfirmed;
            else if (job_ && !ReadAccountingOwn()) cause_ = Cause::AccountingUnconfirmed;
            else if (job_ && activeProcesses_ != 0)
                cause_ = activeProcesses_ > 2 ? Cause::MemberBudgetExceeded : Cause::MemberUnknown;
            else if (job_ && !CloseHandle(job_)) cause_ = Cause::CloseUnconfirmed;
            else { job_ = nullptr; state_ = State::Closed; }
            closing_ = false;
        }
        result = ViewLocked();
    }
    if (result.state == State::Closed) ReleaseClosed(live);
    return result;
}
}
