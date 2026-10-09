#include "GuestNoJobObserver.hpp"
#include "../helper/OwnedSuspendedProcess.hpp"
#include <limits>
#include <stdexcept>
namespace gb {
std::mutex GuestNoJobObserver::registryMutex_;
std::map<GuestNoJobObserver*, std::shared_ptr<GuestNoJobObserver>> GuestNoJobObserver::retained_;
namespace {
class ObservationPin final {
public:
    explicit ObservationPin(bool& active) : active_(active), previous_(active) { active_ = true; }
    ~ObservationPin() { active_ = previous_; }
    ObservationPin(const ObservationPin&) = delete;
    ObservationPin& operator=(const ObservationPin&) = delete;
private:
    bool& active_;
    bool previous_;
};
std::uint64_t Creation(const FILETIME& time) {
    return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}
}
void GuestNoJobObserver::RevokeLocked(Cause cause) {
    revoked_ = true; cause_ = cause;
    if (state_ != State::Closed) state_ = State::ClosePending;
}
void GuestNoJobObserver::ReleaseClosed(const std::shared_ptr<GuestNoJobObserver>& owner) {
    std::shared_ptr<GuestNoJobObserver> release;
    { std::lock_guard<std::mutex> lock(registryMutex_);
      auto found = retained_.find(owner.get());
      if (found != retained_.end()) { release = std::move(found->second); retained_.erase(found); } }
    release.reset();
}
std::shared_ptr<GuestNoJobObserver> GuestNoJobObserver::ObserveCreatorOwn() {
    auto owner = std::shared_ptr<GuestNoJobObserver>(new GuestNoJobObserver);
    { std::lock_guard<std::mutex> registry(registryMutex_); retained_.emplace(owner.get(), owner); }
    {
        std::lock_guard<std::recursive_mutex> lock(owner->mutex_);
        owner->acquiring_ = true;
        try {
        owner->thread_ = GetCurrentThreadId();
        HANDLE process = nullptr;
        const BOOL duplicated = owner->CheckActualOwn() && DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
            GetCurrentProcess(), &process, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, 0);
        // Se captura incluso el retorno parcial antes de la primera consulta.
        owner->creator_ = process;
        FILETIME creation{}, exit{}, kernel{}, user{};
        if (!duplicated || !process) {
            if (!owner->revoked_) owner->RevokeLocked(Cause::DuplicateUnconfirmed);
        }
        else if (owner->CheckActualOwn()) {
            owner->pid_ = GetProcessId(process);
            if (owner->CheckActualOwn()) {
                const DWORD current = GetCurrentProcessId();
                if (owner->CheckActualOwn() && owner->pid_ && owner->pid_ == current) {
                    const BOOL times = GetProcessTimes(process, &creation, &exit, &kernel, &user);
                    if (owner->CheckActualOwn() && times && Creation(creation)) {
                        owner->creation_ = Creation(creation);
                        if (owner->ReadActualOwn()) owner->state_ = State::Observed;
                    } else if (!owner->revoked_) owner->RevokeLocked(Cause::IdentityUnconfirmed);
                } else if (!owner->revoked_) owner->RevokeLocked(Cause::IdentityUnconfirmed);
            }
        }
        } catch (...) { owner->RevokeLocked(Cause::IdentityUnconfirmed); }
        owner->acquiring_ = false;
    }
    if (owner->InspectOwn().revoked) owner->CloseOwn();
    return owner;
}
std::shared_ptr<GuestNoJobObserver> GuestNoJobObserver::ObserveChildOwn(
    const std::shared_ptr<OwnedSuspendedProcess>& child) {
    auto owner = std::shared_ptr<GuestNoJobObserver>(new GuestNoJobObserver);
    { std::lock_guard<std::mutex> registry(registryMutex_); retained_.emplace(owner.get(), owner); }
    {
        std::lock_guard<std::recursive_mutex> lock(owner->mutex_);
        owner->acquiring_ = true;
        if (!child) owner->RevokeLocked(Cause::IdentityUnconfirmed);
        else {
            std::lock_guard<std::recursive_mutex> childLock(child->mutex_);
            if ((child->state_ != OwnedSuspendedProcess::State::Suspended &&
                child->state_ != OwnedSuspendedProcess::State::Running) || child->revoked_ ||
                child->cancelRequested_.load() || child->closing_ || child->acquiring_ ||
                !child->process_ || child->noJobObservers_ == std::numeric_limits<unsigned>::max())
                owner->RevokeLocked(Cause::IdentityUnconfirmed);
            else {
                owner->child_ = child; owner->childProcess_ = child->process_;
                // Reserva antes de cualquier SDK: CloseOwn reentrante no toca este HANDLE.
                ++child->noJobObservers_; owner->childUse_ = true;
                try {
                    owner->thread_ = GetCurrentThreadId();
                    owner->pid_ = child->pid_; owner->creation_ = child->creation_;
                    if (owner->ReadActualOwn()) owner->state_ = State::Observed;
                } catch (...) { owner->RevokeLocked(Cause::IdentityUnconfirmed); }
            }
        }
        owner->acquiring_ = false;
    }
    if (owner->InspectOwn().revoked) owner->CloseOwn();
    return owner;
}
bool GuestNoJobObserver::CheckActualOwn() {
    if (cancelRequested_.load() || revoked_) { RevokeLocked(Cause::Cancelled); return false; }
    if (!thread_ || thread_ != GetCurrentThreadId()) { RevokeLocked(Cause::WrongThread); return false; }
    if (cancelRequested_.load() || revoked_ ||
        (child_ && (!childUse_ || !childProcess_ || child_->process_ != childProcess_ ||
        (child_->state_ != OwnedSuspendedProcess::State::Suspended &&
        child_->state_ != OwnedSuspendedProcess::State::Running) || child_->acquiring_ || child_->closing_ ||
        child_->revoked_ || child_->cancelRequested_.load()))) {
        RevokeLocked(Cause::Cancelled); return false;
    }
    return true;
}
bool GuestNoJobObserver::ReadActualOwn() {
    if (!CheckActualOwn()) return false;
    const HANDLE process = child_ ? childProcess_ : creator_;
    if (!process || !pid_ || !creation_) { RevokeLocked(Cause::IdentityUnconfirmed); return false; }
    FILETIME creation{}, exit{}, kernel{}, user{};
    auto identity = [&] {
        if (!CheckActualOwn()) return false;
        const DWORD pid = GetProcessId(process);
        if (!CheckActualOwn()) return false;
        if (pid != pid_) { RevokeLocked(Cause::IdentityUnconfirmed); return false; }
        if (!child_) {
            if (!CheckActualOwn()) return false;
            const DWORD current = GetCurrentProcessId();
            if (!CheckActualOwn()) return false;
            if (current != pid_) { RevokeLocked(Cause::IdentityUnconfirmed); return false; }
        }
        if (!CheckActualOwn()) return false;
        const BOOL times = GetProcessTimes(process, &creation, &exit, &kernel, &user);
        if (!CheckActualOwn()) return false;
        if (!times || Creation(creation) != creation_) { RevokeLocked(Cause::IdentityUnconfirmed); return false; }
        if (!CheckActualOwn()) return false;
        const DWORD wait = WaitForSingleObject(process, 0);
        if (!CheckActualOwn()) return false;
        if (wait != WAIT_TIMEOUT) { RevokeLocked(Cause::IdentityUnconfirmed); return false; }
        return true;
    };
    if (!identity() || !CheckActualOwn()) return false;
    BOOL inJob = TRUE;
    const BOOL queried = IsProcessInJob(process, nullptr, &inJob);
    if (!CheckActualOwn()) return false;
    if (!queried) { RevokeLocked(Cause::JobQueryFailed); return false; }
    if (inJob) { RevokeLocked(Cause::AlreadyInJob); return false; }
    // NoJob es puntual; no bloquea un Assign futuro ni concede Resume.
    return identity() && CheckActualOwn();
}
GuestNoJobObserver::Snapshot GuestNoJobObserver::InspectOwn() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (acquiring_ || closing_) {
        auto view = ViewLocked();
        // La reentrada no consulta SDK ni publica el positivo de un frame exterior.
        if (view.state == State::Observed) view.state = State::Observing;
        return view;
    }
    std::unique_lock<std::recursive_mutex> childLock;
    if (child_) childLock = std::unique_lock<std::recursive_mutex>(child_->mutex_);
    if (state_ == State::Observed) {
        // Veto tambien durante SDK reentrante de una inspeccion sin Guard exterior.
        ObservationPin pin(acquiring_);
        try { ReadActualOwn(); } catch (...) { RevokeLocked(Cause::IdentityUnconfirmed); }
    }
    return ViewLocked();
}
GuestNoJobObserver::Snapshot GuestNoJobObserver::CancelOwn() {
    cancelRequested_.store(true);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (state_ != State::Closed) RevokeLocked(Cause::Cancelled);
    return ViewLocked();
}
GuestNoJobObserver::Guard::Guard(std::shared_ptr<GuestNoJobObserver> owner)
    : owner_(std::move(owner)), lock_(owner_->mutex_) {
    if (owner_->child_) childLock_ = std::unique_lock<std::recursive_mutex>(owner_->child_->mutex_);
    if (owner_->state_ != State::Observed || owner_->acquiring_ || owner_->closing_ ||
        owner_->guards_ == std::numeric_limits<unsigned>::max())
        throw std::runtime_error("GuardNoJobNoDisponible");
    ++owner_->guards_;
    try {
        if (!owner_->ReadActualOwn()) throw std::runtime_error("ObservacionNoJobPerdida");
    } catch (...) {
        --owner_->guards_;
        if (!owner_->revoked_) owner_->RevokeLocked(Cause::IdentityUnconfirmed);
        throw;
    }
}
GuestNoJobObserver::Guard::~Guard() { --owner_->guards_; }
GuestNoJobObserver::Guard GuestNoJobObserver::GuardOwn() { return Guard(shared_from_this()); }
GuestNoJobObserver::Snapshot GuestNoJobObserver::CloseOwn() {
    const auto live = shared_from_this(); Snapshot result{};
    cancelRequested_.store(true);
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (state_ != State::Closed) {
            RevokeLocked(cause_ == Cause::None ? Cause::Cancelled : cause_);
            if (acquiring_ || closing_ || guards_) return ViewLocked();
            closing_ = true;
            if (creator_) {
                if (CloseHandle(creator_)) creator_ = nullptr;
                else cause_ = Cause::CloseUnconfirmed;
            }
            if (child_) {
                const auto retainedChild = child_;
                std::lock_guard<std::recursive_mutex> childLock(retainedChild->mutex_);
                if (childUse_) { --retainedChild->noJobObservers_; childUse_ = false; }
                child_.reset();
                childProcess_ = nullptr;
            }
            if (!creator_ && !child_) state_ = State::Closed;
            closing_ = false;
        }
        result = ViewLocked();
    }
    if (result.state == State::Closed) ReleaseClosed(live);
    return result;
}
}
