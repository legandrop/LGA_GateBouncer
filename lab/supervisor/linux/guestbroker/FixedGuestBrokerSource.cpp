#include "FixedGuestBrokerSource.hpp"
namespace gb {
std::recursive_mutex FixedGuestBrokerSource::mutex_;
std::shared_ptr<GuestNoJobObserver> FixedGuestBrokerSource::pending_;
bool FixedGuestBrokerSource::observing_ = false;
FixedGuestBrokerSource::Snapshot FixedGuestBrokerSource::InspectFixedOwn() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (observing_)
        return {Block::ObservationInProgress,
            {GuestNoJobObserver::State::Observing, GuestNoJobObserver::Cause::None, true}};
    if (pending_) {
        const auto closure = pending_->CloseOwn();
        if (closure.state != GuestNoJobObserver::State::Closed)
            return {Block::CreatorCleanupPending, closure};
        pending_.reset();
    }
    struct ObservingScope {
        bool& value;
        explicit ObservingScope(bool& active) : value(active) { value = true; }
        ~ObservingScope() { value = false; }
    } observing(observing_);
    auto observer = GuestNoJobObserver::ObserveCreatorOwn();
    pending_ = observer;
    const auto observation = observer->InspectOwn();
    const auto closure = observer->CloseOwn();
    if (closure.state != GuestNoJobObserver::State::Closed)
        return {Block::CreatorCleanupPending, observation};
    pending_.reset();
    if (observation.state != GuestNoJobObserver::State::Observed || observation.revoked)
        return {Block::CreatorObservationRejected, observation};
    // No hay owner VM, enrollment ni imagen retenida: ni Create ni Resume son admisibles.
    return {Block::VmOwnerEnrollmentImagePinMissing, observation};
}
std::shared_ptr<GuestNoJobObserver> FixedGuestBrokerSource::ObserveCreatedChildOwn(
    const std::shared_ptr<OwnedSuspendedProcess>& child) {
    return GuestNoJobObserver::ObserveChildOwn(child);
}
}
