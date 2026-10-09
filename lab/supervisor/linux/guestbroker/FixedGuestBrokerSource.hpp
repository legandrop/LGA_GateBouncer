#pragma once
#include "GuestNoJobObserver.hpp"
namespace gb {
class FixedGuestBrokerSource final {
public:
    enum class Block { VmOwnerEnrollmentImagePinMissing, CreatorObservationRejected,
        CreatorCleanupPending, ObservationInProgress };
    struct Snapshot { Block block; GuestNoJobObserver::Snapshot observation; };
    static Snapshot InspectFixedOwn();
private:
    static std::recursive_mutex mutex_;
    static std::shared_ptr<GuestNoJobObserver> pending_;
    static bool observing_;
    // La futura creacion fija debe entregar su hoja propia, nunca PID/DTO del SCM.
    static std::shared_ptr<GuestNoJobObserver> ObserveCreatedChildOwn(
        const std::shared_ptr<OwnedSuspendedProcess>&);
};
}
