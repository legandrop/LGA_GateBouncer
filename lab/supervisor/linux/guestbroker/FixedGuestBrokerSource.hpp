#pragma once
#include "GuestNoJobObserver.hpp"
namespace gb {
class GuestBrokerBoundary;
class BrokerAdmission;
class FixedGuestBrokerSource final {
public:
    enum class Block { VmOwnerEnrollmentImagePinMissing, CreatorObservationRejected,
        CreatorCleanupPending, ObservationInProgress };
    struct Snapshot { Block block; GuestNoJobObserver::Snapshot observation; };
    static Snapshot InspectFixedOwn();
private:
    friend class GuestBrokerBoundary;
    static std::shared_ptr<GuestNoJobObserver> ObserveOwnNative();
    static bool StartHelperOwn(const std::shared_ptr<BrokerAdmission>&,
        std::shared_ptr<OwnedSuspendedProcess>&, std::shared_ptr<GuestNoJobObserver>&);
    static bool ExactHelperOwn(const std::shared_ptr<OwnedSuspendedProcess>&,
        HANDLE, DWORD, std::uint64_t);
    static std::recursive_mutex mutex_;
    static std::shared_ptr<GuestNoJobObserver> pending_;
    static bool observing_;
    // La futura creacion fija debe entregar su hoja propia, nunca PID/DTO del SCM.
    static std::shared_ptr<GuestNoJobObserver> ObserveCreatedChildOwn(
        const std::shared_ptr<OwnedSuspendedProcess>&);
};
}
