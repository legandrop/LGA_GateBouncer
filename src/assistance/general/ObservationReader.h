#pragma once
#include "PendingPresentationContext.h"
#include "client_ii_win.h"
#include "wire_iv.h"

namespace Gate::Assistance::General {
// Lectura de presentación del productor vigente; no contiene autoridad del motor.
struct ObservationRead {
    PendingServiceContext service;
    Id128 connection{};
    std::shared_ptr<const gb::ipc::ii::ReadPeerLease> peer;
    gb::wire::iv::ObservedRecord record;
    std::uint64_t profile=0,desired=0;
};
class PrivateObservationReaderTest;
class ObservationReader final {
public:
    static std::optional<ObservationRead> read(gb::ipc::ii::Client&,const Id128&,
        const ObservationRead* expected=nullptr);
    static bool sameRecord(const gb::wire::iv::ObservedRecord&,
        const gb::wire::iv::ObservedRecord&,bool projected=false);
private:
    friend class PrivateObservationReaderTest;
    static std::optional<ObservationRead> observe(gb::ipc::ii::SessionChannel&,
        const Id128&,const Id128&,std::function<bool()>,std::function<std::int64_t()>,
        const ObservationRead*);
};
}
