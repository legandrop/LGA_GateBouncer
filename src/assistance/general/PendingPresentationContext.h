#pragma once
#include "GeneralContracts.h"
#include <QByteArray>
namespace Gate::Assistance::General {
class GeneralBrokerHost;
class GeneralFactory;
class PresentationContext;
struct ConfigurationView;
struct PendingServiceContext {
    Id128 serviceEpoch{},boot{},engineContext{};
    std::uint64_t engineBindingGeneration=0;
    bool operator==(const PendingServiceContext& other) const;
};
bool validPendingService(const PendingServiceContext&);
// Observación sin capacidad de restaurar el owner, hechos locales ni permisos.
class PendingPresentationContext final {
public:
    const PendingServiceContext& service() const {return service_;}
    const Id128& request() const {return request_;}
    // En observaciones IV, este slot es captureBinding readonly, nunca selector del writer.
    const Id128& selector() const {return selector_;}
    std::uint64_t requestRevision() const {return requestRevision_;}
    std::uint64_t selectorRevision() const {return selectorRevision_;}
    std::uint64_t profileGeneration() const {return profileGeneration_;}
    const Id128& snapshotToken() const {return snapshotToken_;}
    std::uint64_t snapshotGeneration() const {return snapshotGeneration_;}
    const std::optional<Destination>& destination() const {return destination_;}
private:
    friend class GeneralBrokerHost;
    friend std::optional<PendingPresentationContext> pendingPresentationContext(const QByteArray&);
    PendingPresentationContext(PendingServiceContext service,Id128 request,Id128 selector,
        std::uint64_t requestRevision,std::uint64_t selectorRevision,std::uint64_t profileGeneration,
        Id128 token,std::uint64_t generation,std::optional<Destination> destination={}):service_(service),request_(request),selector_(selector),
        snapshotToken_(token),requestRevision_(requestRevision),selectorRevision_(selectorRevision),
        profileGeneration_(profileGeneration),snapshotGeneration_(generation),destination_(std::move(destination)){}
    PendingServiceContext service_;
    Id128 request_,selector_,snapshotToken_;
    std::uint64_t requestRevision_,selectorRevision_,profileGeneration_,snapshotGeneration_;
    std::optional<Destination> destination_;
};
std::optional<Id128> pendingQuery(const QByteArray&);
std::optional<QByteArray> pendingQueryBytes(const Id128&);
std::optional<PendingPresentationContext> pendingPresentationContext(const QByteArray&);
std::optional<QByteArray> pendingPresentationBytes(const PendingPresentationContext&);
// Construye una observación para el consumidor; el dueño canónico todavía debe validar Current.
std::optional<FullBinding> pendingFullBinding(const PendingPresentationContext&,
    const PresentationContext&,const ConfigurationView&,const Id128& connection);
class OwnedPendingPresentation final {
private:
    friend class GeneralBrokerHost;
    friend class GeneralFactory;
    OwnedPendingPresentation(PendingPresentationContext view,Id128 connection,
        std::shared_ptr<const void> lifetime,std::function<bool()> current):view_(std::move(view)),
        connection_(connection),lifetime_(std::move(lifetime)),current_(std::move(current)){}
    const PendingPresentationContext view_;
    const Id128 connection_;
    const std::shared_ptr<const void> lifetime_;
    const std::function<bool()> current_;
};
}
