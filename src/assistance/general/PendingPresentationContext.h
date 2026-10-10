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
// Selección de lectura, nunca autoridad. El servicio recoteja el owner original.
struct PendingQuerySelection {
    Id128 request{}, owner{};
    std::uint64_t revision=0;
};
struct PrincipalObservationContext {
    Id128 owner{};
    std::vector<std::uint8_t> accountSid;
    std::array<std::uint8_t,32> targetDigest{};
    bool operator==(const PrincipalObservationContext& other) const {
        unsigned changed=0;
        for(std::size_t i=0;i<targetDigest.size();++i)changed|=targetDigest[i]^other.targetDigest[i];
        return owner==other.owner&&accountSid==other.accountSid&&!changed;
    }
    bool operator!=(const PrincipalObservationContext& other) const {return !(*this==other);}
};
std::optional<PrincipalObservationContext> principalObservationContext(const Id128&,
    const std::vector<std::uint8_t>& sid,const std::vector<std::uint8_t>& originalTarget);
enum class LocalSignatureStatus : std::uint8_t { VerifiedOffline,Unsigned,Invalid,Unavailable,TimedOut,Cancelled };
// Presentación LOCAL del snapshot retenido. No contiene ruta, hash ni capacidad.
struct LocalFilePresentation {
    std::uint64_t size=0,modifiedAtMs=0,checkedAtMs=0;
    LocalSignatureStatus signature=LocalSignatureStatus::Unavailable;
    std::string publisher;
};
bool validLocalFilePresentation(const LocalFilePresentation&);
// Observación sin capacidad de restaurar el owner ni permisos.
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
    const std::optional<LocalFilePresentation>& localFile() const {return localFile_;}
    std::uint16_t presentationVersion() const {return version_;}
    const std::optional<PrincipalObservationContext>& principal() const {return principal_;}
private:
    friend class GeneralBrokerHost;
    friend std::optional<PendingPresentationContext> pendingPresentationContext(const QByteArray&);
    PendingPresentationContext(PendingServiceContext service,Id128 request,Id128 selector,
        std::uint64_t requestRevision,std::uint64_t selectorRevision,std::uint64_t profileGeneration,
        Id128 token,std::uint64_t generation,std::optional<Destination> destination={},
        std::optional<LocalFilePresentation> localFile={},std::uint16_t version=3,
        std::optional<PrincipalObservationContext> principal={}):service_(service),request_(request),selector_(selector),
        snapshotToken_(token),requestRevision_(requestRevision),selectorRevision_(selectorRevision),
        profileGeneration_(profileGeneration),snapshotGeneration_(generation),destination_(std::move(destination)),localFile_(std::move(localFile)),version_(version),principal_(std::move(principal)){}
    PendingServiceContext service_;
    Id128 request_,selector_,snapshotToken_;
    std::uint64_t requestRevision_,selectorRevision_,profileGeneration_,snapshotGeneration_;
    std::optional<Destination> destination_;
    std::optional<LocalFilePresentation> localFile_;
    std::uint16_t version_=3;
    std::optional<PrincipalObservationContext> principal_;
};
std::optional<Id128> pendingQuery(const QByteArray&);
std::optional<QByteArray> pendingQueryBytes(const Id128&);
std::optional<PendingQuerySelection> pendingQuerySelection(const QByteArray&);
std::optional<QByteArray> pendingQueryBytes(const PendingQuerySelection&);
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
