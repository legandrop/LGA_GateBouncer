#pragma once
#include "ExplanationContracts.h"
#include "broker/BrokerWire.h"
#include "websearch/WebSearch.h"
#include <QObject>
#include <cstdint>

namespace Gate::Assistance::GroundedBridge { class GroundedModelTransport; }
namespace Gate::Assistance::General { class GeneralModelTransport; class SealedGeneralPayload; struct FullBinding; }
namespace Gate::Assistance::Configuration { class NetworkPermit; enum class PermitCause : std::uint8_t; }
namespace Gate::Assistance::Broker { class BrokerVault; class AssistantBrokerRuntime; }
namespace Gate::Assistance {
class PrivateHttpTest;
struct HttpObservation {
    int observedStatus = 0;
    bool sendStarted = false;
    unsigned long secureFailure = 0;
    unsigned int retryAfterSeconds = 0;
    Broker::Failure failure = Broker::Failure::None;
    std::optional<Configuration::PermitCause> permitCause;
    bool reservationCommitted = false;
    Broker::Failure reservationFailure = Broker::Failure::None;
    unsigned long reservationPrimaryError = 0;
    gatebouncer::websearch::HttpDiagnostic diagnostic;
};
class WinHttpExplanationTransport final : public QObject, public IExplanationTransport {
public:
    using Observer = std::function<void(HttpObservation)>;
    explicit WinHttpExplanationTransport(QObject *parent = nullptr);
    ~WinHttpExplanationTransport() override;
    std::unique_ptr<Operation> start(const RequestBinding &, const QByteArray &, Completion) override;
private:
    friend class Broker::AssistantBrokerRuntime;
    friend class PrivateHttpTest;
    friend class GroundedBridge::GroundedModelTransport;
    friend class General::GeneralModelTransport;
    enum class ResponseContract { Legacy1, Grounded2, General3 };
    std::unique_ptr<Operation> startGeneral(const General::FullBinding &,const General::SealedGeneralPayload &,Completion,Observer,std::shared_ptr<const void> jobToken,Configuration::NetworkPermit);
    std::optional<HttpObservation> snapshotGeneralObservation(const General::FullBinding &,const std::shared_ptr<const void> &jobToken) const;
    std::unique_ptr<Operation> startGrounded(const RequestBinding &,const QByteArray &,Completion,Observer,std::shared_ptr<const void> jobToken);
    std::optional<HttpObservation> snapshotGroundedObservation(const RequestBinding &,const std::shared_ptr<const void> &jobToken) const;
    std::unique_ptr<Operation> startImpl(const RequestBinding &,const QByteArray &,Completion,Observer,ResponseContract,std::shared_ptr<const void> jobToken={});
    struct State;
    explicit WinHttpExplanationTransport(Broker::BrokerVault &, Observer, QObject *parent);
    Broker::BrokerVault *vault_ = nullptr;
    Observer observer_;
    std::weak_ptr<State> active_;
    std::weak_ptr<const void> admittedGeneralJob_;
};
}
