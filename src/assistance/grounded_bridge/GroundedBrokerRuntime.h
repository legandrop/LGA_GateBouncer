#pragma once
#include "FixedUltraProfile.h"
#include "../broker/BrokerPipe.h"
#include "retrieval/Coordinator.h"
#include "retrieval/ProviderAdapters.h"
namespace Gate::Assistance::GroundedBridge {
class GroundedBrokerRuntime final : public QObject {
public:
    static std::unique_ptr<GroundedBrokerRuntime> forCurrentUser(std::unique_ptr<Broker::PipeSession>,QObject *parent=nullptr);
    ~GroundedBrokerRuntime() override;
    void start();
private:
    friend class PrivateGroundedTest;
    explicit GroundedBrokerRuntime(std::unique_ptr<Broker::PipeSession>,QObject *);
    bool matches(const JobIdentityPtr &) const;
    void receive(Broker::Frame);
    void reply(Broker::Frame);
    void fail(const Broker::Frame &,Broker::Failure);
    void invalidate();
    void dispatch();
    void complete(const JobIdentityPtr &,Retrieval::Result);
    void progress(const JobIdentityPtr &,Retrieval::State);
    std::unique_ptr<Broker::PipeSession> session_;
    std::unique_ptr<Broker::BrokerVault> vault_;
    std::unique_ptr<Retrieval::GetTransport> get_;
    std::unique_ptr<IExplanationTransport> model_;
    std::unique_ptr<Retrieval::BudgetGuard> budget_;
    FixedUltraPayloadBuilder builder_;
    std::unique_ptr<Retrieval::Coordinator> coordinator_;
    JobIdentityPtr active_;
    std::deque<Broker::Frame> queue_;
    std::map<Broker::Id,bool> correlations_;
    std::optional<HttpObservation> observation_;
    Broker::Id capability_{};
    quint8 capabilityVerb_=0;
    ULONGLONG capabilityExpiry_=0;
    quint64 consentEpoch_=1,credentialEpoch_=1,sessionEpoch_=1,retrievalEpoch_=1,serial_=0;
    bool nvidiaConsent_=false,webConsent_=false,automatic_=true,greeted_=false,testing_=false;
};
}
