#pragma once
#include "retrieval/GroundedPayload.h"
#include "../WinHttpExplanationTransport.h"
#include "../broker/BrokerVault.h"
#include <deque>
namespace Gate::Assistance::GroundedBridge {
class GroundedBrokerRuntime;
class PrivateGroundedTest;
class FixedUltraPayloadBuilder final : public Retrieval::PayloadBuilder {
public:
    std::optional<QByteArray> build(Retrieval::Product,const std::vector<Retrieval::Source>&) const override;
    static bool validProfile(const QByteArray &);
};
struct JobIdentity final {
    Broker::Id correlation;
    Retrieval::Binding binding;
    Retrieval::Product product;
    quint64 sessionEpoch=0,serial=0;
};
using JobIdentityPtr=std::shared_ptr<const JobIdentity>;
class GroundedModelTransport final : public QObject, public IExplanationTransport {
public:
    std::unique_ptr<Operation> start(const RequestBinding &,const QByteArray &,Completion) override;
private:
    friend class GroundedBrokerRuntime;
    friend class PrivateGroundedTest;
    GroundedModelTransport(Broker::BrokerVault &,QObject *parent);
    void bindJob(JobIdentityPtr,WinHttpExplanationTransport::Observer);
    void clearJob(const JobIdentityPtr &);
    std::optional<HttpObservation> snapshotJob(const JobIdentityPtr &) const;
    void recordOutcome(const JobIdentityPtr &,const HttpObservation &);
    WinHttpExplanationTransport http_;
    JobIdentityPtr identity_;
    WinHttpExplanationTransport::Observer observer_;
    ULONGLONG blockedUntil_=0;
    std::deque<ULONGLONG> failures_;
    bool outcomeRecorded_=false;
};
}
