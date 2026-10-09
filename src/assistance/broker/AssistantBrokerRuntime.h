#pragma once
#include "BrokerPipe.h"
#include "BrokerVault.h"
#include "../WinHttpExplanationTransport.h"
#include <QTimer>
#include <map>

namespace Gate::Assistance::Broker {
class PrivateRuntimeTest;
class AssistantBrokerRuntime final : public QObject {
public:
    explicit AssistantBrokerRuntime(std::unique_ptr<PipeSession> session,QObject *parent=nullptr);
    ~AssistantBrokerRuntime() override;
    void start();
private:
    friend class PrivateRuntimeTest;
    void receive(Frame);
    void reply(Frame);
    void fail(const Frame &,Failure);
    void invalidate();
    void dispatch();
    void schedule();
    struct Identity {Id correlation;RequestBinding binding;quint64 sessionEpoch;};
    using IdentityPtr=std::shared_ptr<const Identity>;
    bool matches(const IdentityPtr &) const;
    WinHttpExplanationTransport::Observer observerFor(const IdentityPtr &);
    void complete(const IdentityPtr &,TransportReply);
    std::unique_ptr<PipeSession> session_;
    std::unique_ptr<BrokerVault> vault_;
    std::unique_ptr<IExplanationTransport> transport_;
    std::unique_ptr<Operation> operation_;
    quint64 consentEpoch_=1,credentialEpoch_=1,sessionEpoch_=1;
    bool consent_=false,automatic_=true,syntheticLab_=false,greeted_=false;
    Id capability_{};quint8 capabilityVerb_=0;ULONGLONG capabilityExpiry_=0;
    std::optional<Frame> active_;
    IdentityPtr activeIdentity_;
    std::deque<Frame> queued_;
    std::deque<ULONGLONG> failures_;
    QTimer dispatchTimer_;
    ULONGLONG nextDispatch_=0,blockedUntil_=0;
    HttpObservation observation_;
    std::map<Id,bool> correlations_;
};
}
