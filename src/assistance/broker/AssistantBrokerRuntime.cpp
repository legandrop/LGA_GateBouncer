#include "AssistantBrokerRuntime.h"
#include <QCoreApplication>
#include <QPointer>
#include <cstring>

namespace Gate::Assistance::Broker {
AssistantBrokerRuntime::AssistantBrokerRuntime(std::unique_ptr<PipeSession> session,QObject *parent):QObject(parent),session_(std::move(session)) {
    dispatchTimer_.setSingleShot(true);QObject::connect(&dispatchTimer_,&QTimer::timeout,this,[this]{dispatch();});
    // Factory cerrada: no toca el perfil real ni siquiera para obtener Status.
    vault_=BrokerVault::forCurrentUser();
    if(vault_)transport_=std::unique_ptr<WinHttpExplanationTransport>(new WinHttpExplanationTransport(*vault_,{},this));
}
AssistantBrokerRuntime::~AssistantBrokerRuntime(){invalidate();if(session_)session_->stop();}
void AssistantBrokerRuntime::start(){session_->start([this](Frame f){receive(std::move(f));},[this]{invalidate();QCoreApplication::quit();});}
void AssistantBrokerRuntime::invalidate(){activeIdentity_.reset();observation_={};consent_=false;++consentEpoch_;++sessionEpoch_;capability_={};capabilityVerb_=0;queued_.clear();dispatchTimer_.stop();active_.reset();if(operation_)operation_->cancel();operation_.reset();}
void AssistantBrokerRuntime::reply(Frame frame){if(!session_->send(std::move(frame))){invalidate();session_->stop();}}
void AssistantBrokerRuntime::fail(const Frame &request,Failure why){Frame f;f.message=Message::ErrorReply;f.correlation=request.correlation;f.fields[23]=integer(quint16(why),2);reply(std::move(f));}
void AssistantBrokerRuntime::receive(Frame request) {
    if(!greeted_){
        if(request.message!=Message::StatusRequest||!request.fields.empty()){session_->stop();return;}
        greeted_=true;
    }
    if(correlations_.count(request.correlation)){session_->stop();return;}
    // Una conexion larga no produce un historial ilimitado de IDs.
    if(correlations_.size()>=4096){fail(request,Failure::Capacity);session_->stop();return;}correlations_[request.correlation]=true;
    switch(request.message) {
    case Message::StatusRequest: {
        if(request.fields.count(31)) {
            const bool desired=number(request.fields.at(31));
            if(desired && !syntheticLab_ && !ProductionActivation::approved()){fail(request,Failure::ConfigurationNotApproved);return;}
            if(!desired)invalidate();else if(!consent_){consent_=true;++consentEpoch_;}
            automatic_=number(request.fields.at(32));
        }
        Frame f;f.message=Message::StatusReply;f.correlation=request.correlation;
        const quint8 credential=vault_?vault_->status():0;
        const quint8 availability=!ProductionActivation::approved()&&!syntheticLab_?3:(!credential?1:(!consent_?2:4));
        f.fields={{1,integer(availability,1)},{2,integer(credential,1)},{3,integer(consentEpoch_,8)},{4,integer(credentialEpoch_,8)},{5,integer(sessionEpoch_,8)},{6,integer(automatic_,1)},{7,integer(syntheticLab_?15:1,2)}};
        if(request.fields.count(33)) {
            if(!syntheticLab_||!vault_){fail(request,Failure::ConfigurationNotApproved);return;}
            if(!randomId(capability_)){fail(request,Failure::VaultUnavailable);return;}
            capabilityVerb_=quint8(number(request.fields.at(33)));capabilityExpiry_=GetTickCount64()+5000;
            f.fields[34]=QByteArray(reinterpret_cast<const char *>(capability_.data()),16);
        }
        reply(std::move(f));break;
    }
    case Message::Configure: case Message::Forget: {
        Id received{};std::memcpy(received.data(),request.fields.at(34).data(),16);
        const quint8 verb=request.message==Message::Configure?1:2;
        if(!syntheticLab_||!vault_||!nonzero(capability_)||received!=capability_||verb!=capabilityVerb_||GetTickCount64()>capabilityExpiry_){fail(request,Failure::Unauthorized);return;}
        capability_={};capabilityVerb_=0;++credentialEpoch_;invalidate();
        const auto result=verb==1?vault_->configure(std::move(request.secret)):vault_->forget();
        Frame f;f.message=verb==1?Message::ConfigureAck:Message::ForgetAck;f.correlation=request.correlation;f.fields={{2,integer(result==Failure::None?vault_->status():2,1)},{4,integer(credentialEpoch_,8)},{23,integer(quint16(result),2)}};reply(std::move(f));break;
    }
    case Message::Explain: {
        if(!ProductionActivation::approved()&&!syntheticLab_){fail(request,Failure::ConfigurationNotApproved);return;}
        const auto b=binding(request);
        if(!b||!b->context.pending||!b->context.serviceAvailable||b->consentEpoch!=consentEpoch_||b->credentialEpoch!=credentialEpoch_||!consent_){fail(request,Failure::Stale);return;}
        if(!transport_||queued_.size()>=16){fail(request,!transport_?Failure::TransportUnavailable:Failure::Capacity);return;}
        queued_.push_back(std::move(request));schedule();break;
    }
    case Message::Cancel: {
        const auto &id=request.fields.at(25);bool found=active_&&id==QByteArray(reinterpret_cast<const char *>(active_->correlation.data()),16);
        if(found){activeIdentity_.reset();active_.reset();observation_={};if(operation_)operation_->cancel();operation_.reset();}
        for(auto i=queued_.begin();i!=queued_.end();++i)if(id==QByteArray(reinterpret_cast<const char *>(i->correlation.data()),16)){queued_.erase(i);found=true;break;}
        Frame f;f.message=Message::CancelAck;f.correlation=request.correlation;f.fields[21]=integer(quint8(found?Outcome::Cancelled:Outcome::NotFound),1);reply(std::move(f));schedule();break;
    }
    default:fail(request,Failure::Unsupported);break;
    }
}
void AssistantBrokerRuntime::schedule(){
    if(active_||queued_.empty()||!consent_)return;
    const auto now=GetTickCount64(),until=std::max(nextDispatch_,blockedUntil_);
    dispatchTimer_.start(until>now?int(std::min<ULONGLONG>(until-now,3600000)):0);
}
void AssistantBrokerRuntime::dispatch(){
    if(active_||queued_.empty()||!consent_)return;
    auto request=std::move(queued_.front());queued_.pop_front();const auto b=binding(request);
    if(!b||b->consentEpoch!=consentEpoch_||b->credentialEpoch!=credentialEpoch_||!b->context.pending||!b->context.serviceAvailable){fail(request,Failure::Stale);schedule();return;}
    const auto payload=buildSamplePayload(PublicAppFacts::sample(number(request.fields.at(20))==1?CatalogEntry::SampleEditor:CatalogEntry::SampleUnknown));
    if(!payload){fail(request,Failure::InvalidResponse);schedule();return;}
    active_=std::move(request);
    const auto identity=std::make_shared<const Identity>(Identity{active_->correlation,*b,sessionEpoch_});activeIdentity_=identity;
    observation_={};nextDispatch_=GetTickCount64()+10000;
    QPointer<AssistantBrokerRuntime> self(this);
    if(auto *http=dynamic_cast<WinHttpExplanationTransport *>(transport_.get()))http->observer_=observerFor(identity);
    operation_=transport_->start(identity->binding,*payload,[self,identity](TransportReply result){if(self)self->complete(identity,std::move(result));});
    if(!operation_&&matches(identity)){activeIdentity_.reset();fail(*active_,Failure::TransportUnavailable);active_.reset();schedule();}
}
bool AssistantBrokerRuntime::matches(const IdentityPtr &identity) const{
    if(!identity||identity!=activeIdentity_||!active_||active_->correlation!=identity->correlation||identity->sessionEpoch!=sessionEpoch_||!consent_||
       identity->binding.consentEpoch!=consentEpoch_||identity->binding.credentialEpoch!=credentialEpoch_)return false;
    const auto current=binding(*active_);return current&&*current==identity->binding;
}
WinHttpExplanationTransport::Observer AssistantBrokerRuntime::observerFor(const IdentityPtr &identity){
    QPointer<AssistantBrokerRuntime> self(this);
    // State copia este closure al start: una operacion vieja conserva su token propio.
    return [self,identity](HttpObservation observation){if(self&&self->matches(identity))self->observation_=observation;};
}
void AssistantBrokerRuntime::complete(const IdentityPtr &identity,TransportReply result){
    if(!matches(identity)||!(result.binding==identity->binding))return;
    Frame out;out.message=Message::Explanation;out.correlation=identity->correlation;setBinding(out,identity->binding);
    auto why=observation_.failure;auto outcome=why==Failure::None?Outcome::Completed:(why==Failure::Uncertain||((why==Failure::Timeout||why==Failure::Cancelled)&&observation_.sendStarted)?Outcome::Uncertain:Outcome::Failed);
    if(outcome==Outcome::Uncertain)why=Failure::Uncertain;
    if(outcome==Outcome::Uncertain&&observation_.observedStatus!=0&&observation_.observedStatus!=202)outcome=Outcome::Failed;
    if(outcome==Outcome::Completed){auto text=boundedExplanation(result.body);if(text)out.fields[24]=*text;else{outcome=Outcome::Failed;why=Failure::InvalidResponse;}}
    out.fields[21]=integer(quint8(outcome),1);out.fields[22]=integer(quint16(observation_.observedStatus),2);out.fields[23]=integer(quint16(why),2);
    const auto now=GetTickCount64();
    if(observation_.retryAfterSeconds)blockedUntil_=std::max(blockedUntil_,now+ULONGLONG(observation_.retryAfterSeconds)*1000);
    if(why==Failure::None)failures_.clear();
    else if(why!=Failure::Cancelled&&why!=Failure::Stale&&why!=Failure::RateLimited&&why!=Failure::Capacity){
        while(!failures_.empty()&&now-failures_.front()>60000)failures_.pop_front();
        failures_.push_back(now);
        if(failures_.size()>=3){blockedUntil_=std::max(blockedUntil_,now+60000);failures_.clear();}
    }
    activeIdentity_.reset();active_.reset();reply(std::move(out));schedule();
}
}
