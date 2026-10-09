#include "GroundedBrokerRuntime.h"
#include "retrieval/Catalog.h"
#include "retrieval/ProviderPolicy.h"
#include "retrieval/GroundedParser.h"
#include <QPointer>
#include <QTimer>
namespace Gate::Assistance::GroundedBridge {
using namespace Broker;
static Retrieval::Frame grounded(const Frame &f){return {quint16(f.message),f.connection,f.correlation,f.sequence,f.fields};}
GroundedBrokerRuntime::GroundedBrokerRuntime(std::unique_ptr<PipeSession> session,QObject *parent):QObject(parent),session_(std::move(session)){}
std::unique_ptr<GroundedBrokerRuntime> GroundedBrokerRuntime::forCurrentUser(std::unique_ptr<PipeSession> session,QObject *parent) {
    if(!session || session->version()!=WireVersion::Grounded2)return {};
    auto runtime=std::unique_ptr<GroundedBrokerRuntime>(new GroundedBrokerRuntime(std::move(session),parent));
    // Antes de cualquier raiz, clave o handle HTTP; una seam compilada no es admision.
    if(!ProductionActivation::approved() || !Retrieval::Activation::approved())return runtime;
    auto activation=Retrieval::Activation::forCurrentUser();if(!activation)return runtime;
    runtime->vault_=BrokerVault::forCurrentUser();if(!runtime->vault_)return runtime;
    runtime->get_=std::make_unique<Retrieval::WinHttpGetTransport>(*activation);
    runtime->budget_=std::make_unique<Retrieval::BudgetGuard>(*activation);
    runtime->model_=std::unique_ptr<GroundedModelTransport>(new GroundedModelTransport(*runtime->vault_,runtime.get()));
    runtime->coordinator_=std::make_unique<Retrieval::Coordinator>(*runtime->get_,*runtime->model_,*runtime->budget_,runtime->builder_,runtime.get());
    return runtime;
}
GroundedBrokerRuntime::~GroundedBrokerRuntime(){invalidate();session_->stop();}
void GroundedBrokerRuntime::start(){session_->start([this](Frame f){receive(std::move(f));},[this]{invalidate();});}
void GroundedBrokerRuntime::reply(Frame f){if(!session_->send(std::move(f))){invalidate();session_->stop();}}
void GroundedBrokerRuntime::fail(const Frame &request,Failure why){Frame f;f.message=Message::ErrorReply;f.correlation=request.correlation;f.fields[23]=integer(quint16(why),2);reply(std::move(f));}
void GroundedBrokerRuntime::invalidate(){
    const auto old=std::move(active_);queue_.clear();capability_={};capabilityVerb_=0;++sessionEpoch_;++retrievalEpoch_;nvidiaConsent_=false;webConsent_=false;observation_={};
    if(auto *m=dynamic_cast<GroundedModelTransport *>(model_.get()))m->clearJob(old);
    if(coordinator_)coordinator_->cancel();
}
bool GroundedBrokerRuntime::matches(const JobIdentityPtr &id) const {
    return id && id==active_ && id->sessionEpoch==sessionEpoch_ && nvidiaConsent_ && webConsent_ &&
        id->binding.request.consentEpoch==consentEpoch_ && id->binding.request.credentialEpoch==credentialEpoch_ && id->binding.retrievalEpoch==retrievalEpoch_;
}
void GroundedBrokerRuntime::receive(Frame f) {
    if(!greeted_){if(f.message!=Message::StatusRequest || !f.fields.empty()){session_->stop();return;}greeted_=true;}
    if(correlations_.count(f.correlation) || correlations_.size()>=4096){session_->stop();return;}correlations_[f.correlation]=true;
    if(f.message==Message::StatusRequest){
        if(f.fields.count(33)){
            if(!ProductionActivation::approved()||!vault_||!coordinator_){fail(f,Failure::ConfigurationNotApproved);return;}
            if(!randomId(capability_)){fail(f,Failure::VaultUnavailable);return;}
            capabilityVerb_=quint8(number(f.fields.at(33)));capabilityExpiry_=GetTickCount64()+5000;
        }
        if(f.fields.count(31)){
            const bool n=number(f.fields.at(31)),w=number(f.fields.at(40));
            if((n||w)&&!testing_&&(!ProductionActivation::approved()||!coordinator_)){fail(f,Failure::ConfigurationNotApproved);return;}
            if(n!=nvidiaConsent_||w!=webConsent_){invalidate();++consentEpoch_;}
            nvidiaConsent_=n;webConsent_=w;automatic_=number(f.fields.at(32));
        }
        Frame r;r.message=Message::StatusReply;r.correlation=f.correlation;
        const quint8 credential=vault_?vault_->status():0;
        const quint8 availability=testing_?4:(!coordinator_?3:(credential!=1?1:(!nvidiaConsent_||!webConsent_?2:4)));
        r.fields={{1,integer(availability,1)},{2,integer(credential,1)},{3,integer(consentEpoch_,8)},{4,integer(credentialEpoch_,8)},
            {5,integer(sessionEpoch_,8)},{6,integer(automatic_,1)},{7,integer(1,2)},{41,integer(retrievalEpoch_,8)},
            {42,integer(Retrieval::CatalogRevision,8)},{43,integer(Retrieval::PolicyEpoch,8)},{44,integer(testing_?4:0,1)}};
        if(f.fields.count(33))r.fields[34]=QByteArray(reinterpret_cast<const char *>(capability_.data()),16);
        reply(std::move(r));return;
    }
    if(f.message==Message::Configure||f.message==Message::Forget){
        if(!ProductionActivation::approved()||!vault_){fail(f,Failure::ConfigurationNotApproved);return;}
        const auto cap=f.fields.at(34);const quint8 verb=f.message==Message::Configure?1:2;
        if(!nonzero(capability_)||cap!=QByteArray(reinterpret_cast<const char *>(capability_.data()),16)||verb!=capabilityVerb_||GetTickCount64()>capabilityExpiry_){fail(f,Failure::Unauthorized);return;}
        invalidate();++credentialEpoch_;const auto failure=verb==1?vault_->configure(std::move(f.secret)):vault_->forget();
        Frame r;r.message=verb==1?Message::ConfigureAck:Message::ForgetAck;r.correlation=f.correlation;
        r.fields={{2,integer(failure==Failure::None?vault_->status():2,1)},{4,integer(credentialEpoch_,8)},{23,integer(quint16(failure),2)}};reply(std::move(r));return;
    }
    if(f.message==Message::Cancel){
        const auto target=f.fields.at(25);const bool found=active_&&target==QByteArray(reinterpret_cast<const char *>(active_->correlation.data()),16);
        if(found){auto old=std::move(active_);if(auto *m=dynamic_cast<GroundedModelTransport *>(model_.get()))m->clearJob(old);observation_={};coordinator_->cancel();}
        bool queued=false;for(auto it=queue_.begin();it!=queue_.end();++it)if(target==QByteArray(reinterpret_cast<const char *>(it->correlation.data()),16)){queue_.erase(it);queued=true;break;}
        Frame r;r.message=Message::CancelAck;r.correlation=f.correlation;r.fields[21]=integer(quint8(found||queued?Outcome::Cancelled:Outcome::NotFound),1);reply(std::move(r));dispatch();return;
    }
    if(f.message!=Message::GroundedExplain){fail(f,Failure::Unsupported);return;}
    if(!coordinator_ || (!testing_ && !ProductionActivation::approved()) || !nvidiaConsent_ || !webConsent_){fail(f,Failure::ConfigurationNotApproved);return;}
    if(!testing_ && (!vault_ || vault_->status()!=1)){fail(f,Failure::VaultUnavailable);return;}
    const auto b=Retrieval::frameBinding(grounded(f));
    if(!b || b->request.consentEpoch!=consentEpoch_ || b->request.credentialEpoch!=credentialEpoch_ || b->retrievalEpoch!=retrievalEpoch_){fail(f,Failure::Stale);return;}
    if(queue_.size()>=16){fail(f,Failure::Capacity);return;}queue_.push_back(std::move(f));dispatch();
}
void GroundedBrokerRuntime::dispatch(){
    if(active_ || queue_.empty() || !coordinator_ || !nvidiaConsent_ || !webConsent_)return;
    auto f=std::move(queue_.front());queue_.pop_front();const auto b=Retrieval::frameBinding(grounded(f));if(!b){fail(f,Failure::Malformed);return;}
    const auto product=Retrieval::Product(number(f.fields.at(20)));
    const auto id=std::make_shared<const JobIdentity>(JobIdentity{f.correlation,*b,product,sessionEpoch_,++serial_});active_=id;observation_={};
    if(auto *m=dynamic_cast<GroundedModelTransport *>(model_.get())){
        QPointer<GroundedBrokerRuntime> self(this);m->bindJob(id,[self,id](HttpObservation observation){if(self&&self->matches(id))self->observation_=observation;});
    }
    coordinator_->configure(nvidiaConsent_,webConsent_,retrievalEpoch_,automatic_);coordinator_->setContext(*b,product);
    if(!matches(id))return;
    if(!Retrieval::eligibleProduct(product)){complete(id,{*b,product,Retrieval::State::Insufficient,Retrieval::Failure::Uncertain,0,{},{}});return;}
    QPointer<GroundedBrokerRuntime> self(this);
    const bool started=coordinator_->start([self,id](Retrieval::Result r){if(self)self->complete(id,std::move(r));},[self,id](Retrieval::State s){if(self)self->progress(id,s);});
    if(!started && matches(id)){active_.reset();fail(f,Failure::Capacity);QTimer::singleShot(0,this,[this]{dispatch();});}
}
void GroundedBrokerRuntime::progress(const JobIdentityPtr &id,Retrieval::State state){
    if(!matches(id) || (state!=Retrieval::State::Searching && state!=Retrieval::State::Explaining))return;
    Retrieval::Frame g;g.type=14;g.correlation=id->correlation;Retrieval::setBinding(g,id->binding);g.fields[20]=integer(quint32(id->product),4);g.fields[45]=integer(quint8(state),1);
    Frame r;r.message=Message::GroundedProgress;r.correlation=g.correlation;r.fields=std::move(g.fields);reply(std::move(r));
}
void GroundedBrokerRuntime::complete(const JobIdentityPtr &id,Retrieval::Result result){
    if(!matches(id) || !(result.binding==id->binding) || result.product!=id->product)return;
    const bool deadline=result.failure==Retrieval::Failure::Timeout;
    auto *model=dynamic_cast<GroundedModelTransport *>(model_.get());auto evidence=observation_;
    // Cancel tecnico del Coordinator no retira identity_: consultar antes de clear.
    if(model)if(auto snapshot=model->snapshotJob(id)){
        if(!evidence)evidence=*snapshot;
        else evidence->sendStarted=evidence->sendStarted||snapshot->sendStarted;
    }
    const auto observation=evidence.value_or(HttpObservation{});
    const bool uncertainCause=observation.failure==Failure::None||observation.failure==Failure::Uncertain||observation.failure==Failure::Timeout||observation.failure==Failure::Cancelled;
    if(evidence&&observation.failure!=Failure::None&&!uncertainCause){
        result.state=observation.failure==Failure::RateLimited||observation.failure==Failure::Capacity?Retrieval::State::ProviderUnavailable:Retrieval::State::Failed;
        result.failure=Retrieval::Failure(quint16(observation.failure));
        result.observedHttpStatus=observation.observedStatus;result.inference.reset();
    }else if(evidence&&deadline){result.observedHttpStatus=observation.observedStatus;result.inference.reset();}
    const bool postUncertain=uncertainCause&&observation.sendStarted&&!result.sources.empty()&&(observation.observedStatus==0||observation.observedStatus==202)&&
        (observation.failure==Failure::Uncertain||observation.failure==Failure::Timeout||observation.failure==Failure::Cancelled||result.failure==Retrieval::Failure::Timeout||result.failure==Retrieval::Failure::Cancelled);
    if(postUncertain){
        result.state=Retrieval::State::PostUncertain;
        result.failure=Retrieval::Failure::Uncertain;result.observedHttpStatus=observation.observedStatus;result.inference.reset();
    }else if(observation.failure==Failure::Uncertain){result.state=Retrieval::State::Failed;result.failure=Retrieval::Failure::TransportUnavailable;result.observedHttpStatus=observation.observedStatus;result.inference.reset();}
    if(model&&evidence&&result.failure!=Retrieval::Failure::None){
        auto accounting=*evidence;
        if(deadline&&accounting.sendStarted&&(accounting.failure==Failure::None||accounting.failure==Failure::Timeout||accounting.failure==Failure::Cancelled))accounting.failure=Failure::Timeout;
        // Sólo accounting; el helper nunca entrega observer externo ni éxito Sending.
        if(accounting.failure!=Failure::None&&accounting.failure!=Failure::Cancelled)model->recordOutcome(id,accounting);
    }
    auto sources=Retrieval::encodeSources(result.product,result.sources);auto inference=result.inference?std::optional<QByteArray>(Retrieval::inferenceJson(*result.inference)):std::nullopt;
    if(!sources || (inference && (inference->size()>2048 || !Retrieval::parseInference(*inference,result.sources)))){
        result.state=Retrieval::State::Failed;result.failure=Retrieval::Failure::InvalidResponse;result.inference.reset();result.sources.clear();sources=Retrieval::encodeSources(result.product,{});inference.reset();
    }
    Outcome outcome=result.inference?Outcome::Completed:Outcome::Failed;
    if(result.state==Retrieval::State::Insufficient)outcome=Outcome::Uncertain;
    else if(result.state==Retrieval::State::Cancelled)outcome=Outcome::Cancelled;
    else if(result.failure==Retrieval::Failure::RateLimited)outcome=Outcome::Limited;
    Retrieval::Frame g;g.type=13;g.correlation=id->correlation;Retrieval::setBinding(g,id->binding);
    g.fields[20]=integer(quint32(result.product),4);g.fields[21]=integer(quint8(outcome),1);g.fields[22]=integer(quint16(result.observedHttpStatus),2);
    g.fields[23]=integer(quint16(result.failure),2);g.fields[45]=integer(quint8(result.state),1);g.fields[46]=sources.value_or(QByteArray(1,'\0'));if(inference)g.fields[47]=*inference;
    active_.reset();if(auto *m=dynamic_cast<GroundedModelTransport *>(model_.get()))m->clearJob(id);
    Frame r;r.message=Message::GroundedExplanation;r.correlation=g.correlation;r.fields=std::move(g.fields);reply(std::move(r));QTimer::singleShot(0,this,[this]{dispatch();});
}
}
