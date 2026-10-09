#include "GeneralModelTransport.h"
namespace Gate::Assistance::General {
struct GeneralModelTransport::Data {
    struct Job { FullBinding binding;std::shared_ptr<const SealedGeneralPayload> seal;HttpObservation seen;bool terminal=false; };
    std::shared_ptr<Configuration::ConfigurationController> configuration;
    std::shared_ptr<Broker::BrokerVault> vault;
    std::shared_ptr<WinHttpExplanationTransport> native;
    Authorize authorize;std::shared_ptr<Job> active;bool closed=false;
};
namespace {
class NativeOperation final : public Operation {
    std::unique_ptr<Gate::Assistance::Operation> native_;
    std::function<void()> retire_;
    bool cancelled_=false;
public:
    NativeOperation(std::unique_ptr<Gate::Assistance::Operation> op,std::function<void()> retire):native_(std::move(op)),retire_(std::move(retire)){}
    ~NativeOperation() override {cancel();}
    void cancel() override {if(cancelled_)return;cancelled_=true;if(retire_)retire_();if(native_)native_->cancel();}
};
class RejectedOperation final : public Operation { public:void cancel() override{} };
}
GeneralModelTransport::GeneralModelTransport(Broker::BrokerVault& vault,Authorize authorize):data_(std::make_shared<Data>()) {
    data_->authorize=std::move(authorize);
    data_->native=std::shared_ptr<WinHttpExplanationTransport>(new WinHttpExplanationTransport(vault,{},nullptr));
}
GeneralModelTransport::~GeneralModelTransport(){data_->closed=true;data_->active.reset();}
GeneralModelTransport::GeneralModelTransport(std::shared_ptr<Broker::BrokerVault> vault,
    std::shared_ptr<Configuration::ConfigurationController> configuration,Authorize authorize):data_(std::make_shared<Data>()) {
    data_->configuration=std::move(configuration);data_->vault=std::move(vault);data_->authorize=std::move(authorize);
    if(data_->vault&&data_->configuration)
        data_->native=std::shared_ptr<WinHttpExplanationTransport>(new WinHttpExplanationTransport(*data_->vault,{},nullptr));
    else data_->closed=true;
}
std::unique_ptr<Operation> GeneralModelTransport::begin(const FullBinding& b,const SealedGeneralPayload& seal,Completion completion) {
    const auto d=data_;if(d->closed||d->active||!d->authorize||!completion||!GeneralPayloadBuilder::validProfile(seal,b))return {};
    auto job=std::make_shared<Data::Job>();job->binding=b;job->seal=std::make_shared<const SealedGeneralPayload>(seal);d->active=job;
    // La identidad efectiva queda reclamada antes de cualquier callback del issuer.
    const std::shared_ptr<const void> token=job;
    auto issued=d->authorize(job->binding,*job->seal,token);
    if(d->closed||d->active!=job){if(d->active==job)d->active.reset();return {};}
    if(!issued.permit){
        d->active.reset();job->terminal=true;
        const auto stale=issued.cause==Configuration::ActivationCause::SessionStale||issued.cause==Configuration::ActivationCause::ProviderPolicyChanged;
        completion({job->binding,{},stale?Failure::Stale:Failure::ConfigurationNotApproved,0,false});
        return std::make_unique<RejectedOperation>();
    }
    const auto native=d->native;
    auto operation=native->startGeneral(job->binding,*job->seal,[d,job,native,token,completion=std::move(completion)](TransportReply reply) mutable {
        if(job->terminal)return;
        job->terminal=true;
        if(const auto seen=native->snapshotGeneralObservation(job->binding,token))job->seen=*seen;
        if(d->active==job)d->active.reset();
        if(d->closed)return;
        auto failure=static_cast<Failure>(job->seen.failure);
        if(failure==Failure::None&&reply.error!=Error::None)failure=reply.error==Error::InvalidResponse?Failure::InvalidResponse:Failure::TransportUnavailable;
        completion({job->binding,reply.body.toStdString(),failure,job->seen.observedStatus,job->seen.sendStarted});
    },[job](HttpObservation seen){if(!job->terminal)job->seen=seen;},token,std::move(*issued.permit));
    if(!operation){if(d->active==job)d->active.reset();return {};}
    const std::weak_ptr<Data> weak=d;
    return std::make_unique<NativeOperation>(std::move(operation),[weak,job]{if(const auto owner=weak.lock();owner&&owner->active==job)owner->active.reset();});
}
}
