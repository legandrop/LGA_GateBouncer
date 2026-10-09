#include "GeneralRuntimeState.h"
#include <algorithm>
#include <limits>
namespace Gate::Assistance::General {
GeneralRuntime::GeneralRuntime(std::shared_ptr<SearchPort> search,std::shared_ptr<ModelPort> model,
    GeneralCoordinator::Current current,GeneralCoordinator::Clock clock,QObject* parent):GeneralRuntime(std::move(current),std::move(clock),parent) {
    compose(std::move(search),std::move(model));
}
GeneralRuntime::GeneralRuntime(GeneralCoordinator::Current current,GeneralCoordinator::Clock clock,QObject* parent):QObject(parent),data_(std::make_shared<Data>()) {
    data_->current=std::move(current);data_->clock=std::move(clock);const std::weak_ptr<Data> weak=data_;
    deadline_.setInterval(50);connect(&deadline_,&QTimer::timeout,this,[weak]{if(const auto d=weak.lock();d&&!d->closed&&d->coordinator)d->coordinator->tick();});deadline_.start();
}
void GeneralRuntime::compose(std::shared_ptr<SearchPort> search,std::shared_ptr<ModelPort> model) {
    const std::weak_ptr<Data> weak=data_;
    data_->coordinator=std::make_shared<GeneralCoordinator>(std::move(search),std::move(model),[weak](const FullBinding& b){
        const auto d=weak.lock();if(!d||d->closed||!d->approval||d->approval->binding()!=b)return false;
        return d->current&&d->current(b);
    },data_->clock);
}
GeneralRuntime::~GeneralRuntime(){drain();}
std::shared_ptr<const ApprovalRecord> GeneralRuntime::approve(const FullBinding& pending,const PublicFields& p,const Id128& connection,const Id128& correlation) {
    const auto d=data_;const auto nonzero=[](const Id128& id){return std::any_of(id.begin(),id.end(),[](auto c){return c!=0;});};
    if(d->closed||!d->current||!validBinding(pending,true)||!GeneralPayloadBuilder::publicJson(p)||!nonzero(connection)||!nonzero(correlation))return {};
    const auto proposed=pending;const auto fields=p;const auto ownerConnection=connection,ownerCorrelation=correlation;
    const auto serial=d->serial;const bool current=d->current(proposed);if(d->closed||d->serial!=serial||!current)return {};
    if(d->epoch==std::numeric_limits<std::uint64_t>::max()||d->serial==std::numeric_limits<std::uint64_t>::max()){d->closed=true;d->approval.reset();d->coordinator->drain();return {};}
    d->job.reset();d->approval.reset();++d->serial;const auto ownSerial=d->serial;d->coordinator->cancel();
    if(d->closed||d->serial!=ownSerial)return {};
    auto binding=proposed;binding.approvalEpoch=++d->epoch;binding.publicApprovalDigest=approvalDigest(fields,binding.approvalEpoch);
    const std::weak_ptr<Data> weak=d;
    auto record=std::shared_ptr<const ApprovalRecord>(new ApprovalRecord(binding,fields,ownerConnection,ownerCorrelation,std::weak_ptr<const void>(d),[weak,ownSerial,binding]{
        const auto owner=weak.lock();if(!owner||owner->closed||owner->serial!=ownSerial||!owner->current)return false;
        const bool current=owner->current(binding);return current&&!owner->closed&&owner->serial==ownSerial;
    }));
    d->connection=ownerConnection;d->correlation=ownerCorrelation;d->approval=record;return record;
}
bool GeneralRuntime::explain(const FullBinding& b,const PublicFields& p,GeneralCoordinator::Completion completion,GeneralCoordinator::Progress progress) {
    const auto d=data_;const auto record=d->approval;
    if(d->closed||d->job||!d->clock||!record||d->usedApproval==record||record->binding()!=b||!(record->fields()==p)||!completion||approvalDigest(record->fields(),record->epoch())!=b.publicApprovalDigest)return false;
    // Reclamo irreversible antes de cualquier Clock/Current/progress invocable.
    if(d->registry&&!d->registry->claim(*record))return false;
    d->usedApproval=record;
    const auto serial=d->serial;const auto now=d->clock();
    if(d->closed||d->job||d->serial!=serial||now<0||now>INT64_MAX-45000||d->jobSerial==UINT64_MAX)return false;
    auto job=std::make_shared<Data::Job>();job->record=record;job->serial=++d->jobSerial;job->deadline=std::uint64_t(now)+45000;d->job=job;d->usedApproval=record;
    if(d->admission&&!d->admission(b)){
        if(d->closed||d->job!=job)return false;
        d->job.reset();
        completion({b,State::Failed,Failure::ConfigurationNotApproved,0,{},{}});return true;
    }
    const auto coordinator=d->coordinator;
    const bool started=coordinator->beginAt(record,std::int64_t(job->deadline),[d,job,completion=std::move(completion)](Result r) mutable {
        if(d->job==job)d->job.reset();
        if(completion)completion(std::move(r));
    },std::move(progress));
    if(!started&&d->job==job)d->job.reset();
    return started;
}
void GeneralRuntime::cancel(const Id128& correlation){const auto d=data_;if(correlation==d->correlation)withdraw();}
void GeneralRuntime::withdraw(){const auto d=data_;d->job.reset();d->approval.reset();if(d->serial!=UINT64_MAX)++d->serial;else d->closed=true;if(d->coordinator)d->coordinator->cancel();}
void GeneralRuntime::drain(){deadline_.stop();const auto d=data_;d->closed=true;d->job.reset();d->approval.reset();if(d->coordinator)d->coordinator->drain();}
}
