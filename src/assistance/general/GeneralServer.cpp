#include "GeneralServer.h"
#include <map>
#include <cstring>
namespace Gate::Assistance::General {
struct GeneralServer::Data : std::enable_shared_from_this<Data> {
    std::shared_ptr<FrameChannel> channel;std::shared_ptr<GeneralRuntime> runtime;Control control;
    PendingControl pendingControl;std::function<void()> retire;Id128 pendingStatus{};std::uint64_t pendingGeneration=0;
    std::map<Id128,unsigned> correlations;Id128 approval{},active{};std::uint64_t sent=0,received=0;bool greeted=false,closed=false;
    void close(){if(closed)return;closed=true;pendingStatus={};if(retire)retire();active={};approval={};runtime->drain();channel->stop();}
    void send(Broker::Frame f){if(closed||sent==UINT64_MAX){close();return;}f.connection=channel->connection();f.sequence=++sent;
        if(!Broker::validFrame(f,Broker::WireVersion::General3)||!channel->send(std::move(f)))close();}
    void fail(const Id128& id,Failure failure){Broker::Frame f;f.message=Broker::Message::ErrorReply;f.correlation=id;f.fields[23]=Broker::integer(unsigned(failure),2);send(std::move(f));}
    void receive(Broker::Frame f){
        if(closed)return;
        const auto id=f.correlation;const auto type=unsigned(f.message);
        if(!Broker::validFrame(f,Broker::WireVersion::General3)||f.connection!=channel->connection()||received==UINT64_MAX||f.sequence!=received+1||correlations.count(id)||correlations.size()>=64){close();return;}
        ++received;correlations.emplace(id,type);
        if(!greeted&&(type!=1||!f.fields.empty())){fail(id,Failure::Unauthorized);return;}
        if(type==5){Id128 target{};std::memcpy(target.data(),f.fields.at(25).data(),16);const bool owned=target==pendingStatus;
            const bool found=target==active||target==approval||owned;
            if(owned){pendingStatus={};if(retire)retire();}
            if(found){approval={};runtime->withdraw();}if(closed)return;
            Broker::Frame ack;ack.message=Broker::Message::CancelAck;ack.correlation=id;ack.fields[21]=Broker::integer(found?3:6,1);send(std::move(ack));return;}
        if(type==23){
            const auto b=frameBinding(f,true);const auto p=framePublicFields(f);auto record=runtime->approve(*b,*p,channel->connection(),id);if(closed)return;
            Broker::Frame ack;ack.message=Broker::Message::PublicApprovalAck;ack.correlation=id;setPublicFields(ack,*p);
            if(record){approval=id;setFrameBinding(ack,record->binding());ack.fields[65]=Broker::integer(0,2);}else{setFrameBinding(ack,*b);ack.fields[65]=Broker::integer(unsigned(Failure::Stale),2);}
            send(std::move(ack));return;
        }
        if(type==20){
            if(active!=Id128{}){fail(id,Failure::Capacity);return;}const auto b=frameBinding(f);const auto p=framePublicFields(f);active=id;auto self=shared_from_this();
            const bool started=runtime->explain(*b,*p,[self,id](Result r){if(self->closed||self->active!=id)return;self->active={};Broker::Frame reply;reply.message=Broker::Message::GeneralExplanation;reply.correlation=id;
                if(!setResult(reply,r)){self->fail(id,Failure::InvalidResponse);return;}self->send(std::move(reply));},
                [self,id,b=*b](State state){if(self->closed||self->active!=id)return;Broker::Frame progress;progress.message=Broker::Message::GeneralProgress;progress.correlation=id;setFrameBinding(progress,b);progress.fields[64]=Broker::integer(unsigned(state),1);self->send(std::move(progress));});
            if(!started&&!closed&&active==id){active={};fail(id,Failure::ConfigurationNotApproved);}return;
        }
        unsigned expected=0;switch(type){case 1:if(!f.fields.empty()){fail(id,Failure::Unsupported);return;}expected=2;break;
            case 30:expected=31;break;case 32:expected=33;break;case 34:case 35:case 36:expected=37;break;default:fail(id,Failure::Unsupported);return;}
        if(type==30&&f.fields.count(77)){
            if(pendingStatus!=Id128{}||!pendingControl){fail(id,Failure::Stale);return;}
            if(pendingGeneration==UINT64_MAX){close();return;}
            const auto generation=++pendingGeneration;pendingStatus=id;auto self=shared_from_this();
            pendingControl(std::move(f),[self,id,generation](Broker::Frame reply,std::function<bool()> current){
                if(self->closed||self->pendingStatus!=id||self->pendingGeneration!=generation)return;
                const bool success=reply.message==Broker::Message::ConfigurationStatusReply;
                const bool valid=!success||(current&&current());
                if(self->closed||self->pendingStatus!=id)return;
                self->pendingStatus={};
                if(!valid){if(self->retire)self->retire();self->fail(id,Failure::Stale);return;}
                reply.correlation=id;self->send(std::move(reply));
                if(!self->closed&&self->pendingGeneration==generation&&success&&(!current||!current())&&
                    !self->closed&&self->pendingGeneration==generation)self->close();
            });return;
        }
        if(type>=32&&pendingStatus!=Id128{}){const auto target=pendingStatus;pendingStatus={};if(retire)retire();fail(target,Failure::Stale);if(closed)return;}
        auto reply=control(std::move(f));if(closed)return;if(!reply){fail(id,Failure::Unsupported);return;}
        if(unsigned(reply->message)!=expected&&reply->message!=Broker::Message::ErrorReply){close();return;}
        reply->correlation=id;if(type==1&&reply->message==Broker::Message::StatusReply)greeted=true;send(std::move(*reply));
    }
};
GeneralServer::GeneralServer(std::shared_ptr<FrameChannel> channel,std::shared_ptr<GeneralRuntime> runtime,Control control,QObject* parent):QObject(parent),data_(std::make_shared<Data>()){
    const auto d=data_;d->channel=std::move(channel);d->runtime=std::move(runtime);d->control=std::move(control);
    if(!d->channel||!d->runtime||!d->control||d->channel->version()!=Broker::WireVersion::General3){d->closed=true;return;}
    const std::weak_ptr<Data> weak=d;d->channel->start([weak](Broker::Frame f){if(auto s=weak.lock())s->receive(std::move(f));},[weak]{if(auto s=weak.lock())s->close();});
}
GeneralServer::~GeneralServer(){close();}
void GeneralServer::close(){const auto d=data_;d->close();}
void GeneralServer::setPendingControl(PendingControl control,std::function<void()> retire){
    const auto d=data_;if(d->closed)return;d->pendingControl=std::move(control);d->retire=std::move(retire);
}
}
