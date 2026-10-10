#include "GeneralClient.h"
#include <QTimer>
#include <QThread>
#include <map>
#include <algorithm>
namespace Gate::Assistance::General {
struct GeneralClient::Data : std::enable_shared_from_this<Data> {
    struct Entry {
        unsigned request=0,expected=0,progress=0;bool retired=false,terminal=false;
        FullBinding binding;PublicFields fields;ApprovalCompletion approval;
        std::map<quint16,QByteArray> expectedFields;
        GeneralCoordinator::Completion completion;GeneralCoordinator::Progress notify;ControlCompletion control;
        bool presentation=false;std::uint64_t presentationGeneration=0;std::function<bool()> presentationCurrent;
        std::optional<Id128> pendingRequest;PendingServiceContext service;
        Id128 observationOwner{};std::uint64_t observedRevision=0;
    };
    std::shared_ptr<FrameChannel> channel;GeneralCoordinator::Current current;
    std::map<Id128,std::shared_ptr<Entry>> ledger;std::shared_ptr<Entry> pending;
    std::optional<ApprovedPublicContext> approved;std::uint64_t sent=0,received=0,serial=0;bool closed=false,greeted=false;
    bool send(Broker::Frame f){if(closed||sent==UINT64_MAX)return false;f.connection=channel->connection();f.sequence=++sent;
        if(!Broker::validFrame(f,Broker::WireVersion::General3))return false;
        return channel->send(std::move(f));}
    void finish(std::shared_ptr<Entry> p,Failure failure){
        if(!p||p->retired)return;
        p->retired=true;if(pending==p)pending.reset();
        auto approval=std::move(p->approval);auto completion=std::move(p->completion);
        if(approval)approval({},failure);
        if(completion)completion({p->binding,failure==Failure::Cancelled?State::Cancelled:State::Failed,failure,0,{},{}});
    }
    void close(){if(closed)return;closed=true;approved.reset();if(serial!=UINT64_MAX)++serial;auto entries=ledger;pending.reset();channel->stop();
        for(auto& [id,p]:entries){Q_UNUSED(id);finish(p,Failure::TransportUnavailable);auto control=std::move(p->control);
            if(control){Broker::Frame error;error.message=Broker::Message::ErrorReply;error.fields[23]=Broker::integer(unsigned(Failure::TransportUnavailable),2);control(std::move(error));}}}
    bool contextCurrent(const FullBinding& b){const auto before=serial;const bool result=current&&current(b);return result&&!closed&&serial==before;}
    bool registerFrame(Broker::Frame f,std::shared_ptr<Entry> p){if(closed||ledger.size()>=60||!Broker::randomId(f.correlation))return false;
        const auto id=f.correlation;ledger.emplace(id,p);if(!send(std::move(f))){close();return false;}return true;}
    void cancel(){approved.reset();if(serial==UINT64_MAX){close();return;}++serial;
        auto entries=ledger;
        for(const auto& [id,p]:entries)if(p->pendingRequest&&!p->terminal&&!p->retired){
            p->retired=true;auto callback=std::move(p->control);
            Broker::Frame cancel;cancel.message=Broker::Message::Cancel;cancel.fields[25]=QByteArray(reinterpret_cast<const char*>(id.data()),16);
            auto ack=std::make_shared<Entry>();ack->request=5;ack->expected=6;if(!registerFrame(std::move(cancel),ack)){close();return;}
            if(callback){Broker::Frame stale;stale.message=Broker::Message::ErrorReply;stale.fields[23]=Broker::integer(unsigned(Failure::Stale),2);callback(std::move(stale));}
            if(closed)return;
        }
        if(!pending)return;
        auto p=pending;Id128 target{};
        for(const auto& [id,entry]:ledger)if(entry==p){target=id;break;}
        finish(p,Failure::Cancelled);
        if(closed)return;
        Broker::Frame f;f.message=Broker::Message::Cancel;f.fields[25]=QByteArray(reinterpret_cast<const char*>(target.data()),16);
        auto ack=std::make_shared<Entry>();ack->request=5;ack->expected=6;if(!registerFrame(std::move(f),ack))close();}
    void receive(Broker::Frame f){
        if(closed)return;
        if(!Broker::validFrame(f,Broker::WireVersion::General3)||f.connection!=channel->connection()||received==UINT64_MAX||f.sequence!=received+1){close();return;}++received;
        const auto found=ledger.find(f.correlation);if(found==ledger.end()||found->second->terminal){close();return;}auto p=found->second;const auto type=unsigned(f.message);
        if(type==11){p->terminal=true;if(pending==p)pending.reset();auto approval=std::move(p->approval);auto completion=std::move(p->completion);auto control=std::move(p->control);
            const auto cause=Failure(Broker::number(f.fields.at(23)));if(approval)approval({},cause);if(completion)completion({p->binding,State::Failed,cause,0,{},{}});if(control)control(std::move(f));return;}
        if(type==22){
            auto b=frameBinding(f);const auto progress=unsigned(Broker::number(f.fields.at(64)));
            if(p->request!=20||!b||*b!=p->binding||progress!=p->progress+1){close();return;}p->progress=progress;
            if(!p->retired&&pending==p){const bool valid=contextCurrent(*b);if(closed||pending!=p)return;if(!valid){cancel();return;}auto callback=p->notify;if(callback)callback(State(progress));}return;
        }
        if(type!=p->expected){close();return;}
        if(type==31&&p->request==30){
            if(p->presentation!=bool(f.fields.count(76))||bool(p->pendingRequest)!=bool(f.fields.count(77))){close();return;}
            bool matching=true;
            if(p->pendingRequest){const auto view=pendingPresentationContext(f.fields.at(77));
                if(!view||view->request()!=*p->pendingRequest||bool(view->principal())!=(p->observationOwner!=Id128{})||
                   (view->principal()&&(view->principal()->owner!=p->observationOwner||view->requestRevision()!=p->observedRevision))){close();return;}
                matching=view->service()==p->service;
            }
            if(p->presentation){
                const auto before=serial;
                const bool current=matching&&!p->retired&&p->presentationGeneration==serial&&p->presentationCurrent&&p->presentationCurrent();
                if(closed)return;
                if(!matching||p->retired||!current||serial!=before||p->presentationGeneration!=serial){
                    p->terminal=true;auto callback=std::move(p->control);
                    if(callback){Broker::Frame stale;stale.message=Broker::Message::ErrorReply;
                        stale.fields[23]=Broker::integer(unsigned(Failure::Stale),2);callback(std::move(stale));}
                    return;
                }
                p->terminal=true;auto callback=std::move(p->control);if(callback)callback(std::move(f));
                if(closed)return;
                const bool after=p->presentationCurrent&&p->presentationCurrent();
                // Una respuesta de A nunca retira una aprobación nueva de B.
                if(!closed&&serial==before&&!after)approved.reset();
                return;
            }
        }
        if(type==24){
            auto b=frameBinding(f,Broker::number(f.fields.at(65))!=0);auto fields=framePublicFields(f);const auto failure=Failure(Broker::number(f.fields.at(65)));
            if(!b||!fields||!(*fields==p->fields)){close();return;}auto pendingBinding=*b;pendingBinding.approvalEpoch=0;pendingBinding.publicApprovalDigest={};
            if(pendingBinding!=p->binding){close();return;}p->terminal=true;if(pending==p)pending.reset();
            if(p->retired)return;
            const auto before=serial;
            const bool valid=failure==Failure::None&&contextCurrent(*b);if(closed)return;if(serial!=before){finish(p,Failure::Stale);return;}
            auto callback=std::move(p->approval);
            if(valid){approved=ApprovedPublicContext{*b,*fields};if(callback)callback(approved,Failure::None);}else if(callback)callback({},failure==Failure::None?Failure::Stale:failure);return;
        }
        if(type==21){auto result=frameResult(f);if(!result||result->binding!=p->binding){close();return;}p->terminal=true;if(pending==p)pending.reset();
            if(p->retired)return;
            const auto before=serial;const bool valid=contextCurrent(result->binding);if(closed)return;if(serial!=before){finish(p,Failure::Stale);return;}
            auto completion=std::move(p->completion);
            if(!valid){result->state=State::Failed;result->failure=Failure::Stale;result->inference.reset();result->citations.clear();result->observedHttpStatus=0;}if(completion)completion(std::move(*result));return;}
        for(const auto& [tag,value]:p->expectedFields)if(!f.fields.count(tag)||f.fields.at(tag)!=value){close();return;}
        p->terminal=true;if(type==2)greeted=true;auto callback=std::move(p->control);if(callback)callback(std::move(f));
    }
};
bool GeneralClient::settled() const {
    const auto d=data_;
    return !d->closed&&d->greeted&&!d->pending&&std::all_of(d->ledger.begin(),d->ledger.end(),
        [](const auto& entry){return entry.second->terminal||entry.second->retired;});
}
GeneralClient::GeneralClient(std::shared_ptr<FrameChannel> channel,GeneralCoordinator::Current current,QObject* parent):QObject(parent),data_(std::make_shared<Data>()){
    const auto d=data_;d->channel=std::move(channel);d->current=std::move(current);
    if(!d->channel||d->channel->version()!=Broker::WireVersion::General3||!d->current){d->closed=true;return;}
    const std::weak_ptr<Data> weak=d;d->channel->start([weak](Broker::Frame f){if(auto s=weak.lock())s->receive(std::move(f));},[weak]{if(auto s=weak.lock())s->close();});
    Broker::Frame hello;hello.message=Broker::Message::StatusRequest;auto entry=std::make_shared<Data::Entry>();entry->request=1;entry->expected=2;if(!d->registerFrame(std::move(hello),entry))d->close();
}
GeneralClient::~GeneralClient(){close();}
bool GeneralClient::approve(FullBinding b,PublicFields fields,ApprovalCompletion completion){
    if(QThread::currentThread()!=thread())return false;
    const auto d=data_;if(d->closed||!d->greeted||!completion||!validBinding(b,true)||!GeneralPayloadBuilder::publicJson(fields))return false;
    d->cancel();if(d->closed||!d->contextCurrent(b)||d->pending)return false;
    auto p=std::make_shared<Data::Entry>();p->request=23;p->expected=24;p->binding=std::move(b);p->fields=std::move(fields);p->approval=std::move(completion);d->pending=p;
    Broker::Frame f;f.message=Broker::Message::PublicApproval;setFrameBinding(f,p->binding);setPublicFields(f,p->fields);
    if(!d->registerFrame(std::move(f),p)){d->finish(p,Failure::Capacity);return false;}
    const std::weak_ptr<Data> weak=d;QTimer::singleShot(6000,[weak,p]{if(auto s=weak.lock();s&&s->pending==p)s->cancel();});return true;
}
bool GeneralClient::explain(const FullBinding& b,const PublicFields& fields,GeneralCoordinator::Completion completion,GeneralCoordinator::Progress progress){
    if(QThread::currentThread()!=thread())return false;
    const auto d=data_;if(d->closed||d->pending||!d->approved||d->approved->binding!=b||!(d->approved->fields==fields)||!completion)return false;
    const auto owned=*d->approved;if(!d->contextCurrent(owned.binding)||d->pending||!d->approved)return false;
    d->approved.reset();
    auto p=std::make_shared<Data::Entry>();p->request=20;p->expected=21;p->binding=owned.binding;p->fields=owned.fields;p->completion=std::move(completion);p->notify=std::move(progress);d->pending=p;
    Broker::Frame f;f.message=Broker::Message::GeneralExplain;setFrameBinding(f,p->binding);setPublicFields(f,p->fields);if(!d->registerFrame(std::move(f),p)){d->finish(p,Failure::Capacity);return false;}
    const std::weak_ptr<Data> weak=d;QTimer::singleShot(45000,[weak,p]{if(auto s=weak.lock();s&&s->pending==p)s->cancel();});return true;
}
bool GeneralClient::control(Broker::Frame f,ControlCompletion completion){
    if(QThread::currentThread()!=thread())return false;
    const auto d=data_;if(d->closed||!d->greeted||!completion||f.secret.size()||
        (f.message==Broker::Message::ConfigurationStatus&&(f.fields.count(76)||f.fields.count(77))))return false;
    unsigned expected=0;switch(unsigned(f.message)){case 1:expected=2;break;case 30:expected=31;break;case 32:expected=33;break;case 35:case 36:expected=37;break;default:return false;}
    const auto active=std::count_if(d->ledger.begin(),d->ledger.end(),[](const auto& entry){return !entry.second->terminal&&(entry.second->request!=20&&entry.second->request!=23);});if(active>=3)return false;
    auto p=std::make_shared<Data::Entry>();p->request=unsigned(f.message);p->expected=expected;p->control=std::move(completion);
    if(p->request==32){if(!f.fields.count(71)||!f.fields.count(73))return false;p->expectedFields={{71,f.fields.at(71)},{73,f.fields.at(73)}};}
    if(!d->registerFrame(std::move(f),p))return false;
    const std::weak_ptr<Data> weak=d;QTimer::singleShot(6000,[weak,p]{if(auto s=weak.lock();s&&!s->closed&&!p->terminal){p->terminal=true;auto callback=std::move(p->control);
        if(callback){Broker::Frame error;error.message=Broker::Message::ErrorReply;error.fields[23]=Broker::integer(unsigned(Failure::Timeout),2);callback(std::move(error));}}});return true;
}
bool GeneralClient::configurationStatus(bool presentation,std::function<bool()> currentContext,ControlCompletion completion){
    if(!presentation){Broker::Frame request;request.message=Broker::Message::ConfigurationStatus;return control(std::move(request),std::move(completion));}
    return presentationStatus({}, {},std::move(currentContext),std::move(completion));
}
bool GeneralClient::pendingStatus(const Id128& request,PendingServiceContext captured,
    std::function<bool()> currentContext,ControlCompletion completion,Id128 owner,std::uint64_t revision){
    if(QThread::currentThread()!=thread()||!currentContext||!completion||!pendingQueryBytes(PendingQuerySelection{request,owner,revision})||!validPendingService(captured))return false;
    const auto d=data_;if(d->closed||!d->greeted)return false;
    d->cancel();if(d->closed)return false;
    return presentationStatus(request,captured,std::move(currentContext),std::move(completion),owner,revision);
}
bool GeneralClient::presentationStatus(std::optional<Id128> selected,PendingServiceContext captured,
    std::function<bool()> currentContext,ControlCompletion completion,Id128 owner,std::uint64_t revision){
    if(QThread::currentThread()!=thread()||!currentContext||!completion)return false;
    const auto d=data_;if(d->closed||!d->greeted)return false;
    const auto before=d->serial;const bool current=currentContext();if(!current||d->closed||d->serial!=before)return false;
    const auto active=std::count_if(d->ledger.begin(),d->ledger.end(),[](const auto& entry){return !entry.second->terminal&&entry.second->request!=20&&entry.second->request!=23;});
    if(active>=3)return false;
    auto p=std::make_shared<Data::Entry>();p->request=30;p->expected=31;p->presentation=true;p->presentationGeneration=before;
    p->presentationCurrent=std::move(currentContext);p->control=std::move(completion);
    p->pendingRequest=selected;p->service=captured;p->observationOwner=owner;p->observedRevision=revision;
    Broker::Frame request;request.message=Broker::Message::ConfigurationStatus;request.fields[76]=Broker::integer(1,2);
    if(selected){const auto query=pendingQueryBytes(PendingQuerySelection{*selected,owner,revision});if(!query)return false;request.fields[77]=*query;}
    if(!d->registerFrame(std::move(request),p))return false;
    const std::weak_ptr<Data> weak=d;QTimer::singleShot(6000,[weak,p]{if(auto owner=weak.lock();owner&&!owner->closed&&!p->terminal){
        if(p->pendingRequest&&p->retired)return;
        if(p->pendingRequest&&!p->retired){owner->cancel();return;}
        p->terminal=true;auto callback=std::move(p->control);if(callback){Broker::Frame error;error.message=Broker::Message::ErrorReply;
            error.fields[23]=Broker::integer(unsigned(Failure::Timeout),2);callback(std::move(error));}
    }});return true;
}
bool GeneralClient::storeCredential(Configuration::ConfigurationIntent intent,Broker::SensitiveBytes secret,ControlCompletion completion){
    if(QThread::currentThread()!=thread()||intent.verb!=Configuration::ConfigurationVerb::Store||
       !intent.revision||!Configuration::nonzero(intent.capability)||!secret.size()||secret.size()>512)return false;
    for(std::size_t i=0;i<secret.size();++i)if(secret.data()[i]<33||secret.data()[i]>126)return false;
    const auto d=data_;if(d->closed||!d->greeted||!completion)return false;
    const auto active=std::count_if(d->ledger.begin(),d->ledger.end(),[](const auto& entry){
        return !entry.second->terminal&&entry.second->request!=20&&entry.second->request!=23;
    });if(active>=3)return false;
    auto p=std::make_shared<Data::Entry>();p->request=34;p->expected=37;p->control=std::move(completion);
    Broker::Frame frame;frame.message=Broker::Message::StoreCredential;frame.fields[72]=QByteArray(reinterpret_cast<const char*>(intent.capability.data()),16);
    frame.fields[73]=Broker::integer(intent.revision,8);frame.secret=std::move(secret);
    if(!d->registerFrame(std::move(frame),p))return false;
    const std::weak_ptr<Data> weak=d;QTimer::singleShot(6000,[weak,p]{
        if(auto owner=weak.lock();owner&&!owner->closed&&!p->terminal){
            p->terminal=true;auto callback=std::move(p->control);
            if(callback){Broker::Frame error;error.message=Broker::Message::ErrorReply;
                error.fields[23]=Broker::integer(unsigned(Failure::Timeout),2);callback(std::move(error));}
        }
    });return true;
}
void GeneralClient::cancel(){const auto d=data_;d->cancel();}
void GeneralClient::close(){const auto d=data_;d->close();}
}
