#include "GeneralBrokerHost.h"
#include "../general/PendingPresentationContext.h"
#include "client_ii_win.h"
#include "wire_iv.h"
#include "../../localfacts/WinFile.h"
#include <QPointer>
#include <QThread>
#include <QUuid>
#include <QTimer>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QDir>
#include <algorithm>
#include <set>

namespace Gate::Assistance::General {
namespace L=gatebouncer::localfacts;
namespace {
QString text(const gb::wire::Bytes& bytes){return QString::fromUtf8(
    reinterpret_cast<const char*>(bytes.data()),qsizetype(bytes.size()));}
std::string requestName(const Id128& id){return QUuid::fromRfc4122(QByteArray(
    reinterpret_cast<const char*>(id.data()),16)).toString().toStdString();}
bool sameRecord(const gb::wire::ii::PendingRecord& a,const gb::wire::ii::PendingRecord& b,std::uint16_t minor){
    if(!a.ttl||!b.ttl)return false;
    auto observed=a,captured=b;
    // Remaining TTL desciende en lookup; no es una revisión de identidad.
    observed.ttl=captured.ttl=1;
    gb::wire::Bytes left,right;
    return gb::wire::ii::pack({observed},left,minor)==gb::wire::Error::Ok&&
        gb::wire::ii::pack({captured},right,minor)==gb::wire::Error::Ok&&left==right;
}
}
struct GeneralBrokerHost::OwnedFacts {
    PendingServiceContext service;
    gb::wire::Id sourceConnection{};
    std::shared_ptr<const gb::ipc::ii::ReadPeerLease> sourcePeer;
    gb::wire::ii::PendingRecord record;
    Id128 token{};
    std::uint64_t generation=0;
    L::detail::OpenFile pin;
    L::Snapshot facts;
    bool fileCurrent() const {
        if(!pin.file||facts.state!=L::State::Complete)return false;
        L::Binding now;DWORD error=0;
        return L::detail::bindingFor(pin.file.value,pin.binding.absolutePath,pin.binding.generation,now,error)&&
            L::sameBinding(pin.binding,now)&&L::sameBinding(facts.binding,now);
    }
};
struct GeneralBrokerHost::Data : std::enable_shared_from_this<Data> {
    QPointer<GeneralBrokerHost> host;
    std::shared_ptr<QObject> dispatcher;
    mutable std::unique_ptr<gb::ipc::ii::Client> source;
    std::unique_ptr<GeneralFactory> factory;
    Broker::Id connection{};
    std::shared_ptr<OwnedFacts> selected;
    std::shared_ptr<L::Cancellation> cancellation;
    QThread* worker=nullptr;
    QElapsedTimer peerAge;
    bool seenPeer=false;
    std::uint64_t serial=0;
    bool closed=false;
    struct ReadSource {
        PendingServiceContext context;
        gb::wire::Id connection{};
        std::shared_ptr<const gb::ipc::ii::ReadPeerLease> peer;
        gb::wire::ii::PendingRecord record;
    };
    // Adquiere observaciones actuales del MISMO canal, nunca del cache de la GUI.
    std::optional<ReadSource> readSource(const Id128& request) const;
    bool sourceCurrent(const OwnedFacts& owner) const {
        if(closed||!owner.sourcePeer||owner.sourcePeer->checkLive()!=gb::ipc::ii::ReadPeerState::Current||!owner.fileCurrent())return false;
        const auto observation=readSource(owner.record.request);
        return !closed&&observation&&observation->context==owner.service&&observation->peer&&
            observation->peer->checkLive()==gb::ipc::ii::ReadPeerState::Current&&
            owner.sourcePeer&&owner.sourcePeer->checkLive()==gb::ipc::ii::ReadPeerState::Current&&
            observation->connection==owner.sourceConnection&&sameRecord(observation->record,owner.record,3)&&owner.fileCurrent();
    }
    bool current(const FullBinding& binding) const {
        const auto owner=selected;
        if(!owner||!factory||binding.requestId!=requestName(owner->record.request)||
            binding.applicationToken!=owner->record.selector||binding.snapshotRevision!=owner->record.authority||
            binding.serviceEpoch!=owner->service.engineBindingGeneration||binding.generation!=owner->record.profileGeneration||
            binding.localSnapshotToken!=owner->token||binding.localSnapshotGeneration!=owner->generation||!sourceCurrent(*owner))return false;
        const auto view=factory->status();const auto& config=view.local;const auto& epochs=config.epochs;
        const bool matching=config.search&&binding.sessionEpoch==epochs.session&&binding.retrievalEpoch==epochs.retrieval&&
            binding.providerPolicyEpoch==epochs.providerPolicy&&binding.credentialEpoch==epochs.credential&&
            binding.modelConsentEpoch==epochs.modelConsent&&binding.webConsentEpoch==epochs.webConsent&&
            binding.entitlementPolicyEpoch==epochs.entitlement&&unsigned(binding.provider)==config.search->provider&&
            binding.providerConfiguration==config.search->configurationBinding&&binding.providerInstance==std::string(config.search->instanceToken.data(),38);
        return matching&&selected==owner&&!closed&&sourceCurrent(*owner);
    }
    void retire(){
        selected.reset();if(cancellation)cancellation->requested=true;
        if(serial==UINT64_MAX)closed=true;else ++serial;
    }
    void resolve(const Id128& request,GeneralFactory::PendingResolver::Completion completion){
        retire();
        if(closed||worker||!host){completion({});return;}
        const auto observation=readSource(request);
        if(!observation||!observation->peer||observation->peer->checkLive()!=gb::ipc::ii::ReadPeerState::Current||
            !observation->record.authority||!observation->record.selectorRevision||!observation->record.profileGeneration||
            !observation->context.engineBindingGeneration){completion({});return;}
        auto owner=std::make_shared<OwnedFacts>();owner->service=observation->context;owner->record=observation->record;owner->generation=serial;
        owner->sourceConnection=observation->connection;owner->sourcePeer=observation->peer;
        if(!Broker::randomId(owner->token)){completion({});return;}
        cancellation=std::make_shared<L::Cancellation>();const auto cancelled=cancellation;
        const auto path=text(owner->record.path).toStdWString();const auto before=serial;
        const auto self=shared_from_this();
        worker=QThread::create([owner,path,cancelled]{
            DWORD error=0;L::Request request{path,owner->generation,{}};
            const auto opened=L::detail::openLocal(request,owner->pin,error);
            if(opened!=L::State::Complete||cancelled->requested){owner->facts.state=opened;return;}
            request.expected=owner->pin.binding;
            // Sin inventario protegido, el backend conserva Unavailable.
            L::WindowsSignatureBackend signature({});
            owner->facts=L::inspect(request,{},*cancelled,signature);
        });
        const auto thread=worker;
        QObject::connect(thread,&QThread::finished,thread,&QObject::deleteLater);
        QObject::connect(thread,&QThread::finished,dispatcher.get(),[self,owner,before,cancelled,completion=std::move(completion),thread]() mutable {
            Q_UNUSED(thread);self->worker=nullptr;self->cancellation.reset();
            if(self->closed||self->serial!=before||cancelled->requested||!self->sourceCurrent(*owner)){completion({});return;}
            self->selected=owner;
            PendingPresentationContext view(owner->service,owner->record.request,owner->record.selector,
                owner->record.authority,owner->record.selectorRevision,owner->record.profileGeneration,owner->token,owner->generation);
            const std::weak_ptr<Data> weak=self;
            auto owned=std::shared_ptr<const OwnedPendingPresentation>(new OwnedPendingPresentation(
                std::move(view),self->connection,owner,[weak,owner]{const auto state=weak.lock();
                    return state&&state->selected==owner&&state->sourceCurrent(*owner);}));
            if(self->serial!=before||!self->sourceCurrent(*owner)){self->retire();completion({});return;}
            completion(std::move(owned));
        });
        worker->start();
    }
    void close(){
        if(closed&&!factory&&!source)return;
        retire();closed=true;if(factory)factory->close();if(source)source->close();
        factory.reset();
    }
};
std::optional<GeneralBrokerHost::Data::ReadSource> GeneralBrokerHost::Data::readSource(const Id128& request) const {
    using namespace gb::wire;
    if(closed||zero(request))return {};
    if(!source){
        source=std::make_unique<gb::ipc::ii::Client>(3);
        const auto image=QDir(QCoreApplication::applicationDirPath()).filePath("GateBouncerService.exe");
        if(!source->open(false,std::filesystem::path(image.toStdWString()))){source.reset();return {};}
    }
    const auto peer=source->readonlyPeer();
    auto rejected=[this]()->std::optional<ReadSource>{source->close();source.reset();return {};};
    if(!peer||peer->checkLive()!=gb::ipc::ii::ReadPeerState::Current)return rejected();
    const auto connection=peer->connection();QElapsedTimer age;age.start();
    auto transact=[&](Frame query,Frame& reply,Type expected){
        query.minor=3;query.connection=connection;
        return !closed&&age.elapsed()<5000&&peer->checkLive()==gb::ipc::ii::ReadPeerState::Current&&
            source->transact(std::move(query),reply)&&age.elapsed()<5000&&reply.type==expected&&
            reply.minor==3&&reply.connection==connection&&validate(reply)==gb::wire::Error::Ok&&
            peer->checkLive()==gb::ipc::ii::ReadPeerState::Current;
    };
    Frame before,query;query.type=Type::GetStatus;
    gb::wire::iv::ServiceContext first{},last{};
    if(!transact(query,before,Type::Status)||gb::wire::iv::decodeServiceContext(before,first)!=gb::wire::Error::Ok||
        !first.engineBindingGeneration)return rejected();
    ReadSource observed;observed.context={first.serviceEpoch,first.boot,first.engineContext,first.engineBindingGeneration};
    observed.connection=connection;observed.peer=peer;
    Id snapshot{};std::uint32_t cursor=0;std::uint64_t revision=0;unsigned total=0;
    std::set<Id> ids;bool found=false;
    for(unsigned page=0;page<16;++page){
        Frame rows;query.type=Type::ListPending;
        query.fields={value(Tag::ServiceEpoch,first.serviceEpoch),value(Tag::SnapshotId,snapshot),
            value(Tag::Cursor,cursor,4),value(Tag::Limit,32,2)};
        // Runtime Status-only rechaza ListPending; no se sintetiza un registro.
        if(!transact(query,rows,Type::PendingPage)||idValue(rows,Tag::ServiceEpoch)!=first.serviceEpoch||
            get(rows,Tag::Cursor)!=cursor||(!zero(snapshot)&&idValue(rows,Tag::SnapshotId)!=snapshot)||
            (cursor&&get(rows,Tag::PendingSnapshotRevision)!=revision))return rejected();
        const auto field=find(rows,Tag::Records);std::vector<gb::wire::ii::PendingRecord> records;
        if(!field||gb::wire::ii::unpack(field->bytes,get(rows,Tag::Count),records,3)!=gb::wire::Error::Ok||
            records.size()>512-total)return rejected();
        total+=unsigned(records.size());
        for(const auto& record:records){
            if(!ids.insert(record.request).second||record.state!=gb::wire::ii::RequestState::Pending||
                record.profileGeneration!=get(before,Tag::ProfileGeneration))return rejected();
            if(record.request==request){observed.record=record;found=true;}
        }
        snapshot=idValue(rows,Tag::SnapshotId);revision=get(rows,Tag::PendingSnapshotRevision);
        const auto next=get(rows,Tag::NextCursor);
        if(next==0xffffffffu)break;
        if(!records.size()||next!=cursor+records.size()||page==15)return rejected();
        cursor=std::uint32_t(next);
    }
    Frame after;query.type=Type::GetStatus;query.fields.clear();
    if(!found||!transact(query,after,Type::Status)||gb::wire::iv::decodeServiceContext(after,last)!=gb::wire::Error::Ok||
        first.serviceEpoch!=last.serviceEpoch||first.boot!=last.boot||first.engineContext!=last.engineContext||
        first.engineBindingGeneration!=last.engineBindingGeneration||
        get(before,Tag::ProfileGeneration)!=get(after,Tag::ProfileGeneration)||
        get(before,Tag::DesiredRev)!=get(after,Tag::DesiredRev))return rejected();
    const auto live=source->readonlyPeer();
    if(!live||live->connection()!=connection||live->checkLive()!=gb::ipc::ii::ReadPeerState::Current||
        peer->checkLive()!=gb::ipc::ii::ReadPeerState::Current)return rejected();
    return observed;
}
GeneralBrokerHost::GeneralBrokerHost(QObject* parent):QObject(parent),data_(std::make_shared<Data>()){
    data_->host=this;
    data_->dispatcher=std::shared_ptr<QObject>(new QObject,[](QObject* object){
        if(QThread::currentThread()==object->thread())delete object;else object->deleteLater();
    });
}
GeneralBrokerHost::~GeneralBrokerHost(){close();}
void GeneralBrokerHost::close(){data_->close();}
std::unique_ptr<GeneralBrokerHost> GeneralBrokerHost::forCurrentUser(std::unique_ptr<Broker::PipeSession> session,
    const gatebouncer::websearch::ProviderConfig& provider){
    if(!session||session->version()!=Broker::WireVersion::General3)return {};
    auto host=std::unique_ptr<GeneralBrokerHost>(new GeneralBrokerHost);const auto data=host->data_;
    data->connection=session->connection();
    const std::weak_ptr<Data> weak=data;
    GeneralFactory::PendingResolver resolver;
    resolver.resolve=[weak](const Id128& id,GeneralFactory::PendingResolver::Completion complete){
        if(const auto owner=weak.lock())owner->resolve(id,std::move(complete));else complete({});};
    resolver.retire=[weak]{if(const auto owner=weak.lock())owner->retire();};
    data->factory=GeneralFactory::forHost(std::move(session),[weak](const FullBinding& binding){
        const auto owner=weak.lock();return owner&&owner->current(binding);},provider,std::move(resolver));
    if(!data->factory)return {};
    data->peerAge.start();auto* monitor=new QTimer(host.get());monitor->setInterval(100);
    QObject::connect(monitor,&QTimer::timeout,host.get(),[weak]{
        const auto owner=weak.lock();if(!owner)return;
        if(!owner->closed&&owner->factory){
            if(owner->factory->peerCurrent())owner->seenPeer=true;
            else if(owner->seenPeer||owner->peerAge.elapsed()>6000)owner->close();
        }
        if(owner->closed&&!owner->worker)QCoreApplication::quit();
    });monitor->start();
    return host;
}
}
