#include "GeneralBrokerHost.h"
#include "../general/PendingPresentationContext.h"
#include "client_ii_win.h"
#include "../general/ObservationReader.h"
#include "../../localfacts/WinFile.h"
#include "../../../controller/deployment_win.h"
#include <QPointer>
#include <QThread>
#include <QUuid>
#include <QTimer>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QDir>
#include <QDateTime>
#include <algorithm>
#include <set>

namespace Gate::Assistance::General {
namespace L=gatebouncer::localfacts;
namespace {
QString text(const gb::wire::Bytes& bytes){return QString::fromUtf8(
    reinterpret_cast<const char*>(bytes.data()),qsizetype(bytes.size()));}
std::string requestName(const Id128& id){return QUuid::fromRfc4122(QByteArray(
    reinterpret_cast<const char*>(id.data()),16)).toString().toStdString();}
LocalSignatureStatus localSignature(L::SignatureState state){
    switch(state){
    case L::SignatureState::VerifiedOffline:return LocalSignatureStatus::VerifiedOffline;
    case L::SignatureState::Unsigned:return LocalSignatureStatus::Unsigned;
    case L::SignatureState::Invalid:return LocalSignatureStatus::Invalid;
    case L::SignatureState::TimedOut:return LocalSignatureStatus::TimedOut;
    case L::SignatureState::Cancelled:return LocalSignatureStatus::Cancelled;
    default:return LocalSignatureStatus::Unavailable;
    }
}

}
struct GeneralBrokerHost::OwnedFacts {
    PendingServiceContext service;
    gb::wire::Id sourceConnection{};
    std::shared_ptr<const gb::ipc::ii::ReadPeerLease> sourcePeer;
    gb::wire::iv::ObservedRecord record;
    std::uint64_t profile=0,desired=0;
    gb::wire::Bytes destinationContext;
    std::optional<Destination> destination;
    std::optional<PrincipalObservationContext> principal;
    gb::wire::Bytes originalTarget;
    Id128 token{};
    std::uint64_t generation=0;
    L::detail::OpenFile pin;
    L::Snapshot facts;
    std::uint64_t checkedAtMs=0;
    bool fileCurrent() const {
        if(!pin.file||facts.state!=L::State::Complete)return false;
        L::Binding now;DWORD error=0;
        return L::detail::bindingFor(pin.file.value,pin.binding.absolutePath,pin.binding.generation,now,error)&&
            L::sameBinding(pin.binding,now)&&L::sameBinding(facts.binding,now);
    }
    std::optional<LocalFilePresentation> localPresentation() const {
        if(!fileCurrent()||!checkedAtMs)return {};
        // FILETIME es fecha de modificación, no fecha de comprobación ni de firma.
        constexpr std::uint64_t windowsEpoch=116444736000000000ULL;
        LocalFilePresentation view{facts.binding.size,facts.binding.modified>=windowsEpoch?
            (facts.binding.modified-windowsEpoch)/10000:0,checkedAtMs,localSignature(facts.signature.state),{}};
        if(view.signature==LocalSignatureStatus::VerifiedOffline){
            const auto publisher=QString::fromStdWString(facts.signature.publisherLocal).toUtf8().toStdString();
            if(safeText(publisher,1024,true))view.publisher=publisher;
        }
        return validLocalFilePresentation(view)&&fileCurrent()?std::optional<LocalFilePresentation>(std::move(view)):std::nullopt;
    }
};
struct GeneralBrokerHost::Data : std::enable_shared_from_this<Data> {
    QPointer<GeneralBrokerHost> host;
    std::shared_ptr<QObject> dispatcher;
    mutable std::unique_ptr<gb::ipc::ii::Client> source;
    std::unique_ptr<GeneralFactory> factory;
    std::shared_ptr<gb::controller::Deployment> deployment;
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
        gb::wire::iv::ObservedRecord record;
        std::uint64_t profile=0,desired=0;
        gb::wire::Bytes destinationContext;
        std::optional<Destination> destination;
        std::optional<PrincipalObservationContext> principal;
        gb::wire::Bytes originalTarget;
    };
    // Adquiere observaciones actuales del MISMO canal, nunca del cache de la GUI.
    std::optional<ReadSource> readSource(const PendingQuerySelection&) const;
    bool sourceCurrent(const OwnedFacts& owner) const {
        if(closed||!deployment||!deployment->current()||!owner.sourcePeer||owner.sourcePeer->checkLive()!=gb::ipc::ii::ReadPeerState::Current||!owner.fileCurrent())return false;
        const auto observation=readSource({owner.record.observed,owner.principal?owner.principal->owner:Id128{},
            owner.principal?owner.record.revision:0});
        return !closed&&observation&&observation->context==owner.service&&observation->peer==owner.sourcePeer&&
            observation->peer->checkLive()==gb::ipc::ii::ReadPeerState::Current&&
            owner.sourcePeer&&owner.sourcePeer->checkLive()==gb::ipc::ii::ReadPeerState::Current&&
            observation->connection==owner.sourceConnection&&observation->profile==owner.profile&&observation->desired==owner.desired&&
            observation->destinationContext==owner.destinationContext&&observation->destination==owner.destination&&
            observation->principal==owner.principal&&observation->originalTarget==owner.originalTarget&&
            ObservationReader::sameRecord(observation->record,owner.record)&&owner.fileCurrent()&&deployment->current();
    }
    bool current(const FullBinding& binding) const {
        const auto owner=selected;
        if(!owner||!factory||binding.requestId!=requestName(owner->record.observed)||
            binding.applicationToken!=owner->record.binding||binding.snapshotRevision!=owner->record.revision||
            binding.serviceEpoch!=owner->service.engineBindingGeneration||binding.generation!=owner->profile||
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
    void resolve(const PendingQuerySelection& request,GeneralFactory::PendingResolver::Completion completion){
        retire();
        if(closed||worker||!host||!deployment||!deployment->current()){completion({});return;}
        const auto observation=readSource(request);
        if(!observation||!observation->peer||observation->peer->checkLive()!=gb::ipc::ii::ReadPeerState::Current||
            !observation->record.revision||!observation->profile||
            !observation->context.engineBindingGeneration){completion({});return;}
        auto owner=std::make_shared<OwnedFacts>();owner->service=observation->context;owner->record=observation->record;owner->profile=observation->profile;owner->desired=observation->desired;owner->generation=serial;
        owner->sourceConnection=observation->connection;owner->sourcePeer=observation->peer;
        owner->destinationContext=observation->destinationContext;owner->destination=observation->destination;
        owner->principal=observation->principal;owner->originalTarget=observation->originalTarget;
        if(!Broker::randomId(owner->token)){completion({});return;}
        cancellation=std::make_shared<L::Cancellation>();const auto cancelled=cancellation;
        const auto path=text(owner->record.display.path).toStdWString();const auto before=serial;
        const auto self=shared_from_this();
        const auto package=deployment;
        worker=QThread::create([owner,path,cancelled,package]{
            if(!package->current())return;
            DWORD error=0;L::Request request{path,owner->generation,{}};
            const auto opened=L::detail::openLocal(request,owner->pin,error);
            if(opened!=L::State::Complete||cancelled->requested){owner->facts.state=opened;return;}
            request.expected=owner->pin.binding;
            L::WindowsSignatureBackend signature(package);
            owner->facts=L::inspect(request,{},*cancelled,signature);
            if(!package->current())owner->facts.state=L::State::Stale;
            if(!cancelled->requested&&owner->fileCurrent()){
                const auto checked=QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();
                if(checked>0)owner->checkedAtMs=std::uint64_t(checked);
            }
        });
        const auto thread=worker;
        QObject::connect(thread,&QThread::finished,thread,&QObject::deleteLater);
        QObject::connect(thread,&QThread::finished,dispatcher.get(),[self,owner,before,cancelled,completion=std::move(completion),thread]() mutable {
            Q_UNUSED(thread);self->worker=nullptr;self->cancellation.reset();
            if(self->closed||self->serial!=before||cancelled->requested||!self->sourceCurrent(*owner)){completion({});return;}
            self->selected=owner;
            PendingPresentationContext view(owner->service,owner->record.observed,owner->record.binding,
                owner->record.revision,owner->record.revision,owner->profile,owner->token,owner->generation,owner->destination,owner->localPresentation(),
                owner->principal?4:3,owner->principal);
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
        factory.reset();deployment.reset();
    }
};
std::optional<GeneralBrokerHost::Data::ReadSource> GeneralBrokerHost::Data::readSource(const PendingQuerySelection& request) const {
    if(closed||!pendingQueryBytes(request))return {};
    const auto intent=gb::wire::zero(request.owner)?gb::ipc::ii::Client::ReadIntent::OwnAccount:
        gb::ipc::ii::Client::ReadIntent::AdministrativeObservation;
    if(source&&source->readIntent()!=intent){source->close();source.reset();}
    if(!source){
        source=std::make_unique<gb::ipc::ii::Client>(3,intent);
        const auto image=QDir(QCoreApplication::applicationDirPath()).filePath("GateBouncerService.exe");
        if(!source->open(false,std::filesystem::path(image.toStdWString()))){source.reset();return {};}
    }
    std::optional<ObservationRead> expected;
    const auto owner=selected;
    if(owner&&owner->record.observed==request.request){
        expected=ObservationRead{owner->service,owner->sourceConnection,owner->sourcePeer,
            owner->record,owner->profile,owner->desired,owner->destinationContext,owner->destination,
            owner->principal,owner->originalTarget};
    }
    const auto observed=intent==gb::ipc::ii::Client::ReadIntent::AdministrativeObservation?
        ObservationReader::readPrincipal(*source,request,expected?&*expected:nullptr):
        ObservationReader::read(*source,request.request,expected?&*expected:nullptr);
    if(closed||!observed){source->close();source.reset();return {};}
    return ReadSource{observed->service,observed->connection,observed->peer,observed->record,
        observed->profile,observed->desired,observed->destinationContext,observed->destination,
        observed->principal,observed->originalTarget};
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
    const auto image=std::filesystem::path(Broker::imagePath(GetCurrentProcess()).toStdWString());
    auto deployment=std::make_shared<gb::controller::Deployment>(image.parent_path());
    if(!deployment->verify(image,gb::controller::DeploymentRole::AssistantBroker)||!deployment->current())return {};
    auto host=std::unique_ptr<GeneralBrokerHost>(new GeneralBrokerHost);const auto data=host->data_;
    data->deployment=std::move(deployment);
    data->connection=session->connection();
    const std::weak_ptr<Data> weak=data;
    GeneralFactory::PendingResolver resolver;
    resolver.resolve=[weak](const PendingQuerySelection& id,GeneralFactory::PendingResolver::Completion complete){
        if(const auto owner=weak.lock())owner->resolve(id,std::move(complete));else complete({});};
    resolver.retire=[weak]{if(const auto owner=weak.lock())owner->retire();};
    data->factory=GeneralFactory::forHost(std::move(session),[weak](const FullBinding& binding){
        const auto owner=weak.lock();return owner&&owner->current(binding);},provider,std::move(resolver));
    if(!data->factory)return {};
    data->peerAge.start();auto* monitor=new QTimer(host.get());monitor->setInterval(100);
    QObject::connect(monitor,&QTimer::timeout,host.get(),[weak]{
        const auto owner=weak.lock();if(!owner)return;
        if(!owner->closed&&owner->factory){
            const auto selected=owner->selected;
            // El canal original se retira si desaparece la custodia; la GUI no conserva hechos como actuales.
            if(!owner->deployment||!owner->deployment->current()||(selected&&!owner->sourceCurrent(*selected)))owner->close();
            else if(owner->factory->peerCurrent())owner->seenPeer=true;
            else if(owner->seenPeer||owner->peerAge.elapsed()>6000)owner->close();
        }
        if(owner->closed&&!owner->worker)QCoreApplication::quit();
    });monitor->start();
    return host;
}
}
