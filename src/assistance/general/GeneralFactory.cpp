#include "GeneralFactory.h"
#include "GeneralRuntimeState.h"
#include "QtSearchAdapter.h"
#include "PresentationContext.h"
#include "broker/BrokerVault.h"
#include <QThread>
#include <cstring>
namespace Gate::Assistance::General {
namespace C=Configuration;
namespace Web=gatebouncer::websearch;
namespace {
bool sameDisclosure(const C::ModelDisclosure& a,const C::ModelDisclosure& b) {
    return a.source==b.source&&a.cause==b.cause&&a.evidence==b.evidence&&a.body==b.body&&
        a.descriptor==b.descriptor&&a.viewRevision==b.viewRevision;
}
std::optional<C::ConsentReceipt> modelDescriptor(const C::ModelDisclosure& model,const ConfigurationView& canonical) {
    const auto &receipt=model.descriptor;
    const bool available=model.cause==C::DisclosureCause::Available&&
        model.source==C::DisclosureSource::TrialRestricted&&model.evidence==C::EvidenceState::Restricted;
    if(!available||model.evidence!=canonical.activation.entitlementState||model.viewRevision!=canonical.local.revision||
        model.body.empty()||model.body.size()>2048||receipt.granted||receipt.epoch||!receipt.noticeRevision||
        !C::validReceipt(receipt,true)||receipt.profileRef!=canonical.local.selectedProfileRef||
        receipt.destinationPolicyBinding!=canonical.activation.destinationModelModeBinding)return {};
    const auto hash=C::digest("GB_MODEL_NOTICE_1",reinterpret_cast<const unsigned char*>(model.body.data()),model.body.size());
    return hash==receipt.noticeDigest?std::optional<C::ConsentReceipt>(receipt):std::nullopt;
}
}
struct GeneralFactory::Data : std::enable_shared_from_this<Data> {
    // Los callbacks de transporte retienen sus propios owners tras la retirada.
    std::shared_ptr<C::ConfigurationController> configuration;
    std::shared_ptr<C::WindowsConfigurationStore> store;
    std::shared_ptr<Broker::BrokerVault> vault;
    std::shared_ptr<GeneralJobRegistry> registry;
    std::shared_ptr<Web::SearchClient> search;
    std::shared_ptr<QtSearchAdapter> adapter;
    std::shared_ptr<FrameChannel> channel;
    std::shared_ptr<GeneralRuntime> runtime;
    std::unique_ptr<GeneralServer> server;
    std::optional<WebSearchDisclosure> web;
    PendingResolver pendingResolver;
    std::shared_ptr<const OwnedPendingPresentation> ownedPending;
    std::uint64_t pendingGeneration=0;
    bool pendingInFlight=false;
    Web::ProviderConfig provider;
    QThread* owner=QThread::currentThread();
    bool closed=false;
    bool localThread() const {return QThread::currentThread()==owner;}
    bool peer() const {
        const auto live=channel;if(closed||!live)return false;
        const bool current=live->peerCurrent();return current&&!closed&&channel==live;
    }
    ConfigurationView status() const {
        const auto controller=configuration;
        ConfigurationView view;view.local=controller->snapshot();
        view.activation=C::NetworkActivationIssuer(*controller).snapshot();return view;
    }
    std::optional<C::SearchBindingRef> searchReference() const {
        if(closed||!search||!runtime||!web)return {};
        const auto snapshot=configuration->snapshot();C::SearchBindingRef ref;
        ref.provider=static_cast<std::uint8_t>(provider.provider)+1;
        const auto binding=QByteArray::fromHex(search->configurationBinding()),token=search->instanceToken();
        if(binding.size()!=32||token.size()!=38)return {};
        std::memcpy(ref.configurationBinding.data(),binding.constData(),32);
        std::memcpy(ref.instanceToken.data(),token.constData(),38);
        ref.providerPolicyEpoch=snapshot.epochs.providerPolicy;ref.webConsentEpoch=snapshot.epochs.webConsent;
        return C::validSearch(ref)?std::optional<C::SearchBindingRef>(ref):std::nullopt;
    }
    void synchronizeSearch() {
        if(closed||!search||!web)return;
        const auto snapshot=configuration->snapshot();const auto ref=searchReference();
        const auto &receipt=snapshot.webConsent;const auto &expected=web->descriptor();
        const bool matching=ref&&snapshot.search&&snapshot.search->provider==ref->provider&&
            snapshot.search->configurationBinding==ref->configurationBinding&&snapshot.search->instanceToken==ref->instanceToken&&
            receipt.granted&&receipt.noticeRevision==expected.noticeRevision&&receipt.noticeDigest==expected.noticeDigest&&
            receipt.profileRef==expected.profileRef&&receipt.destinationPolicyBinding==expected.destinationPolicyBinding&&
            receipt.epoch==snapshot.epochs.webConsent;
        if(matching)search->grantConsent(search->configurationBinding());else search->revokeConsent();
    }
    std::optional<PresentationContext> presentation(const ConfigurationView& canonical) const {
        if(!peer()||!runtime||!web)return {};
        const auto runtimeOwner=runtime;
        const auto connection=channel->connection();
        const auto model=runtimeOwner->modelDisclosure();
        const auto live=runtimeOwner->currentSearchPresentation();const auto client=searchReference();
        std::optional<C::SearchBindingRef> ref;std::optional<C::ConsentReceipt> expectedWeb;
        if(live.binding&&client&&live.binding->provider==client->provider&&
            live.binding->configurationBinding==client->configurationBinding&&live.binding->instanceToken==client->instanceToken&&
            live.binding->providerPolicyEpoch==canonical.local.epochs.providerPolicy&&client->providerPolicyEpoch==canonical.local.epochs.providerPolicy&&
            client->webConsentEpoch==canonical.local.epochs.webConsent) {
            // Authority conserva el epoch histórico del bind; presentación usa el canónico actual.
            ref=client;
            if(live.notice==web->descriptor()&&C::validReceipt(live.notice,true))expectedWeb=live.notice;
        }
        if(!peer()||channel->connection()!=connection||!sameConfigurationView(canonical,status())||
            !(live==runtimeOwner->currentSearchPresentation())||!(client==searchReference()))return {};
        const auto modelAfter=runtimeOwner->modelDisclosure();
        if(model.cause==C::DisclosureCause::ChangedDuringRead||modelAfter.cause==C::DisclosureCause::ChangedDuringRead||
            !sameDisclosure(model,modelAfter)||!sameConfigurationView(canonical,status()))return {};
        return PresentationContext(connection,canonical.local.storeInstance,canonical.local.revision,canonical.local.epochs.session,
            std::move(ref),modelDescriptor(model,canonical),std::move(expectedWeb));
    }
    void retirePending(){
        ownedPending.reset();
        if(pendingGeneration!=UINT64_MAX)++pendingGeneration;
        if(pendingResolver.retire)pendingResolver.retire();
    }
    bool publicCurrent(const FullBinding& binding,const PublicFields& fields){
        if(!fields.destination)return true;
        const auto original=ownedPending;const auto generation=pendingGeneration;
        const auto active=[&]{return !closed&&ownedPending==original&&pendingGeneration==generation;};
        if(!original||!original->lifetime_||!original->current_||!original->view_.destination()||
            !(*original->view_.destination()==*fields.destination)||!validDestination(*fields.destination,true)||!peer()||!active())return false;
        if(!original->current_()||!active())return false;
        const auto canonical=status();const auto notice=presentation(canonical);if(!active()||!notice)return false;
        const auto expected=pendingFullBinding(original->view_,*notice,canonical,original->connection_);
        if(!expected||*expected!=binding||!active())return false;
        const bool current=original->current_();return current&&active()&&peer()&&active()&&sameConfigurationView(canonical,status())&&active();
    }
    void pendingControl(Broker::Frame request,GeneralServer::PendingCompletion completion){
        auto stale=[completion]{Broker::Frame f;f.message=Broker::Message::ErrorReply;
            f.fields[23]=Broker::integer(unsigned(Failure::Stale),2);completion(std::move(f),{});};
        if(!localThread()||!peer()||pendingInFlight||!pendingResolver.resolve||!pendingResolver.retire||
            pendingGeneration==UINT64_MAX){stale();return;}
        const auto selected=pendingQuery(request.fields.at(77));
        const auto canonical=status();const auto initial=presentation(canonical);
        const auto bytes=initial?presentationBytes(*initial,canonical,request.connection):std::nullopt;
        if(!selected||!bytes){retirePending();stale();return;}
        const auto generation=++pendingGeneration;pendingInFlight=true;
        const auto d=shared_from_this();const auto once=std::make_shared<bool>(false);
        auto finish=[d,generation,selected=*selected,canonical,notice=*bytes,completion,stale,once](std::shared_ptr<const OwnedPendingPresentation> owner){
            if(*once)return;
            *once=true;d->pendingInFlight=false;
            if(d->closed||d->pendingGeneration!=generation){stale();return;}
            if(!owner||!owner->lifetime_||!owner->current_||owner->view_.request()!=selected||
                !d->channel||owner->connection_!=d->channel->connection()){d->retirePending();stale();return;}
            auto current=[d,owner,generation,canonical,notice]{
                const auto channel=d->channel;
                const auto active=[&]{return !d->closed&&d->pendingGeneration==generation&&channel&&d->channel==channel;};
                const auto coherent=[&]{
                    if(!active())return false;
                    const bool peer=d->peer();if(!active()||!peer)return false;
                    const auto configuration=d->status();
                    if(!active()||!sameConfigurationView(canonical,configuration))return false;
                    const auto view=d->presentation(canonical);if(!active())return false;
                    const auto bytes=view?presentationBytes(*view,canonical,channel->connection()):std::nullopt;
                    if(!active()||!bytes||*bytes!=notice)return false;
                    const bool peerAfter=d->peer();if(!active()||!peerAfter)return false;
                    const auto configurationAfter=d->status();
                    return active()&&sameConfigurationView(canonical,configurationAfter);
                };
                if(!active()||owner->connection_!=channel->connection()||!active())return false;
                const bool first=owner->current_();if(!active()||!first||!coherent())return false;
                // Current puede reentrar una mutación real; sus bytes anteriores no autorizan el envío.
                const bool second=owner->current_();return active()&&second&&coherent();
            };
            if(!current()){if(!d->closed&&d->pendingGeneration==generation)d->retirePending();stale();return;}
            const auto pending=pendingPresentationBytes(owner->view_);const auto config=configurationBytes(canonical);
            if(!pending||!config||!current()){if(!d->closed&&d->pendingGeneration==generation)d->retirePending();stale();return;}
            Broker::Frame reply;reply.message=Broker::Message::ConfigurationStatusReply;
            reply.fields[70]=*config;reply.fields[76]=notice;reply.fields[77]=*pending;
            d->ownedPending=owner;
            completion(std::move(reply),std::move(current));
        };
        // La entrega conserva el dispatcher; un worker nunca toca el estado Qt directamente.
        const auto dispatch=runtime;
        pendingResolver.resolve(*selected,[dispatch,finish](std::shared_ptr<const OwnedPendingPresentation> owner){
            QMetaObject::invokeMethod(dispatch.get(),[dispatch,finish,owner=std::move(owner)]{finish(owner);},Qt::AutoConnection);
        });
    }
    std::optional<Broker::Frame> control(Broker::Frame request) {
        if(!localThread()||!peer()||request.connection!=channel->connection())return {};
        const auto controllerOwner=configuration;const auto storeOwner=store;const auto runtimeOwner=runtime;const auto searchOwner=search;
        const auto type=unsigned(request.message);Broker::Frame reply;
        if(type==1){
            const auto snapshot=controllerOwner->snapshot();reply.message=Broker::Message::StatusReply;
            reply.fields[1]=Broker::integer(unsigned(snapshot.credential),1);
            reply.fields[2]=Broker::integer(snapshot.mode==C::ModeChoice::Automatic?1:2,1);
            reply.fields[3]=Broker::integer(snapshot.epochs.session,8);reply.fields[4]=Broker::integer(snapshot.epochs.credential,8);
            reply.fields[5]=Broker::integer(snapshot.epochs.consent,8);reply.fields[6]=Broker::integer(0,1);
            reply.fields[7]=Broker::integer(unsigned(Broker::Failure::ConfigurationNotApproved),2);return peer()?std::optional<Broker::Frame>(std::move(reply)):std::nullopt;
        }
        if(type==30){
            const auto canonical=status();const auto bytes=configurationBytes(canonical);
            if(!bytes||!peer())return {};
            reply.message=Broker::Message::ConfigurationStatusReply;reply.fields[70]=*bytes;
            if(request.fields.count(76)) {
                const auto context=presentation(canonical);
                const auto encoded=context?presentationBytes(*context,canonical,channel->connection()):std::nullopt;
                if(!encoded){reply.message=Broker::Message::ErrorReply;reply.fields.clear();reply.fields[23]=Broker::integer(unsigned(Failure::Stale),2);}
                else reply.fields[76]=*encoded;
            }
            return reply;
        }
        if(type==32){
            const auto verb=C::ConfigurationVerb(Broker::number(request.fields.at(71)));
            const auto intent=controllerOwner->intent(verb,Broker::number(request.fields.at(73)));if(!intent||!peer())return {};
            reply.message=Broker::Message::ConfigurationIntentReply;reply.fields[71]=Broker::integer(unsigned(intent->verb),1);
            reply.fields[72]=QByteArray(reinterpret_cast<const char*>(intent->capability.data()),16);reply.fields[73]=Broker::integer(intent->revision,8);return reply;
        }
        if(type!=34&&type!=35&&type!=36)return {};
        C::ConfigurationMutation mutation;
        if(type==34)mutation.verb=C::ConfigurationVerb::Store;
        else if(type==35)mutation.verb=C::ConfigurationVerb::Forget;
        else {const auto parsed=configurationUpdate(request.fields.at(74));if(!parsed)return {};mutation=*parsed;}
        C::ConfigurationIntent intent;intent.verb=mutation.verb;intent.revision=Broker::number(request.fields.at(73));
        std::memcpy(intent.capability.data(),request.fields.at(72).constData(),16);
        runtimeOwner->withdraw();searchOwner->revokeConsent();if(!peer())return {};
        C::ConfigFailure failure{};auto ticket=controllerOwner->begin(intent,mutation,std::move(request.secret),failure);
        if(!peer())return {};
        const auto result=ticket?storeOwner->apply(*controllerOwner,std::move(*ticket)):C::MutationResult{failure,controllerOwner->snapshot(),0};
        if(!peer())return {};
        synchronizeSearch();
        reply.message=Broker::Message::ConfigurationAck;const auto bytes=configurationBytes(status());if(!bytes||!peer())return {};
        reply.fields[70]=*bytes;reply.fields[75]=Broker::integer(unsigned(result.failure),2);return reply;
    }
    void close() {
        if(closed)return;
        closed=true;
        retirePending();
        if(server)server->close();else if(runtime)runtime->drain();
        if(search)search->revokeConsent();
        if(channel)channel->stop();
        server.reset();runtime.reset();adapter.reset();search.reset();channel.reset();
        registry.reset();vault.reset();store.reset();configuration.reset();
    }
};
GeneralFactory::GeneralFactory(std::shared_ptr<FrameChannel> channel,std::shared_ptr<C::ConfigurationController> configuration,
    std::shared_ptr<C::WindowsConfigurationStore> store,std::shared_ptr<Web::SearchClient> search,
    const Web::ProviderConfig& provider,GeneralCoordinator::Current current,PendingResolver resolver):data_(std::make_shared<Data>()) {
    const auto d=data_;d->channel=std::move(channel);d->configuration=std::move(configuration);d->store=std::move(store);
    d->search=std::move(search);d->provider=provider;d->web=publicWebDisclosure(provider);
    d->pendingResolver=std::move(resolver);
    if(!d->channel||!d->configuration||!d->store||!d->search||!d->web||!current||
        d->channel->version()!=Broker::WireVersion::General3||!d->search->configure(provider)){d->close();return;}
    d->vault=std::shared_ptr<Broker::BrokerVault>(Broker::BrokerVault::forLocalConfiguration(d->store));
    if(!d->vault){d->close();return;}
    d->registry=std::shared_ptr<GeneralJobRegistry>(new GeneralJobRegistry);d->adapter=std::make_shared<QtSearchAdapter>(d->search);
    const std::weak_ptr<Data> weak=d;
    d->runtime=std::shared_ptr<GeneralRuntime>(new GeneralRuntime(d->adapter,d->vault,d->configuration,d->registry,
        [weak,current=std::move(current)](const FullBinding& binding){
            const auto owner=weak.lock();if(!owner||!owner->peer())return false;
            const bool valid=current(binding);return valid&&owner->peer();
        },[]{return std::int64_t(GetTickCount64());}));
    // El peer todavía no está conectado aquí; la primera prueba ocurre tras Hello.
    const auto ref=d->searchReference();if(!ref){d->close();return;}
    auto notice=d->web->descriptor();notice.granted=true;notice.epoch=1;
    d->runtime->bindSearch(*ref,std::move(notice));
    if(!d->runtime->initializeEntitlement(d->store)){d->close();return;}
    d->server=std::make_unique<GeneralServer>(d->channel,d->runtime,[weak](Broker::Frame frame){
        const auto owner=weak.lock();return owner?owner->control(std::move(frame)):std::nullopt;
    });
    d->server->setPendingControl([weak](Broker::Frame frame,GeneralServer::PendingCompletion completion){
        if(const auto owner=weak.lock())owner->pendingControl(std::move(frame),std::move(completion));
    },[weak]{if(const auto owner=weak.lock())owner->retirePending();});
    d->server->setPublicControl([weak](const FullBinding& b,const PublicFields& p){const auto owner=weak.lock();return owner&&owner->publicCurrent(b,p);});
}
std::unique_ptr<GeneralFactory> GeneralFactory::forCurrentUser(std::unique_ptr<Broker::PipeSession> session,
    GeneralCoordinator::Current current,const Web::ProviderConfig& provider) {
    return forHost(std::move(session),std::move(current),provider,{});
}
std::unique_ptr<GeneralFactory> GeneralFactory::forHost(std::unique_ptr<Broker::PipeSession> session,
    GeneralCoordinator::Current current,const Web::ProviderConfig& provider,PendingResolver resolver) {
    if(!session||session->version()!=Broker::WireVersion::General3||!current||!Web::validConfiguration(provider))return {};
    auto configuration=std::shared_ptr<C::ConfigurationController>(C::ConfigurationController::forCurrentUser(session->connection()));
    if(!configuration)return {};
    auto store=std::shared_ptr<C::WindowsConfigurationStore>(C::WindowsConfigurationStore::forCurrentUser(*configuration));if(!store)return {};
    store->reload(*configuration);auto search=std::make_shared<Web::SearchClient>(Web::makeWinHttpTransport());
    auto factory=std::unique_ptr<GeneralFactory>(new GeneralFactory(std::make_shared<PipeFrameChannel>(std::move(session)),
        std::move(configuration),std::move(store),std::move(search),provider,std::move(current),std::move(resolver)));
    return factory->data_->closed?std::unique_ptr<GeneralFactory>{}:std::move(factory);
}
GeneralFactory::~GeneralFactory(){close();}
ConfigurationView GeneralFactory::status() const {return data_->configuration?data_->status():ConfigurationView{};}
std::optional<C::SearchBindingRef> GeneralFactory::searchReference() const {return data_->localThread()?data_->searchReference():std::nullopt;}
void GeneralFactory::close(){const auto owner=data_;owner->close();}
bool GeneralFactory::peerCurrent() const {return data_->localThread()&&data_->peer();}
}
