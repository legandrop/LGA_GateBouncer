#include "GeneralSession.h"
#include "ObservationSelection.h"
#include <cstring>
#include <QTimer>
namespace Gate::Assistance::Ui {
namespace G=General; namespace C=Configuration;
GeneralSession::GeneralSession(std::shared_ptr<G::FrameChannel> channel,Current pending,
    std::function<bool()> presentationCurrent,gatebouncer::websearch::ProviderConfig provider,QObject* parent)
    :QObject(parent),channel_(std::move(channel)),pendingCurrent_(std::move(pending)),
     presentationCurrent_(std::move(presentationCurrent)),provider_(std::move(provider)) {
    if(!channel_||!presentationCurrent_) {closed_=true;return;}
    QPointer<GeneralSession> self(this);
    client_=std::make_unique<G::GeneralClient>(channel_,[self](const G::FullBinding& binding){
        if(!self)return false;
        const auto stamp=self->generation_;const auto predicate=self->pendingCurrent_;
        const bool valid=predicate&&predicate(binding);return self&&valid&&self->current(stamp);
    });
    auto* monitor=new QTimer(this);monitor->setInterval(250);
    connect(monitor,&QTimer::timeout,this,[self]{
        if(!self||self->closed_||(!self->busy_&&!self->view_&&!self->pendingBinding_))return;
        const auto stamp=self->generation_;
        const bool settings=self->current(stamp);if(!self)return;
        if(!settings){self->invalidate();if(!self)return;
            self->problem_="The assistance connection changed. Reconnect to view your settings.";emit self->changed();return;}
        if(self->pendingBinding_){const auto binding=*self->pendingBinding_;const auto predicate=self->pendingCurrent_;
            const bool pending=predicate&&predicate(binding);if(!self||stamp!=self->generation_)return;
            if(!pending){self->cancel();self->problem_="The pending request changed. Open its current request to explain it.";emit self->changed();}
        }
    });monitor->start();
}
GeneralSession::~GeneralSession(){close();}
bool GeneralSession::available() const {return current(generation_);}
bool GeneralSession::current(quint64 stamp) const {
    if(closed_||!client_||!channel_||stamp!=generation_||!channel_->peerCurrent())return false;
    const auto predicate=presentationCurrent_;const auto channel=channel_;QPointer<const GeneralSession> self(this);
    const bool valid=predicate();return self&&valid&&!self->closed_&&stamp==self->generation_&&channel->peerCurrent();
}
void GeneralSession::failed(const QString& text){busy_=false;approving_=false;problem_=text;emit changed();}
bool GeneralSession::adopt(const Broker::Frame& frame,bool withPresentation){
    if(!frame.fields.count(70))return false;
    const auto canonical=G::configurationView(frame.fields.at(70));if(!canonical)return false;
    std::optional<G::PresentationContext> context;
    QString model,web;
    const auto stamp=generation_;
    if(withPresentation){
        if(!frame.fields.count(76))return false;
        context=G::presentationContext(frame.fields.at(76),*canonical,channel_->connection());if(!context)return false;
        if(context->expectedModel()){
            const auto disclosure=C::ProductPublicDisclosure::lookup(*context->expectedModel(),canonical->activation.entitlementState);
            if(disclosure.cause==C::DisclosureCause::Available&&disclosure.descriptor==*context->expectedModel())
                model=QString::fromUtf8(disclosure.body);
        }
        const auto disclosure=G::publicWebDisclosure(provider_);
        if(context->expectedWeb()&&disclosure&&disclosure->descriptor()==*context->expectedWeb())
            web=QString::fromUtf8(disclosure->body());
    }
    if(!current(stamp))return false;
    if(view_&&!G::sameConfigurationView(*view_,*canonical))review_.reset();
    view_=canonical;presentation_=std::move(context);modelBody_=std::move(model);webBody_=std::move(web);return true;
}
bool GeneralSession::refresh(){
    if(busy_||!available())return false;
    busy_=true;problem_.clear();const auto stamp=generation_;QPointer<GeneralSession> self(this);
    const bool sent=client_->configurationStatus(true,[self,stamp]{return self&&self->current(stamp);},
        [self,stamp](Broker::Frame frame){
            if(!self||!self->current(stamp))return;
            if(frame.message!=Broker::Message::ConfigurationStatusReply||!self->adopt(frame,true)){
                self->view_.reset();self->presentation_.reset();self->modelBody_.clear();self->webBody_.clear();
                self->failed("Current assistance configuration is unavailable. Refresh to inspect it again.");return;
            }
            self->busy_=false;emit self->changed();
        });
    if(!sent)failed("The assistance broker is not ready. Refresh after the connection completes.");
    else emit changed();
    return sent;
}
bool GeneralSession::mutate(C::ConfigurationMutation mutation,std::shared_ptr<Broker::SensitiveBytes> secret){
    if(busy_||!view_||!available())return false;
    const auto revision=view_->local.revision;
    review_.reset();cancel();busy_=true;problem_.clear();const auto stamp=generation_;QPointer<GeneralSession> self(this);
    Broker::Frame request;request.message=Broker::Message::ConfigurationIntent;
    request.fields[71]=Broker::integer(unsigned(mutation.verb),1);request.fields[73]=Broker::integer(revision,8);
    const bool sent=client_->control(std::move(request),[self,stamp,revision,mutation,secret](Broker::Frame reply) mutable {
        if(!self||!self->current(stamp))return;
        if(reply.message!=Broker::Message::ConfigurationIntentReply||!reply.fields.count(72)||
           !reply.fields.count(73)||Broker::number(reply.fields.at(73))!=revision){self->failed("Configuration changed. Refresh before trying again.");return;}
        C::ConfigurationIntent intent;intent.verb=mutation.verb;intent.revision=revision;
        if(reply.fields.at(72).size()!=16){self->failed("The broker returned an invalid configuration intent.");return;}
        std::memcpy(intent.capability.data(),reply.fields.at(72).constData(),16);
        auto completed=[self,stamp](Broker::Frame ack){if(self)self->completeMutation(std::move(ack),stamp);};
        bool accepted=false;
        if(mutation.verb==C::ConfigurationVerb::Store&&secret)
            accepted=self->client_->storeCredential(intent,std::move(*secret),std::move(completed));
        else {
            Broker::Frame update;update.message=mutation.verb==C::ConfigurationVerb::Forget?
                Broker::Message::ForgetCredential:Broker::Message::UpdateConfiguration;
            update.fields[72]=reply.fields.at(72);update.fields[73]=reply.fields.at(73);
            if(update.message==Broker::Message::UpdateConfiguration){const auto bytes=G::configurationBytes(mutation);
                if(!bytes){self->failed("The configuration selection is invalid.");return;}update.fields[74]=*bytes;}
            accepted=self->client_->control(std::move(update),std::move(completed));
        }
        if(!accepted)self->failed("The configuration update was not sent. Refresh before trying again.");
    });
    if(!sent)failed("The configuration intent was not sent.");else emit changed();return sent;
}
void GeneralSession::completeMutation(Broker::Frame frame,quint64 stamp){
    if(!current(stamp))return;
    if(frame.message!=Broker::Message::ConfigurationAck||!frame.fields.count(75)||!adopt(frame,false)){
        view_.reset();presentation_.reset();failed("The update could not be confirmed. Refresh; it will not be retried automatically.");return;
    }
    busy_=false;
    if(Broker::number(frame.fields.at(75))!=unsigned(C::ConfigFailure::None)){
        failed("The broker rejected the update. The displayed state is its readback.");return;
    }
    refresh();
}
bool GeneralSession::store(Broker::SensitiveBytes secret){
    if(!secret.size()||secret.size()>512){failed("Enter a nonempty API key with at most 512 ASCII characters.");return false;}
    for(std::size_t n=0;n<secret.size();++n)if(secret.data()[n]<33||secret.data()[n]>126){
        failed("The API key must contain printable ASCII characters without spaces.");return false;
    }
    C::ConfigurationMutation mutation;mutation.verb=C::ConfigurationVerb::Store;
    return mutate(mutation,std::make_shared<Broker::SensitiveBytes>(std::move(secret)));
}
bool GeneralSession::forget(){C::ConfigurationMutation mutation;mutation.verb=C::ConfigurationVerb::Forget;return mutate(mutation);}
bool GeneralSession::mode(C::ModeChoice choice){C::ConfigurationMutation mutation;mutation.verb=C::ConfigurationVerb::Mode;mutation.mode=choice;return mutate(mutation);}
bool GeneralSession::serviceUse(C::ServiceUse choice){C::ConfigurationMutation mutation;mutation.verb=C::ConfigurationVerb::ServiceUse;mutation.serviceUse=choice;return mutate(mutation);}
bool GeneralSession::selectSearch(){
    if(!presentation_||!presentation_->searchReference())return false;
    C::ConfigurationMutation mutation;mutation.verb=C::ConfigurationVerb::Search;mutation.search=presentation_->searchReference();
    mutation.search->providerPolicyEpoch=0;mutation.search->webConsentEpoch=0;
    return mutate(mutation);
}
bool GeneralSession::consent(C::ConsentTarget target,bool granted){
    if(!presentation_||!view_)return false;
    C::ConfigurationMutation mutation;mutation.verb=C::ConfigurationVerb::Consent;mutation.target=target;
    mutation.receipt.epoch=0;
    if(granted){
        const auto& expected=target==C::ConsentTarget::Model?presentation_->expectedModel():presentation_->expectedWeb();
        if(!expected||(target==C::ConsentTarget::Model?modelBody_:webBody_).isEmpty())return false;
        mutation.receipt=*expected;mutation.receipt.granted=true;
    }
    return mutate(mutation);
}
std::optional<G::FullBinding> GeneralSession::pendingBinding() const {
    if(!pendingBinding_||!pendingCurrent_||!available())return {};
    const auto binding=*pendingBinding_;const auto predicate=pendingCurrent_;const auto stamp=generation_;
    QPointer<const GeneralSession> self(this);const bool valid=predicate(binding);
    return self&&valid&&self->current(stamp)&&self->pendingBinding_&&*self->pendingBinding_==binding?
        std::optional<G::FullBinding>(binding):std::nullopt;
}
bool GeneralSession::selectPending(const G::Id128& request,G::PendingServiceContext service){
    if(busy_||!pendingCurrent_||!available()||!G::pendingQueryBytes(request)||!G::validPendingService(service))return false;
    review_.reset();cancel();busy_=true;problem_.clear();const auto stamp=generation_;QPointer<GeneralSession> self(this);
    const bool sent=client_->pendingStatus(request,service,[self,stamp]{return self&&self->current(stamp);},
        [self,stamp,request,service](Broker::Frame frame){
            if(!self||!self->current(stamp))return;
            const auto pending=frame.fields.count(77)?G::pendingPresentationContext(frame.fields.at(77)):std::nullopt;
            if(frame.message!=Broker::Message::ConfigurationStatusReply||!pending||pending->request()!=request||
                !(pending->service()==service)||!self->adopt(frame,true)||!self->view_||!self->presentation_){
                self->failed("The current pending request is unavailable. Your request remains undecided.");return;
            }
            const auto binding=G::pendingFullBinding(*pending,*self->presentation_,*self->view_,self->channel_->connection());
            if(!binding){self->failed("The current request cannot be explained with this configuration.");return;}
            const auto predicate=self->pendingCurrent_;const bool valid=predicate&&predicate(*binding);
            if(!self||!self->current(stamp))return;
            if(!valid){self->failed("The pending request changed. Your request remains undecided.");return;}
            self->pendingPresentation_=pending;self->pendingBinding_=binding;self->busy_=false;self->state_=G::State::Insufficient;emit self->changed();
        });
    if(!sent)failed("The current request could not be read. Your request remains undecided.");else emit changed();
    return sent;
}
std::optional<G::Destination> GeneralSession::observedDestination() const {
    const auto stamp=generation_;QPointer<const GeneralSession> self(this);
    const auto binding=pendingBinding();
    return self&&binding&&self->generation_==stamp&&self->pendingPresentation_?self->pendingPresentation_->destination():std::nullopt;
}
bool GeneralSession::publicReviewCurrent() const {
    if(!review_||!view_||!presentation_||!pendingCurrent_||!available())return false;
    const auto review=*review_;const auto stamp=generation_;const auto predicate=pendingCurrent_;
    if(review.connection!=channel_->connection())return false;
    const auto pending=G::pendingPresentationContext(review.pendingBytes);
    const auto binding=pending?G::pendingFullBinding(*pending,*presentation_,*view_,review.connection):std::nullopt;
    if(!binding||*binding!=review.binding||!G::validPublicFields(review.fields))return false;
    QPointer<const GeneralSession> self(this);const bool valid=predicate(review.binding);
    return self&&valid&&self->current(stamp)&&self->review_&&self->review_->binding==review.binding&&
        self->review_->fields==review.fields&&self->review_->pendingBytes==review.pendingBytes;
}
bool GeneralSession::clearPublicReview(){
    if(busy_||closed_||generation_==UINT64_MAX||state_==G::State::Uncertain||!client_||
        !client_->settled()||!channel_||!view_||!presentation_||!pendingPresentation_){
        review_.reset();cancel();return false;
    }
    QPointer<GeneralSession> self(this);const auto before=generation_,expected=before+1;
    const auto client=client_.get();const auto channel=channel_;const auto connection=channel->connection();
    const auto config=*view_;const auto presentation=*presentation_;const auto pending=*pendingPresentation_;
    const auto bytes=G::pendingPresentationBytes(pending);
    const auto presentationBytes=G::presentationBytes(presentation,config,connection);
    const auto binding=pendingBinding();
    auto unchanged=[self,client,channel,connection,config,presentationBytes](quint64 stamp){
        return self&&self->generation_==stamp&&!self->busy_&&!self->closed_&&self->client_.get()==client&&
            client->settled()&&self->channel_==channel&&channel->connection()==connection&&channel->peerCurrent()&&self&&
            self->view_&&G::sameConfigurationView(*self->view_,config)&&self->presentation_&&presentationBytes&&
            G::presentationBytes(*self->presentation_,*self->view_,connection)==presentationBytes;
    };
    if(!self||!binding||!bytes||!unchanged(before)||!pendingPresentation_||
        G::pendingPresentationBytes(*pendingPresentation_)!=bytes)return false;
    cancel();if(!self||!unchanged(expected))return false;
    review_.reset();const auto predicate=pendingCurrent_;const bool valid=predicate&&predicate(*binding);
    if(!self||!valid||!unchanged(expected))return false;
    // Sólo presentación ya entregada, sin operación ni cancelación en wire.
    pendingPresentation_=pending;pendingBinding_=binding;state_=G::State::Insufficient;emit changed();
    return self&&unchanged(expected)&&self->pendingBinding_==binding&&self->pendingPresentation_&&
        G::pendingPresentationBytes(*self->pendingPresentation_)==bytes;
}
bool GeneralSession::reviewLocalApplication(const OrdinaryDecisionClient& source){
    QPointer<GeneralSession> self(this);QPointer<const OrdinaryDecisionClient> original(&source);
    const auto observed=currentObservation(original.data());const auto binding=pendingBinding();
    if(!self||!original||!observed||!binding||!pendingPresentation_||
        !(pendingPresentation_->service()==observed->service)||!observed->matches(*binding))return false;
    // Sólo basename entregado por el productor actual; no es ProductName ni publisher verificado.
    const auto& name=observed->record.display.name;
    G::PublicFields fields{std::string(name.begin(),name.end()),{},std::string(name.begin(),name.end())};
    const auto after=currentObservation(original.data());
    if(!G::validPublicFields(fields)||!after||!(*after==*observed))return false;
    const bool reviewed=reviewPublicFields(std::move(fields));
    if(!self||!original)return false;
    const auto current=currentObservation(original.data());
    if(!current||!(*current==*observed)){cancel();return false;}
    return reviewed;
}
bool GeneralSession::reviewPublicFields(G::PublicFields fields){
    if(busy_||!pendingPresentation_||!G::validPublicFields(fields))return false;
    QPointer<GeneralSession> self(this);const auto before=generation_;
    const auto binding=pendingBinding();if(!self||!binding||before!=generation_||!pendingPresentation_)return false;
    const auto original=pendingPresentation_->destination();
    if(fields.destination&&(!original||!(*fields.destination==*original)))return false;
    if(original&&G::validDestination(*original,true))fields.destination=original;
    else fields.destination.reset();
    if(!G::validPublicFields(fields))return false;
    const auto bytes=G::pendingPresentationBytes(*pendingPresentation_);if(!bytes||before==UINT64_MAX)return false;
    const auto stamp=before+1;
    if(!clearPublicReview()||!self||generation_!=stamp||!pendingBinding_||*pendingBinding_!=*binding||
        !pendingPresentation_||G::pendingPresentationBytes(*pendingPresentation_)!=bytes)return false;
    review_=PublicReview{*binding,std::move(fields),*bytes,channel_->connection()};
    const bool valid=publicReviewCurrent();if(!self||stamp!=generation_)return false;
    if(!valid){review_.reset();return false;}
    // La revisión declara texto público; los consentimientos y derechos se comprueban aparte.
    if(view_->local.mode==C::ModeChoice::Automatic)explainReviewed();
    if(self&&stamp==generation_)emit changed();
    return true;
}
bool GeneralSession::explainReviewed(){
    if(busy_||!publicReviewCurrent()||!view_||!presentation_)return false;
    const auto canonical=*view_;const auto& config=canonical.local;
    const auto matching=[](const C::ConsentReceipt& actual,const std::optional<C::ConsentReceipt>& expected,std::uint64_t epoch){
        if(!expected||!actual.granted||actual.epoch!=epoch||!C::validReceipt(actual))return false;
        auto descriptor=actual;descriptor.granted=false;descriptor.epoch=0;return descriptor==*expected;
    };
    if(!matching(config.modelConsent,presentation_->expectedModel(),config.epochs.modelConsent)||
        !matching(config.webConsent,presentation_->expectedWeb(),config.epochs.webConsent)||
        !canonical.activation.technicallyAvailable||
        canonical.activation.cause!=C::ActivationCause::Ready)return false;
    const auto review=*review_;
    // 23/24 registra el texto ya revisado para este snapshot: no solicita otra decisión del usuario.
    return registerPublic(review.binding,review.fields,true);
}
bool GeneralSession::approvePublic(G::FullBinding binding,G::PublicFields fields){
    return registerPublic(std::move(binding),std::move(fields),false);
}
bool GeneralSession::registerPublic(G::FullBinding binding,G::PublicFields fields,bool startAfterRegistration){
    if(!pendingCurrent_){failed("Connect to the current pending request before approving a public query.");return false;}
    if(busy_||!view_||!available())return false;
    const auto predicate=pendingCurrent_;const auto before=generation_;QPointer<GeneralSession> guarded(this);
    const bool valid=predicate(binding);if(!guarded||!valid||!guarded->current(before))return false;
    const auto projection=pendingBinding_&&*pendingBinding_==binding?pendingPresentation_:std::nullopt;
    cancel();pendingBinding_=binding;pendingPresentation_=projection;busy_=true;approving_=true;problem_.clear();state_=G::State::Searching;const auto stamp=generation_;QPointer<GeneralSession> self(this);
    const bool sent=client_->approve(binding,fields,[self,stamp,startAfterRegistration](std::optional<G::ApprovedPublicContext> approval,G::Failure failure){
        if(!self||!self->current(stamp))return;
        if(!approval||failure!=G::Failure::None){self->state_=G::State::Failed;self->failed("The public query is no longer approved for this request.");return;}
        self->public_=std::move(approval);self->busy_=false;self->approving_=false;
        if(startAfterRegistration||(self->view_&&self->view_->local.mode==C::ModeChoice::Automatic))self->explainApproved();
        else {self->state_=G::State::Insufficient;emit self->changed();}
    });
    if(!sent){state_=G::State::Failed;failed("The public query could not be approved. Your request remains undecided.");}
    else emit changed();
    return sent;
}
bool GeneralSession::explainApproved(){
    if(busy_||!public_||!pendingCurrent_||!available())return false;
    const auto context=*public_;const auto predicate=pendingCurrent_;const auto stamp=generation_;QPointer<GeneralSession> self(this);
    if(!predicate(context.binding)||!self||!self->current(stamp))return false;
    public_.reset();busy_=true;state_=G::State::Searching;
    const bool started=client_->explain(context.binding,context.fields,[self,stamp](G::Result result){
        if(!self||!self->current(stamp))return;
        const auto predicate=self->pendingCurrent_;const bool valid=predicate(result.binding);
        if(!self||!self->current(stamp))return;
        if(!valid){self->cancel();self->problem_="The pending request changed. Your request remains undecided.";emit self->changed();return;}
        self->busy_=false;self->state_=result.state;self->result_=std::move(result);emit self->changed();
    },[self,stamp](G::State state){if(self&&self->current(stamp)){self->state_=state;emit self->changed();}});
    if(!started){state_=G::State::Failed;failed("The explanation could not start. Your request remains undecided.");}
    else emit changed();
    return started;
}
bool GeneralSession::explain(G::FullBinding binding,G::PublicFields fields){return approvePublic(std::move(binding),std::move(fields));}
void GeneralSession::cancel(){
    if(generation_==UINT64_MAX){close();return;}
    ++generation_;busy_=false;approving_=false;result_.reset();public_.reset();review_.reset();pendingBinding_.reset();pendingPresentation_.reset();state_=G::State::Cancelled;
    if(client_)client_->cancel();
}
void GeneralSession::invalidate(){review_.reset();cancel();view_.reset();presentation_.reset();modelBody_.clear();webBody_.clear();emit changed();}
void GeneralSession::close(){if(closed_)return;closed_=true;busy_=false;approving_=false;result_.reset();public_.reset();pendingBinding_.reset();view_.reset();presentation_.reset();
    pendingPresentation_.reset();review_.reset();
    modelBody_.clear();webBody_.clear();if(client_)client_->close();client_.reset();channel_.reset();}
}
