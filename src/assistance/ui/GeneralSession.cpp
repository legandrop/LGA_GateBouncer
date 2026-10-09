#include "GeneralSession.h"
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
    cancel();busy_=true;problem_.clear();const auto stamp=generation_;QPointer<GeneralSession> self(this);
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
bool GeneralSession::approvePublic(G::FullBinding binding,G::PublicFields fields){
    if(!pendingCurrent_){failed("Connect to the current pending request before approving a public query.");return false;}
    if(busy_||!view_||!available())return false;
    const auto predicate=pendingCurrent_;const auto before=generation_;QPointer<GeneralSession> guarded(this);
    const bool valid=predicate(binding);if(!guarded||!valid||!guarded->current(before))return false;
    cancel();pendingBinding_=binding;busy_=true;approving_=true;problem_.clear();state_=G::State::Searching;const auto stamp=generation_;QPointer<GeneralSession> self(this);
    const bool sent=client_->approve(binding,fields,[self,stamp](std::optional<G::ApprovedPublicContext> approval,G::Failure failure){
        if(!self||!self->current(stamp))return;
        if(!approval||failure!=G::Failure::None){self->state_=G::State::Failed;self->failed("The public query is no longer approved for this request.");return;}
        self->public_=std::move(approval);self->busy_=false;self->approving_=false;
        if(self->view_&&self->view_->local.mode==C::ModeChoice::Automatic)self->explainApproved();
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
    ++generation_;busy_=false;approving_=false;result_.reset();public_.reset();pendingBinding_.reset();state_=G::State::Cancelled;
    if(client_)client_->cancel();
}
void GeneralSession::invalidate(){cancel();view_.reset();presentation_.reset();modelBody_.clear();webBody_.clear();emit changed();}
void GeneralSession::close(){if(closed_)return;closed_=true;busy_=false;approving_=false;result_.reset();public_.reset();pendingBinding_.reset();view_.reset();presentation_.reset();
    modelBody_.clear();webBody_.clear();if(client_)client_->close();client_.reset();channel_.reset();}
}
