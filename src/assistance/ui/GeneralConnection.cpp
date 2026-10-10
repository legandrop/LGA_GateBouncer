#include "GeneralConnection.h"
#include "ObservationSelection.h"
#include "../broker/BrokerLauncher.h"
#include "../../mainwindow.h"
#include <QCoreApplication>
#include <QTimer>

namespace Gate::Assistance::Ui {
struct GeneralConnection::LaunchResult {std::unique_ptr<Broker::PipeSession> session;};
struct GeneralConnection::SettingsView {
    Broker::Id nonce{},connection{};
    std::uint64_t generation=0;
    QPointer<MainWindow> window;
    std::weak_ptr<General::FrameChannel> channel;
    bool retired=false;
    std::optional<ObservationSelection> selected,attempted;
    std::uint64_t attemptedConfiguration=0;
    bool publicAttempted=false;
    bool current(const Broker::Id& captured,std::uint64_t revision) const {
        const auto live=channel.lock();
        return !retired&&window&&Broker::nonzero(nonce)&&nonce==captured&&generation==revision&&
            live&&live->connection()==connection&&live->peerCurrent()&&!retired&&window;
    }
};
GeneralConnection::GeneralConnection(MainWindow& window):QObject(&window),window_(&window){
    connect(&window,&MainWindow::assistanceConnectRequested,this,&GeneralConnection::connectBroker);
    connect(window.product(),&ProductController::changed,this,&GeneralConnection::synchronizePending);
    connect(window.product(),&ProductController::invalidated,this,&GeneralConnection::synchronizePending);
}
GeneralConnection::~GeneralConnection(){
    close();
    // Launcher tiene un deadline propio de cinco segundos; no queda un hijo sin dueño.
    if(worker_){worker_->disconnect(this);worker_->wait();delete worker_;worker_=nullptr;}
    if(launch_&&launch_->session)launch_->session->stop();
}
bool GeneralConnection::idle() const{return !worker_||!worker_->isRunning();}
void GeneralConnection::close(){
    closed_=true;
    if(settings_){settings_->retired=true;if(const auto live=settings_->channel.lock())live->stop();settings_.reset();}
    if(launch_&&idle()&&launch_->session)launch_->session->stop();
}
void GeneralConnection::connectBroker(){
    if(closed_||worker_||!window_)return;
    if(settings_){settings_->retired=true;if(const auto live=settings_->channel.lock())live->stop();settings_.reset();}
    window_->setAssistance({});
    if(generation_==UINT64_MAX){close();emit failed("The assistance connection must be restarted.");return;}
    const auto serial=++generation_;
    launch_=std::make_shared<LaunchResult>();const auto result=launch_;
    auto* guiThread=QCoreApplication::instance()->thread();
    worker_=QThread::create([result,guiThread]{
        result->session=Broker::launchSiblingBroker(Broker::WireVersion::General3);
        if(result->session)result->session->moveToThread(guiThread);
    });
    const auto thread=worker_;
    connect(thread,&QThread::finished,this,[this,thread,result,serial]{
        worker_=nullptr;thread->deleteLater();launch_.reset();
        if(closed_||!window_||serial!=generation_){if(result->session)result->session->stop();return;}
        if(!result->session){emit failed("Assistance could not connect. Try connecting again.");return;}
        auto view=std::make_shared<SettingsView>();view->window=window_;view->generation=serial;
        if(!Broker::randomId(view->nonce)){result->session->stop();emit failed("Assistance could not create a safe connection.");return;}
        view->connection=result->session->connection();
        auto channel=std::make_shared<General::PipeFrameChannel>(std::move(result->session));view->channel=channel;
        settings_=view;const auto nonce=view->nonce;
        const std::weak_ptr<SettingsView> weak=view;
        auto session=std::make_unique<GeneralSession>(std::move(channel),[weak,nonce,serial](const General::FullBinding& binding){
            const auto owner=weak.lock();if(!owner||!owner->selected||!owner->current(nonce,serial))return false;
            const auto captured=*owner->selected;
            const auto actual=currentObservation(owner->window->product()->ordinary());
            if(!actual||!(*actual==captured)||!captured.matches(binding))return false;
            const auto after=currentObservation(owner->window->product()->ordinary());
            return owner->selected&&*owner->selected==captured&&after&&*after==captured&&owner->current(nonce,serial);
        },[weak,nonce,serial]{
            const auto owner=weak.lock();return owner&&owner->current(nonce,serial);
        },Broker::generalSearchConfiguration(),nullptr,[weak,nonce,serial](const General::PendingPresentationContext& pending){
            // Lectura LOCAL: mismo contexto original; no fabrica FullBinding ni habilita HTTP.
            const auto owner=weak.lock();if(!owner||!owner->selected||!owner->current(nonce,serial))return false;
            const auto captured=*owner->selected;
            const auto actual=currentObservation(owner->window->product()->ordinary());
            if(!actual||!(*actual==captured)||!captured.matches(pending))return false;
            const auto after=currentObservation(owner->window->product()->ordinary());
            return owner->selected&&*owner->selected==captured&&after&&*after==captured&&owner->current(nonce,serial);
        });
        window_->setAssistance(std::move(session));
        connect(window_->assistance(),&GeneralSession::changed,this,&GeneralConnection::synchronizePending);
        // La configuración no depende de que exista un registro pendiente canónico.
        QPointer<GeneralSession> observed=window_->assistance();auto* initial=new QTimer(this);initial->setInterval(50);
        connect(initial,&QTimer::timeout,this,[this,initial,observed,weak,nonce,serial,attempts=0]() mutable {
            const auto owner=weak.lock();
            if(closed_||serial!=generation_||!observed||!owner||owner->retired||observed->configuration()){
                initial->stop();initial->deleteLater();return;
            }
            if(++attempts>60){initial->stop();initial->deleteLater();emit failed("Connected, but settings could not be read. Refresh to try again.");return;}
            if(owner->current(nonce,serial)&&!observed->busy())observed->refresh();
        });initial->start();
    });worker_->start();
}
void GeneralConnection::synchronizePending(){
    const auto owner=settings_;if(closed_||!owner||owner->retired||!window_)return;
    QPointer<GeneralSession> session=window_->assistance();if(!session)return;
    const auto selected=window_->product()->simulation()?std::nullopt:currentObservation(window_->product()->ordinary());
    if(!selected){
        if(owner->selected){owner->selected.reset();session->cancel();}
        return;
    }
    if(owner->selected&&!(*owner->selected==*selected)){
        owner->selected.reset();session->cancel();if(!session)return;
    }
    if(session->busy()||!session->available()||!session->configuration())return;
    const auto revision=session->configuration()->local.revision;
    // Un error o Cancel no reintenta la misma selección/configuración automáticamente.
    if(owner->attempted&&*owner->attempted==*selected&&owner->attemptedConfiguration==revision){
        if(!owner->publicAttempted&&owner->selected&&*owner->selected==*selected&&session->pendingBinding()){
            // Marcar antes de changed: ni reentrada ni Cancel/error repiten este intento.
            owner->publicAttempted=true;
            session->reviewLocalApplication(*window_->product()->ordinary());
        }
        return;
    }
    owner->selected=selected;owner->attempted=selected;owner->attemptedConfiguration=revision;
    owner->publicAttempted=false;
    session->selectPending(selected->record.observed,selected->service,
        selected->principal?selected->principal->owner:General::Id128{},selected->principal?selected->record.revision:0);
}
}
