#include "ExplanationWidget.h"
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QProgressBar>
#include <QVBoxLayout>
#include <QDateTime>
namespace Gate::Assistance::Ui {
namespace G=General;
namespace {
QString utc(std::uint64_t ms){return ms?QDateTime::fromMSecsSinceEpoch(qint64(ms),Qt::UTC).toString(Qt::ISODateWithMs):QString("Unknown");}
QString signatureText(G::LocalSignatureStatus status){
    switch(status){
    case G::LocalSignatureStatus::VerifiedOffline:return "Embedded signature accepted by local offline policy";
    case G::LocalSignatureStatus::Unsigned:return "No embedded signature found";
    case G::LocalSignatureStatus::Invalid:return "Embedded signature rejected by local offline policy";
    case G::LocalSignatureStatus::TimedOut:return "Unknown · local verification timed out";
    case G::LocalSignatureStatus::Cancelled:return "Unknown · local verification cancelled";
    default:return "Unknown · local verification unavailable";
    }
}
}
ExplanationWidget::ExplanationWidget(GeneralSession* session,Binding binding,const QString& suggested,QWidget* parent)
    :QFrame(parent),binding_(std::move(binding)),observedName_(suggested){
    setObjectName("general-explanation");setProperty("role","panel");auto* layout=new QVBoxLayout(this);layout->setContentsMargins(12,12,12,12);layout->setSpacing(8);
    destination_=new QLabel("Destination: Unknown",this);destination_->setObjectName("observed-destination");destination_->setTextFormat(Qt::PlainText);destination_->setWordWrap(true);layout->addWidget(destination_);
    text_=new QLabel(this);text_->setObjectName("general-explanation-text");text_->setTextFormat(Qt::PlainText);text_->setWordWrap(true);layout->addWidget(text_);
    localSummary_=new QLabel(this);localSummary_->setObjectName("local-file-summary");localSummary_->setTextFormat(Qt::PlainText);localSummary_->setWordWrap(true);layout->addWidget(localSummary_);
    auto* notice=new QLabel("An explanation and an offline signature cannot establish safety or decide Allow or Block.",this);
    notice->setTextFormat(Qt::PlainText);notice->setWordWrap(true);notice->setProperty("role","faint");layout->addWidget(notice);
    auto* privacy=new QLabel("Sending requires setup and separate Web and Model consent. Only reviewed public names, the public destination and retrieved evidence are shared; paths, hashes and local file checks remain local. Automatic starts after setup and consent; Manual waits for Explain.",this);
    privacy->setTextFormat(Qt::PlainText);privacy->setWordWrap(true);layout->addWidget(privacy);
    product_=new QLineEdit(suggested,this);product_->setObjectName("public-product");product_->setMaxLength(96);product_->setPlaceholderText("Public product name");layout->addWidget(product_);
    publisher_=new QLineEdit(this);publisher_->setObjectName("public-publisher");publisher_->setMaxLength(96);publisher_->setPlaceholderText("Public publisher · optional, entered by you");layout->addWidget(publisher_);
    approve_=new QPushButton("Review public information",this);approve_->setObjectName("approve-public-query");layout->addWidget(approve_,0,Qt::AlignLeft);
    start_=new QPushButton("Explain application",this);start_->setObjectName("explain-approved-query");layout->addWidget(start_,0,Qt::AlignLeft);
    product_->setReadOnly(!observedName_.isEmpty());
    progress_=new QProgressBar(this);progress_->setObjectName("explanation-progress");progress_->setRange(0,0);progress_->setTextVisible(false);layout->addWidget(progress_);
    state_=new QLabel(this);state_->setObjectName("explanation-state");state_->setTextFormat(Qt::PlainText);state_->setWordWrap(true);layout->addWidget(state_);
    cancel_=new QPushButton("Cancel explanation",this);cancel_->setObjectName("cancel-general-explanation");layout->addWidget(cancel_,0,Qt::AlignLeft);
    auto* toggle=new QPushButton("Show evidence and local file details",this);toggle->setObjectName("explanation-details-toggle");toggle->setCheckable(true);layout->addWidget(toggle,0,Qt::AlignLeft);
    details_=new QWidget(this);details_->setObjectName("explanation-details");auto* detailsLayout=new QVBoxLayout(details_);detailsLayout->setContentsMargins(0,0,0,0);
    networkDetails_=new QLabel(details_);networkDetails_->setObjectName("network-evidence-details");networkDetails_->setTextFormat(Qt::PlainText);networkDetails_->setWordWrap(true);detailsLayout->addWidget(networkDetails_);
    localDetails_=new QLabel(details_);localDetails_->setObjectName("local-file-details");localDetails_->setTextFormat(Qt::PlainText);localDetails_->setWordWrap(true);detailsLayout->addWidget(localDetails_);
    citations_=new QWidget(details_);citations_->setObjectName("general-citations");detailsLayout->addWidget(citations_);
    auto* scope=new QLabel("Web: public IP registration, routing and an IP+app search. Model: reviewed public names, IP, port, protocol and retrieved evidence. Internal and reserved addresses stay local. Registration or a CDN does not identify the final service. The local certificate publisher is never filled into the public publisher field automatically.",details_);
    scope->setTextFormat(Qt::PlainText);scope->setWordWrap(true);detailsLayout->addWidget(scope);layout->addWidget(details_);details_->hide();
    connect(toggle,&QPushButton::toggled,this,[this,toggle](bool expanded){details_->setVisible(expanded);toggle->setText(expanded?"Hide evidence and local file details":"Show evidence and local file details");});
    connect(approve_,&QPushButton::clicked,this,[this]{
        if(!session_||!binding_)return;
        const auto binding=binding_();if(!binding)return;
        G::PublicFields fields;fields.product=product_->text().trimmed().toUtf8().toStdString();
        const auto publisher=publisher_->text().trimmed();if(!publisher.isEmpty())fields.publisher=publisher.toUtf8().toStdString();
        fields.query=fields.product+(fields.publisher?" "+*fields.publisher:"");
        session_->reviewPublicFields(std::move(fields));
    });
    connect(start_,&QPushButton::clicked,this,[this]{if(session_)session_->explainReviewed();});
    connect(cancel_,&QPushButton::clicked,this,[this]{if(session_){session_->cancel();refresh();}});
    auto edited=[this]{if(session_){session_->clearPublicReview();refresh();}};
    connect(product_,&QLineEdit::textEdited,this,edited);connect(publisher_,&QLineEdit::textEdited,this,edited);
    setSession(session);
}
void ExplanationWidget::setSession(GeneralSession* session){
    if(session_)disconnect(session_,nullptr,this,nullptr);
    session_=session;product_->setText(observedName_);publisher_->clear();
    if(session_)connect(session_,&GeneralSession::changed,this,&ExplanationWidget::refresh);
    refresh();
}
void ExplanationWidget::refresh(){
    QPointer<ExplanationWidget> self(this);
    const bool busy=session_&&session_->busy(),available=session_&&session_->available();
    if(!self)return;
    const auto configuration=session_?session_->configuration():std::nullopt;
    const bool configured=configuration&&configuration->activation.technicallyAvailable&&
        configuration->activation.cause==Configuration::ActivationCause::Ready;
    const auto binding=binding_?binding_():std::nullopt;
    if(!self)return;
    const auto observation=session_?session_->pendingObservation():std::nullopt;
    if(!self)return;
    auto original=observation?observation->destination():std::nullopt;
    auto local=observation?observation->localFile():std::nullopt;
    const bool reviewed=session_&&session_->publicReviewCurrent();if(!self)return;
    const auto after=session_?session_->pendingBinding():std::nullopt;if(!self)return;
    const bool same=binding&&after&&*binding==*after;
    const auto observationAfter=session_?session_->pendingObservation():std::nullopt;if(!self)return;
    const bool sameObservation=observation&&observationAfter&&G::pendingPresentationBytes(*observation)==G::pendingPresentationBytes(*observationAfter);
    if(!sameObservation){original.reset();local.reset();}
    QString destination="Destination: Unknown";
    if(original){const auto& d=*original;
        destination=QString("Destination: %1 · port %2 · %3")
            .arg(QString::fromUtf8(d.address)).arg(d.port).arg(d.protocol==6?"TCP":"UDP");}
    destination_->setText(destination);
    approve_->setEnabled(available&&!busy&&same);start_->setEnabled(available&&configured&&!busy&&same&&reviewed);cancel_->setEnabled(busy);
    product_->setEnabled(!busy);publisher_->setEnabled(!busy);progress_->setVisible(busy);
    state_->setText(!session_?"Assistance unavailable":busy?session_->publicApprovalPending()?"Registering reviewed public information…":session_->state()==G::State::Explaining?"Explaining public evidence…":session_->state()==G::State::Searching?"Searching for reviewed public information…":"Reading the current request or assistance configuration…":
        session_->state()==G::State::Cancelled?"Explanation cancelled · request remains undecided":
        session_->result()&&same?"Explanation finished · request remains undecided":
        reviewed?"Public information reviewed for this request":
        observedName_.isEmpty()?"Automatic explanation unavailable · no current application name":"Waiting for current configuration, consent and application information");
    QString text="Purpose and the effect of blocking are Unknown until evidence for this destination is available.";
    QString network="Registration and routing ASN: Unknown · observed domain: Unknown";
    const auto result=session_&&same?session_->result():std::nullopt;
    if(result){const auto view=G::makeView(*result);
        text="Possible service: "+QString::fromUtf8(view.service)+"\nPossible purpose: "+QString::fromUtf8(view.purpose)+
            "\nBlocking could: "+QString::fromUtf8(view.impact)+"\nConditional suggestion: "+QString::fromUtf8(view.advice)+
            "\n"+QString::fromUtf8(view.uncertainty);
        network="Registered network operator: "+QString::fromUtf8(view.networkOperator)+"\nAnnouncing ASN: "+QString::fromUtf8(view.routingAsn)+
            "\nObserved domain: Unknown\nPossible network reason: "+QString::fromUtf8(view.networkReason)+"\n"+QString::fromUtf8(view.providerNotice);
        if(result->failure!=G::Failure::None)text="The explanation is unavailable. Purpose and the effect of blocking remain Unknown. Your request remains undecided.";
    }
    if(original)network+="\nConnection observed: "+utc(original->observedAtMs)+" · original outbound connection";
    if(session_&&!session_->problem().isEmpty())text=session_->problem();
    text_->setText(text);
    networkDetails_->setText(network);
    localSummary_->setText(local?"File at observed path: "+signatureText(local->signature)+" · safety unproven":"File at observed path: Unknown · no current retained snapshot");
    QString localText="Local signature, certificate publisher and file metadata: Unknown.";
    if(local)localText=signatureText(local->signature)+"\nCertificate publisher (local): "+
        (local->publisher.empty()?QString("Unknown"):QString::fromUtf8(local->publisher))+"\nFile size: "+QString::number(local->size)+
        " bytes\nFile modified: "+utc(local->modifiedAtMs)+"\nLocally checked: "+utc(local->checkedAtMs);
    localDetails_->setText(localText+"\nSource: the retained local file opened at the observed path and offline Authenticode policy. The image loaded by the process is not verified. No current revocation or catalog verification. A signed file may still be harmful; an unsigned file is not necessarily harmful. These facts do not establish legitimacy or decide permissions.");
    delete citations_->layout();qDeleteAll(citations_->findChildren<QLabel*>(QString{},Qt::FindDirectChildrenOnly));
    auto* sources=new QVBoxLayout(citations_);sources->setContentsMargins(0,0,0,0);
    if(result)for(const auto& citation:result->citations){
        auto* label=new QLabel(QString("[%1] %2\n%3\n%4\nChecked: %5 · %6").arg(citation.id).arg(QString::fromUtf8(citation.title),QString::fromUtf8(citation.url),QString::fromUtf8(citation.snippet),
            QDateTime::fromMSecsSinceEpoch(qint64(citation.retrievedAtMs),Qt::UTC).toString(Qt::ISODateWithMs),
            citation.kind==1?QString("Registration record; service unknown"):citation.kind==2?QString("IP+app search association; service unverified"):citation.kind==3?QString("Announcing ASN from RIS; may lag routing"):QString("Public snippet; uncertain")),citations_);
        label->setTextFormat(Qt::PlainText);label->setWordWrap(true);label->setTextInteractionFlags(Qt::TextSelectableByMouse|Qt::TextSelectableByKeyboard);sources->addWidget(label);
    }
}
}
