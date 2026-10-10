#include "ExplanationWidget.h"
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QProgressBar>
#include <QVBoxLayout>
namespace Gate::Assistance::Ui {
namespace G=General;
ExplanationWidget::ExplanationWidget(GeneralSession* session,Binding binding,const QString& suggested,QWidget* parent)
    :QFrame(parent),binding_(std::move(binding)),observedName_(suggested){
    setObjectName("general-explanation");setProperty("role","panel");auto* layout=new QVBoxLayout(this);layout->setContentsMargins(12,12,12,12);layout->setSpacing(8);
    auto* notice=new QLabel(observedName_.isEmpty()
        ? "The current application name is unavailable. You can review a public name manually. Paths, file hashes and local signature details are not sent. An explanation never decides Allow or Block."
        : "The query uses the executable name observed by the service. Publisher and file identity are unverified. Automatic starts after setup and consent; Manual waits for Explain. Paths, file hashes and local signature details are not sent. An explanation never decides Allow or Block.",this);
    notice->setTextFormat(Qt::PlainText);notice->setWordWrap(true);notice->setProperty("role","faint");layout->addWidget(notice);
    product_=new QLineEdit(suggested,this);product_->setObjectName("public-product");product_->setMaxLength(96);product_->setPlaceholderText("Public product name");layout->addWidget(product_);
    publisher_=new QLineEdit(this);publisher_->setObjectName("public-publisher");publisher_->setMaxLength(96);publisher_->setPlaceholderText("Public publisher · optional");layout->addWidget(publisher_);
    approve_=new QPushButton("Review public information",this);approve_->setObjectName("approve-public-query");layout->addWidget(approve_,0,Qt::AlignLeft);
    start_=new QPushButton("Explain application",this);start_->setObjectName("explain-approved-query");layout->addWidget(start_,0,Qt::AlignLeft);
    product_->setReadOnly(!observedName_.isEmpty());publisher_->setVisible(observedName_.isEmpty());approve_->setVisible(observedName_.isEmpty());
    progress_=new QProgressBar(this);progress_->setObjectName("explanation-progress");progress_->setRange(0,0);progress_->setTextVisible(false);layout->addWidget(progress_);
    state_=new QLabel(this);state_->setObjectName("explanation-state");state_->setTextFormat(Qt::PlainText);state_->setWordWrap(true);layout->addWidget(state_);
    cancel_=new QPushButton("Cancel explanation",this);cancel_->setObjectName("cancel-general-explanation");layout->addWidget(cancel_,0,Qt::AlignLeft);
    text_=new QLabel(this);text_->setObjectName("general-explanation-text");text_->setTextFormat(Qt::PlainText);text_->setWordWrap(true);layout->addWidget(text_);
    citations_=new QWidget(this);citations_->setObjectName("general-citations");layout->addWidget(citations_);
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
    const bool busy=session_&&session_->busy(),available=session_&&session_->available();
    const auto configuration=session_?session_->configuration():std::nullopt;
    const bool configured=configuration&&configuration->activation.technicallyAvailable&&
        configuration->activation.cause==Configuration::ActivationCause::Ready;
    const auto binding=binding_?binding_():std::nullopt;
    approve_->setEnabled(available&&!busy&&binding.has_value());start_->setEnabled(available&&configured&&!busy&&binding.has_value()&&session_->publicReviewCurrent());cancel_->setEnabled(busy);
    product_->setEnabled(!busy);publisher_->setEnabled(!busy);progress_->setVisible(busy);
    state_->setText(!session_?"Assistance unavailable":busy?session_->publicApprovalPending()?"Registering reviewed public information…":session_->state()==G::State::Explaining?"Explaining public evidence…":session_->state()==G::State::Searching?"Searching for reviewed public information…":"Reading the current request or assistance configuration…":
        session_->state()==G::State::Cancelled?"Explanation cancelled · request remains undecided":
        session_->result()?"Explanation finished · file identity remains unverified":
        session_->publicReviewCurrent()?observedName_.isEmpty()?"Public information reviewed for this request · identity unverified":"Observed application name ready · identity unverified":
        observedName_.isEmpty()?"Automatic explanation unavailable · no current application name":"Waiting for current configuration, consent and application information");
    QString text;const auto result=session_?session_->result():std::nullopt;
    if(result){const auto view=G::makeView(*result);text=QString::fromUtf8(view.purpose)+"\n"+QString::fromUtf8(view.networkReason)+"\n"+
        QString::fromUtf8(view.uncertainty)+"\n"+QString::fromUtf8(view.identityNotice);
        if(result->failure!=G::Failure::None)text="The explanation is unavailable. Current service, consent and operational rights must be valid. Your request remains undecided.";
    }
    if(session_&&!session_->problem().isEmpty())text=session_->problem();
    text_->setText(text);
    delete citations_->layout();qDeleteAll(citations_->findChildren<QLabel*>(QString{},Qt::FindDirectChildrenOnly));
    auto* sources=new QVBoxLayout(citations_);sources->setContentsMargins(0,0,0,0);
    if(result)for(const auto& citation:result->citations){
        auto* label=new QLabel(QString("[%1] %2\n%3\n%4").arg(citation.id).arg(QString::fromUtf8(citation.title),QString::fromUtf8(citation.url),QString::fromUtf8(citation.snippet)),citations_);
        label->setTextFormat(Qt::PlainText);label->setWordWrap(true);label->setTextInteractionFlags(Qt::TextSelectableByMouse|Qt::TextSelectableByKeyboard);sources->addWidget(label);
    }
}
}
