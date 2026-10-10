#include "SettingsWidget.h"
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QVBoxLayout>
#include <QSignalBlocker>
#include <QGroupBox>
#include <QHBoxLayout>
#include <cstring>
namespace Gate::Assistance::Ui {
namespace C=Configuration;
namespace {
QString activationMessage(const C::NetworkActivationSnapshot& activation){
    switch(activation.cause){
    case C::ActivationCause::Ready:
        return activation.technicallyAvailable?"Ready for internal testing and evaluation, subject to trial credits and request limits":"Configuration could not be confirmed. Refresh to check it again.";
    case C::ActivationCause::LocalConfigurationUnavailable:return "Local assistance settings are unavailable. Refresh to inspect them.";
    case C::ActivationCause::CredentialMissing:return "Save your own NVIDIA API key locally, select a purpose and review the data notices. A saved key does not verify account rights or remaining trial credits.";
    case C::ActivationCause::CredentialCorrupt:return "The saved API key cannot be read safely. Forget it before storing it again.";
    case C::ActivationCause::EntitlementMissing:return "Explanations are unavailable. Confirm your NVIDIA account type and a service offer that permits everyday use.";
    case C::ActivationCause::OperationalUseRestricted:return "Everyday use is unavailable. The API Catalog trial permits internal testing and evaluation only. Your account and a separate production service offer still need to be resolved.";
    case C::ActivationCause::ServiceUseMissing:return "Select the purpose of use. Internal evaluation and everyday use have different service terms.";
    case C::ActivationCause::EntitlementExpired:return "The reviewed service permission has expired. Explanations are unavailable.";
    case C::ActivationCause::EntitlementConflict:return "The reviewed permission does not match this account, model or service configuration.";
    case C::ActivationCause::ModelConsentMissing:return "Read the current model notice and agree before explanations can start.";
    case C::ActivationCause::WebConsentMissing:return "Read the current web search notice and agree before searches can start.";
    case C::ActivationCause::SearchConfigurationMissing:return "Select the current web search configuration to continue setup.";
    case C::ActivationCause::PublicQueryApprovalMissing:return "The public information for this request could not be registered. Refresh the current request.";
    case C::ActivationCause::ProviderPolicyChanged:return "The web search configuration changed. Refresh and review its current notice.";
    case C::ActivationCause::SessionStale:return "The assistance session changed. Refresh to check the current configuration.";
    case C::ActivationCause::ServiceUnavailable:return "The current request service is unavailable. Your request remains undecided.";
    case C::ActivationCause::PayloadNotSealed:return "The explanation could not be prepared for this request. Refresh the current request.";
    case C::ActivationCause::TechnicalPrerequisitesMissing:return "The explanation prerequisites could not be confirmed. Refresh the current request.";
    case C::ActivationCause::LocalMutationUncertain:return "A settings update could not be confirmed. Refresh; it will not be retried automatically.";
    }
    return "Assistance configuration is unavailable. Refresh to inspect it.";
}
}
SettingsWidget::SettingsWidget(GeneralSession* session,QWidget* parent):QFrame(parent),session_(session){
    setObjectName("assistance-settings");setProperty("role","panel");auto* layout=new QVBoxLayout(this);layout->setContentsMargins(16,16,16,16);layout->setSpacing(8);
    auto addText=[&](const QString& text,const char* name){auto* label=new QLabel(text,this);label->setObjectName(name);
        label->setWordWrap(true);label->setTextFormat(Qt::PlainText);
        label->setProperty("role",QString(name)=="heading"?"heading":QString(name)=="faint"?"faint":QString(name)=="assistance-error"?"warning":"muted");
        layout->addWidget(label);return label;};
    auto addButton=[&](const QString& text,const char* name){auto* button=new QPushButton(text,this);button->setObjectName(name);
        layout->addWidget(button,0,Qt::AlignLeft);return button;};
    addText("NVIDIA assistance","heading");
    addText("Configured model: NVIDIA Nemotron 3 Ultra (text).","faint");
    status_=addText({},"assistance-status");
    addText("Explanations can be wrong. They never allow or block a connection, decide a pending request, or establish that a file is safe.","faint");
    connect_=addButton("Connect assistance","connect-assistance");
    refresh_=addButton("Refresh","refresh-assistance");
    progress_=new QProgressBar(this);progress_->setObjectName("assistance-progress");progress_->setRange(0,0);progress_->setTextVisible(false);layout->addWidget(progress_);
    key_=new QLineEdit(this);key_->setObjectName("nvidia-key-input");key_->setEchoMode(QLineEdit::Password);
    key_->setMaxLength(512);key_->setPlaceholderText("Your NVIDIA Developer API key");key_->setInputMethodHints(Qt::ImhSensitiveData|Qt::ImhNoPredictiveText);layout->addWidget(key_);
    store_=addButton("Store API key","store-assistance-key");forget_=addButton("Forget API key","forget-assistance-key");
    addText("Saving a key stores it locally. It does not check NVIDIA account rights or trial credits, send a request, or grant data consent.","faint");
    auto* purposeLabel=addText("Purpose of use","heading");
    serviceUse_=new QComboBox(this);serviceUse_->setObjectName("assistance-service-use");
    serviceUse_->addItems({"Not selected","Internal testing and evaluation","Everyday use · service offer pending"});
    serviceUse_->setAccessibleName("Purpose of use");purposeLabel->setBuddy(serviceUse_);layout->addWidget(serviceUse_);
    addText("Choose internal evaluation only for internal testing, within your trial time and credits. This choice is not account verification. Production or everyday use requires a separate service subscription and is currently unavailable. Changing purpose withdraws both data consents.","faint");
    addText("When to explain","heading");
    mode_=new QComboBox(this);mode_->setObjectName("assistance-mode");mode_->addItems({"Not selected","Automatic","Manual"});layout->addWidget(mode_);
    addText("Automatic is the default after evaluation setup and both data consents. It explains each new request only while current settings and request limits permit it. The executable name can reveal which app you use. Manual waits for Explain.","faint");
    selectSearch_=addButton("Set up web search","select-assistance-search");
    auto* permissions=new QGroupBox("Permissions · read each notice before agreeing",this);
    permissions->setObjectName("assistance-permissions");
    auto* permissionLayout=new QVBoxLayout(permissions);layout->addWidget(permissions);
    model_=addText({},"model-disclosure");grantModel_=addButton("Consent to this model notice","grant-model-consent");
    revokeModel_=addButton("Revoke model consent","revoke-model-consent");
    web_=addText({},"web-disclosure");grantWeb_=addButton("Consent to this web search notice","grant-web-consent");
    revokeWeb_=addButton("Revoke web search consent","revoke-web-consent");
    for(auto* widget:{static_cast<QWidget*>(model_),static_cast<QWidget*>(grantModel_),static_cast<QWidget*>(revokeModel_),
        static_cast<QWidget*>(web_),static_cast<QWidget*>(grantWeb_),static_cast<QWidget*>(revokeWeb_)}){
        layout->removeWidget(widget);permissionLayout->addWidget(widget);
    }
    grantModel_->setText("Agree to model notice");revokeModel_->setText("Withdraw model consent");
    grantWeb_->setText("Agree to web search notice");revokeWeb_->setText("Withdraw web search consent");
    problem_=addText({},"assistance-error");
    connect(connect_,&QPushButton::clicked,this,&SettingsWidget::connectRequested);
    connect(refresh_,&QPushButton::clicked,this,[this]{if(session_)session_->refresh();});
    connect(store_,&QPushButton::clicked,this,[this]{
        auto entered=key_->text();key_->clear();
        bool ascii=true;for(const auto character:entered)ascii=ascii&&character.unicode()>=33&&character.unicode()<=126;
        auto bytes=ascii?entered.toLatin1():QByteArray{};entered.fill(QChar{});
        Broker::SensitiveBytes secret(std::size_t(bytes.size()));
        if(bytes.size())std::memcpy(secret.data(),bytes.constData(),std::size_t(bytes.size()));
        bytes.fill(0);if(session_)session_->store(std::move(secret));
    });
    connect(forget_,&QPushButton::clicked,this,[this]{key_->clear();if(session_)session_->forget();});
    connect(mode_,&QComboBox::activated,this,[this](int index){if(session_&&index)session_->mode(index==1?C::ModeChoice::Automatic:C::ModeChoice::Manual);});
    connect(serviceUse_,&QComboBox::activated,this,[this](int index){if(session_)session_->serviceUse(C::ServiceUse(index));});
    connect(selectSearch_,&QPushButton::clicked,this,[this]{if(session_)session_->selectSearch();});
    connect(grantModel_,&QPushButton::clicked,this,[this]{if(session_)session_->consent(C::ConsentTarget::Model,true);});
    connect(revokeModel_,&QPushButton::clicked,this,[this]{if(session_)session_->consent(C::ConsentTarget::Model,false);});
    connect(grantWeb_,&QPushButton::clicked,this,[this]{if(session_)session_->consent(C::ConsentTarget::Web,true);});
    connect(revokeWeb_,&QPushButton::clicked,this,[this]{if(session_)session_->consent(C::ConsentTarget::Web,false);});
    if(session_)connect(session_,&GeneralSession::changed,this,&SettingsWidget::refresh);
    refresh();
}
void SettingsWidget::refresh(){
    const bool connected=session_&&session_->available(),busy=session_&&session_->busy();
    const auto view=session_?session_->configuration():std::nullopt;
    const bool writable=connected&&!busy&&view.has_value();
    status_->setText(!connected?"Assistance is not connected":!view?"Connected · refresh to view your settings":
        QString("%1\nAPI key: %2 · Model: %3 · Web search: %4")
            .arg(activationMessage(view->activation))
            .arg(view->local.credential==C::CredentialState::Stored?"saved locally":"not saved or unavailable")
            .arg(view->local.modelConsent.granted?"consented":"consent needed")
            .arg(view->local.webConsent.granted?"consented":"consent needed"));
    connect_->setEnabled(!connected&&!busy);refresh_->setEnabled(connected&&!busy);progress_->setVisible(busy);
    key_->setEnabled(writable);store_->setEnabled(writable);forget_->setEnabled(writable);mode_->setEnabled(writable);
    serviceUse_->setEnabled(writable);
    const QSignalBlocker purposeBlocker(serviceUse_);serviceUse_->setCurrentIndex(view?int(view->local.serviceUse):0);
    const QSignalBlocker blocker(mode_);mode_->setCurrentIndex(!view?0:view->local.mode==C::ModeChoice::Automatic?1:view->local.mode==C::ModeChoice::Manual?2:0);
    model_->setText(session_&&!session_->modelBody().isEmpty()?session_->modelBody():"The current model notice is unavailable. Consent cannot be granted.");
    web_->setText(session_&&!session_->webBody().isEmpty()?session_->webBody():"The current web search notice is unavailable. Consent cannot be granted.");
    grantModel_->setEnabled(writable&&view->local.serviceUse==C::ServiceUse::InternalEvaluation&&session_&&!session_->modelBody().isEmpty());grantWeb_->setEnabled(writable&&session_&&!session_->webBody().isEmpty());
    revokeModel_->setEnabled(writable&&view->local.modelConsent.granted);revokeWeb_->setEnabled(writable&&view->local.webConsent.granted);
    selectSearch_->setEnabled(writable&&session_&&session_->presentation()&&session_->presentation()->searchReference());
    problem_->setText(session_?session_->problem():QString{});
    if(!connected)key_->clear();
}
}
