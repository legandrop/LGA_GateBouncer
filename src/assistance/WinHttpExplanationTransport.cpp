#include "WinHttpExplanationTransport.h"
#include "WinHttpCompatibility.h"
#include "grounded_bridge/NvidiaEnvelope.h"
#include "grounded_bridge/FixedUltraProfile.h"
#include "broker/BrokerVault.h"
#include "general/GeneralPayload.h"
#include "configuration/ConfigurationPolicy.h"
#include <winhttp.h>
#include <QTimer>
#include <QPointer>
#include <QThread>
#include <QCoreApplication>
#include <array>
#include <atomic>
#include <cstring>
#include <mutex>

namespace Gate::Assistance {
namespace W=gatebouncer::websearch;
struct WinHttpExplanationTransport::State final : QObject, std::enable_shared_from_this<State> {
    enum class Phase { Created, OptionsReady, Sending, Headers, Reading, Closing, Completed };
    RequestBinding binding; QByteArray payload, result; ResponseContract contract=ResponseContract::Legacy1;
    std::shared_ptr<const void> groundedJobToken;
    std::optional<General::FullBinding> generalBinding;
    std::shared_ptr<const General::SealedGeneralPayload> generalSeal;
    std::optional<Configuration::NetworkPermit> generalPermit;
    QPointer<WinHttpExplanationTransport> owner;
    Completion completion; Observer observer; HttpObservation observation;
    std::wstring host=L"integrate.api.nvidia.com";INTERNET_PORT port=INTERNET_DEFAULT_HTTPS_PORT;DWORD secure=WINHTTP_FLAG_SECURE;
    std::function<bool(HINTERNET)> additionalHeaderValidation;
    HINTERNET session=nullptr, connection=nullptr, request=nullptr;
    QTimer deadline, closeDeadline; std::array<unsigned char,4096> readBuffer{};
    Phase phase=Phase::Created; bool delivered=false, closingSeen=false, registered=false; std::shared_ptr<State> keepAlive;
    Broker::Failure failure=Broker::Failure::None; Error coreError=Error::None;
    std::mutex diagnosticMutex;W::HttpDiagnostic firstDiagnostic;
    std::optional<quint64> expectedLength;
    State(){deadline.setSingleShot(true);closeDeadline.setSingleShot(true);}
    ~State(){if(connection)WinHttpCloseHandle(connection);if(session)WinHttpCloseHandle(session);}
    bool exactGeneralJob() const {
        return owner&&generalBinding&&generalSeal&&groundedJobToken&&owner->active_.lock().get()==this;
    }
    bool generalCurrent(Configuration::ActivationStage stage,bool active=true) {
        // El permiso puede consultar una aprobación que retira o destruye al dueño.
        auto self=shared_from_this();
        if(!owner||!generalPermit||!generalBinding||!generalSeal||!groundedJobToken||(active&&!exactGeneralJob()))return false;
        const auto cause=generalPermit->cause(stage,generalBinding->canonicalDigest(),generalSeal->payloadDigest());
        if(cause!=Configuration::PermitCause::Current)observation.permitCause=cause;
        return cause==Configuration::PermitCause::Current&&owner&&(!active||exactGeneralJob());
    }
    static void CALLBACK callback(HINTERNET,DWORD_PTR context,DWORD status,void *data,DWORD length) {
        auto *raw=reinterpret_cast<State *>(context);if(!raw)return;
        auto state=raw->shared_from_this();DWORD value=0;std::optional<quint64> api;bool nativeError=false,secureFlags=false;
        if(status==WINHTTP_CALLBACK_STATUS_READ_COMPLETE)value=length;
        else if(status==WINHTTP_CALLBACK_STATUS_SECURE_FAILURE && data && length==sizeof(DWORD)){std::memcpy(&value,data,sizeof(value));secureFlags=true;}
        else if(status==WINHTTP_CALLBACK_STATUS_REQUEST_ERROR && data && length==sizeof(WINHTTP_ASYNC_RESULT)){
            WINHTTP_ASYNC_RESULT result{};std::memcpy(&result,data,sizeof(result));value=result.dwError;api=quint64(result.dwResult);nativeError=true;
        }
        // Retener escalares antes de la cola Qt: Cancel posterior no borra el primer callback fallido.
        if(status==WINHTTP_CALLBACK_STATUS_REQUEST_ERROR){
            auto stage=W::HttpStage::Unknown;
            if(api){switch(*api){case API_SEND_REQUEST:stage=W::HttpStage::Send;break;case API_RECEIVE_RESPONSE:stage=W::HttpStage::Receive;break;
                case API_READ_DATA:stage=W::HttpStage::Read;break;default:break;}}
            state->recordNative(stage,nativeError?std::optional<DWORD>(value):std::nullopt,api);
        }else if(status==WINHTTP_CALLBACK_STATUS_SECURE_FAILURE)
            state->recordNative(W::HttpStage::Unknown,{}, {},secureFlags?std::optional<DWORD>(value):std::nullopt);
        QMetaObject::invokeMethod(state.get(),[state,status,value]{state->notification(status,value);},Qt::QueuedConnection);
    }
    void recordNative(W::HttpStage stage,std::optional<DWORD> error={},std::optional<quint64> api={},std::optional<DWORD> flags={}) {
        std::lock_guard<std::mutex> lock(diagnosticMutex);
        if(firstDiagnostic.failureObserved)return;
        firstDiagnostic.stage=stage;firstDiagnostic.winHttpError=error;firstDiagnostic.asyncApi=api;
        firstDiagnostic.secureFailure=flags;firstDiagnostic.failureObserved=true;
    }
    bool nativeFailed(W::HttpStage stage){const auto error=GetLastError();recordNative(stage,error);return false;}
    bool option(HINTERNET handle,DWORD option,void *value,DWORD size){
        return WinHttpSetOption(handle,option,value,size)?true:nativeFailed(W::HttpStage::Options);
    }
    void timers() {
        auto weak=weak_from_this();
        QObject::connect(&deadline,&QTimer::timeout,this,[weak]{if(auto self=weak.lock())self->finish(Broker::Failure::Timeout,Error::Timeout);});
        QObject::connect(&closeDeadline,&QTimer::timeout,this,[weak]{if(auto self=weak.lock()){self->deliver();QCoreApplication::exit(20);}});
    }
    bool prepare() {
        session=WinHttpOpen(L"LGA GateBouncer",WINHTTP_ACCESS_TYPE_NO_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,WINHTTP_FLAG_ASYNC);
        if(!session)return nativeFailed(W::HttpStage::OpenSession);
        BOOL yes=TRUE;DWORD one=1;FailedConnectionRetries retries{0,0};
        DWORD tls=WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2|WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
        if(!WinHttpSetOption(session,WINHTTP_OPTION_SECURE_PROTOCOLS,&tls,sizeof(tls))){tls=WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;if(!option(session,WINHTTP_OPTION_SECURE_PROTOCOLS,&tls,sizeof(tls)))return false;}
        if(!WinHttpSetTimeouts(session,3000,5000,5000,10000))return nativeFailed(W::HttpStage::Options);
        if(!option(session,FailedConnectionRetriesOption,&retries,sizeof(retries))||
           !option(session,DisableGlobalPoolingOption,&yes,sizeof(yes))||!option(session,WINHTTP_OPTION_CONNECT_RETRIES,&one,sizeof(one))||
           !option(session,WINHTTP_OPTION_DISABLE_SECURE_PROTOCOL_FALLBACK,&yes,sizeof(yes)))return false;
        connection=WinHttpConnect(session,host.c_str(),port,0);if(!connection)return nativeFailed(W::HttpStage::Connect);
        request=WinHttpOpenRequest(connection,L"POST",L"/v1/chat/completions",nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,secure);if(!request)return nativeFailed(W::HttpStage::OpenRequest);
        const DWORD_PTR context=reinterpret_cast<DWORD_PTR>(this);
        if(!option(request,WINHTTP_OPTION_CONTEXT_VALUE,const_cast<DWORD_PTR *>(&context),sizeof(context)))return false;
        if(WinHttpSetStatusCallback(request,&callback,WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS|WINHTTP_CALLBACK_FLAG_HANDLES|WINHTTP_CALLBACK_FLAG_SECURE_FAILURE,0)==WINHTTP_INVALID_STATUS_CALLBACK)return nativeFailed(W::HttpStage::Options);
        registered=true;
        DWORD disabled=WINHTTP_DISABLE_AUTHENTICATION|WINHTTP_DISABLE_COOKIES|WINHTTP_DISABLE_REDIRECTS|WINHTTP_DISABLE_KEEP_ALIVE;
        DWORD autologon=WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH, redirects=WINHTTP_OPTION_REDIRECT_POLICY_NEVER, headers=8192, revocation=WINHTTP_ENABLE_SSL_REVOCATION;
        if(!option(request,WINHTTP_OPTION_DISABLE_FEATURE,&disabled,sizeof(disabled))||!option(request,WINHTTP_OPTION_AUTOLOGON_POLICY,&autologon,sizeof(autologon))||
           !option(request,WINHTTP_OPTION_REDIRECT_POLICY,&redirects,sizeof(redirects))||!option(request,WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE,&headers,sizeof(headers))||
           !option(request,WINHTTP_OPTION_ENABLE_FEATURE,&revocation,sizeof(revocation))||
           !option(request,WINHTTP_OPTION_CLIENT_CERT_CONTEXT,WINHTTP_NO_CLIENT_CERT_CONTEXT,0))return false;
        if(!WinHttpAddRequestHeaders(request,L"Content-Type: application/json; charset=utf-8\r\nAccept: application/json\r\nAccept-Encoding: identity\r\n",DWORD(-1),WINHTTP_ADDREQ_FLAG_ADD|WINHTTP_ADDREQ_FLAG_REPLACE))return nativeFailed(W::HttpStage::Headers);
        phase=Phase::OptionsReady;return true;
    }
    bool authorize(const unsigned char *secret,size_t size) {
        if(size<1||size>512)return false;
        Broker::SensitiveBytes header((size+24)*sizeof(wchar_t));auto *wide=reinterpret_cast<wchar_t *>(header.data());
        const wchar_t prefix[]=L"Authorization: Bearer ";const size_t prefixSize=(sizeof(prefix)/sizeof(wchar_t))-1;
        std::memcpy(wide,prefix,prefixSize*sizeof(wchar_t));for(size_t i=0;i<size;++i)wide[prefixSize+i]=wchar_t(secret[i]);
        return WinHttpAddRequestHeaders(request,wide,DWORD(prefixSize+size),WINHTTP_ADDREQ_FLAG_ADD|WINHTTP_ADDREQ_FLAG_REPLACE)?true:nativeFailed(W::HttpStage::Headers);
    }
    void send() {
        if(contract==ResponseContract::General3) {
            const auto b=generalBinding->canonicalDigest(),p=generalSeal->payloadDigest();
            if(!generalCurrent(Configuration::ActivationStage::PreSend)||!generalPermit->consumePreSend(b,p)||
               !generalCurrent(Configuration::ActivationStage::AfterCallback)) {
                finish(Broker::Failure::Stale,Error::Unavailable);return;
            }
        }
        auto self=shared_from_this();keepAlive=self;
        phase=Phase::Sending;observation.sendStarted=true;deadline.start(20000);
        if(!WinHttpSendRequest(request,WINHTTP_NO_ADDITIONAL_HEADERS,0,payload.data(),DWORD(payload.size()),DWORD(payload.size()),reinterpret_cast<DWORD_PTR>(this)))
            {nativeFailed(W::HttpStage::Send);finish(Broker::Failure::Uncertain,Error::Unavailable);}
    }
    std::optional<QString> header(DWORD key) {
        std::array<wchar_t,4097> buffer{};DWORD bytes=DWORD(buffer.size()*sizeof(wchar_t));
        if(!WinHttpQueryHeaders(request,key,WINHTTP_HEADER_NAME_BY_INDEX,buffer.data(),&bytes,WINHTTP_NO_HEADER_INDEX)){
            const auto error=GetLastError();
            if(error==ERROR_WINHTTP_HEADER_NOT_FOUND)return QString();
            recordNative(W::HttpStage::Headers,error);
            return {};
        }
        return QString::fromWCharArray(buffer.data());
    }
    void readNext(){if(!request||phase!=Phase::Reading)return;if(!WinHttpReadData(request,readBuffer.data(),DWORD(readBuffer.size()),nullptr)){nativeFailed(W::HttpStage::Read);finish(Broker::Failure::Uncertain,Error::Unavailable);}}
    void notification(DWORD status,DWORD value) {
        if(status==WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) {
            closingSeen=true;closeDeadline.stop();phase=Phase::Completed;deliver();keepAlive.reset();return;
        }
        if(phase==Phase::Closing||phase==Phase::Completed)return;
        switch(status) {
        case WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE:
            phase=Phase::Headers;if(!WinHttpReceiveResponse(request,nullptr)){nativeFailed(W::HttpStage::Receive);finish(Broker::Failure::Uncertain,Error::Unavailable);}break;
        case WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE: {
            DWORD code=0,size=sizeof(code);
            if(!WinHttpQueryHeaders(request,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,&code,&size,WINHTTP_NO_HEADER_INDEX)){nativeFailed(W::HttpStage::Headers);finish(Broker::Failure::Uncertain,Error::Unavailable);break;}
            observation.observedStatus=int(code);
            if(additionalHeaderValidation&&!additionalHeaderValidation(request)){finish(Broker::Failure::TlsFailure,Error::Unavailable);break;}
            if(code==202){finish(Broker::Failure::Uncertain,Error::None);break;}
            if(code==429){
                observation.retryAfterSeconds=60;auto retry=header(WINHTTP_QUERY_RETRY_AFTER);
                if(retry&&!retry->isEmpty()){bool decimal=true;for(const auto c:*retry)if(c<'0'||c>'9')decimal=false;
                    bool ok=false;const auto n=retry->toUInt(&ok);if(decimal&&ok&&n<=3600)observation.retryAfterSeconds=n;}
                finish(Broker::Failure::RateLimited,Error::RateLimited);break;
            }
            if(code!=200){finish(Broker::Failure::TransportUnavailable,Error::Unavailable);break;}
            auto encoding=header(WINHTTP_QUERY_CONTENT_ENCODING),length=header(WINHTTP_QUERY_CONTENT_LENGTH),content=header(WINHTTP_QUERY_CONTENT_TYPE);
            bool validLength=true;if(length&&!length->isEmpty()){
                for(const auto c:*length)if(c<'0'||c>'9')validLength=false;
                bool ok=false;const auto n=length->toULongLong(&ok);validLength=validLength&&ok&&n<=32768;if(validLength)expectedLength=n;
            }
            if(!encoding||(!encoding->isEmpty()&&encoding->trimmed().compare("identity",Qt::CaseInsensitive))||!length||!validLength||!content||content->section(';',0,0).trimmed().compare("application/json",Qt::CaseInsensitive)){finish(Broker::Failure::InvalidResponse,Error::InvalidResponse);break;}
            phase=Phase::Reading;readNext();break;
        }
        case WINHTTP_CALLBACK_STATUS_READ_COMPLETE:
            if(value>readBuffer.size()||quint64(result.size())+value>32768){finish(Broker::Failure::InvalidResponse,Error::InvalidResponse);break;}
            if(value){result.append(reinterpret_cast<const char *>(readBuffer.data()),int(value));readNext();}
            else if(expectedLength&&quint64(result.size())!=*expectedLength){finish(Broker::Failure::InvalidResponse,Error::InvalidResponse);}
            else if(contract==ResponseContract::Grounded2){auto canonical=GroundedBridge::normalizeNvidiaEnvelope(result);if(!canonical)finish(Broker::Failure::InvalidResponse,Error::InvalidResponse);else{result=std::move(*canonical);finish(Broker::Failure::None,Error::None);}}
            else if(contract==ResponseContract::General3) {
                const auto canonical=General::General3ResponseContract::normalize(std::string_view(result.constData(),size_t(result.size())),*generalSeal);
                if(!canonical)finish(Broker::Failure::InvalidResponse,Error::InvalidResponse);
                else {result=QByteArray(canonical->data(),qsizetype(canonical->size()));finish(Broker::Failure::None,Error::None);}
            }
            else if(!Broker::boundedExplanation(result)){finish(Broker::Failure::InvalidResponse,Error::InvalidResponse);}
            else finish(Broker::Failure::None,Error::None);
            break;
        case WINHTTP_CALLBACK_STATUS_SECURE_FAILURE:
            observation.secureFailure=value;finish(Broker::Failure::TlsFailure,Error::Unavailable);break;
        case WINHTTP_CALLBACK_STATUS_REQUEST_ERROR: {
            finish(value==ERROR_WINHTTP_TIMEOUT?Broker::Failure::Timeout:(observation.sendStarted?Broker::Failure::Uncertain:Broker::Failure::TransportUnavailable),value==ERROR_WINHTTP_TIMEOUT?Error::Timeout:Error::Unavailable);break;
        }
        default:break;
        }
    }
    void finish(Broker::Failure why,Error error) {
        if(phase==Phase::Closing||phase==Phase::Completed)return;
        {
            std::lock_guard<std::mutex> lock(diagnosticMutex);
            if(!firstDiagnostic.failureObserved && (why==Broker::Failure::Cancelled||why==Broker::Failure::Timeout)){
                firstDiagnostic.local=why==Broker::Failure::Cancelled?W::LocalHttpFailure::Cancelled:W::LocalHttpFailure::Deadline;
                firstDiagnostic.failureObserved=true;
            }
            observation.diagnostic=firstDiagnostic;
        }
        auto self=shared_from_this();keepAlive=self;failure=why;coreError=error;deadline.stop();phase=Phase::Closing;
        if(request){auto old=request;request=nullptr;if(registered)closeDeadline.start(5000);if(!WinHttpCloseHandle(old)){deliver();QCoreApplication::exit(20);}else if(!registered){phase=Phase::Completed;deliver();keepAlive.reset();}}
        else {phase=Phase::Completed;deliver();keepAlive.reset();}
    }
    void deliver() {
        if(delivered)return;
        delivered=true;observation.failure=failure;
        TransportReply reply{binding,observation.observedStatus,{},coreError};
        if(failure==Broker::Failure::None)reply.body=result;
        if(contract==ResponseContract::General3) {
            if(!generalCurrent(Configuration::ActivationStage::BeforeCallback))return;
            auto observed=observer;
            if(observed)observed(observation);
            if(!generalCurrent(Configuration::ActivationStage::AfterCallback))return;
            if(!generalCurrent(Configuration::ActivationStage::BeforeCallback))return;
            auto completed=std::move(completion);
            if(completed)completed(std::move(reply));
            generalCurrent(Configuration::ActivationStage::AfterCallback);
            return;
        }
        if(observer)observer(observation);
        if(completion){auto callback=std::move(completion);callback(std::move(reply));}
    }
};
class HttpOperation final:public Operation {
public:
    explicit HttpOperation(std::function<void()> f):cancel_(std::move(f)){}
    ~HttpOperation() override{cancel();}
    void cancel() override{if(cancel_){auto f=std::move(cancel_);f();}}
private:std::function<void()> cancel_;
};
WinHttpExplanationTransport::WinHttpExplanationTransport(QObject *parent):QObject(parent){}
WinHttpExplanationTransport::WinHttpExplanationTransport(Broker::BrokerVault &vault,Observer observer,QObject *parent):QObject(parent),vault_(&vault),observer_(std::move(observer)){}
WinHttpExplanationTransport::~WinHttpExplanationTransport(){if(auto state=active_.lock()){if(state->contract==ResponseContract::General3){state->owner.clear();active_.reset();}state->finish(Broker::Failure::Cancelled,Error::Cancelled);}}
std::unique_ptr<Operation> WinHttpExplanationTransport::start(const RequestBinding &binding,const QByteArray &payload,Completion completion) {
    return startImpl(binding,payload,std::move(completion),observer_,ResponseContract::Legacy1);
}
std::unique_ptr<Operation> WinHttpExplanationTransport::startGrounded(const RequestBinding &binding,const QByteArray &payload,Completion completion,Observer observer,std::shared_ptr<const void> jobToken){return startImpl(binding,payload,std::move(completion),std::move(observer),ResponseContract::Grounded2,std::move(jobToken));}
std::unique_ptr<Operation> WinHttpExplanationTransport::startGeneral(const General::FullBinding &binding,const General::SealedGeneralPayload &seal,Completion completion,Observer observer,std::shared_ptr<const void> jobToken,Configuration::NetworkPermit permit) {
    if(QThread::currentThread()!=thread()||!jobToken||!General::validBinding(binding))return {};
    auto state=std::make_shared<State>();
    state->contract=ResponseContract::General3;state->owner=this;state->generalBinding=binding;
    // Copia completa e inmutable: ningún string_view prestado sobrevive al caller.
    state->generalSeal=std::make_shared<const General::SealedGeneralPayload>(seal);
    state->generalPermit.emplace(std::move(permit));state->groundedJobToken=std::move(jobToken);
    if(!General::GeneralPayloadBuilder::validProfile(*state->generalSeal,*state->generalBinding)||
       state->generalSeal->bytes().empty()||state->generalSeal->bytes().size()>4096||
       !state->generalCurrent(Configuration::ActivationStage::Admission,false))return {};
    auto self=state->owner;
    if(!self)return {};
    if(auto admitted=self->admittedGeneralJob_.lock();admitted==state->groundedJobToken)return {};
    if(auto old=self->active_.lock();old&&(old->phase!=State::Phase::Completed||!old->delivered))return {};
    auto *vault=self->vault_;if(!vault)return {};
    Broker::TokenIdentity identity;
    if(!Broker::tokenIdentity(GetCurrentProcess(),identity)||!identity.ordinary)return {};
    const auto &ownedBinding=*state->generalBinding;
    state->binding.context={
        QString::fromUtf8(ownedBinding.requestId),
        QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(ownedBinding.applicationToken.data()),16).toHex()),
        ownedBinding.snapshotRevision,ownedBinding.serviceEpoch,ownedBinding.sessionEpoch,true,true};
    state->binding.consentEpoch=ownedBinding.modelConsentEpoch;
    state->binding.credentialEpoch=ownedBinding.credentialEpoch;
    state->binding.generation=ownedBinding.generation;
    const auto bytes=state->generalSeal->bytes();state->payload=QByteArray(bytes.data(),qsizetype(bytes.size()));
    state->completion=std::move(completion);state->observer=std::move(observer);state->timers();
    auto cancel=[weak=std::weak_ptr<State>(state)] {
        if(auto s=weak.lock()) {
            auto retire=[s]{if(s->owner&&s->owner->active_.lock()==s)s->owner->active_.reset();s->finish(Broker::Failure::Cancelled,Error::Cancelled);};
            if(QThread::currentThread()==s->thread())retire();else QMetaObject::invokeMethod(s.get(),std::move(retire),Qt::QueuedConnection);
        }
    };
    auto operation=std::make_unique<HttpOperation>(std::move(cancel));
    self->active_=state;
    self->admittedGeneralJob_=state->groundedJobToken;
    if(!state->generalCurrent(Configuration::ActivationStage::Admission)){state->finish(Broker::Failure::Stale,Error::Unavailable);return operation;}
    if(!state->prepare()){state->finish(Broker::Failure::TransportUnavailable,Error::Unavailable);return operation;}
    if(!state->generalCurrent(Configuration::ActivationStage::BeforeSecret)){state->finish(Broker::Failure::Stale,Error::Unavailable);return operation;}
    const auto bindingDigest=state->generalBinding->canonicalDigest(),sealDigest=state->generalSeal->payloadDigest();
    bool headerReady=false;
    const auto borrowed=vault->withSecret(*state->generalPermit,bindingDigest,sealDigest,[state,&headerReady](const unsigned char *secret,size_t size){
        if(state->generalCurrent(Configuration::ActivationStage::BeforeSecret))headerReady=state->authorize(secret,size);
    });
    if(!state->generalCurrent(Configuration::ActivationStage::AfterCallback)){state->finish(Broker::Failure::Stale,Error::Unavailable);return operation;}
    if(borrowed!=Broker::Failure::None||!headerReady){state->finish(borrowed!=Broker::Failure::None?borrowed:Broker::Failure::VaultUnavailable,Error::Unavailable);return operation;}
    if(!state->generalCurrent(Configuration::ActivationStage::BeforeReserve)){state->finish(Broker::Failure::Stale,Error::Unavailable);return operation;}
    const auto budget=vault->reserveGeneral(*state->generalPermit,bindingDigest,sealDigest);
    // Contabilización observada independiente de la vigencia y del envío HTTP.
    state->observation.reservationCommitted=budget.committed;
    state->observation.reservationFailure=budget.failure;
    state->observation.reservationPrimaryError=budget.primaryError;
    if(budget.failure!=Broker::Failure::None||!budget.committed){
        state->finish(budget.failure!=Broker::Failure::None?budget.failure:Broker::Failure::Uncertain,
            budget.failure==Broker::Failure::RateLimited?Error::RateLimited:Error::Unavailable);return operation;
    }
    if(!state->generalCurrent(Configuration::ActivationStage::AfterCallback)){state->finish(Broker::Failure::Stale,Error::Unavailable);return operation;}
    state->send();return operation;
}
std::optional<HttpObservation> WinHttpExplanationTransport::snapshotGeneralObservation(const General::FullBinding &binding,const std::shared_ptr<const void> &jobToken) const {
    if(QThread::currentThread()!=thread()||!jobToken)return {};
    auto state=active_.lock();
    if(!state||state->contract!=ResponseContract::General3||state->groundedJobToken!=jobToken||!state->generalBinding||*state->generalBinding!=binding)return {};
    // La evidencia ya observada sigue disponible aunque el permiso no sea vigente.
    state->generalCurrent(Configuration::ActivationStage::Snapshot);
    if(!state->exactGeneralJob())return {};
    auto snapshot=state->observation;snapshot.failure=state->failure;return snapshot;
}
std::optional<HttpObservation> WinHttpExplanationTransport::snapshotGroundedObservation(const RequestBinding &binding,const std::shared_ptr<const void> &jobToken) const {
    if(QThread::currentThread()!=thread()||!jobToken)return {};
    auto state=active_.lock();if(!state||state->contract!=ResponseContract::Grounded2||state->groundedJobToken!=jobToken||!(state->binding==binding))return {};
    auto snapshot=state->observation;snapshot.failure=state->failure;return snapshot;
}
std::unique_ptr<Operation> WinHttpExplanationTransport::startImpl(const RequestBinding &binding,const QByteArray &payload,Completion completion,Observer observer,ResponseContract contract,std::shared_ptr<const void> jobToken){
    if(QThread::currentThread()!=thread())return {};
    auto state=std::make_shared<State>();state->timers();state->binding=binding;state->payload=payload;state->completion=std::move(completion);state->observer=std::move(observer);state->contract=contract;
    state->groundedJobToken=std::move(jobToken);
    auto cancel=[weak=std::weak_ptr<State>(state)]{if(auto s=weak.lock())QMetaObject::invokeMethod(s.get(),[s]{s->finish(Broker::Failure::Cancelled,Error::Cancelled);},Qt::QueuedConnection);};
    auto operation=std::make_unique<HttpOperation>(std::move(cancel));
    auto reject=[state](Broker::Failure why,Error error){QTimer::singleShot(0,state.get(),[state,why,error]{state->finish(why,error);});};
    Broker::TokenIdentity identity;
    if(!Broker::ProductionActivation::approved()||!vault_||!Broker::tokenIdentity(GetCurrentProcess(),identity)||!identity.ordinary){reject(Broker::Failure::ConfigurationNotApproved,Error::Unavailable);return operation;}
    if(!active_.expired()){reject(Broker::Failure::Capacity,Error::RateLimited);return operation;}
    // Hoy no existe catalogo publico productivo: ninguna muestra se manda al proveedor.
    constexpr bool publicCatalogPopulated=false;
    if((contract==ResponseContract::Legacy1?!publicCatalogPopulated:!GroundedBridge::FixedUltraPayloadBuilder::validProfile(payload))||payload.isEmpty()||payload.size()>4096||!binding.context.pending||!binding.context.serviceAvailable){reject(Broker::Failure::ConfigurationNotApproved,Error::Unavailable);return operation;}
    active_=state;if(!state->prepare()){state->finish(Broker::Failure::TransportUnavailable,Error::Unavailable);return operation;}
    bool headerReady=false;
    if(vault_->withSecret([&](const unsigned char *secret,size_t size){headerReady=state->authorize(secret,size);})!=Broker::Failure::None||!headerReady){state->finish(Broker::Failure::VaultUnavailable,Error::Unavailable);return operation;}
    const auto budget=vault_->reserveAttempt();if(budget!=Broker::Failure::None){state->finish(budget,Error::RateLimited);return operation;}
    state->send();return operation;
}
}
