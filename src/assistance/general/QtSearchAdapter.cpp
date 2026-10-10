#include "QtSearchAdapter.h"
#include <QPointer>
#include <QThread>
#include <cstring>
namespace Gate::Assistance::General {
QtSearchAdapter::QtSearchAdapter(std::shared_ptr<gatebouncer::websearch::SearchClient> c,QObject* parent):QObject(parent),client_(std::move(c)) {
    connection_=connect(client_.get(),&gatebouncer::websearch::SearchClient::finished,this,&QtSearchAdapter::receive);
}
QtSearchAdapter::~QtSearchAdapter(){disconnect(connection_);cancel();}
bool QtSearchAdapter::begin(const FullBinding& b,const PublicFields& p,Completion completion) {
    return beginCurrent(b,p,std::move(completion),{});
}
bool QtSearchAdapter::beginCurrent(const FullBinding& b,const PublicFields& p,Completion completion,std::function<bool()> current) {
    if(QThread::currentThread()!=thread()||pending_||!client_||!validBinding(b)||!validPublicFields(p)||!completion||
        approvalDigest(p,b.approvalEpoch)!=b.publicApprovalDigest||client_->instanceToken().toStdString()!=b.providerInstance||
        client_->configurationBinding()!=QByteArray(reinterpret_cast<const char*>(b.providerConfiguration.data()),32).toHex())return false;
    pending_=Pending{b,p,std::move(completion)};QPointer<QtSearchAdapter> self(this);
    gatebouncer::websearch::SearchInput input{QString::fromUtf8(b.requestId),b.generation,QString::fromUtf8(p.query),{}};
    if(p.destination)input.destination=gatebouncer::websearch::Destination{QString::fromUtf8(p.destination->address),p.destination->port,p.destination->protocol,p.destination->observedAtMs};
    const bool started=client_->begin(input,std::move(current));
    if(!self)return started;
    if(!started)pending_.reset();
    return started;
}
void QtSearchAdapter::cancel(){if(!pending_)return;pending_.reset();if(client_)client_->cancel();}
void QtSearchAdapter::receive(const gatebouncer::websearch::SearchResult& r) {
    if(!pending_)return;
    const auto& b=pending_->binding;
    const bool same=r.input.requestId.toStdString()==b.requestId&&r.input.generation==b.generation&&
        r.input.publicQuery.toStdString()==pending_->fields.query&&r.input.destination.has_value()==pending_->fields.destination.has_value()&&
        (!r.input.destination||(r.input.destination->address.toStdString()==pending_->fields.destination->address&&
            r.input.destination->port==pending_->fields.destination->port&&r.input.destination->protocol==pending_->fields.destination->protocol&&
            r.input.destination->observedAtMs==pending_->fields.destination->observedAtMs))&&r.instanceToken.toStdString()==b.providerInstance&&
        r.configurationBinding==QByteArray(reinterpret_cast<const char*>(b.providerConfiguration.data()),32).toHex()&&std::uint8_t(r.provider)+1==std::uint8_t(b.provider);
    // Un resultado retirado de A no consume el callback ni el contexto de B.
    if(!same)return;
    auto pending=std::move(*pending_);pending_.reset();SearchReply out{pending.binding,{},Failure::SearchUnavailable};
    if(r.status==gatebouncer::websearch::Status::Evidence||r.status==gatebouncer::websearch::Status::NoEvidence){
        out.failure=Failure::None;for(const auto& c:r.citations)if(c.retrievalUtc.isValid()&&c.retrievalUtc.toMSecsSinceEpoch()>0)
            out.citations.push_back({0,c.url.toEncoded().toStdString(),c.title.toUtf8().toStdString(),c.snippet.toUtf8().toStdString(),c.origin.toUtf8().toStdString(),std::uint64_t(c.retrievalUtc.toMSecsSinceEpoch()),false,c.kind,c.subject.toStdString()});
    }else if(r.status==gatebouncer::websearch::Status::Cancelled)out.failure=Failure::Cancelled;
    else if(r.status==gatebouncer::websearch::Status::Unavailable){
        switch(gatebouncer::websearch::networkFailure(r.diagnostic,r.observedHttpStatus)){
        case gatebouncer::websearch::NetworkFailure::Timeout:out.failure=Failure::Timeout;break;
        case gatebouncer::websearch::NetworkFailure::Tls:out.failure=Failure::TlsFailure;break;
        case gatebouncer::websearch::NetworkFailure::Cancelled:out.failure=Failure::Cancelled;break;
        default:break;
        }
    }
    auto completion=std::move(pending.completion);if(completion)completion(std::move(out));
}
}
