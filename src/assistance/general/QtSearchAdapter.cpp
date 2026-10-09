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
    if(QThread::currentThread()!=thread()||pending_||!client_||!validBinding(b)||!validPublicFields(p)||!completion||
        approvalDigest(p,b.approvalEpoch)!=b.publicApprovalDigest||client_->instanceToken().toStdString()!=b.providerInstance||
        client_->configurationBinding()!=QByteArray(reinterpret_cast<const char*>(b.providerConfiguration.data()),32).toHex())return false;
    pending_=Pending{b,p,std::move(completion)};QPointer<QtSearchAdapter> self(this);
    const bool started=client_->begin({QString::fromUtf8(b.requestId),b.generation,QString::fromUtf8(p.query)});
    if(!self)return started;
    if(!started)pending_.reset();
    return started;
}
void QtSearchAdapter::cancel(){if(!pending_)return;pending_.reset();if(client_)client_->cancel();}
void QtSearchAdapter::receive(const gatebouncer::websearch::SearchResult& r) {
    if(!pending_)return;
    const auto& b=pending_->binding;
    const bool same=r.input.requestId.toStdString()==b.requestId&&r.input.generation==b.generation&&
        r.input.publicQuery.toStdString()==pending_->fields.query&&r.instanceToken.toStdString()==b.providerInstance&&
        r.configurationBinding==QByteArray(reinterpret_cast<const char*>(b.providerConfiguration.data()),32).toHex()&&std::uint8_t(r.provider)+1==std::uint8_t(b.provider);
    // Un resultado retirado de A no consume el callback ni el contexto de B.
    if(!same)return;
    auto pending=std::move(*pending_);pending_.reset();SearchReply out{pending.binding,{},Failure::SearchUnavailable};
    if(r.status==gatebouncer::websearch::Status::Evidence||r.status==gatebouncer::websearch::Status::NoEvidence){
        out.failure=Failure::None;for(const auto& c:r.citations)if(c.retrievalUtc.isValid()&&c.retrievalUtc.toMSecsSinceEpoch()>0)
            out.citations.push_back({0,c.url.toEncoded().toStdString(),c.title.toUtf8().toStdString(),c.snippet.toUtf8().toStdString(),c.origin.toUtf8().toStdString(),std::uint64_t(c.retrievalUtc.toMSecsSinceEpoch()),false});
    }else if(r.status==gatebouncer::websearch::Status::Cancelled)out.failure=Failure::Cancelled;
    auto completion=std::move(pending.completion);if(completion)completion(std::move(out));
}
}
