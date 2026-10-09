#include "GeneralCoordinator.h"
#include "retrieval/StrictJson.h"
#include <limits>
namespace Gate::Assistance::General {
struct GeneralCoordinator::Impl : std::enable_shared_from_this<Impl> {
    struct Job {
        std::shared_ptr<const ApprovalRecord> approval;
        std::shared_ptr<const SealedGeneralPayload> seal;
        Completion completion;Progress progress;std::int64_t deadline=0;
        std::unique_ptr<Operation> model;bool searching=false,modelClaimed=false;
    };
    std::shared_ptr<SearchPort> search;std::shared_ptr<ModelPort> model;Current current;Clock clock;
    std::shared_ptr<Job> active;bool closed=false;
    bool same(const std::shared_ptr<Job>& j) const {return !closed&&active==j;}
    bool fresh(const std::shared_ptr<Job>& j) {
        if(!same(j))return false;
        const auto now=clock();if(!same(j))return false;
        if(now>=j->deadline){finish(j,State::Failed,Failure::Timeout);return false;}
        const bool approved=j->approval->isCurrent();if(!same(j))return false;
        const bool valid=approved&&current(j->approval->binding());if(!same(j))return false;
        const auto after=clock();if(!same(j))return false;
        if(after>=j->deadline){finish(j,State::Failed,Failure::Timeout);return false;}
        if(!valid){finish(j,State::Failed,Failure::Stale);return false;}return true;
    }
    void finish(std::shared_ptr<Job> j,State state,Failure failure,int http=0,std::optional<Inference> text={}) {
        if(active!=j)return;
        active.reset();
        Result result{j->approval->binding(),state,failure,http,j->seal?j->seal->citations():std::vector<Citation>{},std::move(text)};
        auto completion=std::move(j->completion);auto op=std::move(j->model);const bool stopSearch=j->searching;j->searching=false;
        if(stopSearch)search->cancel();
        if(op)op->cancel();
        if(completion)completion(std::move(result));
    }
    bool progress(const std::shared_ptr<Job>& j,State state) {
        if(!fresh(j))return false;
        auto callback=j->progress;if(callback)callback(state);return fresh(j);
    }
    void searched(const std::shared_ptr<Job>& j,SearchReply reply) {
        if(!same(j)||!j->searching||j->modelClaimed)return;
        j->searching=false;
        if(reply.binding!=j->approval->binding()){finish(j,State::Failed,Failure::Stale);return;}
        if(!fresh(j))return;
        if(reply.failure!=Failure::None){finish(j,reply.failure==Failure::Cancelled?State::Cancelled:State::Failed,reply.failure);return;}
        auto seal=GeneralPayloadBuilder::build(j->approval->binding(),j->approval->fields(),reply.citations);
        if(!fresh(j))return;
        if(!seal){finish(j,State::Insufficient,Failure::None);return;}
        j->seal=std::make_shared<const SealedGeneralPayload>(*seal);
        // Reclamar antes de callbacks: un duplicado no vuelve a emitir ni reservar.
        j->modelClaimed=true;
        if(!progress(j,State::Explaining))return;
        auto self=shared_from_this();auto operation=model->begin(j->approval->binding(),*j->seal,
            [self,j](ModelReply r){self->explained(j,std::move(r));});
        if(!same(j)){if(operation)operation->cancel();return;}
        if(!operation){finish(j,State::Failed,Failure::TransportUnavailable);return;}
        j->model=std::move(operation);fresh(j);
    }
    void explained(const std::shared_ptr<Job>& j,ModelReply reply) {
        if(!same(j))return;
        if(reply.binding!=j->approval->binding()){finish(j,State::Failed,Failure::Stale);return;}
        if(!fresh(j))return;
        if(reply.failure!=Failure::None){
            const bool uncertain=reply.failure==Failure::Uncertain&&reply.sendStarted&&(reply.observedHttpStatus==0||reply.observedHttpStatus==202);
            finish(j,uncertain?State::Uncertain:State::Failed,uncertain?Failure::Uncertain:
                (reply.failure==Failure::Uncertain?Failure::InvalidResponse:reply.failure),reply.observedHttpStatus);return;
        }
        if(reply.observedHttpStatus!=200||!reply.sendStarted){finish(j,State::Failed,Failure::InvalidResponse,reply.observedHttpStatus);return;}
        auto normalized=General3ResponseContract::normalize(reply.envelope,*j->seal);
        if(!normalized){finish(j,State::Failed,Failure::InvalidResponse,reply.observedHttpStatus);return;}
        const auto root=Retrieval::strictJson(QByteArray::fromStdString(*normalized),8192);
        const auto content=root->get("choices")->array.front().get("message")->get("content")->text()->toUtf8().toStdString();
        auto inference=General3ResponseContract::parseInference(content,j->seal->citations());
        if(!fresh(j))return;
        finish(j,inference?State::Evidence:State::Failed,inference?Failure::None:Failure::InvalidResponse,reply.observedHttpStatus,std::move(inference));
    }
};
GeneralCoordinator::GeneralCoordinator(std::shared_ptr<SearchPort> s,std::shared_ptr<ModelPort> m,Current c,Clock clock):impl_(std::make_shared<Impl>()) {
    impl_->search=std::move(s);impl_->model=std::move(m);impl_->current=std::move(c);impl_->clock=std::move(clock);
}
GeneralCoordinator::~GeneralCoordinator(){drain();}
bool GeneralCoordinator::begin(std::shared_ptr<const ApprovalRecord> approval,Completion completion,Progress progress) {
    const auto s=impl_;if(s->closed||s->active||!s->search||!s->model||!s->current||!s->clock||!approval||!completion||!validBinding(approval->binding()))return false;
    const auto now=s->clock();if(s->closed||s->active||now<0||now>std::numeric_limits<std::int64_t>::max()-45000)return false;
    return beginAt(std::move(approval),now+45000,std::move(completion),std::move(progress));
}
bool GeneralCoordinator::beginAt(std::shared_ptr<const ApprovalRecord> approval,std::int64_t absoluteDeadline,Completion completion,Progress progress) {
    const auto s=impl_;if(s->closed||s->active||!s->search||!s->model||!s->current||!s->clock||!approval||!completion||!validBinding(approval->binding()))return false;
    if(absoluteDeadline<=0)return false;
    auto job=std::make_shared<Impl::Job>();job->approval=std::move(approval);job->completion=std::move(completion);job->progress=std::move(progress);job->deadline=absoluteDeadline;s->active=job;
    if(!s->progress(job,State::Searching))return true;
    job->searching=true;
    const bool started=s->search->begin(job->approval->binding(),job->approval->fields(),[s,job](SearchReply r){s->searched(job,std::move(r));});
    if(!s->same(job))return true;
    if(!started){job->searching=false;s->finish(job,State::Failed,Failure::SearchRejected);}else s->fresh(job);return true;
}
void GeneralCoordinator::cancel(){const auto s=impl_;if(s->active)s->finish(s->active,State::Cancelled,Failure::Cancelled);}
void GeneralCoordinator::tick(){const auto s=impl_;if(s->active)s->fresh(s->active);}
void GeneralCoordinator::drain(){const auto s=impl_;s->closed=true;if(s->active)s->finish(s->active,State::Cancelled,Failure::Cancelled);}
}
