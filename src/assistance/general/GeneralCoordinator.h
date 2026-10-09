#pragma once
#include "GeneralPayload.h"
namespace Gate::Assistance::General {
class GeneralCoordinator final {
public:
    using Current=std::function<bool(const FullBinding&)>;
    using Clock=std::function<std::int64_t()>;
    using Completion=std::function<void(Result)>;
    using Progress=std::function<void(State)>;
    GeneralCoordinator(std::shared_ptr<SearchPort>,std::shared_ptr<ModelPort>,Current,Clock);
    ~GeneralCoordinator();
    bool begin(std::shared_ptr<const ApprovalRecord>,Completion,Progress={});
    void cancel();
    void tick();
    void drain();
private:
    friend class GeneralRuntime;
    bool beginAt(std::shared_ptr<const ApprovalRecord>,std::int64_t absoluteDeadline,Completion,Progress);
    struct Impl;
    std::shared_ptr<Impl> impl_;
};
}
