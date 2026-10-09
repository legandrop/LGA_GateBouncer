#include "GeneralJobRegistry.h"
namespace Gate::Assistance::General {
bool GeneralJobRegistry::claim(const ApprovalRecord& record) {
    auto pending=record.binding();pending.approvalEpoch=0;pending.publicApprovalDigest={};
    // El fingerprint se conserva; nunca amplía la clave efectiva del trabajo.
    const auto fingerprint=std::make_pair(pending.canonicalDigest(),approvalDigest(record.fields(),1));
    std::lock_guard<std::mutex> lock(mutex_);
    const auto key=std::make_pair(record.connection(),record.correlation());
    if(claimed_.count(key)||claimed_.size()>=256)return false;
    claimed_.emplace(key,fingerprint);return true;
}
}
