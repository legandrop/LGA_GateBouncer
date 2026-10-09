#pragma once
#include "GeneralContracts.h"
#include <map>
#include <mutex>
namespace Gate::Assistance::General {
class GeneralFactory;
class PrivateGeneralFactoryTest;
// Una aprobación identifica un trabajo aun cuando dos runtimes la reciben.
class GeneralJobRegistry final {
private:
    friend class GeneralFactory;
    friend class GeneralRuntime;
    friend class PrivateGeneralFactoryTest;
    GeneralJobRegistry()=default;
    bool claim(const ApprovalRecord&);
    std::mutex mutex_;
    std::map<std::pair<Id128,Id128>,std::pair<Digest256,Digest256>> claimed_;
};
}
