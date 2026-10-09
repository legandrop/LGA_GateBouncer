#pragma once
#define NOMINMAX
#include "policy.h"
#include <windows.h>
#include <fwpmu.h>
#include <atomic>

namespace gb {
namespace decisions {class NativeCollector;}
constexpr wchar_t ServiceName[]=L"LGAGateBouncerLab";
bool guestActivationAuthorized();
class WfpBackend final:public Backend {
public:
    explicit WfpBackend(SelectorRegistry& registry):registry_(registry){}
    ~WfpBackend() override;
    bool connectGuest();
    bool available()const override;
    bool actualOs()const override{return available();}
    bool apply(const std::vector<Rule>& rules,std::uint64_t revision)override;
    bool matches(const std::vector<Rule>& rules,std::uint64_t revision)override;
    void attachCollector(decisions::NativeCollector* collector);
private:
    static void CALLBACK eventCallback(void* context,const FWPM_NET_EVENT1* event);
    SelectorRegistry& registry_;
    HANDLE engine_=nullptr,subscription_=nullptr;
    std::vector<Bytes> ownTools_;
    std::mutex callbackMutex_;
    decisions::NativeCollector* collector_=nullptr;
};
class DisconnectedBackend final:public Backend {
public:
    bool available()const override{return false;}
    bool apply(const std::vector<Rule>&,std::uint64_t)override{return false;}
    bool matches(const std::vector<Rule>&,std::uint64_t)override{return false;}
};
}
