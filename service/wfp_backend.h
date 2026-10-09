#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "policy.h"
#include "coordinator_iii.h"
#include "catalog_plan_iv.h"
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
    bool applyDirections(const std::vector<directional::Rule>& rules,std::uint64_t revision);
    bool matchDirections(const std::vector<directional::Rule>& rules,std::uint64_t revision);
    // Gate U: source/fixtures no acreditan guard unicast/reauth/boot en Windows.
    bool directionalCoverageValidated() const { return false; }
    void attachCollector(decisions::NativeCollector* collector);
private:
    friend class decisions::NativeRuntime;
    decisions::CatalogPlanBuilder::WriteOutcome applyPrincipalPlan(
        decisions::CatalogPlanBuilder &,
        const std::shared_ptr<const decisions::allnative::CatalogSnapshot> &,
        decisions::CatalogPlanBuilder::VerifyBeforeWrite, void *) noexcept;
    decisions::CatalogPlanBuilder::WriteOutcome applyInitialPrincipalPlan(
        decisions::CatalogPlanBuilder &, decisions::CatalogPlanBuilder::VerifyBeforeWrite, void *) noexcept;
    static void CALLBACK eventCallback(void* context,const FWPM_NET_EVENT1* event);
    SelectorRegistry& registry_;
    HANDLE engine_=nullptr,subscription_=nullptr;
    std::vector<Bytes> ownTools_;
    std::mutex callbackMutex_;
    decisions::NativeCollector* collector_=nullptr;
};
class NativeDirections final : public directional::DirectionalBackend {
public:
    explicit NativeDirections(WfpBackend& backend):backend_(backend){}
    void initialLegacy(bool legacy){legacy_=legacy;}
    bool ready()const override{return backend_.available()&&backend_.directionalCoverageValidated();}
    bool apply(const std::vector<directional::Rule>& rules,std::uint64_t revision)override {
        legacy_=false;return backend_.applyDirections(rules,revision);
    }
    bool matches(const std::vector<directional::Rule>& rules,std::uint64_t revision)override {
        if(!legacy_)return backend_.matchDirections(rules,revision);
        std::vector<Rule> old;
        for(const auto& r:rules){if(r.direction!=3)return false;old.push_back({r.id,r.selector,r.action,r.appId});}
        return backend_.matches(old,revision);
    }
    bool actualOs()const override{return backend_.actualOs();}
private:
    WfpBackend& backend_;bool legacy_=false;
};
class DisconnectedBackend final:public Backend {
public:
    bool available()const override{return false;}
    bool apply(const std::vector<Rule>&,std::uint64_t)override{return false;}
    bool matches(const std::vector<Rule>&,std::uint64_t)override{return false;}
};
}
