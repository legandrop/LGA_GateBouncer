#include "wfp_backend.h"
#include "collector_ii.h"
#include "directional_specs.h"
#include <sddl.h>
#include <shlobj.h>
#include <algorithm>
#include <cstring>
#include <iostream>

namespace gb {
namespace {
// Identidades propias del proveedor; no se usa la subcapa predeterminada.
const GUID Provider={0xeec4d47a,0x91a5,0x4f6c,{0xba,0x34,0xb1,0xc7,0x8d,0xaa,0x82,0x31}};
const GUID Sublayer={0xa80c1782,0x61a7,0x4499,{0xb7,0x96,0x5a,0x3d,0x3a,0x28,0x22,0x39}};
bool same(const GUID& a,const GUID& b){return std::memcmp(&a,&b,sizeof(GUID))==0;}
bool localToolPath(const std::wstring& path){
    if(path.size()<4||path[1]!=L':'||path[2]!=L'\\'||GetDriveTypeW(path.substr(0,3).c_str())!=DRIVE_FIXED)return false;
    // Guardas desde la raiz, antes de consultar un descendiente; ningun destino reparse.
    std::size_t end=3;while(end<path.size()){end=path.find(L'\\',end);if(end==std::wstring::npos)end=path.size();auto current=path.substr(0,end);auto attributes=GetFileAttributesW(current.c_str());if(attributes==INVALID_FILE_ATTRIBUTES||(attributes&FILE_ATTRIBUTE_REPARSE_POINT))return false;if(end==path.size())return !(attributes&FILE_ATTRIBUTE_DIRECTORY);++end;}
    return false;
}
GUID key(const Id& id,unsigned slot){Bytes b(id.begin(),id.end());auto n=integer(slot,4);b.insert(b.end(),n.begin(),n.end());auto d=sha256(b);GUID g{};std::memcpy(&g,d.data(),sizeof(g));return g;}
struct Spec { GUID id,layer;DWORD flags;std::uint64_t weight;FWP_ACTION_TYPE action;Bytes appId;unsigned rawMode=0;bool raw=false;bool unicast=false; };
std::vector<Spec> specs(const std::vector<Rule>& rules){
    const GUID layers[]={FWPM_LAYER_ALE_AUTH_CONNECT_V4,FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        FWPM_LAYER_ALE_AUTH_LISTEN_V4,FWPM_LAYER_ALE_AUTH_LISTEN_V6};
    Id baseline{};baseline[0]=0xab;std::vector<Spec> out;unsigned slot=0;
    for(auto flags:{DWORD(FWPM_FILTER_FLAG_PERSISTENT),DWORD(FWPM_FILTER_FLAG_BOOTTIME)}){
        for(const auto& layer:layers)out.push_back({key(baseline,slot++),layer,flags,0,FWP_ACTION_BLOCK,{}});
        for(const auto& layer:{FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6}){
            out.push_back({key(baseline,slot++),layer,flags,200,FWP_ACTION_BLOCK,{},0,true});
            for(unsigned mode:{0x98000001u,0x98000002u,0x98000003u})out.push_back({key(baseline,slot++),layer,flags,200,FWP_ACTION_BLOCK,{},mode,false});
        }
    }
    for(const auto& r:rules){unsigned index=0;for(const auto& layer:layers)out.push_back({key(r.id,index++),layer,FWPM_FILTER_FLAG_PERSISTENT,r.decision==1?200ull:100ull,static_cast<FWP_ACTION_TYPE>(r.decision==1?FWP_ACTION_BLOCK:FWP_ACTION_PERMIT),r.appId});}
    return out;
}
std::vector<FWPM_FILTER_CONDITION0> conditions(const Spec& s,FWP_BYTE_BLOB& blob){
    std::vector<FWPM_FILTER_CONDITION0> c;
    if(!s.appId.empty()){blob={static_cast<UINT32>(s.appId.size()),const_cast<UINT8*>(s.appId.data())};FWPM_FILTER_CONDITION0 x{};x.fieldKey=FWPM_CONDITION_ALE_APP_ID;x.matchType=FWP_MATCH_EQUAL;x.conditionValue.type=FWP_BYTE_BLOB_TYPE;x.conditionValue.byteBlob=&blob;c.push_back(x);}
    if(s.raw){FWPM_FILTER_CONDITION0 x{};x.fieldKey=FWPM_CONDITION_FLAGS;x.matchType=FWP_MATCH_FLAGS_ALL_SET;x.conditionValue.type=FWP_UINT32;x.conditionValue.uint32=FWP_CONDITION_FLAG_IS_RAW_ENDPOINT;c.push_back(x);}
    if(s.rawMode){FWPM_FILTER_CONDITION0 x{};x.fieldKey=FWPM_CONDITION_ALE_PROMISCUOUS_MODE;x.matchType=FWP_MATCH_EQUAL;x.conditionValue.type=FWP_UINT32;x.conditionValue.uint32=s.rawMode;c.push_back(x);}
    if(s.unicast){FWPM_FILTER_CONDITION0 x{};x.fieldKey=FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE;x.matchType=FWP_MATCH_EQUAL;x.conditionValue.type=FWP_UINT8;x.conditionValue.uint8=1;c.push_back(x);}
    return c;
}
Bytes metadata(std::uint64_t revision){Bytes b={'G','B','F','1'};auto n=integer(revision,8);b.insert(b.end(),n.begin(),n.end());return b;}
bool conditionSame(const FWPM_FILTER_CONDITION0& a,const FWPM_FILTER_CONDITION0& b){
    if(!same(a.fieldKey,b.fieldKey)||a.matchType!=b.matchType||a.conditionValue.type!=b.conditionValue.type)return false;
    if(a.conditionValue.type==FWP_UINT32)return a.conditionValue.uint32==b.conditionValue.uint32;
    if(a.conditionValue.type==FWP_UINT8)return a.conditionValue.uint8==b.conditionValue.uint8;
    if(a.conditionValue.type==FWP_BYTE_BLOB_TYPE){auto x=a.conditionValue.byteBlob,y=b.conditionValue.byteBlob;return x&&y&&x->size==y->size&&(x->size==0||std::memcmp(x->data,y->data,x->size)==0);}
    return false;
}
bool enumerate(HANDLE engine,std::vector<GUID>& keys){
    HANDLE enumeration=nullptr;FWPM_FILTER_ENUM_TEMPLATE0 t{};t.providerKey=const_cast<GUID*>(&Provider);t.enumType=FWP_FILTER_ENUM_FULLY_CONTAINED;t.flags=FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME|FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;
    if(FwpmFilterCreateEnumHandle0(engine,&t,&enumeration)!=ERROR_SUCCESS)return false;
    bool ok=true;for(;;){FWPM_FILTER0** filters=nullptr;UINT32 count=0;auto e=FwpmFilterEnum0(engine,enumeration,256,&filters,&count);if(e!=ERROR_SUCCESS){ok=false;break;}for(UINT32 i=0;i<count;++i)keys.push_back(filters[i]->filterKey);FwpmFreeMemory0(reinterpret_cast<void**>(&filters));if(count==0)break;if(keys.size()>MaxRules*6+64){ok=false;break;}}
    if(FwpmFilterDestroyEnumHandle0(engine,enumeration)!=ERROR_SUCCESS)ok=false;return ok;
}
bool objectIdentity(HANDLE engine,const wchar_t *serviceName){
    FWPM_PROVIDER0* provider=nullptr;FWPM_SUBLAYER0* sublayer=nullptr;
    bool ok=FwpmProviderGetByKey0(engine,&Provider,&provider)==ERROR_SUCCESS;
    if(ok)ok=provider->serviceName&&std::wcscmp(provider->serviceName,serviceName)==0&&provider->flags==FWPM_PROVIDER_FLAG_PERSISTENT;
    if(ok)ok=FwpmSubLayerGetByKey0(engine,&Sublayer,&sublayer)==ERROR_SUCCESS;
    if(ok)ok=sublayer->providerKey&&same(*sublayer->providerKey,Provider)&&sublayer->flags==FWPM_SUBLAYER_FLAG_PERSISTENT&&sublayer->weight==0x7d00;
    if(provider)FwpmFreeMemory0(reinterpret_cast<void**>(&provider));if(sublayer)FwpmFreeMemory0(reinterpret_cast<void**>(&sublayer));return ok;
}
bool objects(HANDLE engine,const wchar_t *serviceName){
    PSECURITY_DESCRIPTOR sd=nullptr;if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",SDDL_REVISION_1,&sd,nullptr))return false;
    FWPM_PROVIDER0 p{};p.providerKey=Provider;p.displayData.name=const_cast<wchar_t*>(std::wcscmp(serviceName,ServiceName) == 0 ? L"LGA GateBouncer lab" : L"LGA GateBouncer");p.flags=FWPM_PROVIDER_FLAG_PERSISTENT;p.serviceName=const_cast<wchar_t*>(serviceName);
    auto error=FwpmProviderAdd0(engine,&p,sd);
    bool ok=error==ERROR_SUCCESS||error==FWP_E_ALREADY_EXISTS;
    if(ok){FWPM_PROVIDER0* current=nullptr;ok=FwpmProviderGetByKey0(engine,&Provider,&current)==ERROR_SUCCESS;if(ok)ok=current->serviceName&&std::wcscmp(current->serviceName,serviceName)==0&&(current->flags&FWPM_PROVIDER_FLAG_PERSISTENT);if(current)FwpmFreeMemory0(reinterpret_cast<void**>(&current));}
    if(ok){FWPM_SUBLAYER0 s{};s.subLayerKey=Sublayer;s.displayData.name=p.displayData.name;s.flags=FWPM_SUBLAYER_FLAG_PERSISTENT;s.providerKey=const_cast<GUID*>(&Provider);s.weight=0x7d00;error=FwpmSubLayerAdd0(engine,&s,sd);ok=error==ERROR_SUCCESS||error==FWP_E_ALREADY_EXISTS;}
    if(ok){FWPM_SUBLAYER0* current=nullptr;ok=FwpmSubLayerGetByKey0(engine,&Sublayer,&current)==ERROR_SUCCESS;if(ok)ok=current->providerKey&&same(*current->providerKey,Provider)&&current->flags==FWPM_SUBLAYER_FLAG_PERSISTENT&&current->weight==0x7d00;if(current)FwpmFreeMemory0(reinterpret_cast<void**>(&current));}
    LocalFree(sd);return ok&&objectIdentity(engine,serviceName);
}
bool initialAbsent(HANDLE engine) {
    FWPM_PROVIDER0 *provider = nullptr; FWPM_SUBLAYER0 *sublayer = nullptr;
    const auto p = FwpmProviderGetByKey0(engine,&Provider,&provider);
    const auto s = FwpmSubLayerGetByKey0(engine,&Sublayer,&sublayer);
    const bool absent = p == FWP_E_PROVIDER_NOT_FOUND && s == FWP_E_SUBLAYER_NOT_FOUND && !provider && !sublayer;
    if (provider) FwpmFreeMemory0(reinterpret_cast<void **>(&provider));
    if (sublayer) FwpmFreeMemory0(reinterpret_cast<void **>(&sublayer));
    if (!absent) return false;
    HANDLE enumeration = nullptr;
    if (FwpmFilterCreateEnumHandle0(engine,nullptr,&enumeration) != ERROR_SUCCESS || !enumeration) return false;
    bool ok = true, ended = false; std::size_t total = 0;
    while (ok && !ended) {
        FWPM_FILTER0 **rows = nullptr; UINT32 count = 0;
        const auto result = FwpmFilterEnum0(engine,enumeration,64,&rows,&count);
        if (result != ERROR_SUCCESS || count > 64 || (count && !rows) || count > 65536-total) ok = false;
        if (ok) for (UINT32 i = 0; i < count; ++i)
            if (!rows[i] || (rows[i]->providerKey && same(*rows[i]->providerKey,Provider))) { ok = false; break; }
        if (rows) FwpmFreeMemory0(reinterpret_cast<void **>(&rows));
        total += count; ended = count < 64;
        if (total > 65536) ok = false;
    }
    return FwpmFilterDestroyEnumHandle0(engine,enumeration) == ERROR_SUCCESS && ok && ended;
}
}
bool guestActivationAuthorized(){
    // Marcador administrativo del harness invitado. No se escribe desde el producto.
    DWORD enabled=0,size=sizeof(enabled);auto e=RegGetValueW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\LGA\\GateBouncerLab",L"EnableWfp",RRF_RT_REG_DWORD,nullptr,&enabled,&size);
    return e==ERROR_SUCCESS&&enabled==1&&IsUserAnAdmin();
}
WfpBackend::~WfpBackend(){if(subscription_)FwpmNetEventUnsubscribe0(engine_,subscription_);if(engine_)FwpmEngineClose0(engine_);}
bool WfpBackend::authorized() const {
    return deployment_ ? deployment_->mode() == controller::DeploymentMode::Product &&
        deployment_->serviceAdmittedCurrent() : guestActivationAuthorized();
}
const wchar_t *WfpBackend::serviceName() const {
    return controller::deploymentService(deployment_ ? deployment_->mode() : controller::DeploymentMode::Laboratory);
}
bool WfpBackend::connectGuest() {
    return !deployment_ && guestActivationAuthorized() && connect();
}
bool WfpBackend::connectProduct(std::shared_ptr<controller::Deployment> owner) {
    if (engine_ || deployment_ || !owner || owner->mode() != controller::DeploymentMode::Product ||
        !owner->serviceAdmittedCurrent()) return false;
    deployment_ = std::move(owner);
    return connect() && authorized();
}
bool WfpBackend::available()const{if(!engine_||!authorized())return false;FWP_VALUE0* value=nullptr;auto error=FwpmEngineGetOption0(engine_,FWPM_ENGINE_COLLECT_NET_EVENTS,&value);if(value)FwpmFreeMemory0(reinterpret_cast<void**>(&value));return error==ERROR_SUCCESS;}
decisions::CatalogPlanBuilder::WriteOutcome WfpBackend::applyPrincipalPlan(
    decisions::CatalogPlanBuilder &plan,
    const std::shared_ptr<const decisions::allnative::CatalogSnapshot> &before,
    decisions::CatalogPlanBuilder::VerifyBeforeWrite verify, void *context) noexcept {
    if (!engine_ || !authorized() || !verify || !context) return {};
    struct Check {
        WfpBackend *backend;
        HANDLE engine;
        decisions::CatalogPlanBuilder::VerifyBeforeWrite verify;
        void *context;
    } check{this, engine_, verify, context};
    auto inside = [](void *raw) noexcept {
        auto &check = *static_cast<Check *>(raw);
        try { return check.backend->authorized() && objectIdentity(check.engine,check.backend->serviceName()) && check.verify(check.context) && check.backend->authorized(); }
        catch (...) { return false; }
    };
    return plan.transact(engine_, decisions::CatalogPlanBuilder::WriteApi{}, before, inside, &check);
}
decisions::CatalogPlanBuilder::WriteOutcome WfpBackend::applyInitialPrincipalPlan(
    decisions::CatalogPlanBuilder &plan,decisions::CatalogPlanBuilder::VerifyBeforeWrite verify,void *context) noexcept {
    if (!engine_ || !authorized() || !verify || !context) return {};
    struct Check { WfpBackend *backend; HANDLE engine; decisions::CatalogPlanBuilder::VerifyBeforeWrite verify; void *context; }
        check{this,engine_,verify,context};
    const auto inside = [](void *raw) noexcept {
        auto &c = *static_cast<Check *>(raw);
        try { return c.backend->authorized() && c.verify(c.context) && initialAbsent(c.engine) && objects(c.engine,c.backend->serviceName()) &&
            objectIdentity(c.engine,c.backend->serviceName()) && c.verify(c.context) && c.backend->authorized(); }
        catch (...) { return false; }
    };
    return plan.transactInitial(engine_,decisions::CatalogPlanBuilder::WriteApi{},inside,&check);
}
bool WfpBackend::connect(){
    if(!authorized()||engine_)return false;
    FWPM_SESSION0 session{};session.displayData.name=const_cast<wchar_t*>(deployment_ ? L"LGA GateBouncer" : L"LGA GateBouncer lab");session.txnWaitTimeoutInMSec=5000;
    if(FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,&session,&engine_)!=ERROR_SUCCESS)return false;
    wchar_t path[32768]{};auto n=GetModuleFileNameW(nullptr,path,32768);if(!n||n>=32768||n<3||path[1]!=L':'||GetDriveTypeW(std::wstring(path,path+3).c_str())!=DRIVE_FIXED)return false;
    std::wstring own(path,n);auto slash=own.find_last_of(L"\\/");if(slash==std::wstring::npos)return false;
    // Rutas fijas del paquete propio; no se inspeccionan paths recibidos por IPC.
    for(const auto& tool:{own,own.substr(0,slash+1)+L"GateBouncerProbe.exe"}){if(!localToolPath(tool))continue;FWP_BYTE_BLOB* blob=nullptr;if(FwpmGetAppIdFromFileName0(tool.c_str(),&blob)!=ERROR_SUCCESS)continue;ownTools_.emplace_back(blob->data,blob->data+blob->size);FwpmFreeMemory0(reinterpret_cast<void**>(&blob));}
    FWPM_NET_EVENT_SUBSCRIPTION0 subscription{};
    // No modifica la opcion global de recoleccion. Sin eventos, no registra selectors.
    FwpmNetEventSubscribe0(engine_,&subscription,&WfpBackend::eventCallback,this,&subscription_);
    return !ownTools_.empty();
}
void CALLBACK WfpBackend::eventCallback(void* context,const FWPM_NET_EVENT1* event){
    auto self=static_cast<WfpBackend*>(context);std::lock_guard<std::mutex> guard(self->callbackMutex_);
    if(self->collector_){try{self->collector_->capture(event);}catch(...){self->collector_->unavailable(7);}return;}
    if(!event||event->type!=FWPM_NET_EVENT_TYPE_CLASSIFY_DROP||!event->classifyDrop||!(event->header.flags&FWPM_NET_EVENT_FLAG_APP_ID_SET)||!event->header.appId.data||event->header.appId.size>32768)return;
    FWPM_FILTER0* filter=nullptr;if(FwpmFilterGetById0(self->engine_,event->classifyDrop->filterId,&filter)!=ERROR_SUCCESS)return;
    bool own=filter->providerKey&&same(*filter->providerKey,Provider)&&same(filter->subLayerKey,Sublayer)&&filter->action.type==FWP_ACTION_BLOCK;
    FwpmFreeMemory0(reinterpret_cast<void**>(&filter));if(!own)return;
    try{Bytes native(event->header.appId.data,event->header.appId.data+event->header.appId.size);if(std::find(self->ownTools_.begin(),self->ownTools_.end(),native)==self->ownTools_.end())return;auto digest=sha256(native);Id candidate{};std::copy_n(digest.begin(),16,candidate.begin());bool existing=self->registry_.lookup(candidate).has_value();auto id=self->registry_.registerNative(native);if(!zero(id)&&!existing)std::clog<<"Selector nativo local registrado: "<<hex(id)<<'\n';}catch(...){/* El evento perdido no cambia filtros. */}
}
void WfpBackend::attachCollector(decisions::NativeCollector* collector){std::lock_guard<std::mutex> lock(callbackMutex_);collector_=collector;if(collector_){collector_->whitelist(ownTools_);if(!subscription_)collector_->unavailable(2);}}
bool WfpBackend::apply(const std::vector<Rule>& rules,std::uint64_t revision){
    if(!available()||!authorized()||rules.size()>MaxRules)return false;
    for(const auto& r:rules)if(std::find(ownTools_.begin(),ownTools_.end(),r.appId)==ownTools_.end())return false;
    if(FwpmTransactionBegin0(engine_,0)!=ERROR_SUCCESS)return false;
    bool ok=objects(engine_,serviceName());std::vector<GUID> old;
    if(ok)ok=enumerate(engine_,old);
    if(ok)for(auto& id:old)if(FwpmFilterDeleteByKey0(engine_,&id)!=ERROR_SUCCESS){ok=false;break;}
    auto data=metadata(revision);auto wanted=specs(rules);
    if(ok)for(const auto& s:wanted){FWP_BYTE_BLOB blob{};auto c=conditions(s,blob);FWPM_FILTER0 f{};f.filterKey=s.id;f.displayData.name=const_cast<wchar_t*>(L"LGA GateBouncer lab policy");f.flags=s.flags;f.providerKey=const_cast<GUID*>(&Provider);f.providerData={static_cast<UINT32>(data.size()),data.data()};f.layerKey=s.layer;f.subLayerKey=Sublayer;auto weight=s.weight;f.weight.type=FWP_UINT64;f.weight.uint64=&weight;f.numFilterConditions=static_cast<UINT32>(c.size());f.filterCondition=c.data();f.action.type=s.action;if(FwpmFilterAdd0(engine_,&f,nullptr,nullptr)!=ERROR_SUCCESS){ok=false;break;}}
    if(!ok){FwpmTransactionAbort0(engine_);return false;}
    if(FwpmTransactionCommit0(engine_)!=ERROR_SUCCESS){FwpmTransactionAbort0(engine_);return false;}return true;
}
bool WfpBackend::matches(const std::vector<Rule>& rules,std::uint64_t revision){
    if(!available()||!objectIdentity(engine_,serviceName()))return false;auto wanted=specs(rules);std::vector<GUID> actual;if(!enumerate(engine_,actual)||actual.size()!=wanted.size())return false;
    auto meta=metadata(revision);std::vector<decisions::LedgerFilter> ledger;
    for(const auto& s:wanted){FWPM_FILTER0* f=nullptr;if(FwpmFilterGetByKey0(engine_,&s.id,&f)!=ERROR_SUCCESS)return false;FWP_BYTE_BLOB blob{};auto c=conditions(s,blob);
        bool ok=f->providerKey&&same(*f->providerKey,Provider)&&same(f->subLayerKey,Sublayer)&&same(f->layerKey,s.layer)&&f->flags==s.flags&&f->action.type==s.action&&f->weight.type==FWP_UINT64&&f->weight.uint64&&*f->weight.uint64==s.weight&&f->numFilterConditions==c.size()&&f->providerData.size==meta.size()&&f->providerData.data&&std::memcmp(f->providerData.data,meta.data(),meta.size())==0;
        if(ok)for(std::size_t i=0;i<c.size();++i)if(!conditionSame(f->filterCondition[i],c[i])){ok=false;break;}
        if(ok&&revision!=UINT64_MAX){FWPM_LAYER0* layer=nullptr;ok=FwpmLayerGetByKey0(engine_,&f->layerKey,&layer)==ERROR_SUCCESS;
            if(ok){std::uint8_t flow=0;if(same(f->layerKey,FWPM_LAYER_ALE_AUTH_CONNECT_V4)||same(f->layerKey,FWPM_LAYER_ALE_AUTH_CONNECT_V6))flow=2;
                if(same(f->layerKey,FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4)||same(f->layerKey,FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6))flow=1;
                decisions::LedgerFilter item;
                item.filterId=f->filterId;item.generation=revision+1;item.desired=revision;
                item.guid=decisions::canonicalGuid(f->filterKey);item.layerId=layer->layerId;
                item.originalFlow=flow;item.drop=f->action.type==FWP_ACTION_BLOCK;
                item.layerGuid=decisions::canonicalGuid(f->layerKey);item.rule[0]=0xab;item.appId=s.appId;
                for(const auto& r:rules)for(unsigned slot=0;slot<6;++slot)
                    if(same(key(r.id,slot),s.id))item.rule=r.id;
                item.origin=flow==2?1:flow==1?2:
                    (same(s.layer,FWPM_LAYER_ALE_AUTH_LISTEN_V4)||same(s.layer,FWPM_LAYER_ALE_AUTH_LISTEN_V6))?3:0;
                item.direction=s.appId.empty()?0:3;item.mode=s.action==FWP_ACTION_PERMIT?2:0;
                ledger.push_back(std::move(item));}
            if(layer)FwpmFreeMemory0(reinterpret_cast<void**>(&layer));}
        FwpmFreeMemory0(reinterpret_cast<void**>(&f));if(!ok)return false;
    }
    std::lock_guard<std::mutex> lock(callbackMutex_);if(collector_){FILETIME clock{};GetSystemTimeAsFileTime(&clock);auto ft=(std::uint64_t(clock.dwHighDateTime)<<32)|clock.dwLowDateTime;
        if(!subscription_||!collector_->publish(std::move(ledger),ft))collector_->unavailable(7);}
    return true;
}
namespace {
const GUID& directionalLayer(directional::Layer layer) {
    static const GUID layers[]={FWPM_LAYER_ALE_AUTH_CONNECT_V4,FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        FWPM_LAYER_ALE_AUTH_LISTEN_V4,FWPM_LAYER_ALE_AUTH_LISTEN_V6,
        FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6};
    return layers[static_cast<unsigned>(layer)];
}
Spec nativeSpec(const directional::FilterSpec& s) {
    return {key(s.rule,s.slot),directionalLayer(s.layer),
            DWORD(s.boot?FWPM_FILTER_FLAG_BOOTTIME:FWPM_FILTER_FLAG_PERSISTENT),s.weight,
            FWP_ACTION_TYPE(s.action==1?FWP_ACTION_BLOCK:FWP_ACTION_PERMIT),s.appId,s.promiscuous,s.rawEndpoint,s.unicast};
}
}
bool WfpBackend::applyDirections(const std::vector<directional::Rule>& rules,std::uint64_t revision) {
    std::vector<directional::FilterSpec> wanted;
    if(!available()||!authorized()||!directional::generate(rules,revision,wanted))return false;
    for(const auto& r:rules)
        if(std::find(ownTools_.begin(),ownTools_.end(),r.appId)==ownTools_.end())return false;
    if(FwpmTransactionBegin0(engine_,0)!=ERROR_SUCCESS)return false;
    bool ok=objects(engine_,serviceName());std::vector<GUID> old;
    if(ok)ok=enumerate(engine_,old);
    if(ok)for(const auto& id:old)
        if(FwpmFilterDeleteByKey0(engine_,&id)!=ERROR_SUCCESS){ok=false;break;}
    if(ok)for(const auto& row:wanted) {
        auto s=nativeSpec(row);FWP_BYTE_BLOB blob{};auto c=conditions(s,blob);
        FWPM_FILTER0 f{};f.filterKey=s.id;f.displayData.name=const_cast<wchar_t*>(L"LGA GateBouncer directional policy");
        f.flags=s.flags;f.providerKey=const_cast<GUID*>(&Provider);
        f.providerData={static_cast<UINT32>(row.metadata.size()),const_cast<UINT8*>(row.metadata.data())};
        f.layerKey=s.layer;f.subLayerKey=Sublayer;auto weight=s.weight;
        f.weight.type=FWP_UINT64;f.weight.uint64=&weight;
        f.numFilterConditions=static_cast<UINT32>(c.size());f.filterCondition=c.data();f.action.type=s.action;
        if(FwpmFilterAdd0(engine_,&f,nullptr,nullptr)!=ERROR_SUCCESS){ok=false;break;}
    }
    if(!ok){FwpmTransactionAbort0(engine_);return false;}
    if(FwpmTransactionCommit0(engine_)!=ERROR_SUCCESS){FwpmTransactionAbort0(engine_);return false;}
    return true;
}
bool WfpBackend::matchDirections(const std::vector<directional::Rule>& rules,std::uint64_t revision) {
    std::vector<directional::FilterSpec> wanted;
    if(!available()||!objectIdentity(engine_,serviceName())||!directional::generate(rules,revision,wanted))return false;
    std::vector<GUID> actual;
    if(!enumerate(engine_,actual)||actual.size()!=wanted.size())return false;
    std::vector<decisions::LedgerFilter> ledger;
    for(const auto& row:wanted) {
        auto s=nativeSpec(row);FWPM_FILTER0* f=nullptr;
        if(FwpmFilterGetByKey0(engine_,&s.id,&f)!=ERROR_SUCCESS)return false;
        FWP_BYTE_BLOB blob{};auto c=conditions(s,blob);
        bool ok=f->providerKey&&same(*f->providerKey,Provider)&&same(f->subLayerKey,Sublayer)&&
            same(f->layerKey,s.layer)&&f->flags==s.flags&&f->action.type==s.action&&
            f->weight.type==FWP_UINT64&&f->weight.uint64&&*f->weight.uint64==s.weight&&
            f->effectiveWeight.type==FWP_UINT64&&f->effectiveWeight.uint64&&*f->effectiveWeight.uint64==s.weight&&
            f->numFilterConditions==c.size()&&f->providerData.size==row.metadata.size()&&
            f->providerData.data&&std::memcmp(f->providerData.data,row.metadata.data(),row.metadata.size())==0;
        if(ok)for(std::size_t i=0;i<c.size();++i)
            if(!conditionSame(f->filterCondition[i],c[i])){ok=false;break;}
        FWPM_LAYER0* layer=nullptr;
        if(ok)ok=FwpmLayerGetByKey0(engine_,&f->layerKey,&layer)==ERROR_SUCCESS;
        if(ok) {
            auto origin=directional::origin(row.layer);
            decisions::LedgerFilter item;
            item.filterId=f->filterId;item.generation=revision+1;item.desired=revision;
            item.guid=decisions::canonicalGuid(f->filterKey);item.layerId=layer->layerId;
            item.originalFlow=static_cast<std::uint8_t>(directional::originalFlow(origin));
            item.drop=s.action==FWP_ACTION_BLOCK;item.layerGuid=decisions::canonicalGuid(f->layerKey);
            item.rule=row.rule;item.appId=row.appId;item.origin=static_cast<std::uint8_t>(origin);
            item.direction=row.direction;item.mode=row.mode;ledger.push_back(std::move(item));
        }
        if(layer)FwpmFreeMemory0(reinterpret_cast<void**>(&layer));
        FwpmFreeMemory0(reinterpret_cast<void**>(&f));if(!ok)return false;
    }
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if(collector_) {
        FILETIME clock{};GetSystemTimeAsFileTime(&clock);
        auto ft=(std::uint64_t(clock.dwHighDateTime)<<32)|clock.dwLowDateTime;
        if(!subscription_||!collector_->publish(std::move(ledger),ft))collector_->unavailable(7);
    }
    return true;
}
}
