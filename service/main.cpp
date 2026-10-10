#include "pipe_transport.h"
#include "wfp_backend.h"
#include "runtime_ii.h"
#include "../controller/deployment_prepare_win.h"
#include "../controller/deployment_maintenance_win.h"
#include <iostream>
#include <memory>
#include <string>
#include <sddl.h>
#ifdef _MSC_VER
#include <delayimp.h>
#include <cstring>
#endif

namespace {
using namespace gb;
SERVICE_STATUS_HANDLE statusHandle=nullptr;
HANDLE stopEvent=nullptr;
controller::DeploymentMode deploymentMode = controller::DeploymentMode::Laboratory;
#ifdef _MSC_VER
// La retención tiene vida de proceso, igual que QtCore y los destructores estáticos del parser.
std::shared_ptr<controller::Deployment> *serviceRuntimeOwner = nullptr;
FARPROC WINAPI serviceQtDelayHook(unsigned notification,PDelayLoadInfo information) {
    if (!information || !information->szDll) throw std::runtime_error("Delay import invalido");
    if (std::strcmp(information->szDll,"Qt6Cored.dll") == 0)
        throw std::runtime_error("El paquete del servicio requiere Qt MSVC Release");
    if (std::strcmp(information->szDll,"Qt6Core.dll") != 0) return nullptr;
    const auto module = serviceRuntimeOwner && *serviceRuntimeOwner ? (*serviceRuntimeOwner)->serviceQtModule() : nullptr;
    if (!module) throw std::runtime_error("Qt MSVC original no admitido");
    if (notification == dliNotePreLoadLibrary) return reinterpret_cast<FARPROC>(module);
    if (notification == dliNotePreGetProcAddress && information->hmodCur != module)
        throw std::runtime_error("Delay import de otro modulo Qt");
    return nullptr;
}
#endif
void report(DWORD state,DWORD error=NO_ERROR){SERVICE_STATUS status{};status.dwServiceType=SERVICE_WIN32_OWN_PROCESS;status.dwCurrentState=state;status.dwControlsAccepted=state==SERVICE_RUNNING?SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN:0;status.dwWin32ExitCode=error;if(state==SERVICE_START_PENDING||state==SERVICE_STOP_PENDING){status.dwCheckPoint=1;status.dwWaitHint=10000;}if(statusHandle)SetServiceStatus(statusHandle,&status);}
DWORD WINAPI handler(DWORD control,DWORD,void*,void*){if((control==SERVICE_CONTROL_STOP||control==SERVICE_CONTROL_SHUTDOWN)&&stopEvent){report(SERVICE_STOP_PENDING);SetEvent(stopEvent);}return NO_ERROR;}
Id bootIdentity(){
    // La subclave volatil desaparece al reiniciar Windows y persiste al caer el servicio.
    PSECURITY_DESCRIPTOR descriptor=nullptr;if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;KA;;;SY)(A;;KA;;;BA)",SDDL_REVISION_1,&descriptor,nullptr))throw std::runtime_error("ACL de arranque invalida");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),descriptor,FALSE};HKEY key=nullptr;DWORD disposition=0;
    const auto bootKey = std::wstring(controller::deploymentRegistry(deploymentMode)) + L"\\BootSession";
    auto error=RegCreateKeyExW(HKEY_LOCAL_MACHINE,bootKey.c_str(),0,nullptr,REG_OPTION_VOLATILE,KEY_QUERY_VALUE|KEY_SET_VALUE|READ_CONTROL,&attributes,&key,&disposition);LocalFree(descriptor);if(error!=ERROR_SUCCESS)throw std::runtime_error("Identidad de arranque no disponible");
    if(!native::protectedRegistry(key)){RegCloseKey(key);throw std::runtime_error("Configuracion de arranque no protegida");}
    Id id{};DWORD type=0,bytes=16;error=RegQueryValueExW(key,L"Id",nullptr,&type,id.data(),&bytes);
    if(error==ERROR_FILE_NOT_FOUND&&disposition==REG_CREATED_NEW_KEY){id=randomId();error=RegSetValueExW(key,L"Id",0,REG_BINARY,id.data(),16);type=REG_BINARY;bytes=16;}
    RegCloseKey(key);if(error!=ERROR_SUCCESS||type!=REG_BINARY||bytes!=16||zero(id))throw std::runtime_error("Identidad de arranque invalida");return id;
}
void WINAPI serviceMain(DWORD,wchar_t**){
    statusHandle=RegisterServiceCtrlHandlerExW(controller::deploymentService(deploymentMode),handler,nullptr);if(!statusHandle)return;report(SERVICE_START_PENDING);
    stopEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!stopEvent){report(SERVICE_STOPPED,GetLastError());return;}
    try{
        if(deploymentMode == controller::DeploymentMode::Laboratory && !guestActivationAuthorized()) throw std::runtime_error("Activacion invitada no autorizada");
        native::Handle token; HANDLE raw = nullptr;
        if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw)) throw std::runtime_error("Token del servicio no disponible");
        token.reset(raw);
        if(!native::systemServiceToken(token.value,controller::deploymentService(deploymentMode))) throw std::runtime_error("SID del servicio no admitido");
        wchar_t path[32768]{}; auto count=GetModuleFileNameW(nullptr,path,32768);
        if(!count||count>=32768) throw std::runtime_error("Imagen del servicio no disponible");
        const std::filesystem::path own(std::wstring(path,count));
        auto deployment=std::make_shared<controller::Deployment>(own.parent_path(),deploymentMode);
        Bytes account; std::filesystem::path root; bool provision=false;
        if(!deployment->verify(own,controller::DeploymentRole::Service)||
            !deployment->admitServiceConfiguration(account,root,provision)||!deployment->current())
            throw std::runtime_error("Deployment no admitido");
#ifdef _MSC_VER
        if (!deployment->loadServiceRuntime(deployment)) throw std::runtime_error("Runtime MSVC del servicio no admitido");
        serviceRuntimeOwner = new std::shared_ptr<controller::Deployment>(deployment);
#endif
        const auto boot=bootIdentity();
        SelectorRegistry registry; WfpBackend backend(registry);
        if(!deployment->current()||!(deploymentMode == controller::DeploymentMode::Product ? backend.connectProduct(deployment) : backend.connectGuest())) throw std::runtime_error("Backend no conectado");
        decisions::NativeRuntime runtime(backend,registry,root,std::move(account),randomId(),boot,
            deployment->root()/L"GateBouncer.exe",deployment);
        if(!runtime.initialize(provision)) throw std::runtime_error("Recuperacion de store pendiente");
        // El perfil único limita revisión; no afirma cobertura completa ni autoriza kernel scopes.
        decisions::NativeServer server(runtime);report(SERVICE_RUNNING);server.run(stopEvent);report(SERVICE_STOPPED);
    }catch(...){report(SERVICE_STOPPED,ERROR_SERVICE_SPECIFIC_ERROR);}
    CloseHandle(stopEvent);stopEvent=nullptr;
}
bool ownAdmin(){HANDLE token=nullptr;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return false;bool ok=elevatedAdministrator(token);CloseHandle(token);return ok;}
std::string narrow(const wchar_t* s){std::string out;for(;*s;++s){if(*s>127)throw std::runtime_error("Argumento invalido");out+=static_cast<char>(*s);}return out;}
}
#ifdef _MSC_VER
// Símbolo documentado de delayimp: nunca deja resolver QtCore por basename/PATH.
extern "C" const PfnDliHook __pfnDliNotifyHook2 = serviceQtDelayHook;
#endif
int wmain(int argc,wchar_t** argv){
    try{
        if(argc==6 && std::wstring(argv[1])==L"--prepare-deployment")
            return controller::prepareProductDeployment(argv[2],argv[3],argv[4],argv[5]) ? 0 : 2;
        if(argc==6 && std::wstring(argv[1])==L"--prepare-guest-deployment")
            return controller::prepareGuestDeployment(argv[2],argv[3],argv[4],argv[5]) ? 0 : 2;
        if ((argc == 5 && std::wstring(argv[1]) == L"--update-deployment") ||
            (argc == 3 && (std::wstring(argv[1]) == L"--uninstall-deployment" ||
                std::wstring(argv[1]) == L"--finalize-deployment"))) {
            const auto result = argc == 5 ? controller::updateProductDeployment(argv[2],argv[3],argv[4]) :
                std::wstring(argv[1]) == L"--finalize-deployment" ? controller::finalizeProductDeployment(argv[2]) :
                controller::uninstallProductDeployment(argv[2]);
            std::cout << "Mantenimiento resultado=" << static_cast<unsigned>(result.outcome) <<
                " fase=" << static_cast<unsigned>(result.phase) << " error=" << result.error <<
                " recuperacion_confirmada=" << result.recoveryRecorded << '\n';
            return result.outcome == controller::MaintenanceOutcome::UpdatedPrepared ||
                result.outcome == controller::MaintenanceOutcome::UninstalledRetained ||
                result.outcome == controller::MaintenanceOutcome::PreparedFinalized ? 0 : 2;
        }
        if ((argc == 5 && std::wstring(argv[1]) == L"--update-guest-deployment") ||
            (argc == 3 && (std::wstring(argv[1]) == L"--uninstall-guest-deployment" ||
                std::wstring(argv[1]) == L"--finalize-guest-deployment"))) {
            const auto result = argc == 5 ? controller::updateGuestDeployment(argv[2],argv[3],argv[4]) :
                std::wstring(argv[1]) == L"--finalize-guest-deployment" ? controller::finalizeGuestDeployment(argv[2]) :
                controller::uninstallGuestDeployment(argv[2]);
            std::cout << "Mantenimiento resultado=" << static_cast<unsigned>(result.outcome) <<
                " fase=" << static_cast<unsigned>(result.phase) << " error=" << result.error <<
                " recuperacion_confirmada=" << result.recoveryRecorded << '\n';
            return result.outcome == controller::MaintenanceOutcome::UpdatedPrepared ||
                result.outcome == controller::MaintenanceOutcome::UninstalledRetained ||
                result.outcome == controller::MaintenanceOutcome::PreparedFinalized ? 0 : 2;
        }
        if ((argc == 2 && std::wstring(argv[1]) == L"--service") ||
            (argc == 3 && std::wstring(argv[1]) == L"--service" && std::wstring(argv[2]) == L"--guest-wfp")) {
            deploymentMode = argc == 2 ? controller::DeploymentMode::Product : controller::DeploymentMode::Laboratory;
            if (deploymentMode == controller::DeploymentMode::Laboratory && !guestActivationAuthorized()) return 2;
            SERVICE_TABLE_ENTRYW table[]={{const_cast<wchar_t*>(controller::deploymentService(deploymentMode)),serviceMain},{nullptr,nullptr}};
            return StartServiceCtrlDispatcherW(table)?0:static_cast<int>(GetLastError());
        }
        bool control=argc>=3&&std::wstring(argv[1])==L"--control";
        if((argc==2&&std::wstring(argv[1])==L"--status")||control){
            if(control&&!ownAdmin()){std::cerr<<"Control requiere administrador elevado\n";return 2;}
            PipeClient client;if(!client.open(control)){std::cerr<<"Servicio no disponible o identidad no comprobada\n";return 3;}
            Frame request;request.type=Type::GetStatus;
            if(control&&std::wstring(argv[2])!=L"status"){
                auto verb=std::wstring(argv[2]);if((verb!=L"allow"&&verb!=L"block"&&verb!=L"revoke")||argc!=5)return 2;Id id{};if(!parseId(narrow(argv[3]),id))return 2;
                std::size_t consumed=0;auto text=std::wstring(argv[4]);if(text.empty()||text.find_first_not_of(L"0123456789")!=std::wstring::npos)return 2;auto revision=std::stoull(text,&consumed);if(consumed!=text.size())return 2;
                request.type=verb==L"revoke"?Type::RevokeRule:Type::CreateRule;request.fields={value(Tag::ExpectedDesiredRev,revision),value(verb==L"revoke"?Tag::RuleId:Tag::SelectorId,id)};
                if(request.type==Type::CreateRule){request.fields.push_back(value(Tag::Decision,verb==L"block"?1:2,1));request.fields.push_back(value(Tag::ScopeKind,1,1));}
            }
            Frame reply;if(!client.transact(request,reply))return 3;
            std::cout<<"Tipo="<<static_cast<unsigned>(reply.type)<<" comando="<<hex(reply.correlation)<<" deseada="<<get(reply,Tag::DesiredRev)<<" efectiva="<<get(reply,Tag::EffectiveRev)<<" conocida="<<get(reply,Tag::EffectiveKnown)<<" error="<<get(reply,Tag::ErrorCode)<<"\n";
            return get(reply,Tag::ErrorCode)==0?0:4;
        }
        std::cout<<"Backend no conectado. Preparacion administrativa no inicia el servicio ni acredita cobertura completa.\n";
        std::cout<<"Consulta: --status. Control elevado: --control status|allow|block|revoke.\n";
        return argc==1?0:2;
    }catch(...){std::cerr<<"Operacion rechazada\n";return 2;}
}
