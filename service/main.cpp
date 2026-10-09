#include "pipe_transport.h"
#include "wfp_backend.h"
#include <iostream>
#include <memory>
#include <string>
#include <sddl.h>

namespace {
using namespace gb;
SERVICE_STATUS_HANDLE statusHandle=nullptr;
HANDLE stopEvent=nullptr;
void report(DWORD state,DWORD error=NO_ERROR){SERVICE_STATUS status{};status.dwServiceType=SERVICE_WIN32_OWN_PROCESS;status.dwCurrentState=state;status.dwControlsAccepted=state==SERVICE_RUNNING?SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN:0;status.dwWin32ExitCode=error;if(state==SERVICE_START_PENDING||state==SERVICE_STOP_PENDING){status.dwCheckPoint=1;status.dwWaitHint=10000;}if(statusHandle)SetServiceStatus(statusHandle,&status);}
DWORD WINAPI handler(DWORD control,DWORD,void*,void*){if((control==SERVICE_CONTROL_STOP||control==SERVICE_CONTROL_SHUTDOWN)&&stopEvent){report(SERVICE_STOP_PENDING);SetEvent(stopEvent);}return NO_ERROR;}
bool deploymentReady(){
    HANDLE token=nullptr;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return false;auto identity=serviceTokenIdentity(token);CloseHandle(token);if(!identity)return false;
    SC_HANDLE manager=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);if(!manager)return false;
    SC_HANDLE service=OpenServiceW(manager,ServiceName,SERVICE_QUERY_CONFIG);DWORD bytes=0;bool ok=false;
    if(service){QueryServiceConfigW(service,nullptr,0,&bytes);Bytes buffer(bytes);if(bytes&&QueryServiceConfigW(service,reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data()),bytes,&bytes)){auto c=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());ok=c->dwServiceType==SERVICE_WIN32_OWN_PROCESS&&c->dwStartType==SERVICE_AUTO_START;}CloseServiceHandle(service);}
    CloseServiceHandle(manager);return ok;
}
Id bootIdentity(){
    // La subclave volatil desaparece al reiniciar Windows y persiste al caer el servicio.
    PSECURITY_DESCRIPTOR descriptor=nullptr;if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;KA;;;SY)(A;;KA;;;BA)",SDDL_REVISION_1,&descriptor,nullptr))throw std::runtime_error("ACL de arranque invalida");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),descriptor,FALSE};HKEY key=nullptr;DWORD disposition=0;
    auto error=RegCreateKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\LGA\\GateBouncerLab\\BootSession",0,nullptr,REG_OPTION_VOLATILE,KEY_QUERY_VALUE|KEY_SET_VALUE,&attributes,&key,&disposition);LocalFree(descriptor);if(error!=ERROR_SUCCESS)throw std::runtime_error("Identidad de arranque no disponible");
    Id id{};DWORD type=0,bytes=16;error=RegQueryValueExW(key,L"Id",nullptr,&type,id.data(),&bytes);
    if(error==ERROR_FILE_NOT_FOUND&&disposition==REG_CREATED_NEW_KEY){id=randomId();error=RegSetValueExW(key,L"Id",0,REG_BINARY,id.data(),16);type=REG_BINARY;bytes=16;}
    RegCloseKey(key);if(error!=ERROR_SUCCESS||type!=REG_BINARY||bytes!=16||zero(id))throw std::runtime_error("Identidad de arranque invalida");return id;
}
void WINAPI serviceMain(DWORD,wchar_t**){
    statusHandle=RegisterServiceCtrlHandlerExW(ServiceName,handler,nullptr);if(!statusHandle)return;report(SERVICE_START_PENDING);
    stopEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!stopEvent){report(SERVICE_STOPPED,GetLastError());return;}
    try{
        if(!guestActivationAuthorized()||!deploymentReady()){report(SERVICE_STOPPED,ERROR_ACCESS_DENIED);CloseHandle(stopEvent);stopEvent=nullptr;return;}
        wchar_t programData[32768]{},viewSid[256]{};DWORD bytes=sizeof(viewSid),session=0,sessionBytes=sizeof(session);
        auto n=GetEnvironmentVariableW(L"ProgramData",programData,32768);
        if(n<3||n>=32768||programData[1]!=L':'||GetDriveTypeW(std::wstring(programData,programData+3).c_str())!=DRIVE_FIXED||
            RegGetValueW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\LGA\\GateBouncerLab",L"ViewSid",RRF_RT_REG_SZ,nullptr,viewSid,&bytes)!=ERROR_SUCCESS||
            RegGetValueW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\LGA\\GateBouncerLab",L"ViewSessionId",RRF_RT_REG_DWORD,nullptr,&session,&sessionBytes)!=ERROR_SUCCESS)throw std::runtime_error("Configuracion de invitado incompleta");
        PSID sid=nullptr;if(!ConvertStringSidToSidW(viewSid,&sid))throw std::runtime_error("SID de lectura invalido");LocalFree(sid);auto boot=bootIdentity();
        SelectorRegistry registry;WfpBackend backend(registry);if(!backend.connectGuest())throw std::runtime_error("Backend no conectado");
        PolicyStore store(std::filesystem::path(programData)/L"LGAGateBouncerLab");Coordinator coordinator(store,backend,registry);coordinator.initialize();
        // Este corte no publica un perfil validado ni inventa eventos de trafico.
        PipeServer server(coordinator,randomId(),boot,viewSid,session);report(SERVICE_RUNNING);server.run(stopEvent);report(SERVICE_STOPPED);
    }catch(...){report(SERVICE_STOPPED,ERROR_SERVICE_SPECIFIC_ERROR);}
    CloseHandle(stopEvent);stopEvent=nullptr;
}
bool ownAdmin(){HANDLE token=nullptr;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return false;bool ok=elevatedAdministrator(token);CloseHandle(token);return ok;}
std::string narrow(const wchar_t* s){std::string out;for(;*s;++s){if(*s>127)throw std::runtime_error("Argumento invalido");out+=static_cast<char>(*s);}return out;}
}
int wmain(int argc,wchar_t** argv){
    try{
        if(argc==3&&std::wstring(argv[1])==L"--service"&&std::wstring(argv[2])==L"--guest-wfp"){
            if(!guestActivationAuthorized()){std::cerr<<"Activacion invitada no autorizada\n";return 2;}
            SERVICE_TABLE_ENTRYW table[]={{const_cast<wchar_t*>(ServiceName),serviceMain},{nullptr,nullptr}};
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
        std::cout<<"Backend no conectado. Servicio de laboratorio sin activacion automatica.\n";
        std::cout<<"Consulta: --status. Control elevado: --control status|allow|block|revoke.\n";
        return argc==1?0:2;
    }catch(...){std::cerr<<"Operacion rechazada\n";return 2;}
}
