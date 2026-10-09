#include "pipe_transport.h"
#include "wfp_backend.h"
#include <sddl.h>
#include <thread>
#include <vector>
#include <algorithm>

namespace gb {
namespace {
struct Local {HLOCAL p=nullptr;~Local(){if(p)LocalFree(p);}};
struct Handle {HANDLE h=nullptr;~Handle(){if(h&&h!=INVALID_HANDLE_VALUE)CloseHandle(h);}};
Bytes tokenInfo(HANDLE token,TOKEN_INFORMATION_CLASS cls){DWORD n=0;GetTokenInformation(token,cls,nullptr,0,&n);Bytes b(n);if(!n||!GetTokenInformation(token,cls,b.data(),n,&n))return{};return b;}
bool io(HANDLE pipe,Bytes& data,bool write,HANDLE stop,DWORD timeout=5000){
    OVERLAPPED operation{};Handle event;event.h=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!event.h)return false;operation.hEvent=event.h;DWORD bytes=0;
    BOOL immediate=write?WriteFile(pipe,data.data(),static_cast<DWORD>(data.size()),&bytes,&operation):ReadFile(pipe,data.data(),static_cast<DWORD>(data.size()),&bytes,&operation);
    if(!immediate&&GetLastError()!=ERROR_IO_PENDING)return false;
    if(!immediate){HANDLE events[]={event.h,stop};auto count=stop?2ul:1ul;auto state=WaitForMultipleObjects(count,events,FALSE,timeout);
        if(state!=WAIT_OBJECT_0){CancelIoEx(pipe,&operation);if(WaitForSingleObject(event.h,1000)!=WAIT_OBJECT_0){TerminateProcess(GetCurrentProcess(),ERROR_TIMEOUT);}return false;}
        if(!GetOverlappedResult(pipe,&operation,&bytes,FALSE))return false;
    }
    if(write)return bytes==data.size();data.resize(bytes);return bytes>0;
}
bool send(HANDLE pipe,const Frame& f,HANDLE stop){Bytes b;return encode(f,b)==Error::Ok&&io(pipe,b,true,stop);}
bool receive(HANDLE pipe,Frame& f,HANDLE stop,Error& error){
    Decoder decoder;std::vector<Frame> frames;Bytes prefix;std::size_t remaining=HeaderBytes;auto start=GetTickCount64();
    do{auto elapsed=GetTickCount64()-start;if(elapsed>=5000){error=Error::Timeout;return false;}Bytes chunk(std::min<std::size_t>(64,remaining));if(!io(pipe,chunk,false,stop,static_cast<DWORD>(5000-elapsed))){error=Error::Timeout;return false;}
        if(prefix.size()<HeaderBytes)prefix.insert(prefix.end(),chunk.begin(),chunk.end());remaining-=chunk.size();
        error=decoder.feed(chunk.data(),chunk.size(),frames);if(error!=Error::Ok){if(error==Error::Unsupported&&!frames.empty()){f=frames.back();return true;}return false;}
        if(prefix.size()==HeaderBytes&&remaining==0&&frames.empty()){remaining=0;for(unsigned i=0;i<4;++i)remaining|=std::size_t(prefix[12+i])<<(8*i);prefix.push_back(0);}
    }while(frames.empty()&&remaining);
    // Cada ReadFile se limita al resto del frame; una escritura concatenada queda en el pipe.
    if(frames.size()!=1||decoder.incomplete())return false;f=frames.front();return true;
}
Frame response(const Frame& request,Type type,std::uint64_t sequence){Frame f;f.type=type;f.connection=request.connection;f.correlation=request.correlation;f.sequence=sequence;return f;}
void statusFields(Frame& f,const Status& status,const Id& epoch,const Id& boot){
    f.fields={value(Tag::ServiceEpoch,epoch),value(Tag::BootId,boot),value(Tag::Capabilities,status.capabilities),value(Tag::DesiredRev,status.desired),value(Tag::EffectiveRev,status.effective),value(Tag::EffectiveKnown,status.effectiveKnown?1:0,1),value(Tag::EngineState,static_cast<unsigned>(status.state),1),value(Tag::BackendMode,static_cast<unsigned>(status.mode),1)};
    if(f.type==Type::Status)f.fields.push_back(value(Tag::GapCount,0));
}
bool verifyServer(HANDLE pipe){
    ULONG pid=0;if(!GetNamedPipeServerProcessId(pipe,&pid)||!pid)return false;
    SC_HANDLE manager=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);if(!manager)return false;SC_HANDLE service=OpenServiceW(manager,ServiceName,SERVICE_QUERY_STATUS);SERVICE_STATUS_PROCESS status{};DWORD bytes=0;bool ok=service&&QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&status),sizeof(status),&bytes)&&status.dwCurrentState==SERVICE_RUNNING&&status.dwServiceType==SERVICE_WIN32_OWN_PROCESS&&status.dwProcessId==pid;if(service)CloseServiceHandle(service);CloseServiceHandle(manager);if(!ok)return false;
    Handle process;process.h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);if(!process.h)return false;FILETIME created{},exited{},kernel{},user{};if(!GetProcessTimes(process.h,&created,&exited,&kernel,&user))return false;
    Handle token;if(!OpenProcessToken(process.h,TOKEN_QUERY,&token.h)||!serviceTokenIdentity(token.h))return false;
    ULONG again=0;DWORD exit=0;FILETIME stable{},unused1{},unused2{},unused3{};
    return GetNamedPipeServerProcessId(pipe,&again)&&again==pid&&GetExitCodeProcess(process.h,&exit)&&exit==STILL_ACTIVE&&GetProcessTimes(process.h,&stable,&unused1,&unused2,&unused3)&&CompareFileTime(&stable,&created)==0;
}
}
bool serviceTokenIdentity(HANDLE token){
    auto user=tokenInfo(token,TokenUser),groups=tokenInfo(token,TokenGroups);if(user.empty()||groups.empty())return false;
    BYTE system[SECURITY_MAX_SID_SIZE]{};DWORD n=sizeof(system);if(!CreateWellKnownSid(WinLocalSystemSid,nullptr,system,&n)||!EqualSid(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid,system))return false;
    BYTE service[SECURITY_MAX_SID_SIZE]{};wchar_t domain[256]{};DWORD sidBytes=sizeof(service),domainChars=256;SID_NAME_USE use{};
    // Cuenta virtual de servicio resuelta en la maquina local exclusivamente.
    std::wstring name=L"NT SERVICE\\";name+=ServiceName;
    if(!LookupAccountNameW(L".",name.c_str(),service,&sidBytes,domain,&domainChars,&use))return false;
    auto list=reinterpret_cast<TOKEN_GROUPS*>(groups.data());for(DWORD i=0;i<list->GroupCount;++i)if(EqualSid(service,list->Groups[i].Sid)&&(list->Groups[i].Attributes&SE_GROUP_ENABLED)&&!(list->Groups[i].Attributes&SE_GROUP_USE_FOR_DENY_ONLY))return true;
    return false;
}
bool elevatedAdministrator(HANDLE token){
    auto elevation=tokenInfo(token,TokenElevation);auto integrity=tokenInfo(token,TokenIntegrityLevel);auto groups=tokenInfo(token,TokenGroups);if(elevation.empty()||integrity.empty()||groups.empty())return false;
    auto il=reinterpret_cast<TOKEN_MANDATORY_LABEL*>(integrity.data())->Label.Sid;auto count=*GetSidSubAuthorityCount(il);if(!count||*GetSidSubAuthority(il,count-1)<SECURITY_MANDATORY_HIGH_RID||!reinterpret_cast<TOKEN_ELEVATION*>(elevation.data())->TokenIsElevated)return false;
    BYTE admin[SECURITY_MAX_SID_SIZE]{};DWORD n=sizeof(admin);if(!CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,admin,&n))return false;auto g=reinterpret_cast<TOKEN_GROUPS*>(groups.data());for(DWORD i=0;i<g->GroupCount;++i)if(EqualSid(admin,g->Groups[i].Sid)&&(g->Groups[i].Attributes&SE_GROUP_ENABLED)&&!(g->Groups[i].Attributes&SE_GROUP_USE_FOR_DENY_ONLY))return true;return false;
}
PipeServer::PipeServer(Coordinator& c,Id epoch,Id boot,std::wstring sid,DWORD session):coordinator_(c),epoch_(epoch),boot_(boot),viewSid_(std::move(sid)),viewSession_(session){}
bool PipeServer::authority(HANDLE pipe,bool control){
    ULONG client=0,pipeSession=0;DWORD processSession=0;FILETIME created{},exited{},kernel{},userTime{};Handle process;
    if(!GetNamedPipeClientProcessId(pipe,&client)||!client||!GetNamedPipeClientSessionId(pipe,&pipeSession)||!ProcessIdToSessionId(client,&processSession)||pipeSession!=processSession)return false;
    process.h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,client);if(!process.h||!GetProcessTimes(process.h,&created,&exited,&kernel,&userTime))return false;
    if(!ImpersonateNamedPipeClient(pipe))return false;Handle token;bool ok=OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&token.h)!=FALSE;
    if(ok&&control)ok=elevatedAdministrator(token.h);
    if(ok&&!control){auto user=tokenInfo(token.h,TokenUser);auto session=tokenInfo(token.h,TokenSessionId);Local sid;ok=ConvertStringSidToSidW(viewSid_.c_str(),reinterpret_cast<PSID*>(&sid.p))&& !user.empty()&&!session.empty()&&EqualSid(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid,sid.p)&&*reinterpret_cast<DWORD*>(session.data())==viewSession_;}
    if(!RevertToSelf()){TerminateProcess(GetCurrentProcess(),ERROR_CANNOT_IMPERSONATE);}
    ULONG again=0;DWORD exit=0;FILETIME stable{},a{},b{},c{};
    return ok&&GetNamedPipeClientProcessId(pipe,&again)&&again==client&&GetExitCodeProcess(process.h,&exit)&&exit==STILL_ACTIVE&&GetProcessTimes(process.h,&stable,&a,&b,&c)&&CompareFileTime(&stable,&created)==0;
}
void PipeServer::run(HANDLE stop){std::thread view([&]{channel(false,stop);});std::thread control([&]{channel(true,stop);});view.join();control.join();}
void PipeServer::channel(bool control,HANDLE stop){
    Local descriptor;std::wstring acl=L"D:P(D;;GA;;;NU)(A;;GA;;;SY)";
    // Derechos individuales de datos/atributos; no conceden autoridad de Control.
    acl+=L"(A;;"+std::wstring(PipeClientRightsSddl)+L";;;"+(control?std::wstring(L"BA"):viewSid_)+L")";
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(),SDDL_REVISION_1,reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.p),nullptr)){SetEvent(stop);return;}
    SECURITY_ATTRIBUTES sa{sizeof(sa),descriptor.p,FALSE};Handle pipe;pipe.h=CreateNamedPipeW(control?ControlPipe:ViewPipe,PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,4096,4096,5000,&sa);if(pipe.h==INVALID_HANDLE_VALUE){SetEvent(stop);return;}
    while(WaitForSingleObject(stop,0)!=WAIT_OBJECT_0){Handle connected;connected.h=CreateEventW(nullptr,TRUE,FALSE,nullptr);OVERLAPPED operation{};operation.hEvent=connected.h;bool ready=ConnectNamedPipe(pipe.h,&operation)!=FALSE;auto error=ready?ERROR_SUCCESS:GetLastError();if(error==ERROR_PIPE_CONNECTED)ready=true;
        if(!ready&&error==ERROR_IO_PENDING){HANDLE events[]={connected.h,stop};auto state=WaitForMultipleObjects(2,events,FALSE,INFINITE);DWORD count=0;if(state==WAIT_OBJECT_0)ready=GetOverlappedResult(pipe.h,&operation,&count,FALSE)!=FALSE;else{CancelIoEx(pipe.h,&operation);if(WaitForSingleObject(connected.h,1000)!=WAIT_OBJECT_0)TerminateProcess(GetCurrentProcess(),ERROR_TIMEOUT);}}
        if(!ready){DisconnectNamedPipe(pipe.h);continue;}
        Frame request;Error parse=Error::Ok;std::uint64_t expected=1,outgoing=1;Id connection{};bool hello=false;
        while(WaitForSingleObject(stop,0)!=WAIT_OBJECT_0&&receive(pipe.h,request,stop,parse)){
            if(!authority(pipe.h,control))break;
            if(request.sequence!=expected||expected==UINT64_MAX)break;
            if(!hello){if(parse!=Error::Ok||request.type!=Type::Hello||get(request,Tag::ClientRole)!=(control?2u:1u))break;connection=randomId();Frame ack=response(request,Type::HelloAck,outgoing++);ack.connection=connection;statusFields(ack,coordinator_.status(),epoch_,boot_);if(!send(pipe.h,ack,stop))break;hello=true;++expected;continue;}
            if(request.connection!=connection||request.type==Type::Hello)break;++expected;
            Frame reply=response(request,Type::ProtocolError,outgoing++);
            if(parse==Error::Unsupported){reply.fields={value(Tag::ErrorCode,static_cast<unsigned>(Error::Unsupported),2)};}
            else if(request.type==Type::GetStatus){reply.type=Type::Status;statusFields(reply,coordinator_.status(),epoch_,boot_);}
            else if(request.type==Type::CreateRule||request.type==Type::RevokeRule){auto result=coordinator_.mutate(request,control);reply.type=Type::MutationAck;reply.fields={value(Tag::DesiredRev,result.status.desired),value(Tag::EffectiveRev,result.status.effective),value(Tag::EffectiveKnown,result.status.effectiveKnown?1:0,1),value(Tag::CommandState,static_cast<unsigned>(result.state),1),value(Tag::ErrorCode,static_cast<unsigned>(result.error),2)};}
            else reply.fields={value(Tag::ErrorCode,static_cast<unsigned>(Error::Unsupported),2)};
            if(!send(pipe.h,reply,stop)||outgoing==UINT64_MAX)break;
        }
        DisconnectNamedPipe(pipe.h);
    }
}
PipeClient::~PipeClient(){if(pipe_!=INVALID_HANDLE_VALUE)CloseHandle(pipe_);}
bool PipeClient::open(bool control){
    if(pipe_!=INVALID_HANDLE_VALUE)return false;
    pipe_=CreateFileW(control?ControlPipe:ViewPipe,PipeClientRights,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
    if(pipe_==INVALID_HANDLE_VALUE||!verifyServer(pipe_))return false;
    Frame hello;hello.type=Type::Hello;hello.correlation=randomId();hello.fields={value(Tag::ClientRole,control?2:1,1)};Frame ack;Error error;
    if(!send(pipe_,hello,nullptr)||!receive(pipe_,ack,nullptr,error)||error!=Error::Ok||ack.type!=Type::HelloAck||ack.correlation!=hello.correlation||ack.sequence!=1||zero(ack.connection))return false;connection_=ack.connection;send_=receive_=2;return true;
}
bool PipeClient::transact(Frame request,Frame& reply){
    if(pipe_==INVALID_HANDLE_VALUE||zero(connection_)||send_==UINT64_MAX||receive_==UINT64_MAX)return false;
    request.connection=connection_;request.sequence=send_++;if(zero(request.correlation))request.correlation=randomId();Error error;
    if(!send(pipe_,request,nullptr)||!receive(pipe_,reply,nullptr,error)||error!=Error::Ok||reply.connection!=connection_||reply.sequence!=receive_++||reply.correlation!=request.correlation)return false;return true;
}
}
