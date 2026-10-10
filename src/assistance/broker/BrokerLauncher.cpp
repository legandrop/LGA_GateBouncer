#include "BrokerLauncher.h"
#include "AssistantBrokerRuntime.h"
#include "../grounded_bridge/GroundedBrokerRuntime.h"
#include "GeneralBrokerHost.h"
#include "../../../controller/deployment_win.h"
#include <QCoreApplication>
#include <QDir>
#include <cstring>

namespace Gate::Assistance::Broker {
static constexpr size_t BootstrapLimit=512;
std::optional<BrokerEnvironment> BrokerEnvironment::fromTrustedPaths(QString deployment,QString windows,QString system){
    auto valid=[](const QString &path){
        if(path.isEmpty()||path.size()>512)return false;
        const auto parts=QDir::fromNativeSeparators(path).split('/');
        if(parts.size()<2||parts[0].size()!=2||parts[0][1]!=':')return false;
        const auto drive=parts[0][0].toUpper();if(drive<'A'||drive>'Z')return false;
        for(const auto c:path)if(c.isNull()||c.category()==QChar::Other_Control||c=='"'||c==';'||c=='%')return false;
        for(int i=1;i<parts.size();++i)if(parts[i].isEmpty()||parts[i]=="."||parts[i]==".."||parts[i].contains(':')||parts[i].endsWith('.')||parts[i].endsWith(' '))return false;
        return true;
    };
    if(!valid(deployment)||!valid(windows)||!valid(system))return {};
    deployment=QDir::toNativeSeparators(deployment);windows=QDir::toNativeSeparators(windows);system=QDir::toNativeSeparators(system);
    if(system.compare(windows+"\\System32",Qt::CaseInsensitive))return {};
    BrokerEnvironment environment;environment.directory_=deployment.toStdWString();
    // Orden fijo de keys; los values vienen de APIs/rutas verificadas, nunca getenv.
    for(const auto &entry:{L"PATH="+environment.directory_+L";"+system.toStdWString(),L"SystemRoot="+windows.toStdWString()}){
        environment.block_.insert(environment.block_.end(),entry.begin(),entry.end());environment.block_.push_back(0);
    }
    environment.block_.push_back(0);if(environment.block_.size()>2048)return {};return environment;
}
std::optional<BrokerEnvironment> BrokerEnvironment::forSibling(){
    std::array<wchar_t,MAX_PATH+1> windows{},system{};
    const UINT wn=GetSystemWindowsDirectoryW(windows.data(),UINT(windows.size())),sn=GetSystemDirectoryW(system.data(),UINT(system.size()));
    if(!wn||wn>=windows.size()||!sn||sn>=system.size())return {};
    const auto deployment=QCoreApplication::applicationDirPath();
    const auto root=QString::fromWCharArray(windows.data(),int(wn)),sys=QString::fromWCharArray(system.data(),int(sn));
    for(const auto &path:{deployment,root,sys})if(GetDriveTypeW((QDir::fromNativeSeparators(path).left(2)+"/").toStdWString().c_str())!=DRIVE_FIXED)return {};
    return fromTrustedPaths(deployment,root,sys);
}
static bool ordinarySelf(TokenIdentity &id){return tokenIdentity(GetCurrentProcess(),id)&&id.ordinary;}
static QString pipeName(const Id &id){return "\\\\.\\pipe\\LGA.GateBouncer.Assistance."+QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(id.data()),16).toHex());}
static bool lockFixedImage(const QString &path,std::vector<Handle> &handles){
    const auto parts=QDir::fromNativeSeparators(path).split('/');
    if(parts.size()<2||parts[0].size()!=2||parts[0][1]!=':'||parts.contains(".")||parts.contains("..")||parts.contains(""))return false;
    if(GetDriveTypeW((parts[0]+"/").toStdWString().c_str())!=DRIVE_FIXED)return false;
    QString current=parts[0]+"/";
    for(int i=0;i<parts.size();++i){
        if(i)current+=(i==1?"":"/")+parts[i];
        const bool directory=i+1<parts.size();
        Handle h(CreateFileW(QDir::toNativeSeparators(current).toStdWString().c_str(),directory?FILE_READ_ATTRIBUTES:GENERIC_READ,
            directory?FILE_SHARE_READ|FILE_SHARE_WRITE:FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|(directory?FILE_FLAG_BACKUP_SEMANTICS:0),nullptr));
        BY_HANDLE_FILE_INFORMATION info{};
        if(!h||!GetFileInformationByHandle(h.value,&info)||(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)||bool(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=directory||(!directory&&info.nNumberOfLinks!=1))return false;
        handles.push_back(std::move(h));
    }
    return true;
}
std::unique_ptr<PipeSession> launchSiblingBroker(){return launchSiblingBroker(WireVersion::Legacy1);}
gatebouncer::websearch::ProviderConfig generalSearchConfiguration(){
    gatebouncer::websearch::ProviderConfig config;config.revision="GB_GENERAL_SEARCH_1";return config;
}
std::unique_ptr<PipeSession> launchSiblingBroker(WireVersion version) {
    if(version!=WireVersion::Legacy1&&version!=WireVersion::Grounded2&&version!=WireVersion::General3)return {};
    TokenIdentity identity;if(!ordinarySelf(identity))return {};
    const QString exe=QDir::toNativeSeparators(QCoreApplication::applicationDirPath()+"/GateBouncerAssistant.exe");
    const QString expectedUi=QDir::toNativeSeparators(QCoreApplication::applicationDirPath()+"/GateBouncer.exe");
    if(imagePath(GetCurrentProcess()).compare(expectedUi,Qt::CaseInsensitive))return {};
    std::unique_ptr<gb::controller::Deployment> deployment;
    if(version==WireVersion::General3){
        const auto image=std::filesystem::path(imagePath(GetCurrentProcess()).toStdWString());
        deployment=std::make_unique<gb::controller::Deployment>(image.parent_path());
        if(!deployment->verify(image,gb::controller::DeploymentRole::OrdinaryGui)||!deployment->current())return {};
    }
    std::vector<Handle> pathGuards;if(!lockFixedImage(exe,pathGuards)||!lockFixedImage(expectedUi,pathGuards))return {};
    auto environment=BrokerEnvironment::forSibling();if(!environment)return {};
    // Runtime de despliegue junto al broker; no resolver Qt/MinGW desde PATH ajeno.
    for(const char *dll:{"Qt6Core.dll","libgcc_s_seh-1.dll","libstdc++-6.dll","libwinpthread-1.dll"})
        if(!lockFixedImage(QString::fromStdWString(environment->directory_)+"/"+dll,pathGuards))return {};
    Id connection{};if(!randomId(connection))return {};const auto name=pipeName(connection).toLatin1();
    SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};HANDLE r=nullptr,w=nullptr;
    if(!CreatePipe(&r,&w,&sa,DWORD(BootstrapLimit)))return {};
    Handle read(r),write(w);
    if(!SetHandleInformation(write.value,HANDLE_FLAG_INHERIT,0))return {};
    Handle parent(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,TRUE,GetCurrentProcessId()));quint64 created=0;
    if(!parent||!processCreated(parent.value,created))return {};
    SIZE_T bytes=0;InitializeProcThreadAttributeList(nullptr,1,0,&bytes);std::vector<unsigned char> attributes(bytes);
    auto *list=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());if(!InitializeProcThreadAttributeList(list,1,0,&bytes))return {};
    HANDLE inherited[]{read.value,parent.value};
    if(!UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),nullptr,nullptr)){DeleteProcThreadAttributeList(list);return {};}
    STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.StartupInfo.dwFlags=STARTF_USESHOWWINDOW;startup.StartupInfo.wShowWindow=SW_HIDE;startup.lpAttributeList=list;
    std::wstring command=L"\""+exe.toStdWString()+L"\" --bootstrap-handle "+std::to_wstring(reinterpret_cast<quintptr>(read.value));PROCESS_INFORMATION info{};
    if(deployment&&!deployment->current()){DeleteProcThreadAttributeList(list);return {};}
    const BOOL launched=CreateProcessW(exe.toStdWString().c_str(),command.data(),nullptr,nullptr,TRUE,EXTENDED_STARTUPINFO_PRESENT|CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT,environment->block_.data(),environment->directory_.c_str(),&startup.StartupInfo,&info);
    DeleteProcThreadAttributeList(list);if(!launched)return {};Handle process(info.hProcess),thread(info.hThread);read.reset();
    SensitiveBytes bootstrap(52+size_t(name.size()));auto *d=bootstrap.data();std::memcpy(d,"GBAB",4);d[4]=quint8(version);d[5]=version==WireVersion::Grounded2?2:version==WireVersion::General3?3:0;
    auto put=[&](size_t at,quint64 n,size_t len){for(size_t i=0;i<len;++i)d[at+i]=static_cast<unsigned char>(n>>(8*i));};
    put(6,quint64(name.size()),2);std::memcpy(d+16,connection.data(),16);put(32,reinterpret_cast<quintptr>(parent.value),8);put(40,created,8);put(48,GetCurrentProcessId(),4);std::memcpy(d+52,name.data(),size_t(name.size()));
    DWORD count=0;if(!WriteFile(write.value,d,DWORD(bootstrap.size()),&count,nullptr)||count!=bootstrap.size())return {};write.reset();
    Peer peer;peer.pid=info.dwProcessId;peer.process=std::move(process);peer.image=exe;peer.identity=identity;
    if(!processCreated(peer.process.value,peer.creation))return {};
    const ULONGLONG until=GetTickCount64()+5000;Handle pipe;
    while(GetTickCount64()<until) {
        pipe.reset(CreateFileW(QString::fromLatin1(name).toStdWString().c_str(),ClientPipeAccess,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr));
        if(pipe)break;
        if(WaitForSingleObject(peer.process.value,0)!=WAIT_TIMEOUT)return {};
        Sleep(10);
    }
    if(!pipe||(deployment&&!deployment->current()))return {};
    return std::make_unique<PipeSession>(std::move(pipe),std::move(peer),connection,false,nullptr,version);
}
int runBrokerFromBootstrap(quintptr inheritedHandle) {
    TokenIdentity self;if(!ordinarySelf(self))return 3;
    Handle bootstrap(reinterpret_cast<HANDLE>(inheritedHandle));if(!bootstrap)return 4;
    std::array<unsigned char,BootstrapLimit> bytes{};DWORD available=0;ULONGLONG until=GetTickCount64()+5000;
    while(GetTickCount64()<until){if(!PeekNamedPipe(bootstrap.value,nullptr,0,nullptr,&available,nullptr))return 4;if(available>=52)break;Sleep(10);}
    if(available<52||available>BootstrapLimit)return 4;
    DWORD count=0;
    if(!ReadFile(bootstrap.value,bytes.data(),available,&count,nullptr)||count!=available||std::memcmp(bytes.data(),"GBAB",4)||(bytes[4]!=1&&bytes[4]!=2&&bytes[4]!=3))return 4;
    const auto version=WireVersion(bytes[4]);
    auto num=[&](size_t at,size_t len){quint64 n=0;for(size_t i=0;i<len;++i)n|=quint64(bytes[at+i])<<(8*i);return n;};
    const auto nameLength=num(6,2);if(nameLength>160||52+nameLength!=available||bytes[5]!=(version==WireVersion::Grounded2?2:version==WireVersion::General3?3:0)||num(8,8))return 4;
    Id connection{};std::memcpy(connection.data(),bytes.data()+16,16);if(!nonzero(connection))return 4;
    const QString name=QString::fromLatin1(reinterpret_cast<const char *>(bytes.data()+52),int(nameLength));if(name!=pipeName(connection))return 4;
    Peer peer;peer.process.reset(reinterpret_cast<HANDLE>(quintptr(num(32,8))));peer.creation=num(40,8);peer.pid=DWORD(num(48,4));peer.image=imagePath(peer.process.value);
    const QString expectedUi=QDir::toNativeSeparators(QCoreApplication::applicationDirPath()+"/GateBouncer.exe");
    std::vector<Handle> pathGuards;if(peer.image.compare(expectedUi,Qt::CaseInsensitive)||!lockFixedImage(expectedUi,pathGuards))return 4;
    quint64 actual=0;if(!peer.process||GetProcessId(peer.process.value)!=peer.pid||!processCreated(peer.process.value,actual)||actual!=peer.creation||peer.image.isEmpty()||!tokenIdentity(peer.process.value,peer.identity)||!sameIdentity(self,peer.identity))return 4;
    bootstrap.reset();SecureZeroMemory(bytes.data(),bytes.size());auto pipe=PipeSession::createServer(name,self);if(!pipe)return 5;
    auto session=std::make_unique<PipeSession>(std::move(pipe),std::move(peer),connection,true,nullptr,version);
    if(version==WireVersion::General3){auto host=General::GeneralBrokerHost::forCurrentUser(std::move(session),generalSearchConfiguration());if(!host)return 6;return QCoreApplication::exec();}
    if(version==WireVersion::Grounded2){auto runtime=GroundedBridge::GroundedBrokerRuntime::forCurrentUser(std::move(session));if(!runtime)return 6;runtime->start();return QCoreApplication::exec();}
    AssistantBrokerRuntime runtime(std::move(session));runtime.start();return QCoreApplication::exec();
}
}
