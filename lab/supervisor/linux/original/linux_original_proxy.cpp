#include "OriginalHostResources.hpp"
#include <shellapi.h>
namespace {
using namespace gb::original;
int RunProxy(int argc,wchar_t**argv) {
    if(argc!=3||std::wstring(argv[1])!=L"--own-stdio"||std::wstring(argv[2]).rfind(L"//./pipe/GateBouncerOriginalProxy-",0)!=0)return 4;
    const HANDLE input=GetStdHandle(STD_INPUT_HANDLE),output=GetStdHandle(STD_OUTPUT_HANDLE);
    if(GetFileType(input)!=FILE_TYPE_PIPE||GetFileType(output)!=FILE_TYPE_PIPE)return 4;
    Handle self(OpenProcess(PROCESS_QUERY_INFORMATION|SYNCHRONIZE,FALSE,GetCurrentProcessId()));
    const DWORD sshPid=ParentPid(self.h);Handle ssh(OpenProcess(PROCESS_QUERY_INFORMATION|SYNCHRONIZE,FALSE,sshPid));const auto sshCreated=Created(ssh.h);
    const DWORD hostPid=ParentPid(ssh.h);Handle host(OpenProcess(PROCESS_QUERY_INFORMATION|SYNCHRONIZE,FALSE,hostPid));const auto hostCreated=Created(host.h);
    const auto selfCreated=Created(self.h);const auto hostImage=Image(host.h);gb::native::TokenEvidence token,sshToken,hostToken;
    File sshFile,hostFile;
    if(!selfCreated||!sshCreated||!hostCreated||hostCreated>sshCreated||sshCreated>selfCreated||!Token(self.h,token)||!Token(ssh.h,sshToken)||!Token(host.h,hostToken)||!EqualToken(token,sshToken)||!EqualToken(token,hostToken)||
       Image(ssh.h)!=L"C:\\Windows\\System32\\OpenSSH\\ssh.exe"||std::filesystem::path(hostImage).filename()!=L"gatebouncer-linux-original-host.exe"||
       std::filesystem::path(Image(self.h)).parent_path()!=std::filesystem::path(hostImage).parent_path()||!sshFile.Open(Image(ssh.h))||!hostFile.Open(hostImage))return 3;
    const ULONGLONG end=GetTickCount64()+300000;
    auto current=[&] {
        gb::native::TokenEvidence a,b,c;
        return GetTickCount64()<end&&Created(self.h)==selfCreated&&Created(ssh.h)==sshCreated&&Created(host.h)==hostCreated&&
            WaitForSingleObject(ssh.h,0)==WAIT_TIMEOUT&&WaitForSingleObject(host.h,0)==WAIT_TIMEOUT&&ParentPid(self.h)==sshPid&&ParentPid(ssh.h)==hostPid&&
            Image(ssh.h)==sshFile.Path()&&Image(host.h)==hostFile.Path()&&Token(self.h,a)&&Token(ssh.h,b)&&Token(host.h,c)&&EqualToken(token,a)&&EqualToken(token,b)&&EqualToken(token,c)&&
            InOriginalBase(self.h,GetCurrentProcessId())&&InOriginalBase(ssh.h,sshPid)&&InOriginalBase(host.h,hostPid)&&sshFile.Current()&&hostFile.Current();
    };
    if(!current()||!sshFile.Hash(BCRYPT_SHA256_ALGORITHM,"786ff14be7cd652b2b9770a57e9b1aa5e03a052ce3a3d641fb4760c0ff3fde05",current))return 3;
    std::wstring pipeName=argv[2];std::replace(pipeName.begin(),pipeName.end(),L'/',L'\\');
    Handle pipe(CreateFileW(pipeName.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr));ULONG server=0;
    if(!pipe.h||!GetNamedPipeServerProcessId(pipe.h,&server)||server!=hostPid||!current())return 3;
    struct Transfer {Handle event;OVERLAPPED io{};std::array<BYTE,MaximumChunk>b{};DWORD size=0;bool pending=false;};
    auto read=std::make_unique<Transfer>(),write=std::make_unique<Transfer>();read->event=Handle(CreateEventW(nullptr,TRUE,FALSE,nullptr));write->event=Handle(CreateEventW(nullptr,TRUE,FALSE,nullptr));if(!read->event.h||!write->event.h)return 3;
    bool complete=false;while(current()) {
        if(write->pending){DWORD n=0;if(GetOverlappedResult(pipe.h,&write->io,&n,FALSE)){write->pending=false;if(n!=write->size||!current())break;}else if(GetLastError()!=ERROR_IO_INCOMPLETE)break;}
        if(read->pending){DWORD n=0;if(GetOverlappedResult(pipe.h,&read->io,&n,FALSE)){read->pending=false;if(!n){complete=true;break;}if(!current())break;
                std::size_t at=0;while(at<n){DWORD done=0;if(!current()||!WriteFile(output,read->b.data()+at,n-static_cast<DWORD>(at),&done,nullptr)||!done||!current())return 3;at+=done;}}
            else if(GetLastError()==ERROR_BROKEN_PIPE){read->pending=false;complete=true;break;}else if(GetLastError()!=ERROR_IO_INCOMPLETE)break;}
        if(!write->pending){DWORD available=0;if(!PeekNamedPipe(input,nullptr,0,nullptr,&available,nullptr)){if(GetLastError()!=ERROR_BROKEN_PIPE)break;}
            if(available){DWORD n=0;if(!ReadFile(input,write->b.data(),static_cast<DWORD>(std::min<std::size_t>(available,write->b.size())),&n,nullptr)||!n||!current())break;write->size=n;ResetEvent(write->event.h);write->io={};write->io.hEvent=write->event.h;write->pending=true;
                if(!WriteFile(pipe.h,write->b.data(),n,nullptr,&write->io)&&GetLastError()!=ERROR_IO_PENDING){write->pending=false;break;}}}
        if(!read->pending){ResetEvent(read->event.h);read->io={};read->io.hEvent=read->event.h;read->pending=true;
            if(!ReadFile(pipe.h,read->b.data(),static_cast<DWORD>(read->b.size()),nullptr,&read->io)&&GetLastError()!=ERROR_IO_PENDING){read->pending=false;if(GetLastError()==ERROR_BROKEN_PIPE)complete=true;break;}}
        Sleep(2);
    }
    bool drained=true;for(auto*t:{read.get(),write.get()})if(t->pending){CancelIoEx(pipe.h,&t->io);DWORD n=0;if(GetOverlappedResult(pipe.h,&t->io,&n,FALSE))t->pending=false;else if(GetLastError()==ERROR_OPERATION_ABORTED||GetLastError()==ERROR_BROKEN_PIPE)t->pending=false;else drained=false;}
    if(!drained){static std::vector<std::unique_ptr<Transfer>>retained;retained.push_back(std::move(read));retained.push_back(std::move(write));static std::vector<Handle>keepers;keepers.push_back(std::move(pipe));return 3;}
    return complete&&current()?0:3;
}
}
// Subsistema GUI: OpenSSH crea este proceso sin ventana ni consola propia.
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int) {
    int argc=0;wchar_t**argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(!argv)return 4;
    int result=5;try{result=RunProxy(argc,argv);}catch(...){}LocalFree(argv);return result;
}
