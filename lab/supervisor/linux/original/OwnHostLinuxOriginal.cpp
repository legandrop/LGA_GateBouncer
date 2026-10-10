#include "OwnHostLinuxOriginal.hpp"
#include "OriginalHostResources.hpp"
#include "OwnCloudSeed.hpp"
#include "../OwnMemorySshCredential.hpp"
#include "OriginalGuestPins.hpp"
#include "../../../../common/pipe_ii_win.h"
#include <sddl.h>
#include <tlhelp32.h>
#include <wintrust.h>
#include <softpub.h>
#include <deque>
#include <fstream>
#include <set>
#include <sstream>
namespace gb {
namespace {
using namespace original;
constexpr char CloudHash[]="6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2";
constexpr char QemuHash[]="5bcf9eed634e8575a37b74f445af41a2fe4106da512d0c30c368301d4c105037fdfab40a5287367a28a957624cddebbc8c07e16c88ab6634f554cdf3d16bf543";
constexpr char UbuntuSigner[]="D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81";
bool MicrosoftImage(const File&file) {
    WINTRUST_FILE_INFO info{};info.cbStruct=sizeof(info);info.pcwszFilePath=file.Path().c_str();info.hFile=file.Raw();
    WINTRUST_DATA data{};data.cbStruct=sizeof(data);data.dwUIChoice=WTD_UI_NONE;data.fdwRevocationChecks=WTD_REVOKE_NONE;data.dwUnionChoice=WTD_CHOICE_FILE;data.pFile=&info;
    data.dwStateAction=WTD_STATEACTION_VERIFY;data.dwProvFlags=WTD_CACHE_ONLY_URL_RETRIEVAL;GUID policy=WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG result=WinVerifyTrust(nullptr,&policy,&data);bool microsoft=false;
    if(result==ERROR_SUCCESS){auto*provider=WTHelperProvDataFromStateData(data.hWVTStateData);auto*signer=provider?WTHelperGetProvSignerFromChain(provider,0,FALSE,0):nullptr;
        if(signer&&signer->csCertChain&&signer->pasCertChain[0].pCert){std::array<wchar_t,1024>name{};CertGetNameStringW(signer->pasCertChain[0].pCert,CERT_NAME_ATTR_TYPE,0,const_cast<char*>(szOID_ORGANIZATION_NAME),name.data(),static_cast<DWORD>(name.size()));microsoft=std::wstring(name.data())==L"Microsoft Corporation";}}
    data.dwStateAction=WTD_STATEACTION_CLOSE;WinVerifyTrust(nullptr,&policy,&data);return microsoft&&file.Current();
}
bool Random(Bytes& b,std::size_t n) {b.resize(n);return BCryptGenRandom(nullptr,b.data(),static_cast<ULONG>(n),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0;}
std::string Hex(const Bytes& b) {constexpr char h[]="0123456789abcdef";std::string s;for(auto v:b){s+=h[v>>4];s+=h[v&15];}return s;}
std::wstring Wide(const std::string&s) {return std::wstring(s.begin(),s.end());}
Bytes Text(const std::string&s){return Bytes(s.begin(),s.end());}
std::string Unix(const std::wstring&s) {std::string out;for(wchar_t c:s){if(c>127||c<32||c=='"'||c=='\''||c=='\n'||c=='\r')throw std::runtime_error("OriginalPathEncoding");out+=c==L'\\'?'/':static_cast<char>(c);}return out;}
bool PipePair(Handle& reader,Handle& writer) {SECURITY_ATTRIBUTES a{sizeof(a),nullptr,TRUE};HANDLE r=nullptr,w=nullptr;if(!CreatePipe(&r,&w,&a,65536))return false;reader=Handle(r);writer=Handle(w);return true;}
bool NoInherit(HANDLE h) {return SetHandleInformation(h,HANDLE_FLAG_INHERIT,0)!=FALSE;}
bool WriteAll(HANDLE h,const Bytes&b,const std::function<bool()>&fresh) {
    std::size_t at=0;while(at<b.size()){DWORD n=0;if(!fresh()||!WriteFile(h,b.data()+at,static_cast<DWORD>(std::min<std::size_t>(65536,b.size()-at)),&n,nullptr)||!n||!fresh())return false;at+=n;}return fresh();
}
bool ReadAvailable(HANDLE pipe,Bytes&out,std::size_t cap,bool& eof) {
    DWORD available=0;if(!PeekNamedPipe(pipe,nullptr,0,nullptr,&available,nullptr)){eof=GetLastError()==ERROR_BROKEN_PIPE;return eof;}
    if(available>cap-out.size())return false;std::array<BYTE,65536>b{};
    while(available){DWORD n=0;if(!ReadFile(pipe,b.data(),static_cast<DWORD>(std::min<std::size_t>(b.size(),available)),&n,nullptr)||!n)return false;out.insert(out.end(),b.begin(),b.begin()+n);available-=n;}return true;
}
// Importes de cada imagen PE observados desde el reader original; no ejecuta otra herramienta.
bool Imports(const File&file,std::vector<std::string>&names) {
    Bytes b;if(!file.Read(b,64*1024*1024)||b.size()<512||b[0]!='M'||b[1]!='Z')return false;
    auto u16=[&](std::size_t p){return p+2<=b.size()?static_cast<unsigned>(b[p]|b[p+1]<<8):0u;};
    auto u32=[&](std::size_t p){return p+4<=b.size()?static_cast<std::uint32_t>(b[p])|(static_cast<std::uint32_t>(b[p+1])<<8)|(static_cast<std::uint32_t>(b[p+2])<<16)|(static_cast<std::uint32_t>(b[p+3])<<24):0u;};
    const auto pe=u32(60);if(pe+24>b.size()||u32(pe)!=0x4550||u16(pe+4)!=0x8664)return false;
    const auto optional=pe+24,sections=u16(pe+6),optionalSize=u16(pe+20);if(u16(optional)!=0x20b||sections>96||optionalSize<240)return false;
    const std::size_t table=optional+optionalSize;if(table+sections*40>b.size())return false;
    auto offset=[&](std::uint32_t rva)->std::size_t {
        for(unsigned i=0;i<sections;++i){const auto p=table+i*40;const auto start=u32(p+12),size=std::max(u32(p+8),u32(p+16));if(rva>=start&&rva-start<size){const auto at=static_cast<std::uint64_t>(u32(p+20))+rva-start;return at<b.size()?static_cast<std::size_t>(at):b.size();}}
        return b.size();
    };
    auto name=[&](std::uint32_t rva)->bool {
        const auto at=offset(rva);if(at>=b.size())return false;std::string s;
        for(std::size_t p=at;p<b.size()&&s.size()<256;++p){if(!b[p]){if(s.empty()||s.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")!=std::string::npos)return false;for(auto&c:s)if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');names.push_back(s);return true;}s+=static_cast<char>(b[p]);}return false;
    };
    const auto directory=offset(u32(optional+120));if(directory<b.size()) {
        bool terminal=false;for(unsigned i=0;i<4096;++i){const auto p=directory+i*20;if(p+20>b.size())return false;if(!u32(p)&&!u32(p+12)&&!u32(p+16)){terminal=true;break;}if(!name(u32(p+12)))return false;}if(!terminal)return false;
    }
    const auto delayRva=u32(optional+112+13*8);
    if(delayRva){const auto delay=offset(delayRva);bool terminal=false;for(unsigned i=0;i<4096;++i){const auto p=delay+i*32;if(p+32>b.size())return false;
            if(!u32(p)&&!u32(p+4)){terminal=true;break;}if(u32(p)!=1||!name(u32(p+4)))return false;}if(!terminal)return false;}
    return true;
}
bool LoadedOwn(const Child&child,const std::vector<std::unique_ptr<File>>&pins,const File&exe) {
    if(!child.Current())return false;Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,child.pid));if(!snapshot.h)return false;
    MODULEENTRY32W module{};module.dwSize=sizeof(module);if(!Module32FirstW(snapshot.h,&module))return false;unsigned count=0;
    do {
        if(++count>4096||!child.Current())return false;File current;if(!current.Open(module.szExePath))return false;
        bool known=exe.Same(current.Raw());for(const auto&pin:pins)if(pin->Same(current.Raw())){known=true;break;}
        if(!known){const auto path=current.Path();const std::wstring system=L"C:\\Windows\\System32\\";
            if(path.size()<=system.size()||CompareStringOrdinal(path.c_str(),static_cast<int>(system.size()),system.c_str(),static_cast<int>(system.size()),TRUE)!=CSTR_EQUAL||!MicrosoftImage(current))return false;}
        if(!current.Current())return false;
    }while(Module32NextW(snapshot.h,&module));
    return GetLastError()==ERROR_NO_MORE_FILES&&child.Current();
}
struct ToolPin {const wchar_t*name;const char*sha;};
constexpr ToolPin GpgPins[]{
    {L"gpg.exe","b0c30e3a5b14fa8463b67b58c81121c4005e565c4935e1cefdcff4e4e01246de"},
    {L"msys-2.0.dll","70323b309e05cf98c7fbf629730f9fbd86ff63b48e334e9ee9a7cdfef03c6a09"},
    {L"msys-gcrypt-20.dll","e9d08b8cbcd701e2394d76a077b74e39e8da41f0ee010b0c3e05659d89f47d0d"},
    {L"msys-gpg-error-0.dll","54ad15c31793dd82376e80612e848b8873a90b0f06e453b56cc2bd9fbe7af3de"},
    {L"msys-assuan-0.dll","90446ee55e396d4d1efffbba8a8176091e55775a2d868c5075d1aa7e0a1abac9"},
    {L"msys-intl-8.dll","23d30f4bcbc0a258cf5ecfe29e707f9b05d51c32d5b16a910f1012b889136c12"},
    {L"msys-iconv-2.dll","9cbf5613b946be7bad403ac0d7277efbd514a35faa644c6a0d6e7f6cc0b40780"}};
}
struct OwnHostLinuxOriginal::Impl {
    State state=State::Reserved;DWORD thread=GetCurrentThreadId(),pid=GetCurrentProcessId();Handle self;std::uint64_t created=0;native::TokenEvidence token;std::wstring image,desktop,media,work,agentName,proxyName,uuid,mac;
    ULONGLONG acquisitionEnd=GetTickCount64()+180000,bootEnd=0;bool bootSubmitted=false,authenticated=false,linuxReady=false,modulesConfirmed=false,closing=false,sshCredit=true,guestEof=false;
    std::uint64_t request=0,generation=0,sendSequence=1,receiveSequence=1;std::string hostLine,clientLine,bootId;std::uint64_t guestStart=0,uid=0,gid=0;
    File selfFile,outputParent,root,source,archive,sums,signature,keyring,guest,capture,sshImage,proxyImage;
    std::vector<std::unique_ptr<File>>pins;std::map<std::string,File*>bundle;File*disk=nullptr,*seed=nullptr,*config=nullptr,*knownHosts=nullptr;
    Child qemu,ssh;std::vector<std::unique_ptr<Child>>tools;Handle qemuInput,qemuOutput,qemuError,sshInput,sshOutput,sshError,proxyPipe,proxyProcess,stop;
    std::uint64_t proxyCreated=0;DWORD proxyPid=0;OVERLAPPED proxyConnect{};Handle proxyEvent;bool connectPending=false;
    PipeTransfer proxyRead,proxyWrite;mutable ULONGLONG diskChecked=0;
    bool DiskCurrent()const {
        const ULONGLONG now=GetTickCount64();
        if(!disk||(diskChecked&&now-diskChecked>1000)||!disk->QcowWithinCap())return false;
        diskChecked=GetTickCount64();return true;
    }
    std::shared_ptr<OwnMemorySshCredential> credential;Bytes pendingQemu,sshCapture,sshDiagnostics;std::deque<Bytes>toProxy;std::string line;std::vector<Handle>consumed;
};
OwnHostLinuxOriginal::OwnHostLinuxOriginal():own_(new Impl){}
OwnHostLinuxOriginal::~OwnHostLinuxOriginal()noexcept=default;
bool OwnHostLinuxOriginal::OriginalCurrentOwn()const {
    const auto&o=*own_;native::TokenEvidence token;
    if(cancelled_.load()||GetCurrentThreadId()!=o.thread||!o.self.h||Created(o.self.h)!=o.created||GetProcessId(o.self.h)!=o.pid||Image(o.self.h)!=o.image||
       !Token(o.self.h,token)||!EqualToken(o.token,token)||!InOriginalBase(o.self.h,o.pid)||Desktop(o.thread)!=o.desktop||!o.selfFile.Current())return false;
    if(GetTickCount64()>=(o.bootSubmitted?o.bootEnd:o.acquisitionEnd))return false;
    for(const auto*f:{&o.outputParent,&o.root,&o.source,&o.archive,&o.sums,&o.signature,&o.keyring,&o.guest,&o.capture,&o.sshImage,&o.proxyImage})if(f->Raw()&&!f->Current())return false;
    for(const auto&p:o.pins)if(!p->Current())return false;
    if(!o.bootSubmitted)return true;
    if(!o.DiskCurrent())return false;
    const auto qemu=o.bundle.find("qemu-system-x86_64.exe");
    if(qemu==o.bundle.end()||!o.qemu.Current()||(o.modulesConfirmed&&!LoadedOwn(o.qemu,o.pins,*qemu->second)))return false;
    if(o.ssh.process.h){DWORD terminal=0;if(!o.ssh.Current()&&!o.ssh.Terminal(terminal))return false;if(o.ssh.Current()&&o.proxyProcess.h&&!LoadedOwn(o.ssh,o.pins,o.sshImage))return false;}
    return o.DiskCurrent();
}
std::wstring OwnHostLinuxOriginal::AgentNameOwn()const{return own_->agentName;}
bool OwnHostLinuxOriginal::AgentPeerOwn(HANDLE process,DWORD pid,std::uint64_t created)const {
    const auto&o=*own_;native::TokenEvidence token;
    return o.linuxReady&&o.ssh.Current()&&pid==o.ssh.pid&&created==o.ssh.created&&Created(process)==created&&GetProcessId(process)==pid&&Image(process)==o.ssh.image&&
        Token(process,token)&&EqualToken(o.token,token)&&ParentPid(process)==o.pid&&InOriginalBase(process,pid)&&LoadedOwn(o.ssh,o.pins,o.sshImage)&&OriginalCurrentOwn();
}
bool OwnHostLinuxOriginal::SignDataOwn(const std::vector<BYTE>&data)const {
    if(!OriginalCurrentOwn()||!own_->linuxReady||!own_->ssh.Current())return false;
    std::size_t p=0;std::uint64_t size=0;if(!Get(data,p,size,4)||!size||size>64||size>data.size()-p)return false;p+=static_cast<std::size_t>(size);
    if(p>=data.size()||data[p++]!=50)return false;
    std::string user,service,method,algorithm;
    if(!GetText(data,p,user,64)||user!="gatebouncerlab"||!GetText(data,p,service,64)||service!="ssh-connection"||!GetText(data,p,method,64)||method!="publickey"||p>=data.size()||data[p++]!=1||!GetText(data,p,algorithm,64)||algorithm!="ecdsa-sha2-nistp256"||!Get(data,p,size,4)||size>data.size()-p)return false;
    Bytes blob;if(!PublicLine(own_->clientLine,"ecdsa-sha2-nistp256",blob))return false;
    return size==blob.size()&&size==data.size()-p&&std::equal(blob.begin(),blob.end(),data.begin()+static_cast<std::ptrdiff_t>(p))&&OriginalCurrentOwn();
}
bool OwnHostLinuxOriginal::PrepareOwn(int argc,wchar_t**argv) {
    auto&o=*own_;if(argc!=3||o.self.h)return false;
    HANDLE self=nullptr;if(!DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(),GetCurrentProcess(),&self,PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|SYNCHRONIZE,FALSE,0))return false;
    o.self=Handle(self);o.created=Created(self);o.image=Image(self);o.desktop=Desktop(o.thread);
    if(!o.created||o.desktop.empty()||o.desktop==L"Default"||!Token(self,o.token)||o.token.uiAccess||!o.selfFile.Open(o.image)||!OriginalCurrentOwn())return false;
    o.media=argv[1];o.work=argv[2];
    if(!ClosedAbsolutePath(o.media)||!ClosedAbsolutePath(o.work)||o.work.compare(0,3,L"T:\\"))return false;
    const auto output=std::filesystem::path(o.work);File media;
    if(!media.Open(o.media,true)||!o.outputParent.Open(output.parent_path().wstring(),true)||!OriginalCurrentOwn()||
       !o.root.CreateDirectoryChild(o.outputParent,output.filename().wstring())||!OriginalCurrentOwn())return false;
    auto fresh=[this]{return OriginalCurrentOwn();};
    auto input=[&](File&f,const wchar_t*name,const char*pin,const wchar_t*alg=BCRYPT_SHA256_ALGORITHM) {
        return f.Open((std::filesystem::path(o.media)/name).wstring())&&f.Hash(alg,pin,fresh);
    };
    if(!input(o.source,L"ubuntu-24.04-server-cloudimg-amd64.img",CloudHash)||o.source.Size()>1024ull*1024*1024||!input(o.archive,L"qemu-w64-setup-20260811.exe",QemuHash,BCRYPT_SHA512_ALGORITHM)||o.archive.Size()>512ull*1024*1024||
       !input(o.guest,L"gatebouncer-linux-original",GB_ORIGINAL_GUEST_SHA256)||!input(o.capture,L"gatebouncer-capture",GB_ORIGINAL_CAPTURE_SHA256)||!o.sums.Open((std::filesystem::path(o.media)/L"SHA256SUMS").wstring())||!o.signature.Open((std::filesystem::path(o.media)/L"SHA256SUMS.gpg").wstring())||!o.keyring.Open((std::filesystem::path(o.media)/L"ubuntu-cloudimage-keyring.gpg").wstring()))return false;
    Bytes guest,capture,sums;if(!o.guest.Read(guest,4*1024*1024)||!o.capture.Read(capture,4*1024*1024)||!o.sums.Read(sums,1024*1024)||guest.size()<64||capture.size()<64)return false;
    for(const auto*b:{&guest,&capture})if((*b)[0]!=0x7f||(*b)[1]!='E'||(*b)[2]!='L'||(*b)[3]!='F'||(*b)[4]!=2||(*b)[5]!=1||(*b)[18]!=62||(*b)[19]!=0)return false;
    const std::string sumsText(sums.begin(),sums.end());const std::string expected=std::string(CloudHash)+" *ubuntu-24.04-server-cloudimg-amd64.img";
    if(sumsText.find(expected+"\n")==std::string::npos&&sumsText.find(std::string(CloudHash)+"  ubuntu-24.04-server-cloudimg-amd64.img\n")==std::string::npos)return false;
    auto retain=[&](const std::wstring&path,const char*sha)->File* {auto f=std::make_unique<File>();if(!f->Open(path)||!f->Hash(BCRYPT_SHA256_ALGORITHM,sha,fresh))return nullptr;auto*p=f.get();o.pins.push_back(std::move(f));return p;};
    std::map<std::string,File*>gpgFiles;
    for(const auto&pin:GpgPins){auto*f=retain((std::filesystem::path(L"C:/Program Files/Git/usr/bin")/pin.name).wstring(),pin.sha);if(!f)return false;gpgFiles.emplace(Unix(pin.name),f);}
    // Todo import local debe pertenecer al conjunto fijado; System32 se retiene por imagen original.
    auto closure=[&](const std::map<std::string,File*>&images)->bool {
        std::set<std::string>done;std::deque<File*>queue;for(const auto&p:images)queue.push_back(p.second);
        while(!queue.empty()){File*f=queue.front();queue.pop_front();if(!done.insert(Unix(f->Path())).second)continue;
            const auto extension=std::filesystem::path(f->Path()).extension().wstring();if(extension!=L".exe"&&extension!=L".dll")continue;
            std::vector<std::string>imports;if(!Imports(*f,imports))return false;
            for(const auto&name:imports){if(name.rfind("api-ms-",0)==0||name.rfind("ext-ms-",0)==0)continue;if(images.count(name))continue;
                auto dep=std::make_unique<File>();if(!dep->Open((std::filesystem::path(L"C:/Windows/System32")/Wide(name)).wstring())||!MicrosoftImage(*dep))return false;
                queue.push_back(dep.get());o.pins.push_back(std::move(dep));
            }}return fresh();
    };
    if(!closure(gpgFiles))return false;
    auto tool=[&](File&exe,const std::vector<std::wstring>&args,Bytes&out,std::size_t cap)->bool {
        auto child=std::make_unique<Child>();auto*original=child.get();o.tools.push_back(std::move(child));Handle inR,inW,outR,outW,errR,errW;
        if(!PipePair(inR,inW)||!PipePair(outR,outW)||!PipePair(errR,errW)||!NoInherit(inW.h)||!NoInherit(outR.h)||!NoInherit(errR.h))return false;
        if(!original->Start(exe,args,o.work,{inR.h,outW.h,errW.h},fresh))return false;
        inR.Close();outW.Close();errW.Close();inW.Close();const ULONGLONG end=std::min(o.acquisitionEnd,GetTickCount64()+30000);Bytes errors;bool outEof=false,errEof=false;DWORD code=0;
        while(GetTickCount64()<end&&fresh()) {
            if(!ReadAvailable(outR.h,out,cap,outEof)||!ReadAvailable(errR.h,errors,65536,errEof))return false;
            if(original->Terminal(code)){if(code)return false;if(outEof&&errEof)return fresh();}Sleep(5);
        }return false;
    };
    if(!CreateDirectoryW((std::filesystem::path(o.work)/L"gpg-home").c_str(),nullptr))return false;
    Bytes status;
    if(!tool(*gpgFiles.at("gpg.exe"),{L"--no-options",L"--batch",L"--no-auto-key-retrieve",L"--no-auto-check-trustdb",L"--lock-never",L"--no-default-keyring",L"--homedir",(std::filesystem::path(o.work)/L"gpg-home").wstring(),L"--keyring",o.keyring.Path(),L"--status-fd",L"1",L"--verify",o.signature.Path(),o.sums.Path()},status,65536))return false;
    const std::string verification(status.begin(),status.end());unsigned valid=0;std::istringstream lines(verification);std::string line;
    while(std::getline(lines,line)){if(line.find("[GNUPG:] VALIDSIG ")==0){std::istringstream fields(line.substr(18));std::string fingerprint;if(!(fields>>fingerprint)||fingerprint!=UbuntuSigner)return false;++valid;}if(line.find("BADSIG")!=std::string::npos||line.find("ERRSIG")!=std::string::npos||line.find("REVKEYSIG")!=std::string::npos||line.find("EXPKEYSIG")!=std::string::npos)return false;}
    if(valid!=1||!o.signature.Current()||!o.sums.Current()||!o.keyring.Current())return false;
    auto* seven=retain(L"C:/Program Files/7-Zip/7z.exe","fcdf41ab5a749e82575d36365bf11e8ce9b52d05c9058cd3589c8c2c8c4f59f5");
    auto* sevenDll=retain(L"C:/Program Files/7-Zip/7z.dll","5529fdc4e6385ad95106a4e6da1d2792046a71c9d7452ee6cbc8012b4eb8f3f4");
    if(!seven||!sevenDll||!closure({{"7z.exe",seven},{"7z.dll",sevenDll}}))return false;
    Bytes listing;if(!tool(*seven,{L"l",L"-slt",L"-ba",L"--",o.archive.Path()},listing,4*1024*1024))return false;
    std::istringstream archiveRows(std::string(listing.begin(),listing.end()));std::string row,path;std::uint64_t declared=0;bool folder=false;std::vector<std::pair<std::string,std::uint64_t>>entries;std::uint64_t total=0;
    auto addEntry=[&]()->bool {if(path.empty())return true;if(folder){path.clear();return true;}std::replace(path.begin(),path.end(),'\\','/');
        const auto name=std::filesystem::path(path).filename().string();const bool selected=(path.find('/')==std::string::npos&&(name=="qemu-system-x86_64.exe"||(name.size()>4&&name.substr(name.size()-4)==".dll")))||(path.rfind("share/",0)==0&&name=="bios-256k.bin");
        if(selected){if(path.front()=='/'||path.find(':')!=std::string::npos||path.find("..")!=std::string::npos||path.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-/+")!=std::string::npos||!declared||declared>128*1024*1024||entries.size()>=2048||total+declared>512ull*1024*1024)return false;entries.push_back({path,declared});total+=declared;}path.clear();return true;};
    while(std::getline(archiveRows,row)){if(!row.empty()&&row.back()=='\r')row.pop_back();if(row.empty()){if(!addEntry())return false;folder=false;declared=0;}else if(row.rfind("Path = ",0)==0)path=row.substr(7);else if(row.rfind("Size = ",0)==0){std::istringstream value(row.substr(7));if(!(value>>declared))return false;}else if(row.rfind("Folder = ",0)==0)folder=row.substr(9)=="+";else if(row.rfind("Attributes = ",0)==0&&row.substr(13).find('D')!=std::string::npos)folder=true;}if(!addEntry()||entries.empty())return false;
    auto ownWrite=[&](const std::wstring&name,const Bytes&bytes,bool mutableLeaf=false)->File* {
        const auto path=(std::filesystem::path(o.work)/name).wstring();Handle writer(CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|(mutableLeaf?FILE_SHARE_WRITE:0),nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        if(!writer.h||!WriteAll(writer.h,bytes,fresh)||!FlushFileBuffers(writer.h))return nullptr;
        auto reader=std::make_unique<File>();if(!reader->Open(path,false,mutableLeaf,true)||!reader->RetainWriter(writer.h)||!reader->Current())return nullptr;
        auto*p=reader.get();o.pins.push_back(std::move(reader));return p;
    };
    std::set<std::string>names;
    for(const auto&e:entries) {
        if(!names.insert(e.first).second)return false;const auto relative=std::filesystem::path(Wide(e.first));auto part=std::filesystem::path(o.work);
        for(const auto&component:relative.parent_path()){part/=component;if(GetFileAttributesW(part.c_str())==INVALID_FILE_ATTRIBUTES&&!CreateDirectoryW(part.c_str(),nullptr))return false;File retained;if(!retained.Open(part.wstring(),true))return false;}
        Bytes output;if(!tool(*seven,{L"x",L"-so",L"-bd",L"-y",L"--",o.archive.Path(),Wide(e.first)},output,static_cast<std::size_t>(e.second))||output.size()!=e.second)return false;
        auto*reader=ownWrite(Wide(e.first),output);if(!reader)return false;
        std::string fileName=relative.filename().string();for(auto&c:fileName)if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');
        const std::string index=e.first.find('/')==std::string::npos?fileName:e.first;
        if(o.bundle.count(index))return false;o.bundle.emplace(index,reader);
        if(fileName=="bios-256k.bin"){if(o.bundle.count(fileName))return false;o.bundle.emplace(fileName,reader);}
    }
    if(!o.bundle.count("qemu-system-x86_64.exe")||!o.bundle.count("bios-256k.bin")||!closure(o.bundle)||!o.archive.Hash(BCRYPT_SHA512_ALGORITHM,QemuHash,fresh))return false;
    // Copia original qcow2: CREATE_NEW, reader del mismo FileObject antes de cerrar writer.
    Bytes header;if(!o.source.Read(header,1024ull*1024*1024)||header.size()<104||header[0]!='Q'||header[1]!='F'||header[2]!='I'||header[3]!=0xfb)return false;
    auto be=[&](std::size_t p,unsigned n){std::uint64_t v=0;while(n--)v=(v<<8)|header[p++];return v;};
    if(be(4,4)!=3||be(8,8)||be(16,4)||be(24,8)>64ull*1024*1024*1024||!be(24,8)||be(32,4)||be(72,8))return false;
    o.disk=ownWrite(L"working.qcow2",header,true);if(!o.disk||!o.disk->Hash(BCRYPT_SHA256_ALGORITHM,CloudHash,fresh))return false;header.clear();header.shrink_to_fit();
    Bytes id;if(!Random(id,32))return false;std::size_t p=0;Get(id,p,o.request,8);Get(id,p,o.generation,8);if(!o.request||!o.generation)return false;
    Bytes uuid(id.begin()+16,id.end());uuid[6]=(uuid[6]&15)|0x40;uuid[8]=(uuid[8]&63)|0x80;auto hex=Hex(uuid);o.uuid=Wide(hex.substr(0,8)+"-"+hex.substr(8,4)+"-"+hex.substr(12,4)+"-"+hex.substr(16,4)+"-"+hex.substr(20));
    o.mac=L"52:54:"+Wide(hex.substr(0,2)+":"+hex.substr(2,2)+":"+hex.substr(4,2)+":"+hex.substr(6,2));o.agentName=L"\\\\.\\pipe\\GateBouncerOriginalAgent-"+Wide(hex);o.proxyName=L"\\\\.\\pipe\\GateBouncerOriginalProxy-"+Wide(hex);
    o.credential=OwnMemorySshCredential::CreateHostOwn(shared_from_this());Bytes publicKey;if(!o.credential||!o.credential->PublicBlobOwn(publicKey))return false;
    o.clientLine="ecdsa-sha2-nistp256 "+Base64(publicKey)+"\n";
    Frame control{Op::Hello,o.request,o.generation,0,{}};PutText(control.body,Unix(o.uuid));PutText(control.body,Unix(o.mac));PutText(control.body,o.clientLine);std::string encoded;if(!Encode(control,encoded))return false;
    auto writeFile=[&](const std::string&path,const std::string&mode,const Bytes&bytes) {return std::string("  - path: ")+path+"\n    owner: root:root\n    permissions: '"+mode+"'\n    encoding: b64\n    content: "+Base64(bytes)+"\n";};
    const std::string user="#cloud-config\nusers: []\ndisable_root: true\nssh_pwauth: false\nssh_deletekeys: true\nssh_genkeytypes: [ed25519]\npackage_update: false\npackage_upgrade: false\nwrite_files:\n"+
        writeFile("/usr/local/libexec/gatebouncer-linux-original","0755",guest)+writeFile("/usr/local/libexec/gatebouncer-capture","0755",capture)+writeFile("/var/lib/gatebouncer/owner-public","0600",Text(encoded))+
        "runcmd:\n  - [ /usr/local/libexec/gatebouncer-linux-original ]\n";
    const std::string metadata="instance-id: gatebouncer-"+hex+"\nlocal-hostname: gatebouncer\n";
    const std::string network="version: 2\nethernets:\n  gbeth0:\n    match:\n      macaddress: '"+Unix(o.mac)+"'\n    set-name: gbeth0\n    dhcp4: false\n    dhcp6: false\n    link-local: []\n    optional: true\n";
    const auto seedBytes=OwnCloudSeed::MakeOwn({{"user-data",Text(user)},{"meta-data",Text(metadata)},{"network-config",Text(network)}});o.seed=ownWrite(L"cidata.iso",seedBytes);if(!o.seed)return false;
    const auto binaryDirectory=std::filesystem::path(o.image).parent_path();
    if(!o.sshImage.Open(L"C:/Windows/System32/OpenSSH/ssh.exe")||!o.sshImage.Hash(BCRYPT_SHA256_ALGORITHM,"786ff14be7cd652b2b9770a57e9b1aa5e03a052ce3a3d641fb4760c0ff3fde05",fresh)||!MicrosoftImage(o.sshImage)||!o.proxyImage.Open((binaryDirectory/L"gatebouncer-linux-proxy.exe").wstring())||!o.proxyImage.Hash(BCRYPT_SHA256_ALGORITHM,GB_ORIGINAL_PROXY_SHA256,fresh)||!closure({{"ssh.exe",&o.sshImage},{"gatebouncer-linux-proxy.exe",&o.proxyImage}}))return false;
    o.state=State::MediaOwned;return fresh();
}
bool OwnHostLinuxOriginal::FreshLinuxOwn() {
    auto&o=*own_;if(!o.linuxReady||!OriginalCurrentOwn())return false;
    Bytes nonce;if(!Random(nonce,16))return false;std::string encoded;
    if(!Encode({Op::Check,o.request,o.generation,o.sendSequence++,nonce},encoded)||!WriteAll(o.qemuInput.h,Text(encoded),[this]{return OriginalCurrentOwn();}))return false;
    const auto end=std::min(o.bootEnd,GetTickCount64()+500);bool eof=false;
    while(GetTickCount64()<end&&OriginalCurrentOwn()) {
        if(!ReadAvailable(o.qemuOutput.h,o.pendingQemu,MaximumLine*4,eof)||eof)return false;
        auto newline=std::find(o.pendingQemu.begin(),o.pendingQemu.end(),'\n');
        if(newline==o.pendingQemu.end()){Sleep(1);continue;}
        std::string line(o.pendingQemu.begin(),newline+1);o.pendingQemu.erase(o.pendingQemu.begin(),newline+1);Frame frame;
        if(!Decode(line,frame)||frame.request!=o.request||frame.generation!=o.generation||frame.sequence!=o.receiveSequence++)return false;
        if(frame.op==Op::Current)return frame.body==nonce&&OriginalCurrentOwn()&&GetTickCount64()<end;
        if(frame.op==Op::Ssh){if(frame.body.empty()||frame.body.size()>MaximumChunk||o.toProxy.size()>16)return false;o.toProxy.push_back(std::move(frame.body));}
        else if(frame.op==Op::Credit){if(!frame.body.empty()||o.sshCredit)return false;o.sshCredit=true;}
        else if(frame.op==Op::Eof){if(!frame.body.empty()||o.guestEof)return false;o.guestEof=true;}
        else return false;
    }return false;
}
namespace {
bool ConsumedFiles(Child&child,const File&disk,const File&seed,std::vector<Handle>&retained) {
    struct Entry {HANDLE handle;ULONG_PTR handles,pointers;ULONG access,type,attributes,reserved;};
    struct Table {ULONG_PTR count,reserved;Entry first;};
    const auto query=reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationProcess"));
    if(!query||!child.Current())return false;std::vector<BYTE>storage(offsetof(Table,first)+4096*sizeof(Entry));ULONG returned=0;
    if(query(child.process.h,static_cast<PROCESSINFOCLASS>(51),storage.data(),static_cast<ULONG>(storage.size()),&returned)!=0||returned>storage.size()||returned<offsetof(Table,first))return false;
    const auto*table=reinterpret_cast<const Table*>(storage.data());if(table->count>4096||offsetof(Table,first)+table->count*sizeof(Entry)>returned)return false;
    bool a=false,b=false;const auto*entries=&table->first;
    for(ULONG_PTR i=0;i<table->count;++i) {
        if(!(entries[i].access&FILE_READ_DATA))continue;HANDLE raw=nullptr;
        if(!DuplicateHandle(child.process.h,entries[i].handle,GetCurrentProcess(),&raw,FILE_READ_ATTRIBUTES,FALSE,0))continue;Handle own(raw);
        if(GetFileType(raw)!=FILE_TYPE_DISK)continue;
        if(disk.Same(raw)){a=true;retained.push_back(std::move(own));}
        else if(seed.Same(raw)){b=true;retained.push_back(std::move(own));}
    }return a&&b&&child.Current()&&disk.Current()&&seed.Current();
}
}
bool OwnHostLinuxOriginal::RunOwn() {
    auto&o=*own_;if(o.state!=State::MediaOwned||!OriginalCurrentOwn())return false;
    auto fresh=[this]{return OriginalCurrentOwn();};
    Handle inR,inW,outR,outW,errR,errW;
    if(!PipePair(inR,inW)||!PipePair(outR,outW)||!PipePair(errR,errW)||!NoInherit(inW.h)||!NoInherit(outR.h)||!NoInherit(errR.h))return false;
    o.qemuInput=std::move(inW);o.qemuOutput=std::move(outR);o.qemuError=std::move(errR);
    const std::wstring disk=Wide(Unix(o.disk->Path())),seed=Wide(Unix(o.seed->Path()));
    if(disk.find(L',')!=std::wstring::npos||seed.find(L',')!=std::wstring::npos)return false;
    const std::vector<std::wstring>args{L"-machine",L"q35",L"-accel",L"tcg,thread=single",L"-cpu",L"qemu64",L"-smp",L"2",L"-m",L"2048",L"-uuid",o.uuid,
        L"-L",std::filesystem::path(o.bundle.at("bios-256k.bin")->Path()).parent_path().wstring(),L"-display",L"none",L"-monitor",L"none",L"-serial",L"none",L"-no-reboot",L"-nodefaults",
        L"-drive",L"file="+disk+L",if=virtio,format=qcow2,cache=none",L"-drive",L"file="+seed+L",if=ide,media=cdrom,format=raw,readonly=on",
        L"-netdev",L"user,id=gbnet,restrict=on",L"-device",L"virtio-net-pci,netdev=gbnet,romfile=,mac="+o.mac,
        L"-chardev",L"stdio,id=gbchannel,signal=off,mux=off",L"-device",L"virtio-serial-pci",L"-device",L"virtserialport,chardev=gbchannel,nr=1,name=gatebouncer.bootstrap"};
    // La llamada original cuenta el único intento antes del primer efecto CreateProcess/Resume.
    o.bootSubmitted=true;o.diskChecked=GetTickCount64();o.bootEnd=o.diskChecked+300000;o.state=State::BootSubmitted;
    auto before=[&]{const bool submitted=o.bootSubmitted;o.bootSubmitted=false;const bool current=OriginalCurrentOwn();o.bootSubmitted=submitted;return current&&o.DiskCurrent()&&GetTickCount64()<o.bootEnd;};
    if(!o.qemu.Start(*o.bundle.at("qemu-system-x86_64.exe"),args,o.work,{inR.h,outW.h,errW.h},before))return false;
    inR.Close();outW.Close();errW.Close();
    auto send=[&](Op op,const Bytes&body)->bool {std::string encoded;return Encode({op,o.request,o.generation,o.sendSequence++,body},encoded)&&WriteAll(o.qemuInput.h,Text(encoded),fresh);};
    auto receive=[&](Frame&frame,ULONGLONG end,bool initial=false)->bool {
        bool eof=false;while(GetTickCount64()<end&&fresh()) {
            Bytes diagnostics;if(!ReadAvailable(o.qemuError.h,diagnostics,65536,eof)||!diagnostics.empty()||eof)return false;
            if(!ReadAvailable(o.qemuOutput.h,o.pendingQemu,MaximumLine*4,eof)||eof)return false;
            const auto newline=std::find(o.pendingQemu.begin(),o.pendingQemu.end(),'\n');if(newline==o.pendingQemu.end()){if(o.pendingQemu.size()>MaximumLine)return false;Sleep(2);continue;}
            const std::string line(o.pendingQemu.begin(),newline+1);o.pendingQemu.erase(o.pendingQemu.begin(),newline+1);
            if(!Decode(line,frame)||GetTickCount64()>=end||!fresh())return false;
            if(initial)return frame.op==Op::Init&&!frame.request&&!frame.generation&&!frame.sequence&&frame.body.empty();
            return frame.request==o.request&&frame.generation==o.generation&&frame.sequence==o.receiveSequence++;
        }return false;
    };
    Frame frame;Bytes nonce;if(!receive(frame,o.bootEnd,true)||!LoadedOwn(o.qemu,o.pins,*o.bundle.at("qemu-system-x86_64.exe"))||!ConsumedFiles(o.qemu,*o.disk,*o.seed,o.consumed))return false;
    o.modulesConfirmed=true;
    if(!Random(nonce,16)||!send(Op::Hello,nonce)||!receive(frame,std::min(o.bootEnd,GetTickCount64()+500))||frame.op!=Op::Ready||frame.body.size()<16||!std::equal(nonce.begin(),nonce.end(),frame.body.begin()))return false;
    const Bytes ready=frame.body;std::size_t at=16;std::string uuid,mac,client;
    if(!GetText(ready,at,uuid,36)||uuid!=Unix(o.uuid)||!GetText(ready,at,mac,17)||mac!=Unix(o.mac)||!GetText(ready,at,o.bootId,36)||o.bootId.size()!=36||!Get(ready,at,o.guestStart,8)||!o.guestStart||
       !Get(ready,at,o.uid,4)||!o.uid||!Get(ready,at,o.gid,4)||!o.gid||!GetText(ready,at,o.hostLine,2048)||!GetText(ready,at,client,2048)||client!=o.clientLine||at!=ready.size())return false;
    Bytes hostKey;if(!PublicLine(o.hostLine,"ssh-ed25519",hostKey)||!send(Op::Ack,ready)||!receive(frame,std::min(o.bootEnd,GetTickCount64()+500))||frame.op!=Op::Acked||frame.body!=nonce||!fresh())return false;
    o.linuxReady=true;o.state=State::LinuxReady;if(!FreshLinuxOwn())return false;
    auto ownText=[&](const wchar_t*name,const std::string&text)->File* {
        const auto path=(std::filesystem::path(o.work)/name).wstring();Handle writer(CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        if(!writer.h||!WriteAll(writer.h,Text(text),fresh)||!FlushFileBuffers(writer.h))return nullptr;auto reader=std::make_unique<File>();
        if(!reader->Open(path,false,false,true)||!reader->RetainWriter(writer.h))return nullptr;Bytes observed;if(!reader->Read(observed,16384)||observed!=Text(text))return nullptr;
        auto*p=reader.get();o.pins.push_back(std::move(reader));return p;
    };
    const std::string alias="gatebouncer-"+Unix(o.uuid);
    o.knownHosts=ownText(L"known_hosts",alias+" "+o.hostLine);if(!o.knownHosts)return false;
    const std::string config="Host gatebouncer\n  HostName gatebouncer.invalid\n  User gatebouncerlab\n  Port 22\n  HostKeyAlias "+alias+"\n  UserKnownHostsFile \""+Unix(o.knownHosts->Path())+"\"\n  GlobalKnownHostsFile none\n  StrictHostKeyChecking yes\n  CheckHostIP no\n  VerifyHostKeyDNS no\n  UpdateHostKeys no\n  HostKeyAlgorithms ssh-ed25519\n  PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256\n  IdentityFile none\n  IdentityAgent "+Unix(o.agentName)+"\n  IdentitiesOnly no\n  PreferredAuthentications publickey\n  PasswordAuthentication no\n  KbdInteractiveAuthentication no\n  BatchMode yes\n  ConnectionAttempts 1\n  ConnectTimeout 10\n  RequestTTY no\n  EscapeChar none\n  ClearAllForwardings yes\n  ProxyCommand \""+Unix(o.proxyImage.Path())+"\" --own-stdio \""+Unix(o.proxyName)+"\"\n";
    o.config=ownText(L"ssh_config",config);if(!o.config)return false;
    const auto descriptor=PipeSecurity();PSECURITY_DESCRIPTOR security=nullptr;
    if(descriptor.empty()||!ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor.c_str(),SDDL_REVISION_1,&security,nullptr))return false;
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),security,FALSE};o.proxyPipe=Handle(CreateNamedPipeW(o.proxyName.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE|FILE_FLAG_OVERLAPPED,PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,65536,65536,500,&attributes));LocalFree(security);
    if(!o.proxyPipe.h||!ipc::ii::exactDescriptor(o.proxyPipe.h,descriptor))return false;
    o.proxyEvent=Handle(CreateEventW(nullptr,TRUE,FALSE,nullptr));if(!o.proxyEvent.h)return false;o.proxyConnect.hEvent=o.proxyEvent.h;
    if(!ConnectNamedPipe(o.proxyPipe.h,&o.proxyConnect)){const DWORD error=GetLastError();if(error!=ERROR_IO_PENDING&&error!=ERROR_PIPE_CONNECTED)return false;o.connectPending=error==ERROR_IO_PENDING;}
    Handle sshInR,sshInW,sshOutR,sshOutW,sshErrR,sshErrW;
    if(!PipePair(sshInR,sshInW)||!PipePair(sshOutR,sshOutW)||!PipePair(sshErrR,sshErrW)||!NoInherit(sshInW.h)||!NoInherit(sshOutR.h)||!NoInherit(sshErrR.h))return false;
    o.sshInput=std::move(sshInW);o.sshOutput=std::move(sshOutR);o.sshError=std::move(sshErrR);
    if(!FreshLinuxOwn()||!o.ssh.Start(o.sshImage,{L"-F",o.config->Path(),L"-T",L"gatebouncer"},o.work,{sshInR.h,sshOutW.h,sshErrW.h},fresh))return false;
    sshInR.Close();sshOutW.Close();sshErrW.Close();o.sshInput.Close();o.state=State::SshRunning;
    auto*read=&o.proxyRead;auto*write=&o.proxyWrite;read->event=Handle(CreateEventW(nullptr,TRUE,FALSE,nullptr));write->event=Handle(CreateEventW(nullptr,TRUE,FALSE,nullptr));
    if(!read->event.h||!write->event.h)return false;
    bool connected=false,acceptedProxy=false,bridgeClosed=false,proxyReadEof=false;ULONGLONG nextCheck=GetTickCount64();
    auto proxyCurrent=[&]()->bool {
        native::TokenEvidence token;return connected&&o.proxyProcess.h&&GetProcessId(o.proxyProcess.h)==o.proxyPid&&Created(o.proxyProcess.h)==o.proxyCreated&&WaitForSingleObject(o.proxyProcess.h,0)==WAIT_TIMEOUT&&ParentPid(o.proxyProcess.h)==o.ssh.pid&&o.proxyCreated>=o.ssh.created&&Image(o.proxyProcess.h)==o.proxyImage.Path()&&Token(o.proxyProcess.h,token)&&EqualToken(o.token,token)&&InOriginalBase(o.proxyProcess.h,o.proxyPid)&&o.ssh.Current()&&fresh();
    };
    auto cancelTransfers=[&]()->bool {
        const bool a=read->Drain(o.proxyPipe.h),b=write->Drain(o.proxyPipe.h);return a&&b;
    };
    bool okay=false;while(GetTickCount64()<o.bootEnd&&fresh()) {
        bool eof=false;if(!ReadAvailable(o.sshOutput.h,o.sshCapture,4096,eof)||!ReadAvailable(o.sshError.h,o.sshDiagnostics,65536,eof))break;
        DWORD code=0;if(o.ssh.Terminal(code)){okay=code==0&&o.sshCapture==Text("Guest capture: own session ready\n")&&acceptedProxy&&o.guestEof;break;}
        if(o.connectPending){DWORD done=0;if(GetOverlappedResult(o.proxyPipe.h,&o.proxyConnect,&done,FALSE))o.connectPending=false;else if(GetLastError()!=ERROR_IO_INCOMPLETE)break;}
        if(!o.connectPending&&!connected&&!bridgeClosed) {
            ULONG pid=0;if(!GetNamedPipeClientProcessId(o.proxyPipe.h,&pid)||!pid)break;
            o.proxyProcess=Handle(OpenProcess(PROCESS_QUERY_INFORMATION|SYNCHRONIZE,FALSE,pid));o.proxyPid=pid;o.proxyCreated=Created(o.proxyProcess.h);connected=true;if(!proxyCurrent())break;acceptedProxy=true;
        }
        if(GetTickCount64()>=nextCheck){if(!FreshLinuxOwn())break;nextCheck=GetTickCount64()+100;}
        const auto agentState=o.credential->InspectOwn().state;
        if(agentState!=OwnMemorySshCredential::State::MemoryOwned&&agentState!=OwnMemorySshCredential::State::SignatureSubmitted)break;
        if(!connected){Sleep(2);continue;}if(!proxyCurrent())break;
        if(read->pending){DWORD n=0;if(GetOverlappedResult(o.proxyPipe.h,&read->io,&n,FALSE)){read->pending=false;read->size=n;if(!n){proxyReadEof=true;if(!send(Op::Eof,{}))break;}else if(!o.sshCredit||!send(Op::Ssh,Bytes(read->bytes.begin(),read->bytes.begin()+n)))break;else o.sshCredit=false;}
            else if(GetLastError()==ERROR_BROKEN_PIPE){read->pending=false;proxyReadEof=true;if(!send(Op::Eof,{}))break;}else if(GetLastError()!=ERROR_IO_INCOMPLETE)break;}
        if(write->pending){DWORD n=0;if(GetOverlappedResult(o.proxyPipe.h,&write->io,&n,FALSE)){write->pending=false;if(n!=write->size||!proxyCurrent())break;}else if(GetLastError()!=ERROR_IO_INCOMPLETE)break;}
        if(!write->pending&&!o.toProxy.empty()) {
            const auto bytes=std::move(o.toProxy.front());o.toProxy.pop_front();if(bytes.size()>write->bytes.size())break;std::copy(bytes.begin(),bytes.end(),write->bytes.begin());write->size=static_cast<DWORD>(bytes.size());ResetEvent(write->event.h);write->io={};write->io.hEvent=write->event.h;write->pending=true;
            if(!WriteFile(o.proxyPipe.h,write->bytes.data(),write->size,nullptr,&write->io)&&GetLastError()!=ERROR_IO_PENDING){write->pending=false;break;}
        }
        if(!read->pending&&o.sshCredit&&!proxyReadEof) {ResetEvent(read->event.h);read->io={};read->io.hEvent=read->event.h;read->pending=true;
            if(!ReadFile(o.proxyPipe.h,read->bytes.data(),static_cast<DWORD>(read->bytes.size()),nullptr,&read->io)&&GetLastError()!=ERROR_IO_PENDING){read->pending=false;break;}}
        // EOF del daemon termina la misma instancia, después de vaciar su última escritura.
        if(o.guestEof&&o.toProxy.empty()&&!write->pending){if(!cancelTransfers()||!o.proxyPipe.Close())break;connected=false;bridgeClosed=true;}
        Sleep(2);
    }
    if(!cancelTransfers())return false; // Impl conserva todos los transfers hasta CloseOwn confirmado.
    if(!okay||!fresh())return false;o.authenticated=true;
    if(!send(Op::Close,{})||!receive(frame,std::min(o.bootEnd,GetTickCount64()+500))||frame.op!=Op::Closed||!frame.body.empty())return false;
    o.linuxReady=false;o.closing=true;DWORD qemuCode=0;
    while(GetTickCount64()<o.bootEnd&&!cancelled_.load()){if(!o.DiskCurrent())return false;if(o.qemu.Terminal(qemuCode))return qemuCode==0&&o.DiskCurrent();Sleep(5);}return false;
}
OwnHostLinuxOriginal::Snapshot OwnHostLinuxOriginal::InspectOwn(){std::lock_guard<std::recursive_mutex>lock(mutex_);if(own_->state!=State::Closed&&!OriginalCurrentOwn())own_->state=State::ClosePending;return {own_->state,own_->bootSubmitted,own_->authenticated};}
OwnHostLinuxOriginal::Snapshot OwnHostLinuxOriginal::CancelOwn(){cancelled_.store(true);std::lock_guard<std::recursive_mutex>lock(mutex_);own_->linuxReady=false;own_->state=State::ClosePending;if(own_->credential)own_->credential->CancelOwn();return {own_->state,own_->bootSubmitted,own_->authenticated};}
OwnHostLinuxOriginal::Snapshot OwnHostLinuxOriginal::CloseOwn(){CancelOwn();std::lock_guard<std::recursive_mutex>lock(mutex_);auto&o=*own_;bool closed=true;
    const bool readDrained=o.proxyRead.Drain(o.proxyPipe.h),writeDrained=o.proxyWrite.Drain(o.proxyPipe.h);closed=readDrained&&writeDrained;
    if(o.connectPending){if(!CancelIoEx(o.proxyPipe.h,&o.proxyConnect)&&GetLastError()!=ERROR_NOT_FOUND)closed=false;DWORD n=0;if(GetOverlappedResult(o.proxyPipe.h,&o.proxyConnect,&n,FALSE))o.connectPending=false;else if(GetLastError()==ERROR_OPERATION_ABORTED||GetLastError()==ERROR_BROKEN_PIPE)o.connectPending=false;else closed=false;}
    if(o.credential&&o.credential->CloseOwn().state!=OwnMemorySshCredential::State::Closed)closed=false;
    closed=o.ssh.Close()&&closed;closed=o.qemu.Close()&&closed;for(auto&tool:o.tools)closed=tool->Close()&&closed;
    if(!closed)return {o.state,o.bootSubmitted,o.authenticated};
    for(auto&h:o.consumed)closed=h.Close()&&closed;
    for(auto*h:{&o.qemuInput,&o.qemuOutput,&o.qemuError,&o.sshInput,&o.sshOutput,&o.sshError,&o.proxyPipe,&o.proxyEvent,&o.proxyRead.event,&o.proxyWrite.event,&o.proxyProcess,&o.self})closed=h->Close()&&closed;
    for(auto&f:o.pins)closed=f->Close()&&closed;
    for(auto*f:{&o.selfFile,&o.root,&o.outputParent,&o.source,&o.archive,&o.sums,&o.signature,&o.keyring,&o.guest,&o.capture,&o.sshImage,&o.proxyImage})closed=f->Close()&&closed;
    if(closed)o.state=State::Closed;return {o.state,o.bootSubmitted,o.authenticated};
}
int RunOwnHostLinuxOriginal(int argc,wchar_t**argv) {
    static std::mutex registryMutex;static std::map<OwnHostLinuxOriginal*,std::shared_ptr<OwnHostLinuxOriginal>>retained;
    auto original=std::shared_ptr<OwnHostLinuxOriginal>(new OwnHostLinuxOriginal);{std::lock_guard<std::mutex>lock(registryMutex);retained.emplace(original.get(),original);}
    bool succeeded=false;try{succeeded=original->PrepareOwn(argc,argv)&&original->RunOwn();}catch(...){original->CancelOwn();}
    const auto terminal=original->CloseOwn();if(terminal.state==OwnHostLinuxOriginal::State::Closed){std::lock_guard<std::mutex>lock(registryMutex);retained.erase(original.get());}
    return succeeded&&terminal.state==OwnHostLinuxOriginal::State::Closed?0:2;
}
}
