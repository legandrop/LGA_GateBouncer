#include "GuestBrokerBoundary.hpp"
#include "FixedGuestBrokerSource.hpp"
#include "../helper/OwnedSuspendedProcess.hpp"
#include "../../files/RetainedFile.hpp"
#include "../../../../common/pipe_ii_win.h"
#include <bcrypt.h>
#include <sddl.h>
#include <lm.h>
#include <map>
#include <list>
#include <mutex>
#include <vector>
#include <cstring>
#include <string>
#include <algorithm>
#include <atomic>
namespace gb {
namespace {
constexpr wchar_t ServiceName[] = L"LGAGateBouncerLab";
constexpr wchar_t KeeperPipe[] = L"\\\\.\\pipe\\LGAGateBouncerLab.GuestKeeper";
constexpr wchar_t ControllerPipe[] = L"\\\\.\\pipe\\LGAGateBouncerLab.GuestController";
constexpr wchar_t HelperPipe[] = L"\\\\.\\pipe\\LGAGateBouncerLab.GuestHelper";
const std::array<std::wstring,7> Paths{
 L"C:\\GateBouncerLab\\bin\\guest_broker.exe", L"C:\\GateBouncerLab\\bin\\desktop_worker.exe",
 L"C:\\GateBouncerLab\\supervisor\\GuestCommands.ps1", L"C:\\GateBouncerLab\\bin\\capture_netevent.psm1",
 L"C:\\GateBouncerLab\\bin\\guest_conversion.dll", L"C:\\GateBouncerLab\\bin\\conversion_worker.exe",
 L"C:\\GateBouncerLab\\bin\\guest_native_controller.dll"};
using Hash = std::array<BYTE,32>;
std::uint64_t Creation(HANDLE process) {
 FILETIME made{},exit{},kernel{},user{};
 return GetProcessTimes(process,&made,&exit,&kernel,&user) ?
  (std::uint64_t(made.dwHighDateTime)<<32)|made.dwLowDateTime : 0;
}
bool Alive(HANDLE process,std::uint64_t creation) {
 return process && creation && Creation(process)==creation &&
  WaitForSingleObject(process,0)==WAIT_TIMEOUT;
}
bool NoJob(HANDLE process) {
 BOOL inJob=TRUE; return IsProcessInJob(process,nullptr,&inJob) && !inJob;
}
bool Token(HANDLE process,native::TokenEvidence& result) {
 HANDLE raw=nullptr;
 if(!OpenProcessToken(process,TOKEN_QUERY,&raw)) return false;
 native::Handle token(raw); return native::tokenEvidence(token.value,result);
}
bool SameToken(const native::TokenEvidence& a,const native::TokenEvidence& b) {
 return a.account==b.account && a.logon==b.logon && a.session==b.session &&
  a.integrity==b.integrity && a.administrator==b.administrator &&
  a.elevated==b.elevated && a.uiAccess==b.uiAccess;
}
bool Random(void* bytes,ULONG count) {
 return BCryptGenRandom(nullptr,static_cast<PUCHAR>(bytes),count,BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0;
}
struct MacCustody { BCRYPT_ALG_HANDLE algorithm=nullptr; BCRYPT_HASH_HANDLE hash=nullptr; };
std::mutex MacMutex;
std::list<MacCustody> MacResources;
bool Mac(const Hash& key,const void* bytes,ULONG count,Hash& out) {
 std::lock_guard<std::mutex> guard(MacMutex);
 // La hoja precede a CNG; un cierre incierto conserva recursos y veta otro intento.
 if(!MacResources.empty()) return false;
 MacResources.emplace_back();
 auto& resource=MacResources.back();
 Hash result{};
 const bool opened=BCryptOpenAlgorithmProvider(&resource.algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,BCRYPT_ALG_HANDLE_HMAC_FLAG)==0;
 // Windows 7 ya permite que CNG custodie su buffer hasta DestroyHash confirmado.
 const bool created=opened && BCryptCreateHash(resource.algorithm,&resource.hash,nullptr,0,const_cast<PUCHAR>(key.data()),32,0)==0;
 const bool ok=created && BCryptHashData(resource.hash,const_cast<PUCHAR>(static_cast<const BYTE*>(bytes)),count,0)==0 &&
  BCryptFinishHash(resource.hash,result.data(),32,0)==0;
 const bool destroyed=!resource.hash || BCryptDestroyHash(resource.hash)==0;
 if(destroyed) resource.hash=nullptr;
 const bool closed=destroyed && (!resource.algorithm || BCryptCloseAlgorithmProvider(resource.algorithm,0)==0);
 if(closed) {resource.algorithm=nullptr;MacResources.pop_back();}
 if(ok&&destroyed&&closed) out=result;
 SecureZeroMemory(result.data(),result.size());return ok&&destroyed&&closed;
}
bool EqualMac(const Hash& a,const Hash& b) {
 BYTE difference=0; for(std::size_t i=0;i<a.size();++i) difference=static_cast<BYTE>(difference|(a[i]^b[i]));
 return difference==0;
}
Hash TokenIdentity(const native::TokenEvidence& token) {
 wire::Bytes bytes=token.account;
 bytes.insert(bytes.end(),token.logon.begin(),token.logon.end());
 const std::array<DWORD,3> facts{token.session,token.integrity,
  (token.administrator?1u:0u)|(token.elevated?2u:0u)|(token.uiAccess?4u:0u)};
 const auto raw=reinterpret_cast<const BYTE*>(facts.data());
 bytes.insert(bytes.end(),raw,raw+sizeof(facts));
 return native::digest(bytes);
}
enum class Op : std::uint32_t { Section=1, Ack=2, Account=3, Candidate=4, Delivered=5,
 Challenge=6, Proof=7, Admitted=8, Revoke=9, Close=10, StartHelper=11, HelperBound=12, SealAck=13 };
struct Packet {
 std::uint32_t version=1;
 Op op=Op::Revoke;
 std::uint64_t sequence=0, epoch=0, handle=0, pid=0, created=0, cookie=0, brokerPid=0, brokerCreated=0;
 Hash nonce{},peerNonce{},actor{},peer{},proof{};
 std::array<BYTE,224> pins{};
 std::array<wchar_t,96> text{};
};
static_assert(sizeof(Packet)<2048,"fixed packet bound");
bool Transfer(HANDLE pipe,HANDLE stop,Packet& packet,bool write,DWORD timeout=30000) {
 wire::Bytes bytes(sizeof(packet));
 if(write) std::memcpy(bytes.data(),&packet,sizeof(packet));
 if(!ipc::ii::transfer(pipe,write,bytes,bytes.size(),stop,timeout)) return false;
 if(!write) std::memcpy(&packet,bytes.data(),sizeof(packet));
 return packet.version==1;
}
bool Send(HANDLE pipe,HANDLE stop,Packet packet) { return Transfer(pipe,stop,packet,true); }
bool ServiceConfiguration(SC_HANDLE service,DWORD process,const wire::Bytes& owner) {
 DWORD needed=0,returned=0;
 QueryServiceConfigW(service,nullptr,0,&needed);
 if(!needed||needed>65536) return false;
 wire::Bytes configBytes(needed);
 if(!QueryServiceConfigW(service,reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBytes.data()),needed,&returned)) return false;
 auto config=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBytes.data());
 if(config->dwServiceType!=SERVICE_WIN32_OWN_PROCESS||config->dwStartType!=SERVICE_DEMAND_START||
  config->dwErrorControl!=SERVICE_ERROR_IGNORE||!config->lpBinaryPathName||
  std::wstring(config->lpBinaryPathName)!=L"\""+Paths[0]+L"\""||
  !config->lpServiceStartName||_wcsicmp(config->lpServiceStartName,L"LocalSystem")) return false;
 SERVICE_STATUS_PROCESS state{};
 if(!QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&state),sizeof(state),&returned)||
  !process||state.dwProcessId!=process) return false;
 QueryServiceObjectSecurity(service,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,nullptr,0,&needed);
 if(!needed||needed>8192) return false;
 wire::Bytes descriptor(needed);
 if(!QueryServiceObjectSecurity(service,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,descriptor.data(),needed,&returned)) return false;
 PSID actual=nullptr; BOOL defaulted=FALSE;
 return GetSecurityDescriptorOwner(descriptor.data(),&actual,&defaulted) &&
  !owner.empty() && EqualSid(actual,const_cast<BYTE*>(owner.data()));
}
bool ServiceSid(wire::Bytes& sid) {
 wchar_t domain[256]{}; DWORD sidSize=SECURITY_MAX_SID_SIZE,domainSize=256; SID_NAME_USE use{};
 sid.resize(sidSize);
 if(!LookupAccountNameW(L".",L"NT SERVICE\\LGAGateBouncerLab",sid.data(),&sidSize,domain,&domainSize,&use)) return false;
 sid.resize(sidSize); return IsValidSid(sid.data())!=FALSE;
}
native::Handle OpenPipe(const wchar_t* name,HANDLE stop) {
 const auto started=GetTickCount64();
 while(GetTickCount64()-started<30000&&WaitForSingleObject(stop,0)==WAIT_TIMEOUT) {
  if(WaitNamedPipeW(name,100)) {
   HANDLE pipe=CreateFileW(name,ipc::ii::ClientAccess,0,nullptr,OPEN_EXISTING,
    FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
   if(pipe!=INVALID_HANDLE_VALUE) return native::Handle(pipe);
  }
  const DWORD error=GetLastError();
  if(error!=ERROR_FILE_NOT_FOUND&&error!=ERROR_PIPE_BUSY&&error!=ERROR_SEM_TIMEOUT) return {};
  if(WaitForSingleObject(stop,50)!=WAIT_TIMEOUT) return {};
 }
 return {};
}
bool PeerCurrent(HANDLE pipe,bool server,const native::ProcessEvidence& peer,
 const native::TokenEvidence& expected) {
 DWORD pid=0,available=0; native::TokenEvidence token;
 return PeekNamedPipe(pipe,nullptr,0,nullptr,&available,nullptr) &&
  (server?GetNamedPipeClientProcessId(pipe,&pid):GetNamedPipeServerProcessId(pipe,&pid)) &&
  pid==peer.pid && peer.current() && Token(peer.process.value,token) && SameToken(token,expected);
}
bool AccountSid(const std::wstring& name,wire::Bytes& sid) {
 LPBYTE data=nullptr;
 if(NetUserGetInfo(nullptr,name.c_str(),23,&data)!=NERR_Success||!data) return false;
 auto account=reinterpret_cast<USER_INFO_23*>(data);
 bool ok=account->usri23_user_sid && IsValidSid(account->usri23_user_sid) &&
  !(account->usri23_flags&UF_ACCOUNTDISABLE);
 if(ok) { auto raw=static_cast<BYTE*>(account->usri23_user_sid); sid.assign(raw,raw+GetLengthSid(raw)); }
 NetApiBufferFree(data); return ok;
}
}
class GuestNativePins final {
public:
 bool Acquire(const HANDLE* borrowed,const BYTE* hashes) {
  if(!borrowed||!hashes) return false;
  for(std::size_t i=0;i<Paths.size();++i) {
   std::memcpy(hashes_[i].data(),hashes+i*32,32);
   files_[i]=RetainedFile::RetainInputOwn(borrowed[i],Paths[i],16777216);
   if(!files_[i]->HashOwn(hashes_[i])) return false;
  }
  return Current();
 }
 bool Open(const BYTE* hashes) {
  if(!hashes) return false;
  for(std::size_t i=0;i<Paths.size();++i) {
   std::memcpy(hashes_[i].data(),hashes+i*32,32);
   files_[i]=RetainedFile::OpenOwn(Paths[i],false,16777216);
   if(!files_[i]->HashOwn(hashes_[i])) return false;
  }
  return Current();
 }
 bool Current() const {
  for(std::size_t i=0;i<files_.size();++i)
   if(!files_[i]||!files_[i]->CurrentOwn()||!files_[i]->HashOwn(hashes_[i])) return false;
  return true;
 }
 bool Close() {
  for(auto& pin:files_) if(pin) { if(!pin->CloseOwn()) return false; pin.reset(); }
  return true;
 }
 std::array<std::shared_ptr<RetainedFile>,7> files_{};
 std::array<Hash,7> hashes_{};
};
namespace {
struct Leaf {
 std::recursive_mutex gate;
 native::Handle own,stop,section,pipe,duplicateTarget;
 native::ProcessEvidence peer,controller;
 native::TokenEvidence token,peerToken,controllerToken;
 std::shared_ptr<GuestNativePins> pins=std::make_shared<GuestNativePins>();
 SC_HANDLE manager=nullptr,service=nullptr;
 void* view=nullptr;
 Hash key{};
 std::uint64_t made=0,cookie=0,epoch=0,sequence=0;
 DWORD tid=0;
 wire::Bytes account;
 std::wstring reservedName;
 bool keeper=false,revoked=false,closed=false,acquiring=false;
 bool serviceSubmitted=false,startSubmitted=false,sectionSubmitted=false,controllerSubmitted=false;
 bool accountSubmitted=false,accountBound=false,admitted=false,sealed=false;
 HANDLE delivered=nullptr;
 bool Current() const {
  native::TokenEvidence now;
  return !revoked&&!closed&&own&&stop&&GetCurrentThreadId()==tid&&WaitForSingleObject(stop.value,0)==WAIT_TIMEOUT&&
   Alive(own.value,made)&&Token(own.value,now)&&SameToken(now,token)&&pins->Current()&&
   (!pipe||(PeerCurrent(pipe.value,false,peer,peerToken)&&NoJob(peer.process.value)));
 }
};
std::mutex leafMutex;
std::map<void*,std::shared_ptr<Leaf>> leaves;
std::shared_ptr<Leaf> Find(void* key) {
 std::lock_guard<std::mutex> lock(leafMutex); const auto found=leaves.find(key);
 return found==leaves.end()?nullptr:found->second;
}
bool Reserve(const HANDLE* handles,const BYTE* hashes,HANDLE stop,void** output,bool keeper,const wchar_t* name=nullptr) {
 if(!output) return false;
 auto leaf=std::make_shared<Leaf>();
 { std::lock_guard<std::mutex> lock(leafMutex); leaves.emplace(leaf.get(),leaf); }
 *output=leaf.get(); leaf->keeper=keeper; leaf->tid=GetCurrentThreadId();
 if(keeper) {
  if(!name||wcsnlen_s(name,21)!=20||name[0]!=L'g'||name[1]!=L'b') return false;
  for(std::size_t i=2;i<20;++i) if(!((name[i]>=L'0'&&name[i]<=L'9')||(name[i]>=L'a'&&name[i]<=L'f'))) return false;
  leaf->reservedName=name;
 }
 HANDLE raw=nullptr;
 if(!DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(),GetCurrentProcess(),&raw,PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,0)) return false;
 leaf->own.reset(raw); leaf->made=Creation(raw);
 raw=nullptr;
 if(!DuplicateHandle(GetCurrentProcess(),stop,GetCurrentProcess(),&raw,SYNCHRONIZE|EVENT_MODIFY_STATE,FALSE,0)) return false;
 leaf->stop.reset(raw);
 return Token(leaf->own.value,leaf->token)&&Random(&leaf->cookie,sizeof(leaf->cookie))&&
  leaf->cookie&&leaf->pins->Acquire(handles,hashes)&&leaf->Current();
}
bool DupProcess(native::Handle& target,DWORD pid,std::uint64_t made,const native::TokenEvidence& expected) {
 target.reset(OpenProcess(PROCESS_DUP_HANDLE|PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid));
 native::TokenEvidence observed;
 return target && GetProcessId(target.value)==pid&&Alive(target.value,made)&&
  Token(target.value,observed)&&SameToken(expected,observed);
}
bool DupSection(Leaf& leaf,native::Handle& target,HANDLE& delivered,bool& submitted) {
 if(submitted||!leaf.Current()||!target) return false;
 submitted=true;
 return DuplicateHandle(GetCurrentProcess(),leaf.section.value,target.value,&delivered,FILE_MAP_READ,FALSE,0)!=FALSE;
}
bool ReceiveExpected(Leaf& leaf,Op operation,Packet& packet) {
 return Transfer(leaf.pipe.value,leaf.stop.value,packet,false)&&packet.op==operation&&
  PeerCurrent(leaf.pipe.value,false,leaf.peer,leaf.peerToken)&&leaf.Current();
}
}
bool SetOwnedServiceSecurity(SC_HANDLE service,const wire::Bytes& owner) {
 if(owner.empty()) return false;
 const auto sid=native::sidString(owner);
 const auto text=L"O:"+sid+L"G:SYD:P(A;;0x000f01ff;;;SY)(A;;0x000f01ff;;;"+sid+L")";
 PSECURITY_DESCRIPTOR descriptor=nullptr;
 if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(text.c_str(),SDDL_REVISION_1,&descriptor,nullptr)) return false;
 const bool ok=SetServiceObjectSecurity(service,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,descriptor)!=FALSE;
 LocalFree(descriptor); return ok;
}
bool OwnedServiceSecurity(SC_HANDLE service,const wire::Bytes& owner) {
 DWORD needed=0,returned=0;
 QueryServiceObjectSecurity(service,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,nullptr,0,&needed);
 if(!needed||needed>8192||owner.empty()) return false;
 wire::Bytes bytes(needed);
 if(!QueryServiceObjectSecurity(service,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,bytes.data(),needed,&returned)) return false;
 PSID actual=nullptr; PACL acl=nullptr; BOOL defaulted=FALSE,present=FALSE;
 if(!GetSecurityDescriptorOwner(bytes.data(),&actual,&defaulted)||
  !EqualSid(actual,const_cast<BYTE*>(owner.data()))||
  !GetSecurityDescriptorDacl(bytes.data(),&present,&acl,&defaulted)||!present||!acl||acl->AceCount!=2) return false;
 BYTE system[SECURITY_MAX_SID_SIZE]{}; DWORD size=sizeof(system);
 if(!CreateWellKnownSid(WinLocalSystemSid,nullptr,system,&size)) return false;
 for(DWORD i=0;i<2;++i) {
  void* raw=nullptr;
  if(!GetAce(acl,i,&raw)) return false;
  auto ace=static_cast<ACCESS_ALLOWED_ACE*>(raw);
  if(ace->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE||ace->Mask!=SERVICE_ALL_ACCESS||
   !EqualSid(&ace->SidStart,i?const_cast<BYTE*>(owner.data()):system)) return false;
 }
 SECURITY_DESCRIPTOR_CONTROL control=0; DWORD revision=0;
 return GetSecurityDescriptorControl(bytes.data(),&control,&revision)&&(control&SE_DACL_PROTECTED)!=0;
}
GB_GUEST_API bool GbBootstrapReserveOwn(const HANDLE* handles,const BYTE* hashes,HANDLE stop,const wchar_t* name,void** output) {
 try { return Reserve(handles,hashes,stop,output,true,name); } catch(...) { return false; }
}
GB_GUEST_API bool GbBootstrapStartOwn(void* key) {
 auto leaf=Find(key); if(!leaf) return false;
 std::lock_guard<std::recursive_mutex> lock(leaf->gate);
 try {
  if(!leaf->keeper||leaf->serviceSubmitted||leaf->startSubmitted||!leaf->Current()) return false;
  leaf->section.reset(CreateFileMappingW(INVALID_HANDLE_VALUE,nullptr,PAGE_READWRITE,0,4096,nullptr));
  if(!leaf->section) return false;
  leaf->view=MapViewOfFile(leaf->section.value,FILE_MAP_WRITE|FILE_MAP_READ,0,0,4096);
  if(!leaf->view||!Random(leaf->key.data(),32)||!Random(&leaf->epoch,sizeof(leaf->epoch))||!leaf->epoch) return false;
  std::memcpy(leaf->view,leaf->key.data(),32);
  leaf->manager=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CREATE_SERVICE|SC_MANAGER_CONNECT);
  if(!leaf->manager||!leaf->Current()) return false;
  leaf->serviceSubmitted=true;
  const auto command=L"\""+Paths[0]+L"\"";
  leaf->service=CreateServiceW(leaf->manager,ServiceName,ServiceName,SERVICE_ALL_ACCESS,
   SERVICE_WIN32_OWN_PROCESS,SERVICE_DEMAND_START,SERVICE_ERROR_IGNORE,command.c_str(),nullptr,nullptr,nullptr,nullptr,nullptr);
  SERVICE_SID_INFO sid{SERVICE_SID_TYPE_UNRESTRICTED};
  if(!leaf->service||!SetOwnedServiceSecurity(leaf->service,leaf->token.account)||
   !OwnedServiceSecurity(leaf->service,leaf->token.account)||
   !ChangeServiceConfig2W(leaf->service,SERVICE_CONFIG_SERVICE_SID_INFO,&sid)||!leaf->Current()) return false;
  // Sólo correlación pública; ninguna credencial en argumentos SCM.
  const auto pid=std::to_wstring(GetCurrentProcessId()),made=std::to_wstring(leaf->made),cookie=std::to_wstring(leaf->cookie);
  const wchar_t* arguments[]={pid.c_str(),made.c_str(),cookie.c_str()};
  leaf->startSubmitted=true;
  if(!StartServiceW(leaf->service,3,arguments)||!leaf->Current()) return false;
  leaf->pipe=OpenPipe(KeeperPipe,leaf->stop.value);
  if(!leaf->pipe||!ipc::ii::serverEvidence(leaf->pipe.value,leaf->peer)||
   !Token(leaf->peer.process.value,leaf->peerToken)||leaf->peer.image!=Paths[0]||
   !NoJob(leaf->peer.process.value)||!ServiceConfiguration(leaf->service,leaf->peer.pid,leaf->token.account)||
   !OwnedServiceSecurity(leaf->service,leaf->token.account)||
   !DupProcess(leaf->duplicateTarget,leaf->peer.pid,Creation(leaf->peer.process.value),leaf->peerToken)||
   !DupSection(*leaf,leaf->duplicateTarget,leaf->delivered,leaf->sectionSubmitted)) return false;
  Packet packet; packet.op=Op::Section; packet.handle=reinterpret_cast<std::uintptr_t>(leaf->delivered);
  packet.epoch=leaf->epoch; packet.pid=GetCurrentProcessId(); packet.created=leaf->made; packet.cookie=leaf->cookie;
  std::memcpy(packet.pins.data(),leaf->pins->hashes_.data(),packet.pins.size());
  Packet ack;
  return Send(leaf->pipe.value,leaf->stop.value,packet)&&ReceiveExpected(*leaf,Op::Ack,ack)&&ack.epoch==leaf->epoch;
 } catch(...) { leaf->revoked=true; return false; }
}
GB_GUEST_API bool GbBootstrapBeginAccountOwn(void* key) {
 auto leaf=Find(key);if(!leaf) return false;
 std::lock_guard<std::recursive_mutex> lock(leaf->gate);
 if(!leaf->keeper||leaf->accountSubmitted||!GbBootstrapReadyOwn(key)) return false;
 leaf->accountSubmitted=true;
 LPBYTE data=nullptr;const auto status=NetUserGetInfo(nullptr,leaf->reservedName.c_str(),23,&data);
 if(data) NetApiBufferFree(data);
 return status==NERR_UserNotFound&&leaf->Current();
}
GB_GUEST_API bool GbBootstrapAccountOwn(void* key,const wchar_t* sid) {
 auto leaf=Find(key); if(!leaf||!sid) return false;
 std::lock_guard<std::recursive_mutex> lock(leaf->gate);
 try {
  if(!leaf->keeper||!leaf->accountSubmitted||leaf->accountBound||!leaf->Current()||wcsnlen_s(sid,193)>=193) return false;
  wire::Bytes actual; if(!AccountSid(leaf->reservedName,actual)||native::sidString(actual)!=sid) return false;
  leaf->accountBound=true; leaf->account=actual;
  Packet packet; packet.op=Op::Account; packet.epoch=leaf->epoch;
  std::copy(leaf->reservedName.begin(),leaf->reservedName.end(),packet.text.begin()); Packet ack;
  return Send(leaf->pipe.value,leaf->stop.value,packet)&&ReceiveExpected(*leaf,Op::Ack,ack);
 } catch(...) { leaf->revoked=true; return false; }
}
GB_GUEST_API bool GbBootstrapReadyOwn(void* key) {
 auto leaf=Find(key);if(!leaf) return false;
 std::lock_guard<std::recursive_mutex> lock(leaf->gate);
 return leaf->keeper&&leaf->sectionSubmitted&&leaf->Current()&&leaf->pipe&&
  PeerCurrent(leaf->pipe.value,false,leaf->peer,leaf->peerToken)&&NoJob(leaf->peer.process.value)&&
  ServiceConfiguration(leaf->service,leaf->peer.pid,leaf->token.account)&&
  OwnedServiceSecurity(leaf->service,leaf->token.account);
}
GB_GUEST_API bool GbControllerReserveOwn(const HANDLE* handles,const BYTE* hashes,HANDLE stop,
 void** output,DWORD* pid,std::uint64_t* made,std::uint64_t* cookie) {
 if(!pid||!made||!cookie) return false;
 try {
  if(!Reserve(handles,hashes,stop,output,false)) return false;
  auto leaf=Find(*output); if(!leaf) return false;
  std::lock_guard<std::recursive_mutex> lock(leaf->gate);
  leaf->pipe=OpenPipe(ControllerPipe,leaf->stop.value);
  if(!leaf->pipe||!ipc::ii::serverEvidence(leaf->pipe.value,leaf->peer)||
   leaf->peer.image!=Paths[0]||!NoJob(leaf->peer.process.value)||!Token(leaf->peer.process.value,leaf->peerToken)) return false;
  *pid=GetCurrentProcessId(); *made=leaf->made; *cookie=leaf->cookie;
  Packet packet; packet.op=Op::Candidate; packet.pid=*pid; packet.created=*made; packet.cookie=*cookie;
  return Send(leaf->pipe.value,leaf->stop.value,packet)&&leaf->Current();
 } catch(...) { return false; }
}
GB_GUEST_API bool GbBootstrapBindOwn(void* key,DWORD pid,std::uint64_t made,std::uint64_t cookie) {
 auto leaf=Find(key); if(!leaf) return false;
 std::lock_guard<std::recursive_mutex> lock(leaf->gate);
 try {
  if(!leaf->keeper||!leaf->accountBound||leaf->controllerSubmitted||!leaf->Current()||!pid||!made||!cookie) return false;
  if(!leaf->controller.acquire(pid)||Creation(leaf->controller.process.value)!=made||
   !Token(leaf->controller.process.value,leaf->controllerToken)||leaf->controllerToken.account!=leaf->account) return false;
  Packet packet; packet.op=Op::Candidate; packet.epoch=leaf->epoch; packet.pid=pid; packet.created=made; packet.cookie=cookie;
  if(!Send(leaf->pipe.value,leaf->stop.value,packet)) return false;
  Packet ack; if(!ReceiveExpected(*leaf,Op::Ack,ack)||ack.pid!=pid||ack.created!=made||ack.cookie!=cookie) return false;
  // Corroboración OS y canal original ANTES de la entrega única.
  if(!leaf->controller.current()||!DupProcess(leaf->duplicateTarget,pid,made,leaf->controllerToken)) return false;
  leaf->delivered=nullptr;
  if(!DupSection(*leaf,leaf->duplicateTarget,leaf->delivered,leaf->controllerSubmitted)) return false;
  packet.op=Op::Delivered; packet.handle=reinterpret_cast<std::uintptr_t>(leaf->delivered);
  return Send(leaf->pipe.value,leaf->stop.value,packet)&&leaf->Current();
 } catch(...) { leaf->revoked=true; return false; }
}
GB_GUEST_API bool GbControllerBindOwn(void* key) {
 auto leaf=Find(key); if(!leaf) return false;
 std::lock_guard<std::recursive_mutex> lock(leaf->gate);
 try {
  if(leaf->keeper||leaf->admitted||!leaf->Current()) return false;
  Packet packet;
  if(!ReceiveExpected(*leaf,Op::Delivered,packet)||packet.pid!=GetCurrentProcessId()||packet.created!=leaf->made||packet.cookie!=leaf->cookie||!packet.handle||!packet.epoch) return false;
  leaf->section.reset(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(packet.handle)));
  leaf->view=MapViewOfFile(leaf->section.value,FILE_MAP_READ,0,0,32);
  if(!leaf->view) return false;
  std::memcpy(leaf->key.data(),leaf->view,32); leaf->epoch=packet.epoch;
  if(!ReceiveExpected(*leaf,Op::Challenge,packet)||packet.epoch!=leaf->epoch||
   packet.brokerPid!=leaf->peer.pid||packet.brokerCreated!=Creation(leaf->peer.process.value)||
   !Random(packet.peerNonce.data(),32)) return false;
  packet.op=Op::Proof; packet.epoch=leaf->epoch; packet.pid=GetCurrentProcessId(); packet.created=leaf->made; packet.cookie=leaf->cookie;
  packet.actor=TokenIdentity(leaf->token); packet.peer=TokenIdentity(leaf->peerToken);
  packet.sequence=++leaf->sequence; packet.proof.fill(0);
  if(!Mac(leaf->key,&packet,sizeof(packet),packet.proof)||!Send(leaf->pipe.value,leaf->stop.value,packet)) return false;
  Packet response;
  if(!ReceiveExpected(*leaf,Op::Admitted,response)||response.epoch!=leaf->epoch||response.sequence!=leaf->sequence||
   response.nonce!=packet.nonce||response.peerNonce!=packet.peerNonce||
   response.actor!=packet.actor||response.peer!=packet.peer||response.pid!=packet.pid||
   response.created!=packet.created||response.cookie!=packet.cookie||
   response.brokerPid!=packet.brokerPid||response.brokerCreated!=packet.brokerCreated) return false;
  const auto expected=response.proof; response.proof.fill(0); Hash proof{};
  if(!Mac(leaf->key,&response,sizeof(response),proof)||!EqualMac(expected,proof)||!leaf->Current()) return false;
  response.op=Op::Ack;response.proof.fill(0);
  if(!Mac(leaf->key,&response,sizeof(response),response.proof)||!Send(leaf->pipe.value,leaf->stop.value,response)) return false;
  leaf->admitted=true; return true;
 } catch(...) { leaf->revoked=true; return false; }
}
GB_GUEST_API bool GbBootstrapSealOwn(void* key) {
 auto leaf=Find(key); if(!leaf) return false;
 std::lock_guard<std::recursive_mutex> lock(leaf->gate);
 try {
  if(!leaf->keeper||leaf->sealed||!leaf->controllerSubmitted||!leaf->Current()) return false;
  Packet packet;
  if(!ReceiveExpected(*leaf,Op::Admitted,packet)||packet.epoch!=leaf->epoch||packet.sequence!=1||
   packet.pid!=leaf->controller.pid||packet.created!=Creation(leaf->controller.process.value)||
   packet.brokerPid!=leaf->peer.pid||packet.brokerCreated!=Creation(leaf->peer.process.value)||
   packet.actor!=TokenIdentity(leaf->controllerToken)||packet.peer!=TokenIdentity(leaf->peerToken)) return false;
  const auto received=packet.proof;packet.proof.fill(0);Hash expected{};
  if(!Mac(leaf->key,&packet,sizeof(packet),expected)||!EqualMac(received,expected)||!leaf->Current()) return false;
  packet.op=Op::SealAck;packet.pid=GetCurrentProcessId();packet.created=leaf->made;packet.cookie=leaf->cookie;
  packet.actor=TokenIdentity(leaf->token);packet.peer=TokenIdentity(leaf->peerToken);
  packet.proof.fill(0);
  if(!Mac(leaf->key,&packet,sizeof(packet),packet.proof)||!Send(leaf->pipe.value,leaf->stop.value,packet)||!leaf->Current()) return false;
  SecureZeroMemory(leaf->view,32);SecureZeroMemory(leaf->key.data(),leaf->key.size());
  leaf->sealed=true;return true;
 } catch(...) {leaf->revoked=true;return false;}
}
GB_GUEST_API bool GbNativeCurrentOwn(void* key) {
 auto leaf=Find(key); if(!leaf) return false;
 std::lock_guard<std::recursive_mutex> lock(leaf->gate);
 return leaf->Current()&&leaf->pipe&&PeerCurrent(leaf->pipe.value,false,leaf->peer,leaf->peerToken)&&
  NoJob(leaf->peer.process.value)&&(leaf->keeper?leaf->sealed:leaf->admitted);
}
GB_GUEST_API bool GbNativeRevokeOwn(void* key) {
 auto leaf=Find(key); if(!leaf) return false;
 SetEvent(leaf->stop.value);
 std::lock_guard<std::recursive_mutex> lock(leaf->gate); leaf->revoked=true;
 // Cierre del canal original propaga revocación al keeper/broker sin rebind.
 leaf->pipe.reset(); return true;
}
GB_GUEST_API bool GbNativeCloseOwn(void* key) {
 auto leaf=Find(key); if(!leaf) return false;
 SetEvent(leaf->stop.value);
 std::lock_guard<std::recursive_mutex> lock(leaf->gate); leaf->revoked=true;
 if(leaf->keeper&&leaf->startSubmitted) {
  // Arranque incierto aún debe adquirir/retener el receptor OS antes de liberar source.
  SERVICE_STATUS_PROCESS actual{};DWORD returned=0;
  if(!leaf->service||!QueryServiceStatusEx(leaf->service,SC_STATUS_PROCESS_INFO,
   reinterpret_cast<BYTE*>(&actual),sizeof(actual),&returned)) return false;
  if(!leaf->peer.process&&actual.dwProcessId) {
   if(!leaf->peer.acquire(actual.dwProcessId)||leaf->peer.image!=Paths[0]||
    !Token(leaf->peer.process.value,leaf->peerToken)||!NoJob(leaf->peer.process.value)||
    !ServiceConfiguration(leaf->service,leaf->peer.pid,leaf->token.account)||
    !OwnedServiceSecurity(leaf->service,leaf->token.account)) return false;
  }
  if(!leaf->peer.process&&actual.dwCurrentState!=SERVICE_STOPPED) return false;
  SERVICE_STATUS state{};
  if(actual.dwCurrentState!=SERVICE_STOPPED&&actual.dwCurrentState!=SERVICE_STOP_PENDING&&
   !ControlService(leaf->service,SERVICE_CONTROL_STOP,&state)&&GetLastError()!=ERROR_SERVICE_NOT_ACTIVE) return false;
  leaf->pipe.reset();
  if(leaf->peer.process&&WaitForSingleObject(leaf->peer.process.value,0)!=WAIT_OBJECT_0) return false;
  if(leaf->controllerSubmitted&&leaf->controller.process&&WaitForSingleObject(leaf->controller.process.value,0)!=WAIT_OBJECT_0) return false;
 }
 if(leaf->view) {
  if(leaf->keeper) SecureZeroMemory(leaf->view,32);
  if(!UnmapViewOfFile(leaf->view)) return false;
  leaf->view=nullptr;
 }
 SecureZeroMemory(leaf->key.data(),leaf->key.size());
 // Nunca CLOSE_SOURCE remoto, incluso tras ACK perdido.
 leaf->section.reset(); leaf->pipe.reset(); leaf->duplicateTarget.reset();
 if(!leaf->pins->Close()) return false;
 if(leaf->service) { if(!CloseServiceHandle(leaf->service)) return false; leaf->service=nullptr; }
 if(leaf->manager) { if(!CloseServiceHandle(leaf->manager)) return false; leaf->manager=nullptr; }
 leaf->closed=true; leaf->stop.reset(); leaf->own.reset();
 { std::lock_guard<std::mutex> registry(leafMutex); leaves.erase(key); }
 return true;
}

struct GuestBrokerBoundary::Resources {
 native::Handle stop,keeperAnchor,controllerAnchor,helperAnchor,keeper,controller,helper,section,own;
 native::ProcessEvidence bootstrapPeer,controllerPeer,brokerPeer,helperPeer;
 native::TokenEvidence bootstrapToken,controllerToken,brokerToken,ownToken,helperToken;
 std::shared_ptr<GuestNativePins> pins=std::make_shared<GuestNativePins>();
 std::shared_ptr<GuestNoJobObserver> noJob,childObservation;
 std::shared_ptr<OwnedSuspendedProcess> child;
 SC_HANDLE manager=nullptr,service=nullptr;
 Hash key{};
 void* view=nullptr;
 std::uint64_t epoch=0,created=0,sequence=0,controllerCookie=0;
 DWORD tid=0;
 bool admitted=false,revoked=false,helperRole=false,helperBound=false;
};
bool GuestBrokerBoundary::CurrentOwn() const {
 const auto& r=resources_;
 if(!r||r->revoked||!r->admitted||!r->stop||WaitForSingleObject(r->stop.value,0)!=WAIT_TIMEOUT||
  !Alive(r->own.value,r->created)||GetCurrentThreadId()!=r->tid||!r->pins->Current()||
  !NoJob(r->own.value)||!r->noJob||r->noJob->InspectOwn().state!=GuestNoJobObserver::State::Observed) return false;
 if(r->helperRole)
  return PeerCurrent(r->helper.value,false,r->brokerPeer,r->brokerToken)&&
   NoJob(r->brokerPeer.process.value)&&ServiceConfiguration(r->service,r->brokerPeer.pid,r->bootstrapToken.account)&&
   OwnedServiceSecurity(r->service,r->bootstrapToken.account);
 return PeerCurrent(r->keeper.value,true,r->bootstrapPeer,r->bootstrapToken)&&
  PeerCurrent(r->controller.value,true,r->controllerPeer,r->controllerToken)&&
  ServiceConfiguration(r->service,GetCurrentProcessId(),r->bootstrapToken.account)&&
  OwnedServiceSecurity(r->service,r->bootstrapToken.account);
}
bool BrokerAdmission::CurrentOwn() const {
 return boundary_&&noJob_&&boundary_->CurrentOwn();
}
namespace {
SERVICE_STATUS_HANDLE statusHandle=nullptr;
std::atomic<HANDLE> serviceStop{nullptr};
void WINAPI ServiceControl(DWORD control) {
 const auto stop=serviceStop.load();
 if(control==SERVICE_CONTROL_STOP&&stop) SetEvent(stop);
}
void ReportState(DWORD state,DWORD error=NO_ERROR) {
 SERVICE_STATUS status{};
 status.dwServiceType=SERVICE_WIN32_OWN_PROCESS; status.dwCurrentState=state;
 status.dwControlsAccepted=state==SERVICE_RUNNING?SERVICE_ACCEPT_STOP:0;
 status.dwWin32ExitCode=error; status.dwWaitHint=state==SERVICE_STOP_PENDING?30000:0;
 if(statusHandle) SetServiceStatus(statusHandle,&status);
}
bool Number(const wchar_t* value,std::uint64_t& number) {
 if(!value||!*value||wcsnlen_s(value,21)>=21) return false;
 number=0;
 for(const wchar_t* p=value;*p;++p) {
  if(*p<L'0'||*p>L'9') return false;
  const auto digit=static_cast<std::uint64_t>(*p-L'0');
  if(number>(UINT64_MAX-digit)/10) return false;
  number=number*10+digit;
 }
 return number!=0;
}
std::mutex boundaryMutex;
std::vector<std::shared_ptr<GuestBrokerBoundary>> boundaries;
}

bool GuestBrokerBoundary::RunBrokerOwn(DWORD keeperPid,std::uint64_t keeperCreated,std::uint64_t keeperCookie) {
 auto boundary=std::shared_ptr<GuestBrokerBoundary>(new GuestBrokerBoundary);
 { std::lock_guard<std::mutex> lock(boundaryMutex); boundaries.push_back(boundary); }
 boundary->resources_=std::make_shared<Resources>(); auto& r=*boundary->resources_;
 struct Closure {
  Resources& r;
  ~Closure() {
   r.revoked=true;
   if(r.stop) SetEvent(r.stop.value);
   // Conserva el servicio vivo hasta acreditar salida del child propio.
   while(r.childObservation&&r.childObservation->CloseOwn().state!=GuestNoJobObserver::State::Closed) Sleep(50);
   while(r.child&&r.child->CloseOwn().state!=OwnedSuspendedProcess::State::Closed) Sleep(50);
   while(r.noJob&&r.noJob->CloseOwn().state!=GuestNoJobObserver::State::Closed) Sleep(50);
   if(r.view) { UnmapViewOfFile(r.view); r.view=nullptr; }
   SecureZeroMemory(r.key.data(),r.key.size());
  }
 } closure{r};
 r.tid=GetCurrentThreadId();
 r.stop.reset(CreateEventW(nullptr,TRUE,FALSE,nullptr)); serviceStop=r.stop.value;
 if(!r.stop) return false;
 ReportState(SERVICE_RUNNING); // Sólo arranque; NO emite autoridad.
 HANDLE raw=nullptr;
 if(!DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(),GetCurrentProcess(),&raw,
  PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,0)) return false;
 r.own.reset(raw); r.created=Creation(raw);
 if(!Token(raw,r.ownToken)) return false;
 HANDLE tokenRaw=nullptr;
 if(!OpenProcessToken(raw,TOKEN_QUERY,&tokenRaw)) return false;
 native::Handle token(tokenRaw);
 if(!native::systemServiceToken(token.value)||!NoJob(raw)||!r.bootstrapPeer.acquire(keeperPid)||
  Creation(r.bootstrapPeer.process.value)!=keeperCreated||!Token(r.bootstrapPeer.process.value,r.bootstrapToken)) return false;
 r.manager=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
 if(!r.manager) return false;
 r.service=OpenServiceW(r.manager,ServiceName,SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS|READ_CONTROL);
 if(!r.service||!ServiceConfiguration(r.service,GetCurrentProcessId(),r.bootstrapToken.account)||
  !OwnedServiceSecurity(r.service,r.bootstrapToken.account)) return false;
 wire::Bytes serviceSid; if(!ServiceSid(serviceSid)) return false;
 const ipc::ii::Principals principals{r.bootstrapToken.account,r.bootstrapToken.logon,serviceSid};
 r.keeperAnchor=ipc::ii::anchor(KeeperPipe,ipc::ii::Channel::Control,principals);
 r.keeper=ipc::ii::instance(KeeperPipe,ipc::ii::Channel::Control,principals);
 r.controllerAnchor=ipc::ii::anchor(ControllerPipe,ipc::ii::Channel::Control,principals);
 r.controller=ipc::ii::instance(ControllerPipe,ipc::ii::Channel::Control,principals);
 if(!r.keeperAnchor||!r.keeper||!r.controllerAnchor||!r.controller||
  !ipc::ii::connect(r.keeper.value,r.stop.value,30000)) return false;
 native::ProcessEvidence keeperPeer; native::TokenEvidence keeperToken;
 Packet initial;
 // Impersonación sólo DESPUÉS del primer mensaje leído; ningún campo concede autoridad.
 if(!Transfer(r.keeper.value,r.stop.value,initial,false)||
  !ipc::ii::clientEvidence(r.keeper.value,keeperToken,keeperPeer)||keeperPeer.pid!=keeperPid||
  Creation(keeperPeer.process.value)!=keeperCreated||!SameToken(keeperToken,r.bootstrapToken)) return false;
 r.bootstrapPeer=std::move(keeperPeer);
 if(initial.op!=Op::Section||
  initial.pid!=keeperPid||initial.created!=keeperCreated||initial.cookie!=keeperCookie||
  !initial.epoch||!initial.handle) return false;
 r.epoch=initial.epoch;
 // Registrar el HANDLE entregado ANTES de mapear o validar. Sólo cierre local.
 r.section.reset(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(initial.handle)));
 r.view=MapViewOfFile(r.section.value,FILE_MAP_READ,0,0,32);
 if(!r.view) return false;
 std::memcpy(r.key.data(),r.view,32);
 if(!r.pins->Open(initial.pins.data())) return false;
 r.noJob=FixedGuestBrokerSource::ObserveOwnNative();
 if(!r.noJob||r.noJob->InspectOwn().state!=GuestNoJobObserver::State::Observed) return false;
 Packet ack; ack.op=Op::Ack; ack.epoch=r.epoch;
 if(!Send(r.keeper.value,r.stop.value,ack)) return false;
 Packet account;
 if(!Transfer(r.keeper.value,r.stop.value,account,false)||account.op!=Op::Account||
  account.epoch!=r.epoch||account.text[20]!=0||wcsnlen_s(account.text.data(),account.text.size())!=20||
  !PeerCurrent(r.keeper.value,true,r.bootstrapPeer,r.bootstrapToken)) return false;
 wire::Bytes accountSid;
 Packet controller,candidate;
 if(!AccountSid(account.text.data(),accountSid)||!Send(r.keeper.value,r.stop.value,ack)||
  !ipc::ii::connect(r.controller.value,r.stop.value,30000)||
  !Transfer(r.controller.value,r.stop.value,controller,false)||
  !ipc::ii::clientEvidence(r.controller.value,r.controllerToken,r.controllerPeer)||
  r.controllerToken.account!=accountSid) return false;
 if(controller.op!=Op::Candidate||
  controller.pid!=r.controllerPeer.pid||controller.created!=Creation(r.controllerPeer.process.value)||!controller.cookie||
  !Transfer(r.keeper.value,r.stop.value,candidate,false)||candidate.op!=Op::Candidate||
  candidate.epoch!=r.epoch||candidate.pid!=controller.pid||candidate.created!=controller.created||
  candidate.cookie!=controller.cookie||!PeerCurrent(r.keeper.value,true,r.bootstrapPeer,r.bootstrapToken)||
  !PeerCurrent(r.controller.value,true,r.controllerPeer,r.controllerToken)) return false;
 r.controllerCookie=controller.cookie;
 ack.pid=controller.pid; ack.created=controller.created; ack.cookie=controller.cookie;
 if(!Send(r.keeper.value,r.stop.value,ack)) return false;
 Packet delivery;
 if(!Transfer(r.keeper.value,r.stop.value,delivery,false)||delivery.op!=Op::Delivered||
  delivery.epoch!=r.epoch||delivery.pid!=controller.pid||delivery.created!=controller.created||
  delivery.cookie!=controller.cookie||!delivery.handle||!Send(r.controller.value,r.stop.value,delivery)) return false;
 Packet challenge; challenge.op=Op::Challenge; challenge.epoch=r.epoch;
 challenge.brokerPid=GetCurrentProcessId(); challenge.brokerCreated=r.created;
 if(!Random(challenge.nonce.data(),32)||!Send(r.controller.value,r.stop.value,challenge)) return false;
 Packet proof;
 if(!Transfer(r.controller.value,r.stop.value,proof,false)||proof.op!=Op::Proof||proof.sequence!=1||
  proof.epoch!=r.epoch||proof.nonce!=challenge.nonce||proof.pid!=controller.pid||
  proof.created!=controller.created||proof.cookie!=controller.cookie||
  proof.brokerPid!=GetCurrentProcessId()||proof.brokerCreated!=r.created||
  proof.actor!=TokenIdentity(r.controllerToken)||proof.peer!=TokenIdentity(r.ownToken)) return false;
 const auto received=proof.proof; proof.proof.fill(0); Hash expected{};
 if(!Mac(r.key,&proof,sizeof(proof),expected)||!EqualMac(received,expected)||
  !PeerCurrent(r.keeper.value,true,r.bootstrapPeer,r.bootstrapToken)||
  !PeerCurrent(r.controller.value,true,r.controllerPeer,r.controllerToken)) return false;
 proof.op=Op::Admitted; proof.proof.fill(0);
 if(!Mac(r.key,&proof,sizeof(proof),proof.proof)||!Send(r.controller.value,r.stop.value,proof)) return false;
 Packet confirmed;
 if(!Transfer(r.controller.value,r.stop.value,confirmed,false)||confirmed.op!=Op::Ack||
  confirmed.epoch!=proof.epoch||confirmed.sequence!=proof.sequence||confirmed.pid!=proof.pid||
  confirmed.created!=proof.created||confirmed.cookie!=proof.cookie||
  confirmed.brokerPid!=proof.brokerPid||confirmed.brokerCreated!=proof.brokerCreated||
  confirmed.nonce!=proof.nonce||confirmed.peerNonce!=proof.peerNonce||
  confirmed.actor!=proof.actor||confirmed.peer!=proof.peer) return false;
 const auto ackMac=confirmed.proof;confirmed.proof.fill(0);
 if(!Mac(r.key,&confirmed,sizeof(confirmed),expected)||!EqualMac(ackMac,expected)||
  !Send(r.keeper.value,r.stop.value,proof)) return false;
 Packet seal;
 if(!Transfer(r.keeper.value,r.stop.value,seal,false)||seal.op!=Op::SealAck||
  seal.epoch!=r.epoch||seal.sequence!=1||seal.pid!=keeperPid||seal.created!=keeperCreated||
  seal.cookie!=keeperCookie||seal.brokerPid!=GetCurrentProcessId()||seal.brokerCreated!=r.created||
  seal.nonce!=proof.nonce||seal.peerNonce!=proof.peerNonce||
  seal.actor!=TokenIdentity(r.bootstrapToken)||seal.peer!=TokenIdentity(r.ownToken)) return false;
 const auto sealMac=seal.proof;seal.proof.fill(0);
 if(!Mac(r.key,&seal,sizeof(seal),expected)||!EqualMac(sealMac,expected)||
  !PeerCurrent(r.keeper.value,true,r.bootstrapPeer,r.bootstrapToken)||
  !PeerCurrent(r.controller.value,true,r.controllerPeer,r.controllerToken)||!r.pins->Current()||
  !NoJob(r.own.value)||!ServiceConfiguration(r.service,GetCurrentProcessId(),r.bootstrapToken.account)||
  !OwnedServiceSecurity(r.service,r.bootstrapToken.account)) return false;
 r.admitted=true; r.sequence=1;
 if(!boundary->CurrentOwn()) return false;
 auto admission=std::shared_ptr<BrokerAdmission>(new BrokerAdmission);
 admission->boundary_=boundary; admission->noJob_=r.noJob; admission->pins_=r.pins->files_;
 r.helperAnchor=ipc::ii::anchor(HelperPipe,ipc::ii::Channel::Control,principals);
 r.helper=ipc::ii::instance(HelperPipe,ipc::ii::Channel::Control,principals);
 Packet helper;
 if(!r.helperAnchor||!r.helper||!admission->CurrentOwn()||
  !FixedGuestBrokerSource::StartHelperOwn(admission,r.child,r.childObservation)||
  !ipc::ii::connect(r.helper.value,r.stop.value,30000)||
  !Transfer(r.helper.value,r.stop.value,helper,false)||
  !ipc::ii::clientEvidence(r.helper.value,r.helperToken,r.helperPeer)||
  !FixedGuestBrokerSource::ExactHelperOwn(r.child,r.helperPeer.process.value,r.helperPeer.pid,
   Creation(r.helperPeer.process.value))||!NoJob(r.helperPeer.process.value)||!admission->CurrentOwn()) return false;
 if(helper.op!=Op::HelperBound||
  helper.pid!=r.helperPeer.pid||helper.created!=Creation(r.helperPeer.process.value)) return false;
 helper.op=Op::Admitted; helper.epoch=r.epoch;
 // Metadata de identidad OS/pins; no secreto, ni concede un proceso distinto.
 std::memcpy(helper.pins.data(),r.pins->hashes_.data(),helper.pins.size());
 const auto owner=native::sidString(r.bootstrapToken.account);
 if(owner.size()>=helper.text.size()) return false;
 std::copy(owner.begin(),owner.end(),helper.text.begin());
 if(!Send(r.helper.value,r.stop.value,helper)) return false;
 r.helperBound=true;
 ReportState(SERVICE_RUNNING);
 while(boundary->CurrentOwn()&&PeerCurrent(r.helper.value,true,r.helperPeer,r.helperToken)&&
  FixedGuestBrokerSource::ExactHelperOwn(r.child,r.helperPeer.process.value,r.helperPeer.pid,Creation(r.helperPeer.process.value))) {
  DWORD available=0;
  if(!PeekNamedPipe(r.helper.value,nullptr,0,nullptr,&available,nullptr)) break;
  if(available>=sizeof(Packet)) {
   Packet closing;
   if(!Transfer(r.helper.value,r.stop.value,closing,false,1000)||closing.op!=Op::Close) break;
   r.helperBound=false; break;
  }
  if(!PeekNamedPipe(r.keeper.value,nullptr,0,nullptr,&available,nullptr)||
   !PeekNamedPipe(r.controller.value,nullptr,0,nullptr,&available,nullptr)) break;
  if(WaitForSingleObject(r.stop.value,50)!=WAIT_TIMEOUT) break;
 }
 r.revoked=true; ReportState(SERVICE_STOP_PENDING); SetEvent(r.stop.value);
 if(r.childObservation&&r.childObservation->CloseOwn().state!=GuestNoJobObserver::State::Closed) return false;
 if(r.child&&r.child->CloseOwn().state!=OwnedSuspendedProcess::State::Closed) return false;
 if(r.noJob&&r.noJob->CloseOwn().state!=GuestNoJobObserver::State::Closed) return false;
 if(r.view) { if(!UnmapViewOfFile(r.view)) return false; r.view=nullptr; }
 SecureZeroMemory(r.key.data(),r.key.size());
 r.section.reset(); r.helper.reset(); r.controller.reset(); r.keeper.reset();
 r.helperAnchor.reset(); r.controllerAnchor.reset(); r.keeperAnchor.reset();
 if(!r.pins->Close()) return false;
 if(r.service) { if(!CloseServiceHandle(r.service)) return false; r.service=nullptr; }
 if(r.manager) { if(!CloseServiceHandle(r.manager)) return false; r.manager=nullptr; }
 serviceStop=nullptr; return true;
}
void WINAPI GuestBrokerBoundary::ServiceMainOwn(DWORD argc,wchar_t** argv) {
 statusHandle=RegisterServiceCtrlHandlerW(ServiceName,ServiceControl);
 if(!statusHandle) return;
 ReportState(SERVICE_START_PENDING);
 bool ok=false; std::uint64_t pid=0,made=0,cookie=0;
 try {
  if(argc==4&&argv&&Number(argv[1],pid)&&pid<=MAXDWORD&&Number(argv[2],made)&&Number(argv[3],cookie))
   ok=RunBrokerOwn(static_cast<DWORD>(pid),made,cookie);
 } catch(...) { ok=false; }
 ReportState(SERVICE_STOPPED,ok?NO_ERROR:ERROR_PROCESS_ABORTED);
}
int GuestBrokerBoundary::ServiceOwn() {
 SERVICE_TABLE_ENTRYW table[]={{const_cast<wchar_t*>(ServiceName),ServiceMainOwn},{nullptr,nullptr}};
 return StartServiceCtrlDispatcherW(table)?0:2;
}
std::shared_ptr<BrokerAdmission> GuestBrokerBoundary::AdmitHelperOwn() {
 auto boundary=std::shared_ptr<GuestBrokerBoundary>(new GuestBrokerBoundary);
 { std::lock_guard<std::mutex> lock(boundaryMutex); boundaries.push_back(boundary); }
 boundary->resources_=std::make_shared<Resources>(); auto& r=*boundary->resources_;
 r.helperRole=true; r.tid=GetCurrentThreadId();
 r.stop.reset(CreateEventW(nullptr,TRUE,FALSE,nullptr));
 HANDLE raw=nullptr;
 if(!r.stop||!DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(),GetCurrentProcess(),&raw,
  PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,0)) return {};
 r.own.reset(raw); r.created=Creation(raw);
 r.helper=OpenPipe(HelperPipe,r.stop.value);
 if(!r.helper||!ipc::ii::serverEvidence(r.helper.value,r.brokerPeer)||
  r.brokerPeer.image!=Paths[0]||!NoJob(r.brokerPeer.process.value)||
  !Token(r.brokerPeer.process.value,r.brokerToken)||!Token(r.own.value,r.ownToken)||!NoJob(r.own.value)) return {};
 Packet hello; hello.op=Op::HelperBound; hello.pid=GetCurrentProcessId(); hello.created=r.created;
 if(!Send(r.helper.value,r.stop.value,hello)) return {};
 Packet response;
 if(!Transfer(r.helper.value,r.stop.value,response,false)||response.op!=Op::Admitted||
  response.pid!=GetCurrentProcessId()||response.created!=r.created||!response.epoch||
  response.text.back()!=0) return {};
 PSID owner=nullptr;
 if(!ConvertStringSidToSidW(response.text.data(),&owner)) return {};
 const auto ownerBytes=static_cast<BYTE*>(owner);
 r.bootstrapToken.account.assign(ownerBytes,ownerBytes+GetLengthSid(owner)); LocalFree(owner);
 r.manager=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
 if(!r.manager) return {};
 r.service=OpenServiceW(r.manager,ServiceName,SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS|READ_CONTROL);
 if(!r.service||!ServiceConfiguration(r.service,r.brokerPeer.pid,r.bootstrapToken.account)||
  !OwnedServiceSecurity(r.service,r.bootstrapToken.account)||!r.pins->Open(response.pins.data())) return {};
 r.noJob=FixedGuestBrokerSource::ObserveOwnNative();
 if(!r.noJob||r.noJob->InspectOwn().state!=GuestNoJobObserver::State::Observed) return {};
 r.epoch=response.epoch; r.admitted=true;
 auto admission=std::shared_ptr<BrokerAdmission>(new BrokerAdmission);
 admission->boundary_=boundary; admission->noJob_=r.noJob; admission->pins_=r.pins->files_;
 return admission->CurrentOwn()?admission:nullptr;
}
bool GuestBrokerBoundary::CloseHelperOwn(const std::shared_ptr<BrokerAdmission>& admission) {
 if(!admission||!admission->boundary_) return false;
 auto& r=*admission->boundary_->resources_;
 if(!r.helperRole) return false;
 Packet packet; packet.op=Op::Close; packet.epoch=r.epoch;
 Send(r.helper.value,nullptr,packet); r.revoked=true; SetEvent(r.stop.value);
 if(r.noJob&&r.noJob->CloseOwn().state!=GuestNoJobObserver::State::Closed) return false;
 if(!r.pins->Close()) return false;
 r.helper.reset();
 if(r.service) { if(!CloseServiceHandle(r.service)) return false; r.service=nullptr; }
 if(r.manager) { if(!CloseServiceHandle(r.manager)) return false; r.manager=nullptr; }
 return true;
}
}
