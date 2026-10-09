#define NOMINMAX
#include "policy.h"
#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include <aclapi.h>
#include <algorithm>
#include <set>
#include <stdexcept>

namespace gb {
namespace {
void put(Bytes& b,std::uint64_t n,std::size_t width){auto v=integer(n,width);b.insert(b.end(),v.begin(),v.end());}
void put(Bytes& b,const Id& id){b.insert(b.end(),id.begin(),id.end());}
struct Reader {
    const Bytes& b;std::size_t p=0;bool ok=true;
    Bytes take(std::size_t n){if(n>b.size()-p){ok=false;return{};}Bytes x(b.begin()+p,b.begin()+p+n);p+=n;return x;}
    std::uint64_t n(std::size_t width){auto x=take(width);return number({Tag::Text,true,x});}
    Id id(){Id x{};auto v=take(16);if(ok)std::copy(v.begin(),v.end(),x.begin());return x;}
};
bool blobValid(const Bytes& blob) {
    if(blob.empty()||blob.size()>32768||(blob.size()%2)!=0)return false;
    // El APP_ID de ALE está en UTF-16 nativo; el store no convierte rutas.
    return blob.size()>=4 && blob[0]=='\\' && blob[1]==0;
}
struct Handle {
    HANDLE h=INVALID_HANDLE_VALUE;
    ~Handle(){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);}
};
bool noReparse(const std::filesystem::path& p,bool allowMissing){
    auto a=GetFileAttributesW(p.c_str());
    if(a==INVALID_FILE_ATTRIBUTES)return allowMissing&&GetLastError()==ERROR_FILE_NOT_FOUND;
    return (a&FILE_ATTRIBUTE_REPARSE_POINT)==0;
}
bool objectShape(HANDLE file,bool directory){
    FILE_ATTRIBUTE_TAG_INFO info{};
    return GetFileInformationByHandleEx(file,FileAttributeTagInfo,&info,sizeof(info))&&
        !(info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)&&bool(info.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)==directory;
}
bool trustedSecurity(HANDLE object,bool ancestor){
    BYTE system[SECURITY_MAX_SID_SIZE]{},admin[SECURITY_MAX_SID_SIZE]{};DWORD sn=sizeof(system),an=sizeof(admin);
    if(!CreateWellKnownSid(WinLocalSystemSid,nullptr,system,&sn)||!CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,admin,&an))return false;
    // TrustedInstaller es autoridad de Windows sobre ancestros, no dueño del store.
    PSID installer=nullptr;if(ancestor&&!ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",&installer))return false;
    auto trusted=[&](PSID sid){return sid&&IsValidSid(sid)&&(EqualSid(sid,system)||EqualSid(sid,admin)||(ancestor&&EqualSid(sid,installer)));};
    PSECURITY_DESCRIPTOR sd=nullptr;PSID owner=nullptr;PACL acl=nullptr;
    auto error=GetSecurityInfo(object,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&sd);
    SECURITY_DESCRIPTOR_CONTROL control=0;DWORD revision=0;bool ok=error==ERROR_SUCCESS&&trusted(owner)&&acl&&IsValidAcl(acl)&&
        GetSecurityDescriptorControl(sd,&control,&revision)&&(ancestor||(control&SE_DACL_PROTECTED));
    bool fullSystem=false,fullAdmin=false;
    GENERIC_MAPPING mapping{FILE_GENERIC_READ,FILE_GENERIC_WRITE,FILE_GENERIC_EXECUTE,FILE_ALL_ACCESS};
    constexpr DWORD unsafeAncestor=FILE_WRITE_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|FILE_DELETE_CHILD|DELETE|WRITE_DAC|WRITE_OWNER;
    for(DWORD i=0;ok&&i<acl->AceCount;++i){void* raw=nullptr;if(!GetAce(acl,i,&raw)){ok=false;break;}auto header=static_cast<ACE_HEADER*>(raw);if(header->AceFlags&INHERIT_ONLY_ACE)continue;
        if(header->AceType==ACCESS_DENIED_ACE_TYPE){if(!ancestor)ok=false;continue;}
        if(header->AceType!=ACCESS_ALLOWED_ACE_TYPE){ok=false;break;}
        auto ace=static_cast<ACCESS_ALLOWED_ACE*>(raw);PSID sid=&ace->SidStart;DWORD mask=ace->Mask;
        if(!IsValidSid(sid)||(mask&MAXIMUM_ALLOWED)){ok=false;break;}MapGenericMask(&mask,&mapping);
        if(!trusted(sid)&&(!ancestor||(mask&unsafeAncestor))){ok=false;break;}
        if((mask&FILE_ALL_ACCESS)==FILE_ALL_ACCESS){fullSystem|=EqualSid(sid,system)!=FALSE;fullAdmin|=EqualSid(sid,admin)!=FALSE;}
    }
    if(!ancestor)ok=ok&&fullSystem&&fullAdmin;
    if(sd)LocalFree(sd);if(installer)LocalFree(installer);return ok;
}
bool trustedFile(HANDLE file,bool fixture){return objectShape(file,false)&&(fixture||trustedSecurity(file,false));}
bool existingFile(const std::filesystem::path& path,bool fixture,bool& exists){
    Handle file;file.h=CreateFileW(path.c_str(),READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(file.h==INVALID_HANDLE_VALUE){exists=false;return GetLastError()==ERROR_FILE_NOT_FOUND;}
    exists=true;return trustedFile(file.h,fixture);
}
bool flushCommitted(const std::filesystem::path& path,bool fixture){
    Handle file;file.h=CreateFileW(path.c_str(),GENERIC_WRITE|READ_CONTROL|FILE_READ_ATTRIBUTES,0,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,nullptr);
    return file.h!=INVALID_HANDLE_VALUE&&trustedFile(file.h,fixture)&&FlushFileBuffers(file.h);
}
}
Id randomId(){Id id{};if(BCryptGenRandom(nullptr,id.data(),16,BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)throw std::runtime_error("No se pudo crear identidad de sesion");return id;}
Digest sha256(const Bytes& b){Digest d{};if(BCryptHash(BCRYPT_SHA256_ALG_HANDLE,nullptr,0,const_cast<PUCHAR>(b.data()),static_cast<ULONG>(b.size()),d.data(),32)<0)throw std::runtime_error("No se pudo calcular integridad");return d;}
bool equalRules(const std::vector<Rule>& a,const std::vector<Rule>& b){
    if(a.size()!=b.size())return false;
    for(std::size_t i=0;i<a.size();++i)if(a[i].id!=b[i].id||a[i].selector!=b[i].selector||a[i].decision!=b[i].decision||a[i].appId!=b[i].appId)return false;
    return true;
}
Bytes serializeSnapshot(const Snapshot& s){
    if(s.rules.size()>MaxRules)throw std::runtime_error("Capacidad de reglas excedida");
    Bytes b={'G','B','P','1'};put(b,1,2);put(b,0,2);put(b,s.desired,8);put(b,s.effective,8);put(b,s.effectiveKnown?1:0,1);put(b,static_cast<unsigned>(s.state),1);put(b,0,2);put(b,s.command);b.insert(b.end(),s.commandDigest.begin(),s.commandDigest.end());put(b,s.rules.size(),4);
    for(const auto& r:s.rules){if(!blobValid(r.appId))throw std::runtime_error("Identidad nativa invalida");put(b,r.id);put(b,r.selector);put(b,r.decision,1);put(b,r.appId.size(),4);b.insert(b.end(),r.appId.begin(),r.appId.end());if(b.size()>MaxStoreBytes-32)throw std::runtime_error("Capacidad de store excedida");}
    auto d=sha256(b);b.insert(b.end(),d.begin(),d.end());return b;
}
bool parseSnapshot(const Bytes& input,Snapshot& out){
    if(input.size()<112||input.size()>MaxStoreBytes)return false;
    Bytes body(input.begin(),input.end()-32);auto d=sha256(body);if(!std::equal(d.begin(),d.end(),input.end()-32))return false;
    Reader r{body};if(r.take(4)!=Bytes({'G','B','P','1'})||r.n(2)!=1||r.n(2)!=0)return false;
    Snapshot s;s.desired=r.n(8);s.effective=r.n(8);auto known=r.n(1),state=r.n(1);
    if(known>1||state<1||state>5||r.n(2)!=0)return false;
    s.effectiveKnown=known==1;s.state=static_cast<State>(state);s.command=r.id();auto hash=r.take(32);if(!r.ok)return false;std::copy(hash.begin(),hash.end(),s.commandDigest.begin());
    auto count=r.n(4);if(count>MaxRules||(!s.effectiveKnown&&s.effective!=0)||s.effective>s.desired)return false;
    std::set<Id> ids,selectors;
    for(std::size_t i=0;i<count;++i){Rule x;x.id=r.id();x.selector=r.id();auto decision=r.n(1),n=r.n(4);if(!r.ok||n>32768||n>body.size()-r.p||(decision!=1&&decision!=2))return false;x.decision=static_cast<std::uint8_t>(decision);x.appId=r.take(static_cast<std::size_t>(n));if(zero(x.id)||zero(x.selector)||!ids.insert(x.id).second||!selectors.insert(x.selector).second||!blobValid(x.appId))return false;s.rules.push_back(std::move(x));}
    if(!r.ok||r.p!=body.size())return false;out=std::move(s);return true;
}
PolicyStore::PolicyStore(std::filesystem::path root,bool fixture):root_(std::move(root)),fixture_(fixture){}
PolicyStore::~PolicyStore(){for(auto handle:directoryHandles_)CloseHandle(handle);}
bool PolicyStore::prepareDirectory(){
    auto native=root_.native();if(!root_.is_absolute()||root_!=root_.lexically_normal()||native.size()<3||native[1]!=L':'||native[2]!=L'\\'||GetDriveTypeW(native.substr(0,3).c_str())!=DRIVE_FIXED)return false;
    if(!directoryHandles_.empty()){
        for(std::size_t i=0;i<directoryHandles_.size();++i)if(!objectShape(directoryHandles_[i],true)||!trustedSecurity(directoryHandles_[i],i+1<directoryHandles_.size()))return false;
        return true;
    }
    std::vector<std::filesystem::path> ancestors;
    for(auto p=root_;!p.empty();p=p.parent_path()){ancestors.push_back(p);if(p==p.parent_path())break;}
    if(!fixture_){
        // Ancestros adquiridos de raiz a hoja y retenidos SIN SHARE_DELETE: no sustitucion.
        auto fail=[&](){for(auto handle:directoryHandles_)CloseHandle(handle);directoryHandles_.clear();return false;};
        for(auto p=ancestors.rbegin();p!=ancestors.rend();++p){bool leaf=std::next(p)==ancestors.rend();
            Handle directory;directory.h=CreateFileW(p->c_str(),READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
            if(directory.h==INVALID_HANDLE_VALUE){
                auto openError=GetLastError();if(!leaf||(openError!=ERROR_FILE_NOT_FOUND&&openError!=ERROR_PATH_NOT_FOUND))return fail();
                PSECURITY_DESCRIPTOR sd=nullptr;if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;SY)(A;;FA;;;BA)",SDDL_REVISION_1,&sd,nullptr))return fail();
                SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};bool created=CreateDirectoryW(root_.c_str(),&sa)!=FALSE;auto createError=GetLastError();LocalFree(sd);if(!created&&createError!=ERROR_ALREADY_EXISTS)return fail();
                directory.h=CreateFileW(root_.c_str(),READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
            }
            if(directory.h==INVALID_HANDLE_VALUE||!objectShape(directory.h,true)||!trustedSecurity(directory.h,!leaf))return fail();
            directoryHandles_.push_back(directory.h);directory.h=INVALID_HANDLE_VALUE;
        }
        return !directoryHandles_.empty();
    }
    // Fixture local: conserva pruebas funcionales, nunca acredita seguridad de produccion.
    for(auto p=ancestors.rbegin();p!=ancestors.rend();++p){if(!noReparse(*p,true))return false;}
    bool ok=CreateDirectoryW(root_.c_str(),nullptr)||GetLastError()==ERROR_ALREADY_EXISTS;
    if(!ok||!noReparse(root_,false))return false;
    return true;
}
bool PolicyStore::load(Snapshot& out,bool& exists){
    exists=false;if(!prepareDirectory())return false;auto path=root_/L"policy.bin";
    Handle file;file.h=CreateFileW(path.c_str(),GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(file.h==INVALID_HANDLE_VALUE){if(GetLastError()==ERROR_FILE_NOT_FOUND)return true;return false;}
    exists=true;if(!trustedFile(file.h,fixture_))return false;
    LARGE_INTEGER size{};if(!GetFileSizeEx(file.h,&size)||size.QuadPart<0||size.QuadPart>MaxStoreBytes)return false;
    Bytes b(static_cast<std::size_t>(size.QuadPart));DWORD read=0;if(!ReadFile(file.h,b.data(),static_cast<DWORD>(b.size()),&read,nullptr)||read!=b.size())return false;return parseSnapshot(b,out);
}
bool PolicyStore::save(const Snapshot& s){
    if(!prepareDirectory())return false;Bytes b;try{b=serializeSnapshot(s);}catch(...){return false;}
    auto final=root_/L"policy.bin",backup=root_/L"policy.previous.bin",temp=root_/std::filesystem::path(L"prepared-"+std::wstring(32,L'0'));
    auto id=hex(randomId());temp=root_/std::filesystem::path(L"prepared-"+std::wstring(id.begin(),id.end())+L".bin");
    bool finalExists=false,backupExists=false;if(!existingFile(final,fixture_,finalExists)||!existingFile(backup,fixture_,backupExists))return false;
    PSECURITY_DESCRIPTOR sd=nullptr;if(!fixture_&&!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;SY)(A;;FA;;;BA)",SDDL_REVISION_1,&sd,nullptr))return false;SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};
    Handle file;file.h=CreateFileW(temp.c_str(),GENERIC_WRITE|READ_CONTROL|FILE_READ_ATTRIBUTES,0,fixture_?nullptr:&sa,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,nullptr);if(sd)LocalFree(sd);if(file.h==INVALID_HANDLE_VALUE||!trustedFile(file.h,fixture_))return false;
    DWORD written=0;bool ok=WriteFile(file.h,b.data(),static_cast<DWORD>(b.size()),&written,nullptr)&&written==b.size()&&FlushFileBuffers(file.h);CloseHandle(file.h);file.h=INVALID_HANDLE_VALUE;
    if(!ok)return false;
    if(!finalExists)return MoveFileExW(temp.c_str(),final.c_str(),MOVEFILE_WRITE_THROUGH)&&flushCommitted(final,fixture_);
    return ReplaceFileW(final.c_str(),temp.c_str(),backup.c_str(),0,nullptr,nullptr)&&flushCommitted(final,fixture_);
}
Id SelectorRegistry::registerNative(const Bytes& blob){
    if(!blobValid(blob))return{};auto digest=sha256(blob);Id id{};std::copy_n(digest.begin(),16,id.begin());std::lock_guard<std::mutex> guard(mutex_);if(native_.size()>=MaxRules&&!native_.count(id))return{};auto p=native_.find(id);if(p!=native_.end()&&p->second!=blob)return{};native_[id]=blob;return id;
}
std::optional<Bytes> SelectorRegistry::lookup(const Id& id)const{std::lock_guard<std::mutex> guard(mutex_);auto p=native_.find(id);if(p==native_.end())return std::nullopt;return p->second;}
Coordinator::Coordinator(PolicyStore& s,Backend& b,SelectorRegistry& r):store_(s),backend_(b),registry_(r){}
bool Coordinator::initialize(){
    std::lock_guard<std::mutex> guard(mutex_);bool exists=false;
    if(!store_.load(snapshot_,exists)){recovery_=true;return false;}loaded_=true;
    if(!backend_.available())return true;
    if(!exists){if(!snapshot_.rules.empty()||!store_.save(snapshot_)||!backend_.apply({},0)||!backend_.matches({},0)){recovery_=true;return false;}snapshot_.effectiveKnown=true;snapshot_.state=State::Applied;if(!store_.save(snapshot_)){recovery_=true;return false;}return true;}
    if(!backend_.matches(snapshot_.rules,snapshot_.desired)){snapshot_.effectiveKnown=false;snapshot_.effective=0;recovery_=true;return false;}
    snapshot_.effective=snapshot_.desired;snapshot_.effectiveKnown=true;snapshot_.state=State::Applied;
    if(!store_.save(snapshot_)){recovery_=true;return false;}return true;
}
Status Coordinator::statusUnlocked(){
    const bool connected=backend_.available();
    if(connected&&snapshot_.effectiveKnown&&!backend_.matches(snapshot_.rules,snapshot_.effective)){snapshot_.effectiveKnown=false;snapshot_.effective=0;recovery_=true;}
    Status s;s.desired=snapshot_.desired;s.effectiveKnown=snapshot_.effectiveKnown&&connected;s.effective=s.effectiveKnown?snapshot_.effective:0;
    if(recovery_)s.state=EngineState::RecoveryRequired;
    else if(loaded_&&connected){s.state=EngineState::ReadyUnvalidated;s.capabilities|=PathPermanentRule|BlockRetry|RuleRevoke|Ipv4Ale|Ipv6Ale;}
    return s;
}
Status Coordinator::status(){std::lock_guard<std::mutex> guard(mutex_);return statusUnlocked();}
Outcome Coordinator::mutate(const Frame& f,bool admin){
    std::lock_guard<std::mutex> guard(mutex_);auto outcome=[&](State state,Error e){
        auto actual=statusUnlocked();
        // Una segunda lectura puede detectar drift entre commit/guardado y el ACK.
        if((state==State::Applied||state==State::AppliedUnrecorded)&&(!actual.effectiveKnown||actual.effective!=actual.desired))return Outcome{State::RecoveryRequired,e==Error::Ok?Error::RecoveryRequired:e,actual};
        return Outcome{state,e,actual};
    };
    if(!admin)return outcome(State::Failed,Error::Unauthorized);
    if(wire::validate(f)!=Error::Ok)return outcome(State::Failed,Error::Malformed);
    if(f.type!=Type::CreateRule&&f.type!=Type::RevokeRule)return outcome(State::Failed,Error::Unsupported);
    if(recovery_||!loaded_)return outcome(State::RecoveryRequired,Error::RecoveryRequired);
    if(!backend_.available())return outcome(State::Failed,Error::BackendUnavailable);
    if(!backend_.matches(snapshot_.rules,snapshot_.desired)){snapshot_.effectiveKnown=false;snapshot_.effective=0;recovery_=true;return outcome(State::RecoveryRequired,Error::RecoveryRequired);}
    Frame canonical=f;canonical.connection={};canonical.sequence=2;canonical.connection[0]=1;
    Bytes request;wire::encode(canonical,request);auto digest=sha256(request);
    if(snapshot_.command==f.correlation){if(snapshot_.commandDigest!=digest)return outcome(State::Failed,Error::Conflict);return outcome(snapshot_.state,snapshot_.state==State::Applied?Error::Ok:Error::RecoveryRequired);}
    if(get(f,Tag::ExpectedDesiredRev)!=snapshot_.desired)return outcome(State::Failed,Error::Stale);
    if(snapshot_.desired==UINT64_MAX)return outcome(State::Failed,Error::Capacity);
    auto next=snapshot_;next.desired++;next.command=f.correlation;next.commandDigest=digest;next.state=State::Prepared;
    if(f.type==Type::CreateRule){auto selector=idValue(f,Tag::SelectorId);auto blob=registry_.lookup(selector);if(!blob)return outcome(State::Failed,Error::IdentityUnavailable);
        if(next.rules.size()>=MaxRules)return outcome(State::Failed,Error::Capacity);
        if(std::any_of(next.rules.begin(),next.rules.end(),[&](const Rule& r){return r.id==f.correlation||r.selector==selector;}))return outcome(State::Failed,Error::Conflict);
        next.rules.push_back({f.correlation,selector,static_cast<std::uint8_t>(get(f,Tag::Decision)),*blob});
    }else{auto id=idValue(f,Tag::RuleId);auto p=std::find_if(next.rules.begin(),next.rules.end(),[&](auto& r){return r.id==id;});if(p==next.rules.end())return outcome(State::Failed,Error::Stale);next.rules.erase(p);}
    if(!store_.save(next)){recovery_=true;return outcome(State::Failed,Error::StoreFailure);}
    snapshot_=next;
    if(!backend_.apply(next.rules,next.desired)){snapshot_.state=State::Failed;snapshot_.effectiveKnown=false;snapshot_.effective=0;recovery_=true;store_.save(snapshot_);return outcome(State::Failed,Error::WfpFailure);}
    if(!backend_.matches(next.rules,next.desired)){snapshot_.state=State::RecoveryRequired;snapshot_.effectiveKnown=false;snapshot_.effective=0;recovery_=true;store_.save(snapshot_);return outcome(State::RecoveryRequired,Error::WfpFailure);}
    snapshot_.effective=next.desired;snapshot_.effectiveKnown=true;snapshot_.state=State::Applied;
    if(!store_.save(snapshot_)){snapshot_.state=State::AppliedUnrecorded;recovery_=true;return outcome(State::AppliedUnrecorded,Error::StoreFailure);}
    return outcome(State::Applied,Error::Ok);
}
}
