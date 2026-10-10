#include "scopes_v.h"
#include "../common/token_ii_win.h"
#include <sddl.h>
#include <algorithm>
#include <cstring>
#include <set>
namespace gb::decisions {
namespace {
constexpr std::size_t MaxBytes = 4 * 1024 * 1024, MaxEntries = 128;
void put(Bytes &b, std::uint64_t n, unsigned width) {
    for (unsigned i = 0; i < width; ++i) b.push_back(std::uint8_t(n >> (8*i)));
}
void blob(Bytes &b, const Bytes &v) { put(b,v.size(),4); b.insert(b.end(),v.begin(),v.end()); }
template<class T> void raw(Bytes &b,const T &v) {
    auto p = reinterpret_cast<const std::uint8_t *>(&v); b.insert(b.end(),p,p+sizeof(v));
}
struct Reader {
    const Bytes &b; std::size_t at = 0;
    bool take(void *out,std::size_t n) {
        if (n > b.size()-at) return false;
        if (n) std::memcpy(out,b.data()+at,n);
        at += n; return true;
    }
    bool number(std::uint64_t &out,unsigned width) {
        if (width > b.size()-at) return false;
        out=0; for (unsigned i=0;i<width;++i) out |= std::uint64_t(b[at++]) << (8*i);
        return true;
    }
    bool bytes(Bytes &out,std::size_t cap) {
        std::uint64_t n=0;
        if (!number(n,4) || n>cap || n>b.size()-at) return false;
        out.assign(b.begin()+at,b.begin()+at+std::size_t(n)); at+=std::size_t(n); return true;
    }
};
bool valid(const ScopedEntry &e) {
    Frame f; const auto &d=e.kernel.decision;
    return (e.format==1 || e.format==2) && (e.format==1 || e.image.nFileIndexHigh || e.image.nFileIndexLow) &&
        !zero(e.command) && !zero(e.epoch) && !zero(e.boot) && e.pid && e.created &&
        e.account.size()>=8 && e.account.size()<=68 && e.account[0]==1 && e.account[1]<=15 &&
        e.account.size()==8u+4u*e.account[1] && e.logon.size()>=8 && e.logon.size()<=68 &&
        e.logon[0]==1 && e.logon[1]<=15 && e.logon.size()==8u+4u*e.logon[1] &&
        e.payload.size()<=1024 && decode(e.payload,f)==Error::Ok &&
        f.minor==3 && f.type==Type::CommitFuturePolicy && f.correlation==e.command &&
        idValue(f,Tag::ServiceEpoch)==e.epoch &&
        d.version==GB_CLASSIFIER_VERSION && d.bytes==sizeof(d) && d.session && d.cause && d.revision &&
        std::equal(e.command.begin(),e.command.end(),d.command) && !d.reserved &&
        d.scope==get(f,Tag::ScopeKind) && d.action==get(f,Tag::Decision) &&
        d.durationMs==get(f,Tag::ScopeDurationMs) && d.scope>=3 && d.scope<=5 &&
        !e.kernel.reserved && e.kernel.applied<=1 && e.kernel.current<=1 &&
        (e.state==State::Prepared ? !e.kernel.applied :
            e.state==State::Applied && e.kernel.applied==1 && e.kernel.observedAt &&
            e.kernel.state>=GB_SCOPE_APPLIED && e.kernel.state<=GB_SCOPE_CLOSED);
}
bool encode(const std::vector<ScopedEntry> &rows,std::uint64_t revision,Bytes &b) {
    if (rows.size()>MaxEntries) return false;
    const auto format=rows.empty() ? 1u : rows.front().format;
    b={'G','B','T','5'}; put(b,format,4); put(b,revision,8); put(b,rows.size(),4);
    std::set<Id> seen;
    for (const auto &e:rows) {
        if (!valid(e) || e.format!=format || !seen.insert(e.command).second) return false;
        raw(b,e.command); raw(b,e.epoch); raw(b,e.boot); put(b,e.pid,4); put(b,e.session,4);
        put(b,e.created,8); put(b,unsigned(e.state),1); raw(b,e.kernel);
        if(format==2) {
            put(b,e.image.dwVolumeSerialNumber,4); put(b,e.image.nFileIndexHigh,4); put(b,e.image.nFileIndexLow,4);
        }
        blob(b,e.account); blob(b,e.logon); blob(b,e.payload);
        if (b.size()>MaxBytes-32) return false;
    }
    const auto hash=native::digest(b); if (hash==Digest{}) return false;
    b.insert(b.end(),hash.begin(),hash.end()); return true;
}
bool decodeJournal(const Bytes &input,std::vector<ScopedEntry> &rows,std::uint64_t &revision) {
    if (input.size()<52 || input.size()>MaxBytes) return false;
    Bytes b(input.begin(),input.end()-32); auto hash=native::digest(b);
    if (hash==Digest{} || !std::equal(hash.begin(),hash.end(),input.end()-32)) return false;
    Reader r{b}; char magic[4]; std::uint64_t version=0,count=0; std::set<Id> seen;
    if (!r.take(magic,4) || std::memcmp(magic,"GBT5",4) || !r.number(version,4) || (version!=1 && version!=2) ||
        !r.number(revision,8) || !r.number(count,4) || count>MaxEntries) return false;
    rows.clear();
    std::uint64_t last=0;
    for (std::uint64_t i=0;i<count;++i) {
        ScopedEntry e; std::uint64_t n=0; e.format=std::uint32_t(version);
        if (!r.take(e.command.data(),16) || !r.take(e.epoch.data(),16) || !r.take(e.boot.data(),16) ||
            !r.number(n,4)) return false;
        e.pid=std::uint32_t(n); if (!r.number(n,4)) return false; e.session=std::uint32_t(n);
        if (!r.number(e.created,8) || !r.number(n,1)) return false; e.state=State(n);
        if (!r.take(&e.kernel,sizeof(e.kernel))) return false;
        if(version==2) {
            if(!r.number(n,4)) return false; e.image.dwVolumeSerialNumber=DWORD(n);
            if(!r.number(n,4)) return false; e.image.nFileIndexHigh=DWORD(n);
            if(!r.number(n,4)) return false; e.image.nFileIndexLow=DWORD(n);
        }
        if (!r.bytes(e.account,68) || !r.bytes(e.logon,68) ||
            !r.bytes(e.payload,1024) || !valid(e) || !seen.insert(e.command).second ||
            e.kernel.decision.revision<=last) return false;
        last=e.kernel.decision.revision; rows.push_back(std::move(e));
    }
    return r.at==b.size() && revision==last;
}
bool encodeCounter(std::uint64_t revision,Bytes &out) {
    out={'G','B','C','6'};put(out,1,4);put(out,revision,8);put(out,0,8);
    const auto hash=native::digest(out);if(hash==Digest{})return false;
    out.insert(out.end(),hash.begin(),hash.end());return true;
}
bool decodeCounter(const Bytes &input,std::uint64_t &revision) {
    if(input.size()!=56)return false;
    Bytes b(input.begin(),input.end()-32);const auto hash=native::digest(b);
    if(hash==Digest{} || !std::equal(hash.begin(),hash.end(),input.end()-32))return false;
    Reader r{b};char magic[4];std::uint64_t version=0,reserved=0;
    return r.take(magic,4) && !std::memcmp(magic,"GBC6",4) && r.number(version,4) && version==1 &&
        r.number(revision,8) && r.number(reserved,8) && !reserved && r.at==b.size();
}
std::wstring commandLeaf(const Id &id) {
    const auto hex=wire::hex(id);return L"c-"+std::wstring(hex.begin(),hex.end())+L".bin";
}
struct NamespaceProbe {
    const std::filesystem::path &root;
    DWORD attributes(const std::wstring &leaf) {
        return GetFileAttributesW((root/leaf).c_str())!=INVALID_FILE_ATTRIBUTES ? ERROR_SUCCESS : GetLastError();
    }
    DWORD firstCommand() {
        // Sólo presencia de un resultado, incluidos backups; jamás adoptar ni enumerar historial.
        WIN32_FIND_DATAW data{};const auto handle=FindFirstFileW((root/L"c-*").c_str(),&data);
        if(handle!=INVALID_HANDLE_VALUE){FindClose(handle);return ERROR_SUCCESS;}
        return GetLastError();
    }
};
template<class Probe> bool missingBackup(Probe &probe,const std::wstring &leaf) {
    return probe.attributes(leaf+L".previous")==ERROR_FILE_NOT_FOUND;
}
template<class Probe> bool emptyCommands(Probe &probe) {
    return missingBackup(probe,L"scope-revision.bin") && probe.firstCommand()==ERROR_FILE_NOT_FOUND;
}
template<class Store> bool reserveCounter(Store &store,Bytes &counter,std::uint64_t &highwater,
    std::uint64_t revision,bool &uncertain) {
    if(uncertain || highwater==UINT64_MAX || revision!=highwater+1)return false;
    bool matches=false,exists=false;Bytes candidate;
    if(!store.compare(L"scope-revision.bin",counter.data(),counter.size(),matches,exists) || !matches || !exists ||
       !encodeCounter(revision,candidate) || !store.replace(L"scope-revision.bin",candidate,false) ||
       !store.compare(L"scope-revision.bin",candidate.data(),candidate.size(),matches,exists) || !matches || !exists) {
        uncertain=true;return false;
    }
    counter=std::move(candidate);highwater=revision;return true;
}
template<class Store> bool persistEntry(Store &store,const ScopedEntry &candidate,const Bytes &before,
    bool existed,bool &uncertain) {
    if(uncertain)return false;
    Bytes bytes;const auto leaf=commandLeaf(candidate.command);
    if(!encode({candidate},candidate.kernel.decision.revision,bytes) || bytes.size()>4096)return false;
    bool matches=false,exists=false;
    if(!store.compare(leaf.c_str(),before.data(),before.size(),matches,exists) || exists!=existed || (existed && !matches) ||
       !store.replace(leaf.c_str(),bytes,false) ||
       !store.compare(leaf.c_str(),bytes.data(),bytes.size(),matches,exists) || !exists || !matches) {
        uncertain=true;return false;
    }
    return true;
}
}
bool scopedActorMatches(const ScopedEntry &e,const Id &epoch,const Id &boot,std::uint64_t profile,
    DWORD pid,const FILETIME &created,const BY_HANDLE_FILE_INFORMATION &image,const native::TokenEvidence &identity) {
    Frame frame;
    return e.format==2 && e.epoch==epoch && e.boot==boot && decode(e.payload,frame)==Error::Ok &&
        get(frame,Tag::ProfileGeneration)==profile && e.pid==pid &&
        e.created==(std::uint64_t(created.dwLowDateTime)|(std::uint64_t(created.dwHighDateTime)<<32)) &&
        e.account==identity.account && e.logon==identity.logon && e.session==identity.session &&
        e.image.dwVolumeSerialNumber==image.dwVolumeSerialNumber && e.image.nFileIndexHigh==image.nFileIndexHigh &&
        e.image.nFileIndexLow==image.nFileIndexLow;
}
bool ScopedJournal::load() {
    std::lock_guard<std::mutex> lock(mutex_);return initialize();
}
bool ScopedJournal::initialize() {
    if (loaded_) return !uncertain_;
    if (lease_) return false;
    native::Handle token; HANDLE rawToken=nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&rawToken)) return false;
    token.reset(rawToken);
    if (!native::systemServiceToken(token.value) || !parent_.acquire()) return false;
    PSECURITY_DESCRIPTOR sd=nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)",
        SDDL_REVISION_1,&sd,nullptr)) return false;
    SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};
    const auto created=CreateDirectoryW(directory_.root().c_str(),&sa);
    const auto error=GetLastError(); LocalFree(sd);
    if ((!created && error!=ERROR_ALREADY_EXISTS) || !directory_.writerLease(lease_)) return false;
    Bytes b; bool exists=false;std::uint64_t legacyRevision=0;
    NamespaceProbe probe{directory_.root()};
    if (!directory_.read(L"scoped-decisions.bin",MaxBytes,b,exists) ||
        (exists && !decodeJournal(b,legacy_,legacyRevision))) return false;
    if(!exists && !missingBackup(probe,L"scoped-decisions.bin"))return false;
    for(const auto &e:legacy_)if(e.format!=1)return false;
    if(!directory_.read(L"scope-revision.bin",56,counter_,exists))return false;
    if(exists) {
        if(!decodeCounter(counter_,revision_) || revision_<legacyRevision)return false;
    } else {
        if(!emptyCommands(probe) || !encodeCounter(legacyRevision,counter_))return false;
        bool matches=false,present=false;
        if(!directory_.replace(L"scope-revision.bin",counter_,false) ||
           !directory_.compare(L"scope-revision.bin",counter_.data(),counter_.size(),matches,present) || !present || !matches)return false;
        revision_=legacyRevision;
    }
    loaded_=true; uncertain_=false; return true;
}
bool ScopedJournal::reserve(std::uint64_t revision) {
    if(!loaded_ || uncertain_ || revision_==UINT64_MAX || revision!=revision_+1)return false;
    return reserveCounter(directory_,counter_,revision_,revision,uncertain_);
}
bool ScopedJournal::persist(const ScopedEntry &candidate,const Bytes &before,bool existed) {
    if (!loaded_ || uncertain_ || !lease_) return false;
    return persistEntry(directory_,candidate,before,existed,uncertain_);
}
bool ScopedJournal::readOwned(const Id &id,ScopedEntry &out,bool &found) {
    found=false;if(zero(id) || !initialize() || uncertain_)return false;
    auto old=std::find_if(legacy_.begin(),legacy_.end(),[&](const auto &e){return e.command==id;});
    if(old!=legacy_.end()){out=*old;found=true;return true;}
    Bytes b;bool exists=false;std::vector<ScopedEntry> rows;std::uint64_t revision=0;
    if(!directory_.read(commandLeaf(id).c_str(),4096,b,exists)){uncertain_=true;return false;}
    if(!exists) {
        NamespaceProbe probe{directory_.root()};
        if(!missingBackup(probe,commandLeaf(id))){uncertain_=true;return false;}
        return true;
    }
    if(!decodeJournal(b,rows,revision) || rows.size()!=1 || rows[0].format!=2 || rows[0].command!=id || revision>revision_) {
        uncertain_=true;return false;
    }
    out=std::move(rows[0]);found=true;return true;
}
bool ScopedJournal::read(const Id &id,ScopedEntry &out,bool &found) {
    std::lock_guard<std::mutex> lock(mutex_);return readOwned(id,out,found);
}
bool ScopedJournal::prepare(const ScopedEntry &entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    ScopedEntry old;bool found=false;
    if(!readOwned(entry.command,old,found) || found || entry.format!=2 || !valid(entry) ||
       entry.state!=State::Prepared || revision_==UINT64_MAX || entry.kernel.decision.revision!=revision_+1)return false;
    // Counter y Prepared comparten mutex+lease; un fallo entre ambos conserva un hueco, nunca reuse.
    return reserve(entry.kernel.decision.revision) && persist(entry,{},false);
}
bool ScopedJournal::complete(const Id &id,const GB_SCOPE_RECEIPT &receipt) {
    std::lock_guard<std::mutex> lock(mutex_);
    ScopedEntry candidate;bool found=false;Bytes before;
    if(!loaded_ || uncertain_ || !receipt.applied || !readOwned(id,candidate,found) || !found || candidate.format!=2 ||
       candidate.state!=State::Prepared || std::memcmp(&candidate.kernel.decision,&receipt.decision,sizeof(receipt.decision)) ||
       !encode({candidate},candidate.kernel.decision.revision,before))return false;
    candidate.kernel=receipt;candidate.state=State::Applied;return persist(candidate,before,true);
}
}
