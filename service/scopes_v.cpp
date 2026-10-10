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
    return !zero(e.command) && !zero(e.epoch) && !zero(e.boot) && e.pid && e.created &&
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
    b={'G','B','T','5'}; put(b,1,4); put(b,revision,8); put(b,rows.size(),4);
    std::set<Id> seen;
    for (const auto &e:rows) {
        if (!valid(e) || !seen.insert(e.command).second) return false;
        raw(b,e.command); raw(b,e.epoch); raw(b,e.boot); put(b,e.pid,4); put(b,e.session,4);
        put(b,e.created,8); put(b,unsigned(e.state),1); raw(b,e.kernel);
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
    if (!r.take(magic,4) || std::memcmp(magic,"GBT5",4) || !r.number(version,4) || version!=1 ||
        !r.number(revision,8) || !r.number(count,4) || count>MaxEntries) return false;
    rows.clear();
    std::uint64_t last=0;
    for (std::uint64_t i=0;i<count;++i) {
        ScopedEntry e; std::uint64_t n=0;
        if (!r.take(e.command.data(),16) || !r.take(e.epoch.data(),16) || !r.take(e.boot.data(),16) ||
            !r.number(n,4)) return false;
        e.pid=std::uint32_t(n); if (!r.number(n,4)) return false; e.session=std::uint32_t(n);
        if (!r.number(e.created,8) || !r.number(n,1)) return false; e.state=State(n);
        if (!r.take(&e.kernel,sizeof(e.kernel)) || !r.bytes(e.account,68) || !r.bytes(e.logon,68) ||
            !r.bytes(e.payload,1024) || !valid(e) || !seen.insert(e.command).second ||
            e.kernel.decision.revision<=last) return false;
        last=e.kernel.decision.revision; rows.push_back(std::move(e));
    }
    return r.at==b.size() && revision==last;
}
}
bool ScopedJournal::load() {
    if (loaded_) return !uncertain_;
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
    Bytes b; bool exists=false;
    if (!directory_.read(L"scoped-decisions.bin",MaxBytes,b,exists) ||
        (exists && !decodeJournal(b,entries_,revision_))) return false;
    loaded_=true; uncertain_=false; return true;
}
bool ScopedJournal::persist(const std::vector<ScopedEntry> &candidate) {
    if (!loaded_ || uncertain_ || !lease_) return false;
    const auto revision=candidate.empty() ? 0 : candidate.back().kernel.decision.revision;
    Bytes bytes;
    if (!encode(candidate,revision,bytes)) return false;
    bool matches=false,exists=false;
    if (!directory_.replace(L"scoped-decisions.bin",bytes,false) ||
        !directory_.compare(L"scoped-decisions.bin",bytes.data(),bytes.size(),matches,exists) || !exists || !matches) {
        uncertain_=true; return false;
    }
    entries_=candidate; revision_=revision; return true;
}
const ScopedEntry *ScopedJournal::find(const Id &id) const {
    auto p=std::find_if(entries_.begin(),entries_.end(),[&](const auto &e) { return e.command==id; });
    return p==entries_.end() ? nullptr : &*p;
}
bool ScopedJournal::prepare(const ScopedEntry &entry) {
    if (!load() || uncertain_ || entries_.size()==MaxEntries || revision_==UINT64_MAX ||
        find(entry.command) || entry.state!=State::Prepared || entry.kernel.decision.revision!=revision_+1) return false;
    auto candidate=entries_; candidate.push_back(entry); return persist(candidate);
}
bool ScopedJournal::complete(const Id &id,const GB_SCOPE_RECEIPT &receipt) {
    if (!loaded_ || uncertain_ || !receipt.applied) return false;
    auto candidate=entries_;
    auto p=std::find_if(candidate.begin(),candidate.end(),[&](const auto &e) { return e.command==id; });
    if (p==candidate.end() || p->state!=State::Prepared ||
        std::memcmp(&p->kernel.decision,&receipt.decision,sizeof(receipt.decision))) return false;
    p->kernel=receipt; p->state=State::Applied; return persist(candidate);
}
}
