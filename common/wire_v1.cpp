#include "wire_v1.h"
#include "wire_ii.h"
#include <algorithm>
#include <limits>
#include <set>

namespace gb::wire {
namespace {
std::uint64_t read(const std::uint8_t* p, std::size_t n) {
    std::uint64_t v=0; for (std::size_t i=0;i<n;++i) v|=std::uint64_t(p[i])<<(i*8); return v;
}
void append(Bytes& out, std::uint64_t v, std::size_t n) {
    for(std::size_t i=0;i<n;++i) out.push_back(std::uint8_t(v>>(i*8)));
}
std::vector<std::pair<Tag,std::size_t>> schema(Type t) {
    using T=Tag;
    switch(t) {
    case Type::Hello: return {{T::ClientRole,1}};
    case Type::HelloAck: return {{T::ServiceEpoch,16},{T::BootId,16},{T::Capabilities,8},
        {T::DesiredRev,8},{T::EffectiveRev,8},{T::EffectiveKnown,1},{T::EngineState,1},{T::BackendMode,1}};
    case Type::GetStatus: return {};
    case Type::Status: return {{T::ServiceEpoch,16},{T::BootId,16},{T::Capabilities,8},
        {T::DesiredRev,8},{T::EffectiveRev,8},{T::EffectiveKnown,1},{T::EngineState,1},
        {T::GapCount,8},{T::BackendMode,1}};
    case Type::CreateRule: return {{T::ExpectedDesiredRev,8},{T::Decision,1},{T::ScopeKind,1},{T::SelectorId,16}};
    case Type::RevokeRule: return {{T::ExpectedDesiredRev,8},{T::RuleId,16}};
    case Type::MutationAck: return {{T::DesiredRev,8},{T::EffectiveRev,8},
        {T::EffectiveKnown,1},{T::CommandState,1},{T::ErrorCode,2}};
    case Type::ProtocolError: return {{T::ErrorCode,2}};
    default: return {};
    }
}
bool enumOk(const Field& f) {
    auto n=number(f);
    switch(f.tag) {
    case Tag::ClientRole: case Tag::Decision: return n==1 || n==2;
    case Tag::ScopeKind: return n==1;
    case Tag::EffectiveKnown: return n<=1;
    case Tag::EngineState: return n<=5;
    case Tag::BackendMode: return n<=2;
    case Tag::CommandState: return n>=1 && n<=5;
    case Tag::ErrorCode: return n<=14;
    case Tag::Capabilities: return (n>>17)==0;
    default: return true;
    }
}
Error header(const Bytes& b, std::size_t& body) {
    if(b.size()<HeaderBytes) return Error::Malformed;
    if(b[0]!='G'||b[1]!='B'||b[2]!='C'||b[3]!='1') return Error::Malformed;
    if(read(b.data()+4,2)!=1||read(b.data()+6,2)>1) return Error::VersionMismatch;
    if(read(b.data()+10,2)!=0||read(b.data()+56,8)!=0) return Error::Malformed;
    body=static_cast<std::size_t>(read(b.data()+12,4));
    return body>MaxFrameBytes-HeaderBytes ? Error::Capacity : Error::Ok;
}
}
bool zero(const Id& id) { return std::all_of(id.begin(),id.end(),[](auto c){return c==0;}); }
bool supported(Type t,std::uint16_t minor) { if(minor==1) return t>=Type::Hello&&t<=Type::ObservationGap&&t!=Type::Traffic; return t==Type::Hello||t==Type::HelloAck||t==Type::GetStatus||
    t==Type::Status||t==Type::CreateRule||t==Type::RevokeRule||t==Type::MutationAck||t==Type::ProtocolError; }
Bytes integer(std::uint64_t v,std::size_t n) { Bytes b; if(n<=8) append(b,v,n); return b; }
std::uint64_t number(const Field& f) { return f.bytes.size()<=8 ? read(f.bytes.data(),f.bytes.size()) : 0; }
Field value(Tag t,std::uint64_t n,std::size_t width) { return {t,true,integer(n,width)}; }
Field value(Tag t,const Id& id) { return {t,true,Bytes(id.begin(),id.end())}; }
const Field* find(const Frame& f,Tag t) {
    auto it=std::find_if(f.fields.begin(),f.fields.end(),[t](const Field& x){return x.tag==t;});
    return it==f.fields.end()?nullptr:&*it;
}
std::uint64_t get(const Frame& f,Tag t) { auto p=find(f,t); return p?number(*p):0; }
Id idValue(const Frame& f,Tag t) { Id id{};auto p=find(f,t);if(p&&p->bytes.size()==16) std::copy(p->bytes.begin(),p->bytes.end(),id.begin());return id; }
bool validUtf8(const Bytes& b) {
    for(std::size_t i=0;i<b.size();) {
        auto c=b[i++]; if(c==0) return false; if(c<0x80) continue;
        unsigned n;std::uint32_t cp,min;
        if(c>=0xc2&&c<=0xdf){n=1;cp=c&31;min=0x80;}
        else if(c>=0xe0&&c<=0xef){n=2;cp=c&15;min=0x800;}
        else if(c>=0xf0&&c<=0xf4){n=3;cp=c&7;min=0x10000;}
        else return false;
        if(n>b.size()-i) return false;
        while(n--){auto x=b[i++];if((x&0xc0)!=0x80)return false;cp=(cp<<6)|(x&63);}
        if(cp<min||cp>0x10ffff||(cp>=0xd800&&cp<=0xdfff))return false;
    } return true;
}
Error validate(const Frame& f) {
    if(f.minor==1) return ii::validate(f);
    if(f.minor!=0) return Error::VersionMismatch;
    auto t=static_cast<unsigned>(f.type);
    if(t<1||t>16) return Error::Malformed;
    if(!supported(f.type)) return Error::Unsupported;
    if(f.sequence==0||zero(f.correlation))return Error::Malformed;
    if(f.type==Type::Hello && (!zero(f.connection)||f.sequence!=1))return Error::Malformed;
    if(f.type!=Type::Hello && f.type!=Type::ProtocolError && zero(f.connection))return Error::Malformed;
    if(f.type==Type::HelloAck&&f.sequence!=1)return Error::Malformed;
    if(f.fields.size()>64) return Error::Capacity;
    auto expected=schema(f.type);std::set<Tag> seen;std::size_t body=0;
    for(const auto& v:f.fields) {
        if(!seen.insert(v.tag).second)return Error::Malformed;
        auto p=std::find_if(expected.begin(),expected.end(),[&](auto x){return x.first==v.tag;});
        if(v.tag==Tag::Text&&f.type==Type::ProtocolError) {
            if(v.required||v.bytes.size()>1024||!validUtf8(v.bytes))return Error::Malformed;
        } else if(p==expected.end()||!v.required||v.bytes.size()!=p->second||!enumOk(v)) return Error::Malformed;
        if(v.bytes.size()>MaxFrameBytes-HeaderBytes-8 || body>MaxFrameBytes-HeaderBytes-8-v.bytes.size())return Error::Capacity;
        body+=8+v.bytes.size();
    }
    for(auto [tag,width]:expected){(void)width;if(!seen.count(tag))return Error::Malformed;}
    if(f.type==Type::CreateRule && zero(idValue(f,Tag::SelectorId)))return Error::Malformed;
    if(f.type==Type::RevokeRule && zero(idValue(f,Tag::RuleId)))return Error::Malformed;
    if(f.type==Type::Status||f.type==Type::HelloAck||f.type==Type::MutationAck){
        const auto desired=get(f,Tag::DesiredRev),effective=get(f,Tag::EffectiveRev),known=get(f,Tag::EffectiveKnown);
        if(effective>desired||(!known&&effective!=0))return Error::Malformed;
        if(f.type==Type::MutationAck){
            const auto state=get(f,Tag::CommandState),error=get(f,Tag::ErrorCode);
            if(state==2&&(error!=0||!known||effective!=desired))return Error::Malformed;
            if(state==5&&(error!=8||!known||effective!=desired))return Error::Malformed;
        }
    }
    return Error::Ok;
}
Error encode(const Frame& f,Bytes& out) {
    auto e=validate(f);if(e!=Error::Ok)return e;
    Bytes body;for(const auto& v:f.fields){append(body,static_cast<unsigned>(v.tag),2);append(body,v.required?1:0,2);append(body,v.bytes.size(),4);body.insert(body.end(),v.bytes.begin(),v.bytes.end());}
    out={'G','B','C','1'};append(out,1,2);append(out,f.minor,2);append(out,static_cast<unsigned>(f.type),2);append(out,0,2);append(out,body.size(),4);
    out.insert(out.end(),f.connection.begin(),f.connection.end());append(out,f.sequence,8);out.insert(out.end(),f.correlation.begin(),f.correlation.end());append(out,0,8);out.insert(out.end(),body.begin(),body.end());return Error::Ok;
}
Error decode(const Bytes& b,Frame& result) {
    std::size_t body=0;auto e=header(b,body);if(e!=Error::Ok)return e;
    if(b.size()!=HeaderBytes+body)return Error::Malformed;
    Frame f;f.minor=static_cast<std::uint16_t>(read(b.data()+6,2));f.type=static_cast<Type>(read(b.data()+8,2));std::copy_n(b.data()+16,16,f.connection.begin());f.sequence=read(b.data()+32,8);std::copy_n(b.data()+40,16,f.correlation.begin());
    if(static_cast<unsigned>(f.type)<1||static_cast<unsigned>(f.type)>(f.minor==1?23u:16u))return Error::Malformed;
    // Un tipo reservado no llega al coordinador de política.
    if(!supported(f.type,f.minor)){result=f;return Error::Unsupported;}
    for(std::size_t p=HeaderBytes;p<b.size();) {
        if(b.size()-p<8||f.fields.size()==64)return Error::Malformed;
        auto tag=read(b.data()+p,2),flags=read(b.data()+p+2,2),n=read(b.data()+p+4,4);p+=8;
        if(flags>1||n>b.size()-p)return Error::Malformed;
        f.fields.push_back({static_cast<Tag>(tag),flags==1,Bytes(b.begin()+p,b.begin()+p+static_cast<std::size_t>(n))});p+=static_cast<std::size_t>(n);
    }
    e=validate(f);if(e==Error::Ok)result=std::move(f);return e;
}
Error Decoder::feed(const std::uint8_t* p,std::size_t n,std::vector<Frame>& done) {
    while(n) {
        std::size_t target=HeaderBytes;
        if(buffer_.size()>=HeaderBytes){std::size_t body=0;auto e=header(buffer_,body);if(e!=Error::Ok){reset();return e;}target+=body;}
        auto take=std::min(n,target-buffer_.size());buffer_.insert(buffer_.end(),p,p+take);p+=take;n-=take;
        if(buffer_.size()==HeaderBytes){std::size_t body=0;auto e=header(buffer_,body);if(e!=Error::Ok){reset();return e;}if(body)continue;}
        if(buffer_.size()>=HeaderBytes){std::size_t body=0;auto e=header(buffer_,body);if(e!=Error::Ok){reset();return e;}if(buffer_.size()==HeaderBytes+body){Frame f;e=decode(buffer_,f);reset();if(e!=Error::Ok){if(e==Error::Unsupported)done.push_back(f);return e;}done.push_back(std::move(f));}}
    } return Error::Ok;
}
std::string hex(const Id& id){constexpr char h[]="0123456789abcdef";std::string s;for(auto c:id){s+=h[c>>4];s+=h[c&15];}return s;}
bool parseId(const std::string& s,Id& id){if(s.size()!=32)return false;auto digit=[](char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1;};Id out{};for(std::size_t i=0;i<16;++i){auto a=digit(s[i*2]),b=digit(s[i*2+1]);if(a<0||b<0)return false;out[i]=std::uint8_t(a*16+b);}id=out;return true;}
}
