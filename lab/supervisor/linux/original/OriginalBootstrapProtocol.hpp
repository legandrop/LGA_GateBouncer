#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>
namespace gb::original {
using Bytes = std::vector<std::uint8_t>;
enum class Op : std::uint8_t { Init=1, Hello, Ready, Ack, Acked, Check, Current, Ssh, Credit, Eof, Close, Closed, Invalid };
constexpr std::size_t MaximumFrame = 8192, MaximumLine = 10932, MaximumChunk = 4096;
struct Frame { Op op=Op::Invalid; std::uint64_t request=0, generation=0, sequence=0; Bytes body; };
inline void Put(Bytes& b, std::uint64_t n, unsigned count) {
    for(unsigned i=count;i;--i) b.push_back(static_cast<std::uint8_t>(n >> ((i-1)*8)));
}
inline bool Get(const Bytes& b,std::size_t& p,std::uint64_t& n,unsigned count) {
    if(count>8 || p>b.size() || count>b.size()-p) return false;
    n=0;while(count--) n=(n<<8)|b[p++];return true;
}
inline void PutText(Bytes& b,const std::string& s) { Put(b,s.size(),4);b.insert(b.end(),s.begin(),s.end()); }
inline bool GetText(const Bytes& b,std::size_t& p,std::string& s,std::size_t cap) {
    std::uint64_t n=0;if(!Get(b,p,n,4)||n>cap||n>b.size()-p) return false;
    s.assign(reinterpret_cast<const char*>(b.data()+p),static_cast<std::size_t>(n));p+=static_cast<std::size_t>(n);
    return s.find('\0')==std::string::npos;
}
inline std::string Base64(const Bytes& b) {
    constexpr char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string s;s.reserve(((b.size()+2)/3)*4);
    for(std::size_t p=0;p<b.size();p+=3) {
        unsigned n=static_cast<unsigned>(b[p])<<16;
        if(p+1<b.size()) n|=static_cast<unsigned>(b[p+1])<<8;
        if(p+2<b.size()) n|=b[p+2];
        s+=alphabet[(n>>18)&63];s+=alphabet[(n>>12)&63];
        s+=p+1<b.size()?alphabet[(n>>6)&63]:'=';s+=p+2<b.size()?alphabet[n&63]:'=';
    }return s;
}
inline bool Unbase64(const std::string& s,Bytes& b) {
    if(s.empty()||s.size()%4||s.size()>MaximumLine) return false;
    constexpr char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    b.clear();b.reserve((s.size()/4)*3);
    for(std::size_t p=0;p<s.size();p+=4) {
        unsigned n=0,pad=0;
        for(unsigned j=0;j<4;++j) {
            const auto c=s[p+j];unsigned v=0;
            if(c=='=') {if(p+4!=s.size()||j<2) return false;++pad;}
            else {if(pad) return false;std::size_t i=0;while(i<64&&alphabet[i]!=c)++i;if(i==64)return false;v=static_cast<unsigned>(i);}
            n=(n<<6)|v;
        }
        if(pad>2) return false;
        b.push_back(static_cast<std::uint8_t>(n>>16));
        if(pad<2){b.push_back(static_cast<std::uint8_t>(n>>8));}
        if(!pad){b.push_back(static_cast<std::uint8_t>(n));}
    }return Base64(b)==s;
}
inline bool Encode(const Frame& f,std::string& s) {
    if(f.body.size()>MaximumFrame-30 || f.op<Op::Init||f.op>Op::Invalid) return false;
    Bytes b{1,static_cast<std::uint8_t>(f.op)};Put(b,f.request,8);Put(b,f.generation,8);Put(b,f.sequence,8);Put(b,f.body.size(),4);
    b.insert(b.end(),f.body.begin(),f.body.end());s="GBLC1:"+Base64(b)+"\n";return s.size()<=MaximumLine;
}
inline bool Decode(const std::string& s,Frame& f) {
    if(s.size()<11||s.size()>MaximumLine||s.compare(0,6,"GBLC1:")||s.back()!='\n'||s.find('\r')!=std::string::npos) return false;
    Bytes b;if(!Unbase64(s.substr(6,s.size()-7),b)||b.size()<30||b.size()>MaximumFrame||b[0]!=1||b[1]<1||b[1]>13)return false;
    std::size_t p=2;std::uint64_t n=0;f.op=static_cast<Op>(b[1]);
    if(!Get(b,p,f.request,8)||!Get(b,p,f.generation,8)||!Get(b,p,f.sequence,8)||!Get(b,p,n,4)||n!=b.size()-p)return false;
    f.body.assign(b.begin()+static_cast<std::ptrdiff_t>(p),b.end());return true;
}
inline bool P256(const Bytes& b) {
    std::size_t p=0;std::string algorithm,curve;std::uint64_t n=0;
    return GetText(b,p,algorithm,64)&&algorithm=="ecdsa-sha2-nistp256"&&GetText(b,p,curve,32)&&curve=="nistp256"&&
        Get(b,p,n,4)&&n==65&&n==b.size()-p&&b[p]==4;
}
inline bool PublicLine(const std::string& line,const std::string& algorithm,Bytes& blob) {
    if(line.empty()||line.size()>2048||line.back()!='\n')return false;
    const auto space=line.find(' ');if(space==std::string::npos||line.substr(0,space)!=algorithm)return false;
    if(!Unbase64(line.substr(space+1,line.size()-space-2),blob))return false;
    std::size_t p=0;std::string keytype;if(!GetText(blob,p,keytype,64)||keytype!=algorithm)return false;
    if(algorithm=="ecdsa-sha2-nistp256")return P256(blob);
    std::uint64_t n=0;return algorithm=="ssh-ed25519"&&Get(blob,p,n,4)&&n==32&&n==blob.size()-p;
}
}
