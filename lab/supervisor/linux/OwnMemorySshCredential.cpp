#include "OwnMemorySshCredential.hpp"
#include "original/OwnHostLinuxOriginal.hpp"
#include "original/OriginalHostResources.hpp"
#include "guestbroker/GuestBrokerBoundary.hpp"
#include "../../../common/pipe_ii_win.h"
#include <array>
#include <cstring>
#include <sddl.h>
namespace gb {
std::mutex OwnMemorySshCredential::registryMutex_;
std::map<OwnMemorySshCredential*,std::shared_ptr<OwnMemorySshCredential>> OwnMemorySshCredential::retained_;
std::vector<std::weak_ptr<BrokerAdmission>> OwnMemorySshCredential::attempted_;
namespace memoryssh {
constexpr wchar_t PipeName[]=L"\\\\.\\pipe\\GateBouncerOwnMemorySshAgent";
constexpr DWORD MaximumPacket=16384;
void U32(std::vector<BYTE>& bytes,DWORD value) {
    for(unsigned shift=32;shift;shift-=8) bytes.push_back(static_cast<BYTE>(value>>(shift-8)));
}
void String(std::vector<BYTE>& bytes,const BYTE* data,DWORD size) {
    U32(bytes,size);bytes.insert(bytes.end(),data,data+size);
}
template<std::size_t N> void Text(std::vector<BYTE>& bytes,const char(&text)[N]) {
    String(bytes,reinterpret_cast<const BYTE*>(text),static_cast<DWORD>(N-1));
}
// Sólo BCRYPT_ECCPUBLIC_BLOB: ninguna ruta exporta el escalar privado.
bool PublicEncoding(const BYTE* blob,std::size_t size,std::vector<BYTE>& encoded) {
    if(!blob||size!=sizeof(BCRYPT_ECCKEY_BLOB)+64) return false;
    BCRYPT_ECCKEY_BLOB header{};std::memcpy(&header,blob,sizeof(header));
    if(header.dwMagic!=BCRYPT_ECDSA_PUBLIC_P256_MAGIC||header.cbKey!=32) return false;
    std::array<BYTE,65> point{};point[0]=4;
    std::memcpy(point.data()+1,blob+sizeof(header),64);
    std::vector<BYTE> candidate;Text(candidate,"ecdsa-sha2-nistp256");
    Text(candidate,"nistp256");String(candidate,point.data(),static_cast<DWORD>(point.size()));
    encoded=std::move(candidate);return true;
}
bool OwnToken(native::TokenEvidence& evidence) {
    HANDLE raw=nullptr;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw)) return false;
    native::Handle token(raw);return native::tokenEvidence(token.value,evidence);
}
}
struct OwnMemorySshCredential::IoOwn {
    enum class Phase { Connecting, Header, Body, Writing };
    OVERLAPPED overlap{};
    HANDLE event=nullptr;
    std::array<BYTE,memoryssh::MaximumPacket> bytes{};
    Phase phase=Phase::Connecting;
    DWORD target=0,offset=0;
    bool pending=false,completed=false;
};
void OwnMemorySshCredential::RevokeOwn(Cause cause) {
    cancelled_.store(true);if(state_!=State::Closed) state_=State::ClosePending;
    if(cause_==Cause::None) cause_=cause;
}
bool OwnMemorySshCredential::CurrentOwn() {
    return OriginalCurrentOwn()&&stop_&&key_&&provider_&&pipe_&&io_&&
        io_->event&&!publicBlob_.empty()&&(state_==State::MemoryOwned||state_==State::SignatureSubmitted);
}
bool OwnMemorySshCredential::OriginalCurrentOwn() const {
#ifdef GB_ORIGINAL_HOST_ONLY
    const auto host=host_.lock();
    const bool original=hostRoute_&&host&&host->OriginalCurrentOwn();
#else
    const bool original=admission_&&admission_->CurrentOwn();
#endif
    return !cancelled_.load()&&GetCurrentThreadId()==thread_&&original&&
        (!stop_||WaitForSingleObject(stop_,0)==WAIT_TIMEOUT);
}
std::shared_ptr<OwnMemorySshCredential> OwnMemorySshCredential::CreateOwn(
    const std::shared_ptr<BrokerAdmission>& admission) {
    return CreateCoreOwn(admission,{});
}
#ifdef GB_ORIGINAL_HOST_ONLY
std::shared_ptr<OwnMemorySshCredential> OwnMemorySshCredential::CreateHostOwn(
    const std::shared_ptr<OwnHostLinuxOriginal>& host) {
    return CreateCoreOwn({},host);
}
#endif
std::shared_ptr<OwnMemorySshCredential> OwnMemorySshCredential::CreateCoreOwn(
    const std::shared_ptr<BrokerAdmission>& admission,const std::shared_ptr<OwnHostLinuxOriginal>& host) {
    auto own=std::shared_ptr<OwnMemorySshCredential>(new OwnMemorySshCredential);
    // Reserva fuerte anterior a cualquier efecto CNG, event o pipe, incluso retornos parciales.
    {std::lock_guard<std::mutex> registry(registryMutex_);
        retained_.emplace(own.get(),own);
        if(admission) {
            for(const auto& previous:attempted_) {
                if(!previous.owner_before(admission)&&!admission.owner_before(previous)) {
                    own->RevokeOwn(Cause::ReplayRejected);break;
                }
            }
            if(!own->cancelled_.load()) attempted_.push_back(admission);
        }
    }
    std::lock_guard<std::recursive_mutex> operation(own->mutex_);
    own->admission_=admission;own->host_=host;own->hostRoute_=static_cast<bool>(host);own->thread_=GetCurrentThreadId();own->active_=true;
    try {
        if(!own->OriginalCurrentOwn()) {own->RevokeOwn(Cause::OriginalAdmissionLost);}
        else {
            own->stop_=CreateEventW(nullptr,TRUE,FALSE,nullptr);
            own->io_=std::make_shared<IoOwn>();
            own->io_->event=CreateEventW(nullptr,TRUE,FALSE,nullptr);
            own->io_->overlap.hEvent=own->io_->event;
            if(!own->stop_||!own->io_->event||!own->OriginalCurrentOwn())
                own->RevokeOwn(Cause::OriginalAdmissionLost);
            else if(BCryptOpenAlgorithmProvider(&own->provider_,BCRYPT_ECDSA_P256_ALGORITHM,
                MS_PRIMITIVE_PROVIDER,0)!=0||!own->OriginalCurrentOwn()||
                BCryptGenerateKeyPair(own->provider_,&own->key_,256,0)!=0||!own->OriginalCurrentOwn()||
                BCryptFinalizeKeyPair(own->key_,0)!=0||!own->OriginalCurrentOwn())
                own->RevokeOwn(Cause::CryptoUnconfirmed);
            else {
                std::array<BYTE,sizeof(BCRYPT_ECCKEY_BLOB)+64> publicKey{};ULONG written=0;
                const bool exported=BCryptExportKey(own->key_,nullptr,BCRYPT_ECCPUBLIC_BLOB,
                    publicKey.data(),static_cast<ULONG>(publicKey.size()),&written,0)==0;
                const bool encoded=exported&&written==publicKey.size()&&
                    memoryssh::PublicEncoding(publicKey.data(),written,own->publicBlob_);
                SecureZeroMemory(publicKey.data(),publicKey.size());
                native::TokenEvidence token;
                if(!encoded||!own->OriginalCurrentOwn()||!memoryssh::OwnToken(token))
                    own->RevokeOwn(Cause::CryptoUnconfirmed);
                else {
                    const std::wstring user=native::sidString(token.account);
                    // El cliente OpenSSH pide GENERIC_WRITE, que incluye FILE_CREATE_PIPE_INSTANCE.
                    // maxInstances=1 y FIRST retienen el único objeto; no se amplía el transporte común.
                    const std::wstring descriptor=host?original::PipeSecurity():L"O:"+user+L"G:"+user+
                        L"D:P(D;;0x001f01ff;;;NU)(D;;0x001f01ff;;;AN)(A;;0x001f01ff;;;"+user+
                        L")S:P(ML;;NW;;;HI)";
                    PSECURITY_DESCRIPTOR security=nullptr;
                    if(user.empty()||!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        descriptor.c_str(),SDDL_REVISION_1,&security,nullptr))
                        own->RevokeOwn(Cause::PipeUnconfirmed);
                    else {
                        SECURITY_ATTRIBUTES attributes{sizeof(attributes),security,FALSE};
#ifdef GB_ORIGINAL_HOST_ONLY
                        const std::wstring name=host->AgentNameOwn();
#else
                        const std::wstring name=memoryssh::PipeName;
#endif
                        if(own->OriginalCurrentOwn()) own->pipe_=CreateNamedPipeW(name.c_str(),
                            PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,
                            PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,
                            1,memoryssh::MaximumPacket,memoryssh::MaximumPacket,5000,&attributes);
                        LocalFree(security);
                        if(own->pipe_==INVALID_HANDLE_VALUE) own->pipe_=nullptr;
                        if(!own->pipe_||!own->OriginalCurrentOwn()||
                            !ipc::ii::exactDescriptor(own->pipe_,descriptor))
                            own->RevokeOwn(Cause::PipeUnconfirmed);
                        else {own->state_=State::MemoryOwned;if(!own->BeginConnectOwn())
                            own->RevokeOwn(Cause::PipeUnconfirmed);}
                    }
                }
            }
        }
    } catch(...) {own->RevokeOwn(Cause::CryptoUnconfirmed);}
    own->active_=false;
    // El caller recibe también la hoja parcial, nunca un HANDLE o DTO para reconstruirla.
    return own;
}
bool OwnMemorySshCredential::BeginConnectOwn() {
    if(!CurrentOwn()||io_->pending||!ResetEvent(io_->event)) return false;
    io_->overlap={};io_->overlap.hEvent=io_->event;
    io_->phase=IoOwn::Phase::Connecting;io_->completed=false;io_->pending=true;
    if(!CurrentOwn()) {io_->pending=false;return false;}
    if(ConnectNamedPipe(pipe_,&io_->overlap)) {io_->pending=false;io_->completed=true;return CurrentOwn();}
    const DWORD error=GetLastError();
    if(error==ERROR_IO_PENDING) return CurrentOwn();
    io_->pending=false;
    if(error==ERROR_PIPE_CONNECTED) {io_->completed=true;return CurrentOwn();}
    return false;
}
bool OwnMemorySshCredential::BeginReadOwn(DWORD target) {
    if(!CurrentOwn()||io_->pending||target==0||target>io_->bytes.size()||io_->offset>=target||
        !ResetEvent(io_->event)) return false;
    io_->target=target;io_->completed=false;io_->pending=true;
    io_->overlap={};io_->overlap.hEvent=io_->event;
    if(!CurrentOwn()) {io_->pending=false;return false;}
    const BOOL started=io_->phase==IoOwn::Phase::Writing?WriteFile(pipe_,io_->bytes.data()+io_->offset,target-io_->offset,nullptr,&io_->overlap):ReadFile(pipe_,io_->bytes.data()+io_->offset,target-io_->offset,nullptr,&io_->overlap);
    if(started) return CurrentOwn(); // También se confirma GetOverlappedResult en completion inmediata.
    if(GetLastError()==ERROR_IO_PENDING) return CurrentOwn();
    io_->pending=false;return false;
}
bool OwnMemorySshCredential::PollOwn() {
    if(!CurrentOwn()) return false;
    if(io_->pending) {
        DWORD done=0;
        if(!GetOverlappedResult(pipe_,&io_->overlap,&done,FALSE)) {
            if(GetLastError()==ERROR_IO_INCOMPLETE) return true;
            io_->pending=false;return false;
        }
        io_->pending=false;io_->completed=true;
        if(io_->phase!=IoOwn::Phase::Connecting) {
            if(!done||done>io_->target-io_->offset) return false;
            io_->offset+=done;
        }
    }
    if(!io_->completed||!CurrentOwn()) return false;
    if(io_->phase==IoOwn::Phase::Connecting) {
        io_->phase=IoOwn::Phase::Header;io_->offset=0;return BeginReadOwn(4);
    }
    if(io_->offset<io_->target) return BeginReadOwn(io_->target);
    if(io_->phase==IoOwn::Phase::Writing) {
        if(signConsumed_){state_=State::SignatureSubmitted;return CurrentOwn();}
        io_->phase=IoOwn::Phase::Header;io_->offset=0;return BeginReadOwn(4);
    }
    if(io_->phase==IoOwn::Phase::Header) {
        DWORD count=0;for(unsigned i=0;i<4;++i) count=(count<<8)|io_->bytes[i];
        if(!count||count>memoryssh::MaximumPacket) return false;
        io_->phase=IoOwn::Phase::Body;io_->offset=0;return BeginReadOwn(count);
    }
    // Primera lectura limitada antes de impersonación. El peer observado no concede autoridad.
    native::TokenEvidence token;native::ProcessEvidence peer;
    if(!ipc::ii::clientEvidence(pipe_,token,peer)||!peer.current()||!CurrentOwn()) return false;
#ifdef GB_ORIGINAL_HOST_ONLY
    if(hostRoute_) {
        auto host=host_.lock();
        if(!host||!host->AgentPeerOwn(peer.process.value,peer.pid,original::Created(peer.process.value))||!host->FreshLinuxOwn()||!CurrentOwn())return false;
        std::vector<BYTE> packet(io_->bytes.begin(),io_->bytes.begin()+io_->target),reply;
        if(!sessionBindRejected_&&!signConsumed_&&!packet.empty()&&packet[0]==27) {
            std::size_t p=1;std::string extension;std::uint64_t n=0;
            if(!original::GetText(packet,p,extension,64)||extension!="session-bind@openssh.com")return false;
            for(unsigned i=0;i<3;++i) {
                if(!original::Get(packet,p,n,4)||!n||n>(i==1?64u:1024u)||n>packet.size()-p)return false;
                p+=static_cast<std::size_t>(n);
            }
            if(p+1!=packet.size()||packet[p]!=0)return false;
            // Extensión no soportada: failure acotado, sin instalar binding ni cambiar autoridad.
            sessionBindRejected_=true;reply.push_back(5);
        }else if(packet.size()==1&&packet[0]==11) {
            reply.push_back(12);memoryssh::U32(reply,1);
            memoryssh::String(reply,publicBlob_.data(),static_cast<DWORD>(publicBlob_.size()));memoryssh::Text(reply,"GateBouncer ephemeral session");
        }else if(!signConsumed_&&!packet.empty()&&packet[0]==13) {
            std::size_t p=1;std::uint64_t n=0,flags=0;
            if(!original::Get(packet,p,n,4)||n!=publicBlob_.size()||n>packet.size()-p||!std::equal(publicBlob_.begin(),publicBlob_.end(),packet.begin()+static_cast<std::ptrdiff_t>(p)))return false;
            p+=static_cast<std::size_t>(n);if(!original::Get(packet,p,n,4)||n>8192||n>packet.size()-p)return false;
            std::vector<BYTE> data(packet.begin()+static_cast<std::ptrdiff_t>(p),packet.begin()+static_cast<std::ptrdiff_t>(p+n));p+=static_cast<std::size_t>(n);
            if(!original::Get(packet,p,flags,4)||flags||p!=packet.size()||!host->SignDataOwn(data)||!host->FreshLinuxOwn()||!CurrentOwn())return false;
            // Consumo anterior a BCryptSignHash; un fallo tampoco rearma la firma.
            signConsumed_=true;BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;DWORD count=0,size=0;
            if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,MS_PRIMITIVE_PROVIDER,0)!=0)return false;
            bool okay=BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,reinterpret_cast<BYTE*>(&size),sizeof(size),&count,0)==0;
            std::vector<BYTE> object(size);std::array<BYTE,32>digest{};std::array<BYTE,64>sig{};ULONG done=0;
            okay=okay&&BCryptCreateHash(alg,&hash,object.data(),size,nullptr,0,0)==0&&BCryptHashData(hash,data.data(),static_cast<ULONG>(data.size()),0)==0&&BCryptFinishHash(hash,digest.data(),static_cast<ULONG>(digest.size()),0)==0&&host->OriginalCurrentOwn()&&
                BCryptSignHash(key_,nullptr,digest.data(),static_cast<ULONG>(digest.size()),sig.data(),static_cast<ULONG>(sig.size()),&done,0)==0&&done==sig.size()&&host->OriginalCurrentOwn();
            if(hash)BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(alg,0);SecureZeroMemory(object.data(),object.size());SecureZeroMemory(digest.data(),digest.size());
            if(!okay)return false;std::vector<BYTE> pair,signature;
            for(unsigned half=0;half<2;++half) {
                std::size_t at=half*32;while(at<(half+1)*32&&sig[at]==0)++at;
                std::vector<BYTE> mp(sig.begin()+static_cast<std::ptrdiff_t>(at),sig.begin()+(half+1)*32);
                if(mp.empty())return false;if(mp[0]&0x80)mp.insert(mp.begin(),0);memoryssh::String(pair,mp.data(),static_cast<DWORD>(mp.size()));
            }
            memoryssh::Text(signature,"ecdsa-sha2-nistp256");memoryssh::String(signature,pair.data(),static_cast<DWORD>(pair.size()));reply.push_back(14);memoryssh::String(reply,signature.data(),static_cast<DWORD>(signature.size()));
            SecureZeroMemory(sig.data(),sig.size());
        }else return false;
        if(!host->FreshLinuxOwn()||!CurrentOwn()||!ReplyHostOwn(reply))return false;
        return true; // ReplyHostOwn retiene buffer/OVERLAPPED hasta completion.
    }
#endif
    // Falta el productor Linux original: no interpretar como admisión user/identities/SIGN.
    // Se revoca la misma instancia, sin DisconnectNamedPipe ni rearm a otro proceso.
    RevokeOwn(Cause::LinuxBindingUnavailable);return false;
}
bool OwnMemorySshCredential::ReplyHostOwn(const std::vector<BYTE>& body) {
    if(body.empty()||body.size()>memoryssh::MaximumPacket||!CurrentOwn())return false;
    std::vector<BYTE> packet;memoryssh::U32(packet,static_cast<DWORD>(body.size()));packet.insert(packet.end(),body.begin(),body.end());
    if(packet.size()>io_->bytes.size()||io_->pending)return false;
    std::copy(packet.begin(),packet.end(),io_->bytes.begin());io_->phase=IoOwn::Phase::Writing;io_->offset=0;
    return BeginReadOwn(static_cast<DWORD>(packet.size()));
}
bool OwnMemorySshCredential::PublicBlobOwn(std::vector<BYTE>& output) {
    std::lock_guard<std::recursive_mutex> operation(mutex_);
    if(!CurrentOwn()) return false;
    auto candidate=publicBlob_;
    if(!CurrentOwn()) {SecureZeroMemory(candidate.data(),candidate.size());return false;}
    output=std::move(candidate);return true;
}
OwnMemorySshCredential::Snapshot OwnMemorySshCredential::InspectOwn() {
    std::lock_guard<std::recursive_mutex> operation(mutex_);
    if(active_) return ViewOwn();
    if(state_==State::MemoryOwned&&!PollOwn()) RevokeOwn(Cause::OriginalAdmissionLost);
    if(state_==State::SignatureSubmitted&&!OriginalCurrentOwn())RevokeOwn(Cause::OriginalAdmissionLost);
    return ViewOwn();
}
OwnMemorySshCredential::Snapshot OwnMemorySshCredential::CancelOwn() {
    cancelled_.store(true);
    {std::lock_guard<std::mutex> signal(signalMutex_);if(stop_) SetEvent(stop_);}
    std::lock_guard<std::recursive_mutex> operation(mutex_);RevokeOwn(Cause::Cancelled);
    return ViewOwn();
}
bool OwnMemorySshCredential::DrainIoOwn() {
    if(!io_||!io_->pending) return true;
    const BOOL cancelled=CancelIoEx(pipe_,&io_->overlap);
    if(!cancelled&&GetLastError()!=ERROR_NOT_FOUND) return false;
    DWORD done=0;
    if(GetOverlappedResult(pipe_,&io_->overlap,&done,FALSE)) {io_->pending=false;return true;}
    const DWORD error=GetLastError();
    if(error==ERROR_OPERATION_ABORTED||error==ERROR_BROKEN_PIPE||error==ERROR_NO_DATA) {
        io_->pending=false;return true;
    }
    return false; // Conserva OVERLAPPED, event, buffer, pipe y hoja mientras completion sea incierta.
}
bool OwnMemorySshCredential::CloseCryptoOwn() {
    if(key_) {if(BCryptDestroyKey(key_)!=0) return false;key_=nullptr;}
    if(provider_) {if(BCryptCloseAlgorithmProvider(provider_,0)!=0) return false;provider_=nullptr;}
    if(!publicBlob_.empty()) SecureZeroMemory(publicBlob_.data(),publicBlob_.size());
    publicBlob_.clear();return true;
}
OwnMemorySshCredential::Snapshot OwnMemorySshCredential::CloseOwn() {
    CancelOwn();auto own=shared_from_this();
    std::lock_guard<std::recursive_mutex> operation(mutex_);
    if(state_==State::Closed||active_) return ViewOwn();
    if(!DrainIoOwn()) {cause_=Cause::IoUnconfirmed;return ViewOwn();}
    if(pipe_) {if(!CloseHandle(pipe_)) {cause_=Cause::CloseUnconfirmed;return ViewOwn();}pipe_=nullptr;}
    if(!CloseCryptoOwn()) {cause_=Cause::CloseUnconfirmed;return ViewOwn();}
    if(io_&&io_->event) {
        if(!CloseHandle(io_->event)) {cause_=Cause::CloseUnconfirmed;return ViewOwn();}
        io_->event=nullptr;
    }
    {std::lock_guard<std::mutex> signal(signalMutex_);
        if(stop_) {if(!CloseHandle(stop_)) {cause_=Cause::CloseUnconfirmed;return ViewOwn();}stop_=nullptr;}}
    io_.reset();admission_.reset();state_=State::Closed;
    {std::lock_guard<std::mutex> registry(registryMutex_);retained_.erase(this);}
    return ViewOwn();
}
}
