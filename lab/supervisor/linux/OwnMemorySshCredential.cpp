#include "OwnMemorySshCredential.hpp"
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
    enum class Phase { Connecting, Header, Body };
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
        io_->event&&!publicBlob_.empty()&&state_==State::MemoryOwned;
}
bool OwnMemorySshCredential::OriginalCurrentOwn() const {
    return !cancelled_.load()&&GetCurrentThreadId()==thread_&&admission_&&admission_->CurrentOwn()&&
        (!stop_||WaitForSingleObject(stop_,0)==WAIT_TIMEOUT);
}
std::shared_ptr<OwnMemorySshCredential> OwnMemorySshCredential::CreateOwn(
    const std::shared_ptr<BrokerAdmission>& admission) {
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
    own->admission_=admission;own->thread_=GetCurrentThreadId();own->active_=true;
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
                    const std::wstring descriptor=L"O:"+user+L"G:"+user+
                        L"D:P(D;;0x001f01ff;;;NU)(D;;0x001f01ff;;;AN)(A;;0x001f01ff;;;"+user+
                        L")S:P(ML;;NW;;;HI)";
                    PSECURITY_DESCRIPTOR security=nullptr;
                    if(user.empty()||!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        descriptor.c_str(),SDDL_REVISION_1,&security,nullptr))
                        own->RevokeOwn(Cause::PipeUnconfirmed);
                    else {
                        SECURITY_ATTRIBUTES attributes{sizeof(attributes),security,FALSE};
                        if(own->OriginalCurrentOwn()) own->pipe_=CreateNamedPipeW(memoryssh::PipeName,
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
    const BOOL started=ReadFile(pipe_,io_->bytes.data()+io_->offset,target-io_->offset,nullptr,&io_->overlap);
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
    if(io_->phase==IoOwn::Phase::Header) {
        DWORD count=0;for(unsigned i=0;i<4;++i) count=(count<<8)|io_->bytes[i];
        if(!count||count>memoryssh::MaximumPacket) return false;
        io_->phase=IoOwn::Phase::Body;io_->offset=0;return BeginReadOwn(count);
    }
    // Primera lectura limitada antes de impersonación. El peer observado no concede autoridad.
    native::TokenEvidence token;native::ProcessEvidence peer;
    if(!ipc::ii::clientEvidence(pipe_,token,peer)||!peer.current()||!CurrentOwn()) return false;
    // Falta el productor Linux original: no interpretar como admisión user/identities/SIGN.
    // Se revoca la misma instancia, sin DisconnectNamedPipe ni rearm a otro proceso.
    RevokeOwn(Cause::LinuxBindingUnavailable);return false;
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
