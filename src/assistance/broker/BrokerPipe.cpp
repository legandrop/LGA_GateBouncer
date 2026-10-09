#include "BrokerPipe.h"
#include <sddl.h>
#include <QMetaObject>
#include <cstring>

namespace Gate::Assistance::Broker {
PipeSession::PipeSession(Handle pipe,Peer peer,Id id,bool server,QObject *parent,WireVersion version):QObject(parent),version_(version),pipe_(std::move(pipe)),peer_(std::move(peer)),connection_(id),server_(server){}
PipeSession::~PipeSession(){stop();if(worker_.joinable())worker_.join();}
Handle PipeSession::createServer(const QString &name,const TokenIdentity &id) {
    if(!id.ordinary||!name.startsWith("\\\\.\\pipe\\LGA.GateBouncer.Assistance.")||name.size()>160)return {};
    LPWSTR sid=nullptr;if(!ConvertSidToStringSidW(const_cast<unsigned char *>(id.logon.data()),&sid))return {};
    // Derechos individuales: el cliente no obtiene CREATE_PIPE_INSTANCE por GENERIC_WRITE.
    const std::wstring sddl=L"D:P(A;;0x"+QString::number(ClientPipeAccess,16).toStdWString()+L";;;"+std::wstring(sid)+L")";LocalFree(sid);PSECURITY_DESCRIPTOR sd=nullptr;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&sd,nullptr))return {};
    SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};Handle pipe(CreateNamedPipeW(name.toStdWString().c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,8192,8192,5000,&sa));LocalFree(sd);return pipe;
}
bool PipeSession::peerCurrent() const {
    if(stopping_||!pipe_||!peer_.process||!peer_.pid||peer_.image.isEmpty()||GetProcessId(peer_.process.value)!=peer_.pid)return false;
    ULONG pid=0;if(!(server_?GetNamedPipeClientProcessId(pipe_.value,&pid):GetNamedPipeServerProcessId(pipe_.value,&pid))||pid!=peer_.pid)return false;
    quint64 creation=0;TokenIdentity token;
    if(WaitForSingleObject(peer_.process.value,0)!=WAIT_TIMEOUT||!processCreated(peer_.process.value,creation)||creation!=peer_.creation||
       !tokenIdentity(peer_.process.value,token)||!sameIdentity(token,peer_.identity)||imagePath(peer_.process.value).compare(peer_.image,Qt::CaseInsensitive))return false;
    return !stopping_;
}
bool PipeSession::authenticate() {
    if(!peerCurrent())return false;
    if(server_) {
        if(!ImpersonateNamedPipeClient(pipe_.value))return false;
        HANDLE raw=nullptr;bool ok=OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&raw);
        Handle threadToken(raw);TokenIdentity effective;
        if(ok)ok=identityFromToken(threadToken.value,effective)&&sameIdentity(effective,peer_.identity);
        const bool reverted=RevertToSelf();if(!reverted){stopping_=true;return false;}if(!ok)return false;
    }
    return peerCurrent();
}
bool PipeSession::transfer(bool write,unsigned char *data,DWORD count,DWORD &done) {
    struct Io {Handle event{CreateEventW(nullptr,TRUE,FALSE,nullptr)};OVERLAPPED ov{};SensitiveBytes bytes;explicit Io(size_t n):bytes(n){ov.hEvent=event.value;}};
    auto io=std::make_unique<Io>(count);if(!io->event)return false;if(write)std::memcpy(io->bytes.data(),data,count);
    BOOL ok=write?WriteFile(pipe_.value,io->bytes.data(),count,&done,&io->ov):ReadFile(pipe_.value,io->bytes.data(),count,&done,&io->ov);
    if(!ok&&GetLastError()!=ERROR_IO_PENDING)return false;
    if(!ok){const auto wait=WaitForSingleObject(io->event.value,5000);
        if(wait!=WAIT_OBJECT_0){CancelIoEx(pipe_.value,&io->ov);
            if(WaitForSingleObject(io->event.value,5000)!=WAIT_OBJECT_0){
                // El kernel aun posee OVERLAPPED/buffer: conservarlos hasta fin de proceso.
                // Es una sola operacion bounded de esta sesion fallida, sin worker huerfano.
                io.release();
            }
            stopping_=true;return false;
        }
        if(!GetOverlappedResult(pipe_.value,&io->ov,&done,FALSE))return false;
    }
    if(!write&&done<=count)std::memcpy(data,io->bytes.data(),done);
    return done<=count;
}
void PipeSession::start(Receive receive,std::function<void()> closed){
    receive_=std::move(receive);closed_=std::move(closed);
    if(version_!=WireVersion::Legacy1&&version_!=WireVersion::Grounded2&&version_!=WireVersion::General3){
        stopping_=true;QMetaObject::invokeMethod(this,[this]{if(closed_)closed_();},Qt::QueuedConnection);return;
    }
    worker_=std::thread([this]{run();});
}
void PipeSession::stop(){stopping_=true;if(pipe_)CancelIoEx(pipe_.value,nullptr);}
bool PipeSession::send(Frame frame) {
    std::lock_guard<std::mutex> lock(mutex_);if(!peerCurrent()||writes_.size()>=4||sendSequence_==UINT64_MAX)return false;
    frame.connection=connection_;frame.sequence=++sendSequence_;auto wire=encodeFrame(frame,version_);if(!wire)return false;writes_.push_back(std::move(*wire));return true;
}
void PipeSession::run() {
    if(server_) {
        struct Connect {Handle event{CreateEventW(nullptr,TRUE,FALSE,nullptr)};OVERLAPPED ov{};Connect(){ov.hEvent=event.value;}};
        auto pending=std::make_unique<Connect>();
        const BOOL connected=pending->event&&ConnectNamedPipe(pipe_.value,&pending->ov);const DWORD error=connected?ERROR_SUCCESS:GetLastError();
        if(!pending->event)stopping_=true;
        if(!connected&&error==ERROR_IO_PENDING){
            if(WaitForSingleObject(pending->event.value,5000)!=WAIT_OBJECT_0){
                CancelIoEx(pipe_.value,&pending->ov);
                // Tampoco liberar el contexto de accept mientras el kernel lo posee.
                if(WaitForSingleObject(pending->event.value,5000)!=WAIT_OBJECT_0)pending.release();
                stopping_=true;
            }else{DWORD unused=0;if(!GetOverlappedResult(pipe_.value,&pending->ov,&unused,FALSE))stopping_=true;}
        }
        else if(!connected&&error!=ERROR_PIPE_CONNECTED)stopping_=true;
    }
    FrameReader reader(version_);std::array<unsigned char,4096> chunk{};ULONGLONG partialSince=0,started=GetTickCount64();
    while(!stopping_) {
        if(WaitForSingleObject(peer_.process.value,0)!=WAIT_TIMEOUT){stopping_=true;break;}
        std::optional<SensitiveBytes> outgoing;
        {std::lock_guard<std::mutex> lock(mutex_);if(!writes_.empty()){outgoing=std::move(writes_.front());writes_.pop_front();}}
        if(outgoing){DWORD done=0;if(!peerCurrent()||!transfer(true,outgoing->data(),DWORD(outgoing->size()),done)||done!=outgoing->size()){stopping_=true;break;}}
        DWORD available=0;if(!PeekNamedPipe(pipe_.value,nullptr,0,nullptr,&available,nullptr)){stopping_=true;break;}
        if(available){DWORD read=0;const auto size=std::min<DWORD>(available,DWORD(chunk.size()));
            if(!transfer(false,chunk.data(),size,read)||!read||!reader.feed(chunk.data(),read)){stopping_=true;break;}SecureZeroMemory(chunk.data(),chunk.size());
            while(auto frame=reader.take()) {
                if(frame->connection!=connection_||frame->sequence!=receiveSequence_+1||receiveSequence_==UINT64_MAX||!authenticate()){stopping_=true;break;}
                ++receiveSequence_;auto shared=std::make_shared<Frame>(std::move(*frame));QMetaObject::invokeMethod(this,[this,shared]{if(!peerCurrent()){stop();return;}if(receive_)receive_(std::move(*shared));},Qt::QueuedConnection);
            }
            if(reader.failed())stopping_=true;
        }
        if(reader.partial()){if(!partialSince)partialSince=GetTickCount64();if(GetTickCount64()-partialSince>=5000)stopping_=true;}else partialSince=0;
        if(!receiveSequence_&&GetTickCount64()-started>=5000)stopping_=true;
        Sleep(5);
    }
    SecureZeroMemory(chunk.data(),chunk.size());if(server_)DisconnectNamedPipe(pipe_.value);
    QMetaObject::invokeMethod(this,[this]{if(closed_)closed_();},Qt::QueuedConnection);
}
}
