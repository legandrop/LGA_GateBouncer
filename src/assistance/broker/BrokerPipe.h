#pragma once
#include "BrokerWire.h"
#include <QObject>
#include <atomic>
#include <deque>
#include <mutex>
#include <thread>

namespace Gate::Assistance::Broker {
inline constexpr DWORD ClientPipeAccess=FILE_READ_DATA|FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE;
static_assert(ClientPipeAccess==0x00100083);
static_assert((ClientPipeAccess&FILE_CREATE_PIPE_INSTANCE)==0);
struct Peer {
    Handle process;
    DWORD pid=0;
    quint64 creation=0;
    QString image;
    TokenIdentity identity;
};
class PipeSession final : public QObject {
public:
    using Receive=std::function<void(Frame)>;
    PipeSession(Handle pipe,Peer peer,Id connection,bool server,QObject *parent=nullptr,WireVersion version=WireVersion::Legacy1);
    ~PipeSession() override;
    void start(Receive,std::function<void()> closed);
    bool send(Frame);
    bool peerCurrent() const;
    void stop();
    WireVersion version() const {return version_;}
    const Id &connection() const {return connection_;}
    static Handle createServer(const QString &name,const TokenIdentity &owner);
private:
    bool authenticate();
    bool transfer(bool write,unsigned char *data,DWORD count,DWORD &done);
    void run();
    WireVersion version_;Handle pipe_;Peer peer_;Id connection_;bool server_;
    std::atomic<bool> stopping_{false};std::thread worker_;std::mutex mutex_;
    std::deque<SensitiveBytes> writes_;quint64 sendSequence_=0,receiveSequence_=0;
    Receive receive_;std::function<void()> closed_;
};
}
