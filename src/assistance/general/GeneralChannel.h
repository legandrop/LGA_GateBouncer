#pragma once
#include "../broker/BrokerPipe.h"
namespace Gate::Assistance::General {
class FrameChannel {
public:
    using Receive=std::function<void(Broker::Frame)>;
    virtual ~FrameChannel()=default;
    virtual Broker::WireVersion version() const=0;
    virtual Broker::Id connection() const=0;
    virtual bool peerCurrent() const {return false;}
    virtual void start(Receive,std::function<void()>)=0;
    virtual bool send(Broker::Frame)=0;
    virtual void stop()=0;
};
// El canal nativo conserva peer/ACL/secuencia/framing de PipeSession.
class PipeFrameChannel final : public FrameChannel {
public:
    explicit PipeFrameChannel(std::unique_ptr<Broker::PipeSession> session):session_(std::move(session)){}
    ~PipeFrameChannel() override {stop();}
    Broker::WireVersion version() const override {return session_->version();}
    Broker::Id connection() const override {return session_->connection();}
    bool peerCurrent() const override {return session_&&session_->peerCurrent();}
    void start(Receive r,std::function<void()> c) override {session_->start(std::move(r),std::move(c));}
    bool send(Broker::Frame f) override {return session_->send(std::move(f));}
    void stop() override {if(session_)session_->stop();}
private:
    std::unique_ptr<Broker::PipeSession> session_;
};
}
