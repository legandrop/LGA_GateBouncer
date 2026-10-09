#pragma once
#include "pipe_ii_win.h"
#include <deque>
namespace gb::ipc::ii {
class SessionChannel {
  public:
    virtual ~SessionChannel() = default;
    virtual bool open(bool control, const std::filesystem::path &serviceImage) = 0;
    virtual bool transact(wire::Frame request, wire::Frame &reply) = 0;
    virtual bool events(std::vector<wire::Frame> &batch) = 0;
    virtual void close() = 0;
    virtual const wire::Frame &hello() const = 0;
    virtual bool actualOsAuthenticated() const { return false; }
};
class Client : public SessionChannel {
  public:
    explicit Client(std::uint16_t minor = 1) : minor_(minor) {}
    bool open(bool control, const std::filesystem::path &serviceImage);
    bool transact(wire::Frame request, wire::Frame &reply);
    bool events(std::vector<wire::Frame> &batch);
    void close();
    const wire::Frame &hello() const { return hello_; }
    bool control() const { return control_; }
    bool actualOsAuthenticated() const override {
        return bool(pipe_) && control_ && !wire::zero(connection_);
    }

  private:
    bool authenticated();
    native::Handle pipe_;
    native::ProcessEvidence server_;
    std::filesystem::path image_;
    wire::Id connection_{};
    std::uint64_t tx_ = 1, rx_ = 1;
    bool control_ = false;
    std::uint16_t minor_;
    wire::Frame hello_;
    std::deque<wire::Frame> bufferedEvents_;
};
} // namespace gb::ipc::ii
