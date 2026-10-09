#pragma once
#include "pipe_ii_win.h"
#include <deque>
#include <memory>
namespace gb::controller { class Session; }
namespace gb::ipc::ii {
class Client;
enum class ReadPeerState { Current, Closed, Replaced, Unavailable };
// Lease del mismo canal readonly. No concede derechos ni continuidad del motor.
class ReadPeerLease final {
    friend class Client;
    friend class gb::controller::Session;
    struct State;
    explicit ReadPeerLease(std::shared_ptr<State> state) : state_(std::move(state)) {}
    std::shared_ptr<State> state_;
    void revoke() const noexcept;
  public:
    ReadPeerState checkLive() const noexcept;
    wire::Id connection() const noexcept;
};
class SessionChannel {
  public:
    virtual ~SessionChannel() = default;
    virtual bool open(bool control, const std::filesystem::path &serviceImage) = 0;
    virtual bool transact(wire::Frame request, wire::Frame &reply) = 0;
    virtual bool events(std::vector<wire::Frame> &batch) = 0;
    virtual void close() = 0;
    virtual const wire::Frame &hello() const = 0;
    virtual bool actualOsAuthenticated() const { return false; }
    virtual std::shared_ptr<const ReadPeerLease> readonlyPeer() const { return {}; }
};
class Client final : public SessionChannel {
  public:
    explicit Client(std::uint16_t minor = 1) : minor_(minor) {}
    ~Client() override { close(); }
    bool open(bool control, const std::filesystem::path &serviceImage);
    bool transact(wire::Frame request, wire::Frame &reply);
    bool events(std::vector<wire::Frame> &batch);
    void close();
    const wire::Frame &hello() const { return hello_; }
    bool control() const { return control_; }
    std::shared_ptr<const ReadPeerLease> readonlyPeer() const override {
        return std::atomic_load(&peer_);
    }
    bool actualOsAuthenticated() const override {
        return bool(pipe_) && control_ && !wire::zero(connection_);
    }

  private:
    bool authenticated();
    bool acquireReadonlyPeer();
    std::shared_ptr<ReadPeerLease> peer_;
    std::uint64_t peerGeneration_ = 0;
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
