#include "client_ii_win.h"
#include "wire_iv.h"
#include <mutex>
namespace gb::ipc::ii {
struct ReadPeerLease::State {
    struct Api {
        decltype(&DuplicateHandle) duplicate = &DuplicateHandle;
        decltype(&CloseHandle) close = &CloseHandle;
        decltype(&PeekNamedPipe) peek = &PeekNamedPipe;
        decltype(&readableServerEvidence) evidence = &readableServerEvidence;
    } api;
    mutable std::mutex mutex;
    HANDLE pipe = nullptr;
    native::ProcessEvidence process;
    std::filesystem::path image;
    wire::Id connection{};
    std::uint64_t generation = 0;
    bool revoked = false;
    ~State() { if (pipe) api.close(pipe); }
    void revoke() noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex);
            revoked = true; // Antes de cerrar: un lease anterior nunca resucita.
            if (pipe && api.close(pipe)) pipe = nullptr;
        } catch (...) { std::terminate(); }
    }
};
wire::Id ReadPeerLease::connection() const noexcept { return state_->connection; }
void ReadPeerLease::revoke() const noexcept { state_->revoke(); }
ReadPeerState ReadPeerLease::checkLive() const noexcept {
    try {
        std::unique_lock<std::mutex> lock(state_->mutex, std::try_to_lock);
        if (!lock.owns_lock()) return ReadPeerState::Unavailable;
        if (state_->revoked) return ReadPeerState::Closed;
        if (!state_->pipe || !state_->generation || wire::zero(state_->connection) ||
            !state_->process.current() ||
            !state_->api.peek(state_->pipe, nullptr, 0, nullptr, nullptr, nullptr))
            return ReadPeerState::Unavailable;
        native::ProcessEvidence current;
        if (!state_->api.evidence(state_->pipe, state_->image, current) ||
            !current.current() || !state_->process.current())
            return ReadPeerState::Unavailable;
        return current.pid == state_->process.pid &&
               CompareFileTime(&current.created, &state_->process.created) == 0 &&
               current.image == state_->process.image
                   ? ReadPeerState::Current : ReadPeerState::Replaced;
    } catch (...) { return ReadPeerState::Unavailable; }
}
bool Client::acquireReadonlyPeer() {
    if (control_) return true;
    if (peerGeneration_ == UINT64_MAX) return false;
    auto state = std::make_shared<ReadPeerLease::State>();
    state->image = image_;
    state->connection = connection_;
    if (!state->api.duplicate(GetCurrentProcess(), pipe_.value, GetCurrentProcess(),
                              &state->pipe, 0, FALSE, DUPLICATE_SAME_ACCESS) ||
        !state->api.evidence(state->pipe, state->image, state->process) ||
        state->process.pid != server_.pid ||
        CompareFileTime(&state->process.created, &server_.created) != 0 ||
        state->process.image != server_.image) return false;
    state->generation = ++peerGeneration_;
    std::atomic_store(&peer_, std::shared_ptr<ReadPeerLease>(new ReadPeerLease(std::move(state))));
    return true;
}
void Client::close() {
    if (auto peer = std::atomic_exchange(&peer_, std::shared_ptr<ReadPeerLease>{}))
        peer->state_->revoke();
    pipe_.reset();
    connection_ = {};
    tx_ = rx_ = 1;
    hello_ = {};
    bufferedEvents_.clear();
    server_ = {};
}
bool Client::authenticated() {
    native::ProcessEvidence proof;
    if (!pipe_ || !readableServerEvidence(pipe_.value, image_, proof))
        return false;
    if (server_.pid &&
        (proof.pid != server_.pid || CompareFileTime(&proof.created, &server_.created) != 0))
        return false;
    if (control_) {
        native::ProcessEvidence full;
        if (!serverEvidence(pipe_.value, full) || full.pid != proof.pid ||
            CompareFileTime(&full.created, &proof.created) != 0)
            return false;
    }
    server_ = std::move(proof);
    return true;
}
bool Client::open(bool control, const std::filesystem::path &image) {
    close();
    if ((minor_ != 1 && minor_ != 2 && minor_ != 3) || (control && minor_ == 3)) return false;
    control_ = control;
    image_ = image;
    auto name = control ? L"\\\\.\\pipe\\LGA.GateBouncer.Control.v1"
                        : L"\\\\.\\pipe\\LGA.GateBouncer.View.v1";
    pipe_.reset(CreateFileW(name, ClientAccess, 0, nullptr, OPEN_EXISTING,
                            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
                            nullptr));
    if (!pipe_ || !authenticated()) {
        close();
        return false;
    }
    wire::Frame f;
    f.minor = minor_;
    f.type = wire::Type::Hello;
    f.correlation = native::randomIdentity();
    f.fields = {wire::value(wire::Tag::ClientRole, control ? 2 : 1, 1)};
    wire::Frame response;
    if (!send(pipe_.value, f, nullptr) || !receive(pipe_.value, response, nullptr) ||
        response.minor != minor_ || response.type != wire::Type::HelloAck || response.sequence != 1 ||
        response.correlation != f.correlation || wire::zero(response.connection) ||
        !authenticated()) {
        close();
        return false;
    }
    connection_ = response.connection;
    if (minor_ == 3) {
        wire::iv::ServiceContext context;
        if (wire::iv::decodeServiceContext(response, context) != wire::Error::Ok) {
            close(); return false;
        }
    }
    tx_ = rx_ = 2;
    hello_ = std::move(response);
    try {
        if (!acquireReadonlyPeer()) { close(); return false; }
    } catch (...) { close(); return false; }
    return true;
}
bool Client::transact(wire::Frame f, wire::Frame &out) {
    if (!authenticated() || tx_ == UINT64_MAX || rx_ == UINT64_MAX) {
        close();
        return false;
    }
    f.minor = minor_;
    f.connection = connection_;
    f.sequence = tx_++;
    if (wire::zero(f.correlation))
        f.correlation = native::randomIdentity();
    if (!send(pipe_.value, f, nullptr)) {
        close();
        return false;
    }
    for (unsigned n = 0; n <= 512; ++n) {
        wire::Frame reply;
        if (!receive(pipe_.value, reply, nullptr) || reply.minor != minor_ ||
            reply.connection != connection_ || reply.sequence != rx_++ ||
            (reply.type != wire::Type::ProtocolError &&
             wire::idValue(reply, wire::Tag::ServiceEpoch) !=
                 wire::idValue(hello_, wire::Tag::ServiceEpoch)) ||
            !authenticated()) {
            close();
            return false;
        }
        if (reply.type == wire::Type::Attempt || reply.type == wire::Type::ObservationGap ||
            reply.type == wire::Type::Authorization) {
            if (bufferedEvents_.size() == 512) {
                close();
                return false;
            }
            if (wire::get(reply, wire::Tag::Source) != 1 ||
                (reply.type == wire::Type::Attempt &&
                 !(wire::get(hello_, wire::Tag::Capabilities) & (1ull << 14))) ||
                (reply.type == wire::Type::Authorization &&
                 !(wire::get(hello_, wire::Tag::Capabilities) & (1ull << 15)))) {
                close();
                return false;
            }
            bufferedEvents_.push_back(std::move(reply));
            continue;
        }
        if (reply.type != wire::Type::ProtocolError && reply.correlation != f.correlation) {
            close();
            return false;
        }
        if (reply.correlation != f.correlation) {
            close();
            return false;
        }
        out = std::move(reply);
        if (minor_ == 3 && out.type == wire::Type::Status) {
            wire::iv::ServiceContext context;
            if (wire::iv::decodeServiceContext(out, context) != wire::Error::Ok) {
                out = {}; close(); return false;
            }
        }
        return true;
    }
    close();
    return false;
}
bool Client::events(std::vector<wire::Frame> &out) {
    out.assign(bufferedEvents_.begin(), bufferedEvents_.end());
    bufferedEvents_.clear();
    if (!authenticated())
        return false;
    DWORD available = 0;
    while (PeekNamedPipe(pipe_.value, nullptr, 0, nullptr, &available, nullptr) && available) {
        if (out.size() == 512 || rx_ == UINT64_MAX) {
            close();
            return false;
        }
        wire::Frame f;
        if (!receive(pipe_.value, f, nullptr) || f.minor != minor_ || f.connection != connection_ ||
            f.sequence != rx_++ ||
            (f.type != wire::Type::Attempt && f.type != wire::Type::ObservationGap &&
             f.type != wire::Type::Authorization)) {
            close();
            return false;
        }
        if (wire::idValue(f, wire::Tag::ServiceEpoch) !=
                wire::idValue(hello_, wire::Tag::ServiceEpoch) ||
            wire::get(f, wire::Tag::Source) != 1 ||
            (f.type == wire::Type::Attempt &&
             !(wire::get(hello_, wire::Tag::Capabilities) & (1ull << 14))) ||
            (f.type == wire::Type::Authorization &&
             !(wire::get(hello_, wire::Tag::Capabilities) & (1ull << 15)))) {
            close();
            return false;
        }
        out.push_back(std::move(f));
    }
    return authenticated();
}
} // namespace gb::ipc::ii
