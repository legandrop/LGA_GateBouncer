#include "client_ii_win.h"
namespace gb::ipc::ii {
void Client::close() {
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
    f.minor = 1;
    f.type = wire::Type::Hello;
    f.correlation = native::randomIdentity();
    f.fields = {wire::value(wire::Tag::ClientRole, control ? 2 : 1, 1)};
    wire::Frame response;
    if (!send(pipe_.value, f, nullptr) || !receive(pipe_.value, response, nullptr) ||
        response.minor != 1 || response.type != wire::Type::HelloAck || response.sequence != 1 ||
        response.correlation != f.correlation || wire::zero(response.connection) ||
        !authenticated()) {
        close();
        return false;
    }
    connection_ = response.connection;
    tx_ = rx_ = 2;
    hello_ = std::move(response);
    return true;
}
bool Client::transact(wire::Frame f, wire::Frame &out) {
    if (!authenticated() || tx_ == UINT64_MAX || rx_ == UINT64_MAX) {
        close();
        return false;
    }
    f.minor = 1;
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
        if (!receive(pipe_.value, reply, nullptr) || reply.minor != 1 ||
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
        if (!receive(pipe_.value, f, nullptr) || f.minor != 1 || f.connection != connection_ ||
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
