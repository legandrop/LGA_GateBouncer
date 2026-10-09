#include "review_ingress.h"
namespace gb::controller {
namespace {
using namespace wire;
const std::wstring Pipe = L"\\\\.\\pipe\\LGA.GateBouncer.ReviewOpen.v1";
bool read(HANDLE pipe, Frame &f, HANDLE stop) {
    const auto started = GetTickCount64();
    constexpr DWORD budget = 5000;
    Bytes b;
    if (!ipc::ii::transfer(pipe, false, b, 64, stop) || b[0] != 'G' || b[1] != 'B' || b[2] != 'R' ||
        b[3] != '1')
        return false;
    std::size_t count = 0;
    for (unsigned i = 0; i < 4; ++i)
        count |= std::size_t(b[12 + i]) << (i * 8);
    if (count > 448)
        return false;
    if (count) {
        Bytes body;
        const auto elapsed = GetTickCount64() - started;
        if (elapsed >= budget ||
            !ipc::ii::transfer(pipe, false, body, count, stop, DWORD(budget - elapsed)))
            return false;
        b.insert(b.end(), body.begin(), body.end());
    }
    return GetTickCount64() - started < budget && review::decode(b, f) == Error::Ok;
}
bool write(HANDLE pipe, const Frame &f, HANDLE stop) {
    Bytes b;
    return review::encode(f, b) == Error::Ok && ipc::ii::transfer(pipe, true, b, b.size(), stop);
}
} // namespace
ReviewIngress::ReviewIngress(std::filesystem::path root, native::TokenEvidence identity, Id epoch,
                             std::uint64_t profile, Resolve resolve)
    : root_(std::move(root)), identity_(std::move(identity)),
      helperEpoch_(native::randomIdentity()), epoch_(epoch), profile_(profile),
      resolve_(std::move(resolve)) {}
ReviewIngress::~ReviewIngress() { stop(); }
bool ReviewIngress::start() {
    if (thread_.joinable() || !stop_ || !identity_.administrator || !identity_.elevated ||
        identity_.uiAccess || identity_.integrity < SECURITY_MANDATORY_HIGH_RID || zero(epoch_) ||
        !profile_)
        return false;
    ipc::ii::Principals p{identity_.account, identity_.logon, {}};
    anchor_ = ipc::ii::anchor(Pipe, ipc::ii::Channel::ReviewOpen, p);
    if (!anchor_)
        return false;
    running_ = true;
    thread_ = std::thread([this] {
        try {
            run();
        } catch (...) { /* Ingreso perdido nunca decide. */
        }
        running_ = false;
    });
    return true;
}
void ReviewIngress::stop() {
    if (stop_)
        SetEvent(stop_.value);
    if (thread_.joinable())
        thread_.join();
    anchor_.reset();
}
bool ReviewIngress::peer(HANDLE pipe) const {
    native::TokenEvidence token;
    native::ProcessEvidence process;
    return ipc::ii::clientEvidence(pipe, token, process) &&
           token.integrity >= SECURITY_MANDATORY_MEDIUM_RID &&
           native::equalSidBytes(token.account, identity_.account) &&
           native::equalSidBytes(token.logon, identity_.logon) &&
           token.session == identity_.session &&
           ipc::ii::ownClient(process, root_ / L"GateBouncer.exe");
}
void ReviewIngress::run() {
    ipc::ii::Principals p{identity_.account, identity_.logon, {}};
    auto lastRefill = GetTickCount64();
    unsigned tokens = 2;
    while (WaitForSingleObject(stop_.value, 0) == WAIT_TIMEOUT) {
        auto pipe = ipc::ii::instance(Pipe, ipc::ii::Channel::ReviewOpen, p);
        if (!pipe)
            return;
        if (!ipc::ii::connect(pipe.value, stop_.value))
            continue;
        Frame hello;
        if (!read(pipe.value, hello, stop_.value) || unsigned(hello.type) != 1 ||
            !peer(pipe.value)) {
            DisconnectNamedPipe(pipe.value);
            continue;
        }
        auto connection = native::randomIdentity();
        Frame ack;
        ack.type = Type::HelloAck;
        ack.connection = connection;
        ack.correlation = hello.correlation;
        ack.fields = {value(Tag::ServiceEpoch, helperEpoch_), value(Tag::Records, epoch_),
                      value(Tag::ProfileGeneration, profile_)};
        if (!write(pipe.value, ack, stop_.value)) {
            DisconnectNamedPipe(pipe.value);
            continue;
        }
        std::uint64_t rx = 2, tx = 2, lastActivity = GetTickCount64();
        while (WaitForSingleObject(stop_.value, 0) == WAIT_TIMEOUT &&
               GetTickCount64() - lastActivity < 60000) {
            DWORD available = 0;
            if (!PeekNamedPipe(pipe.value, nullptr, 0, nullptr, &available, nullptr))
                break;
            if (!available) {
                WaitForSingleObject(stop_.value, 50);
                continue;
            }
            Frame f;
            if (!read(pipe.value, f, stop_.value) || unsigned(f.type) != 3 ||
                f.connection != connection || f.sequence != rx++ || rx == UINT64_MAX ||
                tx == UINT64_MAX || !peer(pipe.value))
                break;
            auto now = GetTickCount64();
            auto elapsed = (now - lastRefill) / 1000;
            if (elapsed) {
                tokens = unsigned(std::min<std::uint64_t>(2, tokens + elapsed));
                lastRefill = now;
            }
            Error error = Error::Capacity;
            if (tokens) {
                --tokens;
                error =
                    idValue(f, Tag::Records) == epoch_ && get(f, Tag::ProfileGeneration) == profile_
                        ? resolve_({epoch_, idValue(f, Tag::RequestId), profile_})
                        : Error::Stale;
            }
            Frame response;
            response.type = Type::Status;
            response.connection = connection;
            response.sequence = tx++;
            response.correlation = f.correlation;
            response.fields = {value(Tag::ErrorCode, unsigned(error), 2)};
            if (!write(pipe.value, response, stop_.value))
                break;
            lastActivity = now;
        }
        DisconnectNamedPipe(pipe.value);
    }
}
} // namespace gb::controller
