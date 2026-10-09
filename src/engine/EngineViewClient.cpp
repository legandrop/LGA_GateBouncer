#include "EngineViewClient.h"
#include <QMetaObject>
#include <QUuid>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winsvc.h>
#include <vector>

namespace Gate {
namespace {
using namespace gb::wire;
Id freshId() {
    const auto bytes = QUuid::createUuid().toRfc4122();
    Id id{};
    std::copy(bytes.begin(), bytes.end(), id.begin());
    return id;
}
class Handle {
  public:
    HANDLE value = INVALID_HANDLE_VALUE;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
class ServiceHandle {
  public:
    SC_HANDLE value = nullptr;
    ~ServiceHandle() { if (value) CloseServiceHandle(value); }
};
// Constantes del contrato del servicio; nunca se toman de datos enviados por el peer.
constexpr wchar_t ServiceName[] = L"LGAGateBouncerLab";
constexpr wchar_t ViewPipe[] = L"\\\\.\\pipe\\LGA.GateBouncer.View.v1";
class LocalViewChannel final : public ViewByteChannel {
  public:
    explicit LocalViewChannel(std::atomic_bool &cancelled) : cancelled_(cancelled) {}
    bool authenticate() override {
        pipe_.value = CreateFileW(ViewPipe, FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, 0, nullptr,
            OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (pipe_.value == INVALID_HANDLE_VALUE || cancelled_) return false;
        ULONG pid = 0;
        if (!GetNamedPipeServerProcessId(pipe_.value, &pid) || !pid) return false;
        manager_.value = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!manager_.value) return false;
        service_.value = OpenServiceW(manager_.value, ServiceName, SERVICE_QUERY_STATUS);
        if (!service_.value) return false;
        SERVICE_STATUS_PROCESS status{};
        DWORD needed = 0;
        if (!QueryServiceStatusEx(service_.value, SC_STATUS_PROCESS_INFO,
                 reinterpret_cast<BYTE *>(&status), sizeof(status), &needed) ||
            status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId != pid ||
            status.dwServiceType != SERVICE_WIN32_OWN_PROCESS) return false;
        process_.value = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
        if (!process_.value) return false;
        FILETIME exit{}, kernel{}, user{};
        if (!GetProcessTimes(process_.value, &creation_, &exit, &kernel, &user) ||
            WaitForSingleObject(process_.value, 0) != WAIT_TIMEOUT) return false;
        if (!OpenProcessToken(process_.value, TOKEN_QUERY, &token_.value)) return false;
        std::vector<BYTE> tokenUser;
        if (!tokenInfo(TokenUser, tokenUser)) return false;
        BYTE systemSid[SECURITY_MAX_SID_SIZE]; DWORD systemSize = sizeof(systemSid);
        if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid, &systemSize) ||
            !EqualSid(reinterpret_cast<TOKEN_USER *>(tokenUser.data())->User.Sid, systemSid)) return false;
        DWORD sidSize = 0, domainSize = 0; SID_NAME_USE use{};
        LookupAccountNameW(nullptr, L"NT SERVICE\\LGAGateBouncerLab", nullptr, &sidSize,
                           nullptr, &domainSize, &use);
        if (!sidSize || sidSize > SECURITY_MAX_SID_SIZE || domainSize > 256) return false;
        std::vector<BYTE> sid(sidSize); std::vector<wchar_t> domain(domainSize);
        if (!LookupAccountNameW(nullptr, L"NT SERVICE\\LGAGateBouncerLab", sid.data(), &sidSize,
                                domain.data(), &domainSize, &use)) return false;
        std::vector<BYTE> tokenGroups;
        if (!tokenInfo(TokenGroups, tokenGroups)) return false;
        const auto *groups = reinterpret_cast<TOKEN_GROUPS *>(tokenGroups.data());
        bool found = false;
        for (DWORD i = 0; i < groups->GroupCount; ++i)
            if ((groups->Groups[i].Attributes & SE_GROUP_ENABLED) &&
                !(groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY) &&
                EqualSid(groups->Groups[i].Sid, sid.data())) found = true;
        // CreateFile inicia byte-read mode; no ampliar derechos para un setter innecesario.
        return found && samePeer();
    }
    bool write(const Bytes &bytes) override {
        deadline_ = GetTickCount64() + 5000;
        DWORD done = 0;
        return samePeer() && transfer(false, const_cast<std::uint8_t *>(bytes.data()),
                                     DWORD(bytes.size()), done) && done == bytes.size();
    }
    bool read(Bytes &bytes) override {
        bytes.resize(4096); DWORD done = 0;
        if (!samePeer() || !transfer(true, bytes.data(), DWORD(bytes.size()), done) || !done) {
            bytes.clear(); return false;
        }
        bytes.resize(done); return samePeer();
    }
  private:
    bool tokenInfo(TOKEN_INFORMATION_CLASS kind, std::vector<BYTE> &bytes) {
        DWORD size = 0; GetTokenInformation(token_.value, kind, nullptr, 0, &size);
        if (!size || size > 65536) return false;
        bytes.resize(size);
        return GetTokenInformation(token_.value, kind, bytes.data(), size, &size);
    }
    bool samePeer() {
        if (cancelled_ || WaitForSingleObject(process_.value, 0) != WAIT_TIMEOUT) return false;
        ULONG pid = 0; SERVICE_STATUS_PROCESS status{}; DWORD needed = 0;
        FILETIME creation{}, exit{}, kernel{}, user{};
        return GetNamedPipeServerProcessId(pipe_.value, &pid) &&
            QueryServiceStatusEx(service_.value, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<BYTE *>(&status), sizeof(status), &needed) &&
            status.dwCurrentState == SERVICE_RUNNING && status.dwServiceType == SERVICE_WIN32_OWN_PROCESS &&
            status.dwProcessId == pid && pid == GetProcessId(process_.value) &&
            GetProcessTimes(process_.value, &creation, &exit, &kernel, &user) &&
            CompareFileTime(&creation, &creation_) == 0;
    }
    bool transfer(bool reading, void *buffer, DWORD size, DWORD &done) {
        Handle event; event.value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!event.value) return false;
        OVERLAPPED operation{}; operation.hEvent = event.value;
        const BOOL started = reading ? ReadFile(pipe_.value, buffer, size, &done, &operation)
                                     : WriteFile(pipe_.value, buffer, size, &done, &operation);
        if (started) return true;
        if (GetLastError() != ERROR_IO_PENDING) return false;
        while (!cancelled_ && GetTickCount64() < deadline_) {
            if (WaitForSingleObject(event.value, 50) == WAIT_OBJECT_0)
                return GetOverlappedResult(pipe_.value, &operation, &done, FALSE);
        }
        // CancelIoEx no libera la operacion: se drena antes de destruir OVERLAPPED/buffer.
        CancelIoEx(pipe_.value, &operation);
        GetOverlappedResult(pipe_.value, &operation, &done, TRUE);
        return false;
    }
    std::atomic_bool &cancelled_;
    Handle pipe_, process_, token_;
    ServiceHandle manager_, service_;
    FILETIME creation_{};
    ULONGLONG deadline_ = 0;
};
bool exchange(ViewByteChannel &channel, const Frame &request, Type expected, Frame &reply) {
    Bytes bytes;
    if (encode(request, bytes) != Error::Ok || !channel.write(bytes)) return false;
    Decoder decoder;
    const auto start = GetTickCount64();
    while (GetTickCount64() - start < 5000) {
        if (!channel.read(bytes) || bytes.empty()) return false;
        std::vector<Frame> frames;
        if (decoder.feed(bytes.data(), bytes.size(), frames) != Error::Ok) return false;
        if (!frames.empty()) {
            if (frames.size() != 1 || decoder.incomplete()) return false;
            reply = std::move(frames.front());
            return reply.minor == request.minor && reply.type == expected && reply.correlation == request.correlation &&
                   reply.sequence == request.sequence &&
                   (expected == Type::HelloAck ? !zero(reply.connection)
                                              : reply.connection == request.connection);
        }
    }
    return false;
}
} // namespace
EngineStatus queryViewStatus(ViewByteChannel &channel) {
    using namespace gb::wire;
    EngineStatus result;
    result.error = "Engine authentication or status unavailable";
    if (!channel.authenticate()) return result;
    Frame hello; hello.type = Type::Hello; hello.correlation = freshId();
    hello.fields = {value(Tag::ClientRole, 1, 1)};
    Frame ack;
    if (!exchange(channel, hello, Type::HelloAck, ack) || !(get(ack, Tag::Capabilities) & ReadStatus) ||
        (get(ack, Tag::Capabilities) & ~quint64(63)) || zero(idValue(ack, Tag::ServiceEpoch)) ||
        zero(idValue(ack, Tag::BootId))) return result;
    Frame request; request.connection = ack.connection; request.sequence = 2;
    request.correlation = freshId();
    Frame status;
    if (!exchange(channel, request, Type::Status, status) ||
        idValue(status, Tag::ServiceEpoch) != idValue(ack, Tag::ServiceEpoch) ||
        idValue(status, Tag::BootId) != idValue(ack, Tag::BootId) ||
        (get(status, Tag::Capabilities) & ~quint64(63))) return result;
    result.current = true; result.error.clear();
    result.serviceEpoch = idValue(status, Tag::ServiceEpoch); result.bootId = idValue(status, Tag::BootId);
    result.connection = status.connection; result.capabilities = get(status, Tag::Capabilities);
    result.desired = get(status, Tag::DesiredRev); result.effective = get(status, Tag::EffectiveRev);
    result.effectiveKnown = get(status, Tag::EffectiveKnown); result.gaps = get(status, Tag::GapCount);
    result.state = EngineState(get(status, Tag::EngineState)); result.backend = BackendMode(get(status, Tag::BackendMode));
    return result;
}
EngineViewClient::EngineViewClient(bool isolatedQa, QObject *parent)
    : QObject(parent), isolatedQa_(isolatedQa) {}
EngineViewClient::~EngineViewClient() {
    cancelled_ = true;
    if (worker_) { worker_->wait(); delete worker_; }
}
void EngineViewClient::invalidate() {
    ++generation_; cancelled_ = true; status_.current = false; emit changed();
}
bool EngineViewClient::refresh() {
    if (worker_ && worker_->isRunning()) return false;
    if (worker_) { delete worker_; worker_ = nullptr; }
    if (isolatedQa_) { status_.error = "Engine access disabled in isolated QA"; emit changed(); return false; }
    cancelled_ = false; const auto generation = ++generation_;
    status_.current = false; status_.error = "Reading engine status…"; emit changed();
    worker_ = QThread::create([this, generation] {
        LocalViewChannel channel(cancelled_); const auto result = queryViewStatus(channel);
        QMetaObject::invokeMethod(this, [this, generation, result] {
            if (generation != generation_) return;
            if (result.current) status_ = result;
            else { status_.current = false; status_.error = result.error; }
            emit changed();
        }, Qt::QueuedConnection);
    });
    worker_->start(); return true;
}
} // namespace Gate
