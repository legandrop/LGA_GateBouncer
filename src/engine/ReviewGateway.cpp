#include "ReviewGateway.h"
#include "../../common/pipe_ii_win.h"
#include "../../common/pipe_rights_ii.h"
#include "../../common/review_open.h"
#include "../../controller/deployment_win.h"
#include <QCoreApplication>
#include <QUuid>
#include <algorithm>
#include <shellapi.h>

namespace Gate {
namespace {
using namespace gb;
wire::Id correlation() {
    const auto b = QUuid::createUuid().toRfc4122();
    wire::Id id{};
    std::copy_n(reinterpret_cast<const unsigned char *>(b.constData()), 16, id.begin());
    return id;
}
bool write(HANDLE pipe, const wire::Frame &f) {
    wire::Bytes b;
    return review::encode(f, b) == wire::Error::Ok &&
           ipc::ii::transfer(pipe, true, b, b.size(), nullptr);
}
bool read(HANDLE pipe, wire::Frame &f) {
    const auto start = GetTickCount64();
    wire::Bytes b;
    if (!ipc::ii::transfer(pipe, false, b, 64, nullptr) || b[0] != 'G' || b[1] != 'B' ||
        b[2] != 'R' || b[3] != '1')
        return false;
    std::size_t count = 0;
    for (unsigned i = 0; i < 4; ++i)
        count |= std::size_t(b[12 + i]) << (8 * i);
    if (count > 448)
        return false;
    if (count) {
        wire::Bytes body;
        const auto elapsed = GetTickCount64() - start;
        if (elapsed >= 5000 ||
            !ipc::ii::transfer(pipe, false, body, count, nullptr, DWORD(5000 - elapsed)))
            return false;
        b.insert(b.end(), body.begin(), body.end());
    }
    return GetTickCount64() - start < 5000 && review::decode(b, f) == wire::Error::Ok;
}
bool peer(HANDLE pipe, const std::filesystem::path &image, const native::TokenEvidence &own,
          native::ProcessEvidence &evidence) {
    ULONG pid = 0;
    HANDLE raw = nullptr;
    if (!GetNamedPipeServerProcessId(pipe, &pid) || !evidence.acquire(pid) ||
        !ipc::ii::ownClient(evidence, image) ||
        !OpenProcessToken(evidence.process.value, TOKEN_QUERY, &raw))
        return false;
    native::Handle token(raw);
    native::TokenEvidence server;
    return native::tokenEvidence(token.value, server) && server.administrator && server.elevated &&
           !server.uiAccess && server.integrity >= SECURITY_MANDATORY_HIGH_RID &&
           native::equalSidBytes(own.account, server.account) &&
           native::equalSidBytes(own.logon, server.logon) && own.session == server.session &&
           evidence.current();
}
class NativeReviewBackend final : public ReviewBackend {
  public:
    QString launch(const std::filesystem::path &root) override {
        auto image = root / L"GateBouncerDecisionBootstrap.exe";
        controller::Deployment package(root);
        if (!package.verify(image))
            return "Protected reviewer deployment is unavailable";
        SHELLEXECUTEINFOW info{};
        info.cbSize = sizeof(info);
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        info.lpVerb = L"runas";
        info.lpFile = image.c_str();
        info.lpDirectory = root.c_str();
        info.nShow = SW_SHOWNORMAL;
        if (!ShellExecuteExW(&info))
            return GetLastError() == ERROR_CANCELLED
                       ? "Administrator enablement was cancelled"
                       : "Administrator reviewer could not be started";
        native::Handle process(info.hProcess);
        // Lanzado no equivale a canal autenticado ni a decisión/protección aplicada.
        return {};
    }
    QString open(const std::filesystem::path &root, ReviewReference reference) override {
        if (wire::zero(reference.epoch) || wire::zero(reference.request) || !reference.profile)
            return "The request reference is stale";
        controller::Deployment package(root);
        auto image = root / L"GateBouncerDecisionBootstrap.exe";
        if (!package.verify(image))
            return "Protected reviewer deployment is unavailable";
        HANDLE raw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
            return "Account identity is unavailable";
        native::Handle ownToken(raw);
        native::TokenEvidence own;
        if (!native::tokenEvidence(ownToken.value, own))
            return "Account identity is unavailable";
        native::Handle pipe(CreateFileW(L"\\\\.\\pipe\\LGA.GateBouncer.ReviewOpen.v1",
                                        ipc::ii::ClientAccess, 0, nullptr, OPEN_EXISTING,
                                        FILE_FLAG_OVERLAPPED, nullptr));
        native::ProcessEvidence helper;
        ipc::ii::Principals principals{own.account, own.logon, {}};
        if (!pipe ||
            !ipc::ii::exactDescriptor(
                pipe.value, ipc::ii::descriptor(ipc::ii::Channel::ReviewOpen, principals)) ||
            !peer(pipe.value, image, own, helper))
            return "Authenticated administrator reviewer is unavailable";
        wire::Frame hello;
        hello.type = wire::Type::Hello;
        hello.correlation = correlation();
        hello.fields = {wire::value(wire::Tag::ClientRole, 1, 1)};
        wire::Frame ack;
        if (!write(pipe.value, hello) || !read(pipe.value, ack) ||
            ack.type != wire::Type::HelloAck || ack.sequence != 1 ||
            ack.correlation != hello.correlation ||
            wire::idValue(ack, wire::Tag::Records) != reference.epoch ||
            wire::get(ack, wire::Tag::ProfileGeneration) != reference.profile || !helper.current())
            return "Administrator reviewer binding changed";
        wire::Frame request;
        request.type = wire::Type::GetStatus;
        request.sequence = 2;
        request.connection = ack.connection;
        request.correlation = correlation();
        request.fields = {wire::value(wire::Tag::RequestId, reference.request),
                          wire::value(wire::Tag::Records, reference.epoch),
                          wire::value(wire::Tag::ProfileGeneration, reference.profile)};
        wire::Frame result;
        native::ProcessEvidence after;
        if (!peer(pipe.value, image, own, after) || after.pid != helper.pid ||
            CompareFileTime(&after.created, &helper.created) != 0 || !write(pipe.value, request) ||
            !read(pipe.value, result) || result.type != wire::Type::Status ||
            result.sequence != 2 || result.connection != request.connection ||
            result.correlation != request.correlation || !peer(pipe.value, image, own, after) ||
            after.pid != helper.pid || CompareFileTime(&after.created, &helper.created) != 0 ||
            !helper.current())
            return "Administrator review queue is unavailable";
        return wire::get(result, wire::Tag::ErrorCode) == 0
                   ? QString{}
                   : "Administrator review was not queued (" +
                         QString::number(wire::get(result, wire::Tag::ErrorCode)) + ")";
    }
};
} // namespace
ReviewGateway::ReviewGateway(bool isolatedQa, QObject *parent,
                             std::unique_ptr<ReviewBackend> backend)
    : QObject(parent), isolatedQa_(isolatedQa && !backend),
      backend_(backend ? std::move(backend) : std::make_unique<NativeReviewBackend>()) {}
ReviewGateway::~ReviewGateway() {
    stop();
    if (worker_) {
        worker_->wait();
        delete worker_;
    }
}
void ReviewGateway::stop() {
    stopped_ = true;
    ++generation_;
}
void ReviewGateway::invalidate() {
    ++generation_;
    status_ = "Review reference invalidated; no decision was made";
    emit changed();
}
bool ReviewGateway::launch() { return !launched_ && run(true, {}); }
bool ReviewGateway::open(ReviewReference reference) { return run(false, reference); }
bool ReviewGateway::run(bool launch, ReviewReference reference) {
    if (stopped_ || !idle())
        return false;
    if (isolatedQa_) {
        status_ = "Native reviewer and elevation are disabled in isolated QA";
        emit changed();
        return false;
    }
    if (worker_) {
        delete worker_;
        worker_ = nullptr;
    }
    const auto generation = ++generation_;
    const auto root = std::filesystem::path(QCoreApplication::applicationDirPath().toStdWString());
    status_ = launch ? "Waiting for explicit administrator enablement"
                     : "Requesting a review queue entry";
    emit changed();
    worker_ = QThread::create([this, root, reference, launch, generation] {
        const auto error = launch ? backend_->launch(root) : backend_->open(root, reference);
        QMetaObject::invokeMethod(
            this,
            [this, launch, generation, error] {
                if (stopped_ || generation != generation_)
                    return;
                if (launch && error.isEmpty())
                    launched_ = true;
                status_ =
                    error.isEmpty()
                        ? (launch
                               ? "Reviewer launch requested. Connect its session in its own window."
                               : "Review queued. Confirm only in the administrator reviewer; the "
                                 "active review and input are unchanged.")
                        : error;
                emit changed();
            },
            Qt::QueuedConnection);
    });
    worker_->start();
    return true;
}
} // namespace Gate
