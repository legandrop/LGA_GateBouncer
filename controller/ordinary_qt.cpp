#include "ordinary_qt.h"
#ifdef _WIN32
#include <ordinary_iii_win.h>
#endif
namespace gb::controller {
OrdinarySession::OrdinarySession(QObject *parent, std::unique_ptr<ipc::ii::SessionChannel> channel)
    : QObject(parent), channel_(std::move(channel)) {
    qRegisterMetaType<wire::Frame>(); qRegisterMetaType<wire::Id>();
    worker_ = new QObject;
    worker_->moveToThread(&thread_);
    connect(&thread_, &QThread::finished, worker_, &QObject::deleteLater);
    thread_.start();
}
OrdinarySession::~OrdinarySession() {
    stop(); thread_.quit(); thread_.wait();
}
bool OrdinarySession::open(std::filesystem::path image) {
    if (stopping_ || pending_ || !channel_) return false;
    ++pending_;
    QMetaObject::invokeMethod(worker_, [this, image = std::move(image)] {
        const bool ok = !stopping_ && channel_->open(false, image);
        auto hello = ok ? channel_->hello() : wire::Frame{};
        std::shared_ptr<const wire::Id> connection;
#ifdef _WIN32
        if (ok) if (auto *ordinary = dynamic_cast<ipc::iii::OrdinaryClient *>(channel_.get())) {
            const auto original = ordinary->administrativeConnection();
            if (!wire::zero(original) && original == hello.connection) connection = std::make_shared<const wire::Id>(original);
        }
#endif
        // Un SessionChannel inyectado no puede fabricar esta procedencia.
        std::atomic_store(&administrativeConnection_,std::move(connection));
        --pending_; emit opened(ok && !stopping_, std::move(hello));
    });
    return true;
}
bool OrdinarySession::request(wire::Frame frame, quint64 generation) {
    if (stopping_ || pending_ || !channel_ || wire::zero(frame.correlation)) return false;
    ++pending_;
    QMetaObject::invokeMethod(worker_, [this, frame = std::move(frame), generation] {
        wire::Frame reply;
        const bool ok = !stopping_ && channel_->transact(frame, reply);
        std::vector<wire::Frame> beforeReply;
#ifdef _WIN32
        if (auto *ordinary = dynamic_cast<ipc::iii::OrdinaryClient *>(channel_.get()))
            ordinary->takeBuffered(beforeReply);
#endif
        // Mismo emisor/cola: todo evento anterior se entrega antes del ACK.
        for (auto &event : beforeReply) if (!stopping_) emit observation(std::move(event));
        --pending_; emit received(ok && !stopping_, std::move(reply), frame.correlation, generation);
    });
    return true;
}
bool OrdinarySession::pollEvents() {
    if (stopping_ || pending_ || !channel_) return false;
    ++pending_;
    QMetaObject::invokeMethod(worker_, [this] {
        std::vector<wire::Frame> batch;
        const bool ok = !stopping_ && channel_->events(batch);
        const auto count = unsigned(batch.size());
        for (auto &event : batch) if (!stopping_) emit observation(std::move(event));
        --pending_; emit observationsRead(ok && !stopping_,count);
    });
    return true;
}
void OrdinarySession::closeChannel() {
    if (stopping_ || !channel_) return;
    ++pending_;
    QMetaObject::invokeMethod(worker_,[this] { channel_->close(); --pending_; });
}
void OrdinarySession::stop() {
    if (stopping_.exchange(true)) return;
    ++pending_;
    QMetaObject::invokeMethod(worker_, [this] {
        if (channel_) channel_->close();
        --pending_;
    });
}
}
