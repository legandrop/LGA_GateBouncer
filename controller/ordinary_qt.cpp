#include "ordinary_qt.h"
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
        --pending_; emit received(ok && !stopping_, std::move(reply), frame.correlation, generation);
    });
    return true;
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
