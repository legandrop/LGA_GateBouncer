#include "session_qt.h"
namespace gb::controller {
Session::Session(QObject *parent, std::unique_ptr<ipc::ii::SessionChannel> channel, std::uint16_t minor)
    : QObject(parent), client_(channel ? std::move(channel) : std::make_unique<ipc::ii::Client>(minor)) {
    qRegisterMetaType<wire::Frame>();
    qRegisterMetaType<wire::Id>();
    worker_ = new QObject;
    worker_->moveToThread(&thread_);
    connect(&thread_, &QThread::finished, worker_, &QObject::deleteLater);
    thread_.start();
}
Session::~Session() {
    stopping_ = true;
    if (auto peer = std::atomic_exchange(&readonlyPeer_, std::shared_ptr<const ipc::ii::ReadPeerLease>{}))
        peer->revoke();
    thread_.quit();
    thread_.wait();
}
void Session::done() {
    --pending_;
    if (stopping_ && pending_ == 0)
        emit drained();
}
bool Session::open(bool control, std::filesystem::path image) {
    if (stopping_ || pending_ != 0)
        return false;
    ++pending_;
    QMetaObject::invokeMethod(worker_, [this, control, image = std::move(image)] {
        bool ok = !stopping_ && client_->open(control, image);
        nativeAuthenticated_ = ok && client_->actualOsAuthenticated();
        // Un double no puede tomar prestado el lease de otro Client nativo.
        auto nativeClient = dynamic_cast<ipc::ii::Client *>(client_.get());
        std::atomic_store(&readonlyPeer_, ok && nativeClient ? nativeClient->readonlyPeer() : nullptr);
        if (stopping_) {
            if (auto peer = std::atomic_exchange(&readonlyPeer_, std::shared_ptr<const ipc::ii::ReadPeerLease>{}))
                peer->revoke();
            client_->close();
            ok = false;
        }
        emit opened(ok, ok ? client_->hello() : wire::Frame{});
        done();
    });
    return true;
}
bool Session::request(wire::Frame f) {
    if (stopping_ || pending_ >= 8 || wire::zero(f.correlation))
        return false;
    ++pending_;
    QMetaObject::invokeMethod(worker_, [this, f = std::move(f)] {
        wire::Frame reply;
        auto request = f;
        request.minor = client_->hello().minor;
        bool ok = !stopping_ && (request.minor == 1 || request.minor == 2 || request.minor == 3) && client_->transact(request, reply);
        emit received(ok, std::move(reply), f.correlation);
        if (ok) {
            std::vector<wire::Frame> events;
            if (client_->events(events))
                for (auto &event : events)
                    emit observation(std::move(event));
            else {
                nativeAuthenticated_ = false;
                emit received(false, wire::Frame{}, wire::Id{});
            }
        }
        done();
    });
    return true;
}
void Session::stop() {
    if (stopping_.exchange(true))
        return;
    if (auto peer = std::atomic_exchange(&readonlyPeer_, std::shared_ptr<const ipc::ii::ReadPeerLease>{}))
        peer->revoke();
    ++pending_;
    QMetaObject::invokeMethod(worker_, [this] {
        nativeAuthenticated_ = false;
        client_->close();
        done();
    });
}
} // namespace gb::controller
