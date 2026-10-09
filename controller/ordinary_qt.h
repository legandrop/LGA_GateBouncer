#pragma once
#include "session_qt.h"
namespace gb::controller {
// Worker separado: nunca abre Control ni comparte el lease readonly de View.
class OrdinarySession final : public QObject {
    Q_OBJECT
  public:
    explicit OrdinarySession(QObject *parent, std::unique_ptr<ipc::ii::SessionChannel> channel);
    ~OrdinarySession() override;
    bool open(std::filesystem::path image);
    bool request(wire::Frame frame, quint64 generation);
    void stop();
    bool idle() const { return pending_ == 0; }
  signals:
    void opened(bool ok, gb::wire::Frame hello);
    void received(bool ok, gb::wire::Frame reply, gb::wire::Id correlation, quint64 generation);
  private:
    QThread thread_;
    QObject *worker_ = nullptr;
    std::unique_ptr<ipc::ii::SessionChannel> channel_;
    std::atomic<unsigned> pending_{0};
    std::atomic<bool> stopping_{false};
};
}
