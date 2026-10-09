#pragma once
#include "../common/client_ii_win.h"
#include <QObject>
#include <QThread>
#include <atomic>
#include <memory>
Q_DECLARE_METATYPE(gb::wire::Frame)
namespace gb::controller {
class Session : public QObject {
    Q_OBJECT
  public:
    explicit Session(QObject *parent = nullptr,
                     std::unique_ptr<ipc::ii::SessionChannel> channel = {});
    ~Session() override;
    bool open(bool control, std::filesystem::path serviceImage);
    bool request(wire::Frame request);
    void stop();
    bool idle() const { return pending_ == 0; }
    bool actualOsAuthenticated() const { return nativeAuthenticated_; }
  signals:
    void opened(bool authenticated, gb::wire::Frame status);
    void received(bool authenticated, gb::wire::Frame response, gb::wire::Id correlation);
    void observation(gb::wire::Frame event);
    void drained();

  private:
    void done();
    QThread thread_;
    QObject *worker_ = nullptr;
    std::unique_ptr<ipc::ii::SessionChannel> client_;
    std::atomic<bool> nativeAuthenticated_{false};
    std::atomic<unsigned> pending_{0};
    std::atomic<bool> stopping_{false};
};
} // namespace gb::controller
Q_DECLARE_METATYPE(gb::wire::Id)
