#pragma once
#include "wire_v1.h"
#include <QObject>
#include <QThread>
#include <atomic>

namespace Gate {
struct EngineStatus {
    bool current = false;
    gb::wire::Id serviceEpoch{}, bootId{}, connection{};
    quint64 desired = 0, effective = 0, capabilities = 0, gaps = 0;
    bool effectiveKnown = false;
    gb::wire::EngineState state = gb::wire::EngineState::Unavailable;
    gb::wire::BackendMode backend = gb::wire::BackendMode::Simulation;
    QString error;
};
class ViewByteChannel {
  public:
    virtual ~ViewByteChannel() = default;
    virtual bool authenticate() = 0;
    virtual bool write(const gb::wire::Bytes &bytes) = 0;
    virtual bool read(gb::wire::Bytes &bytes) = 0;
};
// El consumidor acepta un canal de prueba, pero el producto solo compone View local.
EngineStatus queryViewStatus(ViewByteChannel &channel);
class EngineViewClient final : public QObject {
    Q_OBJECT
  public:
    explicit EngineViewClient(bool isolatedQa, QObject *parent = nullptr);
    ~EngineViewClient() override;
    bool refresh();
    void invalidate();
    bool idle() const { return !worker_ || !worker_->isRunning(); }
    const EngineStatus &status() const { return status_; }
    quint64 generation() const { return generation_; }
  signals:
    void changed();
  private:
    bool isolatedQa_;
    QThread *worker_ = nullptr;
    std::atomic_bool cancelled_{false};
    quint64 generation_ = 0;
    EngineStatus status_;
};
} // namespace Gate
