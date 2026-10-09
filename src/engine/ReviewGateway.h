#pragma once
#include "wire_v1.h"
#include <QObject>
#include <QThread>
#include <atomic>
#include <filesystem>
#include <memory>

namespace Gate {
struct ReviewReference {
    gb::wire::Id epoch{}, request{};
    quint64 profile = 0;
};
class ReviewBackend {
  public:
    virtual ~ReviewBackend() = default;
    virtual QString launch(const std::filesystem::path &root) = 0;
    virtual QString open(const std::filesystem::path &root, ReviewReference reference) = 0;
};
class ReviewGateway final : public QObject {
    Q_OBJECT
  public:
    explicit ReviewGateway(bool isolatedQa, QObject *parent = nullptr,
                           std::unique_ptr<ReviewBackend> backend = {});
    ~ReviewGateway() override;
    bool launch();
    bool open(ReviewReference reference);
    void stop();
    void invalidate();
    bool idle() const { return !worker_ || !worker_->isRunning(); }
    QString status() const { return status_; }
  signals:
    void changed();

  private:
    bool run(bool launch, ReviewReference reference);
    bool isolatedQa_, stopped_ = false, launched_ = false;
    quint64 generation_ = 0;
    QThread *worker_ = nullptr;
    std::unique_ptr<ReviewBackend> backend_;
    QString status_ = "Administrator reviewer has not been enabled";
};
} // namespace Gate
