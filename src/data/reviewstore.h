#pragma once
#include "contracts.h"
#include <QLockFile>
#include <memory>

namespace Gate::Data {
enum class StoreStatus { Ok, Missing, Busy, Corrupt, FutureSchema, IoError, StaleRevision, Invalid };
struct StoreResult {
    StoreStatus status = StoreStatus::Invalid;
    QString error;
    std::optional<ReviewDocument> document;
    bool ok() const { return status == StoreStatus::Ok; }
};
class ReviewStore final {
  public:
    explicit ReviewStore(const QString &ownRoot);
    ~ReviewStore();
    ReviewStore(const ReviewStore &) = delete;
    ReviewStore &operator=(const ReviewStore &) = delete;
    StoreResult load();
    StoreResult save(const ReviewDocument &document, quint64 expectedRevision);
    QString filePath() const { return path_; }
  private:
    QString path_, rootError_;
    std::unique_ptr<QLockFile> owner_;
    bool ensureOwner();
};
} // namespace Gate::Data
