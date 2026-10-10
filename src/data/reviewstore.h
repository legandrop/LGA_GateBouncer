#pragma once
#include "contracts.h"
#include <QLockFile>
#include <QUuid>
#include <memory>
#include "../../common/wire_iv.h"

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
    StoreResult saveRuleBackup(const QByteArray &archive, const QUuid &id);
    static StoreResult parseRuleBackup(const QByteArray &, std::vector<gb::wire::iv::PrincipalRuleRecord> &);
    static StoreResult loadRuleBackup(const QString &, std::vector<gb::wire::iv::PrincipalRuleRecord> &);
    QString filePath() const { return path_; }
  private:
    QString path_, rootError_;
    std::unique_ptr<QLockFile> owner_;
    bool ensureOwner();
};
} // namespace Gate::Data
