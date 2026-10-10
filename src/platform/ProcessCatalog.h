#pragma once
#include "../data/contracts.h"
#include <memory>
namespace gb::ipc::ii { class ReadPeerLease; }
namespace Gate { class NativeProcessReceipt; }

namespace Gate::Data {
struct ProcessCatalogResult {
    QVector<ProcessObservation> processes;
    QString error;
    quint64 generation = 0;
};
struct NativeOwnBatch;
// Normaliza sólo una declaración de ruta local mediante API Windows. No obtiene FileID,
// proceso, token, imagen mapeada, lease ni autoridad; el consumidor coteja causa original.
std::optional<QByteArray> canonicalLocalApplicationId(const QString &path);
class ProcessCatalog final {
  public:
    ProcessCatalog();
    ~ProcessCatalog();
    ProcessCatalogResult refresh();
    bool setNativeContext(const NativeSourceBinding &, std::shared_ptr<const gb::ipc::ii::ReadPeerLease>, const QString &connection);
    bool queueNativeAttempt(const ActivityEvent &);
    void revokeNative();
    std::shared_ptr<NativeOwnBatch> acquireNative();
    QVector<QString> nativeSubjects(const std::shared_ptr<NativeOwnBatch> &) const;
    std::optional<ActivityEvent> nativeAttempt(const std::shared_ptr<NativeOwnBatch> &, const QString &) const;
    bool admitNativeRead(const std::shared_ptr<NativeOwnBatch> &, std::shared_ptr<const Gate::NativeProcessReceipt>, int phase);
    bool validateNative(const std::shared_ptr<NativeOwnBatch> &);
    ProcessCatalogResult finishNative(const std::shared_ptr<NativeOwnBatch> &);
    bool batchCurrent(const std::shared_ptr<NativeOwnBatch> &) const;
    bool hasNativeCandidates() const;
    bool publicationCurrent(const std::shared_ptr<NativeOwnBatch> &) const;
  private:
    struct NativeBridge;
    std::unique_ptr<NativeBridge> native_;
    QString epoch_;
    quint64 generation_ = 0;
};
} // namespace Gate::Data
