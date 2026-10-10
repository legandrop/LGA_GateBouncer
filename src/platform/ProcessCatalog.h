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
struct SelectedFileFacts {
    QString image;
    QByteArray appId, accountSid;
    quint32 volumeSerial = 0, fileIndexHigh = 0, fileIndexLow = 0;
    quint32 fileSizeHigh = 0, fileSizeLow = 0, attributes = 0;
    quint64 lastWrite = 0;
};
// Sólo acquire obtiene el dueño Windows original; las copias de facts no lo recrean.
class SelectedApplicationFile final {
  public:
    static std::shared_ptr<SelectedApplicationFile> acquire(const QString &path, QString &error);
    static unsigned physicalJobs();
    const SelectedFileFacts &facts() const { return facts_; }
    bool current() const; // IO: ejecutar fuera del hilo de interfaz.
    ~SelectedApplicationFile();
  private:
    struct Owner;
    SelectedApplicationFile();
    std::shared_ptr<Owner> owner_;
    SelectedFileFacts facts_;
};
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
