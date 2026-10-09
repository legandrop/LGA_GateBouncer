#pragma once
#include "data/contracts.h"
#include "data/reviewstore.h"
#include "platform/ProcessCatalog.h"
#include "engine/EngineViewClient.h"
#include <QObject>
#include <QThread>
#include <memory>

namespace Gate {
enum class UiMode { LiveReadOnly, Simulation };
class ProductController final : public QObject {
    Q_OBJECT
  public:
    explicit ProductController(bool isolatedQa = false, const QString &qaRoot = {}, QObject *parent = nullptr);
    ~ProductController() override;
    UiMode mode() const { return mode_; }
    bool simulation() const { return mode_ == UiMode::Simulation; }
    void setMode(UiMode mode);
    bool refreshProcesses();
    bool refreshEngine();
    const Data::ProcessCatalogResult &catalog() const { return catalog_; }
    const Data::ProcessObservation *process(const QString &id) const;
    QString processId(const Data::ProcessObservation &process) const;
    const Data::ReviewDocument &review() const { return review_; }
    const Data::ImportReport &draft() const { return draft_; }
    QString reviewError() const { return reviewError_; }
    QString importError() const { return importError_; }
    bool reviewWritable() const { return reviewWritable_ && !simulation(); }
    bool analyzeChosenFile(const QString &path);
    bool saveCandidates();
    void clearDraft();
    bool updateCandidate(const QString &id, Data::Action action);
    // View no concede autoridad de control, aun si la GUI tiene token elevado.
    bool canMutatePolicy() const { return false; }
    bool decideReal(const QString &, int) { return false; }
    const EngineStatus &engine() const { return engine_.status(); }
    QString engineSummary() const;
    QString revisionSummary() const;
    quint64 generation() const { return generation_; }
    void stop() { ++generation_; engine_.invalidate(); }
    bool idle() const { return (!worker_ || !worker_->isRunning()) && engine_.idle(); }
  signals:
    void changed();
    void invalidated();
  private:
    void loadReview(const QString &root);
    bool isolatedQa_;
    UiMode mode_ = UiMode::LiveReadOnly;
    quint64 generation_ = 1;
    QThread *worker_ = nullptr;
    Data::ProcessCatalog source_;
    Data::ProcessCatalogResult catalog_;
    EngineViewClient engine_;
    gb::wire::Id lastEpoch_{}, lastBoot_{};
    std::unique_ptr<Data::ReviewStore> store_;
    Data::ReviewDocument review_;
    Data::ImportReport draft_;
    bool reviewWritable_ = false;
    QString reviewError_, importError_;
};
} // namespace Gate
