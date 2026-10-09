#pragma once
#include "data/contracts.h"
#include "data/reviewstore.h"
#include "data/netlimitersemantics.h"
#include "data/netlimiterxmlprofile.h"
#include "platform/ProcessCatalog.h"
#include "engine/EngineViewClient.h"
#include "engine/DecisionViewClient.h"
#include "engine/OrdinaryDecisionClient.h"
#include <QObject>
#include <QThread>
#include <memory>
#include <QUuid>
#include <QHash>

namespace Gate {
enum class UiMode { LiveReadOnly, Simulation };
enum class ImportFormat { Structural, QNameProfile };
struct ImportedReviewView {
    QString digest;
    quint64 revision = 0;
    QUuid job;
    bool current = false, busy = false;
    Data::SemanticView facts;
    std::optional<Data::QNameProfileView> qname;
    QHash<QString, int> candidates;
};
class ProductController final : public QObject {
    Q_OBJECT
  public:
    explicit ProductController(bool isolatedQa = false, const QString &qaRoot = {}, QObject *parent = nullptr,
                               std::unique_ptr<gb::ipc::ii::SessionChannel> decisionChannel = {},
                               std::unique_ptr<gb::ipc::ii::SessionChannel> ordinaryChannel = {});
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
    const std::optional<Data::QNameEvidence> &importEvidence(bool draft) const { return draft ? draftEvidence_ : review_.qnameEvidence; }
    const ImportedReviewView &importedView(bool draft) const { return draft ? draftView_ : reviewView_; }
    const Data::SemanticCandidate *derivedCandidate(bool draft, const QString &id) const;
    const Data::QNameCandidateFacts *derivedQNameCandidate(bool draft, const QString &id) const;
    QString reviewError() const { return reviewError_; }
    QString importError() const { return importError_; }
    bool reviewWritable() const { return reviewWritable_ && !simulation(); }
    bool analyzeChosenFile(const QString &path);
    void setImportFormat(ImportFormat format) { importFormat_ = format; }
    ImportFormat importFormat() const { return importFormat_; }
    bool importBusy() const { return !importJob_.isNull(); }
    quint64 importGeneration() const { return importGeneration_; }
    void cancelImport();
    bool saveCandidates();
    void clearDraft();
    bool updateCandidate(const QString &id, Data::Action action);
    // View no concede autoridad de control, aun si la GUI tiene token elevado.
    bool canMutatePolicy() const { return false; }
    bool decideReal(const QString &, int) { return false; }
    const EngineStatus &engine() const { return recordsSelected_ ? records_.status() : engine_.status(); }
    DecisionViewClient *records() { return &records_; }
    const DecisionViewClient *records() const { return &records_; }
    OrdinaryDecisionClient *ordinary() { return &ordinary_; }
    const OrdinaryDecisionClient *ordinary() const { return &ordinary_; }
    bool recordsSelected() const { return recordsSelected_; }
    bool selectDecisionRecords();
    void selectStatusOnly();
    QString engineSummary() const;
    QString revisionSummary() const;
    quint64 generation() const { return generation_; }
    void stop() { stopped_ = true; ++generation_; cancelImport(); semanticJob_ = QUuid{}; draftView_ = {}; reviewView_ = {}; engine_.invalidate(); records_.stop(); ordinary_.stop(); }
    bool idle() const { return (!worker_ || !worker_->isRunning()) && (!semanticWorker_ || !semanticWorker_->isRunning()) && (!importWorker_ || !importWorker_->isRunning()) && engine_.idle() && records_.idle() && ordinary_.idle(); }
  signals:
    void changed();
    void invalidated();
    void importedViewsInvalidated();
  private:
    void loadReview(const QString &root);
    void deriveImportedViews();
    void startImportedViews();
    void startImport();
    bool isolatedQa_;
    UiMode mode_ = UiMode::LiveReadOnly;
    quint64 generation_ = 1;
    QThread *worker_ = nullptr;
    QThread *semanticWorker_ = nullptr;
    QUuid semanticJob_;
    QThread *importWorker_ = nullptr;
    QUuid importJob_;
    QString importPath_;
    ImportFormat importFormat_ = ImportFormat::Structural, pendingFormat_ = ImportFormat::Structural;
    quint64 importGeneration_ = 1;
    std::optional<Data::QNameEvidence> draftEvidence_;
    ImportedReviewView draftView_, reviewView_;
    Data::ProcessCatalog source_;
    Data::ProcessCatalogResult catalog_;
    EngineViewClient engine_;
    DecisionViewClient records_;
    OrdinaryDecisionClient ordinary_;
    bool recordsSelected_ = false, stopped_ = false;
    gb::wire::Id lastEpoch_{}, lastBoot_{};
    quint64 lastProfile_ = 0;
    std::unique_ptr<Data::ReviewStore> store_;
    Data::ReviewDocument review_;
    Data::ImportReport draft_;
    bool reviewWritable_ = false;
    QString reviewError_, importError_;
};
} // namespace Gate
