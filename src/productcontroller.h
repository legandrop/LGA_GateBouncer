#pragma once
#include "data/contracts.h"
#include "data/reviewstore.h"
#include "data/activityhistory.h"
#include "data/netlimitersemantics.h"
#include "data/netlimiterxmlprofile.h"
#include "platform/ProcessCatalog.h"
#include "engine/EngineViewClient.h"
#include "engine/DecisionViewClient.h"
#include "engine/OrdinaryDecisionClient.h"
#include <QObject>
#include <QThread>
#include <QTimer>
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
struct ImportedActivationView {
    QString candidate, process, message;
    quint64 token = 0;
    bool busy = false, ready = false;
};
struct FileRuleView {
    QString message;
    quint64 token = 0;
    bool busy = false, ready = false;
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
    const Data::HistoryState &history() const { return history_.state(); }
    QString historyError() const { return historyError_; }
    const Data::ImportReport &draft() const { return draft_; }
    const std::optional<Data::QNameEvidence> &importEvidence(bool draft) const { return draft ? draftEvidence_ : review_.qnameEvidence; }
    const ImportedReviewView &importedView(bool draft) const { return draft ? draftView_ : reviewView_; }
    const Data::SemanticCandidate *derivedCandidate(bool draft, const QString &id) const;
    const Data::QNameCandidateFacts *derivedQNameCandidate(bool draft, const QString &id) const;
    QString reviewError() const { return reviewError_; }
    QString importError() const { return importError_; }
    bool reviewWritable() const { return reviewWritable_ && !simulation() && !storeLoading_; }
    bool reviewBusy() const { return storeLoading_ || flushingHistory_ || storeWriteRequested_ || bool(pendingReview_); }
    bool analyzeChosenFile(const QString &path);
    void setImportFormat(ImportFormat format) { importFormat_ = format; }
    ImportFormat importFormat() const { return importFormat_; }
    bool importBusy() const { return !importJob_.isNull(); }
    quint64 importGeneration() const { return importGeneration_; }
    void cancelImport();
    bool saveCandidates();
    void clearDraft();
    bool updateCandidate(const QString &id, Data::Action action);
    bool prepareImportedRule(const QString &candidate, const QString &process);
    bool confirmImportedRule(quint64 token, bool consent);
    void cancelImportedRule();
    const ImportedActivationView &importedActivation() const { return activationView_; }
    bool prepareApplicationFile(const QString &path, Data::Action action, Data::Direction direction,
        const std::optional<gb::wire::Id> &editing = {}, quint64 selection = 0,
        const QString &candidate = {}, int backupIndex = -1);
    bool confirmApplicationFile(quint64 token, bool consent);
    void cancelApplicationFile();
    const FileRuleView &fileRuleView() const { return fileRuleView_; }
    bool loadSelectedRuleBackup(const QString &path);
    const auto &inactiveRuleBackup() const { return inactiveRuleBackup_; }
    // View no concede autoridad de control, aun si la GUI tiene token elevado.
    bool canMutatePolicy() const { return false; }
    bool decideReal(const QString &, int) { return false; }
    const EngineStatus &engine() const { return recordsSelected_ ? records_.status() : engine_.status(); }
    DecisionViewClient *records() { return &records_; }
    const DecisionViewClient *records() const { return &records_; }
    OrdinaryDecisionClient *ordinary() { return administrativeSelected_ ? &administrative_ : &ordinary_; }
    const OrdinaryDecisionClient *ordinary() const { return administrativeSelected_ ? &administrative_ : &ordinary_; }
    bool administrativeSelected() const { return administrativeSelected_; }
    bool selectAdministrative(bool enabled);
    bool recordsSelected() const { return recordsSelected_; }
    bool selectDecisionRecords();
    bool backupSelectedRules(const std::vector<gb::wire::Id> &, quint64 selection, bool consent);
    bool ruleBackupBusy() const { return pendingRuleBackup_.has_value() || savingRuleBackup_; }
    QString ruleBackupDirectory() const;
    void selectStatusOnly();
    QString engineSummary() const;
    QString revisionSummary() const;
    quint64 generation() const { return generation_; }
    void stop();
    bool idle() const { return (!fileWorker_ || !fileWorker_->isRunning()) && !Data::SelectedApplicationFile::physicalJobs() && (!worker_ || !worker_->isRunning()) && (!semanticWorker_ || !semanticWorker_->isRunning()) && (!importWorker_ || !importWorker_->isRunning()) && (!storeWorker_ || !storeWorker_->isRunning()) && !storeLoading_ && !flushingHistory_ &&
        !pendingRuleBackup_ && !savingRuleBackup_ && !(reviewWritable_ && (storeWriteRequested_ || historyDirty_)) && engine_.idle() && records_.idle() && ordinary_.idle() && administrative_.idle(); }
  signals:
    void changed();
    void invalidated();
    void importedViewsInvalidated();
    void reviewSaved(const QString &message);
  private:
    void loadReview(const QString &root);
    void startReviewWrite();
    void queueReview(Data::ReviewDocument document, const QString &notification);
    void deriveImportedViews();
    void startImportedViews();
    void startImport();
    bool flushHistory();
    void historyChanged();
    void advanceNativeProcesses();
    void runNativeWorker(int phase);
    void cancelNativeProcesses();
    void clearProcessHistory();
    void projectProcessHistory(Data::ProcessCatalogResult &);
    void advanceImportedRule();
    void finishImportedComparison(const NativeContextSnapshot &, const std::shared_ptr<Data::NativeOwnBatch> &,
                                  const Data::ProcessCatalogResult &);
    bool importedRuleCurrent() const;
    void advanceApplicationFile();
    void checkApplicationFile(bool committing);
    struct FileActivation;
    std::unique_ptr<FileActivation> fileActivation_;
    FileRuleView fileRuleView_;
    quint64 fileRuleToken_ = 0;
    QThread *fileWorker_ = nullptr;
    QTimer fileDrain_;
    std::vector<gb::wire::iv::PrincipalRuleRecord> inactiveRuleBackup_;
    struct ImportedActivation;
    std::unique_ptr<ImportedActivation> activation_;
    ImportedActivationView activationView_;
    quint64 activationToken_ = 0;
    std::optional<QByteArray> pendingRuleBackup_;
    QUuid pendingRuleBackupId_;
    bool savingRuleBackup_ = false;
    struct NativeProcessJob;
    std::unique_ptr<NativeProcessJob> nativeProcessJob_;
    QTimer nativeProcessTick_;
    quint64 nativeProcessTag_ = 0;
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
    OrdinaryDecisionClient administrative_;
    bool administrativeSelected_ = false;
    bool recordsSelected_ = false, stopped_ = false;
    gb::wire::Id lastEpoch_{}, lastBoot_{};
    quint64 lastProfile_ = 0;
    std::unique_ptr<Data::ReviewStore> store_;
    QThread *storeWorker_ = nullptr;
    bool storeLoading_ = false, storeWriteRequested_ = false;
    quint64 historyVersion_ = 0;
    std::optional<Data::ReviewDocument> pendingReview_, inFlightReview_;
    QString writeNotification_;
    Data::ReviewDocument review_;
    Data::ActivityHistory history_;
    QTimer historyFlush_;
    QTimer administrativeHistoryNotify_;
    bool historyDirty_ = false, flushingHistory_ = false;
    QString historyError_;
    Data::ImportReport draft_;
    bool reviewWritable_ = false;
    QString reviewError_, importError_;
};
} // namespace Gate
