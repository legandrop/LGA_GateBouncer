#include "productcontroller.h"
#include "data/netlimiterimport.h"
#include <QFile>
#include <QDir>
#include <QStandardPaths>
#include <QMetaObject>
#include <QBuffer>

namespace Gate {
ProductController::ProductController(bool isolatedQa, const QString &qaRoot, QObject *parent,
                                     std::unique_ptr<gb::ipc::ii::SessionChannel> decisionChannel,
                                     std::unique_ptr<gb::ipc::ii::SessionChannel> ordinaryChannel)
    : QObject(parent), isolatedQa_(isolatedQa), engine_(isolatedQa, this), records_(isolatedQa, this, std::move(decisionChannel)),
      ordinary_(isolatedQa, this, std::move(ordinaryChannel)) {
    connect(&ordinary_, &OrdinaryDecisionClient::changed, this, &ProductController::changed);
    if (!isolatedQa_) QTimer::singleShot(0, this, [this] { if (!simulation() && !stopped_) ordinary_.startAutomatic(); });
    if (isolatedQa && (qaRoot.isEmpty() || !QDir::isAbsolutePath(qaRoot)))
        reviewError_ = "Isolated QA requires an explicit review root";
    else loadReview(isolatedQa ? qaRoot : QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) + "/review-live");
    connect(&engine_, &EngineViewClient::changed, this, [this] {
        if (recordsSelected_) return;
        const auto &status = engine_.status();
        if (status.current && (status.serviceEpoch != lastEpoch_ || status.bootId != lastBoot_)) {
            lastEpoch_ = status.serviceEpoch; lastBoot_ = status.bootId;
            ++generation_; emit invalidated();
        } else if (!status.current) { ++generation_; emit invalidated(); }
        emit changed();
    });
    connect(&records_, &DecisionViewClient::changed, this, [this] {
        if (!recordsSelected_) return;
        const auto &status = records_.status();
        if (!status.current || status.serviceEpoch != lastEpoch_ || status.bootId != lastBoot_ || records_.profile() != lastProfile_) {
            lastEpoch_ = status.serviceEpoch; lastBoot_ = status.bootId;
            lastProfile_ = records_.profile();
            ++generation_; emit invalidated();
        }
        emit changed();
    });
}
ProductController::~ProductController() {
    // La destrucción de miembros no emite hacia una ventana parcialmente destruida.
    stopped_ = true; cancelImport(); semanticJob_ = QUuid{};
    if (worker_) { worker_->wait(); delete worker_; }
    if (semanticWorker_) { semanticWorker_->wait(); delete semanticWorker_; }
    if (importWorker_) { importWorker_->wait(); delete importWorker_; }
}
void ProductController::loadReview(const QString &root) {
    store_ = std::make_unique<Data::ReviewStore>(root);
    const auto result = store_->load();
    reviewWritable_ = result.ok() || result.status == Data::StoreStatus::Missing;
    if (result.document) review_ = *result.document;
    if (!reviewWritable_) reviewError_ = result.status == Data::StoreStatus::Busy
        ? "Review store is open in another instance" : "Review store unavailable: " + result.error;
    deriveImportedViews();
}
void ProductController::deriveImportedViews() {
    ++importGeneration_;
    semanticJob_ = QUuid::createUuid();
    draftView_ = {}; reviewView_ = {};
    draftView_.job = reviewView_.job = semanticJob_;
    draftView_.busy = reviewView_.busy = !stopped_ && !simulation();
    emit importedViewsInvalidated();
    startImportedViews();
}
void ProductController::startImportedViews() {
    if (stopped_ || simulation() || semanticWorker_) return;
    const auto job = semanticJob_;
    const auto draft = draft_;
    const auto evidence = draftEvidence_;
    const auto saved = review_;
    semanticWorker_ = QThread::create([this, job, draft, evidence, saved] {
        ImportedReviewView preview, review;
        preview.digest = draft.digest; preview.job = job;
        review.digest = saved.report.digest; review.revision = saved.revision; review.job = job;
        if (evidence) preview.qname = Data::deriveQNameProfile(*evidence);
        else preview.facts = Data::NetLimiterSemantics::describe(draft, Data::SemanticProfile::ExternalUnaccredited);
        if (saved.qnameEvidence) review.qname = Data::deriveQNameProfile(*saved.qnameEvidence);
        else review.facts = Data::NetLimiterSemantics::describe(saved.report, Data::SemanticProfile::ExternalUnaccredited);
        preview.current = preview.qname ? preview.qname->valid : preview.facts.accepted;
        review.current = review.qname ? review.qname->valid : review.facts.accepted;
        for (int i = 0; i < preview.facts.candidates.size(); ++i)
            preview.candidates.insert(preview.facts.candidates[i].candidateId, i);
        for (int i = 0; i < review.facts.candidates.size(); ++i)
            review.candidates.insert(review.facts.candidates[i].candidateId, i);
        if (preview.qname) for (int i = 0; i < preview.qname->candidates.size(); ++i)
            preview.candidates.insert(preview.qname->candidates[i].candidateId, i);
        if (review.qname) for (int i = 0; i < review.qname->candidates.size(); ++i)
            review.candidates.insert(review.qname->candidates[i].candidateId, i);
        QMetaObject::invokeMethod(this, [this, job, preview, review] {
            if (stopped_ || simulation() || job != semanticJob_ || preview.digest != draft_.digest ||
                review.digest != review_.report.digest || review.revision != review_.revision) return;
            draftView_ = preview; reviewView_ = review; emit changed();
        }, Qt::QueuedConnection);
    });
    auto *thread = semanticWorker_;
    connect(thread, &QThread::finished, this, [this, thread, job] {
        semanticWorker_ = nullptr; thread->deleteLater();
        if (job != semanticJob_) startImportedViews();
    });
    thread->start();
}
const Data::SemanticCandidate *ProductController::derivedCandidate(bool draft, const QString &id) const {
    const auto &view = importedView(draft);
    const auto &report = draft ? draft_ : review_.report;
    if (view.qname || !view.current || view.job != semanticJob_ || view.digest != report.digest ||
        (!draft && view.revision != review_.revision)) return nullptr;
    const auto found = view.candidates.constFind(id);
    return found == view.candidates.cend() ? nullptr : &view.facts.candidates[*found];
}
const Data::QNameCandidateFacts *ProductController::derivedQNameCandidate(bool draft, const QString &id) const {
    const auto &view = importedView(draft);
    const auto &report = draft ? draft_ : review_.report;
    if (!view.qname || !view.current || view.job != semanticJob_ || view.digest != report.digest ||
        (!draft && view.revision != review_.revision)) return nullptr;
    const auto found = view.candidates.constFind(id);
    return found == view.candidates.cend() ? nullptr : &view.qname->candidates[*found];
}
void ProductController::setMode(UiMode mode) {
    if (stopped_ || mode_ == mode) return;
    mode_ = mode; ++generation_; emit invalidated();
    cancelImport();
    engine_.invalidate();
    records_.invalidate();
    ordinary_.invalidate();
    if (!simulation() && !isolatedQa_) ordinary_.startAutomatic();
    deriveImportedViews();
    if (!simulation()) refreshProcesses();
    emit changed();
}
bool ProductController::refreshProcesses() {
    if (stopped_ || simulation() || (worker_ && worker_->isRunning())) return false;
    if (worker_) { delete worker_; worker_ = nullptr; }
    const auto generation = generation_;
    worker_ = QThread::create([this, generation] {
        const auto result = source_.refresh();
        QMetaObject::invokeMethod(this, [this, generation, result] {
            if (simulation() || generation != generation_) return;
            catalog_ = result; emit changed();
        }, Qt::QueuedConnection);
    });
    worker_->start(); return true;
}
bool ProductController::refreshEngine() {
    return !stopped_ && !simulation() && (recordsSelected_ ? records_.refresh() : engine_.refresh());
}
bool ProductController::selectDecisionRecords() {
    if (stopped_ || simulation()) return false;
    if (!recordsSelected_) {
        recordsSelected_ = true; engine_.invalidate();
        ++generation_; emit invalidated(); emit changed();
    }
    return records_.refresh();
}
void ProductController::selectStatusOnly() {
    if (stopped_ || !recordsSelected_) return;
    recordsSelected_ = false; records_.invalidate(); engine_.invalidate();
    ++generation_; emit invalidated(); emit changed();
}
QString ProductController::processId(const Data::ProcessObservation &p) const {
    const auto &i = p.instance;
    return "live:" + i.sourceEpoch + ":" + QString::number(i.pid) + ":" +
           (i.creationFiletime ? QString::number(i.creationFiletime) : "snapshot:" + QString::number(catalog_.generation));
}
const Data::ProcessObservation *ProductController::process(const QString &id) const {
    if (simulation()) return nullptr;
    for (const auto &p : catalog_.processes) if (processId(p) == id) return &p;
    return nullptr;
}
bool ProductController::analyzeChosenFile(const QString &path) {
    if (stopped_ || simulation() || path.isEmpty()) return false;
    importJob_ = QUuid::createUuid(); importPath_ = path; pendingFormat_ = importFormat_;
    if (importWorker_) importWorker_->requestInterruption();
    importError_.clear(); startImport(); emit changed(); return true;
}
void ProductController::cancelImport() {
    importJob_ = QUuid{}; importPath_.clear();
    if (importWorker_) importWorker_->requestInterruption();
}
void ProductController::startImport() {
    if (stopped_ || simulation() || importWorker_ || importJob_.isNull()) return;
    const auto job = importJob_; const auto path = importPath_; const auto format = pendingFormat_;
    importWorker_ = QThread::create([this, job, path, format] {
        Data::ImportReport report; std::optional<Data::QNameEvidence> evidence;
        try {
            QFile file(path); QByteArray bytes; const Data::ImportLimits limits;
            if (!file.open(QIODevice::ReadOnly)) report.error = "Could not read the chosen migration file";
            else if (file.size() > limits.bytes) report.error = "Migration file exceeds the 8 MiB limit";
            else {
                while (!file.atEnd() && !QThread::currentThread()->isInterruptionRequested()) {
                    auto chunk = file.read(qMin<qint64>(65536, limits.bytes + 1 - bytes.size()));
                    if (chunk.isEmpty() && file.error() != QFileDevice::NoError) { report.error = "Could not read the chosen migration file"; break; }
                    bytes += chunk;
                    if (bytes.size() > limits.bytes) { report.error = "Migration file exceeds the 8 MiB limit"; break; }
                }
                if (report.error.isEmpty() && !QThread::currentThread()->isInterruptionRequested()) {
                    if (format == ImportFormat::QNameProfile) {
                        auto result = Data::importQNameProfile(bytes, limits);
                        report = std::move(result.report); evidence = std::move(result.evidence);
                    } else { QBuffer input(&bytes); input.open(QIODevice::ReadOnly); report = Data::NetLimiterImport::analyze(input, limits); }
                }
            }
        } catch (...) { report.error = "Migration analysis failed within the selected profile"; }
        QMetaObject::invokeMethod(this, [this, job, report, evidence] {
            if (stopped_ || simulation() || job != importJob_) return;
            importJob_ = QUuid{}; importPath_.clear();
            if (!report.accepted) importError_ = report.error;
            else { draft_ = report; draftEvidence_ = evidence; importError_.clear(); deriveImportedViews(); }
            emit changed();
        }, Qt::QueuedConnection);
    });
    auto *thread = importWorker_;
    connect(thread, &QThread::finished, this, [this, thread, job] {
        importWorker_ = nullptr; thread->deleteLater();
        if (job != importJob_) startImport();
    });
    thread->start();
}
void ProductController::clearDraft() { if (stopped_) return; cancelImport(); draft_ = {}; draftEvidence_.reset(); importError_.clear(); deriveImportedViews(); emit changed(); }
bool ProductController::saveCandidates() {
    if (stopped_ || importBusy() || !reviewWritable() || !store_ || !draft_.accepted) return false;
    auto next = review_; next.report = draft_;
    next.qnameEvidence = draftEvidence_;
    const auto result = store_->save(next, review_.revision);
    if (!result.ok() || !result.document) {
        reviewWritable_ = false; reviewError_ = "Candidates were not saved: " + result.error;
        emit changed(); return false;
    }
    review_ = *result.document; deriveImportedViews(); emit changed(); return true;
}
bool ProductController::updateCandidate(const QString &id, Data::Action action) {
    if (stopped_ || !reviewWritable() || !store_) return false;
    auto next = review_; bool found = false;
    for (auto &c : next.report.candidates) if (c.id == id) { c.reviewAction = action; c.reviewed = true; found = true; }
    if (!found) return false;
    const auto result = store_->save(next, review_.revision);
    if (!result.ok() || !result.document) { reviewWritable_ = false; reviewError_ = "Review was not saved: " + result.error; emit changed(); return false; }
    review_ = *result.document; deriveImportedViews(); emit changed(); return true;
}
QString ProductController::engineSummary() const {
    const auto &e = engine();
    if (!e.current) return "Engine status unavailable";
    if (e.backend == gb::wire::BackendMode::Simulation || e.state == gb::wire::EngineState::Simulation)
        return "Engine reports simulation";
    if (e.backend != gb::wire::BackendMode::WfpUsermode) return "Engine backend not supported by this build";
    switch (e.state) {
    case gb::wire::EngineState::Reconciling: return "Engine reconciling · changes not confirmed";
    case gb::wire::EngineState::RecoveryRequired: return "Engine recovery required";
    case gb::wire::EngineState::Unavailable: return "Engine backend unavailable";
    case gb::wire::EngineState::ValidatedProfile: return "Coverage evidence unavailable";
    default: return "Engine connected · coverage not validated";
    }
}
QString ProductController::revisionSummary() const {
    const auto &e = engine();
    if (gb::wire::zero(e.serviceEpoch)) return "Applied revision unknown";
    const QString suffix = e.current ? "" : " · last known, stale";
    if (!e.effectiveKnown) return "Desired revision " + QString::number(e.desired) + " · applied revision unknown" + suffix;
    return "Desired revision " + QString::number(e.desired) + " · applied revision " + QString::number(e.effective) +
           (e.desired == e.effective ? "" : " · changes not confirmed") + suffix;
}
} // namespace Gate
