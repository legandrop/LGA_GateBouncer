#include "productcontroller.h"
#include "data/netlimiterimport.h"
#include <QFile>
#include <QDir>
#include <QStandardPaths>
#include <QMetaObject>

namespace Gate {
ProductController::ProductController(bool isolatedQa, const QString &qaRoot, QObject *parent,
                                     std::unique_ptr<gb::ipc::ii::SessionChannel> decisionChannel)
    : QObject(parent), isolatedQa_(isolatedQa), engine_(isolatedQa, this), records_(isolatedQa, this, std::move(decisionChannel)) {
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
    stopped_ = true; semanticJob_ = QUuid{};
    if (worker_) { worker_->wait(); delete worker_; }
    if (semanticWorker_) { semanticWorker_->wait(); delete semanticWorker_; }
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
    semanticJob_ = QUuid::createUuid();
    draftView_ = {}; reviewView_ = {};
    draftView_.busy = reviewView_.busy = !stopped_ && !simulation();
    emit importedViewsInvalidated();
    startImportedViews();
}
void ProductController::startImportedViews() {
    if (stopped_ || simulation() || semanticWorker_) return;
    const auto job = semanticJob_;
    const auto draft = draft_;
    const auto saved = review_;
    semanticWorker_ = QThread::create([this, job, draft, saved] {
        ImportedReviewView preview, review;
        preview.digest = draft.digest; preview.job = job;
        review.digest = saved.report.digest; review.revision = saved.revision; review.job = job;
        preview.facts = Data::NetLimiterSemantics::describe(draft, Data::SemanticProfile::ExternalUnaccredited);
        review.facts = Data::NetLimiterSemantics::describe(saved.report, Data::SemanticProfile::ExternalUnaccredited);
        preview.current = preview.facts.accepted; review.current = review.facts.accepted;
        for (int i = 0; i < preview.facts.candidates.size(); ++i)
            preview.candidates.insert(preview.facts.candidates[i].candidateId, i);
        for (int i = 0; i < review.facts.candidates.size(); ++i)
            review.candidates.insert(review.facts.candidates[i].candidateId, i);
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
    if (!view.current || view.job != semanticJob_ || view.digest != report.digest ||
        (!draft && view.revision != review_.revision)) return nullptr;
    const auto found = view.candidates.constFind(id);
    return found == view.candidates.cend() ? nullptr : &view.facts.candidates[*found];
}
void ProductController::setMode(UiMode mode) {
    if (stopped_ || mode_ == mode) return;
    mode_ = mode; ++generation_; emit invalidated();
    engine_.invalidate();
    records_.invalidate();
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
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) { importError_ = "Could not read the chosen migration file"; emit changed(); return false; }
    auto report = Data::NetLimiterImport::analyze(file);
    if (!report.accepted) { importError_ = report.error; emit changed(); return false; }
    draft_ = std::move(report); importError_.clear(); deriveImportedViews(); emit changed(); return true;
}
void ProductController::clearDraft() { if (stopped_) return; draft_ = {}; importError_.clear(); deriveImportedViews(); emit changed(); }
bool ProductController::saveCandidates() {
    if (stopped_ || !reviewWritable() || !store_ || !draft_.accepted) return false;
    auto next = review_; next.report = draft_;
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
