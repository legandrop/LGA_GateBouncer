#include "productcontroller.h"
#include "data/netlimiterimport.h"
#include <QFile>
#include <QDir>
#include <QStandardPaths>
#include <QMetaObject>

namespace Gate {
ProductController::ProductController(bool isolatedQa, const QString &qaRoot, QObject *parent)
    : QObject(parent), isolatedQa_(isolatedQa), engine_(isolatedQa, this) {
    if (isolatedQa && (qaRoot.isEmpty() || !QDir::isAbsolutePath(qaRoot)))
        reviewError_ = "Isolated QA requires an explicit review root";
    else loadReview(isolatedQa ? qaRoot : QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) + "/review-live");
    connect(&engine_, &EngineViewClient::changed, this, [this] {
        const auto &status = engine_.status();
        if (status.current && (status.serviceEpoch != lastEpoch_ || status.bootId != lastBoot_)) {
            lastEpoch_ = status.serviceEpoch; lastBoot_ = status.bootId;
            ++generation_; emit invalidated();
        } else if (!status.current) { ++generation_; emit invalidated(); }
        emit changed();
    });
}
ProductController::~ProductController() { if (worker_) { worker_->wait(); delete worker_; } }
void ProductController::loadReview(const QString &root) {
    store_ = std::make_unique<Data::ReviewStore>(root);
    const auto result = store_->load();
    reviewWritable_ = result.ok() || result.status == Data::StoreStatus::Missing;
    if (result.document) review_ = *result.document;
    if (!reviewWritable_) reviewError_ = result.status == Data::StoreStatus::Busy
        ? "Review store is open in another instance" : "Review store unavailable: " + result.error;
}
void ProductController::setMode(UiMode mode) {
    if (mode_ == mode) return;
    mode_ = mode; ++generation_; emit invalidated();
    engine_.invalidate();
    if (!simulation()) refreshProcesses();
    emit changed();
}
bool ProductController::refreshProcesses() {
    if (simulation() || (worker_ && worker_->isRunning())) return false;
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
bool ProductController::refreshEngine() { return !simulation() && engine_.refresh(); }
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
    if (simulation() || path.isEmpty()) return false;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) { importError_ = "Could not read the chosen migration file"; emit changed(); return false; }
    auto report = Data::NetLimiterImport::analyze(file);
    if (!report.accepted) { importError_ = report.error; emit changed(); return false; }
    draft_ = std::move(report); importError_.clear(); emit changed(); return true;
}
void ProductController::clearDraft() { draft_ = {}; importError_.clear(); emit changed(); }
bool ProductController::saveCandidates() {
    if (!reviewWritable() || !store_ || !draft_.accepted) return false;
    auto next = review_; next.report = draft_;
    const auto result = store_->save(next, review_.revision);
    if (!result.ok() || !result.document) {
        reviewWritable_ = false; reviewError_ = "Candidates were not saved: " + result.error;
        emit changed(); return false;
    }
    review_ = *result.document; emit changed(); return true;
}
bool ProductController::updateCandidate(const QString &id, Data::Action action) {
    if (!reviewWritable() || !store_) return false;
    auto next = review_; bool found = false;
    for (auto &c : next.report.candidates) if (c.id == id) { c.reviewAction = action; c.reviewed = true; found = true; }
    if (!found) return false;
    const auto result = store_->save(next, review_.revision);
    if (!result.ok() || !result.document) { reviewWritable_ = false; reviewError_ = "Review was not saved: " + result.error; emit changed(); return false; }
    review_ = *result.document; emit changed(); return true;
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
