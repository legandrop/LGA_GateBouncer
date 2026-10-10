#include "productcontroller.h"
#include "data/netlimiterimport.h"
#include <QFile>
#include <QDir>
#include <QStandardPaths>
#include <QMetaObject>
#include <QBuffer>
#include <algorithm>

namespace Gate {
struct ProductController::NativeProcessJob {
    enum Phase { StatusBefore, Acquire, ReadBefore, Validate, ReadAfter, StatusAfter, Finish };
    Phase phase = StatusBefore;
    NativeContextSnapshot context;
    std::shared_ptr<Data::NativeOwnBatch> batch;
    QVector<QString> subjects;
    int cursor = 0;
    quint64 generation = 0, tag = 0;
    bool pending = false;
    QElapsedTimer age;
};
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
    connect(&records_, &DecisionViewClient::nativeSourceOpened, this, [this](const Data::NativeSourceBinding &binding, quint64 baseline) {
        if (stopped_ || simulation()) return;
        if (!history_.addNativeSource(binding, baseline)) {
            historyError_ = "History source limit or cursor binding rejected; previous records are preserved.";
            records_.rejectHistory(historyError_); return;
        }
        historyChanged();
    });
    connect(&records_, &DecisionViewClient::nativeEvent, this, [this](const Data::ActivityEvent &event) {
        if (stopped_ || simulation()) return;
        if (!history_.ingest(event)) {
            historyChanged(); historyError_ = "History evidence was not retained; coverage is incomplete.";
            records_.rejectHistory(historyError_); return;
        }
        historyChanged();
        if (event.kind == Data::ActivityKind::Attempt && event.native && event.native->process) {
            const auto context = records_.currentNativeContext(false);
            if (context && source_.setNativeContext(context->binding,context->peer,context->connection) && source_.queueNativeAttempt(event))
                QTimer::singleShot(0,this,[this] { if (!nativeProcessJob_) refreshProcesses(); });
        }
    });
    connect(&records_, &DecisionViewClient::nativeGap, this,
        [this](const Data::NativeSourceBinding &binding, quint64 after, quint64 resync, quint64 revision,
               quint8 reason, bool lostKnown, quint64 lost) {
            if (stopped_ || simulation()) return;
            if (!history_.nativeGap(binding, after, resync, revision, reason, lostKnown, lost)) {
                historyError_ = "History discontinuity binding rejected."; records_.rejectHistory(historyError_); return;
            }
            historyChanged();
        });
    connect(&records_, &DecisionViewClient::nativeSourceLost, this,
        [this](const Data::NativeSourceBinding &binding, const QString &reason) {
            cancelNativeProcesses();
            history_.disconnectNative(binding, reason); historyChanged();
        });
    historyFlush_.setInterval(1000);
    connect(&historyFlush_, &QTimer::timeout, this, [this] {
        if (!stopped_ && !simulation() && historyDirty_ && history_.flushDue(QDateTime::currentDateTimeUtc())) flushHistory();
    });
    historyFlush_.start();
    nativeProcessTick_.setInterval(50);
    connect(&nativeProcessTick_, &QTimer::timeout, this, &ProductController::advanceNativeProcesses);
    connect(&records_, &DecisionViewClient::nativeSnapshotContext, this,
        [this](quint64 tag,const NativeContextSnapshot &context) {
            if (!nativeProcessJob_ || nativeProcessJob_->tag != tag || !nativeProcessJob_->pending) return;
            auto &job = *nativeProcessJob_;
            if (!(context.capabilities & gb::wire::iv::NativeProcessFacts) ||
                !(context.binding == job.context.binding) || context.peer != job.context.peer ||
                context.connection != job.context.connection || !context.peer ||
                context.peer->checkLive() != gb::ipc::ii::ReadPeerState::Current ||
                (job.phase == NativeProcessJob::StatusAfter && context.serial <= job.context.serial)) {
                cancelNativeProcesses(); return;
            }
            job.pending = false; job.context = context;
            if (job.phase == NativeProcessJob::StatusBefore) {
                if (!source_.setNativeContext(context.binding,context.peer,context.connection)) { cancelNativeProcesses(); return; }
                job.phase = NativeProcessJob::Acquire;
            } else if (job.phase == NativeProcessJob::StatusAfter) job.phase = NativeProcessJob::Finish;
            else { cancelNativeProcesses(); return; }
            advanceNativeProcesses();
        });
    connect(&records_, &DecisionViewClient::nativeProcessContext, this,
        [this](quint64 tag,const QString &subject,bool accepted,const NativeContextSnapshot &context,const QString &reason,
               std::shared_ptr<const NativeProcessReceipt> receipt) {
            if (!nativeProcessJob_ || nativeProcessJob_->tag != tag || !nativeProcessJob_->pending) return;
            auto &job = *nativeProcessJob_;
            if (!(context.binding == job.context.binding) || context.peer != job.context.peer ||
                context.connection != job.context.connection || job.cursor >= job.subjects.size() ||
                job.subjects[job.cursor] != subject ||
                (job.phase != NativeProcessJob::ReadBefore && job.phase != NativeProcessJob::ReadAfter) ||
                !receipt || receipt->accepted()!=accepted || receipt->descriptor()!=subject ||
                !source_.admitNativeRead(job.batch,receipt,job.phase == NativeProcessJob::ReadBefore ? 1 : 2)) {
                cancelNativeProcesses(); return;
            }
            if (!accepted && !reason.isEmpty()) catalog_.error = reason;
            ++job.cursor; job.pending = false; advanceNativeProcesses();
        });
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
        const bool paired = std::any_of(catalog_.processes.begin(),catalog_.processes.end(),
            [](const Data::ProcessObservation &p) { return !p.identityEvidence.isEmpty(); });
        if (paired && !records_.currentNativeContext()) cancelNativeProcesses();
        else if (nativeProcessJob_) advanceNativeProcesses();
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
    stopped_ = true; cancelNativeProcesses(); cancelImport(); semanticJob_ = QUuid{};
    if (worker_) { worker_->wait(); delete worker_; }
    if (semanticWorker_) { semanticWorker_->wait(); delete semanticWorker_; }
    if (importWorker_) { importWorker_->wait(); delete importWorker_; }
    if (storeWorker_) { storeWorker_->wait(); delete storeWorker_; }
}
void ProductController::historyChanged() {
    ++historyVersion_; historyDirty_ = true;
    if (!simulation() && history_.flushDue(QDateTime::currentDateTimeUtc())) flushHistory();
}
bool ProductController::flushHistory() {
    if (!historyDirty_) return true;
    if (storeLoading_) { storeWriteRequested_=true; return true; }
    if (!store_ || !reviewWritable_) {
        historyError_ = "History could not be saved; previous stored records are preserved.";
        history_.storageFailed(); return false;
    }
    storeWriteRequested_=true; startReviewWrite(); return true;
}
void ProductController::queueReview(Data::ReviewDocument document,const QString &notification) {
    pendingReview_=std::move(document); writeNotification_=notification;
    storeWriteRequested_=true; startReviewWrite(); emit changed();
}
void ProductController::startReviewWrite() {
    // Único escritor físico: la revisión se toma al despachar, nunca de una captura vieja.
    if (storeLoading_ || storeWorker_ || !store_ || !reviewWritable_ ||
        (!storeWriteRequested_ && !historyDirty_)) return;
    auto next=pendingReview_ ? *pendingReview_ : review_;
    next.revision=review_.revision; next.history=history_.state();
    pendingReview_.reset(); inFlightReview_=next; storeWriteRequested_=false; flushingHistory_=true;
    const auto version=historyVersion_; const auto notification=writeNotification_; writeNotification_.clear();
    auto *store=store_.get(); const auto expected=review_.revision;
    storeWorker_=QThread::create([this,store,next,expected,version,notification] {
        Data::StoreResult saved;
        try { saved=store->save(next,expected); }
        catch (...) { saved={Data::StoreStatus::IoError,"Review processing failed; previous file preserved",{}}; }
        QMetaObject::invokeMethod(this,[this,saved,version,notification] {
            flushingHistory_=false; inFlightReview_.reset();
            if (!saved.ok() || !saved.document) {
                history_.storageFailed(); ++historyVersion_; reviewWritable_=false;
                pendingReview_.reset(); storeWriteRequested_=false; writeNotification_.clear();
                reviewError_="Review was not saved: "+saved.error; historyError_=reviewError_; emit changed(); return;
            }
            review_=*saved.document;
            if (historyVersion_==version) { history_.checkpoint(QDateTime::currentDateTimeUtc()); historyDirty_=false; }
            else storeWriteRequested_=true; // El siguiente write incluye toda la historia más reciente.
            historyError_.clear(); reviewError_.clear();
            if (!notification.isEmpty()) { deriveImportedViews(); emit reviewSaved(notification); }
            else if (reviewView_.digest==review_.report.digest) reviewView_.revision=review_.revision;
            emit changed();
        },Qt::QueuedConnection);
    });
    auto *thread=storeWorker_;
    connect(thread,&QThread::finished,this,[this,thread] {
        if (storeWorker_==thread) storeWorker_=nullptr;
        thread->deleteLater(); startReviewWrite(); emit changed();
    });
    thread->start();
}
void ProductController::stop() {
    if (stopped_) return;
    stopped_ = true; cancelNativeProcesses(); historyFlush_.stop(); ++generation_; cancelImport();
    semanticJob_ = QUuid{}; draftView_ = {}; reviewView_ = {};
    engine_.invalidate(); records_.stop(); ordinary_.stop();
    flushHistory();
}
void ProductController::loadReview(const QString &root) {
    store_=std::make_unique<Data::ReviewStore>(root); storeLoading_=true;
    auto *store=store_.get();
    storeWorker_=QThread::create([this,store] {
        Data::StoreResult result;
        try { result=store->load(); }
        catch (...) { result={Data::StoreStatus::IoError,"Review processing failed; file preserved",{}}; }
        QMetaObject::invokeMethod(this,[this,result] {
            storeLoading_=false; reviewWritable_=result.ok() || result.status==Data::StoreStatus::Missing;
            if (result.document) review_=*result.document;
            if (!history_.restore(review_.history)) {
                reviewWritable_=false; historyError_="Stored history could not be restored; the file is preserved.";
            } else if (!review_.history.coverage.isEmpty()) { ++historyVersion_; historyDirty_=true; }
            if (!reviewWritable_) reviewError_=result.status==Data::StoreStatus::Busy
                ? "Review store is open in another instance" : "Review store unavailable: "+result.error;
            deriveImportedViews(); emit changed();
        },Qt::QueuedConnection);
    });
    auto *thread=storeWorker_;
    connect(thread,&QThread::finished,this,[this,thread] {
        if (storeWorker_==thread) storeWorker_=nullptr;
        thread->deleteLater(); if (stopped_ && historyDirty_) storeWriteRequested_=true;
        startReviewWrite(); emit changed();
    });
    thread->start();
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
                review.digest != review_.report.digest) return;
            draftView_ = preview; reviewView_ = review; reviewView_.revision = review_.revision; emit changed();
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
    cancelNativeProcesses(); mode_ = mode; ++generation_; emit invalidated();
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
    if (stopped_ || simulation() || nativeProcessJob_ || (worker_ && worker_->isRunning())) return false;
    if (worker_) { delete worker_; worker_ = nullptr; }
    const auto context = records_.currentNativeContext(false);
    if (context && source_.hasNativeCandidates()) {
        nativeProcessJob_ = std::make_unique<NativeProcessJob>();
        nativeProcessJob_->context = *context; nativeProcessJob_->generation = generation_;
        nativeProcessJob_->age.start(); nativeProcessTick_.start(); advanceNativeProcesses(); return true;
    }
    const auto generation = generation_;
    worker_ = QThread::create([this, generation] {
        const auto result = source_.refresh();
        QMetaObject::invokeMethod(this, [this, generation, result] {
            if (stopped_ || simulation() || generation != generation_) return;
            catalog_ = result; emit changed();
        }, Qt::QueuedConnection);
    });
    connect(worker_, &QThread::finished, this, [this] {
        if (!stopped_ && !simulation() && !nativeProcessJob_ && source_.hasNativeCandidates() && records_.currentNativeContext(false))
            QTimer::singleShot(0,this,&ProductController::refreshProcesses);
    });
    worker_->start(); return true;
}
bool ProductController::refreshEngine() {
    return !stopped_ && !simulation() && (recordsSelected_ ? records_.refresh() : engine_.refresh());
}
bool ProductController::selectDecisionRecords() {
    if (stopped_ || simulation() || storeLoading_) return false;
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
    if (stopped_ || importBusy() || reviewBusy() || !reviewWritable() || !store_ || !draft_.accepted) return false;
    auto next=review_; next.report=draft_; next.qnameEvidence=draftEvidence_;
    queueReview(std::move(next),"All candidates saved inactive. No firewall policy was changed."); return true;
}
bool ProductController::updateCandidate(const QString &id,Data::Action action) {
    if (stopped_ || !reviewWritable() || !store_) return false;
    auto next=pendingReview_ ? *pendingReview_ : inFlightReview_ ? *inFlightReview_ : review_;
    bool found=false;
    for (auto &c:next.report.candidates) if(c.id==id) { c.reviewAction=action; c.reviewed=true; found=true; }
    if (!found) return false;
    queueReview(std::move(next),"Local review saved. Candidate remains inactive."); return true;
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

namespace Gate {
void ProductController::clearProcessHistory() {
    for (auto &p : catalog_.processes) {
        p.historySubjects.clear(); p.historyCauses.clear(); p.identityEvidence.clear(); p.sourceImage.reset();
        p.lastAttemptUtc = {}; p.lastAuthorizedUtc = {}; p.lastTrafficUtc = {};
    }
}
void ProductController::cancelNativeProcesses() {
    nativeProcessTick_.stop(); nativeProcessJob_.reset(); source_.revokeNative(); clearProcessHistory();
}
void ProductController::projectProcessHistory(Data::ProcessCatalogResult &result) {
    for (auto &p:result.processes) {
        if (p.identityEvidence!="SourceRetainedImageAndOwnInstance") continue;
        const auto dates=Data::nativeProcessHistoryDates(history_.state(),p.historyCauses);
        p.lastAttemptUtc=dates.attempt; p.lastAuthorizedUtc=dates.authorization; p.lastTrafficUtc=dates.traffic;
    }
}
void ProductController::advanceNativeProcesses() {
    if (!nativeProcessJob_) return;
    auto &job=*nativeProcessJob_;
    const auto context=records_.currentNativeContext(false);
    if (stopped_ || simulation() || job.age.elapsed()>=10000 || job.generation!=generation_ || !context ||
        !(context->binding==job.context.binding) || context->peer!=job.context.peer || context->connection!=job.context.connection ||
        (job.phase!=NativeProcessJob::StatusBefore && !(context->capabilities & gb::wire::iv::NativeProcessFacts))) {
        catalog_.error="Original process window expired or was invalidated; history is retained.";
        cancelNativeProcesses(); emit changed(); return;
    }
    if (job.pending || (worker_ && worker_->isRunning())) return;
    if (job.phase==NativeProcessJob::Acquire || job.phase==NativeProcessJob::Validate || job.phase==NativeProcessJob::Finish) {
        runNativeWorker(int(job.phase)); return;
    }
    if (job.phase==NativeProcessJob::ReadBefore || job.phase==NativeProcessJob::ReadAfter) {
        if (job.cursor>=job.subjects.size()) {
            job.phase=job.phase==NativeProcessJob::ReadBefore ? NativeProcessJob::Validate : NativeProcessJob::StatusAfter;
            job.cursor=0; advanceNativeProcesses(); return;
        }
        const auto attempt=source_.nativeAttempt(job.batch,job.subjects[job.cursor]);
        if (!attempt) { ++job.cursor; advanceNativeProcesses(); return; }
        if (nativeProcessTag_==UINT64_MAX) { cancelNativeProcesses(); return; }
        const auto tag=++nativeProcessTag_;
        job.tag=tag; job.pending=true;
        if (!records_.requestNativeProcessContext(tag,*attempt)) job.pending=false;
        return;
    }
    if (nativeProcessTag_==UINT64_MAX) { cancelNativeProcesses(); return; }
    const auto tag=++nativeProcessTag_;
    job.tag=tag; job.pending=true;
    if (!records_.requestNativeSnapshotContext(tag)) job.pending=false;
}
void ProductController::runNativeWorker(int phase) {
    if (!nativeProcessJob_ || (worker_ && worker_->isRunning())) return;
    if (worker_) { delete worker_; worker_=nullptr; }
    const auto generation=nativeProcessJob_->generation;
    const auto token=nativeProcessJob_->tag;
    const auto batch=nativeProcessJob_->batch;
    nativeProcessJob_->pending=true;
    worker_=QThread::create([this,generation,token,phase,batch] {
        std::shared_ptr<Data::NativeOwnBatch> acquired;
        Data::ProcessCatalogResult result;
        bool ok=false;
        try {
            if (phase==NativeProcessJob::Acquire) { acquired=source_.acquireNative(); ok=source_.batchCurrent(acquired); }
            else if (phase==NativeProcessJob::Validate) ok=source_.validateNative(batch);
            else { result=source_.finishNative(batch); ok=source_.batchCurrent(batch); }
        } catch (...) { ok=false; }
        QMetaObject::invokeMethod(this,[this,generation,token,phase,acquired,batch,result,ok] {
            if (!nativeProcessJob_ || stopped_ || simulation() || nativeProcessJob_->generation!=generation ||
                nativeProcessJob_->tag!=token || int(nativeProcessJob_->phase)!=phase) return;
            auto &job=*nativeProcessJob_;
            job.pending=false;
            if (!ok) { cancelNativeProcesses(); emit changed(); return; }
            if (phase==NativeProcessJob::Acquire) {
                job.batch=acquired; job.subjects=source_.nativeSubjects(acquired); job.cursor=0;
                job.phase=NativeProcessJob::ReadBefore;
            } else if (phase==NativeProcessJob::Validate) {
                job.subjects=source_.nativeSubjects(batch); job.cursor=0; job.phase=NativeProcessJob::ReadAfter;
            } else {
                const auto current=records_.currentNativeContext();
                if (!current || !(current->binding==job.context.binding) || current->peer!=job.context.peer ||
                    current->connection!=job.context.connection || !source_.publicationCurrent(batch) || job.age.elapsed()>=10000) {
                    cancelNativeProcesses(); emit changed(); return;
                }
                auto published=result; projectProcessHistory(published); catalog_=std::move(published);
                nativeProcessTick_.stop(); nativeProcessJob_.reset(); emit changed(); return;
            }
            advanceNativeProcesses();
        },Qt::QueuedConnection);
    });
    worker_->start();
}
} // namespace Gate
