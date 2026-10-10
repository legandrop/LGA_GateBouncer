#include "productcontroller.h"
#include "data/netlimiterimport.h"
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QStandardPaths>
#include <QMetaObject>
#include <QBuffer>
#include <algorithm>

namespace Gate {
namespace {
QString importedId(const gb::wire::Id &id) {
    return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(id.data()), int(id.size())).toHex());
}
bool importedObservedMatches(const gb::wire::iv::ObservedRecord &row, const Data::ActivityEvent &event) {
    return event.native && row.state == 1 && row.package == 1 && row.display.package.empty() &&
        importedId(row.observed) == event.native->observed && row.revision == event.native->observedRevision &&
        importedId(row.binding) == event.native->captureBinding;
}
bool importedSameAttempt(const Data::ActivityEvent &a, const Data::ActivityEvent &b) {
    if (!Data::validNativeEvent(a) || !Data::validNativeEvent(b) || a.kind != Data::ActivityKind::Attempt ||
        b.kind != Data::ActivityKind::Attempt || Data::nativeEventKey(a) != Data::nativeEventKey(b)) return false;
    const auto &x = *a.native; const auto &y = *b.native;
    return a.subjectId == b.subjectId && x.connection == y.connection && x.observed == y.observed &&
        x.observedRevision == y.observedRevision && x.captureBinding == y.captureBinding && x.source == y.source &&
        x.direction == y.direction && x.protocol == y.protocol && x.presence == y.presence &&
        x.routeMask == y.routeMask && x.unixNanoseconds == y.unixNanoseconds && x.process == y.process;
}
bool importedSameDraft(const gb::wire::iv::FutureDraftRecord &a, const gb::wire::iv::FutureDraftRecord &b) {
    return a.draft == b.draft && a.observed == b.observed && a.source == b.source && a.binding == b.binding &&
        a.selector == b.selector && a.challenge == b.challenge && a.version == b.version &&
        a.observedRevision == b.observedRevision && a.targetRevision == b.targetRevision &&
        a.expectedDesired == b.expectedDesired && a.profile == b.profile && a.target == b.target && a.migration == b.migration &&
        a.ttl == b.ttl && a.durationMs == b.durationMs && a.state == b.state && a.package == b.package &&
        a.direction == b.direction && a.scope == b.scope && a.accepted == b.accepted && a.proof == b.proof && a.reason == b.reason &&
        a.display.name == b.display.name && a.display.path == b.display.path && a.display.principal == b.display.principal &&
        a.display.package == b.display.package && a.display.projection == b.display.projection;
}
QString importedAccount(const QByteArray &sid) {
    if (sid.size() < 12 || quint8(sid[0]) != 1 || sid.size() != 8 + 4 * quint8(sid[1])) return "Unknown";
    quint64 authority = 0;
    for (int i = 2; i < 8; ++i) authority = (authority << 8) | quint8(sid[i]);
    QString text = "S-1-" + QString::number(authority);
    for (int i = 8; i < sid.size(); i += 4) {
        quint32 value = 0;
        for (int b = 0; b < 4; ++b) value |= quint32(quint8(sid[i+b])) << (8*b);
        text += '-' + QString::number(value);
    }
    return text;
}
}
struct ProductController::ImportedActivation {
    QString digest, processId;
    quint64 importGeneration = 0, generation = 0;
    int index = -1;
    Data::QNameProfileView view;
    Data::ActivityEvent attempt;
    Data::QNameApplicationComparison comparison;
    NativeContextSnapshot context;
    std::shared_ptr<Data::NativeOwnBatch> batch;
    quint64 selection = 0;
    std::optional<gb::wire::iv::FutureDraftRecord> draft;
    bool compared = false, selecting = false;
    QElapsedTimer age;
};
struct ProductController::FileActivation {
    enum Phase { Capture, Prepare, CheckReady, Ready, CheckCommit, Sending };
    Phase phase = Capture;
    std::shared_ptr<Data::SelectedApplicationFile> owner;
    Data::Action action = Data::Action::Block;
    Data::Direction direction = Data::Direction::Out;
    gb::wire::Bytes expectedTarget, admittedDraft;
    std::optional<gb::wire::Id> editing;
    quint64 ruleSelection = 0, selection = 0, generation = 0, importGeneration = 0;
    QString candidate, digest;
    QElapsedTimer age;
};
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
      ordinary_(isolatedQa, this, std::move(ordinaryChannel)), administrative_(isolatedQa, this, {}, true) {
    connect(&ordinary_, &OrdinaryDecisionClient::changed, this, [this] { advanceImportedRule(); advanceApplicationFile(); emit changed(); });
    connect(&administrative_, &OrdinaryDecisionClient::changed, this, [this] { advanceApplicationFile(); emit changed(); });
    fileDrain_.setInterval(100);
    connect(&fileDrain_,&QTimer::timeout,this,[this] {
        if (Data::SelectedApplicationFile::physicalJobs()) return;
        fileDrain_.stop(); emit changed();
    });
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
        if (event.kind == Data::ActivityKind::Attempt && event.native) ordinary_.observationChanged();
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
    // El canal administrativo conserva su conexión propia. Ninguna observación
    // foreign entra al catálogo de procesos/lease Own ni al comparador de import.
    administrativeHistoryNotify_.setSingleShot(true);
    connect(&administrativeHistoryNotify_,&QTimer::timeout,this,[this] { if (!stopped_) emit changed(); });
    const auto administrativeChanged = [this] {
        historyChanged();
        if (!stopped_ && !administrativeHistoryNotify_.isActive()) administrativeHistoryNotify_.start(150);
    };
    connect(&administrative_,&OrdinaryDecisionClient::nativeSourceOpened,this,
        [this,administrativeChanged](const Data::NativeSourceBinding &binding,quint64 baseline) {
            if (stopped_ || simulation()) return;
            if (binding.role != 2 || !history_.addNativeSource(binding,baseline)) {
                historyError_ = "Administrative history source was rejected; saved records are preserved.";
                administrative_.rejectHistory(historyError_); return;
            }
            administrativeChanged();
        });
    connect(&administrative_,&OrdinaryDecisionClient::nativeEvent,this,
        [this,administrativeChanged](const Data::ActivityEvent &event) {
            if (stopped_ || simulation()) return;
            if (!history_.ingest(event)) {
                historyError_ = "Administrative monitoring evidence was not retained; history is incomplete.";
                administrativeChanged(); administrative_.rejectHistory(historyError_); return;
            }
            administrativeChanged();
        });
    connect(&administrative_,&OrdinaryDecisionClient::nativeGap,this,
        [this,administrativeChanged](const Data::NativeSourceBinding &binding,quint64 after,quint64 resync,
            quint64 revision,quint8 reason,bool known,quint64 lost) {
            if (stopped_ || simulation()) return;
            if (!history_.nativeGap(binding,after,resync,revision,reason,known,lost)) {
                historyError_ = "Administrative history discontinuity was rejected.";
                administrative_.rejectHistory(historyError_); return;
            }
            administrativeChanged();
        });
    connect(&administrative_,&OrdinaryDecisionClient::nativeSourceLost,this,
        [this,administrativeChanged](const Data::NativeSourceBinding &binding,const QString &reason) {
            history_.disconnectNative(binding,reason); administrativeChanged();
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
    fileActivation_.reset();
    if (fileWorker_) { fileWorker_->wait(); delete fileWorker_; }
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
    cancelApplicationFile(); cancelImportedRule();
    pendingReview_=std::move(document); writeNotification_=notification;
    storeWriteRequested_=true; startReviewWrite(); emit changed();
}
void ProductController::startReviewWrite() {
    // Único escritor físico: la revisión se toma al despachar, nunca de una captura vieja.
    if (storeLoading_ || storeWorker_ || !store_ || !reviewWritable_ ||
        (!storeWriteRequested_ && !historyDirty_ && !pendingRuleBackup_)) return;
    if (pendingRuleBackup_) {
        const auto bytes = *pendingRuleBackup_; const auto id = pendingRuleBackupId_;
        pendingRuleBackup_.reset(); pendingRuleBackupId_ = QUuid{}; savingRuleBackup_ = true;
        auto *store = store_.get();
        storeWorker_ = QThread::create([this,store,bytes,id] {
            Data::StoreResult saved;
            try { saved = store->saveRuleBackup(bytes,id); }
            catch (...) { saved = {Data::StoreStatus::IoError,"Selected rule backup failed; no rule was changed",{}}; }
            QMetaObject::invokeMethod(this,[this,saved,id] {
                savingRuleBackup_ = false;
                if (saved.ok()) emit reviewSaved("Selected rules saved as inactive backup: rules-" +
                    id.toString(QUuid::WithoutBraces) + ".json. No rule was changed.");
                else reviewError_ = saved.error;
                emit changed();
            },Qt::QueuedConnection);
        });
        auto *thread = storeWorker_;
        connect(thread,&QThread::finished,this,[this,thread] {
            if (storeWorker_ == thread) storeWorker_ = nullptr;
            thread->deleteLater(); startReviewWrite(); emit changed();
        });
        thread->start(); return;
    }
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
                pendingRuleBackup_.reset(); pendingRuleBackupId_ = QUuid{};
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
    stopped_ = true; cancelApplicationFile(); cancelImportedRule(); cancelNativeProcesses(); historyFlush_.stop(); ++generation_; cancelImport();
    semanticJob_ = QUuid{}; draftView_ = {}; reviewView_ = {};
    engine_.invalidate(); records_.stop(); ordinary_.stop(); administrative_.stop();
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
    cancelImportedRule();
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
bool ProductController::selectAdministrative(bool enabled) {
    if (stopped_ || simulation()) return false;
    if (enabled == administrativeSelected_) return true;
    const auto available = [](const OrdinaryDecisionClient &client) {
        return client.idle() && client.state() != OrdinaryDecisionClient::State::Sending &&
            client.state() != OrdinaryDecisionClient::State::Uncertain;
    };
    if (fileWorker_ || fileActivation_ || Data::SelectedApplicationFile::physicalJobs() || activation_ ||
        !available(ordinary_) || !available(administrative_)) return false;
    ordinary()->pauseAutomatic(); ordinary()->closeNotice();
    administrativeSelected_ = enabled; ++generation_;
    ordinary()->invalidate();
    emit invalidated(); emit changed();
    // El constructor aislado nunca abre un canal real. La intención tampoco
    // provoca elevación: el servicio rechaza un primary token no admitido.
    if (!isolatedQa_) ordinary()->startAutomatic();
    return true;
}
void ProductController::setMode(UiMode mode) {
    cancelApplicationFile();
    if (stopped_ || mode_ == mode) return;
    cancelNativeProcesses(); mode_ = mode; ++generation_; emit invalidated();
    cancelImport();
    engine_.invalidate();
    records_.invalidate();
    ordinary_.invalidate(); administrative_.invalidate();
    if (!simulation() && !isolatedQa_) ordinary()->startAutomatic();
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
bool ProductController::backupSelectedRules(const std::vector<gb::wire::Id> &rules,quint64 selection,bool consent) {
    if (stopped_ || simulation() || !consent || !store_ || !reviewWritable_ || storeLoading_ || ruleBackupBusy()) return false;
    const auto bytes = ordinary()->selectedRuleBackup(rules,selection);
    if (!bytes) { reviewError_ = "A current selection with complete original AppId and account targets is required for backup.";
        emit changed(); return false; }
    pendingRuleBackup_ = *bytes; pendingRuleBackupId_ = QUuid::createUuid();
    startReviewWrite(); emit changed(); return true;
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
    if (activation_) { activationView_.message = "Inactive: original source connection was lost"; cancelImportedRule(); }
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
    const quint64 activationToken = activation_ ? activationView_.token : 0;
    const auto activationAttempt = activation_ ? std::optional<Data::ActivityEvent>(activation_->attempt) : std::nullopt;
    const auto activationProfile = activation_ ? std::optional<Data::QNameProfileView>(activation_->view) : std::nullopt;
    const int activationIndex = activation_ ? activation_->index : -1;
    nativeProcessJob_->pending=true;
    worker_=QThread::create([this,generation,token,phase,batch,activationToken,activationAttempt,activationProfile,activationIndex] {
        std::shared_ptr<Data::NativeOwnBatch> acquired;
        Data::ProcessCatalogResult result;
        bool ok=false;
        Data::QNameApplicationComparison comparison;
        try {
            if (phase==NativeProcessJob::Acquire) { acquired=source_.acquireNative(); ok=source_.batchCurrent(acquired); }
            else if (phase==NativeProcessJob::Validate) {
                ok=source_.validateNative(batch);
                if (ok && activationAttempt && activationProfile) {
                    const auto held = source_.nativeAttempt(batch, Data::nativeEventKey(*activationAttempt));
                    if (held && importedSameAttempt(*held, *activationAttempt) && held->native->process) {
                        QMap<int,QByteArray> canonical;
                        if (activationIndex >= 0 && activationIndex < activationProfile->candidates.size()) {
                            const auto &candidate = activationProfile->candidates[activationIndex];
                            if (candidate.filterIndex >= 0 && candidate.filterIndex < activationProfile->filters.size()) {
                                const auto &filter = activationProfile->filters[candidate.filterIndex];
                                if (filter.predicates.size() == 1 && filter.predicates[0].applications.size() == 1) {
                                    const auto &application = filter.predicates[0].applications[0];
                                    // Un único pathname local/8KiB: físicamente dentro de ambas READs y own HANDLEs.
                                    if (application.path.known() && application.path.value == held->native->process->image) {
                                        const auto id = Data::canonicalLocalApplicationId(application.path.value);
                                        if (id) canonical.insert(application.node, *id);
                                    }
                                }
                            }
                        }
                        const auto &facts = *held->native->process;
                        comparison = Data::compareQNameApplicationScope(*activationProfile, activationIndex,
                            facts.appId, facts.accountSid, facts.image, canonical);
                    }
                }
            }
            else { result=source_.finishNative(batch); ok=source_.batchCurrent(batch); }
        } catch (...) { ok=false; }
        QMetaObject::invokeMethod(this,[this,generation,token,phase,acquired,batch,result,ok,activationToken,comparison] {
            if (!nativeProcessJob_ || stopped_ || simulation() || nativeProcessJob_->generation!=generation ||
                nativeProcessJob_->tag!=token || int(nativeProcessJob_->phase)!=phase) return;
            auto &job=*nativeProcessJob_;
            job.pending=false;
            if (!ok) { cancelNativeProcesses(); emit changed(); return; }
            if (phase==NativeProcessJob::Acquire) {
                job.batch=acquired; job.subjects=source_.nativeSubjects(acquired); job.cursor=0;
                job.phase=NativeProcessJob::ReadBefore;
            } else if (phase==NativeProcessJob::Validate) {
                if (activation_ && activationToken == activationView_.token) activation_->comparison = comparison;
                job.subjects=source_.nativeSubjects(batch); job.cursor=0; job.phase=NativeProcessJob::ReadAfter;
            } else {
                const auto current=records_.currentNativeContext();
                if (!current || !(current->binding==job.context.binding) || current->peer!=job.context.peer ||
                    current->connection!=job.context.connection || !source_.publicationCurrent(batch) || job.age.elapsed()>=10000) {
                    cancelNativeProcesses(); emit changed(); return;
                }
                auto published=result; projectProcessHistory(published); catalog_=std::move(published);
                finishImportedComparison(*current,batch,catalog_);
                nativeProcessTick_.stop(); nativeProcessJob_.reset(); emit changed(); return;
            }
            advanceNativeProcesses();
        },Qt::QueuedConnection);
    });
    worker_->start();
}
} // namespace Gate

namespace Gate {
void ProductController::cancelImportedRule() {
    const bool owned = activation_ && activation_->selecting && ordinary_.observed() &&
        importedObservedMatches(*ordinary_.observed(), activation_->attempt);
    activation_.reset(); activationView_.ready = activationView_.busy = false;
    if (owned && ordinary_.state() != OrdinaryDecisionClient::State::Sending &&
        ordinary_.state() != OrdinaryDecisionClient::State::Uncertain) ordinary_.closeNotice();
}
bool ProductController::prepareImportedRule(const QString &candidate, const QString &processIdValue) {
    if (administrativeSelected_) return false; // El puente causal de procesos foreign sigue pendiente.
    cancelImportedRule(); activationView_ = {}; activationView_.candidate = candidate; activationView_.process = processIdValue;
    activationView_.message = "Inactive: current original process and request evidence are required";
    const auto *p = process(processIdValue);
    const auto *sourceCandidate = derivedQNameCandidate(false, candidate);
    const auto context = records_.currentNativeContext();
    if (stopped_ || simulation() || !reviewWritable() || pendingReview_ || !reviewView_.current || !reviewView_.qname ||
        !sourceCandidate || !p || !p->sourceImage || p->identityEvidence != "SourceRetainedImageAndOwnInstance" ||
        !context || !ordinary_.current() || !ordinary_.idle() || nativeProcessJob_ ||
        (worker_ && worker_->isRunning()) || activationToken_ == UINT64_MAX) { emit changed(); return false; }
    const Data::ActivityEvent *cause = nullptr;
    for (const auto &event : p->historyCauses) if (event && event->native && event->native->process == p->sourceImage) {
        const auto row = std::find_if(ordinary_.observations().begin(), ordinary_.observations().end(),
            [&](const auto &r) { return importedObservedMatches(r, *event) && importedId(r.source) == context->binding.sourceEpoch; });
        if (row != ordinary_.observations().end()) { cause = event.get(); break; }
    }
    if (!cause || !Data::validNativeEvent(*cause)) { emit changed(); return false; }
    for (const auto &row : review_.report.candidates) if (row.id == candidate && row.reviewAction &&
        (!sourceCandidate->action.known() || *row.reviewAction !=
            (sourceCandidate->action.value == Data::SourceFwAction::Allow ? Data::Action::Allow : Data::Action::Block))) {
        activationView_.message = "Inactive: the local review choice differs from the original source policy";
        emit changed(); return false;
    }
    auto request = std::make_unique<ImportedActivation>();
    request->digest = review_.report.digest; request->generation = generation_; request->importGeneration = importGeneration_;
    request->processId = processIdValue; request->view = *reviewView_.qname; request->attempt = *cause; request->context = *context;
    request->index = reviewView_.candidates.value(candidate, -1); request->age.start();
    activation_ = std::move(request); activationView_.token = ++activationToken_;
    activationView_.busy = true; activationView_.message = "Rechecking original process custody, AppId, SID and source precedence…";
    if (!refreshProcesses() || !nativeProcessJob_) { cancelImportedRule(); emit changed(); return false; }
    const auto token = activationView_.token;
    QTimer::singleShot(10000, this, [this,token] {
        if (activation_ && activationView_.token == token) {
            activationView_.message = "Inactive: original comparison expired; prepare it again";
            cancelImportedRule(); emit changed();
        }
    });
    emit changed(); return true;
}
bool ProductController::importedRuleCurrent() const {
    if (!activation_ || stopped_ || simulation() || activation_->age.elapsed() >= 10000 ||
        activation_->generation != generation_ || activation_->importGeneration != importGeneration_ ||
        activation_->digest != review_.report.digest || pendingReview_ || !reviewView_.current) return false;
    const auto context = records_.currentNativeContext();
    if (!context || !(context->binding == activation_->context.binding) ||
        context->peer != activation_->context.peer || context->connection != activation_->context.connection) return false;
    return !activation_->compared || source_.publicationCurrent(activation_->batch);
}
void ProductController::finishImportedComparison(const NativeContextSnapshot &context,
    const std::shared_ptr<Data::NativeOwnBatch> &batch, const Data::ProcessCatalogResult &published) {
    if (!activation_) return;
    if (!importedRuleCurrent() || !(context.binding == activation_->context.binding) ||
        context.peer != activation_->context.peer || context.connection != activation_->context.connection ||
        !activation_->comparison.representable) {
        activationView_.message = activation_->comparison.reason.isEmpty()
            ? "Inactive: original identity or source context changed" : "Inactive: " + activation_->comparison.reason;
        cancelImportedRule(); return;
    }
    bool admitted = false;
    for (const auto &p : published.processes) for (const auto &cause : p.historyCauses)
        admitted |= cause && importedSameAttempt(*cause, activation_->attempt);
    if (!admitted) { activationView_.message = "Inactive: exact original cause was not admitted by both fresh reads"; cancelImportedRule(); return; }
    activation_->batch = batch; activation_->context = context; activation_->compared = true;
    const auto row = std::find_if(ordinary_.observations().begin(), ordinary_.observations().end(),
        [&](const auto &r) { return importedObservedMatches(r, activation_->attempt) && importedId(r.source) == context.binding.sourceEpoch; });
    const auto token = activationView_.token;
    if (row == ordinary_.observations().end() || !ordinary_.select(row->observed)) {
        activationView_.message = "Inactive: original request cannot prepare a selector"; cancelImportedRule(); return;
    }
    if (!activation_ || activationView_.token != token) return;
    activation_->selecting = true; activationView_.message = "Preparing the original application/account selector…";
    advanceImportedRule();
}
void ProductController::advanceImportedRule() {
    if (!activation_) return;
    if (!importedRuleCurrent()) { activationView_.message = "Inactive: original process, source or review expired"; cancelImportedRule(); return; }
    if (!activation_->selecting) return;
    if (ordinary_.state() == OrdinaryDecisionClient::State::Failed || ordinary_.state() == OrdinaryDecisionClient::State::Closed ||
        ordinary_.state() == OrdinaryDecisionClient::State::Sending || ordinary_.state() == OrdinaryDecisionClient::State::Uncertain) {
        activationView_.message = ordinary_.message(); cancelImportedRule(); return;
    }
    if (!ordinary_.ready()) return;
    if (!ordinary_.idle()) {
        QTimer::singleShot(50,this,[this] { if (activation_) { advanceImportedRule(); emit changed(); } });
        return;
    }
    const auto observed = ordinary_.observed(); const auto ordinaryContext = ordinary_.observationContext();
    const auto &binding = activation_->context.binding;
    if (!observed || !importedObservedMatches(*observed, activation_->attempt) || !ordinaryContext ||
        importedId(observed->source) != binding.sourceEpoch || importedId(ordinaryContext->service.serviceEpoch) != binding.serviceEpoch ||
        importedId(ordinaryContext->service.boot) != binding.boot || importedId(ordinaryContext->service.engineContext) != binding.engineContext ||
        ordinaryContext->service.engineBindingGeneration != binding.generation || ordinaryContext->profile != binding.profile) {
        activationView_.message = "Inactive: original selector and native cause have different source contexts"; cancelImportedRule(); return;
    }
    if (activationView_.ready && (ordinary_.selection() != activation_->selection || !activation_->draft || !ordinary_.draft() ||
        !importedSameDraft(*ordinary_.draft(), *activation_->draft))) {
        activationView_.message = "Inactive: original selector or consent challenge changed"; cancelImportedRule(); return;
    }
    if (ordinary_.selectedScope() != 2) {
        if (!ordinary_.scope(2)) { activationView_.message = "Inactive: original duration could not be prepared"; cancelImportedRule(); }
        return;
    }
    const int direction = activation_->comparison.direction == Data::Direction::In ? 2 :
        activation_->comparison.direction == Data::Direction::Both ? 3 : 1;
    if (ordinary_.selectedDirection() != direction) {
        if (!ordinary_.direction(direction)) { activationView_.message = "Inactive: original direction could not be prepared"; cancelImportedRule(); }
        return;
    }
    const auto draft = ordinary_.draft();
    if (!draft || draft->package != 1 || draft->scope != 2 || draft->direction != direction ||
        !std::all_of(draft->migration.begin(), draft->migration.end(), [](auto byte) { return byte == 0; })) {
        activationView_.message = "Inactive: original application scope is not representable"; cancelImportedRule(); return;
    }
    activation_->selection = ordinary_.selection(); activation_->draft = draft;
    activationView_.ready = true; activationView_.busy = false;
    const auto scopeText = Data::applicationRuleScopeText(draft->package,
        draft->direction == 1 ? Data::Direction::Out : draft->direction == 2 ? Data::Direction::In : Data::Direction::Both,
        activation_->comparison.action.value == Data::SourceFwAction::Allow ? Data::Action::Allow : Data::Action::Block,
        observed->temporal == 2);
    activationView_.message = QString("Ready to confirm a new %1 rule.\nApplication: %2\nAccount: %3\nDirection: %4\nPackage: %5\nWill apply to: %6\nWill cover: %7\n%8\n%9\nSource candidates stay inactive.")
        .arg(activation_->comparison.action.value == Data::SourceFwAction::Allow ? "Allow" : "Block",
             activation_->attempt.native->process->image, importedAccount(activation_->attempt.native->process->accountSid),
             Data::directionName(activation_->comparison.direction), scopeText.package, scopeText.scope,
             scopeText.connections, scopeText.coverage, scopeText.originalAttempt);
}
bool ProductController::confirmImportedRule(quint64 token, bool consent) {
    advanceImportedRule();
    if (!consent || !activation_ || !activationView_.ready || token != activationView_.token ||
        !importedRuleCurrent() || !ordinary_.ready() || ordinary_.selection() != activation_->selection) return false;
    const bool allow = activation_->comparison.action.value == Data::SourceFwAction::Allow;
    const auto selection = activation_->selection;
    activation_.reset(); activationView_.ready = activationView_.busy = false;
    const bool sent = ordinary_.decide(allow, true, selection);
    activationView_.message = sent ? "Decision submitted to the original service; the imported archive remains inactive. Check the same command if its outcome is unknown."
                                   : "Inactive: the original selector expired before confirmation";
    emit changed(); return sent;
}
void ProductController::cancelApplicationFile() {
    ++fileRuleToken_; fileRuleView_.token = fileRuleToken_;
    fileRuleView_.ready = fileRuleView_.busy = false;
    fileActivation_.reset();
    if (ordinary()->fileOwner_ && ordinary()->state() != OrdinaryDecisionClient::State::Sending &&
        ordinary()->state() != OrdinaryDecisionClient::State::Uncertain) ordinary()->closeNotice();
    if (Data::SelectedApplicationFile::physicalJobs()) fileDrain_.start();
}
bool ProductController::prepareApplicationFile(const QString &path, Data::Action action, Data::Direction direction,
    const std::optional<gb::wire::Id> &editing, quint64 selection, const QString &candidate, int backupIndex) {
    if (stopped_ || simulation() || isolatedQa_ || fileWorker_ || Data::SelectedApplicationFile::physicalJobs() ||
        fileActivation_ || activation_ || ordinary()->visible() || !ordinary()->idle() ||
        ordinary()->state() == OrdinaryDecisionClient::State::Sending || ordinary()->state() == OrdinaryDecisionClient::State::Uncertain ||
        (action != Data::Action::Allow && action != Data::Action::Block) ||
        (direction != Data::Direction::Out && direction != Data::Direction::In && direction != Data::Direction::Both)) return false;
    std::optional<Data::QNameProfileView> profile; int index = -1;
    if (!candidate.isEmpty()) {
        if (administrativeSelected_) {
            fileRuleView_.message = "Inactive: imported account and predicate migration requires its original cross-account bridge.";
            emit changed(); return false;
        }
        if (!reviewView_.current || !reviewView_.qname || pendingReview_ || reviewBusy()) return false;
        const auto found = reviewView_.candidates.find(candidate);
        if (found == reviewView_.candidates.end()) return false;
        index = found.value(); profile = reviewView_.qname;
        for (const auto &r : review_.report.candidates) if (r.id == candidate && r.reviewAction && *r.reviewAction != action) {
            fileRuleView_.message = "Inactive: the local review choice differs from the original source policy."; emit changed(); return false;
        }
    }
    gb::wire::Bytes expectedTarget;
    if (backupIndex >= 0) {
        if (!candidate.isEmpty() || editing || std::size_t(backupIndex) >= inactiveRuleBackup_.size()) return false;
        const auto &r = inactiveRuleBackup_[std::size_t(backupIndex)];
        if (r.package != 1 || r.action != (action == Data::Action::Allow ? 2 : 1) ||
            r.direction != (direction == Data::Direction::Out ? 1 : direction == Data::Direction::In ? 2 : 3)) {
            fileRuleView_.message = "Inactive: this backup scope cannot be restored by the application and account route."; emit changed(); return false;
        }
        expectedTarget = r.originalTarget;
    }
    auto request = std::make_unique<FileActivation>();
    request->action = action; request->direction = direction; request->editing = editing; request->ruleSelection = selection;
    request->expectedTarget = expectedTarget; request->candidate = candidate; request->generation = generation_;
    request->importGeneration = importGeneration_; request->digest = review_.report.digest; request->age.start();
    fileActivation_ = std::move(request); fileRuleView_ = {"Retaining the selected executable under your original account…",++fileRuleToken_,true,false};
    const auto token = fileRuleToken_;
    struct Capture { std::shared_ptr<Data::SelectedApplicationFile> owner; QString error; Data::QNameApplicationComparison comparison; };
    auto result = std::make_shared<Capture>();
    auto *worker = QThread::create([path,profile,index,result] {
        try {
            result->owner = Data::SelectedApplicationFile::acquire(path,result->error);
            if (!result->owner) return;
            if (profile) {
                QMap<int,QByteArray> canonical;
                const auto &facts = result->owner->facts();
                // Sólo el archivo retenido permite el match positivo. Competidores no resueltos siguen bloqueando.
                for (const auto &filter : profile->filters) for (const auto &predicate : filter.predicates)
                    for (const auto &application : predicate.applications) if (application.path.known() && application.path.value == facts.image)
                        canonical.insert(application.node,facts.appId);
                result->comparison = Data::compareQNameApplicationScope(*profile,index,facts.appId,facts.accountSid,facts.image,canonical);
            }
            if (!result->owner->current()) { result->owner.reset(); result->error = "The original executable or account changed."; }
        } catch (...) { result->owner.reset(); result->error = "The original file inspection did not complete."; }
    });
    fileWorker_ = worker;
    connect(worker,&QThread::finished,this,[this,worker,result,token,profile] {
        if (fileWorker_ == worker) fileWorker_ = nullptr;
        worker->deleteLater();
        if (!fileActivation_ || stopped_ || token != fileRuleToken_) {
            if (Data::SelectedApplicationFile::physicalJobs()) fileDrain_.start(); return;
        }
        auto &request = *fileActivation_;
        const bool sourceMatches = !profile || (result->comparison.representable && result->comparison.direction == request.direction &&
            result->comparison.action.known() && result->comparison.action.value ==
                (request.action == Data::Action::Allow ? Data::SourceFwAction::Allow : Data::SourceFwAction::Deny));
        if (!result->owner || !sourceMatches || generation_ != request.generation ||
            (!request.candidate.isEmpty() && (importGeneration_ != request.importGeneration || review_.report.digest != request.digest || !reviewView_.current))) {
            fileRuleView_.message = "Inactive: " + (!result->error.isEmpty() ? result->error : result->comparison.reason.isEmpty()
                ? "the original source scope, account or precedence cannot be represented" : result->comparison.reason);
            cancelApplicationFile(); emit changed(); return;
        }
        request.owner = result->owner; request.phase = FileActivation::Prepare;
        const int direction = request.direction == Data::Direction::Out ? 1 : request.direction == Data::Direction::In ? 2 : 3;
        if (!ordinary()->prepareFile(request.owner,direction,request.expectedTarget,request.editing,request.ruleSelection)) {
            fileRuleView_.message = "Inactive: the original service cannot prepare this file rule."; cancelApplicationFile(); emit changed(); return;
        }
        advanceApplicationFile(); emit changed();
    });
    worker->start(); emit changed(); return true;
}
void ProductController::advanceApplicationFile() {
    if (!fileActivation_) return;
    auto &request = *fileActivation_;
    if (request.phase == FileActivation::Capture || request.phase == FileActivation::CheckReady || request.phase == FileActivation::CheckCommit) return;
    if (stopped_ || simulation() || request.generation != generation_ || request.age.elapsed() >= 120000 ||
        (!request.candidate.isEmpty() && (request.importGeneration != importGeneration_ || request.digest != review_.report.digest || !reviewView_.current || pendingReview_))) {
        fileRuleView_.message = "Inactive: the original file review or imported source expired."; cancelApplicationFile(); return;
    }
    const auto state = ordinary()->state();
    if (state == OrdinaryDecisionClient::State::Failed || state == OrdinaryDecisionClient::State::Recorded || state == OrdinaryDecisionClient::State::Uncertain) {
        fileRuleView_.message = ordinary()->message(); cancelApplicationFile(); return;
    }
    if (!ordinary()->ready() || !ordinary()->fileDraft()) return;
    if (!ordinary()->idle()) { QTimer::singleShot(50,this,[this] { advanceApplicationFile(); }); return; }
    gb::wire::Bytes packed;
    if (gb::wire::iv::pack(std::vector<gb::wire::iv::FileFutureDraftRecord>{*ordinary()->fileDraft()},packed) != gb::wire::Error::Ok) {
        fileRuleView_.message = "Inactive: the original draft could not be retained."; cancelApplicationFile(); return;
    }
    if (request.phase == FileActivation::Ready) {
        if (request.selection != ordinary()->selection() || request.admittedDraft != packed) {
            fileRuleView_.message = "Inactive: the original draft or consent challenge changed."; cancelApplicationFile();
        }
        return;
    }
    if (request.phase == FileActivation::Prepare) {
        request.selection = ordinary()->selection(); request.admittedDraft = std::move(packed); checkApplicationFile(false);
    }
}
void ProductController::checkApplicationFile(bool committing) {
    if (!fileActivation_ || fileWorker_) return;
    auto &request = *fileActivation_;
    request.phase = committing ? FileActivation::CheckCommit : FileActivation::CheckReady;
    fileRuleView_.ready = false; fileRuleView_.busy = true;
    const auto owner = request.owner; const auto token = fileRuleToken_;
    auto result = std::make_shared<bool>(false);
    auto *worker = QThread::create([owner,result] { try { *result = owner && owner->current(); } catch (...) {} });
    fileWorker_ = worker;
    connect(worker,&QThread::finished,this,[this,worker,result,token,committing] {
        if (fileWorker_ == worker) fileWorker_ = nullptr; worker->deleteLater();
        if (!fileActivation_ || stopped_ || token != fileRuleToken_) return;
        auto &request = *fileActivation_; gb::wire::Bytes packed;
        const bool same = *result && ordinary()->ready() && ordinary()->idle() && ordinary()->selection() == request.selection && ordinary()->fileDraft() &&
            gb::wire::iv::pack(std::vector<gb::wire::iv::FileFutureDraftRecord>{*ordinary()->fileDraft()},packed) == gb::wire::Error::Ok &&
            packed == request.admittedDraft && request.generation == generation_ && request.age.elapsed() < 120000 &&
            (request.candidate.isEmpty() || (request.importGeneration == importGeneration_ && request.digest == review_.report.digest && reviewView_.current && !pendingReview_));
        if (!same) {
            fileRuleView_.message = "Inactive: the retained file, original account, service or reviewed draft changed.";
            cancelApplicationFile(); emit changed(); return;
        }
        fileRuleView_.busy = false;
        if (committing) {
            request.phase = FileActivation::Sending;
            const bool sent = ordinary()->decideFile(request.action == Data::Action::Allow,true,request.selection);
            fileRuleView_.message = sent ? "Rule submitted to the original service. If its outcome is unknown, check the same command; do not repeat it."
                                        : "Inactive: the original draft expired before submission.";
            if (!sent) cancelApplicationFile(); emit changed(); return;
        }
        request.phase = FileActivation::Ready; fileRuleView_.ready = true;
        const auto &facts = request.owner->facts();
        const auto &fileDraft = *ordinary()->fileDraft(); const auto &draft = fileDraft.draft;
        gb::wire::iv::OriginalTarget target;
        if (gb::wire::iv::unpackOriginalTarget(fileDraft.originalTarget,target) != gb::wire::Error::Ok) {
            fileRuleView_.message = "Inactive: the original target account is unavailable."; cancelApplicationFile(); return;
        }
        const QByteArray targetSid(reinterpret_cast<const char *>(target.accountSid.data()),qsizetype(target.accountSid.size()));
        const auto scope = Data::applicationRuleScopeText(draft.package,request.direction,request.action,false);
        fileRuleView_.message = QString("Ready to confirm %1.\nApplication: %2\nAccount: %3\nDirection: %4\nPackage: %5\nWill apply to: %6\nWill cover: %7\n%8\nNo existing connection or request is changed. Imported documents and backups remain inactive.")
            .arg(request.editing ? "an atomic rule replacement" : "a new rule for future connections",facts.image,importedAccount(targetSid),
                Data::directionName(request.direction),scope.package,scope.scope,scope.connections,scope.coverage);
        fileRuleView_.message.prepend(QString("Decision: %1\n").arg(request.action == Data::Action::Allow ? "Allow" : "Block"));
        if (administrativeSelected_) fileRuleView_.message.prepend("Acting account: " + importedAccount(facts.accountSid) +
            " · original authenticated administrative session\n");
        if (ordinary()->editing_) {
            const auto &old = *ordinary()->editing_;
            fileRuleView_.message.prepend(QString("Replacing selected rule: %1 · %2 · %3\n")
                .arg(QString::fromUtf8(reinterpret_cast<const char *>(old.display.name.data()),qsizetype(old.display.name.size())),
                     old.action == 2 ? "Allow" : "Block",Data::directionName(old.direction == 1 ? Data::Direction::Out : old.direction == 2 ? Data::Direction::In : Data::Direction::Both)));
        }
        emit changed();
    });
    worker->start();
}
bool ProductController::confirmApplicationFile(quint64 token, bool consent) {
    advanceApplicationFile();
    if (!consent || !fileActivation_ || !fileRuleView_.ready || token != fileRuleToken_ || fileWorker_ ||
        fileActivation_->phase != FileActivation::Ready) return false;
    checkApplicationFile(true); emit changed(); return true;
}
bool ProductController::loadSelectedRuleBackup(const QString &path) {
    if (stopped_ || simulation() || fileWorker_ || fileActivation_ || ordinary()->state() == OrdinaryDecisionClient::State::Sending ||
        ordinary()->state() == OrdinaryDecisionClient::State::Uncertain) return false;
    inactiveRuleBackup_.clear();
    fileRuleView_ = {"Opening an inactive selected rule backup…",++fileRuleToken_,true,false};
    const auto token = fileRuleToken_;
    struct Read { Data::StoreResult result; std::vector<gb::wire::iv::PrincipalRuleRecord> records; };
    auto result = std::make_shared<Read>();
    auto *worker = QThread::create([path,result] {
        try { result->result = Data::ReviewStore::loadRuleBackup(path,result->records); }
        catch (...) { result->result = {Data::StoreStatus::IoError,"Inactive backup read did not complete",{}}; }
    });
    fileWorker_ = worker;
    connect(worker,&QThread::finished,this,[this,worker,result,token] {
        if (fileWorker_ == worker) fileWorker_ = nullptr; worker->deleteLater();
        if (stopped_ || token != fileRuleToken_) return;
        fileRuleView_.busy = false;
        if (result->result.ok()) {
            inactiveRuleBackup_ = std::move(result->records);
            fileRuleView_.message = "Inactive backup opened. Each selected executable and original account must match again before confirmation.";
        } else fileRuleView_.message = result->result.error;
        emit changed();
    });
    worker->start(); emit changed(); return true;
}
QString ProductController::ruleBackupDirectory() const {
    return store_ ? QFileInfo(store_->filePath()).absolutePath() : QString{};
}
} // namespace Gate
