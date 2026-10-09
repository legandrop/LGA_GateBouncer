#include "OrdinaryDecisionClient.h"
#include <ordinary_iii_win.h>
#include <QCoreApplication>
#include <QDir>
#include <QUuid>
#include <algorithm>
namespace Gate {
using namespace gb::wire;
namespace {
Id freshId() {
    const auto bytes = QUuid::createUuid().toRfc4122();
    Id id{}; std::copy_n(reinterpret_cast<const unsigned char *>(bytes.constData()), 16, id.begin()); return id;
}
Field digest(Tag tag, const Digest &value) { return {tag, true, Bytes(value.begin(), value.end())}; }
std::unique_ptr<gb::ipc::ii::SessionChannel> channelFor(bool qa, std::unique_ptr<gb::ipc::ii::SessionChannel> channel) {
    if (channel || qa) return channel;
    return std::make_unique<gb::ipc::iii::OrdinaryClient>();
}
}
OrdinaryDecisionClient::OrdinaryDecisionClient(bool isolatedQa, QObject *parent,
                                             std::unique_ptr<gb::ipc::ii::SessionChannel> channel)
    : QObject(parent), session_(this, channelFor(isolatedQa, std::move(channel))) {
    connect(&session_, &gb::controller::OrdinarySession::opened, this, &OrdinaryDecisionClient::opened);
    connect(&session_, &gb::controller::OrdinarySession::received, this, &OrdinaryDecisionClient::received);
    draftExpiry_.setSingleShot(true);
    connect(&draftExpiry_, &QTimer::timeout, this, [this] {
        if (state_ == State::Ready) { draft_.reset(); state_ = State::Failed;
            message_ = "Review expired. Reopen the request before deciding."; emit changed(); }
    });
    // QA depende de un canal inyectado; sin canal nunca conecta con el equipo.
    poll_.setInterval(12000);
    connect(&poll_, &QTimer::timeout, this, [this] {
        if (!session_.idle()) return;
        if (visible_ && state_ == State::Ready) { checkOnly_ = true; send(Type::GetStatus); }
        else if (!visible_ && state_ != State::Sending && state_ != State::Uncertain) refresh();
    });
}
void OrdinaryDecisionClient::startAutomatic() {
    if (stopping_) return;
    automatic_ = true; poll_.start();
    if (!visible_ && state_ != State::Sending && state_ != State::Uncertain) refresh();
}
void OrdinaryDecisionClient::showNext() {
    if (!automatic_ || !current_ || visible_ || !session_.idle() || state_ == State::Sending || state_ == State::Uncertain) return;
    for (const auto &row : rows_) {
        const ShownKey key{epoch_, boot_, source_, profile_, row.revision};
        auto shown = shown_.find(row.observed);
        if (shown == shown_.end() || shown->second != key) { select(row.observed); return; }
    }
}
bool OrdinaryDecisionClient::refresh() {
    if (stopping_ || !session_.idle() || state_ == State::Sending || state_ == State::Uncertain) return false;
    closeNotice(); current_ = false; rows_.clear(); pageRows_.clear(); ids_.clear();
    state_ = State::Loading; message_ = "Reading admitted observations…"; finalStatus_ = false; checkOnly_ = false;
    emit changed();
    if (!connected_) {
        const auto image = QDir(QCoreApplication::applicationDirPath()).filePath("GateBouncerService.exe");
        if (!session_.open(std::filesystem::path(image.toStdWString()))) { fail("Ordinary decisions unavailable."); return false; }
        return true;
    }
    return send(Type::GetStatus);
}
bool OrdinaryDecisionClient::status(const Frame &f, bool same) {
    if (f.minor != 3 || iv::validate(f) != Error::Ok ||
        (f.type != Type::HelloAck && f.type != Type::Status) || get(f, Tag::IVProfile) != 1 ||
        (get(f, Tag::Capabilities) & (ObservedRead | FuturePolicyControl)) != (ObservedRead | FuturePolicyControl) ||
        zero(idValue(f, Tag::SourceEpoch)) || !get(f, Tag::ProfileGeneration) ||
        get(f, Tag::EffectiveKnown) || get(f, Tag::EffectiveRev)) return false;
    const auto *context = find(f, Tag::ServiceContext);
    std::uint64_t binding = 0;
    for (unsigned i = 0; i != 8; ++i) binding |= std::uint64_t(context->bytes[48 + i]) << (i * 8);
    if (!binding || (same && (f.connection != connection_ || idValue(f, Tag::ServiceEpoch) != epoch_ ||
        idValue(f, Tag::BootId) != boot_ || idValue(f, Tag::SourceEpoch) != source_ ||
        get(f, Tag::ProfileGeneration) != profile_ || get(f, Tag::DesiredRev) != desired_ || binding != bindingGeneration_))) return false;
    connection_ = f.connection; epoch_ = idValue(f, Tag::ServiceEpoch); boot_ = idValue(f, Tag::BootId);
    source_ = idValue(f, Tag::SourceEpoch); profile_ = get(f, Tag::ProfileGeneration);
    desired_ = get(f, Tag::DesiredRev); bindingGeneration_ = binding; return !zero(connection_);
}
void OrdinaryDecisionClient::opened(bool ok, Frame f) {
    if (stopping_) return;
    if (state_ == State::Uncertain) {
        if (!ok || f.type != Type::HelloAck || iv::validate(f) != Error::Ok ||
            idValue(f, Tag::ServiceEpoch) != epoch_ || idValue(f, Tag::BootId) != boot_ ||
            get(f, Tag::ProfileGeneration) != profile_ || get(f, Tag::EffectiveKnown) || get(f, Tag::EffectiveRev) || zero(f.connection)) {
            connected_ = false; fail("The original receipt owner is unavailable. Outcome remains unknown.", true); return;
        }
        connected_ = true; connection_ = f.connection;
        send(Type::GetFutureCommandStatus, {value(Tag::CommandId, command_)}); return;
    }
    if (state_ != State::Loading) return;
    if (!ok || f.type != Type::HelloAck || !status(f, false)) { fail("Ordinary actor or source admission unavailable."); return; }
    connected_ = true; send(Type::GetStatus);
}
bool OrdinaryDecisionClient::send(Type type, std::vector<Field> fields) {
    Frame f; f.minor = 3; f.type = type; f.connection = connection_; f.correlation = freshId();
    if (type != Type::GetStatus) fields.push_back(value(Tag::ServiceEpoch, epoch_));
    std::sort(fields.begin(), fields.end(), [](const auto &a, const auto &b) { return a.tag < b.tag; });
    f.fields = std::move(fields); expected_ = f.correlation; expectedType_ = type;
    if (type == Type::CommitFuturePolicy) {
        command_ = f.correlation;
        submitted_ = SubmittedPresentation{f, draft_->display, boot_, observed_->observed,
            observed_->revision, bindingGeneration_};
    }
    if (iv::validate(f) != Error::Ok || !session_.request(std::move(f), generation_)) {
        fail("Ordinary request unavailable.", type == Type::CommitFuturePolicy || type == Type::GetFutureCommandStatus); return false;
    }
    return true;
}
void OrdinaryDecisionClient::page() {
    send(Type::ListObserved, {value(Tag::SnapshotId, snapshot_), value(Tag::Cursor, cursor_, 4), value(Tag::Limit, 32, 2)});
}
bool OrdinaryDecisionClient::select(const Id &id) {
    if (!current_ || !session_.idle() || state_ == State::Sending || state_ == State::Uncertain) return false;
    auto row = std::find_if(rows_.begin(), rows_.end(), [&](const auto &r) { return r.observed == id && r.state == 1; });
    if (row == rows_.end()) return false;
    closeNotice(); observed_ = *row; visible_ = true; direction_ = 1;
    shown_[row->observed] = ShownKey{epoch_, boot_, source_, profile_, row->revision};
    state_ = State::Preparing; message_ = "Rechecking this observation…"; emit changed();
    return send(Type::GetObservedRecord, {value(Tag::ObservedId, row->observed),
        value(Tag::ObservedRevision, row->revision), value(Tag::SourceEpoch, row->source)});
}
bool OrdinaryDecisionClient::direction(int direction) {
    if (!visible_ || !current_ || !observed_ || !session_.idle() || direction < 1 || direction > 3 ||
        state_ == State::Sending || state_ == State::Uncertain) return false;
    ++generation_; draftExpiry_.stop(); draft_.reset(); direction_ = direction;
    state_ = State::Preparing; message_ = "Preparing the selected future scope…"; emit changed(); prepare(); return true;
}
void OrdinaryDecisionClient::prepare() {
    send(Type::PrepareFuturePolicy, {value(Tag::ExpectedDesiredRev, desired_), value(Tag::PolicyDirection, direction_, 1),
        value(Tag::ProfileGeneration, profile_), value(Tag::ObservedId, observed_->observed),
        value(Tag::ObservedRevision, observed_->revision), value(Tag::SourceEpoch, source_), value(Tag::IVProfile, 1, 1)});
}
void OrdinaryDecisionClient::closeNotice() {
    visible_ = false; draftExpiry_.stop();
    if (state_ != State::Sending && state_ != State::Uncertain) {
        ++generation_; draft_.reset(); observed_.reset(); submitted_.reset(); state_ = State::Closed;
    }
    emit changed();
    if (automatic_) QTimer::singleShot(0, this, &OrdinaryDecisionClient::showNext);
}
bool OrdinaryDecisionClient::ready() const {
    return current_ && visible_ && state_ == State::Ready && draft_ && draftAge_.isValid() && draftAge_.elapsed() < draft_->ttl;
}
bool OrdinaryDecisionClient::decide(bool allow, bool consent, quint64 selection) {
    if (!consent || selection != generation_ || !ready() || !session_.idle()) return false;
    const auto d = *draft_; const auto accepted = d.accepted | (allow && d.direction == 3 ? 4u : 0u);
    draftExpiry_.stop(); state_ = State::Sending; message_ = "Saving the reviewed future rule…";
    const bool sent = send(Type::CommitFuturePolicy, {value(Tag::ExpectedDesiredRev, d.expectedDesired),
        value(Tag::Decision, allow ? 2 : 1, 1), value(Tag::ScopeKind, d.scope, 1), value(Tag::SelectorId, d.selector),
        value(Tag::PolicyDirection, d.direction, 1), value(Tag::ProfileGeneration, d.profile), value(Tag::SourceEpoch, d.source),
        value(Tag::DraftId, d.draft), value(Tag::DraftVersion, d.version), value(Tag::TargetRevision, d.targetRevision),
        value(Tag::PackageMode, d.package, 1), value(Tag::AcceptedScope, accepted, 2), digest(Tag::TargetDigest, d.target),
        digest(Tag::MigrationDigest, d.migration), value(Tag::ConsentChallengeId, d.challenge),
        value(Tag::CaptureBindingId, d.binding), value(Tag::IVProfile, 1, 1)});
    emit changed(); return sent;
}
bool OrdinaryDecisionClient::recover() {
    if (stopping_ || state_ != State::Uncertain || zero(command_) || !session_.idle()) return false;
    if (!connected_) {
        const auto image = QDir(QCoreApplication::applicationDirPath()).filePath("GateBouncerService.exe");
        if (!session_.open(std::filesystem::path(image.toStdWString()))) { fail("The original receipt owner is unavailable.", true); return false; }
        return true;
    }
    return send(Type::GetFutureCommandStatus, {value(Tag::CommandId, command_)});
}
void OrdinaryDecisionClient::outcome(const Frame &f) {
    if (idValue(f, Tag::CommandId) != command_ ||
        (f.type == Type::FutureCommandStatus && get(f, Tag::CommandFound) && get(f, Tag::OriginalCommandType) != unsigned(Type::CommitFuturePolicy))) {
        fail("Command receipt binding changed.", true); return;
    }
    if ((f.type == Type::FutureCommandStatus && !get(f, Tag::CommandFound)) || get(f, Tag::KnownAppliedUnrecorded) ||
        (get(f, Tag::CommandState) == unsigned(gb::wire::State::Applied) &&
         (desired_ == UINT64_MAX || get(f, Tag::DesiredRev) != desired_ + 1)) ||
        !get(f, Tag::Durable) || get(f, Tag::CommandState) == unsigned(gb::wire::State::Prepared) ||
        get(f, Tag::CommandState) == unsigned(gb::wire::State::AppliedUnrecorded) ||
        get(f, Tag::CommandState) == unsigned(gb::wire::State::RecoveryRequired)) {
        fail("Outcome unknown. Check the same command; do not repeat the decision.", true); return;
    }
    draft_.reset(); current_ = false;
    if (get(f, Tag::CommandState) == unsigned(gb::wire::State::Applied) && !get(f, Tag::ErrorCode)) {
        state_ = State::Recorded; message_ = "Future rule recorded. The original attempt was not resumed; coverage remains unvalidated.";
    } else { state_ = State::Failed; message_ = "The decision was rejected. The observation remains undecided."; }
    emit changed();
}
void OrdinaryDecisionClient::received(bool ok, Frame f, Id correlation, quint64 generation) {
    if (stopping_ || generation != generation_ || correlation != expected_) return;
    const bool mutation = expectedType_ == Type::CommitFuturePolicy || expectedType_ == Type::GetFutureCommandStatus;
    if (!ok || f.minor != 3 || f.connection != connection_ || f.correlation != expected_ || iv::validate(f) != Error::Ok) {
        connected_ = false;
        fail("Connection or response binding lost.", mutation); return;
    }
    if (f.type == Type::ProtocolError) { fail("The service rejected this review.", mutation); return; }
    if (expectedType_ == Type::GetStatus) {
        if (checkOnly_) {
            checkOnly_ = false;
            if (f.type != Type::Status || !status(f, true)) fail("Service context changed. Reopen the review before deciding.");
            return;
        }
        if (f.type != Type::Status || !status(f, finalStatus_)) { fail("Service context changed. Refresh before deciding."); return; }
        if (finalStatus_) { rows_ = std::move(pageRows_); current_ = true; state_ = State::Closed;
            for (auto it = shown_.begin(); it != shown_.end();) {
                if (!ids_.count(it->first)) it = shown_.erase(it); else ++it;
            }
            message_ = "Admitted observations · future permanent rules only"; emit changed();
            showNext(); return; }
        cursor_ = 0; snapshot_ = {}; pageRevision_ = 0; pageAge_.restart(); page(); return;
    }
    if (idValue(f, Tag::ServiceEpoch) != epoch_) { fail("Service epoch changed.", mutation); return; }
    if (expectedType_ == Type::ListObserved) {
        const auto snap = idValue(f, Tag::SnapshotId);
        const auto revision = get(f, Tag::ObservedSnapshotRevision);
        const auto count = get(f, Tag::Count), next = get(f, Tag::NextCursor);
        std::vector<iv::ObservedRecord> rows;
        if (f.type != Type::ObservedPage || idValue(f, Tag::SourceEpoch) != source_ || pageAge_.elapsed() >= 10000 ||
            get(f, Tag::Cursor) != cursor_ || (!zero(snapshot_) && (snap != snapshot_ || revision != pageRevision_)) ||
            iv::unpack(find(f, Tag::Records)->bytes, count, rows) != Error::Ok || rows.size() > 64 - pageRows_.size()) {
            fail("Observation snapshot changed or exceeded its bound."); return;
        }
        for (const auto &r : rows) if (!ids_.insert(r.observed).second || ids_.size() > 64) { fail("Duplicate or excessive observation."); return; }
        for (auto &r : rows) if (r.state == 1) pageRows_.push_back(std::move(r));
        snapshot_ = snap; pageRevision_ = revision;
        if (next != UINT32_MAX) { cursor_ = quint32(next); page(); }
        else { finalStatus_ = true; send(Type::GetStatus); } return;
    }
    if (expectedType_ == Type::GetObservedRecord) {
        std::vector<iv::ObservedRecord> rows;
        if (f.type != Type::ObservedRecord || iv::unpack(find(f, Tag::Records)->bytes, 1, rows) != Error::Ok ||
            rows[0].observed != observed_->observed || rows[0].revision != observed_->revision || rows[0].source != source_ ||
            rows[0].binding != observed_->binding || rows[0].state != 1) { fail("This observation is no longer current."); return; }
        observed_ = rows[0]; prepare(); return;
    }
    if (expectedType_ == Type::PrepareFuturePolicy || expectedType_ == Type::GetFutureDraft) {
        std::vector<iv::FutureDraftRecord> rows;
        if (f.type != Type::FutureDraftRecord || iv::unpack(find(f, Tag::Records)->bytes, 1, rows) != Error::Ok ||
            rows[0].observed != observed_->observed || rows[0].observedRevision != observed_->revision ||
            rows[0].source != source_ || rows[0].binding != observed_->binding || rows[0].profile != profile_ ||
            rows[0].expectedDesired != desired_ || rows[0].direction != direction_ ||
            (draft_ && (rows[0].draft != draft_->draft || rows[0].version != draft_->version ||
             rows[0].challenge != draft_->challenge || rows[0].target != draft_->target ||
             rows[0].migration != draft_->migration || rows[0].selector != draft_->selector ||
             rows[0].targetRevision != draft_->targetRevision || rows[0].accepted != draft_->accepted ||
             rows[0].package != draft_->package || rows[0].scope != draft_->scope))) {
            fail("Future review binding changed."); return;
        }
        draft_ = rows[0];
        if (draft_->state != 3 || draft_->proof != iv::Proof::CurrentShapeUnproven) { fail("The service cannot admit this future scope."); return; }
        if (expectedType_ == Type::PrepareFuturePolicy) { send(Type::GetFutureDraft, {value(Tag::DraftId, draft_->draft),
            value(Tag::DraftVersion, draft_->version), value(Tag::ProfileGeneration, profile_), value(Tag::IVProfile, 1, 1)}); return; }
        draftAge_.restart(); draftExpiry_.start(int(draft_->ttl)); state_ = State::Ready;
        message_ = "Review the effective scope before choosing Allow or Block."; emit changed(); return;
    }
    if ((expectedType_ == Type::CommitFuturePolicy && f.type == Type::FuturePolicyAck) ||
        (expectedType_ == Type::GetFutureCommandStatus && f.type == Type::FutureCommandStatus)) { outcome(f); return; }
    fail("Unexpected ordinary response.", mutation);
}
void OrdinaryDecisionClient::fail(const QString &message, bool uncertain) {
    draftExpiry_.stop(); draft_.reset(); current_ = false;
    state_ = uncertain ? State::Uncertain : State::Failed; message_ = message; emit changed();
}
void OrdinaryDecisionClient::invalidate() {
    poll_.stop(); automatic_ = false;
    if (state_ == State::Sending || state_ == State::Uncertain) { fail("Outcome unknown. The decision will not be repeated.", true); return; }
    closeNotice(); current_ = false; rows_.clear(); connected_ = false; emit changed();
}
void OrdinaryDecisionClient::stop() { stopping_ = true; poll_.stop(); draftExpiry_.stop(); current_ = false; session_.stop(); }
}
