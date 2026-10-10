#include "OrdinaryDecisionClient.h"
#include <ordinary_iii_win.h>
#include <QCoreApplication>
#include <QDir>
#include <QUuid>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCryptographicHash>
#include <algorithm>
namespace Gate {
using namespace gb::wire;
namespace {
constexpr auto commandRecoveryMessage = "Command history needs recovery. No new change was confirmed; existing rules may still allow traffic. Do not repeat this command.";
Id freshId() {
    const auto bytes = QUuid::createUuid().toRfc4122();
    Id id{}; std::copy_n(reinterpret_cast<const unsigned char *>(bytes.constData()), 16, id.begin()); return id;
}
Field digest(Tag tag, const Digest &value) { return {tag, true, Bytes(value.begin(), value.end())}; }
bool originalTargetDigest(const Bytes &target, const Digest &expected) {
    Bytes input;
    if (iv::principalTargetDigestInput(target,input) != Error::Ok) return false;
    const auto hash = QCryptographicHash::hash(QByteArray(reinterpret_cast<const char *>(input.data()),qsizetype(input.size())),QCryptographicHash::Sha256);
    return std::equal(expected.begin(),expected.end(),reinterpret_cast<const unsigned char *>(hash.constData()));
}
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
        if (state_ == State::Ready) { draft_.reset(); fileDraft_.reset(); state_ = State::Failed;
            message_ = "Review expired. Reopen the request before deciding."; emit changed(); }
    });
    // QA depende de un canal inyectado; sin canal nunca conecta con el equipo.
    poll_.setInterval(12000);
    connect(&poll_, &QTimer::timeout, this, [this] {
        if (!session_.idle()) return;
        if (visible_ && state_ == State::Ready) { checkOnly_ = true; send(Type::GetStatus); }
        else if (!visible_ && state_ != State::Sending && state_ != State::Uncertain) {
            if (readingRules_) refreshRules(); else refresh();
        }
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
    if (stopping_ || fileOwner_ || !session_.idle() || state_ == State::Sending || state_ == State::Uncertain) return false;
    closeNotice(); current_ = false; rulesCurrent_ = false; readingRules_ = false;
    revocation_.reset(); rows_.clear(); pageRows_.clear(); ids_.clear();
    state_ = State::Loading; message_ = "Reading pending requests…"; finalStatus_ = false; checkOnly_ = false;
    emit changed();
    if (!connected_) {
        const auto image = QDir(QCoreApplication::applicationDirPath()).filePath("GateBouncerService.exe");
        if (!session_.open(std::filesystem::path(image.toStdWString()))) { fail("Request review unavailable."); return false; }
        return true;
    }
    return send(Type::GetStatus);
}
bool OrdinaryDecisionClient::refreshRules() {
    if (stopping_ || visible_ || !session_.idle() || state_ == State::Sending || state_ == State::Uncertain) return false;
    closeNotice(); current_ = false; rulesCurrent_ = false; readingRules_ = true;
    revocation_.reset(); rulePageRows_.clear(); rulePageBytes_ = 0; ids_.clear();
    state_ = State::Loading; message_ = "Reading rules for your account…";
    finalStatus_ = false; checkOnly_ = false; emit changed();
    if (!connected_) {
        const auto image = QDir(QCoreApplication::applicationDirPath()).filePath("GateBouncerService.exe");
        if (!session_.open(std::filesystem::path(image.toStdWString()))) { fail("Rule review unavailable."); return false; }
        return true;
    }
    return send(Type::GetStatus);
}
bool OrdinaryDecisionClient::revokeRule(const Id &rule, quint64 selection, bool consent) {
    if (stopping_ || !consent || selection != generation_ || !rulesCurrent_ || visible_ ||
        !session_.idle() || state_ == State::Sending || state_ == State::Uncertain) return false;
    const auto found = std::find_if(rules_.begin(),rules_.end(),[&](const auto &r) { return r.rule == rule; });
    if (found == rules_.end() || found->targetKind != 1 || found->scope != 2 || found->desired != desired_) return false;
    revocation_ = *found; current_ = false; rulesCurrent_ = false;
    state_ = State::Preparing; message_ = "Rechecking the selected rule before removal…"; emit changed();
    return send(Type::GetStatus);
}
std::optional<QByteArray> OrdinaryDecisionClient::selectedRuleBackup(const std::vector<Id> &selected, quint64 selection) const {
    if (stopping_ || !rulesCurrent_ || selection != generation_ || selected.empty() || selected.size() > 128) return {};
    std::set<Id> unique; QJsonArray records; qsizetype total = 0;
    for (const auto &id : selected) {
        if (!unique.insert(id).second) return {};
        const auto found = std::find_if(rules_.begin(),rules_.end(),[&](const auto &r) { return r.rule == id; });
        Bytes encoded;
        if (found == rules_.end() || found->desired != desired_ || found->targetKind != 1 || found->scope != 2 ||
            iv::pack(std::vector<iv::PrincipalRuleRecord>{*found},encoded) != Error::Ok || encoded.size() < 8 ||
            encoded[6] != 2 || encoded[7]) return {};
        // Records v1 no contiene AppId/SID: no se anuncia como backup restaurable.
        const auto bytes = QByteArray(reinterpret_cast<const char *>(encoded.data()),qsizetype(encoded.size())).toBase64();
        total += bytes.size(); if (total > 2 * 1024 * 1024 - 4096) return {};
        records.push_back(QString::fromLatin1(bytes));
    }
    const auto idText = [](const Id &id) { return QString::fromStdString(hex(id)); };
    const QJsonObject archive{{"kind","ApplicationRuleBackup"},{"version",1},{"state","Inactive"},
        {"serviceEpoch",idText(epoch_)},{"boot",idText(boot_)},{"sourceEpoch",idText(source_)},
        {"profile",QString::number(profile_)},{"bindingGeneration",QString::number(bindingGeneration_)},
        {"desired",QString::number(desired_)},{"records",records}};
    const auto bytes = QJsonDocument(archive).toJson(QJsonDocument::Compact);
    return bytes.size() <= 2 * 1024 * 1024 ? std::optional<QByteArray>(bytes) : std::nullopt;
}
void OrdinaryDecisionClient::submitRevocation() {
    const auto &r = *revocation_;
    state_ = State::Sending; message_ = "Removing the selected rule…";
    send(Type::RevokePrincipalRule,{value(Tag::ExpectedDesiredRev,desired_),value(Tag::RuleId,r.rule),
        value(Tag::RuleRevision,r.revision),value(Tag::ProfileGeneration,profile_),
        value(Tag::TargetRevision,r.targetRevision),digest(Tag::TargetDigest,r.target),
        digest(Tag::MigrationDigest,Digest{}),value(Tag::IVProfile,1,1)});
    emit changed();
}
bool OrdinaryDecisionClient::prepareFile(std::shared_ptr<Data::SelectedApplicationFile> owner, int direction,
    const Bytes &expectedTarget, const std::optional<Id> &editing, quint64 selection) {
    if (stopping_ || !owner || fileOwner_ || visible_ || !session_.idle() || direction < 1 || direction > 3 ||
        state_ == State::Sending || state_ == State::Uncertain || (!expectedTarget.empty() && !iv::validPrincipalTarget(expectedTarget,1))) return false;
    std::optional<iv::PrincipalRuleRecord> selected;
    if (editing) {
        if (!rulesCurrent_ || selection != generation_) return false;
        const auto r = std::find_if(rules_.begin(),rules_.end(),[&](const auto &v) { return v.rule == *editing; });
        if (r == rules_.end() || r->desired != desired_ || r->targetKind != 1 || r->scope != 2 || r->package != 1 ||
            r->revision == UINT64_MAX || r->targetRevision == UINT64_MAX || r->originalTarget.empty()) return false;
        selected = *r;
    }
    closeNotice(); fileOwner_ = std::move(owner); expectedFileTarget_ = expectedTarget; editing_ = selected;
    current_ = false; rulesCurrent_ = false; readingRules_ = false; direction_ = direction; scope_ = 2;
    visible_ = true; finalStatus_ = false; checkOnly_ = false;
    state_ = State::Loading; message_ = "Checking the selected executable and your account…"; emit changed();
    if (!connected_) {
        const auto image = QDir(QCoreApplication::applicationDirPath()).filePath("GateBouncerService.exe");
        if (!session_.open(std::filesystem::path(image.toStdWString()))) { fail("File rule review unavailable."); return false; }
        return true;
    }
    return send(Type::GetStatus);
}
void OrdinaryDecisionClient::submitFilePreparation() {
    const auto image = fileOwner_->facts().image.toUtf8();
    std::vector<Field> fields{value(Tag::ExpectedDesiredRev,desired_),value(Tag::PolicyDirection,direction_,1),
        value(Tag::ProfileGeneration,profile_),value(Tag::SourceEpoch,source_),value(Tag::IVProfile,1,1),
        value(Tag::ScopeKind,2,1),value(Tag::PackageMode,1,1),{Tag::Text,true,Bytes(reinterpret_cast<const unsigned char *>(image.constData()),
            reinterpret_cast<const unsigned char *>(image.constData()) + image.size())}};
    if (!expectedFileTarget_.empty()) fields.push_back({Tag::Records,true,expectedFileTarget_});
    if (editing_) {
        fields.push_back(value(Tag::RuleId,editing_->rule)); fields.push_back(value(Tag::RuleRevision,editing_->revision));
        fields.push_back(value(Tag::SelectorRevision,editing_->targetRevision)); fields.push_back(digest(Tag::PreviousTargetDigest,editing_->target));
    }
    state_ = State::Preparing; send(Type::PrepareFileFuturePolicy,std::move(fields)); emit changed();
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
    desired_ = get(f, Tag::DesiredRev); bindingGeneration_ = binding; capabilities_ = get(f,Tag::Capabilities); return !zero(connection_);
}
void OrdinaryDecisionClient::opened(bool ok, Frame f) {
    if (stopping_) return;
    if (state_ == State::Uncertain) {
        if (!ok || f.type != Type::HelloAck || iv::validate(f) != Error::Ok ||
            idValue(f, Tag::ServiceEpoch) != epoch_ || idValue(f, Tag::BootId) != boot_ ||
            get(f, Tag::ProfileGeneration) != profile_ || get(f, Tag::EffectiveKnown) || get(f, Tag::EffectiveRev) || zero(f.connection)) {
            connected_ = false; fail("The service that received this decision is unavailable. Its result remains unknown.", true); return;
        }
        connected_ = true; connection_ = f.connection;
        send(Type::GetFutureCommandStatus, {value(Tag::CommandId, command_)}); return;
    }
    if (state_ != State::Loading) return;
    if (!ok || f.type != Type::HelloAck || !status(f, false)) { fail("Request review unavailable. Check the service connection."); return; }
    connected_ = true; send(Type::GetStatus);
}
bool OrdinaryDecisionClient::send(Type type, std::vector<Field> fields) {
    Frame f; f.minor = 3; f.type = type; f.connection = connection_; f.correlation = freshId();
    if (type != Type::GetStatus) fields.push_back(value(Tag::ServiceEpoch, epoch_));
    std::sort(fields.begin(), fields.end(), [](const auto &a, const auto &b) { return a.tag < b.tag; });
    f.fields = std::move(fields); expected_ = f.correlation; expectedType_ = type;
    if (type == Type::CommitFuturePolicy || type == Type::RevokePrincipalRule || type == Type::ReplacePrincipalRule) {
        command_ = f.correlation;
        submitted_ = type == Type::RevokePrincipalRule
            ? SubmittedPresentation{f,revocation_->display,boot_,{},0,bindingGeneration_}
            : SubmittedPresentation{f, draft_->display, boot_, observed_ ? observed_->observed : Id{},
                observed_ ? observed_->revision : 0, bindingGeneration_};
    }
    if (iv::validate(f) != Error::Ok || !session_.request(std::move(f), generation_)) {
        fail("Request review unavailable.", type == Type::CommitFuturePolicy || type == Type::RevokePrincipalRule || type == Type::ReplacePrincipalRule || type == Type::GetFutureCommandStatus); return false;
    }
    return true;
}
void OrdinaryDecisionClient::page() {
    send(Type::ListObserved, {value(Tag::SnapshotId, snapshot_), value(Tag::Cursor, cursor_, 4), value(Tag::Limit, 32, 2)});
}
void OrdinaryDecisionClient::rulePage() {
    send(Type::ListPrincipalRules,{value(Tag::SnapshotId,snapshot_),value(Tag::Cursor,cursor_,4),value(Tag::Limit,32,2)});
}
bool OrdinaryDecisionClient::select(const Id &id) {
    if (!current_ || !session_.idle() || state_ == State::Sending || state_ == State::Uncertain) return false;
    auto row = std::find_if(rows_.begin(), rows_.end(), [&](const auto &r) { return r.observed == id && r.state == 1; });
    if (row == rows_.end()) return false;
    closeNotice(); observed_ = *row; visible_ = true; direction_ = row->temporal == 2 ? 0 : 1; scope_ = row->temporal == 2 ? 3 : 2;
    shown_[row->observed] = ShownKey{epoch_, boot_, source_, profile_, row->revision};
    state_ = State::Preparing; message_ = "Rechecking this request…"; emit changed();
    return send(Type::GetObservedRecord, {value(Tag::ObservedId, row->observed),
        value(Tag::ObservedRevision, row->revision), value(Tag::SourceEpoch, row->source)});
}
bool OrdinaryDecisionClient::direction(int direction) {
    if (!visible_ || !current_ || !observed_ || !session_.idle() || direction < 1 || direction > 3 ||
        state_ == State::Sending || state_ == State::Uncertain) return false;
    if (scope_ >= 3 && direction != direction_) return false;
    ++generation_; draftExpiry_.stop(); draft_.reset(); direction_ = direction;
    state_ = State::Preparing; message_ = "Checking which connections this rule will cover…"; emit changed(); prepare(); return true;
}
bool OrdinaryDecisionClient::scope(int scope) {
    if (!ready() || !session_.idle() || !observed_ || scope < 2 || scope > 5 ||
        (observed_->temporal != 2 && scope != 2)) return false;
    ++generation_; draftExpiry_.stop(); draft_.reset(); scope_ = scope;
    observedGeneration_ = generation_;
    state_ = State::Preparing; message_ = "Checking how long this decision will apply…";
    if (scope >= 3) {
        direction_ = 0; emit changed();
        return send(Type::GetObservedRecord, {value(Tag::ObservedId, observed_->observed),
            value(Tag::ObservedRevision, observed_->revision), value(Tag::SourceEpoch, observed_->source)});
    }
    emit changed(); prepare(); return true;
}
void OrdinaryDecisionClient::prepare() {
    std::vector<Field> fields{value(Tag::ExpectedDesiredRev, desired_), value(Tag::PolicyDirection, direction_, 1),
        value(Tag::ProfileGeneration, profile_), value(Tag::ObservedId, observed_->observed),
        value(Tag::ObservedRevision, observed_->revision), value(Tag::SourceEpoch, source_), value(Tag::IVProfile, 1, 1),
        value(Tag::ScopeKind, scope_, 1)};
    if (scope_ == 5) fields.push_back(value(Tag::ScopeDurationMs, 900000, 4));
    send(Type::PrepareFuturePolicy, std::move(fields));
}
void OrdinaryDecisionClient::closeNotice() {
    visible_ = false; draftExpiry_.stop();
    if (state_ != State::Sending && state_ != State::Uncertain) {
        ++generation_; draft_.reset(); fileDraft_.reset(); fileOwner_.reset(); expectedFileTarget_.clear(); editing_.reset(); observed_.reset(); submitted_.reset(); state_ = State::Closed;
    }
    emit changed();
    if (automatic_) QTimer::singleShot(0, this, &OrdinaryDecisionClient::showNext);
}
bool OrdinaryDecisionClient::ready() const {
    return current_ && visible_ && state_ == State::Ready && draft_ && draftAge_.isValid() && draftAge_.elapsed() < draft_->ttl;
}
std::optional<OrdinaryDecisionClient::ObservationContext> OrdinaryDecisionClient::observationContext() const {
    if (stopping_ || !connected_ || !current_ || !visible_ || !observed_ || observedGeneration_ != generation_ ||
        (state_ != State::Preparing && state_ != State::Ready) || !profile_ || !bindingGeneration_ ||
        zero(epoch_) || zero(boot_) || zero(source_) || zero(connection_) ||
        observed_->state != 1 || observed_->source != source_) return {};
    const auto row = std::find_if(rows_.begin(),rows_.end(),[&](const auto &r) {
        return r.observed == observed_->observed && r.revision == observed_->revision && r.binding == observed_->binding &&
            r.source == source_ && r.state == 1;
    });
    if (row == rows_.end() || (state_ == State::Ready && !ready())) return {};
    return ObservationContext{{epoch_,boot_,source_,bindingGeneration_},connection_,profile_,desired_,generation_,observed_->revision};
}
bool OrdinaryDecisionClient::decide(bool allow, bool consent, quint64 selection) {
    if (fileOwner_) return false; // El recorrido de archivo revalida su dueño en el worker.
    return commitDraft(allow,consent,selection);
}
bool OrdinaryDecisionClient::decideFile(bool allow, bool consent, quint64 selection) {
    if (!fileOwner_ || !fileDraft_ || !draft_ || !zero(draft_->observed) || draft_->observedRevision ||
        draft_->scope != 2 || draft_->package != 1) return false;
    return commitDraft(allow,consent,selection);
}
bool OrdinaryDecisionClient::commitDraft(bool allow, bool consent, quint64 selection) {
    if (!consent || selection != generation_ || !ready() || !session_.idle()) return false;
    const auto d = *draft_; const auto accepted = d.accepted | (allow && d.direction == 3 ? 4u : 0u);
    draftExpiry_.stop(); state_ = State::Sending; message_ = "Saving the reviewed decision…";
    std::vector<Field> fields{value(Tag::ExpectedDesiredRev, d.expectedDesired),
        value(Tag::Decision, allow ? 2 : 1, 1), value(Tag::ScopeKind, d.scope, 1), value(Tag::SelectorId, d.selector),
        value(Tag::PolicyDirection, d.direction, 1), value(Tag::ProfileGeneration, d.profile), value(Tag::SourceEpoch, d.source),
        value(Tag::DraftId, d.draft), value(Tag::DraftVersion, d.version), value(Tag::TargetRevision, d.targetRevision),
        value(Tag::PackageMode, d.package, 1), value(Tag::AcceptedScope, accepted, 2), digest(Tag::TargetDigest, d.target),
        digest(Tag::MigrationDigest, d.migration), value(Tag::ConsentChallengeId, d.challenge),
        value(Tag::CaptureBindingId, d.binding), value(Tag::IVProfile, 1, 1)};
    if (d.scope == 5) fields.push_back(value(Tag::ScopeDurationMs, d.durationMs, 4));
    if (fileOwner_ && editing_) {
        fields.push_back(value(Tag::RuleId,editing_->rule)); fields.push_back(value(Tag::RuleRevision,editing_->revision));
        fields.push_back(value(Tag::SelectorRevision,editing_->targetRevision)); fields.push_back(digest(Tag::PreviousTargetDigest,editing_->target));
    }
    const bool sent = send(fileOwner_ && editing_ ? Type::ReplacePrincipalRule : Type::CommitFuturePolicy, std::move(fields));
    emit changed(); return sent;
}
bool OrdinaryDecisionClient::recover() {
    if (stopping_ || state_ != State::Uncertain || zero(command_) || !session_.idle()) return false;
    if (!connected_) {
        const auto image = QDir(QCoreApplication::applicationDirPath()).filePath("GateBouncerService.exe");
        if (!session_.open(std::filesystem::path(image.toStdWString()))) { fail("The service that received this decision is unavailable. Its result remains unknown.", true); return false; }
        return true;
    }
    return send(Type::GetFutureCommandStatus, {value(Tag::CommandId, command_)});
}
void OrdinaryDecisionClient::outcome(const Frame &f) {
    const auto submittedScope = submitted_ ? get(submitted_->command, Tag::ScopeKind) : 0;
    const bool removing = submitted_ && submitted_->command.type == Type::RevokePrincipalRule;
    const auto originalType = submitted_ ? submitted_->command.type : Type::CommitFuturePolicy;
    if (idValue(f, Tag::CommandId) != command_ ||
        (f.type == Type::FutureCommandStatus && get(f, Tag::CommandFound) && get(f, Tag::OriginalCommandType) != unsigned(originalType))) {
        fail("Command receipt binding changed.", true); return;
    }
    if (get(f, Tag::ErrorCode) == unsigned(Error::StoreFailure) ||
        get(f, Tag::ErrorCode) == unsigned(Error::RecoveryRequired)) {
        fail(commandRecoveryMessage, true); return;
    }
    if ((submittedScope >= 3 ? get(f, Tag::ScopeKind) != submittedScope : find(f, Tag::ScopeKind) != nullptr)) {
        fail("Command scope binding changed.", true); return;
    }
    if ((f.type == Type::FutureCommandStatus && !get(f, Tag::CommandFound)) || get(f, Tag::KnownAppliedUnrecorded) ||
        (get(f, Tag::CommandState) == unsigned(gb::wire::State::Applied) &&
         ((submittedScope == 2 || removing) && (desired_ == UINT64_MAX || get(f, Tag::DesiredRev) != desired_ + 1))) ||
        !get(f, Tag::Durable) || get(f, Tag::CommandState) == unsigned(gb::wire::State::Prepared) ||
        get(f, Tag::CommandState) == unsigned(gb::wire::State::AppliedUnrecorded) ||
        get(f, Tag::CommandState) == unsigned(gb::wire::State::RecoveryRequired)) {
        fail("Outcome unknown. Check the same command; do not repeat the decision.", true); return;
    }
    const bool fileDecision = bool(fileOwner_);
    draft_.reset(); fileDraft_.reset(); fileOwner_.reset(); editing_.reset(); revocation_.reset(); current_ = false; rulesCurrent_ = false;
    if (get(f, Tag::CommandState) == unsigned(gb::wire::State::Applied) && !get(f, Tag::ErrorCode)) {
        state_ = State::Recorded; message_ = removing
            ? "Rule removal recorded. Other rules still apply; protection coverage has not been validated."
            : fileDecision ? "Application rule recorded for future connections. Protection coverage has not been validated."
            : submittedScope >= 3
            ? "Decision recorded for the selected connection or app instance. Other firewall rules still apply; protection coverage has not been validated."
            : "Always rule recorded for future connections. The original attempt stays blocked; protection coverage has not been validated.";
    } else { state_ = State::Failed; message_ = removing ? "Rule removal was rejected. Refresh the rule list before trying again."
        : "The decision was rejected. The request remains undecided."; }
    emit changed();
}
void OrdinaryDecisionClient::received(bool ok, Frame f, Id correlation, quint64 generation) {
    if (stopping_ || generation != generation_ || correlation != expected_) return;
    const bool mutation = expectedType_ == Type::CommitFuturePolicy || expectedType_ == Type::RevokePrincipalRule || expectedType_ == Type::ReplacePrincipalRule || expectedType_ == Type::GetFutureCommandStatus;
    if (!ok || f.minor != 3 || f.connection != connection_ || f.correlation != expected_ || iv::validate(f) != Error::Ok) {
        connected_ = false;
        fail("Connection or response binding lost.", mutation); return;
    }
    if (f.type == Type::ProtocolError) {
        const auto error = get(f, Tag::ErrorCode);
        fail(error == unsigned(Error::StoreFailure) || error == unsigned(Error::RecoveryRequired)
            ? commandRecoveryMessage : "The service rejected this review.", mutation); return;
    }
    if (expectedType_ == Type::GetStatus) {
        if (fileOwner_ && !checkOnly_) {
            if (f.type != Type::Status || !status(f,bool(editing_)) || !(capabilities_ & iv::FileFutureControl) ||
                (editing_ && editing_->desired != desired_)) { fail("File rule review is unavailable or its original context changed."); return; }
            current_ = true; submitFilePreparation(); return;
        }
        if (revocation_) {
            if (f.type != Type::Status || !status(f,true) || revocation_->desired != desired_) {
                revocation_.reset(); fail("Rule or service context changed. Refresh before removing a rule."); return;
            }
            submitRevocation(); return;
        }
        if (checkOnly_) {
            checkOnly_ = false;
            if (f.type != Type::Status || !status(f, true)) fail("Service context changed. Reopen the review before deciding.");
            return;
        }
        if (f.type != Type::Status || !status(f, finalStatus_)) { fail("Service context changed. Refresh before deciding."); return; }
        if (finalStatus_ && readingRules_) {
            if (pageAge_.elapsed() >= 5000) { fail("Rule review snapshot expired."); return; }
            rules_ = std::move(rulePageRows_); rulesCurrent_ = true; current_ = false; state_ = State::Closed;
            message_ = "Rules for your account ready to review · protection coverage unvalidated"; emit changed(); return;
        }
        if (finalStatus_) { rows_ = std::move(pageRows_); current_ = true; state_ = State::Closed;
            for (auto it = shown_.begin(); it != shown_.end();) {
                if (!ids_.count(it->first)) it = shown_.erase(it); else ++it;
            }
            message_ = "Pending requests ready to review"; emit changed();
            showNext(); return; }
        cursor_ = 0; snapshot_ = {}; pageRevision_ = 0; pageAge_.restart();
        if (readingRules_) rulePage(); else page(); return;
    }
    if (idValue(f, Tag::ServiceEpoch) != epoch_) { fail("Service epoch changed.", mutation); return; }
    if (expectedType_ == Type::ListPrincipalRules) {
        const auto snap = idValue(f,Tag::SnapshotId);
        const auto revision = get(f,Tag::DesiredRev);
        const auto next = get(f,Tag::NextCursor), count = get(f,Tag::Count);
        Bytes context;
        const auto *actualContext = find(f,Tag::ServiceContext);
        const bool contextMatches = iv::encodeServiceContext({epoch_,boot_,source_,bindingGeneration_},context) == Error::Ok &&
            actualContext && actualContext->bytes == context && idValue(f,Tag::SourceEpoch) == source_ &&
            get(f,Tag::ProfileGeneration) == profile_;
        std::vector<iv::PrincipalRuleRecord> rows;
        if (f.type != Type::PrincipalRulesPage || !contextMatches || pageAge_.elapsed() >= 5000 || revision != desired_ ||
            get(f,Tag::Cursor) != cursor_ || (!zero(snapshot_) && (snap != snapshot_ || revision != pageRevision_)) ||
            (next != UINT32_MAX && (!count || next != cursor_ + count)) ||
            find(f,Tag::Records)->bytes.size() > 4 * 1024 * 1024 - rulePageBytes_ ||
            iv::unpack(find(f,Tag::Records)->bytes,count,rows) != Error::Ok || rows.size() > 4096 - rulePageRows_.size()) {
            fail("Rule snapshot changed or exceeded its bound."); return;
        }
        rulePageBytes_ += find(f,Tag::Records)->bytes.size();
        for (auto &r : rows) {
            if (r.desired != revision || r.targetKind != 1 || r.scope != 2 || r.originalTarget.empty() ||
                r.admin != 1 || r.effective || r.proof != iv::Proof::Unknown || r.generation || r.presence || r.created || r.authorized ||
                !originalTargetDigest(r.originalTarget,r.target) || !ids_.insert(r.rule).second) {
                fail("Rule snapshot contains a duplicate or different scope."); return;
            }
            rulePageRows_.push_back(std::move(r));
        }
        snapshot_ = snap; pageRevision_ = revision;
        if (next != UINT32_MAX) { cursor_ = quint32(next); rulePage(); }
        else { finalStatus_ = true; send(Type::GetStatus); } return;
    }
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
            rows[0].binding != observed_->binding || rows[0].state != 1) { fail("This request is no longer current."); return; }
        if (scope_ >= 3) {
            const auto direction = get(f, Tag::PolicyDirection);
            if (rows[0].temporal != 2 || direction < 1 || direction > 2) {
                fail("The current connection direction is unavailable. Refresh this request before deciding."); return;
            }
            direction_ = int(direction);
        }
        observed_ = rows[0]; observedGeneration_ = generation_; prepare(); return;
    }
    if (fileOwner_ && (expectedType_ == Type::PrepareFileFuturePolicy || expectedType_ == Type::GetFutureDraft)) {
        std::vector<iv::FileFutureDraftRecord> rows; Bytes context;
        const auto *records = find(f,Tag::Records); const auto *actual = find(f,Tag::ServiceContext);
        if (f.type != Type::FileFutureDraftRecord || !records || !actual ||
            iv::encodeServiceContext({epoch_,boot_,source_,bindingGeneration_},context) != Error::Ok || actual->bytes != context ||
            idValue(f,Tag::SourceEpoch) != source_ || iv::unpack(records->bytes,1,rows) != Error::Ok || rows.size() != 1) {
            fail("The original file draft or service context changed."); return;
        }
        const auto &row = rows.front(); const auto &d = row.draft; const auto &own = fileOwner_->facts();
        iv::OriginalTarget target;
        const auto ownBytes = [](const QByteArray &v) { return Bytes(reinterpret_cast<const unsigned char *>(v.constData()),reinterpret_cast<const unsigned char *>(v.constData()) + v.size()); };
        const auto &identity = row.file;
        if (d.source != source_ || d.profile != profile_ || d.expectedDesired != desired_ || d.direction != direction_ ||
            d.scope != 2 || d.package != 1 || d.accepted != 3 || !zero(d.observed) || d.observedRevision ||
            std::any_of(d.migration.begin(),d.migration.end(),[](auto b) { return b != 0; }) ||
            iv::unpackOriginalTarget(row.originalTarget,target) != Error::Ok || target.packageMode != 1 ||
            target.appId != ownBytes(own.appId) || target.accountSid != ownBytes(own.accountSid) || !target.packageSid.empty() ||
            !originalTargetDigest(row.originalTarget,d.target) || (!expectedFileTarget_.empty() && row.originalTarget != expectedFileTarget_) ||
            identity.volumeSerial != own.volumeSerial || identity.fileIndexHigh != own.fileIndexHigh || identity.fileIndexLow != own.fileIndexLow ||
            identity.fileSizeHigh != own.fileSizeHigh || identity.fileSizeLow != own.fileSizeLow || identity.attributes != own.attributes ||
            identity.lastWrite != own.lastWrite || (editing_ && (idValue(f,Tag::RuleId) != editing_->rule ||
            get(f,Tag::RuleRevision) != editing_->revision || get(f,Tag::SelectorRevision) != editing_->targetRevision ||
            !find(f,Tag::PreviousTargetDigest) || find(f,Tag::PreviousTargetDigest)->bytes != Bytes(editing_->target.begin(),editing_->target.end()) ||
            d.selector != editing_->selector || d.targetRevision != editing_->targetRevision + (row.originalTarget != editing_->originalTarget ? 1u : 0u))) ||
            (!editing_ && (find(f,Tag::RuleId) || find(f,Tag::RuleRevision) || find(f,Tag::SelectorRevision) || find(f,Tag::PreviousTargetDigest) || d.targetRevision != 1))) {
            fail("The service file, account or selected rule differs from the retained original."); return;
        }
        if (fileDraft_) {
            auto before = *fileDraft_; auto after = row; before.draft.ttl = after.draft.ttl;
            Bytes a,b;
            if (row.draft.ttl > fileDraft_->draft.ttl || iv::pack(std::vector<iv::FileFutureDraftRecord>{before},a) != Error::Ok ||
                iv::pack(std::vector<iv::FileFutureDraftRecord>{after},b) != Error::Ok || a != b) { fail("The reviewed file draft changed."); return; }
        }
        fileDraft_ = row; draft_ = d;
        if (expectedType_ == Type::PrepareFileFuturePolicy) {
            send(Type::GetFutureDraft,{value(Tag::DraftId,d.draft),value(Tag::DraftVersion,d.version),value(Tag::ProfileGeneration,profile_),value(Tag::IVProfile,1,1)}); return;
        }
        draftAge_.restart(); draftExpiry_.start(int(d.ttl)); state_ = State::Ready;
        message_ = "Review this application and account rule for future connections."; emit changed(); return;
    }
    if (expectedType_ == Type::PrepareFuturePolicy || expectedType_ == Type::GetFutureDraft) {
        std::vector<iv::FutureDraftRecord> rows;
        if (f.type != Type::FutureDraftRecord || iv::unpack(find(f, Tag::Records)->bytes, 1, rows) != Error::Ok ||
            rows[0].observed != observed_->observed || rows[0].observedRevision != observed_->revision ||
            rows[0].source != source_ || rows[0].binding != observed_->binding || rows[0].profile != profile_ ||
            rows[0].expectedDesired != desired_ || rows[0].direction != direction_ || rows[0].scope != scope_ ||
            rows[0].durationMs != (scope_ == 5 ? 900000u : 0u) ||
            (draft_ && (rows[0].draft != draft_->draft || rows[0].version != draft_->version ||
             rows[0].challenge != draft_->challenge || rows[0].target != draft_->target ||
             rows[0].migration != draft_->migration || rows[0].selector != draft_->selector ||
             rows[0].targetRevision != draft_->targetRevision || rows[0].accepted != draft_->accepted ||
             rows[0].package != draft_->package || rows[0].scope != draft_->scope))) {
            fail("Future review binding changed."); return;
        }
        draft_ = rows[0];
        if (draft_->state != 3 || draft_->proof != iv::Proof::CurrentShapeUnproven) { fail("The service cannot prepare this decision."); return; }
        if (expectedType_ == Type::PrepareFuturePolicy) { send(Type::GetFutureDraft, {value(Tag::DraftId, draft_->draft),
            value(Tag::DraftVersion, draft_->version), value(Tag::ProfileGeneration, profile_), value(Tag::IVProfile, 1, 1)}); return; }
        draftAge_.restart(); draftExpiry_.start(int(draft_->ttl)); state_ = State::Ready;
        observedGeneration_ = generation_;
        message_ = "Review what this decision will cover, then choose Allow or Block."; emit changed(); return;
    }
    if (((expectedType_ == Type::CommitFuturePolicy || expectedType_ == Type::RevokePrincipalRule || expectedType_ == Type::ReplacePrincipalRule) && f.type == Type::FuturePolicyAck) ||
        (expectedType_ == Type::GetFutureCommandStatus && f.type == Type::FutureCommandStatus)) { outcome(f); return; }
    fail("Unexpected ordinary response.", mutation);
}
void OrdinaryDecisionClient::fail(const QString &message, bool uncertain) {
    draftExpiry_.stop(); draft_.reset(); current_ = false; rulesCurrent_ = false;
    state_ = uncertain ? State::Uncertain : State::Failed; message_ = message; emit changed();
}
void OrdinaryDecisionClient::invalidate() {
    poll_.stop(); automatic_ = false;
    if (state_ == State::Sending || state_ == State::Uncertain) { fail("Outcome unknown. The decision will not be repeated.", true); return; }
    closeNotice(); current_ = false; rulesCurrent_ = false; revocation_.reset(); rows_.clear(); connected_ = false; emit changed();
}
void OrdinaryDecisionClient::stop() { stopping_ = true; poll_.stop(); draftExpiry_.stop(); current_ = false; rulesCurrent_ = false;
    fileOwner_.reset(); fileDraft_.reset(); session_.stop(); }
}
