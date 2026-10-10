#include "DecisionViewClient.h"
#include "../data/activityhistory.h"
#include <QCoreApplication>
#include <QDir>
#include <QUuid>
#include <algorithm>

namespace Gate {
using namespace gb::wire;
namespace {
Id correlationId() {
    const auto bytes = QUuid::createUuid().toRfc4122();
    Id id{};
    std::copy_n(reinterpret_cast<const unsigned char *>(bytes.constData()), id.size(), id.begin());
    return id;
}
bool processFacts(const Frame &frame, Data::NativeProcessFacts &f) {
    const auto field = find(frame, Tag::Records);
    std::vector<iv::ProcessFacts> facts;
    if (!field || iv::unpack(field->bytes, 1, facts) != Error::Ok || facts.size() != 1 ||
        facts[0].pid > UINT32_MAX) return false;
    const auto &p = facts[0];
    f.pid = quint32(p.pid); f.created = p.created; f.volumeSerial = p.volumeSerial;
    f.indexHigh = p.fileIndexHigh; f.indexLow = p.fileIndexLow;
    f.sizeHigh = p.fileSizeHigh; f.sizeLow = p.fileSizeLow;
    f.lastWrite = p.lastWrite; f.tokenSession = p.tokenSession;
    const auto bytes = [](const Bytes &b) { return QByteArray(reinterpret_cast<const char *>(b.data()), qsizetype(b.size())); };
    f.appId = bytes(p.appId); f.accountSid = bytes(p.accountSid); f.logonSid = bytes(p.logonSid);
    f.image = QString::fromUtf8(bytes(p.image));
    return f.image.toUtf8() == bytes(p.image) && Data::validNativeProcessFacts(f);
}
Id identifier(const QString &hexadecimal) {
    const auto b = QByteArray::fromHex(hexadecimal.toLatin1());
    Id id{};
    if (b.size() == qsizetype(id.size())) std::copy_n(reinterpret_cast<const unsigned char *>(b.constData()), id.size(), id.begin());
    return id;
}
} // namespace
DecisionViewClient::DecisionViewClient(bool isolatedQa, QObject *parent,
                                       std::unique_ptr<gb::ipc::ii::SessionChannel> channel)
    : QObject(parent), blocked_(isolatedQa && !channel), session_(this, std::move(channel), 3) {
    connect(&session_, &gb::controller::Session::opened, this, &DecisionViewClient::opened);
    connect(&session_, &gb::controller::Session::received, this, &DecisionViewClient::received);
    connect(&session_, &gb::controller::Session::observation, this,
            &DecisionViewClient::observation);
    poll_.setInterval(12000);
    connect(&poll_, &QTimer::timeout, this, [this] {
        if (!busy_)
            refresh();
    });
}
bool DecisionViewClient::refresh() {
    if (stopping_ || busy_)
        return false;
    if (blocked_) {
        fail("Native View II is disabled in isolated QA without an injected channel");
        return false;
    }
    busy_ = true;
    if (!connected_) {
        const auto image =
            QDir(QCoreApplication::applicationDirPath()).filePath("GateBouncerService.exe");
        if (!session_.open(false, std::filesystem::path(image.toStdWString()))) {
            busy_ = false;
            return false;
        }
        return true;
    }
    return send(Type::GetStatus);
}
std::optional<NativeContextSnapshot> DecisionViewClient::currentNativeContext(bool requireFacts) const {
    if (!connected_ || !nativeSource_ || !serviceContext() ||
        (requireFacts && !(status_.capabilities & iv::NativeProcessFacts))) return {};
    return NativeContextSnapshot{*nativeSource_, readPeer_, QString::fromStdString(hex(status_.connection)),
                                 nativeStatusSerial_, status_.capabilities};
}
bool DecisionViewClient::requestNativeSnapshotContext(quint64 tag) {
    if (!tag || stopping_ || busy_ || !session_.idle() || !currentNativeContext(false)) return false;
    nativeRequestTag_ = tag; nativeRequestAttempt_.reset(); busy_ = true;
    return send(Type::GetStatus);
}
bool DecisionViewClient::requestNativeProcessContext(quint64 tag, const Data::ActivityEvent &attempt) {
    const auto context = currentNativeContext();
    if (!tag || stopping_ || busy_ || !session_.idle() || !context || !Data::validNativeEvent(attempt) ||
        attempt.kind != Data::ActivityKind::Attempt || !attempt.native->process ||
        attempt.native->externalPartial || attempt.sourceId != Data::nativeSourceId(context->binding) ||
        attempt.sourceEpoch != Data::nativeEpochKey(context->binding)) return false;
    Frame f; f.minor = 3; f.type = Type::GetNativeProcessContext;
    f.connection = status_.connection; f.correlation = correlationId();
    Bytes encoded;
    if (iv::encodeServiceContext(*serviceContext_, encoded) != Error::Ok) return false;
    f.fields = {value(Tag::ServiceEpoch, status_.serviceEpoch), value(Tag::SourceEpoch, serviceContext_->engineContext),
        {Tag::ServiceContext, true, encoded}, value(Tag::ProfileGeneration, profile_),
        value(Tag::ObservedId, identifier(attempt.native->observed)), value(Tag::ObservedRevision, attempt.native->observedRevision),
        value(Tag::CaptureBindingId, identifier(attempt.native->captureBinding)),
        value(Tag::AttemptLink, iv::attemptLink(attempt.sequence.toULongLong()))};
    if (iv::validate(f) != Error::Ok) return false;
    nativeRequestTag_ = tag; nativeRequestAttempt_ = attempt; busy_ = true;
    expected_ = f.correlation; expectedType_ = f.type;
    if (!session_.request(std::move(f))) { fail("Original process read queue unavailable"); return false; }
    return true;
}
void DecisionViewClient::invalidate() {
    nativeRequestTag_ = 0; nativeRequestAttempt_.reset();
    endNativeSource("ConnectionLost");
    poll_.stop();
    status_.current = false;
    serviceContext_.reset();
    readPeer_.reset();
    recordsCurrent_ = false;
    pending_.clear();
    rules_.clear();
    events_.clear();
    pendingDraft_.clear();
    rulesDraft_.clear();
    expected_ = {};
    connected_ = false;
    busy_ = false;
    subscribed_ = false;
    lastEvent_ = 0;
    nativeMask_ = 3;
    historyGap_ = true;
    emit changed();
}
void DecisionViewClient::stop() {
    stopping_ = true;
    endNativeSource("ObservationStopped");
    invalidate();
    session_.stop();
}
void DecisionViewClient::rejectHistory(const QString &reason) {
    fail("History unavailable: " + reason);
}
void DecisionViewClient::endNativeSource(const QString &reason) {
    if (!nativeSource_) return;
    const auto old = *nativeSource_;
    nativeSource_.reset();
    emit nativeSourceLost(old, reason);
}
std::optional<Data::NativeSourceBinding> DecisionViewClient::nativeBinding(const Frame &f) const {
    const auto current = serviceContext();
    iv::ServiceContext decoded;
    if (!current || f.minor != 3 || f.connection != status_.connection ||
        iv::validate(f) != Error::Ok || iv::decodeServiceContext(f, decoded) != Error::Ok ||
        decoded.serviceEpoch != current->serviceEpoch || decoded.boot != current->boot ||
        decoded.engineContext != current->engineContext || decoded.engineBindingGeneration != current->engineBindingGeneration ||
        get(f, Tag::ProfileGeneration) != profile_ || idValue(f, Tag::SourceEpoch) != decoded.engineContext) return {};
    Data::NativeSourceBinding b;
    b.serviceEpoch = QString::fromStdString(hex(decoded.serviceEpoch));
    b.boot = QString::fromStdString(hex(decoded.boot));
    b.engineContext = QString::fromStdString(hex(decoded.engineContext));
    b.sourceEpoch = QString::fromStdString(hex(idValue(f, Tag::SourceEpoch)));
    b.generation = decoded.engineBindingGeneration; b.profile = profile_;
    return Data::validNativeBinding(b) ? std::optional<Data::NativeSourceBinding>(b) : std::nullopt;
}
void DecisionViewClient::fail(const QString &reason) {
    invalidate();
    status_.error = reason;
    emit changed();
}
std::optional<iv::ServiceContext> DecisionViewClient::serviceContext() const {
    if (!status_.current || !serviceContext_ || !readPeer_ ||
        readPeer_->checkLive() != gb::ipc::ii::ReadPeerState::Current ||
        readPeer_->connection() != status_.connection)
        return {};
    return serviceContext_;
}
void DecisionViewClient::statusOnly() {
    recordsCurrent_ = false;
    pending_.clear(); rules_.clear(); pendingDraft_.clear(); rulesDraft_.clear();
    expected_ = {}; busy_ = false;
    if (minor_ != 3) subscribed_ = false;
    status_.error = "Pending request records are not available in this service version.";
    if (minor_ == 3 && (status_.capabilities & iv::NativeEvents) && serviceContext()) {
        if (subscribed_) { poll_.start(); emit changed(); return; }
        busy_ = true; send(Type::SubscribeEvents); return;
    }
    poll_.start();
    emit changed();
}
bool DecisionViewClient::adoptStatus(const Frame &f) {
    if ((f.minor != 1 && f.minor != 2 && f.minor != 3) || (connected_ && f.minor != minor_) || validate(f) != Error::Ok ||
        (f.type != Type::Status && f.type != Type::HelloAck))
        return false;
    std::optional<iv::ServiceContext> context;
    std::shared_ptr<const gb::ipc::ii::ReadPeerLease> peer;
    bool contextChanged = false;
    if (f.minor == 3) {
        iv::ServiceContext decoded;
        if (iv::decodeServiceContext(f, decoded) != Error::Ok) return false;
        peer = session_.readonlyPeer();
        if (peer && peer->checkLive() == gb::ipc::ii::ReadPeerState::Current && peer->connection() == f.connection) {
            context = decoded;
            contextChanged = !serviceContext_ || decoded.serviceEpoch != serviceContext_->serviceEpoch ||
                decoded.boot != serviceContext_->boot || decoded.engineContext != serviceContext_->engineContext ||
                decoded.engineBindingGeneration != serviceContext_->engineBindingGeneration;
        } else contextChanged = serviceContext_.has_value();
    }
    const auto epoch = idValue(f, Tag::ServiceEpoch), boot = idValue(f, Tag::BootId);
    const auto profile = get(f, Tag::ProfileGeneration);
    const auto capabilities = get(f, Tag::Capabilities);
    if ((capabilities & iv::NativeTraffic) &&
        ((capabilities & (iv::NativeEvents | ObservedRead)) != (iv::NativeEvents | ObservedRead))) return false;
    if ((capabilities & iv::NativeProcessFacts) && (capabilities & (iv::NativeEvents | ObservedRead)) != (iv::NativeEvents | ObservedRead)) return false;
    const quint8 nextMask = capabilities & iv::NativeTraffic ? 7 : 3;
    if (contextChanged || epoch != status_.serviceEpoch || boot != status_.bootId || profile != profile_) {
        endNativeSource("SourceContextChanged");
        if (stopping_) return false;
        pending_.clear();
        rules_.clear();
        events_.clear();
        recordsCurrent_ = false;
        historyGap_ = true;
        lastEvent_ = 0;
        subscribed_ = false;
    }
    if (nativeSource_ && nativeMask_ != nextMask) {
        // Solo el peer vivo original puede conservar este cursor al cambiar dominio.
        const bool transition = nativeMask_ == 3 && nextMask == 7 && context && peer &&
            readPeer_ == peer && serviceContext() && f.connection == status_.connection;
        endNativeSource(transition ? "ObservationRouteChanged" : "SourceCapabilityLost");
        if (stopping_) return false;
        subscribed_ = false;
        if (!transition) lastEvent_ = 0;
    }
    nativeMask_ = nextMask;
    if (stopping_ || (peer && peer->checkLive() != gb::ipc::ii::ReadPeerState::Current)) return false;
    serviceContext_ = std::move(context);
    readPeer_ = std::move(peer);
    status_.current = true;
    status_.serviceEpoch = epoch;
    status_.bootId = boot;
    status_.connection = f.connection;
    status_.desired = get(f, Tag::DesiredRev);
    status_.effective = get(f, Tag::EffectiveRev);
    status_.effectiveKnown = get(f, Tag::EffectiveKnown);
    status_.capabilities = capabilities;
    if (f.minor == 3 && !(status_.capabilities & iv::NativeEvents)) {
        endNativeSource("SourceCapabilityLost"); subscribed_ = false; lastEvent_ = 0;
    }
    status_.gaps = get(f, Tag::GapCount);
    status_.state = EngineState(get(f, Tag::EngineState));
    status_.backend = BackendMode(get(f, Tag::BackendMode));
    status_.error.clear();
    minor_ = f.minor;
    profile_ = profile;
    collector_ = quint8(get(f, Tag::CollectorState));
    return true;
}
void DecisionViewClient::opened(bool ok, Frame f) {
    if (stopping_ || !busy_)
        return;
    if (!ok || f.type != Type::HelloAck || !adoptStatus(f)) {
        fail("View II authentication or Hello failed");
        return;
    }
    connected_ = true;
    emit changed();
    send(Type::GetStatus);
}
bool DecisionViewClient::send(Type type) {
    Frame f;
    f.minor = minor_;
    f.type = type;
    f.connection = status_.connection;
    f.correlation = correlationId();
    expected_ = f.correlation;
    expectedType_ = type;
    if (type == Type::ListPending || type == Type::ListRules)
        f.fields = {value(Tag::ServiceEpoch, status_.serviceEpoch),
                    value(Tag::SnapshotId, snapshot_), value(Tag::Cursor, cursor_, 4),
                    value(Tag::Limit, 32, 2)};
    if (type == Type::SubscribeEvents) {
        f.fields = {value(Tag::ServiceEpoch, status_.serviceEpoch), value(Tag::EventMask, minor_ == 3 ? nativeMask_ : 1, 4),
                    value(Tag::AfterEventSeq, lastEvent_)};
        if (minor_ == 3) {
            const auto context = serviceContext();
            if (!context) { fail("History source lease unavailable"); return false; }
            f.fields.push_back(value(Tag::ProfileGeneration, profile_));
            f.fields.push_back(value(Tag::SourceEpoch, context->engineContext));
        }
    }
    if (!session_.request(std::move(f))) {
        fail("View II request queue unavailable");
        return false;
    }
    return true;
}
void DecisionViewClient::startPages(bool rules) {
    snapshot_ = {};
    cursor_ = 0;
    pageRevision_ = 0;
    ids_.clear();
    pageAge_.restart();
    if (rules)
        rulesDraft_.clear();
    else
        pendingDraft_.clear();
    send(rules ? Type::ListRules : Type::ListPending);
}
void DecisionViewClient::received(bool ok, Frame f, Id correlation) {
    if (stopping_)
        return;
    if (!ok) {
        if (busy_ || connected_) fail("View II channel lost; request and observation data unavailable");
        return;
    }
    if (!busy_) return;
    if (correlation != expected_)
        return;
    if (f.minor != minor_ || validate(f) != Error::Ok || f.correlation != expected_ ||
        f.connection != status_.connection) {
        fail("View II response binding failed");
        return;
    }
    if (f.type == Type::ProtocolError) {
        if (minor_ == 3 && expectedType_ == Type::ListPending && get(f, Tag::ErrorCode) == std::uint16_t(Error::Unsupported)) {
            statusOnly(); return;
        }
        fail("View II request rejected (" + QString::number(get(f, Tag::ErrorCode)) + ")");
        return;
    }
    if (expectedType_ == Type::GetStatus) {
        if (f.type != Type::Status || !adoptStatus(f)) {
            fail("View II status rejected");
            return;
        }
        if (nativeStatusSerial_ == UINT64_MAX) { fail("Process context serial exhausted"); return; }
        ++nativeStatusSerial_;
        if (nativeRequestTag_ && !nativeRequestAttempt_) {
            const auto tag = nativeRequestTag_; nativeRequestTag_ = 0; busy_ = false;
            const auto context = currentNativeContext(false);
            if (!context) { fail("Original process context unavailable"); return; }
            emit nativeSnapshotContext(tag, *context); emit changed(); return;
        }
        emit changed();
        if (stopping_ || !busy_ || !connected_) return;
        if (!supported(Type::ListPending, minor_)) { statusOnly(); return; }
        startPages(false);
        return;
    }
    if (expectedType_ == Type::GetNativeProcessContext) {
        const auto context = currentNativeContext();
        const auto binding = nativeBinding(f);
        if (!nativeRequestTag_ || !nativeRequestAttempt_ || !context || !binding ||
            f.type != Type::NativeProcessContext || !(*binding == context->binding)) {
            fail("Original process response context rejected"); return;
        }
        const auto attempt = *nativeRequestAttempt_;
        if (idValue(f, Tag::ObservedId) != identifier(attempt.native->observed) ||
            get(f, Tag::ObservedRevision) != attempt.native->observedRevision ||
            idValue(f, Tag::CaptureBindingId) != identifier(attempt.native->captureBinding) ||
            iv::attemptSequence(idValue(f, Tag::AttemptLink)) != attempt.sequence.toULongLong()) {
            fail("Original process response cause rejected"); return;
        }
        const bool accepted = get(f, Tag::ErrorCode) == unsigned(Error::Ok);
        Data::NativeProcessFacts facts;
        if (accepted && (!processFacts(f, facts) || !(facts == *attempt.native->process))) {
            fail("Original process facts changed; history preserved"); return;
        }
        if (!currentNativeContext()) { fail("Original process peer lost after read"); return; }
        const auto tag = nativeRequestTag_; nativeRequestTag_ = 0; nativeRequestAttempt_.reset(); busy_ = false;
        auto receipt = std::shared_ptr<const NativeProcessReceipt>(new NativeProcessReceipt(
            context->binding,context->peer,context->connection,Data::nativeEventKey(attempt),
            QString::fromStdString(hex(f.correlation)),f.sequence,accepted,*attempt.native->process));
        emit nativeProcessContext(tag, Data::nativeEventKey(attempt), accepted, *context,
            accepted ? QString{} : "Original source process custody unavailable (" + QString::number(get(f, Tag::ErrorCode)) + ")",receipt);
        emit changed(); return;
    }
    if (idValue(f, Tag::ServiceEpoch) != status_.serviceEpoch) {
        fail("View II service epoch changed");
        return;
    }
    if (expectedType_ == Type::ListPending || expectedType_ == Type::ListRules) {
        page(f);
        return;
    }
    if (expectedType_ == Type::SubscribeEvents) {
        if (f.type != Type::SubscriptionAck || get(f, Tag::ProfileGeneration) != profile_ ||
            get(f, Tag::EventMask) != (minor_ == 3 ? unsigned(nativeMask_) : 1u)) {
            fail("View II subscription rejected");
            return;
        }
        if (minor_ == 3) {
            const auto binding = nativeBinding(f);
            if (!binding || get(f, Tag::SourceCoverage) != 1) { fail("History subscription context changed"); return; }
            nativeSource_ = *binding; lastEvent_ = get(f, Tag::EventSeq);
            subscribed_ = true; busy_ = false;
            emit nativeSourceOpened(*binding, lastEvent_);
            if (!connected_ || !nativeSource_ || !subscribed_ || !nativeBinding(f)) return;
            historyGap_ = true; poll_.start(); emit changed(); return;
        }
        subscribed_ = true;
        // After=0 fija un ancla; no promete historia anterior ni cobertura completa.
        if (!lastEvent_)
            lastEvent_ = get(f, Tag::EventSeq);
        collector_ = quint8(get(f, Tag::CollectorState));
        busy_ = false;
        poll_.start();
        emit changed();
    }
}
void DecisionViewClient::page(const Frame &f) {
    const bool rules = expectedType_ == Type::ListRules;
    const auto revision = get(f, rules ? Tag::DesiredRev : Tag::PendingSnapshotRevision);
    const auto snapshot = idValue(f, Tag::SnapshotId);
    const auto count = get(f, Tag::Count), next = get(f, Tag::NextCursor);
    if (f.type != (rules ? Type::RulesPage : Type::PendingPage) || pageAge_.elapsed() >= 10000 ||
        get(f, Tag::Cursor) != cursor_ || (!zero(snapshot_) && snapshot != snapshot_) ||
        (cursor_ && revision != pageRevision_) || (rules && revision != status_.desired) ||
        (next != 0xffffffffu && (next != cursor_ + count || !count))) {
        fail("View II page expired or changed");
        return;
    }
    const auto *records = find(f, Tag::Records);
    if (!records) {
        fail("View II records missing");
        return;
    }
    if (rules) {
        std::vector<ii::RuleRecord> rows;
        if (ii::unpack(records->bytes, count, rows, minor_) != Error::Ok ||
            rows.size() > 4096 - rulesDraft_.size()) {
            fail("View II rules exceed their bound");
            return;
        }
        for (auto &row : rows) {
            if (row.desired != revision || !ids_.insert(row.rule).second) {
                fail("View II rule snapshot inconsistent");
                return;
            }
            rulesDraft_.push_back(std::move(row));
        }
    } else {
        std::vector<ii::PendingRecord> rows;
        if (ii::unpack(records->bytes, count, rows, minor_) != Error::Ok ||
            rows.size() > 512 - pendingDraft_.size()) {
            fail("View II pending records exceed their bound");
            return;
        }
        for (auto &row : rows) {
            if (row.profileGeneration != profile_ || row.state != ii::RequestState::Pending ||
                !ids_.insert(row.request).second) {
                fail("View II pending snapshot inconsistent");
                return;
            }
            pendingDraft_.push_back(std::move(row));
        }
    }
    snapshot_ = snapshot;
    pageRevision_ = revision;
    if (next != 0xffffffffu) {
        cursor_ = quint32(next);
        send(expectedType_);
        return;
    }
    if (!rules) {
        startPages(true);
        return;
    }
    pending_ = std::move(pendingDraft_);
    rules_ = std::move(rulesDraft_);
    recordsCurrent_ = true;
    if (collector_ == 1 && (status_.capabilities & (1ull << 14)))
        send(Type::SubscribeEvents);
    else {
        subscribed_ = false;
        busy_ = false;
        poll_.start();
        emit changed();
    }
}
void DecisionViewClient::observation(Frame f) {
    if (stopping_ || !connected_ || !status_.current || !subscribed_)
        return;
    if (minor_ == 3) {
        const auto binding = nativeBinding(f);
        if (!binding || !nativeSource_ || !(*binding == *nativeSource_) ||
            (f.type != Type::Attempt && f.type != Type::Authorization && f.type != Type::ObservationGap &&
             !(nativeMask_ == 7 && f.type == Type::Traffic))) {
            fail("History observation context changed"); return;
        }
        const auto sequence = get(f, Tag::EventSeq);
        if (f.type == Type::ObservationGap) {
            emit nativeGap(*binding, get(f, Tag::AfterEventSeq), sequence, get(f, Tag::GapCount),
                           quint8(get(f, Tag::GapReason)), get(f, Tag::LostCountKnown) == 1, get(f, Tag::LostCount));
        } else {
            Data::ActivityEvent e;
            e.sourceId = Data::nativeSourceId(*binding); e.sourceEpoch = Data::nativeEpochKey(*binding);
            e.sequence = QString::number(sequence); e.receivedAtUtc = QDateTime::currentDateTimeUtc();
            e.kind = f.type == Type::Attempt ? Data::ActivityKind::Attempt :
                f.type == Type::Authorization ? Data::ActivityKind::Authorization : Data::ActivityKind::Traffic;
            Data::NativeEvidence n;
            n.connection = QString::fromStdString(hex(f.connection)); n.observed = QString::fromStdString(hex(idValue(f, Tag::ObservedId)));
            n.captureBinding = QString::fromStdString(hex(idValue(f, Tag::CaptureBindingId)));
            n.observedRevision = get(f, Tag::ObservedRevision); n.unixNanoseconds = get(f, Tag::Timestamp);
            n.presence = get(f, Tag::Presence); n.source = quint8(get(f, Tag::Source));
            n.routeMask = nativeMask_;
            if (n.presence & 4) { Data::NativeProcessFacts facts; if (!processFacts(f, facts)) { fail("Original process facts rejected"); return; } n.process = std::move(facts); }
            n.direction = quint8(get(f, Tag::FlowDirection)); n.protocol = quint8(get(f, Tag::Protocol));
            if (n.presence & 1) e.observedAtUtc = QDateTime::fromMSecsSinceEpoch(qint64(n.unixNanoseconds / 1000000ull), Qt::UTC);
            if (n.presence & 2) e.protocol = n.protocol == 6 ? "TCP" : "UDP";
            e.subjectId = "native:" + e.sourceId + ':' + e.sourceEpoch + ':' + n.observed + ':' + n.captureBinding + ':' + QString::number(n.observedRevision);
            if (f.type == Type::Authorization || f.type == Type::Traffic) {
                n.command = QString::fromStdString(hex(idValue(f, Tag::CommandId)));
                n.attemptSequence = iv::attemptSequence(idValue(f, Tag::AttemptLink));
                n.effectiveRevision = get(f, Tag::EffectiveRev); n.scope = quint8(get(f, Tag::ScopeKind));
                n.durable = get(f, Tag::Durable) == 1; n.currentEffect = get(f, Tag::ProofState) == 2;
                if (f.type == Type::Authorization) {
                    if (get(f, Tag::Decision) == 1) e.action = Data::Action::Block;
                    else if (get(f, Tag::Decision) == 2) e.action = Data::Action::Allow;
                } else {
                    e.bytes = get(f, Tag::ByteCount); n.packetCount = get(f, Tag::PacketCount);
                    n.packetDirection = quint8(get(f, Tag::PacketDirection));
                }
            }
            e.native = n;
            if (!Data::validNativeEvent(e)) { fail("History evidence shape rejected"); return; }
            emit nativeEvent(e);
        }
        if (!connected_ || !nativeSource_ || !subscribed_ || !nativeBinding(f)) return;
        lastEvent_ = std::max(lastEvent_, sequence); historyGap_ = true;
        if (!observationUpdateQueued_) {
            observationUpdateQueued_ = true;
            QTimer::singleShot(0, this, [this] { observationUpdateQueued_ = false; if (!stopping_ && status_.current) emit changed(); });
        }
        return;
    }
    if (f.minor != minor_ || validate(f) != Error::Ok || f.connection != status_.connection ||
        idValue(f, Tag::ServiceEpoch) != status_.serviceEpoch ||
        get(f, Tag::ProfileGeneration) != profile_ || get(f, Tag::Source) != 1 ||
        (f.type != Type::Attempt && f.type != Type::ObservationGap) ||
        get(f, Tag::EventSeq) <= lastEvent_) {
        fail("View II observation binding failed");
        return;
    }
    const auto sequence = get(f, Tag::EventSeq);
    if (lastEvent_ && sequence != lastEvent_ + 1)
        historyGap_ = true;
    if (f.type == Type::ObservationGap || get(f, Tag::GapCount))
        historyGap_ = true;
    lastEvent_ = sequence;
    events_.push_back(std::move(f));
    if (events_.size() > 4096) {
        events_.erase(events_.begin());
        historyGap_ = true;
    }
    if (!observationUpdateQueued_) {
        observationUpdateQueued_ = true;
        QTimer::singleShot(0, this, [this] {
            observationUpdateQueued_ = false;
            if (!stopping_ && status_.current)
                emit changed();
        });
    }
}
} // namespace Gate
