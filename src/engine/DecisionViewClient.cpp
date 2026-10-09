#include "DecisionViewClient.h"
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
} // namespace
DecisionViewClient::DecisionViewClient(bool isolatedQa, QObject *parent,
                                       std::unique_ptr<gb::ipc::ii::SessionChannel> channel)
    : QObject(parent), blocked_(isolatedQa && !channel), session_(this, std::move(channel)) {
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
void DecisionViewClient::invalidate() {
    poll_.stop();
    status_.current = false;
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
    historyGap_ = true;
    emit changed();
}
void DecisionViewClient::stop() {
    stopping_ = true;
    invalidate();
    session_.stop();
}
void DecisionViewClient::fail(const QString &reason) {
    invalidate();
    status_.error = reason;
    emit changed();
}
bool DecisionViewClient::adoptStatus(const Frame &f) {
    if (f.minor != 1 || validate(f) != Error::Ok ||
        (f.type != Type::Status && f.type != Type::HelloAck))
        return false;
    const auto epoch = idValue(f, Tag::ServiceEpoch), boot = idValue(f, Tag::BootId);
    const auto profile = get(f, Tag::ProfileGeneration);
    if (epoch != status_.serviceEpoch || boot != status_.bootId || profile != profile_) {
        pending_.clear();
        rules_.clear();
        events_.clear();
        recordsCurrent_ = false;
        historyGap_ = true;
        lastEvent_ = 0;
        subscribed_ = false;
    }
    status_.current = true;
    status_.serviceEpoch = epoch;
    status_.bootId = boot;
    status_.connection = f.connection;
    status_.desired = get(f, Tag::DesiredRev);
    status_.effective = get(f, Tag::EffectiveRev);
    status_.effectiveKnown = get(f, Tag::EffectiveKnown);
    status_.capabilities = get(f, Tag::Capabilities);
    status_.gaps = get(f, Tag::GapCount);
    status_.state = EngineState(get(f, Tag::EngineState));
    status_.backend = BackendMode(get(f, Tag::BackendMode));
    status_.error.clear();
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
    f.minor = 1;
    f.type = type;
    f.connection = status_.connection;
    f.correlation = correlationId();
    expected_ = f.correlation;
    expectedType_ = type;
    if (type == Type::ListPending || type == Type::ListRules)
        f.fields = {value(Tag::ServiceEpoch, status_.serviceEpoch),
                    value(Tag::SnapshotId, snapshot_), value(Tag::Cursor, cursor_, 4),
                    value(Tag::Limit, 32, 2)};
    if (type == Type::SubscribeEvents)
        f.fields = {value(Tag::ServiceEpoch, status_.serviceEpoch), value(Tag::EventMask, 1, 4),
                    value(Tag::AfterEventSeq, lastEvent_)};
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
    if (stopping_ || !busy_)
        return;
    if (!ok) {
        fail("View II channel lost; request and observation data unavailable");
        return;
    }
    if (correlation != expected_)
        return;
    if (f.minor != 1 || validate(f) != Error::Ok || f.correlation != expected_ ||
        f.connection != status_.connection) {
        fail("View II response binding failed");
        return;
    }
    if (f.type == Type::ProtocolError) {
        fail("View II request rejected (" + QString::number(get(f, Tag::ErrorCode)) + ")");
        return;
    }
    if (expectedType_ == Type::GetStatus) {
        if (f.type != Type::Status || !adoptStatus(f)) {
            fail("View II status rejected");
            return;
        }
        emit changed();
        startPages(false);
        return;
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
            get(f, Tag::EventMask) != 1) {
            fail("View II subscription rejected");
            return;
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
        if (ii::unpack(records->bytes, count, rows) != Error::Ok ||
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
        if (ii::unpack(records->bytes, count, rows) != Error::Ok ||
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
    if (f.minor != 1 || validate(f) != Error::Ok || f.connection != status_.connection ||
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
