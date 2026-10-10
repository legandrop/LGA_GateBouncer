#pragma once

#include <QDateTime>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QByteArray>
#include <QVector>
#include <optional>
#include <memory>
#include "qnameevidence.h"

namespace Gate::Data {
enum class FieldStatus { Known, Unknown, AccessDenied, Gone, Unsupported };
enum class Action { Ask, Allow, Block };
enum class Direction { Unknown, In, Out, Both };
enum class CandidateStatus { NeedsReview, Unsupported };
enum class ActivityKind { Attempt, Authorization, Traffic, HumanDecision, PolicyApplied };
enum class CoverageStatus { Unavailable, Partial, DeclaredScope };

struct NativeProcessFacts {
    quint32 pid = 0, volumeSerial = 0, indexHigh = 0, indexLow = 0;
    quint32 sizeHigh = 0, sizeLow = 0, tokenSession = 0;
    quint64 created = 0, lastWrite = 0;
    QByteArray appId, accountSid, logonSid;
    QString image;
    bool operator==(const NativeProcessFacts &o) const {
        return pid == o.pid && created == o.created && volumeSerial == o.volumeSerial &&
            indexHigh == o.indexHigh && indexLow == o.indexLow && sizeHigh == o.sizeHigh &&
            sizeLow == o.sizeLow && lastWrite == o.lastWrite && tokenSession == o.tokenSession &&
            appId == o.appId && image == o.image && accountSid == o.accountSid && logonSid == o.logonSid;
    }
};
struct ProcessInstance {
    QString sourceEpoch;
    quint32 pid = 0;
    quint64 creationFiletime = 0;
    bool operator==(const ProcessInstance &other) const {
        return sourceEpoch == other.sourceEpoch && pid == other.pid &&
               creationFiletime == other.creationFiletime;
    }
};
struct ActivityEvent;
struct ProcessObservation {
    ProcessInstance instance;
    QString name, imagePath;
    FieldStatus status = FieldStatus::Unknown;
    FieldStatus contentStatus = FieldStatus::Unsupported;
    QString publisher;
    QDateTime observedAtUtc;
    QString identityEvidence;
    std::optional<NativeProcessFacts> sourceImage;
    QStringList historySubjects;
    // Sólo copias de Attempts cuyos recibos originales pasaron ambas READs del batch propio.
    QVector<std::shared_ptr<const ActivityEvent>> historyCauses;
    QDateTime lastAttemptUtc, lastAuthorizedUtc, lastTrafficUtc;
};
struct XmlNode {
    QString name, nameSpace, text;
    QMap<QString, QString> attributes;
    QVector<XmlNode> children;
};
struct Candidate {
    QString id, sourceId, sourceType;
    XmlNode source;
    CandidateStatus status = CandidateStatus::NeedsReview;
    QVector<QString> diagnostics;
    std::optional<Action> action, reviewAction;
    Direction direction = Direction::Unknown;
    std::optional<bool> sourceEnabled;
    std::optional<qint64> sourceWeight;
    bool reviewed = false;
    // No hay campo activo: el documento de revision no expresa permisos efectivos.
};
struct ImportReport {
    bool accepted = false;
    QString digest, sourceVersion, error;
    qint64 errorLine = 0, errorColumn = 0;
    QVector<Candidate> candidates;
    QVector<XmlNode> filters, identities;
    QVector<QString> diagnostics;
};
struct ImportLimits {
    qint64 bytes = 8 * 1024 * 1024;
    int depth = 32, elements = 200000, attributes = 32, text = 32768;
    int rules = 10000, dependencies = 20000, functions = 64, values = 256;
};
// Copias historicas: nunca conservan leases, handles ni autoridad del motor.
struct NativeSourceBinding {
    QString serviceEpoch, boot, engineContext, sourceEpoch;
    quint64 generation = 0, profile = 0;
    // Copia descriptiva del HelloAck administrativo; nunca reconstruye su peer.
    quint8 role = 0;
    QString connection;
    bool operator==(const NativeSourceBinding &other) const {
        return serviceEpoch == other.serviceEpoch && boot == other.boot &&
            engineContext == other.engineContext && sourceEpoch == other.sourceEpoch &&
            generation == other.generation && profile == other.profile &&
            role == other.role && connection == other.connection;
    }
};
struct NativeEvidence {
    QString connection, observed, captureBinding, command;
    quint64 observedRevision = 0, unixNanoseconds = 0, presence = 0;
    quint64 attemptSequence = 0, effectiveRevision = 0;
    quint64 packetCount = 0;
    quint8 source = 0, direction = 0, protocol = 0, scope = 0;
    quint8 routeMask = 3, packetDirection = 0;
    bool durable = false, currentEffect = false, externalPartial = false;
    std::optional<NativeProcessFacts> process;
};
struct ActivityEvent {
    QString sourceId, sourceEpoch, sequence;
    ActivityKind kind = ActivityKind::Attempt;
    QDateTime observedAtUtc, receivedAtUtc;
    QString subjectId, requestId, flowId;
    std::optional<ProcessInstance> instance;
    std::optional<Action> action;
    QString winningRuleId, winningRuleRevision;
    QString endpoint, protocol;
    std::optional<quint64> bytes;
    bool synthetic = false;
    std::optional<NativeEvidence> native;
};
struct EventFact {
    QDateTime atUtc;
    QString sourceId, sourceEpoch, sequence;
};
struct ActivityAggregate {
    std::optional<EventFact> lastAttempt, lastAuthorized, lastTraffic;
};
struct CoverageGap {
    QDateTime atUtc;
    QString reason;
    quint64 lost = 0;
    bool lostKnown = true;
    // Intervalo remoto original. Los gaps locales no consumen un cursor OS.
    bool remote = false;
    quint64 after = 0, resync = 0, revision = 0;
    quint8 nativeReason = 0;
};
struct Coverage {
    QString sourceId, sourceEpoch, declaredScope;
    bool synthetic = false;
    CoverageStatus status = CoverageStatus::Unavailable;
    QDateTime sinceUtc, checkpointUtc, lastObservedUtc;
    quint64 lastSequence = 0;
    QVector<CoverageGap> gaps;
    std::optional<NativeSourceBinding> native;
};
struct HistoryState {
    QVector<ActivityEvent> events;
    QMap<QString, ActivityAggregate> subjects;
    QMap<QString, EventFact> ruleHits;
    QVector<Coverage> coverage;
    QMap<QString, ActivityEvent> nativeAttempts, nativeAuthorizations, nativeTraffic;
};
struct ReviewDocument {
    quint64 revision = 0;
    ImportReport report;
    HistoryState history;
    std::optional<QNameEvidence> qnameEvidence;
};

bool decimalUnsigned(const QString &text, quint64 *value = nullptr);
QString actionName(Action action);
std::optional<Action> readAction(const QString &text);
QString directionName(Direction direction);
Direction readDirection(const QString &text);
// Presentación del ámbito futuro; no acredita identidad ni autoriza decisiones.
struct ApplicationRuleScopeText {
    QString package, scope, connections, originalAttempt, coverage;
};
ApplicationRuleScopeText applicationRuleScopeText(quint8 package, Direction direction, Action action, bool held);
} // namespace Gate::Data
