#pragma once

#include <QDateTime>
#include <QMap>
#include <QString>
#include <QVector>
#include <optional>

namespace Gate::Data {
enum class FieldStatus { Known, Unknown, AccessDenied, Gone, Unsupported };
enum class Action { Ask, Allow, Block };
enum class Direction { Unknown, In, Out, Both };
enum class CandidateStatus { NeedsReview, Unsupported };
enum class ActivityKind { Attempt, Authorization, Traffic, HumanDecision, PolicyApplied };
enum class CoverageStatus { Unavailable, Partial, DeclaredScope };

struct ProcessInstance {
    QString sourceEpoch;
    quint32 pid = 0;
    quint64 creationFiletime = 0;
    bool operator==(const ProcessInstance &other) const {
        return sourceEpoch == other.sourceEpoch && pid == other.pid &&
               creationFiletime == other.creationFiletime;
    }
};
struct ProcessObservation {
    ProcessInstance instance;
    QString name, imagePath;
    FieldStatus status = FieldStatus::Unknown;
    FieldStatus contentStatus = FieldStatus::Unsupported;
    QString publisher;
    QDateTime observedAtUtc;
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
};
struct Coverage {
    QString sourceId, sourceEpoch, declaredScope;
    bool synthetic = false;
    CoverageStatus status = CoverageStatus::Unavailable;
    QDateTime sinceUtc, checkpointUtc, lastObservedUtc;
    quint64 lastSequence = 0;
    QVector<CoverageGap> gaps;
};
struct HistoryState {
    QVector<ActivityEvent> events;
    QMap<QString, ActivityAggregate> subjects;
    QMap<QString, EventFact> ruleHits;
    QVector<Coverage> coverage;
};
struct ReviewDocument {
    quint64 revision = 0;
    ImportReport report;
    HistoryState history;
};

bool decimalUnsigned(const QString &text, quint64 *value = nullptr);
QString actionName(Action action);
std::optional<Action> readAction(const QString &text);
QString directionName(Direction direction);
Direction readDirection(const QString &text);
} // namespace Gate::Data
