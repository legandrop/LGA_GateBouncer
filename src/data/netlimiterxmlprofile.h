#pragma once
#include "qnamexmlreader.h"

namespace Gate::Data {
enum class SourceFwAction { None = 0, Ask = 1, Allow = 2, Deny = 3, Block = 4 };
template <typename T> struct SourceFact {
    FieldStatus status = FieldStatus::Unknown;
    T value{};
    int node = -1;
    bool known() const { return status == FieldStatus::Known; }
};
struct ApplicationConstraint {
    // Sid.Bytes declarado en base64; no acredita SID Windows, cuenta ni identidad host.
    SourceFact<QString> path, sidBytes, packageId, serviceName;
    bool pathExact = false;
    int node = -1;
    QVector<int> metadataNodes;
};
struct QNamePredicate {
    QString kind;
    int node = -1;
    SourceFact<bool> match;
    QVector<ApplicationConstraint> applications;
    QVector<SourceFact<QString>> domains;
    bool complete = false;
};
struct QNameFilterFacts {
    int node = -1;
    SourceFact<QString> id;
    ApplicationConstraint package;
    QVector<QNamePredicate> predicates;
    QVector<int> baseFilters, residues;
    int height = 1;
    bool complete = false;
};
struct QNameCandidateFacts {
    QString candidateId, kind;
    int node = -1, filterIndex = -1;
    SourceFact<QString> id, filterId;
    SourceFact<SourceFwAction> action;
    SourceFact<Direction> direction, limitFlow;
    SourceFact<bool> enabled;
    SourceFact<qint32> weight;
    QVector<int> directionOccurrences, residues;
    bool complete = false, potentialConflict = false, overlapUnknown = true;
};
struct QNameProfileView {
    static constexpr bool inactive = true, unverified = true, engineEligible = false;
    bool valid = false, profileKnown = false, diagnosticsComplete = true, conflictsComplete = true;
    QString error;
    QVector<QNameCandidateFacts> candidates;
    QVector<QNameFilterFacts> filters;
    QVector<ApplicationConstraint> applications;
    QVector<QString> diagnostics;
    int graphVisits = 0, conflictComparisons = 0;
};
struct QNameImportResult {
    ImportReport report;
    std::optional<QNameEvidence> evidence;
    QNameProfileView view;
};
QNameProfileView deriveQNameProfile(const QNameEvidence &evidence, const ImportLimits &limits = {});
QNameImportResult importQNameProfile(const QByteArray &bytes, const ImportLimits &limits = {});
} // namespace Gate::Data
