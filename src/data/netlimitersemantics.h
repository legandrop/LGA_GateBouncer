#pragma once

#include "contracts.h"

namespace Gate::Data {
// El perfil sintetico requiere seleccion explicita; no identifica exports externos.
enum class SemanticProfile { ExternalUnaccredited, SyntheticGraphV1 };
enum class Reconstruction { ReconstructedSubset, Incomplete, Unsupported };
enum class SubjectKind { Unknown, Path, Service, Package };
enum class PredicateKind { Unknown, Application, Domain, RemoteRange, Internet, LocalNetwork, Tag };

struct ApplicationSubject {
    SubjectKind kind = SubjectKind::Unknown;
    QString value;
    bool known = false;
};
struct SemanticPredicate {
    PredicateKind kind = PredicateKind::Unknown;
    // Values se unen por OR; los predicados de un filtro se unen por AND.
    QVector<QString> values;
    QVector<int> applicationIndices;
    int sourceChild = -1;
    bool complete = false;
};
struct SemanticFilter {
    QVector<SemanticPredicate> predicates;
    // Referencias AND, sin expandir diamantes ni productos de Values.
    QVector<int> conjunctiveFilters;
    QVector<QString> diagnostics;
    std::optional<int> singleApplication;
    bool applicationAmbiguous = false;
    bool complete = false;
};
struct SemanticCandidate {
    QString candidateId;
    Reconstruction reconstruction = Reconstruction::Incomplete;
    std::optional<Action> action;
    Direction direction = Direction::Unknown;
    std::optional<bool> sourceEnabled;
    std::optional<qint64> sourceWeight;
    std::optional<int> filterIndex, applicationIndex;
    QVector<QString> diagnostics;
    bool potentialConflict = false, overlapUnknown = false;
};
struct SemanticLimits {
    ImportLimits structure;
    int diagnosticsPerItem = 24;
    int diagnosticsTotal = 200000;
    int graphVisits = 200000;
    int conflictComparisons = 100000;
};
struct SemanticView {
    bool accepted = false;
    QString error;
    SemanticProfile profile = SemanticProfile::ExternalUnaccredited;
    QVector<ApplicationSubject> applications;
    QVector<SemanticFilter> filters;
    QVector<SemanticCandidate> candidates;
    QVector<QString> diagnostics;
    int graphVisits = 0, conflictComparisons = 0;
    bool diagnosticsTruncated = false, conflictsComplete = true;
    // Estas propiedades son constantes del tipo, no estados modificables de policy.
    static constexpr bool inactive = true;
    static constexpr bool unverified = true;
    static constexpr bool enginePolicyEligible = false;
};
class NetLimiterSemantics {
public:
    static SemanticView describe(const ImportReport &report, SemanticProfile profile,
                                 const SemanticLimits &limits = {});
};
} // namespace Gate::Data
