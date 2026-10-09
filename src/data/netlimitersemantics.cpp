#include "netlimitersemantics.h"

#include <QHash>
#include <QSet>
#include <QUuid>

namespace Gate::Data {
namespace {
struct Scalar {
    bool present = false, valid = false;
    QString value;
};
Scalar scalar(const XmlNode &parent, const QString &name)
{
    Scalar result;
    int count = 0;
    for (const auto &child : parent.children) {
        if (child.name != name) continue;
        ++count;
        result.present = true;
        result.value = child.text;
        result.valid = child.nameSpace.isEmpty() && child.attributes.isEmpty() && child.children.isEmpty();
    }
    result.valid = result.valid && count == 1;
    return result;
}
const XmlNode *uniqueContainer(const XmlNode &parent, const QString &name)
{
    const XmlNode *result = nullptr;
    for (const auto &child : parent.children) {
        if (child.name != name) continue;
        if (result) return nullptr;
        result = &child;
    }
    if (!result || !result->nameSpace.isEmpty() || !result->attributes.isEmpty() ||
        !result->text.trimmed().isEmpty()) return nullptr;
    return result;
}
bool typed(const XmlNode &node, const QString &name, const QString &type)
{
    return node.name == name && node.nameSpace.isEmpty() && node.attributes.size() == 1 &&
           node.attributes.value(QStringLiteral("type")) == type && node.text.trimmed().isEmpty();
}
bool signedInteger(const QString &value, qint64 *number)
{
    if (value.isEmpty()) return false;
    int start = value.front() == QLatin1Char('-') ? 1 : 0;
    if (start == value.size() || (value.size() - start > 1 && value[start] == QLatin1Char('0')) ||
        value == QStringLiteral("-0")) return false;
    for (int i = start; i < value.size(); ++i)
        if (value[i] < QLatin1Char('0') || value[i] > QLatin1Char('9')) return false;
    bool ok = false;
    const auto parsed = value.toLongLong(&ok, 10);
    if (ok) *number = parsed;
    return ok;
}
bool allowedChildren(const XmlNode &node, const QSet<QString> &names)
{
    QSet<QString> seen;
    for (const auto &child : node.children) {
        if (!names.contains(child.name) || seen.contains(child.name)) return false;
        seen.insert(child.name);
    }
    return true;
}
bool validLimits(const SemanticLimits &limits)
{
    const ImportLimits defaults;
    const auto &s = limits.structure;
    return s.bytes > 0 && s.bytes <= defaults.bytes && s.depth > 0 && s.depth <= defaults.depth &&
           s.elements > 0 && s.elements <= defaults.elements && s.attributes > 0 && s.attributes <= defaults.attributes &&
           s.text > 0 && s.text <= defaults.text && s.rules > 0 && s.rules <= defaults.rules &&
           s.dependencies > 0 && s.dependencies <= defaults.dependencies &&
           s.functions > 0 && s.functions <= defaults.functions && s.values > 0 && s.values <= defaults.values &&
           limits.diagnosticsPerItem > 0 && limits.diagnosticsPerItem <= 24 &&
           limits.diagnosticsTotal > 0 && limits.diagnosticsTotal <= 200000 &&
           limits.graphVisits > 0 && limits.graphVisits <= 200000 &&
           limits.conflictComparisons > 0 && limits.conflictComparisons <= 100000;
}
// Se valida tambien un DTO mutable/cargado: accepted no reemplaza estas guardas.
class Bounds {
public:
    explicit Bounds(const ImportLimits &bounds) : limits(bounds) {}
    bool string(const QString &value)
    {
        if (value.size() > limits.text) return false;
        bytes += qint64(value.size()) * 2;
        return bytes <= limits.bytes;
    }
    bool strings(const QVector<QString> &values)
    {
        if (values.size() > limits.elements) return false;
        for (const auto &value : values) if (!string(value)) return false;
        return true;
    }
    bool node(const XmlNode &value, int depth)
    {
        if (depth > limits.depth || ++nodes > limits.elements || value.attributes.size() > limits.attributes ||
            value.children.size() > limits.elements || !value.nameSpace.isEmpty() || value.name.contains(QLatin1Char(':')) ||
            !string(value.name) || !string(value.text)) return false;
        for (auto i = value.attributes.cbegin(); i != value.attributes.cend(); ++i)
            if (i.key().contains(QLatin1Char(':')) || !string(i.key()) || !string(i.value())) return false;
        if (value.name == QStringLiteral("FunctionList") && value.children.size() > limits.functions) return false;
        if (value.name == QStringLiteral("FilterRefs") && value.children.size() > limits.functions) return false;
        if (value.name == QStringLiteral("Values") && value.children.size() > limits.values) return false;
        for (const auto &child : value.children) if (!node(child, depth + 1)) return false;
        return true;
    }
private:
    const ImportLimits &limits;
    int nodes = 0;
    qint64 bytes = 0;
};
bool boundedReport(const ImportReport &report, const SemanticLimits &limits)
{
    const auto &s = limits.structure;
    if (report.candidates.size() > s.rules || report.filters.size() + report.identities.size() > s.dependencies)
        return false;
    Bounds bounds(s);
    if (!bounds.string(report.digest) || !bounds.string(report.sourceVersion) || !bounds.string(report.error) ||
        !bounds.strings(report.diagnostics)) return false;
    QSet<QString> candidateIds;
    for (const auto &candidate : report.candidates) {
        if (QUuid(candidate.id).isNull() || QUuid(candidate.id).toString(QUuid::WithoutBraces) != candidate.id ||
            candidateIds.contains(candidate.id) || !bounds.string(candidate.id) ||
            !bounds.string(candidate.sourceId) || !bounds.string(candidate.sourceType) ||
            !bounds.strings(candidate.diagnostics) || !bounds.node(candidate.source, 1)) return false;
        candidateIds.insert(candidate.id);
    }
    for (const auto &filter : report.filters) if (!bounds.node(filter, 1)) return false;
    for (const auto &identity : report.identities) if (!bounds.node(identity, 1)) return false;
    return true;
}
using Index = QHash<QString, int>;
Index indexNodes(const QVector<XmlNode> &nodes)
{
    Index index;
    for (int i = 0; i < nodes.size(); ++i) {
        const auto id = scalar(nodes[i], QStringLiteral("Id"));
        if (!id.valid || id.value.isEmpty()) continue;
        if (index.contains(id.value)) index[id.value] = -1;
        else index.insert(id.value, i);
    }
    return index;
}
int resolve(const Index &index, const Scalar &reference)
{
    return reference.valid && !reference.value.isEmpty() ? index.value(reference.value, -1) : -1;
}
class Builder {
public:
    Builder(const ImportReport &input, SemanticProfile profile, const SemanticLimits &bounds)
        : report(input), limits(bounds), filterIds(indexNodes(input.filters)), appIds(indexNodes(input.identities))
    {
        view.profile = profile;
    }
    SemanticView build()
    {
        if (view.profile == SemanticProfile::SyntheticGraphV1) {
            applications();
            filters();
            if (!resolveGraph()) return failure(QStringLiteral("GRAPH_LIMIT"));
        } else {
            diagnostic(view.diagnostics, QStringLiteral("EXTERNAL_PROFILE_UNACCREDITED"));
        }
        candidates();
        conflicts();
        view.accepted = true;
        return view;
    }
private:
    const ImportReport &report;
    const SemanticLimits &limits;
    const Index filterIds, appIds;
    SemanticView view;
    int diagnosticCount = 0;
    QVector<bool> localComplete;

    SemanticView failure(const QString &code)
    {
        SemanticView result;
        result.profile = view.profile;
        result.error = code;
        return result;
    }
    void diagnostic(QVector<QString> &target, const QString &code)
    {
        if (target.contains(code)) return;
        if (target.size() >= limits.diagnosticsPerItem || diagnosticCount >= limits.diagnosticsTotal) {
            view.diagnosticsTruncated = true;
            return;
        }
        target.push_back(code);
        ++diagnosticCount;
    }
    void applications()
    {
        for (const auto &node : report.identities) {
            ApplicationSubject app;
            const auto id = scalar(node, QStringLiteral("Id"));
            const auto value = scalar(node, QStringLiteral("Value"));
            if (id.valid && !id.value.isEmpty() && appIds.value(id.value, -1) >= 0 && value.valid && !value.value.isEmpty() &&
                allowedChildren(node, {QStringLiteral("Id"), QStringLiteral("Value")})) {
                if (typed(node, QStringLiteral("AppInfo"), QStringLiteral("SyntheticPath"))) app.kind = SubjectKind::Path;
                if (typed(node, QStringLiteral("AppInfo"), QStringLiteral("SyntheticService"))) app.kind = SubjectKind::Service;
                if (typed(node, QStringLiteral("AppInfo"), QStringLiteral("SyntheticPackage"))) app.kind = SubjectKind::Package;
                app.known = app.kind != SubjectKind::Unknown;
                if (app.known) app.value = value.value;
            }
            view.applications.push_back(app);
        }
    }
    SemanticPredicate predicate(const XmlNode &function, int childIndex)
    {
        SemanticPredicate result;
        result.sourceChild = childIndex;
        const auto type = function.attributes.value(QStringLiteral("type"));
        if (!typed(function, QStringLiteral("function"), type) ||
            !allowedChildren(function, {QStringLiteral("Values")})) return result;
        const auto *values = uniqueContainer(function, QStringLiteral("Values"));
        if (!values || values->children.isEmpty()) return result;
        const QMap<QString, PredicateKind> known = {
            {QStringLiteral("SyntheticAppRef"), PredicateKind::Application},
            {QStringLiteral("SyntheticDomain"), PredicateKind::Domain},
            {QStringLiteral("SyntheticRemoteRange"), PredicateKind::RemoteRange},
            {QStringLiteral("SyntheticInternet"), PredicateKind::Internet},
            {QStringLiteral("SyntheticLocalNetwork"), PredicateKind::LocalNetwork},
            {QStringLiteral("SyntheticTag"), PredicateKind::Tag}};
        result.kind = known.value(type, PredicateKind::Unknown);
        if (result.kind == PredicateKind::Unknown) return result;
        result.complete = true;
        for (const auto &value : values->children) {
            if (value.name != QStringLiteral("value") || !value.attributes.isEmpty() || !value.children.isEmpty() ||
                !value.nameSpace.isEmpty() || value.text.isEmpty()) {
                result.complete = false;
                continue;
            }
            if (result.kind == PredicateKind::Application) {
                const int app = appIds.value(value.text, -1);
                if (app < 0 || !view.applications[app].known) result.complete = false;
                else result.applicationIndices.push_back(app);
            } else {
                result.values.push_back(value.text);
                if ((result.kind == PredicateKind::Internet || result.kind == PredicateKind::LocalNetwork) &&
                    value.text != QStringLiteral("true") && value.text != QStringLiteral("false")) result.complete = false;
            }
        }
        return result;
    }
    void filters()
    {
        for (const auto &node : report.filters) {
            SemanticFilter filter;
            bool complete = typed(node, QStringLiteral("filter"), QStringLiteral("SyntheticFilter")) &&
                            allowedChildren(node, {QStringLiteral("Id"), QStringLiteral("FunctionList"), QStringLiteral("FilterRefs")});
            const auto id = scalar(node, QStringLiteral("Id"));
            complete = complete && id.valid && !id.value.isEmpty() && filterIds.value(id.value, -1) >= 0;
            const auto *functions = uniqueContainer(node, QStringLiteral("FunctionList"));
            if (!functions) complete = false;
            else for (int i = 0; i < functions->children.size(); ++i) {
                auto result = predicate(functions->children[i], i);
                if (!result.complete) {
                    complete = false;
                    diagnostic(filter.diagnostics, QStringLiteral("PREDICATE_UNRESOLVED"));
                }
                filter.predicates.push_back(result);
            }
            bool hasRefs = false;
            for (const auto &child : node.children) hasRefs = hasRefs || child.name == QStringLiteral("FilterRefs");
            if (hasRefs) {
                const auto *refs = uniqueContainer(node, QStringLiteral("FilterRefs"));
                if (!refs || refs->children.size() > limits.structure.functions) complete = false;
                else for (const auto &ref : refs->children) {
                    Scalar reference{true, ref.name == QStringLiteral("ref") && ref.attributes.isEmpty() &&
                                     ref.children.isEmpty() && ref.nameSpace.isEmpty(), ref.text};
                    const int target = resolve(filterIds, reference);
                    if (target < 0 || filter.conjunctiveFilters.contains(target)) {
                        complete = false;
                        diagnostic(filter.diagnostics, QStringLiteral("FILTER_REFERENCE_UNRESOLVED"));
                    } else filter.conjunctiveFilters.push_back(target);
                }
            }
            if (!complete) diagnostic(filter.diagnostics, QStringLiteral("FILTER_INCOMPLETE"));
            view.filters.push_back(filter);
            localComplete.push_back(complete);
        }
    }
    bool visit(int index, QVector<int> &height)
    {
        if (++view.graphVisits > limits.graphVisits) return false;
        auto &filter = view.filters[index];
        bool complete = localComplete[index];
        int single = -1;
        bool multiple = false;
        auto add = [&](int app) {
            if (single < 0) single = app;
            else if (single != app) multiple = true;
        };
        for (const auto &predicate : filter.predicates) {
            if (predicate.kind != PredicateKind::Application) continue;
            if (!predicate.complete) multiple = true;
            for (int app : predicate.applicationIndices) add(app);
        }
        for (int target : filter.conjunctiveFilters) {
            if (++view.graphVisits > limits.graphVisits) return false;
            height[index] = qMin(limits.structure.depth + 1, qMax(height[index], height[target] + 1));
            const auto &child = view.filters[target];
            complete = complete && child.complete;
            if (child.singleApplication) add(*child.singleApplication);
            multiple = multiple || child.applicationAmbiguous;
        }
        filter.complete = complete && height[index] <= limits.structure.depth;
        if (height[index] > limits.structure.depth)
            diagnostic(filter.diagnostics, QStringLiteral("FILTER_CYCLE_OR_DEPTH"));
        filter.applicationAmbiguous = multiple;
        if (!multiple && single >= 0) filter.singleApplication = single;
        if (!filter.complete) diagnostic(filter.diagnostics, QStringLiteral("SCOPE_INCOMPLETE"));
        return true;
    }
    bool resolveGraph()
    {
        const int size = view.filters.size();
        QVector<QVector<int>> parents(size);
        QVector<int> remaining(size), height(size, 1), ready;
        for (int i = 0; i < size; ++i) {
            remaining[i] = view.filters[i].conjunctiveFilters.size();
            if (!remaining[i]) ready.push_back(i);
            for (int target : view.filters[i].conjunctiveFilters) parents[target].push_back(i);
        }
        // Hojas antes de padres: la altura transitiva no depende del orden del XML.
        // La cola evita recursion profunda y no expande cadenas compartidas.
        for (int cursor = 0; cursor < ready.size(); ++cursor) {
            const int index = ready[cursor];
            if (!visit(index, height)) return false;
            for (int parent : parents[index]) if (--remaining[parent] == 0) ready.push_back(parent);
        }
        // Lo no resuelto pertenece a un ciclo o depende de uno; no contamina otras filas.
        for (int i = 0; i < size; ++i) if (remaining[i]) {
            if (++view.graphVisits > limits.graphVisits) return false;
            diagnostic(view.filters[i].diagnostics, QStringLiteral("FILTER_CYCLE_OR_DEPTH"));
            diagnostic(view.filters[i].diagnostics, QStringLiteral("SCOPE_INCOMPLETE"));
        }
        return true;
    }
    void candidates()
    {
        Index ruleIds;
        for (int i = 0; i < report.candidates.size(); ++i) {
            const auto id = scalar(report.candidates[i].source, QStringLiteral("Id"));
            if (!id.valid || id.value.isEmpty()) continue;
            if (ruleIds.contains(id.value)) ruleIds[id.value] = -1;
            else ruleIds.insert(id.value, i);
        }
        for (const auto &input : report.candidates) {
            SemanticCandidate candidate;
            candidate.candidateId = input.id;
            const auto &node = input.source;
            const QString type = node.attributes.value(QStringLiteral("type"));
            bool complete = typed(node, QStringLiteral("rule"), type);
            if (type != QStringLiteral("fwRule")) {
                candidate.reconstruction = Reconstruction::Unsupported;
                diagnostic(candidate.diagnostics, QStringLiteral("RULE_TYPE_UNSUPPORTED"));
                view.candidates.push_back(candidate);
                continue;
            }
            if (!complete) {
                diagnostic(candidate.diagnostics, QStringLiteral("RULE_SHAPE_UNACCREDITED"));
                view.candidates.push_back(candidate);
                continue;
            }
            const auto action = scalar(node, QStringLiteral("action"));
            if (action.valid && action.value == QStringLiteral("Allow")) candidate.action = Action::Allow;
            if (action.valid && action.value == QStringLiteral("Deny")) candidate.action = Action::Block;
            if (action.valid && action.value == QStringLiteral("Ask")) candidate.action = Action::Ask;
            const auto direction = scalar(node, QStringLiteral("Dir"));
            if (direction.valid) candidate.direction = readDirection(direction.value);
            const auto enabled = scalar(node, QStringLiteral("IsEnabled"));
            if (enabled.valid && enabled.value == QStringLiteral("true")) candidate.sourceEnabled = true;
            if (enabled.valid && enabled.value == QStringLiteral("false")) candidate.sourceEnabled = false;
            const auto weight = scalar(node, QStringLiteral("Weight"));
            qint64 number = 0;
            if (weight.valid && signedInteger(weight.value, &number)) candidate.sourceWeight = number;
            if (!candidate.action) diagnostic(candidate.diagnostics, QStringLiteral("ACTION_UNKNOWN"));
            if (candidate.direction == Direction::Unknown) diagnostic(candidate.diagnostics, QStringLiteral("DIRECTION_UNKNOWN"));
            if (!candidate.sourceEnabled) diagnostic(candidate.diagnostics, QStringLiteral("ENABLED_UNKNOWN"));
            if (!candidate.sourceWeight) diagnostic(candidate.diagnostics, QStringLiteral("WEIGHT_UNKNOWN"));
            complete = complete && candidate.action.has_value() && candidate.direction != Direction::Unknown &&
                       candidate.sourceEnabled.has_value() && candidate.sourceWeight.has_value();
            const auto id = scalar(node, QStringLiteral("Id"));
            if (!id.valid || id.value.isEmpty() || ruleIds.value(id.value, -1) < 0) {
                complete = false;
                diagnostic(candidate.diagnostics, QStringLiteral("RULE_IDENTITY_UNRESOLVED"));
            }
            if (!allowedChildren(node, {QStringLiteral("Id"), QStringLiteral("action"), QStringLiteral("Dir"),
                QStringLiteral("IsEnabled"), QStringLiteral("Weight"), QStringLiteral("FilterId"),
                QStringLiteral("CreatedTime"), QStringLiteral("UpdatedTime")})) {
                complete = false;
                diagnostic(candidate.diagnostics, QStringLiteral("RULE_FIELDS_UNACCREDITED"));
            }
            for (const auto &name : {QStringLiteral("CreatedTime"), QStringLiteral("UpdatedTime")}) {
                const auto metadata = scalar(node, name);
                if (metadata.present && !metadata.valid) {
                    complete = false;
                    diagnostic(candidate.diagnostics, QStringLiteral("METADATA_SHAPE_UNACCREDITED"));
                }
            }
            if (!typed(node, QStringLiteral("rule"), QStringLiteral("fwRule"))) {
                complete = false;
                diagnostic(candidate.diagnostics, QStringLiteral("RULE_SHAPE_UNACCREDITED"));
            }
            if (view.profile == SemanticProfile::ExternalUnaccredited) {
                complete = false;
                diagnostic(candidate.diagnostics, QStringLiteral("SUBJECT_SCOPE_UNACCREDITED"));
            } else {
                const int filter = resolve(filterIds, scalar(node, QStringLiteral("FilterId")));
                if (filter >= 0) {
                    candidate.filterIndex = filter;
                    candidate.applicationIndex = view.filters[filter].singleApplication;
                    complete = complete && view.filters[filter].complete && candidate.applicationIndex.has_value();
                    if (!view.filters[filter].complete) diagnostic(candidate.diagnostics, QStringLiteral("SCOPE_INCOMPLETE"));
                    if (!candidate.applicationIndex) diagnostic(candidate.diagnostics, QStringLiteral("SUBJECT_NOT_SINGLE"));
                } else {
                    complete = false;
                    diagnostic(candidate.diagnostics, QStringLiteral("FILTER_REFERENCE_UNRESOLVED"));
                }
            }
            candidate.reconstruction = complete ? Reconstruction::ReconstructedSubset : Reconstruction::Incomplete;
            view.candidates.push_back(candidate);
        }
    }
    bool intersects(Direction a, Direction b) const
    {
        return a == Direction::Both || b == Direction::Both || a == b;
    }
    void conflicts()
    {
        for (int i = 0; i < view.candidates.size(); ++i) {
            auto &a = view.candidates[i];
            if (a.reconstruction == Reconstruction::Unsupported || a.sourceEnabled == false) continue;
            if (!a.applicationIndex || a.direction == Direction::Unknown || !a.action || !a.sourceEnabled) {
                a.overlapUnknown = true;
                diagnostic(a.diagnostics, QStringLiteral("OVERLAP_UNKNOWN"));
            }
            for (int j = i + 1; j < view.candidates.size(); ++j) {
                auto &b = view.candidates[j];
                if (b.reconstruction == Reconstruction::Unsupported || b.sourceEnabled == false) continue;
                if (++view.conflictComparisons > limits.conflictComparisons) {
                    --view.conflictComparisons;
                    view.conflictsComplete = false;
                    diagnostic(view.diagnostics, QStringLiteral("CONFLICT_COMPARISON_LIMIT"));
                    for (auto &candidate : view.candidates) {
                        if (candidate.reconstruction == Reconstruction::Unsupported || candidate.sourceEnabled == false) continue;
                        candidate.overlapUnknown = true;
                        diagnostic(candidate.diagnostics, QStringLiteral("OVERLAP_UNKNOWN"));
                    }
                    return;
                }
                if (!a.applicationIndex || !b.applicationIndex || !a.action || !b.action ||
                    a.direction == Direction::Unknown || b.direction == Direction::Unknown ||
                    !a.sourceEnabled || !b.sourceEnabled) {
                    a.overlapUnknown = b.overlapUnknown = true;
                    diagnostic(a.diagnostics, QStringLiteral("OVERLAP_UNKNOWN"));
                    diagnostic(b.diagnostics, QStringLiteral("OVERLAP_UNKNOWN"));
                    continue;
                }
                if (a.applicationIndex != b.applicationIndex) {
                    a.overlapUnknown = b.overlapUnknown = true;
                    diagnostic(a.diagnostics, QStringLiteral("OVERLAP_UNKNOWN"));
                    diagnostic(b.diagnostics, QStringLiteral("OVERLAP_UNKNOWN"));
                    continue;
                }
                if (intersects(a.direction, b.direction) &&
                    ((*a.action == Action::Allow && *b.action == Action::Block) ||
                     (*a.action == Action::Block && *b.action == Action::Allow))) {
                    a.potentialConflict = b.potentialConflict = true;
                    diagnostic(a.diagnostics, QStringLiteral("POTENTIAL_CONFLICT"));
                    diagnostic(b.diagnostics, QStringLiteral("POTENTIAL_CONFLICT"));
                }
            }
        }
    }
};
} // namespace

SemanticView NetLimiterSemantics::describe(const ImportReport &report, SemanticProfile profile,
                                         const SemanticLimits &limits)
{
    SemanticView rejected;
    rejected.profile = profile;
    if (profile != SemanticProfile::ExternalUnaccredited && profile != SemanticProfile::SyntheticGraphV1) {
        rejected.error = QStringLiteral("PROFILE_INVALID");
        return rejected;
    }
    if (!validLimits(limits)) {
        rejected.error = QStringLiteral("LIMITS_INVALID");
        return rejected;
    }
    if (!report.accepted) {
        rejected.error = QStringLiteral("IMPORT_REJECTED");
        return rejected;
    }
    if (!boundedReport(report, limits)) {
        rejected.error = QStringLiteral("REPORT_BOUNDS_OR_NAMESPACE");
        return rejected;
    }
    return Builder(report, profile, limits).build();
}
} // namespace Gate::Data
