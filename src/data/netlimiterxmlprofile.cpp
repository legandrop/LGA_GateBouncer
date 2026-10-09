#include "netlimiterxmlprofile.h"
#include <QCryptographicHash>
#include <QRegularExpression>
#include <QSet>
#include <QUuid>
#include <limits>

namespace Gate::Data {
namespace {
const QString xsi = QStringLiteral("http://www.w3.org/2001/XMLSchema-instance");
const QString arrays = QStringLiteral("http://schemas.microsoft.com/2003/10/Serialization/Arrays");
const QString xsd = QStringLiteral("http://www.w3.org/2001/XMLSchema");
struct Deriver {
    const QNameEvidence &e;
    const ImportLimits &limits;
    QNameProfileView view;
    qint64 diagnosticBytes = 0;
    QVector<bool> localComplete;
    QMap<QString, int> filterIds;
    void diagnostic(const char *code) {
        const QString text = QString::fromLatin1(code);
        if (view.diagnostics.size() >= 2047 || diagnosticBytes + text.size() * 2 > 256 * 1024 - 64) {
            if (view.diagnosticsComplete) view.diagnostics.push_back("DiagnosticsIncomplete");
            view.diagnosticsComplete = false; return;
        }
        view.diagnostics.push_back(text); diagnosticBytes += text.size() * 2;
    }
    bool is(int i, const QString &local, const QString &uri = "nlsettings") const {
        return e.nodes[i].name == ExpandedName{uri, local};
    }
    QVector<int> children(int i) const { return qnameChildren(e.nodes[i]); }
    bool nilOrBad(int i) const {
        for (const auto &a : e.nodes[i].attributes) {
            if (a.name != ExpandedName{xsi, "nil"}) continue;
            if (a.value.trimmed() == "false" || a.value.trimmed() == "0") continue;
            return true;
        }
        return false;
    }
    bool scalarType(int i, const ExpandedName &expected) const {
        for (const auto &a : e.nodes[i].attributes) if (a.name == ExpandedName{xsi, "type"})
            return e.nodes[i].resolvedType && *e.nodes[i].resolvedType == expected;
        return true;
    }
    SourceFact<QString> text(int i, const ExpandedName &expected = {}) const {
        SourceFact<QString> fact; fact.node = i;
        if (i < 0 || nilOrBad(i) || !scalarType(i, expected)) return fact;
        for (const auto &c : e.nodes[i].content) {
            if (c.child >= 0) return fact;
            fact.value += c.text;
        }
        fact.status = FieldStatus::Known;
        return fact;
    }
    QVector<int> occurrences(int i, const QString &name) const {
        QVector<int> result;
        for (int child : children(i)) if (is(child, name)) result.push_back(child);
        return result;
    }
    SourceFact<QString> scalar(int i, const QString &name, const ExpandedName &expected = {}) const {
        const auto found = occurrences(i, name);
        return found.size() == 1 ? text(found[0], expected) : SourceFact<QString>{};
    }
    QString type(int i, const QString &declared) const {
        for (const auto &a : e.nodes[i].attributes) if (a.name == ExpandedName{xsi, "type"}) {
            const auto &resolved = e.nodes[i].resolvedType;
            return resolved && resolved->uri == "nlsettings" ? resolved->local : QString{};
        }
        return declared;
    }
    bool container(int i) const {
        if (i < 0 || nilOrBad(i)) return false;
        for (const auto &c : e.nodes[i].content) if (c.child < 0 && !c.text.trimmed().isEmpty()) return false;
        return true;
    }
    bool order(int i, const QStringList &memberOrder, QVector<int> *residues = nullptr) {
        int cursor = 0;
        bool ok = container(i);
        for (const auto &a : e.nodes[i].attributes)
            if (a.name != ExpandedName{xsi, "type"} && a.name != ExpandedName{xsi, "nil"}) ok = false;
        for (int child : children(i)) {
            const auto &n = e.nodes[child];
            int slot = -1;
            if (n.name.uri == "nlsettings") for (int j = cursor; j < memberOrder.size(); ++j)
                if (memberOrder[j] == n.name.local) { slot = j; break; }
            if (slot < 0) { ok = false; if (residues) residues->push_back(child); }
            else cursor = slot + 1;
        }
        if (!ok) diagnostic("SourceOrderOrResidueUnknown");
        return ok;
    }
    bool slotOrder(int i, const QStringList &memberOrder) const {
        int cursor = 0;
        for (int child : children(i)) {
            const auto &n = e.nodes[child];
            if (n.name.uri != "nlsettings" || !memberOrder.contains(n.name.local)) continue;
            int slot = -1;
            for (int j = cursor; j < memberOrder.size(); ++j) if (memberOrder[j] == n.name.local) { slot = j; break; }
            if (slot < 0) return false;
            cursor = slot + 1;
        }
        return true;
    }
    SourceFact<bool> boolean(const SourceFact<QString> &in) const {
        SourceFact<bool> f; f.node = in.node;
        const auto v = in.value.trimmed();
        if (in.known() && QStringList{"true", "false", "1", "0"}.contains(v)) {
            f.status = FieldStatus::Known; f.value = v == "true" || v == "1";
        }
        return f;
    }
    SourceFact<QString> sid(int i) {
        SourceFact<QString> f;
        if (i < 0 || type(i, "Sid") != "Sid" || !order(i, {"Bytes"})) return f;
        f = scalar(i, "Bytes", {xsd, "base64Binary"});
        if (!f.known() || f.value.trimmed().isEmpty()) { f.status = FieldStatus::Unknown; return f; }
        QByteArray value = f.value.toLatin1();
        value.replace(" ", ""); value.replace("\r", ""); value.replace("\n", ""); value.replace("\t", "");
        const auto decoded = QByteArray::fromBase64Encoding(value, QByteArray::AbortOnBase64DecodingErrors);
        if (!decoded || decoded.decoded.isEmpty() || QString::fromLatin1(value) != f.value.simplified().remove(' '))
            f.status = FieldStatus::Unknown;
        else f.value = QString::fromLatin1(decoded.decoded.toBase64());
        return f;
    }
    ApplicationConstraint application(int i, const QString &wrapper) {
        ApplicationConstraint app; app.node = i;
        if (type(i, wrapper) != wrapper || !container(i)) return app;
        if (wrapper == "AppId") {
            const bool shape = order(i, {"Path", "Sid"});
            app.path = scalar(i, "Path", {xsd, "string"});
            const auto principals = occurrences(i, "Sid");
            if (principals.size() == 1) app.sidBytes = sid(principals[0]);
            if (!shape) { app.path.status = app.sidBytes.status = FieldStatus::Unknown; }
        } else {
            app.path = scalar(i, "path", {xsd, "string"});
            if (!order(i, {"path"})) app.path.status = FieldStatus::Unknown;
        }
        app.pathExact = app.path.known() && !app.path.value.isEmpty() && app.path.value != "null-path" &&
                        !app.path.value.contains('*') && !app.path.value.contains('?');
        return app;
    }
    QNamePredicate predicate(int i) {
        QNamePredicate p; p.node = i; p.kind = type(i, "FilterFunction");
        const bool ordered = order(i, {"match", "Values"});
        p.match = boolean(scalar(i, "match", {xsd, "boolean"}));
        const auto vals = occurrences(i, "Values");
        if (vals.size() != 1 || !ordered || !container(vals[0]) || type(vals[0], "filterValues") != "filterValues") return p;
        const auto items = children(vals[0]);
        if (items.size() > limits.values) { diagnostic("ValueLimit"); return p; }
        bool known = !items.isEmpty();
        for (int value : items) {
            if (!is(value, "value")) { known = false; continue; }
            if (p.kind == "FFAppIdEqual" || p.kind == "FFPathEqual") {
                const bool appId = p.kind == "FFAppIdEqual";
                auto app = application(value, appId ? "AppId" : "appPath");
                known = known && app.pathExact && (!appId || app.sidBytes.known());
                p.applications.push_back(app);
            } else if (p.kind == "FFDomainNameEqual") {
                auto domain = scalar(value, "DomainName", {xsd, "string"});
                if (type(value, "DomainNameFilterValue") != "DomainNameFilterValue" || !order(value, {"DomainName"})) domain.status = FieldStatus::Unknown;
                known = known && domain.known() && !domain.value.isEmpty(); p.domains.push_back(domain);
            } else known = false;
        }
        p.complete = known && p.match.known();
        if (!p.complete) diagnostic("PredicateIncomplete");
        return p;
    }
    void apps(int role) {
        for (int i : children(role)) {
            if (!is(i, "AppInfo")) { diagnostic("AppInfoItemUnknown"); continue; }
            const QString kind = type(i, "AppInfo");
            const auto appIds = occurrences(i, "AppId");
            ApplicationConstraint app;
            if (appIds.size() == 1) app = application(appIds[0], "AppId");
            app.node = i; app.metadataNodes.push_back(i);
            QStringList memberOrder{"AppId", "CompanyName", "FileDescription", "FileVersion", "ProductName", "ProductVersion", "SysCreated", "Tags"};
            if (kind == "SvcAppInfo") { memberOrder += QStringList{"ServiceDesc", "ServiceName"}; app.serviceName = scalar(i, "ServiceName"); }
            if (kind == "StoreAppInfo") {
                memberOrder += QStringList{"IconPath", "PackageDisplayName", "PackageFolder", "PackageId", "PackageName", "PackagePublisher", "PackageVersion"};
                app.packageId = scalar(i, "PackageId");
            }
            order(i, memberOrder); view.applications.push_back(app);
        }
    }
    void filters(int role) {
        const QStringList common{"Id", "Revision", "BaseFilters", "CreatedTime", "FilterType", "FunctionList", "InternalId", "Name", "PerType", "UpdatedTime"};
        for (int i : children(role)) {
            if (!is(i, "filter")) { diagnostic("FilterItemUnknown"); continue; }
            QNameFilterFacts f; f.node = i; f.id = scalar(i, "Id");
            QStringList memberOrder = common;
            const QString kind = type(i, "filter");
            bool packageComplete = true;
            if (QStringList{"PackageFilter", "SvcPackageFilter", "StorePackageFilter"}.contains(kind)) {
                f.package.node = i;
                memberOrder += "Sid";
                const auto found = occurrences(i, "Sid");
                if (found.size() == 1) f.package.sidBytes = sid(found[0]);
                if (kind == "SvcPackageFilter") { memberOrder += QStringList{"Description", "DisplayName", "SvcName"}; f.package.serviceName = scalar(i, "SvcName"); }
                if (kind == "StorePackageFilter") { memberOrder += QStringList{"DisplayName", "IconPath", "PackageFolder", "PackageId", "Publisher", "Version"}; f.package.packageId = scalar(i, "PackageId"); }
                packageComplete = f.package.sidBytes.known() &&
                    (kind != "SvcPackageFilter" || (f.package.serviceName.known() && !f.package.serviceName.value.isEmpty())) &&
                    (kind != "StorePackageFilter" || (f.package.packageId.known() && !f.package.packageId.value.isEmpty()));
            }
            bool complete = order(i, memberOrder, &f.residues) && f.id.known() && !f.id.value.isEmpty();
            complete = complete && container(role) && packageComplete;
            if (!QStringList{"filter", "PackageFilter", "SvcPackageFilter", "StorePackageFilter"}.contains(kind)) complete = false;
            const auto functions = occurrences(i, "FunctionList");
            if (functions.size() == 1 && container(functions[0]) && type(functions[0], "filterFunctions") == "filterFunctions") {
                const auto list = children(functions[0]);
                if (list.size() > limits.functions || list.isEmpty()) complete = false;
                else for (int function : list) {
                    if (!is(function, "function")) { complete = false; continue; }
                    auto p = predicate(function); complete = complete && p.complete; f.predicates.push_back(p);
                }
            } else complete = false;
            f.complete = complete; localComplete.push_back(complete); view.filters.push_back(f);
        }
    }
    QMap<QString, int> index(const QVector<QNameFilterFacts> &filters) const {
        QMap<QString, int> ids;
        for (int i = 0; i < filters.size(); ++i) if (filters[i].id.known() && !filters[i].id.value.isEmpty()) {
            const auto key = filters[i].id.value; ids[key] = ids.contains(key) ? -1 : i;
        }
        return ids;
    }
    void graph() {
        filterIds = index(view.filters);
        const auto &ids = filterIds;
        const int size = view.filters.size();
        QVector<QVector<int>> parents(size);
        QVector<int> remaining(size), ready;
        for (int i = 0; i < size; ++i) {
            auto &f = view.filters[i];
            if (!f.id.known() || ids.value(f.id.value, -1) != i) localComplete[i] = false;
            const auto bases = occurrences(f.node, "BaseFilters");
            if (bases.size() != 1) { localComplete[i] = false; diagnostic("BaseScopeUnknown"); }
            if (bases.size() == 1) {
                if (!container(bases[0])) localComplete[i] = false;
                for (int ref : children(bases[0])) {
                    const auto name = text(ref, {xsd, "string"}); const int target = name.known() ? ids.value(name.value, -1) : -1;
                    if (!is(ref, "string", arrays) || target < 0) { localComplete[i] = false; diagnostic("BaseFilterUnknown"); }
                    else { f.baseFilters.push_back(target); parents[target].push_back(i); }
                }
            }
            remaining[i] = f.baseFilters.size(); if (!remaining[i]) ready.push_back(i);
        }
        for (int cursor = 0; cursor < ready.size(); ++cursor) {
            const int i = ready[cursor]; auto &f = view.filters[i]; f.complete = localComplete[i];
            if (++view.graphVisits > 200000) { diagnostic("GraphVisitLimit"); break; }
            for (int target : f.baseFilters) {
                if (++view.graphVisits > 200000) { f.complete = false; break; }
                f.height = qMin(limits.depth + 1, qMax(f.height, view.filters[target].height + 1));
                f.complete = f.complete && view.filters[target].complete;
            }
            f.complete = f.complete && f.height <= limits.depth;
            for (int parent : parents[i]) if (--remaining[parent] == 0) ready.push_back(parent);
        }
        for (int i = 0; i < size; ++i) {
            if (remaining[i] || view.graphVisits > 200000) view.filters[i].complete = false;
            if (remaining[i] || view.filters[i].height > limits.depth) diagnostic("FilterCycleOrDepth");
        }
    }
    void candidate(const QNameRowBinding &row, bool rulesComplete) {
        const int i = row.node;
        QNameCandidateFacts f; f.node = i; f.candidateId = row.candidateId; f.kind = type(i, "rule");
        f.id = scalar(i, "Id"); f.filterId = scalar(i, "FilterId"); f.enabled = boolean(scalar(i, "IsEnabled", {xsd, "boolean"}));
        const auto weight = scalar(i, "Weight", {xsd, "int"});
        static const QRegularExpression integer(QStringLiteral("^[+-]?[0-9]+$"));
        bool numberOk = false; const auto number = weight.value.trimmed().toLongLong(&numberOk);
        if (weight.known() && integer.match(weight.value.trimmed()).hasMatch() && numberOk && number >= std::numeric_limits<qint32>::min() && number <= std::numeric_limits<qint32>::max())
            f.weight = {FieldStatus::Known, qint32(number), weight.node};
        QStringList memberOrder{"Id", "Revision", "Conditions", "CreatedTime", "Dir", "FilterId", "InternalId", "IsActive", "IsEnabled", "UpdatedTime", "Weight"};
        if (f.kind == "fwRule") memberOrder += QStringList{"Dir", "action"};
        else if (f.kind == "limitRule") memberOrder += QStringList{"Dir", "limitSize"};
        bool complete = order(i, memberOrder, &f.residues) && rulesComplete;
        f.directionOccurrences = occurrences(i, "Dir");
        if (slotOrder(i, memberOrder) && f.directionOccurrences.size() == 2) {
            const auto a = text(f.directionOccurrences[0], {"nlsettings", "RuleDir"}), b = text(f.directionOccurrences[1], {"nlsettings", "RuleDir"});
            if (a.known() && b.known() && a.value == b.value && readDirection(a.value) != Direction::Unknown) {
                auto &d = f.kind == "limitRule" ? f.limitFlow : f.direction;
                d = {FieldStatus::Known, readDirection(a.value), a.node};
            }
        }
        if (f.kind == "fwRule") {
            const auto a = scalar(i, "action", {"nlsettings", "FwAction"});
            const int action = QStringList{"None", "Ask", "Allow", "Deny", "Block"}.indexOf(a.value);
            // Un residuo distinto no borra action; el slot debe seguir al segundo Dir/segmento base.
            if (a.known() && action >= 0 && slotOrder(i, memberOrder))
                f.action = {FieldStatus::Known, SourceFwAction(action), a.node};
        } else f.action.status = FieldStatus::Unsupported;
        if (f.filterId.known()) f.filterIndex = filterIds.value(f.filterId.value, -1);
        if (f.filterIndex < 0) diagnostic("FilterReferenceUnknown");
        const auto conditions = occurrences(i, "Conditions");
        if (!conditions.isEmpty() && (!container(conditions[0]) || !children(conditions[0]).isEmpty() || conditions.size() != 1)) {
            complete = false; diagnostic("ScheduleUnsupported");
        }
        f.complete = view.profileKnown && complete && f.kind == "fwRule" && f.action.known() && f.direction.known() && f.enabled.known() && f.weight.known() &&
                     f.filterIndex >= 0 && view.filters[f.filterIndex].complete && f.id.known() && !f.id.value.isEmpty();
        view.candidates.push_back(f);
    }
    void enrich() {
        QMap<QString, int> ids;
        auto key = [](const ApplicationConstraint &a) { return QString::number(a.path.value.size()) + ':' + a.path.value + a.sidBytes.value; };
        for (int i = 0; i < view.applications.size(); ++i) {
            const auto &a = view.applications[i];
            if (!a.pathExact || !a.sidBytes.known()) continue;
            const auto k = key(a); ids[k] = ids.contains(k) ? -1 : i;
        }
        for (auto &f : view.filters) for (auto &p : f.predicates) for (auto &a : p.applications) {
            if (!a.pathExact || !a.sidBytes.known()) continue;
            const int i = ids.value(key(a), -1);
            if (i >= 0) { a.metadataNodes = view.applications[i].metadataNodes; a.packageId = view.applications[i].packageId; a.serviceName = view.applications[i].serviceName; }
        }
    }
    QNameProfileView run() {
        if (!validateQNameEvidence(e, limits)) { view.error = "InvalidQNameEvidence"; return view; }
        view.valid = true;
        if (e.excludedRootSections) diagnostic("RootSettingsExcluded");
        for (const auto &n : e.nodes) for (const auto &a : n.attributes) if (a.name == ExpandedName{xsi, "nil"}) {
            const auto nil = a.value.trimmed();
            if (!QStringList{"true", "false", "0", "1"}.contains(nil)) diagnostic("NilValueUnknown");
            if (nil == "true" || nil == "1") for (const auto &c : n.content)
                if (c.child >= 0 || !c.text.trimmed().isEmpty()) { diagnostic("InconsistentNil"); break; }
        }
        int versions = 0;
        for (int role : e.roles) if (is(role, "Version")) { ++versions; const auto v = text(role, {xsd, "int"}); view.profileKnown = v.known() && v.value == "21"; }
        view.profileKnown = view.profileKnown && versions == 1;
        if (!view.profileKnown) {
            diagnostic("ProfileVersionUnknown");
            for (const auto &row : e.rows) { QNameCandidateFacts f; f.candidateId = row.candidateId; f.node = row.node; view.candidates.push_back(f); }
            return view;
        }
        for (int role : e.roles) if (is(role, "AppInfos")) apps(role);
        for (int role : e.roles) if (is(role, "Filters")) filters(role);
        if (view.filters.size() + view.applications.size() > limits.dependencies) { view.valid = false; view.error = "DependencyLimit"; return view; }
        graph(); enrich();
        bool rulesComplete = false;
        for (int role : e.roles) if (is(role, "Rules")) rulesComplete = container(role);
        for (const auto &row : e.rows) candidate(row, rulesComplete);
        QMap<QString, int> ids;
        for (const auto &c : view.candidates) if (c.id.known()) ids[c.id.value] = ids.value(c.id.value) + 1;
        for (auto &c : view.candidates) if (ids.value(c.id.value) != 1) c.complete = false;
        for (int i = 0; i < view.candidates.size(); ++i) for (int j = i + 1; j < view.candidates.size(); ++j) {
            if (++view.conflictComparisons > 100000) { view.conflictsComplete = false; diagnostic("ConflictComparisonLimit"); return view; }
            auto &a = view.candidates[i]; auto &b = view.candidates[j];
            if (a.complete && b.complete && a.filterIndex == b.filterIndex && a.action.value != b.action.value &&
                (a.direction.value == b.direction.value || a.direction.value == Direction::Both || b.direction.value == Direction::Both)) a.potentialConflict = b.potentialConflict = true;
        }
        if (!view.diagnosticsComplete) for (auto &c : view.candidates) c.complete = false;
        return view;
    }
};
} // namespace
QNameProfileView deriveQNameProfile(const QNameEvidence &evidence, const ImportLimits &limits) {
    return Deriver{evidence, limits, {}, 0, {}, {}}.run();
}
QNameImportResult importQNameProfile(const QByteArray &bytes, const ImportLimits &limits) {
    QNameImportResult result;
    const auto parsed = readQNameXml(bytes, limits);
    if (!parsed.accepted) { result.report.error = parsed.error; return result; }
    QNameEvidence e; e.profileId = "NetLimiter-5.2.10-DCS-21";
    e.digest = QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex());
    if (!projectQNameRoles(parsed.nodes, e)) { result.report.error = "ProfileNotRecognizedOrAmbiguous"; return result; }
    for (int role : e.roles) if (e.nodes[role].name.local == "Rules") for (int child : qnameChildren(e.nodes[role]))
        if (e.nodes[child].name == ExpandedName{"nlsettings", "rule"}) e.rows.push_back({qnameCandidateId(e, child), child});
    result.view = deriveQNameProfile(e, limits);
    if (!result.view.valid) { result.report.error = result.view.error; return result; }
    result.report.accepted = true; result.report.digest = e.digest; result.report.sourceVersion = result.view.profileKnown ? "21" : "Unknown";
    result.report.diagnostics = result.view.diagnostics;
    for (const auto &facts : result.view.candidates) {
        Candidate row; row.id = facts.candidateId; row.sourceId = facts.id.known() ? facts.id.value : QString{}; row.sourceType = facts.kind;
        row.status = facts.kind == "fwRule" ? CandidateStatus::NeedsReview : CandidateStatus::Unsupported;
        row.direction = facts.direction.known() ? facts.direction.value : Direction::Unknown;
        if (facts.enabled.known()) row.sourceEnabled = facts.enabled.value;
        if (facts.weight.known()) row.sourceWeight = facts.weight.value;
        row.diagnostics.push_back("InactiveUnverifiedQNameSource"); result.report.candidates.push_back(row);
    }
    result.evidence = std::move(e); return result;
}
} // namespace Gate::Data
