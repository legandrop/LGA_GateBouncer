#include "netlimiterxmlprofile.h"
#include <QCryptographicHash>
#include <QRegularExpression>
#include <QSet>
#include <QUuid>
#include <limits>
#include <algorithm>

namespace Gate::Data {
namespace {
constexpr QLatin1StringView xsi("http://www.w3.org/2001/XMLSchema-instance");
constexpr QLatin1StringView arrays("http://schemas.microsoft.com/2003/10/Serialization/Arrays");
constexpr QLatin1StringView xsd("http://www.w3.org/2001/XMLSchema");
bool ipv4(const QString &text, quint32 &result) {
    const auto parts = text.split('.');
    if (parts.size() != 4) return false;
    result = 0;
    for (const auto &part : parts) {
        if (part.isEmpty() || part.size() > 3 || (part.size() > 1 && part[0] == '0')) return false;
        quint32 byte = 0;
        for (QChar c : part) { if (c < '0' || c > '9') return false; byte = byte * 10 + c.unicode() - '0'; }
        if (byte > 255) return false;
        result = (result << 8) | byte;
    }
    return true;
}
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
    bool attributesKnown(int i) const {
        for (const auto &a : e.nodes[i].attributes) {
            if (a.name != ExpandedName{xsi, "type"} && a.name != ExpandedName{xsi, "nil"}) return false;
            if (a.name == ExpandedName{xsi, "type"} && !e.nodes[i].resolvedType) return false;
            if (a.name == ExpandedName{xsi, "nil"}) {
                const auto value = a.value.trimmed();
                if (!QStringList{"true", "false", "0", "1"}.contains(value)) return false;
                if (value == "true" || value == "1") for (const auto &c : e.nodes[i].content)
                    if (c.child >= 0 || !c.text.trimmed().isEmpty()) return false;
            }
        }
        return true;
    }
    bool subtreeAttributesKnown(int i) const {
        QVector<int> pending{i};
        while (!pending.isEmpty()) {
            const int node = pending.takeLast();
            if (!attributesKnown(node)) return false;
            for (int child : children(node)) pending.push_back(child);
        }
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
    SourceFact<bool> explicitNilSid(int i, const SourceFact<QString> &bytes) const {
        SourceFact<bool> f; f.node = i;
        if (i < 0 || type(i, "Sid") != "Sid") return f;
        bool nil = false, present = false;
        for (const auto &a : e.nodes[i].attributes) {
            if (a.name == ExpandedName{xsi, "type"}) continue;
            if (a.name != ExpandedName{xsi, "nil"} || present) return f;
            present = true;
            const auto value = a.value.trimmed();
            if (!QStringList{"true", "false", "1", "0"}.contains(value)) return f;
            nil = value == "true" || value == "1";
        }
        if (nil) {
            for (const auto &c : e.nodes[i].content)
                if (c.child >= 0 || !c.text.trimmed().isEmpty()) return f;
            f.status = FieldStatus::Known; f.value = true;
        } else if (bytes.known()) {
            f.status = FieldStatus::Known; f.value = false;
        }
        return f;
    }
    ApplicationConstraint application(int i, const QString &wrapper) {
        ApplicationConstraint app; app.node = i;
        if (type(i, wrapper) != wrapper || !container(i)) return app;
        if (wrapper == "AppId") {
            const bool shape = order(i, {"Path", "Sid"});
            app.path = scalar(i, "Path", {xsd, "string"});
            const auto principals = occurrences(i, "Sid");
            if (principals.size() == 1) {
                app.sidBytes = sid(principals[0]);
                app.sidExplicitNil = explicitNilSid(principals[0], app.sidBytes);
            }
            if (!shape) { app.path.status = app.sidBytes.status = app.sidExplicitNil.status = FieldStatus::Unknown; }
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
        p.match = boolean(scalar(i, "match", {xsd, "boolean"}));
        // Las funciones de zona heredan FilterFunction, no FilterFunctionT: no tienen Values.
        if (p.kind == "FFIsInternetTraffic" || p.kind == "FFIsLocalNetworkTraffic") {
            p.complete = order(i, {"match"}) && p.match.known();
            p.structureKnown = p.complete && subtreeAttributesKnown(i);
            if (!p.complete) diagnostic("PredicateIncomplete");
            return p;
        }
        const bool ordered = order(i, {"match", "Values"});
        const auto vals = occurrences(i, "Values");
        if (vals.size() != 1 || !ordered || !container(vals[0]) || type(vals[0], "filterValues") != "filterValues") return p;
        const auto items = children(vals[0]);
        if (items.size() > limits.values) { diagnostic("ValueLimit"); return p; }
        bool known = !items.isEmpty(), structureKnown = known;
        for (int value : items) {
            if (!is(value, "value")) { known = structureKnown = false; continue; }
            if (p.kind == "FFAppIdEqual" || p.kind == "FFPathEqual") {
                const bool appId = p.kind == "FFAppIdEqual";
                auto app = application(value, appId ? "AppId" : "appPath");
                known = known && app.pathExact && (!appId || app.sidBytes.known());
                structureKnown = structureKnown && app.pathExact && (!appId || app.sidBytes.known() ||
                    (app.sidExplicitNil.known() && app.sidExplicitNil.value));
                p.applications.push_back(app);
            } else if (p.kind == "FFDomainNameEqual") {
                auto domain = scalar(value, "DomainName", {xsd, "string"});
                if (type(value, "DomainNameFilterValue") != "DomainNameFilterValue" || !order(value, {"DomainName"})) domain.status = FieldStatus::Unknown;
                known = known && domain.known() && !domain.value.isEmpty(); p.domains.push_back(domain);
            } else if (p.kind == "FFTagEqual") {
                auto tag = scalar(value, "tag", {xsd, "string"});
                if (type(value, "appTag") != "appTag" || !order(value, {"tag"})) tag.status = FieldStatus::Unknown;
                known = known && tag.known() && !tag.value.isEmpty(); p.tags.push_back(tag);
            } else if (p.kind == "FFRemoteAddressInRange") {
                QNamePredicate::AddressRange range; range.lexical = scalar(value, "range", {xsd, "string"});
                const bool shape = type(value, "IPRangeFilterValue") == "IPRangeFilterValue" && order(value, {"range"});
                const auto ends = range.lexical.value.split('-'); quint32 first = 0, last = 0;
                if (shape && range.lexical.known() && ends.size() == 2 && ipv4(ends[0], first) && ipv4(ends[1], last) && first <= last) {
                    range.first = {FieldStatus::Known, first, range.lexical.node};
                    range.last = {FieldStatus::Known, last, range.lexical.node};
                }
                // Otras sintaxis/familias permanecen conservadas, sin reinterpretación de alcance.
                known = known && range.first.known() && range.last.known(); p.remoteRanges.push_back(range);
            } else known = false;
            if (p.kind != "FFAppIdEqual") structureKnown = known;
        }
        p.structureKnown = structureKnown && p.match.known() && subtreeAttributesKnown(i);
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
            f.filterType = scalar(i, "FilterType", {"nlsettings", "FilterType"});
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
            bool conjunction = complete && subtreeAttributesKnown(i) && e.nodes[role].attributes.isEmpty() &&
                f.package.node < 0 && f.filterType.known() &&
                (f.filterType.value == "Filter" || f.filterType.value == "Zone");
            const auto functions = occurrences(i, "FunctionList");
            if (functions.size() == 1 && container(functions[0]) && type(functions[0], "filterFunctions") == "filterFunctions") {
                conjunction = conjunction && attributesKnown(functions[0]);
                const auto list = children(functions[0]);
                if (list.size() > limits.functions || list.isEmpty()) complete = conjunction = false;
                else for (int function : list) {
                    if (!is(function, "function")) { complete = conjunction = false; continue; }
                    auto p = predicate(function); complete = complete && p.complete;
                    conjunction = conjunction && p.structureKnown; f.predicates.push_back(p);
                }
            } else complete = conjunction = false;
            f.conjunctionKnown = conjunction;
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
            if (!f.id.known() || ids.value(f.id.value, -1) != i) {
                localComplete[i] = false; f.conjunctionKnown = false;
            }
            const auto bases = occurrences(f.node, "BaseFilters");
            if (bases.size() != 1) { localComplete[i] = false; f.conjunctionKnown = false; diagnostic("BaseScopeUnknown"); }
            if (bases.size() == 1) {
                if (!container(bases[0])) {
                    localComplete[i] = false; f.conjunctionKnown = false;
                }
                // No se infiere el tipo de una colección de bases declarada con atributos.
                if (!e.nodes[bases[0]].attributes.isEmpty() || !children(bases[0]).isEmpty()) f.conjunctionKnown = false;
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
    void candidate(const QNameRowBinding &row, bool rulesComplete, bool rulesScopeKnown) {
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
        f.scopeKnown = view.profileKnown && complete && rulesScopeKnown && subtreeAttributesKnown(i) &&
            (conditions.isEmpty() || e.nodes[conditions[0]].attributes.isEmpty()) && f.kind == "fwRule" && f.filterIndex >= 0 &&
            view.filters[f.filterIndex].conjunctionKnown && f.id.known() && !f.id.value.isEmpty();
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
        bool rulesComplete = false, rulesScopeKnown = false;
        for (int role : e.roles) if (is(role, "Rules")) {
            rulesComplete = container(role);
            rulesScopeKnown = rulesComplete && e.nodes[role].attributes.isEmpty();
        }
        for (const auto &row : e.rows) candidate(row, rulesComplete, rulesScopeKnown);
        QMap<QString, int> ids;
        for (const auto &c : view.candidates) if (c.id.known()) ids[c.id.value] = ids.value(c.id.value) + 1;
        for (auto &c : view.candidates) if (ids.value(c.id.value) != 1) c.complete = c.scopeKnown = false;
        QVector<int> weighted;
        for (int i = 0; i < view.candidates.size(); ++i)
            if (view.candidates[i].kind == "fwRule" && view.candidates[i].weight.known()) weighted.push_back(i);
        std::stable_sort(weighted.begin(), weighted.end(), [this](int a, int b) { return view.candidates[a].weight.value > view.candidates[b].weight.value; });
        for (int i : weighted) {
            if (view.weightGroups.isEmpty() || view.candidates[view.weightGroups.back().front()].weight.value != view.candidates[i].weight.value)
                view.weightGroups.push_back({});
            view.weightGroups.back().push_back(i);
        }
        for (int i = 0; i < view.candidates.size(); ++i) for (int j = i + 1; j < view.candidates.size(); ++j) {
            if (++view.conflictComparisons > 100000) { view.conflictsComplete = false; diagnostic("ConflictComparisonLimit"); return view; }
            auto &a = view.candidates[i]; auto &b = view.candidates[j];
            if (a.complete && b.complete && a.filterIndex == b.filterIndex && a.action.value != b.action.value &&
                (a.direction.value == b.direction.value || a.direction.value == Direction::Both || b.direction.value == Direction::Both)) a.potentialConflict = b.potentialConflict = true;
        }
        if (!view.diagnosticsComplete) for (auto &c : view.candidates) c.complete = c.scopeKnown = false;
        return view;
    }
};
} // namespace
namespace {
QNameMatch comparePredicate(const QNamePredicate &p, const QNameConnectionFacts &facts) {
    if (!p.complete || !p.match.known()) return QNameMatch::Unknown;
    bool any = false;
    if (p.kind == "FFIsInternetTraffic" || p.kind == "FFIsLocalNetworkTraffic") {
        const auto &zone = p.kind == "FFIsInternetTraffic" ? facts.internetZone : facts.localNetworkZone;
        if (!zone.known()) return QNameMatch::Unknown;
        any = zone.value;
    } else if (p.kind == "FFRemoteAddressInRange") {
        if (!facts.remoteIpv4.known()) return QNameMatch::Unknown;
        for (const auto &range : p.remoteRanges)
            any = any || (range.first.value <= facts.remoteIpv4.value && facts.remoteIpv4.value <= range.last.value);
    } else if (p.kind == "FFTagEqual") {
        if (!facts.applicationTags.known()) return QNameMatch::Unknown;
        for (const auto &tag : p.tags) any = any || facts.applicationTags.value.contains(tag.value);
    } else {
        // Identidad AppId/path y comparación de dominio requieren sus catálogos/normalización
        // originales. Datos textuales declarados no cierran ese puente ni conceden autoridad.
        return QNameMatch::Unknown;
    }
    return any == p.match.value ? QNameMatch::Yes : QNameMatch::No;
}
}
QNameMatch compareQNameFilter(const QNameProfileView &view, int filter, const QNameConnectionFacts &facts) {
    if (!view.valid || !view.profileKnown || !view.diagnosticsComplete || filter < 0 || filter >= view.filters.size()) return QNameMatch::Unknown;
    const auto &f = view.filters[filter];
    // El grafo se conserva; no se adivina aquí el operador de filtros Composite ni Package.
    if (!f.conjunctionKnown || !f.baseFilters.isEmpty() || f.package.node >= 0 || f.predicates.isEmpty() ||
        !f.filterType.known() || (f.filterType.value != "Filter" && f.filterType.value != "Zone")) return QNameMatch::Unknown;
    bool unknown = false;
    for (const auto &p : f.predicates) {
        const auto result = comparePredicate(p, facts);
        if (result == QNameMatch::No) return result;
        unknown = unknown || result == QNameMatch::Unknown;
    }
    return unknown ? QNameMatch::Unknown : QNameMatch::Yes;
}
QNamePolicyComparison compareQNamePolicy(const QNameProfileView &view, const QNameConnectionFacts &facts) {
    QNamePolicyComparison result;
    if (!view.valid || !view.profileKnown || !view.diagnosticsComplete ||
        (facts.direction != Direction::In && facts.direction != Direction::Out)) return result;
    struct Compared { int index; QNameMatch match; };
    QVector<Compared> compared;
    std::optional<qint32> highest;
    for (int i = 0; i < view.candidates.size(); ++i) {
        const auto &c = view.candidates[i];
        if (c.kind != "fwRule" || (c.enabled.known() && !c.enabled.value)) continue;
        if (c.direction.known() && c.direction.value != Direction::Both && c.direction.value != facts.direction) continue;
        auto match = c.scopeKnown ? compareQNameFilter(view, c.filterIndex, facts) : QNameMatch::Unknown;
        if (match == QNameMatch::No) continue;
        // La nueva prueba de exclusión nunca convierte una fila incompleta en ganadora.
        if (match == QNameMatch::Yes && !c.complete) match = QNameMatch::Unknown;
        if (!c.weight.known()) return result;
        compared.push_back({i, match});
        if (match == QNameMatch::Yes && (!highest || c.weight.value > *highest)) highest = c.weight.value;
    }
    if (!highest) { result.matched = compared.isEmpty() ? QNameMatch::No : QNameMatch::Unknown; return result; }
    for (const auto &c : compared) {
        const auto weight = view.candidates[c.index].weight.value;
        if (c.match == QNameMatch::Unknown && weight >= *highest) return result;
        if (c.match == QNameMatch::Yes && weight == *highest) result.highestWeightCandidates.push_back(c.index);
    }
    result.matched = QNameMatch::Yes;
    result.tie = result.highestWeightCandidates.size() != 1;
    if (!result.tie) {
        const auto &winner = view.candidates[result.highestWeightCandidates[0]];
        if (winner.action.known() && winner.action.value != SourceFwAction::None) result.action = winner.action;
    }
    return result;
}
namespace {
bool applicationSidShape(const QByteArray &sid) {
    return sid.size() >= 12 && sid.size() <= 68 && quint8(sid[0]) == 1 &&
        quint8(sid[1]) >= 1 && quint8(sid[1]) <= 15 && sid.size() == 8 + 4 * quint8(sid[1]);
}
std::optional<QByteArray> applicationSourceSid(const ApplicationConstraint &application) {
    if (!application.sidBytes.known()) return {};
    const auto encoded = application.sidBytes.value.toLatin1();
    const auto sid = QByteArray::fromBase64(encoded, QByteArray::AbortOnBase64DecodingErrors);
    if (sid.toBase64() != encoded || !applicationSidShape(sid)) return {};
    return sid;
}
QNameMatch compareApplicationPredicate(const QNamePredicate &p, const QByteArray &appId,
    const QByteArray &accountSid, const QString &image, const QMap<int, QByteArray> &canonical) {
    if (!p.complete || !p.match.known() || p.kind != "FFAppIdEqual" || p.applications.isEmpty()) return QNameMatch::Unknown;
    bool any = false, unknown = false;
    for (const auto &a : p.applications) {
        const auto sid = applicationSourceSid(a);
        if (!sid) { unknown = true; continue; }
        if (*sid != accountSid) continue; // Sid.Equals original compara bytes, no nombres/cuenta inferida.
        const auto found = canonical.constFind(a.node);
        if (a.pathExact && a.path.known() && a.path.value == image &&
            found != canonical.cend() && *found == appId) any = true;
        else unknown = true;
        // Un AppId Windows distinto no prueba String.Compare(ignoreCase:true) del motor fuente.
        // Alias/cultura/casing requieren su puente original; no convierten Unknown en No.
    }
    const auto positive = any ? QNameMatch::Yes : unknown ? QNameMatch::Unknown : QNameMatch::No;
    if (positive == QNameMatch::Unknown || p.match.value) return positive;
    return positive == QNameMatch::Yes ? QNameMatch::No : QNameMatch::Yes;
}
QNameMatch compareApplicationFilter(const QNameProfileView &view, int index, const QByteArray &appId,
    const QByteArray &accountSid, const QString &image, const QMap<int, QByteArray> &canonical) {
    if (index < 0 || index >= view.filters.size()) return QNameMatch::Unknown;
    const auto &filter = view.filters[index];
    if (!filter.conjunctionKnown || !filter.baseFilters.isEmpty() || filter.package.node >= 0 ||
        !filter.filterType.known() || (filter.filterType.value != "Filter" && filter.filterType.value != "Zone") ||
        filter.predicates.isEmpty()) return QNameMatch::Unknown;
    bool unknown = false;
    for (const auto &p : filter.predicates) {
        const auto match = compareApplicationPredicate(p, appId, accountSid, image, canonical);
        if (match == QNameMatch::No) return match;
        unknown |= match == QNameMatch::Unknown;
    }
    return unknown ? QNameMatch::Unknown : QNameMatch::Yes;
}
QString actionReviewReason(const QNameCandidateFacts &candidate) {
    if (candidate.enabled.known() && !candidate.enabled.value)
        return "Original rule is disabled; its source action remains inactive";
    if (candidate.action.known() && candidate.action.value == SourceFwAction::Ask)
        return "Original Ask requires a pending connection decision; fixed Allow or Deny is not equivalent";
    if (candidate.action.known() && candidate.action.value == SourceFwAction::Block)
        return "Original Block is distinct from Deny; native equivalence requires review";
    return {};
}
QString membershipReviewReason(const QNameFilterFacts &filter) {
    for (const auto &p : filter.predicates) {
        if (p.kind == "FFIsInternetTraffic" || p.kind == "FFIsLocalNetworkTraffic")
            return "Original editable zone membership is unknown; address classes do not establish equivalence";
        if (p.kind == "FFTagEqual")
            return "Original tag membership is incomplete; retained definitions do not establish an empty set";
    }
    return {};
}
}
QNameApplicationComparison compareQNameApplicationScope(const QNameProfileView &view, int index,
    const QByteArray &appId, const QByteArray &accountSid, const QString &originalImage,
    const QMap<int, QByteArray> &canonicalApplications) {
    QNameApplicationComparison result;
    result.reason = "Source scope is not representable by the original application selector";
    if (!view.valid || !view.profileKnown || index < 0 || index >= view.candidates.size() ||
        !applicationSidShape(accountSid) || appId.size() < 4 || appId.size() > 8192 || (appId.size() & 1) ||
        appId[appId.size()-1] != 0 || appId[appId.size()-2] != 0 || originalImage.isEmpty()) return result;
    const auto &selected = view.candidates[index];
    const auto actionReason = actionReviewReason(selected);
    if (!actionReason.isEmpty()) { result.reason = actionReason; return result; }
    if (selected.filterIndex >= 0 && selected.filterIndex < view.filters.size()) {
        const auto &filter = view.filters[selected.filterIndex];
        const auto membershipReason = membershipReviewReason(filter);
        if (!membershipReason.isEmpty()) { result.reason = membershipReason; return result; }
        for (const auto &p : filter.predicates) for (const auto &a : p.applications)
            if (a.sidExplicitNil.known() && a.sidExplicitNil.value) {
                result.reason = "Original AppId has explicit nil SID; its principal scope is unknown";
                return result;
            }
    }
    if (!view.diagnosticsComplete) {
        result.reason = "Original source diagnostics are incomplete; precedence requires review";
        return result;
    }
    if (!selected.complete || !selected.scopeKnown || selected.kind != "fwRule" || !selected.enabled.known() || !selected.enabled.value ||
        !selected.weight.known() || !selected.action.known() ||
        (selected.action.value != SourceFwAction::Allow && selected.action.value != SourceFwAction::Deny) ||
        !selected.direction.known() || selected.direction.value == Direction::Unknown ||
        selected.filterIndex < 0 || selected.filterIndex >= view.filters.size()) return result;
    const auto &filter = view.filters[selected.filterIndex];
    // Sólo un AppId positivo único conserva exactamente el ámbito del selector aplicación/cuenta.
    if (!filter.complete || !filter.conjunctionKnown || !filter.baseFilters.isEmpty() || filter.package.node >= 0 ||
        !filter.filterType.known() || filter.filterType.value != "Filter" || filter.predicates.size() != 1) return result;
    const auto &p = filter.predicates[0];
    if (p.kind != "FFAppIdEqual" || !p.complete || !p.match.known() || !p.match.value || p.applications.size() != 1) return result;
    const auto &application = p.applications[0];
    if (application.packageId.node >= 0 || application.serviceName.node >= 0 ||
        compareApplicationPredicate(p, appId, accountSid, originalImage, canonicalApplications) != QNameMatch::Yes) {
        result.reason = "Source AppId, account SID or literal image does not match the original cause";
        return result;
    }
    for (int other = 0; other < view.candidates.size(); ++other) {
        if (other == index) continue;
        const auto &candidate = view.candidates[other];
        if (candidate.kind == "limitRule" || (candidate.enabled.known() && !candidate.enabled.value)) continue;
        if (candidate.kind != "fwRule") { result.interferingCandidates.push_back(other); continue; }
        if (candidate.direction.known() && candidate.direction.value != Direction::Unknown &&
            selected.direction.value != Direction::Both && candidate.direction.value != Direction::Both &&
            candidate.direction.value != selected.direction.value) continue;
        if (candidate.weight.known() && candidate.weight.value < selected.weight.value) continue;
        // Incluso una fila incompleta puede quedar disjunta por un SID exacto conocido.
        // Zona/tag/rango/domain/Package/Composite no se aplanan para fabricar esa exclusión.
        if (candidate.scopeKnown && compareApplicationFilter(view, candidate.filterIndex, appId, accountSid, originalImage,
                canonicalApplications) == QNameMatch::No) continue;
        result.interferingCandidates.push_back(other);
    }
    if (!result.interferingCandidates.isEmpty()) {
        result.reason = "An equal, higher or unknown source weight may interfere with this application scope";
        return result;
    }
    result.representable = true; result.action = selected.action; result.direction = selected.direction.value;
    result.reason = "Source scope comparison matches; original live selector and explicit consent are still required";
    return result;
}
namespace {
// Sólo prueba disyunción del intervalo completo. Un punto de conexión no acredita
// equivalencia de toda la regla; zona, tags, negaciones y Composite quedan Unknown.
QNameMatch compareConditionalFilter(const QNameProfileView &view, int index, quint32 first, quint32 last,
    const QByteArray &appId, const QByteArray &sid, const QString &image,
    const QMap<int, QByteArray> &canonical) {
    if (index < 0 || index >= view.filters.size()) return QNameMatch::Unknown;
    const auto &f = view.filters[index];
    if (!f.conjunctionKnown || !f.baseFilters.isEmpty() || f.package.node >= 0 ||
        !f.filterType.known() || (f.filterType.value != "Filter" && f.filterType.value != "Zone") ||
        f.predicates.isEmpty()) return QNameMatch::Unknown;
    for (const auto &p : f.predicates) {
        if (p.kind == "FFAppIdEqual") {
            if (compareApplicationPredicate(p, appId, sid, image, canonical) == QNameMatch::No)
                return QNameMatch::No;
        } else if (p.kind == "FFRemoteAddressInRange" && p.complete && p.match.known() && p.match.value &&
                   !p.remoteRanges.isEmpty()) {
            bool disjoint = true;
            for (const auto &range : p.remoteRanges) {
                if (!range.first.known() || !range.last.known() || range.first.value > range.last.value)
                    return QNameMatch::Unknown;
                disjoint = disjoint && (last < range.first.value || range.last.value < first);
            }
            if (disjoint) return QNameMatch::No;
        }
    }
    return QNameMatch::Unknown;
}
}
QNameConditionalComparison compareQNameConditionalScope(const QNameEvidence &original, const QString &candidateId,
    const QByteArray &appId, const QByteArray &accountSid, const QString &originalImage,
    const QMap<int, QByteArray> &canonicalApplications, const ImportLimits &limits) {
    QNameConditionalComparison result;
    result.reason = "Original conditional source is incomplete or unsupported";
    const auto view = deriveQNameProfile(original, limits);
    if (!view.valid || !view.profileKnown || candidateId.isEmpty()) return result;
    int index = -1;
    for (int i = 0; i < view.candidates.size(); ++i) if (view.candidates[i].candidateId == candidateId) {
        if (index >= 0) return result;
        index = i;
    }
    if (index < 0) return result;
    const auto &selected = view.candidates[index];
    result.candidate = selected; result.sourceOrdinal = index;
    const auto actionReason = actionReviewReason(selected);
    if (!actionReason.isEmpty()) { result.reason = actionReason; return result; }
    if (selected.filterIndex < 0 || selected.filterIndex >= view.filters.size()) return result;
    const auto &filter = view.filters[selected.filterIndex];
    result.filterId = filter.id;
    const auto membershipReason = membershipReviewReason(filter);
    if (!membershipReason.isEmpty()) { result.reason = membershipReason; return result; }
    if (!filter.baseFilters.isEmpty() || filter.package.node >= 0 || !filter.filterType.known() ||
        filter.filterType.value != "Filter" || filter.predicates.size() != 2) return result;
    const QNamePredicate *application = nullptr, *remote = nullptr;
    for (const auto &p : filter.predicates) {
        if (!p.match.known() || !p.match.value) return result;
        if (p.kind == "FFAppIdEqual" && !application && p.applications.size() == 1) application = &p;
        else if (p.kind == "FFRemoteAddressInRange" && !remote && p.remoteRanges.size() == 1) remote = &p;
        else return result;
    }
    if (!application || !remote) return result;
    result.application = application->applications[0]; result.range = remote->remoteRanges[0];
    if (!view.diagnosticsComplete) {
        result.reason = result.application.sidExplicitNil.known() && result.application.sidExplicitNil.value ?
            "Original AppId has explicit nil SID; its principal scope is unknown and diagnostics are incomplete" :
            "Original source diagnostics are incomplete; precedence requires review";
        return result;
    }
    if (!remote->complete || !result.range.first.known() || !result.range.last.known() ||
        result.range.first.value > result.range.last.value) return result;
    // Se conserva todo posible competidor antes de rechazar el principal. Nunca
    // se resuelve un empate mediante índice, orden XML ni ordinal de WFP.
    for (int other = 0; other < view.candidates.size(); ++other) {
        if (other == index) continue;
        const auto &c = view.candidates[other];
        if (c.kind == "limitRule" || (c.enabled.known() && !c.enabled.value)) continue;
        if (c.kind != "fwRule") {
            result.closureCandidates.push_back(c.candidateId);
            result.interferingCandidates.push_back(c.candidateId);
            continue;
        }
        if (selected.direction.known() && selected.direction.value != Direction::Unknown &&
            c.direction.known() && c.direction.value != Direction::Unknown &&
            selected.direction.value != Direction::Both && c.direction.value != Direction::Both &&
            selected.direction.value != c.direction.value) continue;
        if (selected.weight.known() && c.weight.known() && c.weight.value < selected.weight.value) continue;
        result.closureCandidates.push_back(c.candidateId);
        if (!c.scopeKnown || compareConditionalFilter(view, c.filterIndex,
            result.range.first.value, result.range.last.value, appId, accountSid, originalImage,
            canonicalApplications) != QNameMatch::No) result.interferingCandidates.push_back(c.candidateId);
    }
    if (result.application.sidExplicitNil.known() && result.application.sidExplicitNil.value) {
        result.reason = "Original AppId has explicit nil SID; its principal scope is unknown";
        return result;
    }
    if (!selected.complete || !selected.scopeKnown || selected.kind != "fwRule" || !selected.enabled.known() || !selected.enabled.value ||
        !selected.weight.known() || selected.weight.value < 0 || !selected.action.known() ||
        (selected.action.value != SourceFwAction::Allow && selected.action.value != SourceFwAction::Deny) ||
        !selected.direction.known() || selected.direction.value != Direction::Out || !filter.complete || !filter.conjunctionKnown ||
        !applicationSidShape(accountSid) || appId.size() < 4 || appId.size() > 8192 || (appId.size() & 1) ||
        appId[appId.size()-1] != 0 || appId[appId.size()-2] != 0 || originalImage.isEmpty() ||
        result.application.packageId.node >= 0 || result.application.serviceName.node >= 0 ||
        compareApplicationPredicate(*application, appId, accountSid, originalImage, canonicalApplications) != QNameMatch::Yes)
        return result;
    if (!result.interferingCandidates.isEmpty()) {
        result.reason = "An equal, higher or unknown source weight may overlap the original conditional scope";
        return result;
    }
    result.representable = true;
    result.reason = "Original conditional scope comparison matches; service custody and live admission are still required";
    return result;
}
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
