#include "qnamexmlreader.h"
#include <QCryptographicHash>
#include <QSet>
#include <QXmlStreamReader>
#include <QUuid>
#include <functional>

namespace Gate::Data {
namespace {
const QString xsi = QStringLiteral("http://www.w3.org/2001/XMLSchema-instance");
const QString xml = QStringLiteral("http://www.w3.org/XML/1998/namespace");
thread_local QNameReadDiagnostic lastDiagnostic;
bool ncName(const QString &value) {
    if (value.isEmpty()) return false;
    bool first = true;
    for (qsizetype i = 0; i < value.size(); ++i) {
        uint c = value[i].unicode();
        if (value[i].isHighSurrogate()) {
            if (++i >= value.size() || !value[i].isLowSurrogate()) return false;
            c = QChar::surrogateToUcs4(value[i - 1], value[i]);
        } else if (value[i].isLowSurrogate()) return false;
        const bool start = c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= 0xc0 && c <= 0xd6) || (c >= 0xd8 && c <= 0xf6) || (c >= 0xf8 && c <= 0x2ff) ||
            (c >= 0x370 && c <= 0x37d) || (c >= 0x37f && c <= 0x1fff) || (c >= 0x200c && c <= 0x200d) ||
            (c >= 0x2070 && c <= 0x218f) || (c >= 0x2c00 && c <= 0x2fef) || (c >= 0x3001 && c <= 0xd7ff) ||
            (c >= 0xf900 && c <= 0xfdcf) || (c >= 0xfdf0 && c <= 0xfffd) || (c >= 0x10000 && c <= 0xeffff);
        if (!start && (first || !(c == '-' || c == '.' || (c >= '0' && c <= '9') || c == 0xb7 ||
            (c >= 0x300 && c <= 0x36f) || (c >= 0x203f && c <= 0x2040)))) return false;
        first = false;
    }
    return true;
}
QString prefix(const QString &qualified) { return qualified.contains(':') ? qualified.section(':', 0, 0) : QString{}; }
QMap<QString, QString> initial() { return {{QStringLiteral("xml"), xml}}; }
bool declarations(const QVector<NamespaceBinding> &decl, QMap<QString, QString> &env) {
    QSet<QString> seen;
    for (const auto &d : decl) {
        if (seen.contains(d.prefix) || (!d.prefix.isEmpty() && (d.prefix.contains(':') ||
            !resolveQName(d.prefix, {}).has_value())) || d.prefix == "xmlns" ||
            (d.prefix == "xml" && d.uri != xml) || (d.prefix != "xml" && d.uri == xml) ||
            (!d.prefix.isEmpty() && d.uri.isEmpty())) return false;
        seen.insert(d.prefix); env[d.prefix] = d.uri;
    }
    return true;
}
bool nodeNames(const QNameNode &n, const QMap<QString, QString> &env) {
    if (n.qualifiedName != n.qualifiedName.trimmed() || resolveQName(n.qualifiedName, env) != std::optional<ExpandedName>(n.name)) return false;
    QSet<QString> attributes;
    std::optional<ExpandedName> type;
    for (const auto &a : n.attributes) {
        const auto resolved = resolveQName(a.qualifiedName, a.qualifiedName.contains(':') ? env : initial());
        const QString key = QString::number(a.name.uri.size()) + ':' + a.name.uri + a.name.local;
        if (a.qualifiedName != a.qualifiedName.trimmed() || !resolved || *resolved != a.name || attributes.contains(key)) return false;
        attributes.insert(key);
        if (a.name == ExpandedName{xsi, "type"}) type = resolveQName(a.value, env);
    }
    return type == n.resolvedType;
}
void uses(const QNameNode &n, const QSet<QString> &local, const QMap<QString, QString> &ancestor,
          QMap<QString, QString> &needed) {
    auto add = [&](const QString &p) {
        if (!local.contains(p) && p != "xml" && ancestor.contains(p) && !ancestor[p].isEmpty()) needed[p] = ancestor[p];
    };
    add(prefix(n.qualifiedName));
    for (const auto &a : n.attributes) {
        if (a.qualifiedName.contains(':')) add(prefix(a.qualifiedName));
        if (a.name == ExpandedName{xsi, "type"} && resolveQName(a.value, ancestor)) add(prefix(a.value.trimmed()));
    }
}
} // namespace
std::optional<ExpandedName> resolveQName(const QString &lexical, const QMap<QString, QString> &bindings) {
    qsizetype first = 0, last = lexical.size();
    const auto white = [](QChar c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (first < last && white(lexical[first])) ++first;
    while (last > first && white(lexical[last - 1])) --last;
    const QString value = lexical.mid(first, last - first);
    const auto parts = value.split(':');
    if (parts.size() > 2 || !ncName(parts.last()) ||
        (parts.size() == 2 && (!ncName(parts.first()) || !bindings.contains(parts.first())))) return {};
    return ExpandedName{bindings.value(parts.size() == 2 ? parts.first() : QString{}), parts.last()};
}
QVector<int> qnameChildren(const QNameNode &node) {
    QVector<int> result;
    for (const auto &c : node.content) if (c.child >= 0) result.push_back(c.child);
    return result;
}
QString qnameCandidateId(const QNameEvidence &evidence, int node) {
    if (node < 0 || node >= evidence.nodes.size()) return {};
    const QUuid scope(QStringLiteral("b7a5f9d2-758d-4ca1-9258-21914e5f1ab8"));
    return QUuid::createUuidV5(scope, (evidence.digest + ':' + QString::number(evidence.nodes[node].ordinal)).toUtf8()).toString(QUuid::WithoutBraces);
}
QNameReadDiagnostic lastQNameReadDiagnostic() noexcept { return lastDiagnostic; }
QNameReadResult readQNameXml(const QByteArray &bytes, const ImportLimits &limits) {
    lastDiagnostic = {};
    QNameReadResult result;
    if (bytes.size() > limits.bytes || limits.depth < 1 || limits.elements < 1) { result.error = "XmlBounds"; return result; }
    QXmlStreamReader reader(bytes);
    reader.setNamespaceProcessing(true);
    reader.setEntityExpansionLimit(64);
    QVector<int> stack;
    QVector<QMap<QString, QString>> environments;
    QNameBudget budget;
    qint64 textChunks = 0;
    int roots = 0;
    while (!reader.atEnd()) {
        const auto token = reader.readNext();
        if (token == QXmlStreamReader::DTD || token == QXmlStreamReader::EntityReference) { result.error = "XmlEntityRejected"; break; }
        if (token == QXmlStreamReader::StartElement) {
            if (stack.size() >= limits.depth || result.nodes.size() >= limits.elements ||
                reader.attributes().size() + reader.namespaceDeclarations().size() > limits.attributes) { result.error = "XmlBounds"; break; }
            if (stack.isEmpty() && ++roots > 1) { result.error = "XmlRoot"; break; }
            auto env = environments.isEmpty() ? initial() : environments.last();
            QNameNode n;
            n.ordinal = result.nodes.size(); n.name = {reader.namespaceUri().toString(), reader.name().toString()};
            n.qualifiedName = reader.qualifiedName().toString();
            for (const auto &d : reader.namespaceDeclarations()) n.declarations.push_back({d.prefix().toString(), d.namespaceUri().toString()});
            if (!declarations(n.declarations, env)) { result.error = "XmlNamespaces"; break; }
            for (const auto &a : reader.attributes()) {
                n.attributes.push_back({{a.namespaceUri().toString(), a.name().toString()}, a.qualifiedName().toString(), a.value().toString()});
                if (a.namespaceUri() == xsi && a.name() == "type") n.resolvedType = resolveQName(a.value().toString(), env);
            }
            if (!nodeNames(n, env)) { result.error = "XmlNamesOrBudget"; break; }
            const int index = result.nodes.size();
            if (!stack.isEmpty()) {
                result.nodes[stack.last()].content.push_back({index, {}});
            }
            result.nodes.push_back(std::move(n)); stack.push_back(index); environments.push_back(std::move(env));
        } else if (token == QXmlStreamReader::Characters && !stack.isEmpty()) {
            const QString text = reader.text().toString();
            auto &content = result.nodes[stack.last()].content;
            ++textChunks;
            const auto prior = budget;
            auto failure = [&](QNameReadGuard guard) {
                auto &d = result.diagnostic;
                d.guard = guard; d.textUnits = text.size(); d.textLimit = limits.text;
                d.unitsBefore = prior.units; d.unitsAfter = budget.units;
                d.jsonBefore = prior.jsonBound; d.jsonAfter = budget.jsonBound;
                d.nodes = result.nodes.size(); d.contentItems = content.size(); d.textChunks = textChunks;
                d.mergedUnits = !content.isEmpty() && content.last().child < 0 ? content.last().text.size() : 0;
                d.contentCharge = 0; lastDiagnostic = d;
            };
            if (text.size() > limits.text) {
                failure(QNameReadGuard::TextUnits); result.error = "XmlTextBudget"; break;
            }
            if (!content.isEmpty() && content.last().child < 0) {
                if (content.last().text.size() + text.size() > limits.text) {
                    failure(QNameReadGuard::MergedTextUnits); result.error = "XmlTextBounds"; break;
                }
                content.last().text += text;
            } else content.push_back({-1, text});
        } else if (token == QXmlStreamReader::EndElement) {
            // Se cobra la representación final: CDATA/Characters contiguos forman un solo item.
            if (!budgetQNameNode(budget, result.nodes[stack.last()])) { result.error = "XmlBudget"; break; }
            stack.removeLast(); environments.removeLast();
        }
    }
    if (result.error.isEmpty() && !reader.hasError() && !budget.array(result.nodes.size())) result.error = "XmlBudget";
    if (reader.hasError() || roots != 1 || !stack.isEmpty()) result.error = result.error.isEmpty() ? "XmlMalformed" : result.error;
    result.accepted = result.error.isEmpty();
    if (!result.accepted) result.nodes.clear();
    return result;
}
bool projectQNameRoles(const QVector<QNameNode> &input, QNameEvidence &evidence) {
    if (input.isEmpty() || input.size() > 200000 || input[0].name != ExpandedName{"nlsettings", "NLSvcSettings"}) return false;
    auto ancestor = initial();
    if (!declarations(input[0].declarations, ancestor)) return false;
    QSet<QString> roles;
    QSet<int> copied;
    bool safe = true;
    for (int source : qnameChildren(input[0])) {
        if (source < 0 || source >= input.size()) return false;
        const auto &role = input[source];
        if (role.name.uri != "nlsettings" || !QStringList{"Version", "Rules", "Filters", "AppInfos"}.contains(role.name.local)) { ++evidence.excludedRootSections; continue; }
        if (roles.contains(role.name.local) && role.name.local != "Version") return false;
        roles.insert(role.name.local);
        QMap<QString, QString> needed;
        std::function<int(int, QSet<QString>, int)> copy = [&](int i, QSet<QString> local, int depth) {
            if (i < 0 || i >= input.size() || copied.contains(i) || depth > 32) { safe = false; return -1; }
            copied.insert(i);
            QNameNode n = input[i];
            for (const auto &d : n.declarations) local.insert(d.prefix);
            uses(n, local, ancestor, needed);
            const int dest = evidence.nodes.size();
            n.content.clear(); evidence.nodes.push_back(n);
            for (const auto &c : input[i].content) {
                QNameContent out = c;
                if (c.child >= 0) out.child = copy(c.child, local, depth + 1);
                evidence.nodes[dest].content.push_back(out);
            }
            return dest;
        };
        const int dest = copy(source, {}, 1);
        if (!safe) return false;
        for (auto it = needed.begin(); it != needed.end(); ++it) evidence.nodes[dest].closure.push_back({it.key(), it.value()});
        evidence.roles.push_back(dest);
    }
    return true;
}
bool validateQNameEvidence(const QNameEvidence &e, const ImportLimits &limits) {
    if (e.profileId != "NetLimiter-5.2.10-DCS-21" || e.digest.size() != 64 || e.nodes.size() > limits.elements ||
        e.rows.size() > limits.rules || e.roles.size() > limits.elements || e.excludedRootSections < 0 || e.excludedRootSections > limits.elements) return false;
    for (const auto ch : e.digest) if (!QStringLiteral("0123456789abcdef").contains(ch)) return false;
    QVector<bool> visited(e.nodes.size(), false);
    QNameBudget budget;
    if (!budgetQNameEvidence(budget, e)) return false;
    QSet<QString> roleNames, ids;
    QSet<int> ruleNodes;
    std::function<bool(int, int, QMap<QString, QString>, QSet<QString>, const QMap<QString, QString> &, QMap<QString, QString> &)> visit;
    visit = [&](int i, int depth, QMap<QString, QString> env, QSet<QString> local,
                const QMap<QString, QString> &closure, QMap<QString, QString> &needed) {
        if (i < 0 || i >= e.nodes.size() || visited[i] || depth > limits.depth) return false;
        visited[i] = true;
        const auto &n = e.nodes[i];
        if (n.ordinal < 0 || n.attributes.size() + n.declarations.size() > limits.attributes ||
            (depth > 1 && !n.closure.isEmpty()) || !declarations(n.declarations, env)) return false;
        for (const auto &d : n.declarations) local.insert(d.prefix);
        uses(n, local, closure, needed);
        if (!nodeNames(n, env)) return false;
        const auto childCount = qnameChildren(n).size();
        if ((n.name == ExpandedName{"nlsettings", "FunctionList"} && childCount > limits.functions) ||
            (n.name == ExpandedName{"nlsettings", "Values"} && childCount > limits.values)) return false;
        for (const auto &c : n.content) {
            if (c.child < -1 || (c.child >= 0 && !c.text.isEmpty()) || c.text.size() > limits.text) return false;
            if (c.child >= 0 && !visit(c.child, depth + 1, env, local, closure, needed)) return false;
        }
        return true;
    };
    int dependencies = 0;
    for (int i : e.roles) {
        if (i < 0 || i >= e.nodes.size()) return false;
        const auto &n = e.nodes[i];
        if (n.name.uri != "nlsettings" || !QStringList{"Version", "Rules", "Filters", "AppInfos"}.contains(n.name.local) ||
            (roleNames.contains(n.name.local) && n.name.local != "Version")) return false;
        roleNames.insert(n.name.local);
        if (n.name.local == "Filters" || n.name.local == "AppInfos") dependencies += qnameChildren(n).size();
        if (dependencies > limits.dependencies || (n.name.local == "Rules" && qnameChildren(n).size() > limits.rules)) return false;
        auto env = initial();
        if (!declarations(n.closure, env)) return false;
        QMap<QString, QString> expected, actual;
        for (const auto &b : n.closure) actual[b.prefix] = b.uri;
        if (!visit(i, 1, env, {}, env, expected) || expected != actual) return false;
        if (n.name.local == "Rules") for (int child : qnameChildren(n))
            if (e.nodes[child].name == ExpandedName{"nlsettings", "rule"}) ruleNodes.insert(child);
    }
    for (bool v : visited) if (!v) return false;
    QSet<int> bound;
    for (const auto &row : e.rows) {
        if (ids.contains(row.candidateId) || bound.contains(row.node) || !ruleNodes.contains(row.node) ||
            row.candidateId != qnameCandidateId(e, row.node)) return false;
        ids.insert(row.candidateId); bound.insert(row.node);
    }
    return bound == ruleNodes;
}
} // namespace Gate::Data
