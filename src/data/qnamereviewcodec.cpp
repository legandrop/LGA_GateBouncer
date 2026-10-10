#include "qnamereviewcodec.h"
#include "netlimiterxmlprofile.h"
#include <QJsonArray>
#include <QSet>
#include <QUuid>
#include <functional>
#include <cctype>

namespace Gate::Data {
namespace {
int dispatchSchema(const QByteArray &bytes) {
    // Dispatch sin cuotas/validacion nueva para schema1: su parser y validator siguen mandando.
    int depth = 0, schema = -1;
    for (qsizetype at = 0; at < bytes.size(); ++at) {
        const char c = bytes[at];
        if (c == '{' || c == '[') { ++depth; continue; }
        if (c == '}' || c == ']') { --depth; continue; }
        if (c != '"') continue;
        QString key;
        bool small = depth == 1;
        while (++at < bytes.size() && bytes[at] != '"') {
            uchar value = uchar(bytes[at]);
            if (value == '\\') {
                if (++at >= bytes.size()) return schema;
                value = uchar(bytes[at]);
                if (value == 'u') {
                    uint number = 0;
                    for (int j = 0; j < 4; ++j) {
                        if (++at >= bytes.size()) return schema;
                        const int digit = QByteArray("0123456789abcdef").indexOf(char(std::tolower(uchar(bytes[at]))));
                        if (digit < 0) { small = false; break; }
                        number = number * 16 + uint(digit);
                    }
                    if (number > 127) small = false;
                    value = uchar(number);
                }
            }
            if (small) { if (key.size() < 64) key += QChar(value); else small = false; }
        }
        if (!small || key != "schemaVersion") continue;
        auto next = at + 1;
        while (next < bytes.size() && QByteArray(" \r\n\t").contains(bytes[next])) ++next;
        if (next >= bytes.size() || bytes[next++] != ':') continue;
        while (next < bytes.size() && QByteArray(" \r\n\t").contains(bytes[next])) ++next;
        const auto start = next;
        while (next < bytes.size() && !QByteArray(",} \r\n\t").contains(bytes[next])) ++next;
        bool ok = false;
        const auto value = next - start <= 64 ? bytes.mid(start, next - start).toDouble(&ok) : -1;
        schema = ok && value >= 0 && value <= 2147483647 && value == int(value) ? int(value) : -1;
    }
    return schema;
}
struct Scanner {
    const QByteArray &bytes;
    qsizetype at = 0;
    int schema = -1, versions = 0, tokens = 0;
    qint64 units = 0, bound = 0;
    bool budget = true;
    void space() { while (at < bytes.size() && QByteArray(" \n\r\t").contains(bytes[at])) ++at; }
    bool take(char c) { space(); if (at >= bytes.size() || bytes[at] != c) return false; ++at; return true; }
    void charge(qint64 u, qint64 b) {
        units += u; bound += b;
        if (u > 32768 || units > QNameBudget::unitLimit || bound > QNameBudget::byteLimit || tokens > 2000000) budget = false;
    }
    bool string(QString *out = nullptr) {
        if (!take('"')) return false;
        qint64 count = 0, cost = 2;
        bool high = false;
        auto unit = [&](ushort c) {
            ++count;
            if (high && !QChar::isLowSurrogate(c)) return false;
            if (QChar::isLowSurrogate(c) && !high) return false;
            high = QChar::isHighSurrogate(c);
            if (out) out->append(QChar(c));
            cost += c == '"' || c == '\\' ? 2 : c < 32 || c >= 127 ? 6 : 1;
            return true;
        };
        while (at < bytes.size()) {
            const uchar c = uchar(bytes[at++]);
            if (c == '"') { if (high) return false; charge(count, cost); return true; }
            if (c < 32) return false;
            if (c == '\\') {
                if (at >= bytes.size()) return false;
                const char esc = bytes[at++];
                if (esc == 'u') {
                    uint value = 0;
                    for (int i = 0; i < 4; ++i) {
                        if (at >= bytes.size()) return false;
                        const char digit = bytes[at++]; const int n = QByteArray("0123456789abcdef").indexOf(char(std::tolower(uchar(digit))));
                        if (n < 0) return false;
                        value = value * 16 + uint(n);
                    }
                    if (!unit(ushort(value))) return false;
                } else {
                    const int index = QByteArray("\"\\/bfnrt").indexOf(esc);
                    if (index < 0) return false;
                    const ushort codes[] = {'"', '\\', '/', 8, 12, 10, 13, 9};
                    if (!unit(codes[index])) return false;
                }
            } else if (c < 128) { if (!unit(c)) return false; }
            else {
                const int length = c >= 0xc2 && c <= 0xdf ? 2 : c >= 0xe0 && c <= 0xef ? 3 : c >= 0xf0 && c <= 0xf4 ? 4 : 0;
                if (!length || at + length - 1 > bytes.size()) return false;
                uint value = c & (0x7f >> length);
                for (int j = 1; j < length; ++j) {
                    const uchar next = uchar(bytes[at++]); if ((next & 0xc0) != 0x80) return false;
                    value = (value << 6) | (next & 0x3f);
                }
                if (value < (length == 2 ? 0x80u : length == 3 ? 0x800u : 0x10000u) || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return false;
                if (value <= 0xffff) { if (!unit(ushort(value))) return false; }
                else { if (!unit(QChar::highSurrogate(value)) || !unit(QChar::lowSurrogate(value))) return false; }
            }
        }
        return false;
    }
    bool value(int depth, bool schemaValue = false) {
        if (depth > 80) return false;
        ++tokens; space(); if (at >= bytes.size()) return false;
        const char c = bytes[at];
        if (c == '"') return string();
        if (c == '{') {
            ++at; charge(0, 16); space(); if (take('}')) return true;
            while (true) {
                QString key; if (!string(depth == 0 ? &key : nullptr) || !take(':')) return false;
                charge(0, 4); if (!value(depth + 1, depth == 0 && key == "schemaVersion")) return false;
                if (take('}')) return true;
                if (!take(',')) return false;
            }
        }
        if (c == '[') {
            ++at; charge(0, 16); if (take(']')) return true;
            while (true) { charge(0, 4); if (!value(depth + 1)) return false; if (take(']')) return true; if (!take(',')) return false; }
        }
        if (c == 't' || c == 'f' || c == 'n') {
            const QByteArray word = c == 't' ? "true" : c == 'f' ? "false" : "null";
            if (bytes.mid(at, word.size()) != word) return false;
            at += word.size(); charge(0, 64); return true;
        }
        const auto start = at;
        if (bytes[at] == '-') ++at;
        if (at >= bytes.size() || bytes[at] < '0' || bytes[at] > '9') return false;
        if (bytes[at] == '0') ++at;
        else while (at < bytes.size() && bytes[at] >= '0' && bytes[at] <= '9') ++at;
        if (at < bytes.size() && bytes[at] == '.') {
            const auto first = ++at; while (at < bytes.size() && bytes[at] >= '0' && bytes[at] <= '9') ++at;
            if (at == first) return false;
        }
        if (at < bytes.size() && (bytes[at] == 'e' || bytes[at] == 'E')) {
            ++at; if (at < bytes.size() && (bytes[at] == '+' || bytes[at] == '-')) ++at;
            const auto first = at; while (at < bytes.size() && bytes[at] >= '0' && bytes[at] <= '9') ++at;
            if (at == first) return false;
        }
        charge(0, 64); if (at - start > 64) budget = false;
        if (schemaValue) {
            ++versions; bool ok = false;
            const auto number = bytes.mid(start, at - start).toDouble(&ok);
            if (ok && number >= 0 && number <= 2147483647 && number == int(number)) schema = int(number);
        }
        return true;
    }
};
QJsonObject nameJson(const ExpandedName &n) { return {{"uri", n.uri}, {"local", n.local}}; }
bool nameRead(const QJsonValue &v, ExpandedName &n) {
    const auto o = v.toObject();
    if (!v.isObject() || !o["uri"].isString() || !o["local"].isString()) return false;
    n = {o["uri"].toString(), o["local"].toString()}; return true;
}
QJsonArray bindingJson(const QVector<NamespaceBinding> &bindings) {
    QJsonArray a; for (const auto &b : bindings) a.push_back(QJsonObject{{"prefix", b.prefix}, {"uri", b.uri}}); return a;
}
bool bindingRead(const QJsonValue &v, QVector<NamespaceBinding> &bindings) {
    if (!v.isArray() || v.toArray().size() > 32) return false;
    for (const auto &entry : v.toArray()) {
        const auto b = entry.toObject(); if (!entry.isObject() || !b["prefix"].isString() || !b["uri"].isString()) return false;
        bindings.push_back({b["prefix"].toString(), b["uri"].toString()});
    }
    return true;
}
bool intRead(const QJsonValue &v, int &out) {
    if (!v.isDouble() || v.toDouble() < -1 || v.toDouble() > 2147483647 || v.toDouble() != v.toInt()) return false;
    out = v.toInt(); return true;
}
// El margen fijo incluye keys, comas, contenedores y escalares del codec legacy.
bool fixed(QNameBudget &b, int keyUnits, qint64 bytes) { return b.string(QString(keyUnits, 'k')) && b.structure(bytes); }
bool strings(QNameBudget &b, std::initializer_list<QString> values) {
    for (const auto &v : values) if (!b.string(v)) return false;
    return true;
}
bool xmlBudget(QNameBudget &b, const XmlNode &n, int depth, int &nodes) {
    if (depth > 32 || ++nodes > 200000 || n.attributes.size() > 32 || !fixed(b, 40, 512) || !strings(b, {n.name, n.nameSpace, n.text})) return false;
    for (auto it = n.attributes.begin(); it != n.attributes.end(); ++it) if (!strings(b, {it.key(), it.value()}) || !b.structure(4)) return false;
    for (const auto &c : n.children) if (!xmlBudget(b, c, depth + 1, nodes)) return false;
    return true;
}
bool factBudget(QNameBudget &b, const EventFact &f) {
    return fixed(b, 32, 512) && strings(b, {f.sourceId, f.sourceEpoch, f.sequence, f.atUtc.toUTC().toString(Qt::ISODateWithMs)});
}
} // namespace
ReviewJsonPreflight scanReviewJson(const QByteArray &bytes) {
    if (bytes.size() > QNameBudget::byteLimit) return {};
    const int schema = dispatchSchema(bytes);
    if (schema != 2 && schema != 3) return {true, false, schema};
    Scanner s{bytes};
    const bool syntax = s.value(0); s.space();
    return {syntax && s.at == bytes.size() && s.versions == 1 && s.schema == schema, s.budget, s.schema};
}
bool budgetQNameReview(const ReviewDocument &d, qint64 *bound) {
    if (!d.qnameEvidence) return false;
    QNameBudget b;
    if (!fixed(b, 256, 4096) || !strings(b, {d.report.digest, d.report.sourceVersion, d.report.error}) ||
        d.report.candidates.size() > 10000 || d.report.filters.size() + d.report.identities.size() > 20000 ||
        d.history.events.size() > 4096 || d.history.coverage.size() > 128 || d.history.subjects.size() > 20000 || d.history.ruleHits.size() > 20000) return false;
    int nodes = 0;
    for (const auto &c : d.report.candidates) {
        if (!fixed(b, 200, 2048) || !strings(b, {c.id, c.sourceId, c.sourceType, directionName(c.direction)}) ||
            !xmlBudget(b, c.source, 1, nodes)) return false;
        if (c.action && !b.string(actionName(*c.action))) return false;
        if (c.reviewAction && !b.string(actionName(*c.reviewAction))) return false;
        for (const auto &s : c.diagnostics) if (!b.string(s) || !b.structure(4)) return false;
    }
    for (const auto *list : {&d.report.filters, &d.report.identities}) for (const auto &n : *list) if (!xmlBudget(b, n, 1, nodes)) return false;
    for (const auto &s : d.report.diagnostics) if (!b.string(s) || !b.structure(4)) return false;
    const auto &e = *d.qnameEvidence;
    if (!fixed(b, 64, 512) || !strings(b, {e.profileId, e.digest}) || e.nodes.size() > 200000) return false;
    for (const auto &n : e.nodes) {
        if (!fixed(b, 128, 512) || !strings(b, {n.name.uri, n.name.local, n.qualifiedName}) || n.attributes.size() + n.declarations.size() > 32) return false;
        if (n.resolvedType && (!fixed(b, 8, 64) || !strings(b, {n.resolvedType->uri, n.resolvedType->local}))) return false;
        for (const auto &a : n.attributes) if (!fixed(b, 40, 256) || !strings(b, {a.name.uri, a.name.local, a.qualifiedName, a.value})) return false;
        for (const auto *list : {&n.declarations, &n.closure}) for (const auto &a : *list) if (!fixed(b, 12, 128) || !strings(b, {a.prefix, a.uri})) return false;
        for (const auto &c : n.content) if (!fixed(b, 9, 128) || !b.string(c.text)) return false;
    }
    for (const auto &r : e.rows) if (!fixed(b, 15, 128) || !b.string(r.candidateId)) return false;
    if (!b.structure(e.roles.size() * 68ll)) return false;
    const auto eventBudget = [&](const ActivityEvent &event) {
        if (!fixed(b, 256, 4096) || !strings(b, {event.sourceId, event.sourceEpoch, event.sequence, event.subjectId, event.requestId,
            event.flowId, event.winningRuleId, event.winningRuleRevision, event.endpoint, event.protocol,
            event.observedAtUtc.toUTC().toString(Qt::ISODateWithMs), event.receivedAtUtc.toUTC().toString(Qt::ISODateWithMs)})) return false;
        if (event.action && !b.string(actionName(*event.action))) return false;
        if (event.instance && (!fixed(b, 32, 512) || !b.string(event.instance->sourceEpoch))) return false;
        if (event.native && (!fixed(b, 256, 2048) || !strings(b, {event.native->connection,
            event.native->observed, event.native->captureBinding, event.native->command}))) return false;
        if (event.native && event.native->process) {
            const auto &f = *event.native->process;
            if (!fixed(b, 256, 4096) || !strings(b, {f.image, QString::fromLatin1(f.appId.toBase64()),
                QString::fromLatin1(f.accountSid.toBase64()), QString::fromLatin1(f.logonSid.toBase64())})) return false;
        }
        return true;
    };
    for (const auto &event : d.history.events) if (!eventBudget(event)) return false;
    if (d.history.nativeAttempts.size() > 20000 || d.history.nativeAuthorizations.size() > 20000 || d.history.nativeTraffic.size() > 20000) return false;
    for (const auto &event : d.history.nativeAttempts) if (!eventBudget(event)) return false;
    for (const auto &event : d.history.nativeAuthorizations) if (!eventBudget(event)) return false;
    for (const auto &event : d.history.nativeTraffic) if (!eventBudget(event)) return false;
    for (auto it = d.history.subjects.begin(); it != d.history.subjects.end(); ++it) {
        if (!fixed(b, 64, 512) || !b.string(it.key())) return false;
        for (const auto *f : {&it->lastAttempt, &it->lastAuthorized, &it->lastTraffic}) if (*f && !factBudget(b, **f)) return false;
    }
    for (auto it = d.history.ruleHits.begin(); it != d.history.ruleHits.end(); ++it) if (!b.string(it.key()) || !factBudget(b, it.value())) return false;
    for (const auto &c : d.history.coverage) {
        if (!fixed(b, 256, 4096) || !strings(b, {c.sourceId, c.sourceEpoch, c.declaredScope, c.sinceUtc.toUTC().toString(Qt::ISODateWithMs),
            c.checkpointUtc.toUTC().toString(Qt::ISODateWithMs), c.lastObservedUtc.toUTC().toString(Qt::ISODateWithMs)}) || c.gaps.size() > 128) return false;
        if (c.native && (!fixed(b, 96, 1024) || !strings(b, {c.native->serviceEpoch, c.native->boot,
            c.native->engineContext, c.native->sourceEpoch}))) return false;
        for (const auto &gap : c.gaps) if (!fixed(b, c.native ? 96 : 32, c.native ? 1024 : 512) ||
            !strings(b, {gap.reason, gap.atUtc.toUTC().toString(Qt::ISODateWithMs)})) return false;
    }
    if (bound) *bound = b.jsonBound;
    return b.valid;
}
QJsonObject qnameEvidenceJson(const QNameEvidence &e) {
    QJsonArray nodes, roles, rows;
    for (const auto &n : e.nodes) {
        QJsonArray attrs, content;
        for (const auto &a : n.attributes) attrs.push_back(QJsonObject{{"name", nameJson(a.name)}, {"qualifiedName", a.qualifiedName}, {"value", a.value}});
        for (const auto &c : n.content) content.push_back(QJsonObject{{"child", c.child}, {"text", c.text}});
        nodes.push_back(QJsonObject{{"name", nameJson(n.name)}, {"qualifiedName", n.qualifiedName}, {"ordinal", n.ordinal},
            {"attributes", attrs}, {"declarations", bindingJson(n.declarations)}, {"closure", bindingJson(n.closure)},
            {"content", content}, {"resolvedType", n.resolvedType ? QJsonValue(nameJson(*n.resolvedType)) : QJsonValue(QJsonValue::Null)}});
    }
    for (int role : e.roles) roles.push_back(role);
    for (const auto &r : e.rows) rows.push_back(QJsonObject{{"candidateId", r.candidateId}, {"node", r.node}});
    return {{"profileId", e.profileId}, {"digest", e.digest}, {"nodes", nodes}, {"roles", roles}, {"rows", rows}, {"excludedRootSections", e.excludedRootSections}};
}
bool qnameEvidenceRead(const QJsonValue &v, QNameEvidence &e) {
    if (!v.isObject()) return false;
    const auto o = v.toObject();
    if (!o["profileId"].isString() || !o["digest"].isString() || !o["nodes"].isArray() || o["nodes"].toArray().size() > 200000 ||
        !o["roles"].isArray() || !o["rows"].isArray() || o["rows"].toArray().size() > 10000 || !intRead(o["excludedRootSections"], e.excludedRootSections)) return false;
    e.profileId = o["profileId"].toString(); e.digest = o["digest"].toString();
    for (const auto &entry : o["nodes"].toArray()) {
        const auto n = entry.toObject(); QNameNode node;
        if (!entry.isObject() || !nameRead(n["name"], node.name) || !n["qualifiedName"].isString() || !intRead(n["ordinal"], node.ordinal) ||
            !n["attributes"].isArray() || n["attributes"].toArray().size() > 32 || !n["content"].isArray() ||
            !bindingRead(n["declarations"], node.declarations) || !bindingRead(n["closure"], node.closure)) return false;
        node.qualifiedName = n["qualifiedName"].toString();
        if (!n["resolvedType"].isNull()) { ExpandedName name; if (!nameRead(n["resolvedType"], name)) return false; node.resolvedType = name; }
        for (const auto &item : n["attributes"].toArray()) {
            const auto a = item.toObject(); QNameAttribute attr;
            if (!item.isObject() || !nameRead(a["name"], attr.name) || !a["qualifiedName"].isString() || !a["value"].isString()) return false;
            attr.qualifiedName = a["qualifiedName"].toString(); attr.value = a["value"].toString(); node.attributes.push_back(attr);
        }
        for (const auto &item : n["content"].toArray()) {
            const auto c = item.toObject(); QNameContent content;
            if (!item.isObject() || !intRead(c["child"], content.child) || !c["text"].isString()) return false;
            content.text = c["text"].toString(); node.content.push_back(content);
        }
        e.nodes.push_back(std::move(node));
    }
    for (const auto &item : o["roles"].toArray()) { int i; if (!intRead(item, i)) return false; e.roles.push_back(i); }
    for (const auto &item : o["rows"].toArray()) {
        const auto r = item.toObject(); QNameRowBinding row;
        if (!item.isObject() || !r["candidateId"].isString() || !intRead(r["node"], row.node)) return false;
        row.candidateId = r["candidateId"].toString(); e.rows.push_back(row);
    }
    return validateQNameEvidence(e);
}
bool rebuildQNameReport(ReviewDocument &d) {
    if (!d.qnameEvidence || !budgetQNameReview(d)) return false;
    const auto view = deriveQNameProfile(*d.qnameEvidence);
    if (!view.valid || d.report.candidates.size() != view.candidates.size()) return false;
    QMap<QString, Candidate> choices;
    for (const auto &c : d.report.candidates) {
        if (QUuid(c.id).isNull() || QUuid(c.id).toString(QUuid::WithoutBraces) != c.id || choices.contains(c.id)) return false;
        choices[c.id] = c;
    }
    ImportReport report; report.accepted = true; report.digest = d.qnameEvidence->digest;
    report.sourceVersion = view.profileKnown ? "21" : "Unknown"; report.diagnostics = view.diagnostics;
    for (const auto &f : view.candidates) {
        if (!choices.contains(f.candidateId)) return false;
        Candidate c; c.id = f.candidateId; c.reviewed = choices[c.id].reviewed; c.reviewAction = choices[c.id].reviewAction;
        c.sourceId = f.id.known() ? f.id.value : QString{}; c.sourceType = f.kind;
        c.status = f.kind == "fwRule" ? CandidateStatus::NeedsReview : CandidateStatus::Unsupported;
        c.direction = f.direction.known() ? f.direction.value : Direction::Unknown;
        if (f.enabled.known()) c.sourceEnabled = f.enabled.value;
        if (f.weight.known()) c.sourceWeight = f.weight.value;
        c.diagnostics.push_back("InactiveUnverifiedQNameSource"); report.candidates.push_back(c);
    }
    d.report = report;
    return budgetQNameReview(d);
}
} // namespace Gate::Data
