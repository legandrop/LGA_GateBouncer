#pragma once
#include <QMap>
#include <QString>
#include <QVector>
#include <initializer_list>
#include <optional>

namespace Gate::Data {
struct ExpandedName {
    QString uri, local;
    bool operator==(const ExpandedName &b) const { return uri == b.uri && local == b.local; }
    bool operator!=(const ExpandedName &b) const { return !(*this == b); }
};
struct NamespaceBinding { QString prefix, uri; };
struct QNameAttribute { ExpandedName name; QString qualifiedName, value; };
struct QNameContent { int child = -1; QString text; };
struct QNameNode {
    ExpandedName name;
    QString qualifiedName;
    QVector<QNameAttribute> attributes;
    QVector<NamespaceBinding> declarations, closure;
    QVector<QNameContent> content;
    std::optional<ExpandedName> resolvedType;
    int ordinal = 0;
};
struct QNameRowBinding { QString candidateId; int node = -1; };
struct QNameEvidence {
    QString profileId, digest;
    QVector<QNameNode> nodes;
    QVector<int> roles;
    QVector<QNameRowBinding> rows;
    int excludedRootSections = 0;
};
// Cuenta apariciones serializadas, aunque QString comparta memoria.
struct QNameBudget {
    qint64 units = 0, jsonBound = 0;
    bool valid = true;
    // Incluye también keys repetidas del JSON; bytes/tokens/filas conservan sus cotas.
    static constexpr qint64 unitLimit = 16 * 1024 * 1024;
    static constexpr qint64 byteLimit = 32 * 1024 * 1024;
    bool string(const QString &value) {
        if (!valid || value.size() > 32768 || value.size() > unitLimit - units) return valid = false;
        units += value.size();
        qint64 cost = 2;
        for (qsizetype i = 0; i < value.size(); ++i) {
            const auto ch = value[i];
            if (ch.isHighSurrogate()) {
                if (++i >= value.size() || !value[i].isLowSurrogate()) return valid = false;
                cost += 12;
            } else if (ch.isLowSurrogate()) return valid = false;
            else cost += jsonUnitBytes(ch.unicode());
        }
        return structure(cost);
    }
    bool structure(qint64 cost) {
        if (!valid || cost < 0 || cost > byteLimit - jsonBound) return valid = false;
        jsonBound += cost;
        return true;
    }
    // Escapes cortos reales; se conserva la cota Unicode de seis bytes por unidad UTF-16.
    static qint64 jsonUnitBytes(ushort c) {
        if (c == '"' || c == '\\' || c == 8 || c == 9 || c == 10 || c == 12 || c == 13) return 2;
        if (c < 32) return 6;
        return c < 127 ? 1 : 6;
    }
    bool object(std::initializer_list<const char *> keys) {
        for (const auto key : keys) if (!string(QString::fromLatin1(key))) return false;
        return structure(keys.size() ? qint64(keys.size()) * 2 + 1 : 2);
    }
    bool array(qsizetype count) { return count >= 0 && structure(2 + (count ? count - 1 : 0)); }
    bool number(int value) { return structure(QString::number(value).size()); }
};
// Una sola descripción del JSON de evidencia, compartida por lectura, validación y guardado.
inline bool budgetQNameName(QNameBudget &b, const ExpandedName &n) {
    return b.object({"uri", "local"}) && b.string(n.uri) && b.string(n.local);
}
inline bool budgetQNameNode(QNameBudget &b, const QNameNode &n) {
    if (!b.object({"name", "qualifiedName", "ordinal", "attributes", "declarations", "closure", "content", "resolvedType"}) ||
        !budgetQNameName(b, n.name) || !b.string(n.qualifiedName) || !b.number(n.ordinal) ||
        !b.array(n.attributes.size()) || !b.array(n.declarations.size()) || !b.array(n.closure.size()) || !b.array(n.content.size())) return false;
    if (n.resolvedType ? !budgetQNameName(b, *n.resolvedType) : !b.structure(4)) return false;
    for (const auto &a : n.attributes)
        if (!b.object({"name", "qualifiedName", "value"}) || !budgetQNameName(b, a.name) ||
            !b.string(a.qualifiedName) || !b.string(a.value)) return false;
    for (const auto *bindings : {&n.declarations, &n.closure}) for (const auto &d : *bindings)
        if (!b.object({"prefix", "uri"}) || !b.string(d.prefix) || !b.string(d.uri)) return false;
    for (const auto &c : n.content)
        if (!b.object({"child", "text"}) || !b.number(c.child) || !b.string(c.text)) return false;
    return true;
}
inline bool budgetQNameEvidence(QNameBudget &b, const QNameEvidence &e) {
    if (!b.object({"profileId", "digest", "nodes", "roles", "rows", "excludedRootSections"}) ||
        !b.string(e.profileId) || !b.string(e.digest) || !b.number(e.excludedRootSections) ||
        !b.array(e.nodes.size()) || !b.array(e.roles.size()) || !b.array(e.rows.size())) return false;
    for (const auto &n : e.nodes) if (!budgetQNameNode(b, n)) return false;
    for (int role : e.roles) if (!b.number(role)) return false;
    for (const auto &r : e.rows)
        if (!b.object({"candidateId", "node"}) || !b.string(r.candidateId) || !b.number(r.node)) return false;
    return true;
}
} // namespace Gate::Data
