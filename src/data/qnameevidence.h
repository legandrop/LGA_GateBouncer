#pragma once
#include <QMap>
#include <QString>
#include <QVector>
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
    static constexpr qint64 unitLimit = 8 * 1024 * 1024;
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
            else cost += ch == '"' || ch == '\\' ? 2 : ch.unicode() < 32 || ch.unicode() >= 127 ? 6 : 1;
        }
        return structure(cost);
    }
    bool structure(qint64 cost) {
        if (!valid || cost < 0 || cost > byteLimit - jsonBound) return valid = false;
        jsonBound += cost;
        return true;
    }
};
} // namespace Gate::Data
