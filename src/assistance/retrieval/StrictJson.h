#pragma once
#include <QByteArray>
#include <QString>
#include <map>
#include <optional>
#include <vector>

namespace Gate::Assistance::Retrieval {
    struct Json {
        enum class Kind { Null, Boolean, Number, String, Object, Array } kind = Kind::Null;
        QByteArray scalar;
        std::map<QString, Json> object;
        std::vector<Json> array;
        const Json *get(const QString &name) const;
        std::optional<QString> text() const;
        std::optional<quint64> integer() const;
        std::optional<bool> boolean() const;
        bool exact(const std::vector<QString> &) const;
    };
    std::optional<quint64> decimal(const QByteArray &);
    std::optional<Json> strictJson(const QByteArray &, qsizetype maxBytes = 131072);
} // namespace Gate::Assistance::Retrieval
