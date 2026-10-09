#include "StrictJson.h"
#include <QStringDecoder>
#include <limits>

namespace Gate::Assistance::Retrieval {
    std::optional<quint64> decimal(const QByteArray &s) {
        if (s.isEmpty() || s.size() > 20)
            return {};
        quint64 n = 0;
        for (char c : s) {
            if (c < '0' || c > '9' ||
                n > (std::numeric_limits<quint64>::max() - quint64(c - '0')) / 10)
                return {};
            n = n * 10 + quint64(c - '0');
        }
        return n;
    }
    const Json *Json::get(const QString &key) const {
        auto i = object.find(key);
        return kind == Kind::Object && i != object.end() ? &i->second : nullptr;
    }
    std::optional<QString> Json::text() const {
        return kind == Kind::String ? std::optional<QString>(QString::fromUtf8(scalar))
                                    : std::nullopt;
    }
    std::optional<quint64> Json::integer() const {
        return kind == Kind::Number ? decimal(scalar) : std::nullopt;
    }
    std::optional<bool> Json::boolean() const {
        return kind == Kind::Boolean ? std::optional<bool>(scalar == "true") : std::nullopt;
    }
    bool Json::exact(const std::vector<QString> &keys) const {
        if (kind != Kind::Object || object.size() != keys.size())
            return false;
        for (const auto &k : keys)
            if (!get(k))
                return false;
        return true;
    }
    class Reader {
        const QByteArray &b;
        qsizetype p = 0;
        int tokens = 0, arrays = 0;
        void space() {
            while (p < b.size() && (b[p] == ' ' || b[p] == '\t' || b[p] == '\r' || b[p] == '\n'))
                ++p;
        }
        bool take(char c) {
            if (p < b.size() && b[p] == c) {
                ++p;
                return true;
            }
            return false;
        }
        std::optional<ushort> hex() {
            if (b.size() - p < 4)
                return {};
            ushort n = 0;
            for (int i = 0; i < 4; ++i) {
                char c = b[p++];
                int d = c >= '0' && c <= '9'   ? c - '0'
                        : c >= 'a' && c <= 'f' ? c - 'a' + 10
                        : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                               : -1;
                if (d < 0)
                    return {};
                n = ushort(n * 16 + d);
            }
            return n;
        }
        std::optional<QByteArray> string() {
            if (!take('"'))
                return {};
            QByteArray out;
            while (p < b.size()) {
                unsigned char c = static_cast<unsigned char>(b[p++]);
                if (c == '"')
                    return out;
                if (c < 32)
                    return {};
                if (c != '\\') {
                    out.append(char(c));
                    continue;
                }
                if (p == b.size())
                    return {};
                const char e = b[p++];
                switch (e) {
                case '"':
                case '\\':
                case '/':
                    out.append(e);
                    break;
                case 'b':
                    out.append('\b');
                    break;
                case 'f':
                    out.append('\f');
                    break;
                case 'n':
                    out.append('\n');
                    break;
                case 'r':
                    out.append('\r');
                    break;
                case 't':
                    out.append('\t');
                    break;
                case 'u': {
                    auto u = hex();
                    if (!u)
                        return {};
                    QString s;
                    if (*u >= 0xd800 && *u <= 0xdbff) {
                        if (!take('\\') || !take('u'))
                            return {};
                        auto low = hex();
                        if (!low || *low < 0xdc00 || *low > 0xdfff)
                            return {};
                        s.append(QChar(*u));
                        s.append(QChar(*low));
                    } else {
                        if (*u >= 0xdc00 && *u <= 0xdfff)
                            return {};
                        s.append(QChar(*u));
                    }
                    out.append(s.toUtf8());
                    break;
                }
                default:
                    return {};
                }
            }
            return {};
        }
        std::optional<Json> value(int depth) {
            if (depth > 12 || ++tokens > 16384)
                return {};
            space();
            if (p == b.size())
                return {};
            Json n;
            if (b[p] == '"') {
                auto s = string();
                if (!s)
                    return {};
                n.kind = Json::Kind::String;
                n.scalar = std::move(*s);
                return n;
            }
            if (take('{')) {
                n.kind = Json::Kind::Object;
                space();
                if (take('}'))
                    return n;
                do {
                    space();
                    if (++tokens > 16384)
                        return {};
                    auto k = string();
                    if (!k)
                        return {};
                    const QString key = QString::fromUtf8(*k);
                    space();
                    if (!take(':') || n.object.count(key))
                        return {};
                    auto v = value(depth + 1);
                    if (!v)
                        return {};
                    n.object.emplace(key, std::move(*v));
                    space();
                    if (take('}'))
                        return n;
                } while (take(','));
                return {};
            }
            if (take('[')) {
                n.kind = Json::Kind::Array;
                space();
                if (take(']'))
                    return n;
                do {
                    if (++arrays > 256)
                        return {};
                    auto v = value(depth + 1);
                    if (!v)
                        return {};
                    n.array.push_back(std::move(*v));
                    space();
                    if (take(']'))
                        return n;
                } while (take(','));
                return {};
            }
            for (const auto &literal :
                 {QByteArray("true"), QByteArray("false"), QByteArray("null")})
                if (b.mid(p, literal.size()) == literal) {
                    p += literal.size();
                    n.kind = literal == "null" ? Json::Kind::Null : Json::Kind::Boolean;
                    n.scalar = literal;
                    return n;
                }
            const qsizetype start = p;
            take('-');
            if (take('0')) {
                if (p < b.size() && b[p] >= '0' && b[p] <= '9')
                    return {};
            } else {
                if (p == b.size() || b[p] < '1' || b[p] > '9')
                    return {};
                while (p < b.size() && b[p] >= '0' && b[p] <= '9')
                    ++p;
            }
            if (take('.')) {
                const auto at = p;
                while (p < b.size() && b[p] >= '0' && b[p] <= '9')
                    ++p;
                if (p == at)
                    return {};
            }
            if (take('e') || take('E')) {
                if (!take('+'))
                    take('-');
                const auto at = p;
                while (p < b.size() && b[p] >= '0' && b[p] <= '9')
                    ++p;
                if (at == p)
                    return {};
            }
            n.kind = Json::Kind::Number;
            n.scalar = b.mid(start, p - start);
            return n;
        }

      public:
        explicit Reader(const QByteArray &bytes) : b(bytes) {}
        std::optional<Json> read() {
            auto n = value(0);
            space();
            return p == b.size() ? n : std::nullopt;
        }
    };
    std::optional<Json> strictJson(const QByteArray &bytes, qsizetype limit) {
        if (bytes.isEmpty() || bytes.size() > limit || bytes.contains('\0'))
            return {};
        QStringDecoder utf8(QStringDecoder::Utf8);
        const QString decoded = utf8(bytes);
        Q_UNUSED(decoded);
        if (utf8.hasError())
            return {};
        return Reader(bytes).read();
    }
} // namespace Gate::Assistance::Retrieval
