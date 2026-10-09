#include "Contracts.h"
#include "Catalog.h"
#include "GroundedParser.h"
#include "SourceNormalizer.h"
#include <QStringDecoder>
#include <cstring>
#include <set>
namespace Gate::Assistance::Retrieval {
    bool Binding::operator==(const Binding &b) const {
        return request == b.request && retrievalEpoch == b.retrievalEpoch &&
               catalogRevision == b.catalogRevision &&
               providerPolicyEpoch == b.providerPolicyEpoch &&
               disclosureVersion == b.disclosureVersion;
    }
    bool safeText(const QString &s, qsizetype max, bool empty) {
        if ((s.isEmpty() && !empty) || s.toUtf8().size() > max)
            return false;
        for (const auto c : s)
            if (c.category() == QChar::Other_Control || c.category() == QChar::Other_Format ||
                c.category() == QChar::Other_Surrogate || c.unicode() == 0x2028 ||
                c.unicode() == 0x2029)
                return false;
        return true;
    }
    bool validBinding(const Binding &b) {
        return b.disclosureVersion == 2 && b.retrievalEpoch &&
               b.catalogRevision == CatalogRevision && b.providerPolicyEpoch == PolicyEpoch &&
               safeText(b.request.context.requestId, 128) &&
               safeText(b.request.context.applicationIdentity, 512) && b.request.context.pending &&
               b.request.context.serviceAvailable && b.request.context.snapshotRevision &&
               b.request.context.serviceEpoch && b.request.context.sessionEpoch &&
               b.request.consentEpoch && b.request.credentialEpoch && b.request.generation;
    }
    QString disclosure() {
        return "GateBouncer sends the selected public product name to Wikimedia and, when "
               "available, queries its approved public GitHub repository. It sends short source "
               "extracts and the public product name to NVIDIA. This can happen while the app "
               "remains blocked. The providers receive the request and your IP address. No "
               "executable, local path, command line, connection history or credentials from the "
               "investigated app are sent. Your NVIDIA API key is sent only to NVIDIA to "
               "authenticate the request. It is not included in the model input, sent to Wikimedia "
               "or GitHub, or returned in explanations or citations.";
    }
    QString identityDisclaimer() {
        return "These sources describe the selected public product. They do not identify or verify "
               "this executable.";
    }
    QString evidenceLicense() {
        return "Wikipedia / Wikimedia; excerpts shortened or normalized, adapted text: CC BY-SA "
               "4.0 (https://creativecommons.org/licenses/by-sa/4.0/). Source citations attribute "
               "their contributors.";
    }
    static QByteArray integer(quint64 n, int size) {
        QByteArray b(size, '\0');
        for (int i = 0; i < size; ++i)
            b[i] = char(n >> (8 * i));
        return b;
    }
    static quint64 number(const QByteArray &b) {
        quint64 n = 0;
        for (int i = 0; i < b.size() && i < 8; ++i)
            n |= quint64(static_cast<unsigned char>(b[i])) << (8 * i);
        return n;
    }
    static bool nonzero(const std::array<unsigned char, 16> &id) {
        unsigned char any = 0;
        for (auto x : id)
            any |= x;
        return any;
    }
    static bool utf8(const QByteArray &b, int cap) {
        QStringDecoder d(QStringDecoder::Utf8);
        const QString s = d(b);
        return !d.hasError() && safeText(s, cap);
    }
    void setBinding(Frame &f, const Binding &b) {
        const auto &r = b.request;
        f.fields[10] = r.context.requestId.toUtf8();
        f.fields[11] = r.context.applicationIdentity.toUtf8();
        f.fields[12] = integer(r.context.snapshotRevision, 8);
        f.fields[13] = integer(r.context.serviceEpoch, 8);
        f.fields[14] = integer(r.context.sessionEpoch, 8);
        f.fields[15] = integer(r.consentEpoch, 8);
        f.fields[16] = integer(r.credentialEpoch, 8);
        f.fields[17] = integer(r.generation, 8);
        f.fields[18] = integer(r.context.pending, 1);
        f.fields[19] = integer(r.context.serviceAvailable, 1);
        f.fields[30] = integer(b.disclosureVersion, 2);
        f.fields[41] = integer(b.retrievalEpoch, 8);
        f.fields[42] = integer(b.catalogRevision, 8);
        f.fields[43] = integer(b.providerPolicyEpoch, 8);
    }
    std::optional<Binding> frameBinding(const Frame &f) {
        for (auto tag : {10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 30, 41, 42, 43})
            if (!f.fields.count(quint16(tag)))
                return {};
        if (!utf8(f.fields.at(10), 128) || !utf8(f.fields.at(11), 512))
            return {};
        for (auto tag : {12, 13, 14, 15, 16, 17, 41, 42, 43})
            if (f.fields.at(quint16(tag)).size() != 8)
                return {};
        for (auto tag : {18, 19})
            if (f.fields.at(quint16(tag)).size() != 1 || number(f.fields.at(quint16(tag))) > 1)
                return {};
        if (f.fields.at(30).size() != 2)
            return {};
        Binding b;
        auto n = [&](int t) { return number(f.fields.at(quint16(t))); };
        b.request.context = {QString::fromUtf8(f.fields.at(10)),
                             QString::fromUtf8(f.fields.at(11)),
                             n(12),
                             n(13),
                             n(14),
                             bool(n(18)),
                             bool(n(19))};
        b.request.consentEpoch = n(15);
        b.request.credentialEpoch = n(16);
        b.request.generation = n(17);
        b.retrievalEpoch = n(41);
        b.catalogRevision = n(42);
        b.providerPolicyEpoch = n(43);
        b.disclosureVersion = quint16(n(30));
        return validBinding(b) ? std::optional<Binding>(b) : std::nullopt;
    }
    std::optional<QByteArray> encodeSources(Product p, const std::vector<Source> &sources) {
        if (sources.size() > 3)
            return {};
        QByteArray b(1, char(sources.size()));
        std::set<quint8> seen;
        for (const auto &s : sources) {
            if (!validSource(p, s) || !seen.insert(s.id).second)
                return {};
            b += char(s.id);
            b += char(s.provider);
            b += char(s.authority);
            b += char(s.shortened);
            b += integer(s.fetchedAt, 8) + integer(s.updatedAt, 8) + integer(s.revision, 8) +
                 s.digest;
            const QByteArray parts[] = {s.resource.toUtf8(), s.title.toUtf8(), s.url.toUtf8(),
                                        s.excerpt.toUtf8()};
            for (const auto &part : parts)
                b += integer(quint64(part.size()), 2);
            for (const auto &part : parts)
                b += part;
        }
        return b.size() <= 4096 ? std::optional<QByteArray>(b) : std::nullopt;
    }
    std::optional<std::vector<Source>> decodeSources(Product product, const QByteArray &b) {
        if (b.isEmpty() || b.size() > 4096 || static_cast<unsigned char>(b[0]) > 3)
            return {};
        qsizetype p = 1;
        std::vector<Source> out;
        for (int k = 0; k < static_cast<unsigned char>(b[0]); ++k) {
            if (b.size() - p < 68)
                return {};
            Source s;
            s.id = quint8(b[p++]);
            s.provider = Provider(quint8(b[p++]));
            s.authority = Authority(quint8(b[p++]));
            if (b[p] != 0 && b[p] != 1)
                return {};
            s.shortened = bool(b[p++]);
            s.fetchedAt = number(b.mid(p, 8));
            p += 8;
            s.updatedAt = number(b.mid(p, 8));
            p += 8;
            s.revision = number(b.mid(p, 8));
            p += 8;
            s.digest = b.mid(p, 32);
            p += 32;
            int sizes[4];
            const int caps[] = {128, 128, 384, 512};
            for (int i = 0; i < 4; ++i) {
                sizes[i] = int(number(b.mid(p, 2)));
                p += 2;
                if (sizes[i] < 1 || sizes[i] > caps[i])
                    return {};
            }
            QString *dest[] = {&s.resource, &s.title, &s.url, &s.excerpt};
            for (int i = 0; i < 4; ++i) {
                if (b.size() - p < sizes[i])
                    return {};
                auto raw = b.mid(p, sizes[i]);
                p += sizes[i];
                if (!utf8(raw, caps[i]))
                    return {};
                *dest[i] = QString::fromUtf8(raw);
            }
            if (!validSource(product, s))
                return {};
            for (const auto &old : out)
                if (old.id == s.id)
                    return {};
            out.push_back(std::move(s));
        }
        return p == b.size() ? std::optional<std::vector<Source>>(std::move(out)) : std::nullopt;
    }
    static bool validFrame(const Frame &f) {
        if (!nonzero(f.connection) || !nonzero(f.correlation) || !f.sequence ||
            f.fields.size() > 32)
            return false;
        std::set<quint16> required, optional;
        const std::set<quint16> binding = {10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 30, 41, 42, 43};
        switch (f.type) {
        case 1:
            if (f.fields.empty())
                break;
            required =
                f.fields.count(33) ? std::set<quint16>{33} : std::set<quint16>{30, 31, 32, 40};
            break;
        case 2:
            required = {1, 2, 3, 4, 5, 6, 7, 41, 42, 43, 44};
            optional = {34};
            break;
        case 5:
            required = {25};
            break;
        case 6:
            required = {21};
            break;
        case 11:
            required = {23};
            break;
        case 12:
            required = binding;
            required.insert(20);
            break;
        case 13:
            required = binding;
            required.insert({20, 21, 22, 23, 45, 46});
            optional = {47};
            break;
        case 14:
            required = binding;
            required.insert({20, 45});
            break;
        // El adaptador de retrieval no procesa secretos ni variantes de demo GBAS1.
        default:
            return false;
        }
        for (auto t : required)
            if (!f.fields.count(t))
                return false;
        for (const auto &[tag, b] : f.fields) {
            if (!required.count(tag) && !optional.count(tag))
                return false;
            switch (tag) {
            case 1:
            case 2:
            case 44:
                if (b.size() != 1 || number(b) > (tag == 1 ? 6 : tag == 2 ? 2 : 4))
                    return false;
                break;
            case 6:
            case 18:
            case 19:
            case 31:
            case 32:
            case 40:
                if (b.size() != 1 || number(b) > 1)
                    return false;
                break;
            case 7:
                if (b.size() != 2 || number(b) > 63)
                    return false;
                break;
            case 3:
            case 4:
            case 5:
            case 12:
            case 13:
            case 14:
            case 15:
            case 16:
            case 17:
            case 41:
            case 42:
            case 43:
                if (b.size() != 8)
                    return false;
                break;
            case 10:
            case 11:
                if (!utf8(b, tag == 10 ? 128 : 512))
                    return false;
                break;
            case 20:
                if (b.size() != 4 || !knownProduct(Product(number(b))))
                    return false;
                break;
            case 21:
                if (b.size() != 1 || number(b) < 1 || number(b) > 6 ||
                    (f.type == 6 && number(b) != 3 && number(b) != 6))
                    return false;
                break;
            case 22:
                if (b.size() != 2 || (number(b) != 0 && number(b) != 200 && number(b) != 202 &&
                                      (number(b) < 300 || number(b) > 599)))
                    return false;
                break;
            case 23:
                if (b.size() != 2 || number(b) > 16)
                    return false;
                break;
            case 25:
            case 34:
                if (b.size() != 16 || b == QByteArray(16, '\0'))
                    return false;
                break;
            case 30:
                if (b.size() != 2 || number(b) != 2)
                    return false;
                break;
            case 33:
                if (b.size() != 1 || number(b) < 1 || number(b) > 2)
                    return false;
                break;
            case 45:
                if (b.size() != 1 || number(b) > 9)
                    return false;
                break;
            case 46:
                if (b.isEmpty() || b.size() > 4096)
                    return false;
                break;
            case 47:
                if (b.isEmpty() || b.size() > 2048)
                    return false;
                break;
            default:
                return false;
            }
        }
        if (f.type >= 12) {
            if (!frameBinding(f))
                return false;
            if (f.type == 14)
                return number(f.fields.at(45)) == 1 || number(f.fields.at(45)) == 2;
        }
        if (f.type == 13) {
            auto sources = decodeSources(Product(number(f.fields.at(20))), f.fields.at(46));
            if (!sources)
                return false;
            const auto state = State(number(f.fields.at(45)));
            const auto outcome = number(f.fields.at(21)), http = number(f.fields.at(22)),
                       error = number(f.fields.at(23));
            if (outcome == 1)
                return http == 200 && error == 0 &&
                       (state == State::SourcesRetrieved || state == State::CachedSources) &&
                       !sources->empty() && f.fields.count(47) &&
                       bool(parseInference(f.fields.at(47), *sources));
            if (f.fields.count(47) || error == 0)
                return false;
            switch (outcome) {
            case 2:
                return state == State::Insufficient && http == 0 && error == 14;
            case 3:
                return state == State::Cancelled && http == 0 && error == 11;
            case 4:
                if (state == State::PostUncertain)
                    return error == 14 && (http == 0 || http == 202) && !sources->empty();
                // HTTP200 tambien puede ser observado antes de fallar el parser/transporte.
                return (state == State::Failed || state == State::ProviderUnavailable) &&
                       error != 11 && error != 12 && error != 14;
            case 5:
                return state == State::ProviderUnavailable && error == 12 &&
                       (http == 0 || http == 403 || http == 429 || http == 503);
            default:
                // NotFound pertenece a CancelAck; no es resultado de una cadena grounded.
                return false;
            }
        }
        return true;
    }
    std::optional<QByteArray> encodeFrame(const Frame &f) {
        if (!validFrame(f))
            return {};
        QByteArray b(64, '\0');
        std::memcpy(b.data(), "GBAS", 4);
        auto put = [&](int pos, quint64 n, int len) {
            auto raw = integer(n, len);
            std::memcpy(b.data() + pos, raw.data(), size_t(len));
        };
        put(4, 2, 2);
        put(8, f.type, 2);
        std::memcpy(b.data() + 16, f.connection.data(), 16);
        put(32, f.sequence, 8);
        std::memcpy(b.data() + 40, f.correlation.data(), 16);
        for (const auto &[tag, v] : f.fields) {
            if (b.size() + 8 + v.size() > 8192)
                return {};
            b += integer(tag, 2) + integer(1, 2) + integer(quint64(v.size()), 4) + v;
        }
        put(12, quint64(b.size() - 64), 4);
        return b;
    }
    std::optional<Frame> decodeFrame(const QByteArray &b) {
        if (b.size() < 64 || b.size() > 8192 || b.left(4) != "GBAS" || number(b.mid(4, 2)) != 2 ||
            number(b.mid(6, 2)) || number(b.mid(10, 2)) ||
            number(b.mid(12, 4)) != quint64(b.size() - 64) || b.mid(56, 8) != QByteArray(8, '\0'))
            return {};
        Frame f;
        f.type = quint16(number(b.mid(8, 2)));
        f.sequence = number(b.mid(32, 8));
        std::memcpy(f.connection.data(), b.data() + 16, 16);
        std::memcpy(f.correlation.data(), b.data() + 40, 16);
        qsizetype p = 64;
        while (p < b.size()) {
            if (b.size() - p < 8 || f.fields.size() >= 32)
                return {};
            auto tag = quint16(number(b.mid(p, 2)));
            const auto flags = number(b.mid(p + 2, 2)), length = number(b.mid(p + 4, 4));
            p += 8;
            if (flags != 1 || length > quint64(b.size() - p) || f.fields.count(tag))
                return {};
            f.fields.emplace(tag, b.mid(p, qsizetype(length)));
            p += qsizetype(length);
        }
        return validFrame(f) ? std::optional<Frame>(std::move(f)) : std::nullopt;
    }
    bool FrameReader::feed(const QByteArray &b) {
        if (failed_ || b.size() > 8192 - buffer_.size())
            return !(failed_ = true);
        buffer_ += b;
        if (buffer_.size() >= 64 && number(buffer_.mid(12, 4)) > 8128)
            failed_ = true;
        return !failed_;
    }
    std::optional<Frame> FrameReader::take() {
        if (failed_ || buffer_.size() < 64)
            return {};
        auto size = 64 + qsizetype(number(buffer_.mid(12, 4)));
        if (size > 8192) {
            failed_ = true;
            return {};
        }
        if (buffer_.size() < size)
            return {};
        auto f = decodeFrame(buffer_.left(size));
        if (!f) {
            failed_ = true;
            return {};
        }
        buffer_.remove(0, size);
        return f;
    }
    GroundedReplyGate::GroundedReplyGate(std::array<unsigned char, 16> connection)
        : connection_(connection) {
        failed_ = !nonzero(connection_);
    }
    bool GroundedReplyGate::trackRequest(const Frame &f) {
        if (failed_ || pending_ || ledger_.size() >= 60 || f.type != 12 ||
            f.connection != connection_ || !validFrame(f))
            return false;
        for (const auto &entry : ledger_)
            if (entry.request.correlation == f.correlation)
                return false;
        pending_ = ledger_.size();
        ledger_.push_back({f, 0, false});
        return true;
    }
    bool GroundedReplyGate::consumeSequence(const std::array<unsigned char, 16> &connection,
                                           quint64 sequence) {
        if (failed_ || connection != connection_ || sequence != expectedSequence_ ||
            expectedSequence_ == ~quint64(0))
            return !(failed_ = true);
        ++expectedSequence_;
        return true;
    }
    bool GroundedReplyGate::observeControl(quint16 type,
                                          const std::array<unsigned char, 16> &connection,
                                          quint64 sequence) {
        if (type != 2 && type != 6 && type != 8 && type != 10 && type != 11)
            return !(failed_ = true);
        return consumeSequence(connection, sequence);
    }
    bool GroundedReplyGate::acceptReply(const Frame &f) {
        if (failed_)
            return false;
        if ((f.type != 13 && f.type != 14) || !validFrame(f))
            return !(failed_ = true);
        size_t index = 0;
        while (index < ledger_.size() && ledger_[index].request.correlation != f.correlation)
            ++index;
        if (index == ledger_.size())
            return !(failed_ = true);
        auto &entry = ledger_[index];
        if (entry.terminal || !(frameBinding(f) == frameBinding(entry.request)) ||
            f.fields.at(20) != entry.request.fields.at(20))
            return !(failed_ = true);
        if (f.type == 14) {
            const auto state = quint8(number(f.fields.at(45)));
            if (state != entry.progress + 1 || state > 2)
                return !(failed_ = true);
        }
        if (!consumeSequence(f.connection, f.sequence))
            return false;
        if (f.type == 14)
            entry.progress = quint8(number(f.fields.at(45)));
        else {
            entry.terminal = true;
            if (pending_ && *pending_ == index)
                pending_.reset();
        }
        return true;
    }
    void GroundedReplyGate::cancel() {
        pending_.reset();
    }
} // namespace Gate::Assistance::Retrieval
