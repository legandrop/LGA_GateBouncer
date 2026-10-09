#include "SourceNormalizer.h"
#include "Catalog.h"
#include "StrictJson.h"
#include <QCryptographicHash>
#include <QDateTime>
#include <QRegularExpression>
namespace Gate::Assistance::Retrieval {
    static const Json *at(const Json &j, const QString &key) { return j.get(key); }
    static std::optional<QString> text(const Json &j, const QString &k) {
        auto *v = at(j, k);
        return v ? v->text() : std::nullopt;
    }
    static std::optional<quint64> num(const Json &j, const QString &k) {
        auto *v = at(j, k);
        return v ? v->integer() : std::nullopt;
    }
    static bool boolean(const Json &j, const QString &k, bool expected) {
        auto *v = at(j, k);
        return v && v->boolean() && *v->boolean() == expected;
    }
    static std::optional<quint64> date(const QString &s, quint64 fetched) {
        static const QRegularExpression shape(
            "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,3})?Z$");
        if (!shape.match(s).hasMatch())
            return {};
        auto d = QDateTime::fromString(s, Qt::ISODateWithMs);
        if (!d.isValid())
            d = QDateTime::fromString(s, Qt::ISODate);
        if (!d.isValid() || d.toMSecsSinceEpoch() <= 0 ||
            quint64(d.toMSecsSinceEpoch()) > fetched + 300000)
            return {};
        return quint64(d.toMSecsSinceEpoch());
    }
    static std::optional<QString> normalized(QString input) {
        if (input.toUtf8().size() > 4096)
            return {};
        QString out;
        bool space = false;
        for (const auto c : input) {
            if (c == '\n' || c == '\r' || c == '\t' || c == ' ') {
                space = true;
                continue;
            }
            if (c.category() == QChar::Other_Control || c.category() == QChar::Other_Format ||
                c.category() == QChar::Other_Surrogate || c.unicode() == 0x2028 ||
                c.unicode() == 0x2029)
                return {};
            if (space && !out.isEmpty())
                out += ' ';
            space = false;
            out += c;
        }
        static const QRegularExpression instructions(
            "ignore (?:all |previous |the "
            ")?instructions|system\\s*:|assistant\\s*:|<\\|(?:system|assistant|im_start)|grant "
            "allow|call (?:a |the )?tool|api[ _-]?key|authorization\\s*:",
            QRegularExpression::CaseInsensitiveOption);
        if (out.isEmpty() || instructions.match(out).hasMatch() || out.contains('<') ||
            out.contains('>'))
            return {};
        return out;
    }
    std::optional<quint64> searchPage(Product product, const QByteArray &body) {
        auto *c = catalog(product);
        auto j = strictJson(body);
        if (!c || !j)
            return {};
        auto *q = j->get("query");
        auto *s = q ? q->get("search") : nullptr;
        if (!s || s->kind != Json::Kind::Array || s->array.size() > 3)
            return {};
        std::optional<quint64> selected;
        for (const auto &item : s->array) {
            auto title = text(item, "title");
            auto id = num(item, "pageid"), ns = num(item, "ns");
            if (!title || !safeText(*title, 256) || !id || !*id || !ns || *ns)
                return {};
            if (*title == c->wikiNormalized) {
                if (selected)
                    return {};
                selected = id;
            }
        }
        return selected;
    }
    std::optional<Source> normalizeSource(Product product, Endpoint kind, const QByteArray &body,
                                          quint64 fetched, quint64 page) {
        auto *c = catalog(product);
        auto j = strictJson(body);
        if (!c || !j || !fetched || fetched > 253402300799999ULL || kind == Endpoint::WikiSearch)
            return {};
        Source s;
        s.fetchedAt = fetched;
        if (kind == Endpoint::WikiSummary) {
            auto type = text(*j, "type"), lang = text(*j, "lang"), dir = text(*j, "dir"),
                 extract = text(*j, "extract"), rev = text(*j, "revision"),
                 timestamp = text(*j, "timestamp");
            auto *titles = j->get("titles"), *ns = j->get("namespace");
            auto id = num(*j, "pageid");
            if (!type || *type != "standard" || !lang || *lang != "en" || !dir || *dir != "ltr" ||
                !extract || !rev || !timestamp || !id || !*id || *id != page || !titles || !ns)
                return {};
            if (text(*titles, "canonical") != std::optional<QString>(c->wikiCanonical) ||
                text(*titles, "normalized") != std::optional<QString>(c->wikiNormalized) ||
                num(*ns, "id") != std::optional<quint64>(0))
                return {};
            auto r = decimal(rev->toLatin1()), d = date(*timestamp, fetched);
            if (!r || !*r || !d || *rev != QString::number(*r))
                return {};
            s.revision = *r;
            s.updatedAt = *d;
            s.resource = c->wikiCanonical;
            s.title = c->wikiNormalized;
            s.url = canonicalUrl(product, kind, *rev);
            s.excerpt = *extract;
        } else {
            s.provider = Provider::GitHub;
            s.authority = Authority::OfficialProjectMetadata;
            if (kind == Endpoint::GitHubRepo) {
                auto full = text(*j, "full_name");
                auto id = num(*j, "id");
                auto *owner = j->get("owner");
                if (!full || *full != c->repository || !id || !*id || !owner ||
                    text(*owner, "login") !=
                        std::optional<QString>(c->repository.section('/', 0, 0)) ||
                    !boolean(*j, "private", false) || !boolean(*j, "fork", false))
                    return {};
                auto *archived = j->get("archived");
                if (!archived || !archived->boolean())
                    return {};
                s.resource = c->repository;
                s.title = "Official repository metadata";
                s.url = canonicalUrl(product, kind);
                s.excerpt = "Repository: " + c->repository +
                            "; archived: " + (*archived->boolean() ? "true" : "false");
            } else if (kind == Endpoint::GitHubLatest) {
                auto id = num(*j, "id");
                auto tag = text(*j, "tag_name");
                if (!id || !*id || !tag || !boolean(*j, "draft", false) ||
                    !boolean(*j, "prerelease", false))
                    return {};
                s.resource = *tag;
                s.url = canonicalUrl(product, kind, *tag);
                s.title = "Latest full release returned by GitHub";
                auto published = j->get("published_at");
                QString rendered = "unknown";
                if (published && published->kind != Json::Kind::Null) {
                    auto t = published->text();
                    auto d = t ? date(*t, fetched) : std::nullopt;
                    if (!d)
                        return {};
                    s.updatedAt = *d;
                    rendered = *t;
                }
                s.excerpt = "GitHub latest full release tag: " + *tag + "; published: " + rendered;
            } else
                return {};
        }
        auto content = normalized(s.excerpt);
        if (!content || s.url.isEmpty())
            return {};
        s.normalizedContent = *content;
        s.digest = QCryptographicHash::hash(content->toUtf8(), QCryptographicHash::Sha256);
        s.excerpt = *content;
        if (s.excerpt.size() > 128 || s.excerpt.toUtf8().size() > 512) {
            int cut = qMin(128, int(s.excerpt.size()));
            while (cut > 0 && s.excerpt.left(cut).toUtf8().size() > 512)
                --cut;
            cut = s.excerpt.lastIndexOf(' ', cut - 1);
            if (cut <= 0)
                return {};
            s.excerpt = s.excerpt.left(cut);
            s.shortened = true;
        }
        s.id = kind == Endpoint::WikiSummary ? 1 : kind == Endpoint::GitHubRepo ? 2 : 3;
        return validSource(product, s) ? std::optional<Source>(std::move(s)) : std::nullopt;
    }
    bool validSource(Product product, const Source &s) {
        auto *c = catalog(product);
        if (!c || !s.fetchedAt || s.fetchedAt > 253402300799999ULL || s.digest.size() != 32 ||
            !safeText(s.title, 128) || !safeText(s.excerpt, 512) || s.excerpt.size() > 128 ||
            !safeText(s.resource, 128) || s.resource.toLatin1() != s.resource.toUtf8() ||
            s.updatedAt > 253402300799999ULL || s.updatedAt > s.fetchedAt + 300000)
            return false;
        if (!s.normalizedContent.isEmpty()) {
            auto original = normalized(s.normalizedContent);
            if (!original || *original != s.normalizedContent ||
                QCryptographicHash::hash(original->toUtf8(), QCryptographicHash::Sha256) !=
                    s.digest)
                return false;
            if (s.shortened) {
                if (!original->startsWith(s.excerpt + " ") || original->size() <= s.excerpt.size())
                    return false;
            } else if (*original != s.excerpt)
                return false;
        } else if (!s.shortened && QCryptographicHash::hash(s.excerpt.toUtf8(),
                                                            QCryptographicHash::Sha256) != s.digest)
            return false;
        if (s.provider == Provider::Wikimedia && s.authority == Authority::Community && s.id == 1)
            return s.resource == c->wikiCanonical && s.title == c->wikiNormalized && s.revision &&
                   s.updatedAt &&
                   s.url ==
                       canonicalUrl(product, Endpoint::WikiSummary, QString::number(s.revision));
        if (s.provider != Provider::GitHub || s.authority != Authority::OfficialProjectMetadata ||
            s.revision)
            return false;
        return (s.id == 2 && s.resource == c->repository &&
                s.title == "Official repository metadata" && !s.updatedAt &&
                s.url == canonicalUrl(product, Endpoint::GitHubRepo)) ||
               (s.id == 3 && s.title == "Latest full release returned by GitHub" &&
                s.url == canonicalUrl(product, Endpoint::GitHubLatest, s.resource) &&
                !s.url.isEmpty());
    }
} // namespace Gate::Assistance::Retrieval
