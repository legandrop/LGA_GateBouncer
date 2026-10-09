#include "ProviderPolicy.h"
#include "Catalog.h"
namespace Gate::Assistance::Retrieval {
    std::optional<RequestSpec> requestSpec(Product p, Endpoint kind) {
        auto *c = catalog(p);
        if (!c)
            return {};
        RequestSpec r;
        r.headers = {"Accept: application/json", "Accept-Encoding: identity"};
        switch (kind) {
        case Endpoint::WikiSearch:
            r.host = "en.wikipedia.org";
            r.path =
                "/w/"
                "api.php?action=query&list=search&srsearch=OBS%20Studio&srnamespace=0&srlimit=3&"
                "srprop=timestamp&srinfo=totalhits&srwhat=title&format=json&formatversion=2&utf8=1";
            break;
        case Endpoint::WikiSummary:
            r.host = "en.wikipedia.org";
            r.path = "/api/rest_v1/page/summary/" + c->wikiCanonical;
            break;
        case Endpoint::GitHubRepo:
        case Endpoint::GitHubLatest:
            r.host = "api.github.com";
            r.path = "/repos/" + c->repository +
                     (kind == Endpoint::GitHubLatest ? "/releases/latest" : "");
            r.headers = {"Accept: application/vnd.github+json", "Accept-Encoding: identity",
                         "X-GitHub-Api-Version: 2026-03-10"};
            break;
        default:
            return {};
        }
        return r;
    }
    bool noAuthentication(const RequestSpec &r) {
        for (const auto &h : r.headers)
            if (h.startsWith("Authorization:", Qt::CaseInsensitive) ||
                h.startsWith("Cookie:", Qt::CaseInsensitive) ||
                h.startsWith("Proxy-Authorization:", Qt::CaseInsensitive))
                return false;
        return true;
    }
} // namespace Gate::Assistance::Retrieval
