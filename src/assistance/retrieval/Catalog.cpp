#include "Catalog.h"
#include "StrictJson.h"
#include <QUrl>
namespace Gate::Assistance::Retrieval {
    const CatalogEntry *catalog(Product product) {
        static const CatalogEntry obs{Product::ObsStudio, "OBS Studio", "OBS Project",
                                      "OBS_Studio",       "OBS Studio", "obsproject/obs-studio"};
        return product == Product::ObsStudio ? &obs : nullptr;
    }
    bool knownProduct(Product p) {
        return p == Product::ObsStudio || p == Product::NukeCandidate ||
               p == Product::UnknownSynthetic;
    }
    bool eligibleProduct(Product p) { return catalog(p) != nullptr; }
    QString canonicalUrl(Product product, Endpoint kind, const QString &revisionOrTag) {
        auto *c = catalog(product);
        if (!c)
            return {};
        if (kind == Endpoint::WikiSummary) {
            auto rev = decimal(revisionOrTag.toLatin1());
            if (!rev || !*rev || revisionOrTag != QString::number(*rev))
                return {};
            return "https://en.wikipedia.org/w/index.php?title=" + c->wikiCanonical +
                   "&oldid=" + revisionOrTag;
        }
        if (kind == Endpoint::GitHubRepo && revisionOrTag.isEmpty())
            return "https://github.com/" + c->repository;
        if (kind == Endpoint::GitHubLatest && safeText(revisionOrTag, 64) &&
            !revisionOrTag.contains('/') && revisionOrTag.toUtf8().size() == revisionOrTag.size())
            return "https://github.com/" + c->repository + "/releases/tag/" +
                   QString::fromLatin1(QUrl::toPercentEncoding(revisionOrTag));
        return {};
    }
} // namespace Gate::Assistance::Retrieval
