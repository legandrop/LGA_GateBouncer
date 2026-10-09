#pragma once
#include "Contracts.h"
namespace Gate::Assistance::Retrieval {
    struct CatalogEntry {
        Product id;
        QString name, publisher, wikiCanonical, wikiNormalized, repository;
    };
    constexpr quint64 CatalogRevision = 1;
    constexpr quint64 PolicyEpoch = 1;
    const CatalogEntry *catalog(Product);
    bool knownProduct(Product);
    bool eligibleProduct(Product);
    QString canonicalUrl(Product, Endpoint, const QString &revisionOrTag = {});
} // namespace Gate::Assistance::Retrieval
