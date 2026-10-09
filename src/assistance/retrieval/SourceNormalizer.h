#pragma once
#include "Contracts.h"
namespace Gate::Assistance::Retrieval {
    std::optional<quint64> searchPage(Product, const QByteArray &);
    std::optional<Source> normalizeSource(Product, Endpoint, const QByteArray &, quint64 fetchedAt,
                                          quint64 expectedPage = 0);
    bool validSource(Product, const Source &);
} // namespace Gate::Assistance::Retrieval
