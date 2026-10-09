#pragma once
#include "Contracts.h"
namespace Gate::Assistance::Retrieval {
    std::optional<Inference> parseInference(const QByteArray &, const std::vector<Source> &);
    std::optional<Inference> parseGroundedEnvelope(const QByteArray &, const std::vector<Source> &);
    QByteArray inferenceJson(const Inference &);
} // namespace Gate::Assistance::Retrieval
