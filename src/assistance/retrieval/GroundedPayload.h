#pragma once
#include "Contracts.h"
namespace Gate::Assistance::Retrieval {
    class PayloadBuilder {
      public:
        virtual ~PayloadBuilder() = default;
        virtual std::optional<QByteArray> build(Product, const std::vector<Source> &) const = 0;
    };
    std::optional<QByteArray> groundedPayload(Product, const std::vector<Source> &, Model);
}
