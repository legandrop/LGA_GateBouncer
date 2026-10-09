#pragma once
#include "Contracts.h"
namespace Gate::Assistance::Retrieval {
    struct RequestSpec {
        QString host, path;
        std::vector<QString> headers;
    };
    class Activation final {
      public:
        static bool approved() noexcept { return false; }
        static std::optional<Activation> forCurrentUser() { return {}; }

      private:
        Activation() = default;
    };
    std::optional<RequestSpec> requestSpec(Product, Endpoint);
    bool noAuthentication(const RequestSpec &);
} // namespace Gate::Assistance::Retrieval
