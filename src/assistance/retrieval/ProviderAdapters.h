#pragma once
#include "Contracts.h"
#include <QObject>
namespace Gate::Assistance::Retrieval {
    class Activation;
    class WinHttpGetTransport final : public QObject, public GetTransport {
      public:
        explicit WinHttpGetTransport(QObject *parent = nullptr);
        explicit WinHttpGetTransport(const Activation &, QObject *parent = nullptr);
        ~WinHttpGetTransport() override;
        std::unique_ptr<Operation> start(Endpoint, Product, qint64 remainingMs,
                                         Completion) override;

      private:
        struct Job;
        std::weak_ptr<Job> active_;
    };
} // namespace Gate::Assistance::Retrieval
