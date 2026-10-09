#pragma once
#include "Contracts.h"
#include <QObject>
#include <QTimer>
#include <deque>
namespace Gate::Assistance::Retrieval {
    class Activation;
    class PayloadBuilder;
    class PrivateRetrievalTest;
    class BudgetGuard final {
      public:
        BudgetGuard();
        explicit BudgetGuard(const Activation &);
        ~BudgetGuard();
        Failure reserve(quint64 utcMs);
        void cooldown(Provider, quint64 utcMs, quint32 seconds);
        bool providerReady(Provider, quint64 utcMs) const;

      private:
        friend class PrivateRetrievalTest;
        explicit BudgetGuard(QString syntheticRoot);
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };
    class Coordinator final : public QObject {
      public:
        using Completion = std::function<void(Result)>;
        using Progress = std::function<void(State)>;
        using Clock = std::function<qint64()>;
        Coordinator(GetTransport &, IExplanationTransport &, BudgetGuard &,
                    QObject *parent = nullptr);
        Coordinator(GetTransport &, IExplanationTransport &, BudgetGuard &, const PayloadBuilder &,
                    QObject *parent = nullptr);
        ~Coordinator() override;
        void configure(bool nvidiaConsent, bool webConsent, quint64 retrievalEpoch, bool automatic);
        void setContext(const Binding &, Product);
        bool start(Completion, Progress = {});
        void cancel();
        void providerWithdrawn();
        State state() const { return state_; }

      private:
        friend class PrivateRetrievalTest;
        GetTransport &get_;
        IExplanationTransport &model_;
        BudgetGuard &budget_;
        const PayloadBuilder *builder_ = nullptr;
        bool synthetic_ = false, nvidiaConsent_ = false, webConsent_ = false, automatic_ = false,
             active_ = false;
        quint64 consentEpoch_ = 0;
        unsigned invalidating_ = 0;
        Binding context_, submitted_;
        Product product_ = Product::UnknownSynthetic, submittedProduct_ = Product::UnknownSynthetic;
        State state_ = State::Idle;
        Clock monotonic_, utc_;
        qint64 started_ = 0, lastUtc_ = 0, startedUtc_ = 0;
        QTimer deadline_;
        std::unique_ptr<Operation> operation_;
        Completion completion_;
        Progress progress_;
        quint64 serial_ = 0, page_ = 0;
        int stage_ = 0;
        qsizetype received_ = 0;
        bool repositoryAccepted_ = false;
        std::vector<Source> sources_;
        std::vector<RequestContext> consumed_;
        struct Cache {
            Binding binding;
            Product product;
            std::vector<Source> sources;
            Inference inference;
            qint64 saved;
        };
        std::deque<Cache> cache_;
        bool eligible() const;
        bool current(quint64 serial) const;
        bool consumed() const;
        void next();
        void got(quint64, HttpReply);
        void explain();
        void explained(quint64, TransportReply);
        void finish(State, Failure, int status = 0, std::optional<Inference> inference = {});
    };
} // namespace Gate::Assistance::Retrieval
