#pragma once
#include "ExplanationContracts.h"
#include <QObject>
namespace Gate::Assistance {
class MockExplanationTransport final : public QObject, public IExplanationTransport {
public:
    struct Fixture { int status = 200; QByteArray body; Error error = Error::None; int delayMs = 1; bool deliverAfterCancel = false; };
    explicit MockExplanationTransport(QObject *parent = nullptr);
    void setFixture(Fixture fixture) { fixture_ = std::move(fixture); }
    int dispatchCount() const { return dispatches_; }
    static QByteArray sampleEnvelope(bool unclear = false);
    std::unique_ptr<Operation> start(const RequestBinding &, const QByteArray &, Completion) override;
private:
    Fixture fixture_;
    int dispatches_ = 0;
};
} // namespace Gate::Assistance
