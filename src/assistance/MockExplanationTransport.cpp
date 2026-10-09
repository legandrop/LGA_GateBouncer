#include "MockExplanationTransport.h"
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QTimer>
namespace Gate::Assistance {
namespace {
struct CancelState { bool cancelled = false; };
class MockOperation final : public Operation {
public:
    explicit MockOperation(std::shared_ptr<CancelState> state) : state_(std::move(state)) {}
    ~MockOperation() override { cancel(); }
    void cancel() override { state_->cancelled = true; }
private:
    std::shared_ptr<CancelState> state_;
};
}
MockExplanationTransport::MockExplanationTransport(QObject *parent) : QObject(parent) {
    fixture_.body = sampleEnvelope();
}
QByteArray MockExplanationTransport::sampleEnvelope(bool unclear) {
    const QJsonObject inner{
        {"possible_purpose", unclear ? "There is not enough public information." : "This sample application could edit documents."},
        {"possible_network_reason", "It might request updates or synchronize documents."},
        {"caution", "This sample does not identify the installed file or certify its safety."},
        {"certainty", unclear ? "unclear" : "possible"}};
    const auto content = QString::fromUtf8(QJsonDocument(inner).toJson(QJsonDocument::Compact));
    return QJsonDocument(QJsonObject{{"choices", QJsonArray{
        QJsonObject{{"finish_reason", "stop"}, {"message", QJsonObject{
            {"role", "assistant"}, {"content", content}}}}}}}).toJson(QJsonDocument::Compact);
}
std::unique_ptr<Operation> MockExplanationTransport::start(const RequestBinding &binding,
                                                           const QByteArray &payload, Completion completion) {
    if (payload.isEmpty() || payload.size() > 4096 || !completion) return {};
    ++dispatches_;
    const auto fixture = fixture_;
    auto state = std::make_shared<CancelState>();
    QTimer::singleShot(qBound(0, fixture.delayMs, 20001), this, [state, fixture, binding, completion = std::move(completion)] {
        if (!state->cancelled || fixture.deliverAfterCancel)
            completion(TransportReply{binding, fixture.status, fixture.body, fixture.error});
    });
    return std::make_unique<MockOperation>(std::move(state));
}
} // namespace Gate::Assistance
