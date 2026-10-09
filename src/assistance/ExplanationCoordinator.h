#pragma once
#include "ExplanationContracts.h"
#include <QObject>
#include <QPointer>
#include <QTimer>
#include <deque>
namespace Gate::Assistance {
class ExplanationCoordinator final : public QObject {
    Q_OBJECT
public:
    using Clock = std::function<qint64()>;
    explicit ExplanationCoordinator(IExplanationTransport &transport, QObject *parent = nullptr, Clock clock = {});
    ~ExplanationCoordinator() override;
    void configureDemo(bool configured, bool consent);
    void setAutomatic(bool automatic);
    void open(const RequestContext &context, CatalogEntry entry = CatalogEntry::SampleEditor);
    void updateContext(const RequestContext &context);
    void close();
    bool start();
    void cancel();
    Status status() const { return status_; }
    Error error() const { return error_; }
    std::optional<ExplanationText> explanation() const { return text_; }
    bool automatic() const { return automatic_; }
    bool configured() const { return configured_; }
    bool consent() const { return consent_; }
    QString disclosure() const { return localDisclosure(); }
    QString disclaimer() const { return localDisclaimer(); }
    RequestBinding binding() const { return binding_; }
    int sessionAttempts() const { return attempts_; }
signals:
    void changed();
private:
    struct Cached { RequestBinding binding; CatalogEntry entry; ExplanationText text; qint64 saved; };
    bool eligible() const;
    void invalidate(Status status = Status::Idle);
    void finish(TransportReply reply);
    void fail(Error error, Status status);
    void maybeAutomatic();
    void markUncertain();
    bool uncertainRequest() const;
    IExplanationTransport &transport_;
    Clock clock_;
    QTimer deadline_;
    std::unique_ptr<Operation> operation_;
    RequestBinding binding_;
    CatalogEntry entry_ = CatalogEntry::SampleEditor;
    bool visible_ = false, configured_ = false, consent_ = false, automatic_ = false;
    bool automaticChosen_ = false;
    Status status_ = Status::Idle;
    Error error_ = Error::None;
    std::optional<ExplanationText> text_;
    std::deque<Cached> cache_;
    std::deque<RequestContext> uncertain_;
    qint64 started_ = 0, lastAttempt_ = -10000, blockedUntil_ = 0;
    int attempts_ = 0, failures_ = 0;
};
} // namespace Gate::Assistance
