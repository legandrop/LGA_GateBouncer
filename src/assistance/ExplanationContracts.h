#pragma once
#include <QByteArray>
#include <QString>
#include <functional>
#include <memory>
#include <optional>

namespace Gate::Assistance {
enum class CatalogEntry { SampleEditor, SampleUnknown };
class PublicAppFacts final {
public:
    static PublicAppFacts sample(CatalogEntry entry);
    QString applicationName() const { return name_; }
    std::optional<QString> publisher() const { return publisher_; }
private:
    QString name_;
    std::optional<QString> publisher_;
};
struct RequestContext {
    QString requestId, applicationIdentity;
    quint64 snapshotRevision = 0, serviceEpoch = 0, sessionEpoch = 0;
    bool pending = false, serviceAvailable = false;
    bool operator==(const RequestContext &other) const;
};
struct RequestBinding {
    RequestContext context;
    quint64 consentEpoch = 0, credentialEpoch = 0, generation = 0;
    bool operator==(const RequestBinding &other) const;
};
struct ExplanationText {
    QString possiblePurpose, possibleNetworkReason, caution;
    enum class Certainty { Unclear, Possible } certainty = Certainty::Unclear;
};
enum class Status { Idle, Loading, Known, Unclear, Error, Uncertain, Cancelled, Limited };
enum class Error { None, InvalidResponse, Unavailable, RateLimited, Timeout, Cancelled };
struct TransportReply {
    RequestBinding binding;
    int statusCode = 0;
    QByteArray body;
    Error error = Error::None;
};
class Operation {
public:
    virtual ~Operation() = default;
    virtual void cancel() = 0;
};
class IExplanationTransport {
public:
    using Completion = std::function<void(TransportReply)>;
    virtual ~IExplanationTransport() = default;
    virtual std::unique_ptr<Operation> start(const RequestBinding &, const QByteArray &, Completion) = 0;
};
std::optional<QByteArray> buildSamplePayload(const PublicAppFacts &facts);
std::optional<ExplanationText> parseExplanationEnvelope(const QByteArray &body);
QString localDisclosure();
QString localDisclaimer();
} // namespace Gate::Assistance
