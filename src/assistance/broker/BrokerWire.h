#pragma once
#include "BrokerPrimitives.h"
#include "../ExplanationContracts.h"
#include <QByteArray>
#include <map>
#include <optional>

namespace Gate::Assistance::Broker {
enum class WireVersion : quint16 { Legacy1=1, Grounded2=2, General3=3 };
enum class Message : quint16 { StatusRequest=1, StatusReply, Explain, Explanation, Cancel, CancelAck, Configure, ConfigureAck, Forget, ForgetAck, ErrorReply, GroundedExplain=12, GroundedExplanation=13, GroundedProgress=14,
    GeneralExplain=20, GeneralExplanation=21, GeneralProgress=22, PublicApproval=23, PublicApprovalAck=24,
    ConfigurationStatus=30, ConfigurationStatusReply=31, ConfigurationIntent=32, ConfigurationIntentReply=33,
    StoreCredential=34, ForgetCredential=35, UpdateConfiguration=36, ConfigurationAck=37 };
enum class Failure : quint16 { None, Malformed, Unsupported, Unauthorized, Stale, Capacity, VaultUnavailable, Corrupt, TransportUnavailable, TlsFailure, Timeout, Cancelled, RateLimited, InvalidResponse, Uncertain, ConfigurationNotApproved, VersionMismatch };
enum class Outcome : quint8 { Completed=1, Uncertain, Cancelled, Failed, Limited, NotFound };
struct Frame {
    Message message = Message::StatusRequest;
    Id connection{}, correlation{};
    quint64 sequence = 0;
    std::map<quint16, QByteArray> fields;
    SensitiveBytes secret;
};
quint64 number(const QByteArray &bytes);
QByteArray integer(quint64 value, size_t size);
std::optional<Frame> decodeFrame(const unsigned char *data, size_t size,WireVersion version=WireVersion::Legacy1);
std::optional<SensitiveBytes> encodeFrame(const Frame &frame,WireVersion version=WireVersion::Legacy1);
bool validFrame(const Frame &frame,WireVersion version=WireVersion::Legacy1);
std::optional<RequestBinding> binding(const Frame &frame);
void setBinding(Frame &frame, const RequestBinding &binding);
std::optional<QByteArray> boundedExplanation(const QByteArray &envelope);
QByteArray envelopeFromExplanation(const QByteArray &explanation);
class FrameReader final {
public:
    explicit FrameReader(WireVersion version=WireVersion::Legacy1):version_(version){}
    bool feed(const unsigned char *bytes, size_t count);
    std::optional<Frame> take();
    bool failed() const { return failed_; }
    bool partial() const { return count_ != 0; }
private:
    WireVersion version_;
    SensitiveBytes bytes_{8192}; size_t count_ = 0, expected_ = 64; bool failed_ = false;
};
}
