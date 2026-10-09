#pragma once
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace Gate::Assistance::General {
using Id128 = std::array<std::uint8_t,16>;
using Digest256 = std::array<std::uint8_t,32>;
enum class Provider : std::uint8_t { MwmblV2=1, SearXng=2 };
enum class State : std::uint8_t { Searching=1, Explaining, Evidence, Insufficient, Cancelled, Failed, Uncertain };
enum class Failure : std::uint16_t { None, Malformed, Unsupported, Unauthorized, Stale, Capacity,
    VaultUnavailable, Corrupt, TransportUnavailable, TlsFailure, Timeout, Cancelled, RateLimited,
    InvalidResponse, Uncertain, ConfigurationNotApproved, VersionMismatch, SearchRejected, SearchUnavailable };
struct FullBinding {
    std::string requestId;
    Id128 applicationToken{};
    std::uint64_t snapshotRevision=0,serviceEpoch=0,sessionEpoch=0,retrievalEpoch=0,
        providerPolicyEpoch=0,credentialEpoch=0,modelConsentEpoch=0,webConsentEpoch=0,
        generation=0,approvalEpoch=0,entitlementPolicyEpoch=0;
    Id128 localSnapshotToken{};
    std::uint64_t localSnapshotGeneration=0;
    Provider provider=Provider::MwmblV2;
    std::string providerInstance;
    Digest256 providerConfiguration{},publicApprovalDigest{};
    std::uint32_t profileRevision=1;
    bool operator==(const FullBinding&) const;
    bool operator!=(const FullBinding& b) const { return !(*this==b); }
    Digest256 canonicalDigest() const;
};
struct PublicFields {
    std::string product;
    std::optional<std::string> publisher;
    std::string query;
    bool operator==(const PublicFields&) const;
};
struct Citation {
    std::uint8_t id=0;
    std::string url,title,snippet,origin;
    std::uint64_t retrievedAtMs=0;
    bool shortened=false;
};
struct Inference { std::string purpose,networkReason,caution; bool possible=false; std::vector<std::uint8_t> sourceIds; };
struct Result {
    FullBinding binding;
    State state=State::Insufficient;
    Failure failure=Failure::None;
    int observedHttpStatus=0;
    std::vector<Citation> citations;
    std::optional<Inference> inference;
};
struct View {
    std::string purpose,networkReason,uncertainty,identityNotice,providerNotice;
    bool identityUnverified=true;
    std::vector<Citation> citations;
    std::vector<std::uint8_t> sourceIds;
};
bool validBinding(const FullBinding&,bool approvalPending=false);
bool validPublicFields(const PublicFields&);
bool safeText(std::string_view,std::size_t,bool allowEmpty=false);
std::string canonicalBinding(const FullBinding&);
Digest256 approvalDigest(const PublicFields&,std::uint64_t epoch);
View makeView(const Result&);
class GeneralRuntime;
class GeneralModelTransport;
class ApprovalRecord final {
public:
    const FullBinding& binding() const { return binding_; }
    const PublicFields& fields() const { return fields_; }
    const Digest256& publicDigest() const { return binding_.publicApprovalDigest; }
    std::uint64_t epoch() const { return binding_.approvalEpoch; }
    const Id128& connection() const { return connection_; }
    const Id128& correlation() const { return correlation_; }
    bool isCurrent() const;
private:
    friend class GeneralRuntime;
    ApprovalRecord(FullBinding,PublicFields,Id128,Id128,std::weak_ptr<const void>,std::function<bool()>);
    const FullBinding binding_;
    const PublicFields fields_;
    const Id128 connection_,correlation_;
    std::weak_ptr<const void> owner_;
    std::function<bool()> current_;
};
class Operation { public: virtual ~Operation()=default; virtual void cancel()=0; };
struct SearchReply { FullBinding binding; std::vector<Citation> citations; Failure failure=Failure::None; };
class SearchPort {
public:
    using Completion=std::function<void(SearchReply)>;
    virtual ~SearchPort()=default;
    virtual bool begin(const FullBinding&,const PublicFields&,Completion)=0;
    virtual void cancel()=0;
};
class SealedGeneralPayload;
struct ModelReply { FullBinding binding; std::string envelope; Failure failure=Failure::None; int observedHttpStatus=0; bool sendStarted=false; };
class ModelPort {
public:
    using Completion=std::function<void(ModelReply)>;
    virtual ~ModelPort()=default;
    virtual std::unique_ptr<Operation> begin(const FullBinding&,const SealedGeneralPayload&,Completion)=0;
};
}
