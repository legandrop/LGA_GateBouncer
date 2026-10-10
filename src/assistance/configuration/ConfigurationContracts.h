#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <tuple>

namespace Gate::Assistance::Configuration {
using Id128 = std::array<std::uint8_t,16>;
using Digest256 = std::array<std::uint8_t,32>;
inline constexpr const char *GeneralProfile = "GB_GENERAL_SNIPPETS_ULTRA_1";
enum class StorageState : std::uint8_t { Uninitialized, Ready, Busy, UnsafeRoot, Corrupt, Unreadable, IoUncertain };
enum class CredentialState : std::uint8_t { Absent, Stored, Corrupt, Unavailable };
enum class ModeChoice : std::uint8_t { Unchosen, Automatic, Manual };
// Proposito elegido por el usuario; no acredita cuenta, cuota ni permiso productivo.
enum class ServiceUse : std::uint8_t { Unchosen, InternalEvaluation, HostedProduction };
enum class EvidenceState : std::uint8_t { Missing, Applicable, Restricted, Expired, Conflict };
enum class ActivationCause : std::uint16_t {
    Ready, LocalConfigurationUnavailable, CredentialMissing, CredentialCorrupt,
    EntitlementMissing, OperationalUseRestricted, EntitlementExpired, EntitlementConflict,
    ModelConsentMissing, WebConsentMissing, SearchConfigurationMissing,
    PublicQueryApprovalMissing, ProviderPolicyChanged, SessionStale, ServiceUnavailable,
    PayloadNotSealed, TechnicalPrerequisitesMissing, LocalMutationUncertain, ServiceUseMissing
};
enum class ConfigFailure : std::uint16_t { None, Malformed, Unauthorized, Stale, Busy, UnsafeRoot, Corrupt, Unreadable, IoUncertain, UnsupportedProfile, RevisionExhausted };
enum class ConfigurationVerb : std::uint8_t { Store=1, Forget, Consent, Mode, Profile, Search, ServiceUse };
enum class ConsentTarget : std::uint8_t { Model=1, Web };
enum class Modality : std::uint8_t { HostedOperational=1, LocalDeployment, InternalEvaluation };
struct Epochs {
    std::uint64_t configuration=1, credential=1, consent=1, modelConsent=1, webConsent=1;
    std::uint64_t retrieval=1, providerPolicy=1, entitlement=1, session=1;
    auto values() const { return std::tie(configuration,credential,consent,modelConsent,webConsent,retrieval,providerPolicy,entitlement,session); }
    bool operator==(const Epochs &o) const { return values()==o.values(); }
};
struct ConsentReceipt {
    bool granted=false;
    std::uint32_t noticeRevision=0;
    Digest256 noticeDigest{};
    std::string profileRef;
    Digest256 destinationPolicyBinding{};
    std::uint64_t epoch=1;
    auto values() const { return std::tie(granted,noticeRevision,noticeDigest,profileRef,destinationPolicyBinding,epoch); }
    bool operator==(const ConsentReceipt &o) const { return values()==o.values(); }
};
struct SearchBindingRef {
    std::uint8_t provider=0;
    Digest256 configurationBinding{};
    std::array<char,38> instanceToken{};
    std::uint64_t providerPolicyEpoch=0, webConsentEpoch=0;
    auto values() const { return std::tie(provider,configurationBinding,instanceToken,providerPolicyEpoch,webConsentEpoch); }
    bool operator==(const SearchBindingRef &o) const { return values()==o.values(); }
};
struct ConfigurationSnapshot {
    Id128 storeInstance{};
    StorageState storage=StorageState::Uninitialized;
    CredentialState credential=CredentialState::Absent;
    Epochs epochs;
    ConsentReceipt modelConsent,webConsent;
    ModeChoice mode=ModeChoice::Unchosen;
    ServiceUse serviceUse=ServiceUse::Unchosen;
    std::string selectedProfileRef=GeneralProfile;
    std::optional<SearchBindingRef> search;
    std::uint64_t revision=1;
    auto values() const { return std::tie(storeInstance,storage,credential,epochs,modelConsent,webConsent,mode,serviceUse,selectedProfileRef,search,revision); }
    bool operator==(const ConfigurationSnapshot &o) const { return values()==o.values(); }
};
struct NetworkActivationSnapshot {
    ActivationCause cause=ActivationCause::EntitlementMissing;
    EvidenceState entitlementState=EvidenceState::Missing;
    std::string profileRef=GeneralProfile;
    Digest256 destinationModelModeBinding{},entitlementRevisionBinding{};
    Epochs epochs;
    bool technicallyAvailable=false;
};
struct ConfigurationMutation {
    ConfigurationVerb verb=ConfigurationVerb::Mode;
    ConsentTarget target=ConsentTarget::Model;
    ConsentReceipt receipt;
    ModeChoice mode=ModeChoice::Manual;
    ServiceUse serviceUse=ServiceUse::Unchosen;
    std::string profileRef;
    std::uint32_t profileRevision=1;
    std::optional<SearchBindingRef> search;
};
struct ConfigurationIntent { Id128 capability{}; std::uint64_t revision=0; ConfigurationVerb verb=ConfigurationVerb::Mode; };
struct MutationResult { ConfigFailure failure=ConfigFailure::None; ConfigurationSnapshot snapshot; std::uint32_t primaryError=0; };
template<class T> bool nonzero(const T &v) { for(auto b:v) if(b) return true; return false; }
bool validReceipt(const ConsentReceipt &,bool update=false);
bool validSearch(const SearchBindingRef &,bool update=false);
bool validSnapshot(const ConfigurationSnapshot &);
Digest256 digest(const std::string &domain,const unsigned char *bytes,std::size_t size);
}
