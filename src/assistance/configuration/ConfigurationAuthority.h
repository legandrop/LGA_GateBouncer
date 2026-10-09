#pragma once
#include "ConfigurationController.h"
#include "ConfigurationPolicy.h"
#include <atomic>
#include <mutex>

namespace Gate::Assistance::Configuration::Detail {
struct EntitlementState;
struct ProviderRecord {
    std::string profile=GeneralProfile,model="nvidia/nemotron-3-ultra-550b-a55b";
    std::uint32_t profileRevision=1;
    Modality modality=Modality::HostedOperational;
    EvidenceState evidence=EvidenceState::Restricted;
    Digest256 destination{},evidenceRevision{},scope{};
    Id128 accountScope{},evidenceId{};
    std::uint64_t notBefore=0,notAfter=0;
    ConsentReceipt notice;
    auto values() const {return std::tie(profile,model,profileRevision,modality,evidence,destination,evidenceRevision,scope,accountScope,evidenceId,notBefore,notAfter,notice);}
    bool operator==(const ProviderRecord &o) const {return values()==o.values();}
};
struct Authority {
    mutable std::mutex mutex;
    ConfigurationSnapshot snapshot;
    Id128 incarnation{},connection{},capability{},pendingTicket{};
    ConfigurationVerb capabilityVerb=ConfigurationVerb::Mode;
    std::uint64_t capabilityExpiry=0,committedRevision=0,transitionBarrier=1;
    bool alive=true,failureLatched=false;
    std::function<bool()> ordinary;
    ProviderRecord provider;
    std::optional<ConfigurationSnapshot> observedRecord;
    std::optional<SearchBindingRef> currentSearch;
    ConsentReceipt searchNotice;
    std::shared_ptr<EntitlementState> entitlement;
};
struct MutationData {
    std::weak_ptr<Authority> authority;
    Id128 ticket{};
    ConfigurationSnapshot candidate;
    std::optional<ConfigurationSnapshot> precedent;
    std::uint64_t precedentRevision=0;
    std::uint64_t committedRevision=0;
    ConfigurationVerb verb=ConfigurationVerb::Mode;
    bool failureLatchedAtBegin=false;
    Broker::SensitiveBytes secret;
};
struct AuthorityImage {
    ConfigurationSnapshot snapshot;
    Id128 incarnation{},connection{};
    std::uint64_t committedRevision=0,barrier=0;
    bool alive=false,latched=false;
    ProviderRecord provider;
    std::optional<SearchBindingRef> search;
    ConsentReceipt searchNotice;
    bool operator==(const AuthorityImage &o) const {
        return snapshot==o.snapshot&&incarnation==o.incarnation&&connection==o.connection&&committedRevision==o.committedRevision&&barrier==o.barrier&&alive==o.alive&&latched==o.latched&&provider==o.provider&&search==o.search&&searchNotice==o.searchNotice;
    }
};
struct PermitLease {
    std::weak_ptr<Authority> authority;
    AuthorityImage image;
    Digest256 binding{},seal{},privateDigest{};
    std::uint64_t deadline=0,serial=0;
    std::shared_ptr<const void> record;
    std::function<bool()> currentApproval;
    std::atomic<bool> consumed{false};
};
AuthorityImage image(const Authority &);
ActivationCause availability(const AuthorityImage &,std::uint64_t utc);
bool advance(Authority &);
void revokeReceipts(ConfigurationSnapshot &);
ProviderRecord nvidiaTrial();
const std::string &trialModelNoticeBody();
}
