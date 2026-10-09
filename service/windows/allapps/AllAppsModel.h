#pragma once
#include "AllAppsMetadata.h"
namespace gatebouncer::service::windows::allapps {
using Guid = std::array<std::uint8_t, 16>;
enum class Confirmation : std::uint8_t { Missing, Exact };
enum class Layer : std::uint8_t { Unknown, ConnectV4, ConnectV6, ReceiveV4, ReceiveV6 };
enum class Role : std::uint8_t { Unknown, UnknownAppGate, ExplicitBlock, ExplicitAllow };
enum class Action : std::uint8_t { Unknown, Block, Permit };
struct OwnershipKeys { Guid provider{}, sublayer{}; };
struct CurrentView {
    Stamp reconciled;
    std::uint64_t inventoryRevision = 0, filterId = 0;
    std::uint16_t layerId = 0;
    Guid filterKey{}, provider{}, sublayer{}, layerKey{};
    Layer layer = Layer::Unknown;
    Role role = Role::Unknown;
    Action action = Action::Unknown;
    Confirmation active = Confirmation::Missing, temporal = Confirmation::Missing,
                 conditions = Confirmation::Missing, inventory = Confirmation::Missing,
                 packageCapability = Confirmation::Missing;
    bool reusedId = false;
};
enum class EvidenceState : std::uint8_t { Unknown, Unsupported, Evidence, Candidate };
enum class EvidenceKind : std::uint8_t { None, Attempt, PermittedClassification };
struct Restrictions { bool principalRequired = true, allInstances = true, allSessions = true,
    individualServiceUnknown = true, requiresPackageScopeConsent = false; };
struct EvidenceOutcome {
    EvidenceState state = EvidenceState::Unknown;
    Reason reason = Reason::None;
    EvidenceKind kind = EvidenceKind::None;
    Stamp acquired{};
    std::optional<ai::Result> identity;
    std::optional<CurrentView> provenance;
    Restrictions restrictions;
};
// CurrentView acredita sólo fixtures offline; no es mensaje IPC ni capacidad de Allow.
EvidenceOutcome evaluate(const OwnedNetEvent&, const SourceState&, const OwnershipKeys&,
                         const CurrentView&, ai::SidFormatter&) noexcept;
} // namespace gatebouncer::service::windows::allapps
