#include "AllAppsModel.h"
#include <algorithm>
namespace gatebouncer::service::windows::allapps {
namespace {
bool nonzero(const Guid& id) noexcept
{ return std::any_of(id.begin(), id.end(), [](auto b) { return b != 0; }); }
}
EvidenceOutcome evaluate(const OwnedNetEvent& e, const SourceState& source, const OwnershipKeys& own,
                         const CurrentView& v, ai::SidFormatter& formatter) noexcept
{
    EvidenceOutcome out; out.acquired = e.acquired;
    const auto reject = [&](Reason reason) noexcept { out.reason = reason; return std::move(out); };
    if (e.profile != 3 || (e.type != 3 && e.type != 6)) { out.state = EvidenceState::Unsupported; return reject(Reason::Unsupported); }
    const auto h = source.health();
    if (h.health != Health::Ready || h.lossRevision != e.acquiredLossRevision) return reject(Reason::SourceGap);
    if (!source.current(e.acquired) || !(e.acquired == v.reconciled) ||
        !(e.identity.binding == ai::EventBinding{e.acquired.epoch, e.acquired.sequence})) return reject(Reason::StaleStamp);
    if (v.inventory != Confirmation::Exact || v.active != Confirmation::Exact ||
        v.temporal != Confirmation::Exact || v.conditions != Confirmation::Exact || v.reusedId || !v.inventoryRevision)
        return reject(Reason::Ambiguous);
    if (!nonzero(own.provider) || !nonzero(own.sublayer) || !nonzero(v.filterKey) || !nonzero(v.layerKey) ||
        own.provider != v.provider || own.sublayer != v.sublayer || e.filterId != v.filterId || e.layerId != v.layerId)
        return reject(Reason::ForeignFilter);
    const auto dir = e.type == 3 ? (e.rawDirection == 0x3901 ? Direction::Outbound : e.rawDirection == 0x3900 ? Direction::Inbound : Direction::Unknown)
                               : (e.rawDirection == 0 ? Direction::Outbound : e.rawDirection == 1 ? Direction::Inbound : Direction::Unknown);
    const bool connect = v.layer == Layer::ConnectV4 || v.layer == Layer::ConnectV6;
    const bool receive = v.layer == Layer::ReceiveV4 || v.layer == Layer::ReceiveV6;
    if (dir == Direction::Unknown || dir != e.direction || (!connect && !receive) ||
        (connect && dir != Direction::Outbound) || (receive && dir != Direction::Inbound)) return reject(Reason::InvalidEvent);
    const bool dropRole = v.role == Role::UnknownAppGate || v.role == Role::ExplicitBlock;
    if ((e.type == 3 && (!dropRole || v.action != Action::Block)) ||
        (e.type == 6 && (v.role != Role::ExplicitAllow || v.action != Action::Permit))) return reject(Reason::InvalidEvent);
    try {
        auto identity = ai::attribute(e.identity, formatter);
        if (identity.state != ai::State::Attributed || !identity.target || !identity.scope) return reject(Reason::IdentityFailure);
        if (identity.target->packageSid && v.packageCapability != Confirmation::Exact) return reject(Reason::ScopeUnsupported);
        // Una pérdida/Stop concurrente durante el formatter invalida también el resultado.
        const auto after = source.health();
        if (after.health != Health::Ready || after.lossRevision != e.acquiredLossRevision) return reject(Reason::SourceGap);
        out.restrictions.requiresPackageScopeConsent = !identity.target->packageSid;
        out.kind = e.type == 3 ? EvidenceKind::Attempt : EvidenceKind::PermittedClassification;
        out.state = e.type == 3 && v.role == Role::UnknownAppGate ? EvidenceState::Candidate : EvidenceState::Evidence;
        out.identity.emplace(std::move(identity)); out.provenance.emplace(v);
        return out;
    } catch (...) { return reject(Reason::IdentityFailure); }
}
} // namespace gatebouncer::service::windows::allapps
