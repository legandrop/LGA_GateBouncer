#include "runtime_ii.h"
#include <algorithm>
#include <cstring>
namespace gb::decisions {
Frame NativeRuntime::outcomeResult(const Id &id, const PrincipalOutcome &outcome, Type type) const {
    auto response = principalResult(id, outcome.result, type);
    if (outcome.scope >= 3) response.fields.push_back(value(Tag::ScopeKind, outcome.scope, 1));
    std::sort(response.fields.begin(), response.fields.end(), [](const auto &a, const auto &b) { return a.tag < b.tag; });
    return response;
}
directional::Result NativeRuntime::writeScoped(const principal::Entry &command,
    const std::shared_ptr<PrincipalAdmission> &admission, GB_SCOPE_DECISION &retained) {
    directional::Result result;
    if (!admission || admission->consumed || !admission->event || !admission->event->classifier_ ||
        !principalClassifier_ || !principalAdmissionCurrent(*admission, command) ||
        !scopedJournal_.load() || scopedJournal_.uncertain() || scopedJournal_.revision() == UINT64_MAX)
        return result;
    auto cause = admission->event->classifier_;
    if (cause->owner_ != principalClassifier_ || !cause->current() ||
        !principalClassifier_->filterCurrent(*cause, backend_.engine_)) return result;
    ScopedEntry entry;
    entry.command = command.command.id; entry.epoch = epoch_; entry.boot = boot_;
    entry.payload = command.command.payload; entry.account = admission->identity.account;
    entry.logon = admission->identity.logon; entry.session = admission->identity.session;
    entry.pid = admission->actor.pid;
    entry.created = std::uint64_t(admission->actor.created.dwLowDateTime) |
        (std::uint64_t(admission->actor.created.dwHighDateTime) << 32);
    auto &decision = entry.kernel.decision;
    decision.version = GB_CLASSIFIER_VERSION; decision.bytes = sizeof(decision);
    decision.session = cause->record_.session; decision.cause = cause->record_.cause;
    decision.revision = scopedJournal_.revision() + 1;
    std::copy(entry.command.begin(), entry.command.end(), decision.command);
    decision.scope = admission->scope; decision.durationMs = admission->durationMs;
    Frame frame;
    if (decode(entry.payload, frame) != Error::Ok) return result;
    decision.action = static_cast<UINT32>(get(frame, Tag::Decision));
    entry.kernel.state = GB_SCOPE_PENDING;
    retained = decision; result.desired = decision.revision;
    // Prepared queda físicamente confirmado antes de tocar la operación retenida.
    if (!scopedJournal_.prepare(entry)) { result.error = Error::StoreFailure; return result; }
    result.state = State::Prepared; result.observed = directional::Observed::Prepared;
    result.durable = true; result.error = Error::Ok;
    profile_.refresh();
    if (!principalAdmissionCurrent(*admission, command) || !cause->current() ||
        !principalClassifier_->filterCurrent(*cause, backend_.engine_)) return result;
    admission->consumed = true;
    GB_SCOPE_RECEIPT dispatched{};
    // Una entrega incierta sólo se consulta: jamás se vuelve a mandar DECIDE.
    if (!principalClassifier_->decide(decision, dispatched)) return result;
    GB_SCOPE_RECEIPT observed{};
    if (!principalClassifier_->readback(decision, observed) || !observed.applied) return result;
    result.state = State::AppliedUnrecorded; result.appliedReal = true;
    result.durable = false; result.error = Error::StoreFailure;
    if (scopedJournal_.complete(entry.command, observed)) {
        result.state = State::Applied; result.durable = true; result.error = Error::Ok;
        result.observed = directional::Observed::FinalApplied;
    }
    return result;
}
void NativeRuntime::refreshScoped(PrincipalOutcome &outcome) noexcept {
    if (outcome.scope < 3 || outcome.result.state != State::Prepared || !outcome.scoped.revision ||
        !principalClassifier_ || scopedJournal_.uncertain()) return;
    try {
        GB_SCOPE_RECEIPT observed{};
        if (!principalClassifier_->readback(outcome.scoped, observed) || !observed.applied) return;
        outcome.result.state = State::AppliedUnrecorded; outcome.result.appliedReal = true;
        outcome.result.durable = false; outcome.result.error = Error::StoreFailure;
        Id id{}; std::copy(std::begin(outcome.scoped.command), std::end(outcome.scoped.command), id.begin());
        if (scopedJournal_.complete(id, observed)) {
            outcome.result.state = State::Applied; outcome.result.durable = true;
            outcome.result.error = Error::Ok; outcome.result.observed = directional::Observed::FinalApplied;
        }
    } catch (...) { outcome.result.error = Error::StoreFailure; }
}
}
