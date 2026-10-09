#include "effects_ii.h"
namespace gb::decisions {
bool NativeEffects::ready() const {
    auto s = coordinator_.status();
    return s.state == EngineState::ReadyUnvalidated && s.effectiveKnown && s.effective == s.desired;
}
bool NativeEffects::commit(const Frame &f) {
    Frame p;
    Bytes canonical;
    if (!projectPermanent(f, p, canonical))
        return false;
    auto outcome = coordinator_.mutate(p, true);
    journal_.observedDesired(outcome.status.desired);
    return outcome.state == State::Applied && outcome.error == Error::Ok &&
           outcome.status.effectiveKnown && outcome.status.effective == outcome.status.desired;
}
bool NativeEffects::readback(std::uint64_t revision) {
    auto s = coordinator_.status();
    if (s.state != EngineState::ReadyUnvalidated || !s.effectiveKnown || s.desired != revision ||
        s.effective != revision)
        return false;
    journal_.observedDesired(s.desired);
    return true;
}
bool NativeEffects::proveApplied(const CommandEntry &e) {
    Frame f, p;
    Bytes canonical;
    if (decode(e.payload, f) != Error::Ok || !projectPermanent(f, p, canonical))
        return false;
    auto s = coordinator_.snapshot();
    return s.command == e.id && s.commandDigest == native::digest(canonical) &&
           s.desired == e.desired && s.state == State::Applied && s.effectiveKnown &&
           s.effective == e.desired && readback(e.desired);
}
} // namespace gb::decisions
