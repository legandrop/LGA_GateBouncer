#include "review_state.h"
#include <algorithm>

namespace gb::controller {
void ReviewState::barrier() {
    if (generation_ == UINT64_MAX)
        authenticated_ = false;
    else
        ++generation_;
    released_ = pressed_ = reviewed_ = false;
    choice_.reset();
}
void ReviewState::session(Id epoch, Id boot, std::uint64_t profile, bool auth, std::uint16_t minor) {
    if (epoch_ != epoch || boot_ != boot || profile_ != profile || minor_ != minor || !auth) {
        barrier();
        active_.reset();
        queue_.clear();
        busy_ = false;
    }
    epoch_ = epoch;
    boot_ = boot;
    profile_ = profile;
    minor_ = minor;
    authenticated_ = auth && !zero(epoch) && !zero(boot) && profile != 0 && (minor == 1 || minor == 2);
}
bool ReviewState::enqueue(Id epoch, Id request, std::uint64_t profile) {
    if (!authenticated_ || epoch != epoch_ || profile != profile_ || zero(request))
        return false;
    if ((active_ && active_->request == request) ||
        std::find(queue_.begin(), queue_.end(), request) != queue_.end())
        return true;
    if (queue_.size() == 32)
        return false;
    queue_.push_back(request);
    return true;
}
bool ReviewState::selectLocal(const ii::PendingRecord &record) {
    if (busy_ || !authenticated_)
        return false;
    barrier();
    active_.reset();
    if (!ii::eligible(record, minor_) || record.profileGeneration != profile_)
        return false;
    active_ = record;
    queue_.erase(std::remove(queue_.begin(), queue_.end(), record.request), queue_.end());
    return true;
}
bool ReviewState::allInputReleased(std::uint64_t generation) {
    if (generation != generation_ || !active_ || busy_)
        return false;
    released_ = true;
    return true;
}
bool ReviewState::reviewPress(std::uint64_t generation, bool autorepeat) {
    if (generation != generation_ || !released_ || !active_ || busy_ || autorepeat)
        return false;
    pressed_ = true;
    return true;
}
bool ReviewState::reviewRelease(std::uint64_t generation) {
    if (generation != generation_ || !pressed_ || busy_)
        return false;
    pressed_ = false;
    reviewed_ = true;
    return true;
}
bool ReviewState::chooseLocal(std::uint64_t generation, std::uint8_t action, bool remember,
                              bool pathScope, std::uint8_t direction, bool explicitBoth) {
    if (generation != generation_ || !reviewed_ || !active_ || busy_ || action < 1 || action > 2 ||
        (action == 2 && !remember) || !pathScope || direction < 1 || direction > 3 ||
        (minor_ == 1 && direction != 3) ||
        (minor_ == 2 && ((direction != active_->direction && direction != 3) ||
                         (direction == 3 && !explicitBoth))))
        return false;
    // Cada cambio retira el callback anterior y exige binding recién capturado.
    if (generation_ == UINT64_MAX) {
        cancel();
        return false;
    }
    ++generation_;
    choice_ = Binding{epoch_,
                      boot_,
                      active_->request,
                      active_->selector,
                      profile_,
                      active_->authority,
                      active_->selectorRevision,
                      active_->desired,
                      generation_,
                      action,
                      remember};
    choice_->minor = minor_; choice_->direction = direction; choice_->origin = active_->origin;
    choice_->mode = action == 1 || direction == 2 ? 0 : direction == 1 ? 1 : 2;
    return true;
}
std::optional<Binding> ReviewState::binding() const { return choice_; }
bool ReviewState::same(const Binding &a, const Binding &b) const {
    return a.epoch == b.epoch && a.boot == b.boot && a.request == b.request &&
           a.selector == b.selector && a.profile == b.profile && a.authority == b.authority &&
           a.selectorRevision == b.selectorRevision && a.desired == b.desired &&
           a.generation == b.generation && a.decision == b.decision && a.remember == b.remember &&
           a.minor == b.minor && a.direction == b.direction && a.mode == b.mode && a.origin == b.origin;
}
std::optional<Frame> ReviewState::confirm(const Binding &captured, const Id &command) {
    if (!authenticated_ || busy_ || !choice_ || !same(captured, *choice_) ||
        captured.generation != generation_ || zero(command))
        return {};
    Frame f;
    f.minor = captured.minor;
    f.type = Type::CommitDecision;
    f.connection.fill(1);
    f.correlation = command;
    f.fields = {value(Tag::ServiceEpoch, captured.epoch),
                value(Tag::RequestId, captured.request),
                value(Tag::RequestVersion, captured.authority),
                value(Tag::ExpectedDesiredRev, captured.desired),
                value(Tag::Decision, captured.decision, 1),
                value(Tag::Remember, captured.remember, 1),
                value(Tag::ScopeKind, 1, 1),
                value(Tag::SelectorId, captured.selector),
                value(Tag::SelectorRevision, captured.selectorRevision),
                value(Tag::PolicyDirection, captured.direction, 1),
                value(Tag::ProfileGeneration, captured.profile)};
    if (wire::validate(f) != Error::Ok)
        return {};
    busy_ = true;
    return f;
}
bool ReviewState::refresh(const ii::PendingRecord &r) {
    if (!active_ || r.request != active_->request)
        return false;
    if (!ii::eligible(r, minor_) || r.profileGeneration != profile_ || r.authority != active_->authority ||
        r.selector != active_->selector || r.selectorRevision != active_->selectorRevision ||
        r.desired != active_->desired || r.origin != active_->origin ||
        r.direction != active_->direction || r.recommendedMode != active_->recommendedMode) {
        barrier();
        active_.reset();
        return false;
    }
    // Retry/TTL sólo actualizan observación; no arman ni destruyen intención intacta.
    active_ = r;
    return true;
}
void ReviewState::cancel() {
    barrier();
    active_.reset();
}
void ReviewState::discardChoice() {
    bool reviewed = reviewed_;
    barrier();
    reviewed_ = reviewed;
}
void ReviewState::commandFinished() {
    busy_ = false;
    cancel();
}
} // namespace gb::controller
