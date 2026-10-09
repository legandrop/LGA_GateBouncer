#pragma once
#include "../common/wire_ii.h"
#include <deque>
#include <optional>

namespace gb::controller {
using namespace wire;
struct Binding {
    Id epoch{}, boot{}, request{}, selector{};
    std::uint64_t profile = 0, authority = 0, selectorRevision = 0, desired = 0, generation = 0;
    std::uint8_t decision = 0;
    bool remember = false;
    std::uint16_t minor = 1;
    std::uint8_t direction = 3, mode = 0, origin = 0;
};
class ReviewState {
  public:
    void session(Id epoch, Id boot, std::uint64_t profile, bool authenticated, std::uint16_t minor = 1);
    bool enqueue(Id epoch, Id request, std::uint64_t profile);
    bool selectLocal(const ii::PendingRecord &record);
    bool allInputReleased(std::uint64_t generation);
    bool reviewPress(std::uint64_t generation, bool autorepeat);
    bool reviewRelease(std::uint64_t generation);
    bool chooseLocal(std::uint64_t generation, std::uint8_t action, bool remember,
                     bool explicitPathScope, std::uint8_t direction = 3, bool explicitBoth = false);
    std::optional<Binding> binding() const;
    std::optional<Frame> confirm(const Binding &captured, const Id &commandId);
    bool refresh(const ii::PendingRecord &record);
    void cancel();
    void discardChoice();
    void commandFinished();
    std::uint64_t generation() const { return generation_; }
    std::optional<Id> active() const {
        return active_ ? std::optional<Id>(active_->request) : std::nullopt;
    }
    std::size_t queued() const { return queue_.size(); }

  private:
    void barrier();
    bool same(const Binding &a, const Binding &b) const;
    Id epoch_{}, boot_{};
    std::uint64_t profile_ = 0, generation_ = 1;
    std::uint16_t minor_ = 1;
    bool authenticated_ = false, released_ = false, pressed_ = false, reviewed_ = false,
         busy_ = false;
    std::optional<ii::PendingRecord> active_;
    std::optional<Binding> choice_;
    std::deque<Id> queue_;
};
} // namespace gb::controller
