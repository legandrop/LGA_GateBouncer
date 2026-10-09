#pragma once
#include "../common/wire_ii.h"
#include <deque>
#include <map>
#include <optional>

namespace gb::decisions {
using namespace wire;
// Una instancia por conexión autenticada; caller OS fija epoch/profile y los IDs.
class Pages {
  public:
    Pages(Id epoch, std::uint64_t profile) : epoch_(epoch), profile_(profile) {}
    Error rules(Id snapshot, const std::vector<ii::RuleRecord> &rows, std::uint64_t revision,
                std::uint64_t now);
    Error pending(Id snapshot, const std::vector<ii::PendingRecord> &rows, std::uint64_t revision,
                  std::uint64_t now);
    Error page(const Frame &request, std::uint64_t profile, std::uint64_t now, Frame &reply);
    void invalidate() {
        snapshots_.clear();
    }

  private:
    struct Snapshot {
        bool rules = false;
        std::uint64_t revision = 0, deadline = 0;
        std::uint32_t next = 0;
        std::vector<Bytes> records;
    };
    Error insert(Id id, bool rules, std::uint64_t revision, std::uint64_t now, std::vector<Bytes> records);
    void expire(std::uint64_t now);
    Id epoch_;
    std::uint64_t profile_;
    std::map<Id, Snapshot> snapshots_;
};
class ObservationRing {
  public:
    explicit ObservationRing(Id epoch, std::uint64_t profile) : epoch_(epoch), profile_(profile) {}
    Error append(const Frame &event);
    Error after(std::uint64_t sequence, std::uint32_t mask, std::vector<Frame> &events,
                bool &clientGap) const;
    std::uint64_t latest() const {
        return sequence_;
    }
    std::size_t size() const {
        return events_.size();
    }
    void invalidate(std::uint64_t profile) {
        profile_ = profile;
        lostThrough_ = sequence_;
        events_.clear();
    }

  private:
    Id epoch_;
    std::uint64_t profile_, sequence_ = 0, lostThrough_ = 0;
    std::deque<Frame> events_;
};
} // namespace gb::decisions
