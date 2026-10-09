#pragma once
#include "coordinator_iii.h"

namespace gb::directional {
class SnapshotJournal final : public decisions::JournalSink {
  public:
    SnapshotJournal(SnapshotCoordinator &coordinator, SelectorRegistry &registry)
        : coordinator_(coordinator), registry_(registry) {}
    bool persist(const std::vector<decisions::CommandEntry> &entries) override;
    Error admission(const Frame &command) const override;
    bool suspendsMutations() const override { return coordinator_.recovery(); }
    Id pinnedCommand() const override { return coordinator_.snapshot().active; }

  private:
    SnapshotCoordinator &coordinator_;
    SelectorRegistry &registry_;
};
class SnapshotEffects final : public decisions::EffectBackend {
  public:
    explicit SnapshotEffects(SnapshotCoordinator &coordinator, DirectionalBackend &backend)
        : coordinator_(coordinator), backend_(backend) {}
    bool ready() const override;
    bool commit(const Frame &command) override;
    bool readback(std::uint64_t revision) override {
        return coordinator_.currentReadback(revision);
    }
    bool currentProof(std::uint64_t revision) override {
        return coordinator_.currentReadback(revision);
    }
    bool actualOs() const override { return backend_.actualOs(); }

  private:
    SnapshotCoordinator &coordinator_;
    DirectionalBackend &backend_;
};
} // namespace gb::directional
