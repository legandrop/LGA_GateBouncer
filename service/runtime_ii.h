#pragma once
#include "../common/pipe_ii_win.h"
#include "collector_ii.h"
#include "effects_ii.h"
#include "journal_iii.h"
#include "wfp_backend.h"
namespace gb::decisions {
class NativeRuntime {
  public:
    NativeRuntime(WfpBackend &backend, SelectorRegistry &registry,
                  std::filesystem::path store, Bytes account, Id epoch, Id boot);
    ~NativeRuntime();
    bool initialize();
    void tick();
    Frame status(Type type) const;
    Frame dispatch(const Frame &request, const VerifiedControl &peer, Pages &pages);
    bool peer(HANDLE pipe, bool control, VerifiedControl &evidence, bool activate);
    bool principals(ipc::ii::Principals &principals) const;
    Error events(std::uint64_t after, std::uint32_t mask, std::vector<Frame> &events,
                 bool &gap) const;
    bool clientGap() {
        return collector_.clientGap(profile_.value().generation, profile_.value().state);
    }
    std::uint64_t latest() const { return ring_.latest(); }
    Id epoch() const { return epoch_; }
    std::uint64_t profileGeneration() const { return profile_.value().generation; }
    std::mutex mutex;

  private:
    std::vector<ii::RuleRecord> rules() const;
    Frame error(Error error) const;
    directional::NativeSnapshotFile file_;
    NativeDirections directions_;
    directional::SnapshotCoordinator coordinator_;
    WfpBackend &backend_;
    SelectorRegistry &registry_;
    Id epoch_, boot_;
    directional::SnapshotJournal journal_;
    directional::SnapshotEffects effects_;
    Engine engine_;
    NativeProfile profile_;
    ObservationRing ring_;
    NativeCollector collector_;
    bool loaded_ = false;
};
class NativeServer {
  public:
    explicit NativeServer(NativeRuntime &runtime) : runtime_(runtime) {}
    bool run(HANDLE stop);

  private:
    void channel(bool control, HANDLE stop);
    NativeRuntime &runtime_;
};
} // namespace gb::decisions
