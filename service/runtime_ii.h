#pragma once
#include "../common/pipe_ii_win.h"
#include "collector_ii.h"
#include "effects_ii.h"
#include "engine_resource_iv.h"
#include "catalog_plan_iv.h"
#include "store_iv.h"
#include "windows/allapps/native/NativeSource.h"
#include "journal_iii.h"
#include "wfp_backend.h"
namespace gb::decisions {
class NativeRuntime {
  public:
    NativeRuntime(WfpBackend &backend, SelectorRegistry &registry,
                  std::filesystem::path store, Bytes account, Id epoch, Id boot);
    ~NativeRuntime();
    bool initialize();
    ServiceContext serviceContext() const;
    void tick();
    Frame status(Type type, std::uint16_t minor = 2) const;
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
    mutable std::mutex mutex;

  private:
    struct PrincipalAdmission;
    bool principalActorCurrent(const PrincipalAdmission &) const noexcept;
    directional::Result writePrincipal(const principal::Snapshot &, const principal::Entry &,
        const std::shared_ptr<PrincipalAdmission> &);
    bool principalAdmissionCurrent(const PrincipalAdmission &, const principal::Entry &,
        allnative::Stage requiredStage = allnative::Stage::Active) const noexcept;
    std::map<Id, std::shared_ptr<PrincipalAdmission>> principalAdmissions_;
    bool principalWriteFault_ = false;
    std::uint64_t principalDesired_ = 0;
    std::vector<ii::RuleRecord> rules() const;
    Frame error(Error error) const;
    ServiceContext readServiceContext() const noexcept;
    bool acquireObservationEngine();
    bool loadPrincipalImage();
    bool bindPrincipalObservation(CatalogPlanBuilder &);
    void retirePrincipalObservation() noexcept;
    std::shared_ptr<EngineResource> observationEngine_;
    std::shared_ptr<EngineResource> retainedEngineFault_;
    std::uint64_t observationGeneration_ = 0;
    directional::NativeSnapshotFile file_;
    allnative::CatalogRegistry catalogRegistry_;
    std::unique_ptr<principal::SnapshotStore> principalStore_;
    principal::StoreRead principalRead_;
    std::shared_ptr<allnative::NativeSource> principalSource_;
    std::shared_ptr<const allnative::CatalogSnapshot> principalCatalog_;
    std::uint64_t inventoryRevision_ = 0;
    bool principalMode_ = false;
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
