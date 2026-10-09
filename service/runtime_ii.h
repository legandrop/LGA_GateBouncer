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
#include "principal_actor_vi.h"
#include "../controller/deployment_win.h"
namespace gb::decisions {
class NativeRuntime {
  public:
    NativeRuntime(WfpBackend &backend, SelectorRegistry &registry,
                  std::filesystem::path store, Bytes account, Id epoch, Id boot,
                  std::filesystem::path ordinaryImage = {},
                  std::shared_ptr<controller::Deployment> deployment = {});
    ~NativeRuntime();
    bool initialize(bool provision = false);
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
    friend class NativeServer;
    struct PrincipalPage {
        std::vector<wire::iv::ObservedRecord> rows;
        Id source{};
        std::uint64_t revision = 0, deadline = 0;
        std::uint32_t next = 0;
    };
    struct PrincipalPeer {
        native::ProcessEvidence actor;
        native::TokenEvidence identity;
        native::Handle pipe;
        native::Handle image;
        std::unique_ptr<native::ProtectedDirectory> directory;
        BY_HANDLE_FILE_INFORMATION imageId{};
        Id connection{};
        std::uint64_t profile = 0;
        std::map<Id, PrincipalPage> pages;
        bool cancelled = false;
        bool readonly = false;
        std::filesystem::path admittedImage;
    };
    struct PrincipalObservation;
    struct PrincipalAdmission {
        Id request{}, binding{};
        std::uint64_t revision = 0, profile = 0;
        Digest target{};
        std::shared_ptr<allnative::NativeSource> source;
        std::optional<allnative::NativeCopiedMetadata> event;
        std::optional<allnative::NativeProof> proof;
        std::optional<principal::Rule> revocation;
        native::ProcessEvidence actor;
        native::TokenEvidence identity;
        std::shared_ptr<PrincipalPeer> owner;
        Id observed{}, selector{}, challenge{};
        std::uint64_t observedRevision = 0, expectedDesired = 0, deadline = 0;
        principal::ByteView fullTarget;
        std::uint8_t direction = 0, package = 0;
        bool consumed = false, cancelled = false;
    };
    void collectPrincipalObservations();
    void invalidatePrincipalObservations() noexcept;
    bool ordinaryPeer(HANDLE, std::shared_ptr<PrincipalPeer> &, bool readonly = false);
    bool principalPeerCurrent(const PrincipalPeer &) const noexcept;
    bool principalPolicyReady() const noexcept;
    void closeOrdinaryPeer(const std::shared_ptr<PrincipalPeer> &) noexcept;
    Frame dispatchOrdinary(const Frame &, const std::shared_ptr<PrincipalPeer> &);
    Frame ordinaryStatus(Type, const std::shared_ptr<PrincipalPeer> &) const;
    Frame principalError(Error) const;
    Frame principalResult(const Id &, const directional::Result &, Type = Type::FuturePolicyAck) const;
    Frame preparePrincipal(const Frame &, const std::shared_ptr<PrincipalPeer> &);
    Frame commitPrincipal(const Frame &, const std::shared_ptr<PrincipalPeer> &);
    std::filesystem::path ordinaryImage_;
    std::shared_ptr<controller::Deployment> deployment_;
    bool provisionRequested_ = false, initialAttempted_ = false;
    bool deploymentCurrent() const noexcept;
    // Sustituciones privadas del owner para bancos SDK; ningún peer/DTO las fija.
    PrincipalActorQuery::Api principalActorApi_;
    bool (*principalImageCheck_)(const PrincipalPeer &, const std::filesystem::path &) noexcept = nullptr;
    decltype(&DuplicateHandle) principalDuplicate_ = &DuplicateHandle;
    decltype(&GetTickCount64) principalNow_ = &GetTickCount64;
    allnative::SdkApi (*principalSdk_)() = &allnative::systemSdk;
    std::map<Id, std::shared_ptr<PrincipalObservation>> principalObservations_;
    std::uint64_t principalObservedRevision_ = 0;
    std::size_t principalPendingBytes_ = 0;
    struct PrincipalOutcome {
        Bytes payload;
        directional::Result result;
        native::TokenEvidence identity;
        DWORD pid = 0;
        FILETIME created{};
        BY_HANDLE_FILE_INFORMATION imageId{};
        std::uint64_t profile = 0;
        Type type = Type::CommitFuturePolicy;
    };
    std::map<Id, PrincipalOutcome> principalOutcomes_;
    std::size_t principalOutcomeBytes_ = 0;
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
    bool provisionPrincipalImage(CatalogPlanBuilder &);
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
    void channel(bool control, HANDLE stop, bool ordinary = false);
    NativeRuntime &runtime_;
};
} // namespace gb::decisions
