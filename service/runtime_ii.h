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
#include "native_activity_ring.h"
#include "scopes_v.h"
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
        bool administrative = false;
    };
    struct PrincipalPeer {
        native::ProcessEvidence actor;
        native::TokenEvidence identity;
        native::Handle pipe;
        native::Handle image;
        native::Handle administrativePrimary;
        std::unique_ptr<native::ProtectedDirectory> directory;
        BY_HANDLE_FILE_INFORMATION imageId{};
        Id connection{};
        std::uint64_t profile = 0;
        std::map<Id, PrincipalPage> pages;
        struct RulePage {
            principal::ByteView snapshot;
            std::uint64_t desired=0;
            std::vector<std::size_t> indices;
            std::shared_ptr<allnative::NativeSource> source;
            std::shared_ptr<const allnative::CatalogSnapshot> catalog;
            ServiceContext context;
            std::uint64_t profile=0, deadline=0;
            std::uint32_t next=0;
            bool administrative=false;
        };
        std::map<Id,RulePage> rulePages;
        bool cancelled = false;
        bool readonly = false;
        bool administrative = false;
        std::uint32_t subscriptionMask=0;
        NativeActivityRing administrativeEvents;
        bool administrativeTraffic=false, administrativeProcesses=false;
        std::filesystem::path admittedImage;
    };
    struct PrincipalObservation;
    struct PrincipalOutcome;
    struct PrincipalProcessRetainer;
    struct PrincipalFileCapture {
        native::ProcessEvidence actor;
        native::TokenEvidence identity;
        native::Handle primary, image, stop;
        std::vector<native::Handle> directories;
        std::vector<std::filesystem::path> paths;
        std::vector<BY_HANDLE_FILE_INFORMATION> directoryIds;
        std::filesystem::path path;
        BY_HANDLE_FILE_INFORMATION imageId{};
        principal::ByteView target;
        Bytes targetSid;
        wire::iv::Display display;
        std::atomic<bool> cancelled{false};
        bool completed=false;
        std::size_t charged=0;
        std::uint64_t deadline=0;
    };
    struct PrincipalAdmission {
        Id request{}, binding{};
        std::uint64_t revision = 0, profile = 0;
        Digest target{};
        std::shared_ptr<allnative::NativeSource> source;
        std::optional<allnative::NativeCopiedMetadata> event;
        std::optional<allnative::NativeProof> proof;
        std::optional<principal::Rule> revocation;
        std::shared_ptr<PrincipalFileCapture> file;
        std::optional<principal::Rule> replacing;
        std::uint64_t targetRevision=1;
        native::ProcessEvidence actor;
        native::TokenEvidence identity;
        std::shared_ptr<PrincipalPeer> owner;
        Bytes selectedSid;
        bool administrative=false;
        Id observed{}, selector{}, challenge{};
        std::uint64_t observedRevision = 0, expectedDesired = 0, deadline = 0;
        principal::ByteView fullTarget;
        std::uint8_t direction = 0, package = 0;
        std::uint8_t scope = 2;
        std::uint32_t durationMs = 0;
        GB_SCOPE_DECISION cancelledDecision{};
        Frame activityAttempt;
        std::shared_ptr<PrincipalPeer> activityPeer;
        std::uint64_t activitySession = 0, activityCause = 0;
        bool cancelSealed = false;
        bool consumed = false, cancelled = false;
    };
    void collectPrincipalObservations();
    NativeActivityRing &principalEventsFor(PrincipalPeer *) noexcept;
    const NativeActivityRing &principalEventsFor(const PrincipalPeer *) const noexcept;
    bool principalEventsReady(const PrincipalPeer * = nullptr) const noexcept;
    bool principalEventCurrent(PrincipalPeer &, const Frame &) noexcept;
    Frame subscribePrincipalEvents(const Frame &, const std::shared_ptr<PrincipalPeer> &);
    void publishPrincipalAuthorization(PrincipalOutcome &) noexcept;
    void pollPrincipalTraffic() noexcept;
    bool principalTrafficReady(const PrincipalPeer * = nullptr) const noexcept;
    bool principalProcessReady(const PrincipalPeer * = nullptr) const noexcept;
    void publishPrincipalAttempt(PrincipalObservation &, const GB_PROCESS_IMAGE_FACTS * = nullptr) noexcept;
    void pollPrincipalImages() noexcept;
    void pollPrincipalPendingApp() noexcept;
    void finishPrincipalImages() noexcept;
    void prunePrincipalProcesses() noexcept;
    Frame readPrincipalProcess(const Frame &, const std::shared_ptr<PrincipalPeer> &);
    bool principalProcessCurrent(const PrincipalProcessRetainer &, GB_PROCESS_IMAGE_FACTS &) noexcept;
    bool processBudget(std::size_t extra, std::size_t prior=0) const noexcept;
    static std::size_t activityCauseBytes(const allnative::ClassifierCause &) noexcept;
    void invalidatePrincipalObservations() noexcept;
    void stopPrincipalObservation() noexcept;
    bool ordinaryPeer(HANDLE, std::shared_ptr<PrincipalPeer> &, bool readonly = false,
                      bool administrative = false);
    bool principalPeerCurrent(const PrincipalPeer &) const noexcept;
    bool principalTargetSelected(const Frame &, const PrincipalPeer &, const principal::ByteView &) const noexcept;
    bool principalPolicyReady() const noexcept;
    void closeOrdinaryPeer(const std::shared_ptr<PrincipalPeer> &) noexcept;
    Frame dispatchOrdinary(const Frame &, const std::shared_ptr<PrincipalPeer> &);
    Frame ordinaryStatus(Type, const std::shared_ptr<PrincipalPeer> &) const;
    Frame principalError(Error) const;
    Frame principalResult(const Id &, const directional::Result &, Type = Type::FuturePolicyAck) const;
    Frame preparePrincipal(const Frame &, const std::shared_ptr<PrincipalPeer> &);
    Frame dispatchFileFuture(const Frame &, const std::shared_ptr<PrincipalPeer> &, HANDLE stop);
    Frame fileFutureRecord(const PrincipalAdmission &);
    Frame listPrincipalRules(const Frame &, const std::shared_ptr<PrincipalPeer> &);
    static bool capturePrincipalFile(PrincipalFileCapture &, const Frame &) noexcept;
    static bool principalFileActorCurrent(const PrincipalFileCapture &) noexcept;
    static bool principalFileMetadataCurrent(const PrincipalFileCapture &) noexcept;
    void drainPrincipalFiles() noexcept;
    std::array<std::shared_ptr<PrincipalFileCapture>,64> principalFiles_{};
    std::size_t principalFileBytes_=0,principalFilePhysical_=0;
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
    // Cobrar cada ring completo hasta que su último descriptor original se retire.
    std::array<std::shared_ptr<PrincipalPeer>,64> principalAdministrativePeers_{};
    std::uint64_t principalObservedRevision_ = 0;
    std::size_t principalPendingBytes_ = 0;
    std::unique_ptr<allnative::NativeImageWorker> principalImageWorker_;
    std::size_t principalImageBaseCharge_=0,principalImageJobCharge_=0,principalProcessBytes_=0,principalRetiredBytes_=0;
    std::uint64_t principalImageJobId_=0;
    std::uint64_t principalImageSession_=0,principalImageCause_=0,principalAppDeadline_=0;
    std::size_t principalPendingAppBytes_=0;
    std::size_t principalProcessPhysical_=0;
    bool principalAppCapacityGap_=false;
    bool principalProcessAcquired_=false;
    struct PrincipalProcessRetainer {
        std::shared_ptr<PrincipalPeer> activityPeer;
        Frame attempt;
        std::shared_ptr<allnative::NativeSource> source;
        std::shared_ptr<const allnative::CatalogSnapshot> catalog;
        std::shared_ptr<allnative::ClassifierCause> cause;
        std::optional<allnative::NativeCopiedMetadata> event;
        std::optional<allnative::NativeProof> proof;
        GB_PROCESS_IMAGE_FACTS original{};
        std::size_t charged=0;
        bool retired=false;
    };
    std::map<Id,std::shared_ptr<PrincipalProcessRetainer>> principalProcesses_;
    Id principalProcessCursor_{};
    NativeActivityRing principalEvents_;
    bool principalTrafficAcquired_ = false;
    std::size_t principalMask3Subscribers_=0;
    struct PrincipalTrafficWatcher {
        std::shared_ptr<PrincipalPeer> activityPeer;
        Frame attempt;
        std::shared_ptr<allnative::NativeSource> source;
        std::shared_ptr<const allnative::CatalogSnapshot> catalog;
        std::shared_ptr<allnative::ClassifierCause> cause;
        GB_SCOPE_DECISION decision{};
        GB_ACTIVITY_SNAPSHOT published{};
        std::size_t charged=0;
    };
    std::map<Id,std::shared_ptr<PrincipalTrafficWatcher>> principalTraffic_;
    Id principalTrafficCursor_{};
    std::size_t principalTrafficBytes_=0;
    struct PrincipalOutcome {
        std::shared_ptr<PrincipalPeer> activityPeer;
        Bytes payload;
        directional::Result result;
        native::TokenEvidence identity;
        DWORD pid = 0;
        FILETIME created{};
        BY_HANDLE_FILE_INFORMATION imageId{};
        std::uint64_t profile = 0;
        Type type = Type::CommitFuturePolicy;
        std::uint8_t scope = 2;
        GB_SCOPE_DECISION scoped{};
        Frame activityAttempt;
        std::uint64_t activitySession = 0, activityCause = 0;
        std::shared_ptr<allnative::NativeSource> activitySource;
        std::shared_ptr<const allnative::CatalogSnapshot> activityCatalog;
        std::shared_ptr<allnative::ClassifierCause> activityOwner;
        std::size_t activityCharge=0;
        bool activityCompleted = false;
    };
    std::map<Id, PrincipalOutcome> principalOutcomes_;
    Id principalOutcomeCursor_{};
    std::size_t principalOutcomeBytes_ = 0;
    bool principalActorCurrent(const PrincipalAdmission &) const noexcept;
    directional::Result writeScoped(const principal::Entry &, const std::shared_ptr<PrincipalAdmission> &, GB_SCOPE_DECISION &);
    void refreshScoped(PrincipalOutcome &) noexcept;
    Frame outcomeResult(const Id &, const PrincipalOutcome &, Type = Type::FuturePolicyAck) const;
    directional::Result writePrincipal(const principal::Snapshot &, const principal::Entry &,
        const std::shared_ptr<PrincipalAdmission> &);
    Error readScopedOutcome(const Id &, const std::shared_ptr<PrincipalPeer> &, PrincipalOutcome &, bool &found);
    void pruneScopedOutcomes() noexcept;
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
    std::shared_ptr<allnative::NativeClassifier> principalClassifier_;
    std::shared_ptr<EngineResource> retainedEngineFault_;
    std::uint64_t observationGeneration_ = 0;
    ScopedJournal scopedJournal_;
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
