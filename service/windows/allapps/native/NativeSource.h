#pragma once
#include "NativeSdk.h"
#include "NativeShape.h"
#include "NativeLifecycle.h"
#include "../../../../common/wire_v1.h"

namespace gb::decisions { class NativeRuntime; }
namespace gatebouncer::service::windows::allapps::native {
class NativeSource;
class EngineLease {
    friend class gb::decisions::NativeRuntime;
    friend class NativeSource;
    EngineLease(HANDLE, std::shared_ptr<void>);
    HANDLE engine_;
    std::shared_ptr<void> lifetime_;
};
class BindReceipt {
    friend class gb::decisions::NativeRuntime;
    friend class NativeSource;
    BindReceipt(gb::wire::Id, std::uint64_t);
    const gb::wire::Id epoch_;
    const std::uint64_t generation_;
};
class BindingState {
    friend class NativeSource;
    BindingState(gb::wire::Id e, std::uint64_t i, std::uint64_t g) : epoch(e), index(i), generation(g) {}
public:
    const gb::wire::Id epoch;
    const std::uint64_t index, generation;
};
struct CatalogEntry {
    FilterShape shape;
    Role role = Role::Unknown;
    gb::wire::Id rule{};
    std::uint64_t generation = 0, desired = 0;
    std::uint8_t originalFlow = 0, origin = 0, direction = 0, mode = 0;
};
class CatalogReceipt {
    friend class gb::decisions::NativeRuntime;
    friend class NativeSource;
    CatalogReceipt(std::shared_ptr<const BindingState>, std::uint64_t, std::vector<CatalogEntry>);
    const std::shared_ptr<const BindingState> binding_;
    const std::uint64_t revision_;
    const std::shared_ptr<const std::vector<CatalogEntry>> entries_;
};
class RecoveryReceipt {
    friend class gb::decisions::NativeRuntime;
    friend class NativeSource;
    RecoveryReceipt(std::shared_ptr<const BindingState> b, std::uint64_t r) : binding_(std::move(b)), revision_(r) {}
    const std::shared_ptr<const BindingState> binding_;
    const std::uint64_t revision_;
};
class NativeCopiedMetadata {
    friend class NativeSource;
    NativeCopiedMetadata(OwnedNetEvent e, std::shared_ptr<const BindingState> b) : event_(std::move(e)), binding_(std::move(b)) {}
    OwnedNetEvent event_;
    std::shared_ptr<const BindingState> binding_;
public:
    const OwnedNetEvent& owned() const noexcept { return event_; }
};
enum class Coverage : std::uint8_t { UnprovenReadAccessibleOnly };
class NativeProof {
    friend class NativeSource;
    NativeProof(std::shared_ptr<const BindingState> b, Stamp s, std::uint64_t loss, CurrentView v)
        : binding_(std::move(b)), stamp_(s), loss_(loss), view_(std::move(v)) {}
    std::shared_ptr<const BindingState> binding_;
    Stamp stamp_;
    std::uint64_t loss_;
    CurrentView view_;
public:
    Coverage coverage() const noexcept { return Coverage::UnprovenReadAccessibleOnly; }
    const CurrentView& currentShape() const noexcept { return view_; }
};
struct ProofOutcome { Reason reason = Reason::None; std::optional<NativeProof> proof; };
class NativeSource : public std::enable_shared_from_this<NativeSource> {
    friend class gb::decisions::NativeRuntime;
    NativeSource(EngineLease, BindReceipt, SdkApi = systemSdk());
    static void CALLBACK callback(void*, const FWPM_NET_EVENT3*) noexcept;
    void emit(const FWPM_NET_EVENT3*) noexcept;
    void cancel(HANDLE);
    void finalize();
    bool valid(const NativeCopiedMetadata&) const noexcept;
    Reason readInventory(const CatalogReceipt&);
    Reason reconcile(const CatalogReceipt&);
    bool readOptions();
    EngineLease engine_;
    SdkApi sdk_;
    const std::shared_ptr<const BindingState> binding_;
    SourceState source_;
    BoundedQueue queue_;
    Lifecycle control_;
    std::array<SdkWorkspace, MaxCopiers> pool_{};
    std::array<std::atomic<bool>, MaxCopiers> slots_{};
    std::atomic<unsigned> callbacks_{0};
    std::atomic<bool> seen_{false}, admission_{false}, poisoned_{false};
    std::atomic<std::uint32_t> keywords_{0};
    std::shared_ptr<NativeSource> retained_;
public:
    Reason start(const CatalogReceipt&) noexcept;
    Stage stop() noexcept;
    Stage stage() const noexcept;
    std::optional<NativeCopiedMetadata> takeCopied() noexcept;
    ProofOutcome readCurrentProof(const NativeCopiedMetadata&, const CatalogReceipt&) noexcept;
    bool recover(const RecoveryReceipt&) noexcept;
    EvidenceOutcome evaluate(const NativeCopiedMetadata&, const NativeProof&, ai::SidFormatter&) const noexcept;
};
} // namespace gatebouncer::service::windows::allapps::native
