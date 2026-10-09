#pragma once
#include "../../../../common/wire_v1.h"
#include "NativeCatalog.h"
#include "NativeLifecycle.h"
#include "NativeSdk.h"
#include "NativeShape.h"

namespace gb::decisions
{
class NativeRuntime;
class MaintenanceRuntime;
}
namespace gatebouncer::service::windows::allapps::native
{
class NativeSource;
class EngineLease
{
    friend class gb::decisions::NativeRuntime;
    friend class NativeSource;
    EngineLease(HANDLE, std::shared_ptr<void>);
    HANDLE engine_;
    std::shared_ptr<void> lifetime_;
};
class BindReceipt
{
    friend class gb::decisions::NativeRuntime;
    friend class NativeSource;
    BindReceipt(gb::wire::Id, std::uint64_t);
    const gb::wire::Id epoch_;
    const std::uint64_t generation_;
};
class BindingState
{
    friend class NativeSource;
    friend class gb::decisions::MaintenanceRuntime;
    BindingState(gb::wire::Id e, std::uint64_t i, std::uint64_t g) : epoch(e), index(i), generation(g)
    {
    }

  public:
    const gb::wire::Id epoch;
    const std::uint64_t index, generation;
};
class CatalogReceipt
{
    friend class gb::decisions::NativeRuntime;
    friend class NativeSource;
    explicit CatalogReceipt(std::shared_ptr<const CatalogSnapshot>);
    const std::shared_ptr<const BindingState> binding_;
    const std::uint64_t revision_;
    const std::shared_ptr<const CatalogSnapshot> snapshot_;
};
class RecoveryReceipt
{
    friend class gb::decisions::NativeRuntime;
    friend class NativeSource;
    RecoveryReceipt(std::shared_ptr<const BindingState> b, std::shared_ptr<const CatalogSnapshot> s,
                    std::uint64_t inventory, std::uint64_t loss)
        : binding_(std::move(b)), snapshot_(std::move(s)), inventory_(inventory), revision_(loss)
    {
    }
    const std::shared_ptr<const BindingState> binding_;
    const std::shared_ptr<const CatalogSnapshot> snapshot_;
    const std::uint64_t inventory_;
    const std::uint64_t revision_;
};
class NativeCopiedMetadata
{
    friend class NativeSource;
    NativeCopiedMetadata(OwnedNetEvent e, std::shared_ptr<const BindingState> b,
                         std::shared_ptr<const CatalogSnapshot> s)
        : event_(std::move(e)), binding_(std::move(b)), snapshot_(std::move(s))
    {
    }
    OwnedNetEvent event_;
    std::shared_ptr<const BindingState> binding_;
    std::shared_ptr<const CatalogSnapshot> snapshot_;

  public:
    const OwnedNetEvent &owned() const noexcept
    {
        return event_;
    }
};
enum class Coverage : std::uint8_t
{
    UnprovenReadAccessibleOnly
};
class NativeProof
{
    friend class NativeSource;
    NativeProof(std::shared_ptr<const BindingState> b, std::shared_ptr<const CatalogSnapshot> catalog, Stamp s,
                std::uint64_t loss, CurrentView v)
        : binding_(std::move(b)), snapshot_(std::move(catalog)), stamp_(s), loss_(loss), view_(std::move(v))
    {
    }
    std::shared_ptr<const BindingState> binding_;
    std::shared_ptr<const CatalogSnapshot> snapshot_;
    Stamp stamp_;
    std::uint64_t loss_;
    CurrentView view_;

  public:
    Coverage coverage() const noexcept
    {
        return Coverage::UnprovenReadAccessibleOnly;
    }
    const CurrentView &currentShape() const noexcept
    {
        return view_;
    }
};
struct ProofOutcome
{
    Reason reason = Reason::None;
    std::optional<NativeProof> proof;
};
class NativeSource : public std::enable_shared_from_this<NativeSource>
{
    friend class gb::decisions::NativeRuntime;
    NativeSource(EngineLease, BindReceipt, SdkApi = systemSdk());
    static void CALLBACK callback(void *, const FWPM_NET_EVENT3 *) noexcept;
    void emit(const FWPM_NET_EVENT3 *) noexcept;
    void cancel(HANDLE);
    void finalize();
    bool valid(const NativeCopiedMetadata &) const noexcept;
    void publishCatalog(const CatalogReceipt &);
    bool pushCopied(NativeCopiedMetadata &&) noexcept;
    void clearCopied() noexcept;
    Reason readInventory(const CatalogReceipt &);
    Reason readInventory(HANDLE, const CatalogReceipt &);
    bool retainedCause(const NativeCopiedMetadata &, const NativeProof &,
                       const CatalogReceipt &, Stage) const noexcept;
    Reason reconcile(const CatalogReceipt &);
    bool readOptions();
    bool prerequisites();
    EngineLease engine_;
    SdkApi sdk_;
    const std::shared_ptr<const BindingState> binding_;
    SourceState source_;
    std::shared_ptr<const CatalogSnapshot> catalog_;
    std::mutex queueMutex_;
    std::array<std::optional<NativeCopiedMetadata>, MaxRecords> queue_{};
    std::size_t queueHead_ = 0, queueCount_ = 0, queueBytes_ = 0;
    Lifecycle control_;
    std::array<SdkWorkspace, MaxCopiers> pool_{};
    std::array<std::atomic<bool>, MaxCopiers> slots_{};
    std::atomic<unsigned> callbacks_{0};
    std::atomic<bool> seen_{false}, admission_{false}, poisoned_{false};
    std::atomic<std::uint32_t> keywords_{0};
    std::shared_ptr<NativeSource> retained_;

  public:
    Reason start(const CatalogReceipt &) noexcept;
    Stage stop() noexcept;
    Stage stage() const noexcept;
    std::optional<NativeCopiedMetadata> takeCopied() noexcept;
    ProofOutcome readCurrentProof(const NativeCopiedMetadata &, const CatalogReceipt &) noexcept;
    std::vector<ProofOutcome> readCurrentProofBatch(const NativeCopiedMetadata *const *, std::size_t,
                                                    const CatalogReceipt &) noexcept;
    bool recover(const RecoveryReceipt &) noexcept;
    EvidenceOutcome evaluate(const NativeCopiedMetadata &, const NativeProof &, ai::SidFormatter &) const noexcept;
};
} // namespace gatebouncer::service::windows::allapps::native
