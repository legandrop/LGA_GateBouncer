#pragma once
#include "snapshot_iii.h"
#include <functional>
#include <map>
#include <mutex>

namespace gb::directional {
enum class Observed { Unknown, Prepared, FinalApplied };
struct Result {
    Error error = Error::RecoveryRequired;
    State state = State::RecoveryRequired;
    bool effectiveKnown = false, durable = false, appliedReal = false;
    std::uint64_t desired = 0, effective = 0, observedSequence = 0;
    Observed observed = Observed::Unknown;
};
class SnapshotFile {
  public:
    SnapshotFile() = default;
    SnapshotFile(const SnapshotFile &) = delete;
    SnapshotFile &operator=(const SnapshotFile &) = delete;
    virtual ~SnapshotFile() = default;
    // Exclusión del recurso completo, no un flag reutilizable por otro coordinator.
    virtual bool claimWriter(const void *) { return false; }
    virtual void releaseWriter(const void *) noexcept {}
    virtual bool read(Bytes &policy, bool &exists) = 0;
    virtual bool readLegacyJournal(Bytes &journal, bool &exists) = 0;
    virtual bool replace(const Bytes &policy) = 0;
    virtual bool compare(const std::uint8_t *,std::size_t,bool &,bool &) { return false; }
    virtual bool replaceView(const std::uint8_t *,std::size_t) { return false; }
};
class NativeSnapshotFile final : public SnapshotFile {
  public:
    explicit NativeSnapshotFile(std::filesystem::path root) : directory_(std::move(root)) {}
    bool claimWriter(const void *owner) override;
    void releaseWriter(const void *owner) noexcept override;
    bool read(Bytes &bytes, bool &exists) override;
    bool readLegacyJournal(Bytes &bytes, bool &exists) override;
    bool replace(const Bytes &bytes) override;
    bool compare(const std::uint8_t *bytes,std::size_t size,bool &matches,bool &exists) override;
    bool replaceView(const std::uint8_t *bytes,std::size_t size) override;

  private:
    native::ProtectedDirectory directory_;
    native::Handle lease_;
    std::mutex leaseMutex_;
    const void *owner_ = nullptr;
};
class DirectionalBackend {
  public:
    virtual ~DirectionalBackend() = default;
    virtual bool ready() const = 0;
    virtual bool apply(const std::vector<Rule> &rules, std::uint64_t revision) = 0;
    virtual bool matches(const std::vector<Rule> &rules, std::uint64_t revision) = 0;
    virtual bool actualOs() const { return false; }
};
// Un solo lock posee tabla, journal, secuencia y clasificación del activo observado.
class SnapshotCoordinator {
  public:
    SnapshotCoordinator(SnapshotFile &file, DirectionalBackend &backend, SelectorRegistry &registry,
                        Id epoch, std::function<std::uint64_t()> monotonic = {});
    ~SnapshotCoordinator();
    bool load();
    bool reconcile();
    Snapshot snapshot() const;
    bool legacy() const;
    bool recovery() const;
    Result commit(decisions::CommandEntry command, const std::vector<Rule> &target,
                  std::uint64_t expectedSequence);
    Result prepare(decisions::CommandEntry command, const std::vector<Rule> &target,
                   std::uint64_t expectedSequence);
    bool applyPrepared(const Id &command);
    Result complete(decisions::CommandEntry command);
    bool currentReadback(std::uint64_t desired) const;
    Result query(const Id &command) const;

  private:
    bool write(Snapshot next);
    void observeAfterFailure();
    Result result(const Entry &entry, bool durable) const;
    Result prepareLocked(decisions::CommandEntry command, const std::vector<Rule> &target,
                         std::uint64_t expectedSequence);
    bool applyLocked(const Id &command);
    Result completeLocked(decisions::CommandEntry command);
    SnapshotFile &file_;
    DirectionalBackend &backend_;
    SelectorRegistry &registry_;
    Id epoch_{};
    mutable std::mutex mutex_;
    Snapshot snapshot_;
    bool ownsWriter_ = false, loaded_ = false, legacy_ = false, recovery_ = true;
    Observed observed_ = Observed::Unknown;
    Bytes activeBytes_;
    Id observedCommand_{};
    Id inFlight_{};
    bool attempted_ = false;
    std::function<std::uint64_t()> monotonic_;
    std::map<Id, std::uint64_t> retainedAt_;
};
} // namespace gb::directional
