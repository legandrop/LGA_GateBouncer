#pragma once
#include "../common/wire_ii.h"
#include <map>
#include <optional>

namespace gb::decisions {
using namespace wire;
using wire::ii::PendingRecord;
struct Profile {
    Id account{}, logon{};
    std::uint64_t generation = 1;
    std::uint8_t state = 0;
};
// DTO producido sólo por el adaptador OS auditado; no es payload de GUI.
struct VerifiedDrop {
    PendingRecord record;
    bool ownLedger = false, appIdPresent = false, userIdPresent = false, accountMatches = false;
};
struct VerifiedControl {
    Id account{}, logon{};
    std::uint64_t profileGeneration = 0;
    bool highAdministrator = false, fullServerToken = false;
    Bytes accountSid, logonSid;
    std::uint32_t sessionId = 0;
};
struct CommandEntry {
    Id id{}, principal{}, logon{}, commandEpoch{};
    std::uint64_t profileGeneration = 0;
    Bytes payload;
    State state = State::Prepared;
    Error error = Error::Ok;
    std::uint64_t desired = 0, effective = 0, completedAt = 0;
    bool effectiveKnown = false;
    Id boot{};
    Bytes accountSid, logonSid;
    std::uint32_t sessionId = 0;
};
class JournalSink {
  public:
    virtual ~JournalSink() = default;
    // Debe reemplazar/flush un snapshot completo en almacenamiento protegido.
    virtual bool persist(const std::vector<CommandEntry> &entries) = 0;
    // Rechazo de dominio antes de crear Prepared; nunca acredita autoridad ni efecto.
    virtual Error admission(const Frame &) const { return Error::Ok; }
    virtual bool suspendsMutations() const { return false; }
    virtual Id pinnedCommand() const { return {}; }
};
class EffectBackend {
  public:
    virtual ~EffectBackend() = default;
    virtual bool ready() const = 0;
    virtual bool commit(const Frame &command) = 0;
    virtual bool readback(std::uint64_t desiredRevision) = 0;
    virtual bool currentProof(std::uint64_t revision) { return ready() && readback(revision); }
    virtual bool actualOs() const { return false; }
};
struct Result {
    // True sólo proviene del backend OS; fixtures nunca acreditan efecto real.
    bool appliedReal = false;
    Error error = Error::Ok;
    State state = State::Failed;
    std::uint64_t desired = 0, effective = 0;
    bool effectiveKnown = false, replayed = false;
};
class Engine {
  public:
    Engine(Id epoch, Id boot, JournalSink &journal, EffectBackend &backend, std::uint16_t minor = 1);
    bool activate(Profile profile, bool osEvidenceComplete, std::uint64_t monotonicMs);
    void invalidateProfile(std::uint8_t state, std::uint64_t monotonicMs);
    Error observe(const VerifiedDrop &drop, std::uint64_t monotonicMs);
    std::optional<PendingRecord> lookup(const Id &request, std::uint64_t monotonicMs);
    std::optional<PendingRecord> pendingBySelector(Id selector, std::uint8_t flow,
                                                   std::uint64_t monotonicMs);
    std::vector<PendingRecord> pendingRows(std::uint64_t monotonicMs);
    bool initializeRevision(std::uint64_t desired, bool currentReadback);
    bool advanceRevision(std::uint64_t desired, bool currentReadback, std::uint64_t now);
    Result commit(const Frame &command, const VerifiedControl &authority,
                  std::uint64_t monotonicMs);
    std::optional<CommandEntry> command(const Id &id, const VerifiedControl &authority) const;
    bool restore(const std::vector<CommandEntry> &entries, std::uint64_t monotonicMs = 0);
    bool recoveryRequired() const { return recovery_; }
    std::uint64_t desiredRevision() const { return desired_; }
    std::uint64_t gaps() const { return gaps_; }
    const Profile &profile() const { return profile_; }
    std::uint16_t protocolMinor() const { return minor_; }

  private:
    struct Pending {
        PendingRecord record;
        std::uint64_t deadline = 0, terminalAt = 0;
    };
    void expire(std::uint64_t now);
    void stale(Pending &row, std::uint64_t now);
    bool persist();
    Result result(const CommandEntry &entry, bool replay = false) const;
    Id epoch_, boot_;
    JournalSink &journal_;
    EffectBackend &backend_;
    Profile profile_;
    std::map<Id, Pending> pending_;
    std::map<Id, CommandEntry> commands_;
    std::uint64_t desired_ = 0, gaps_ = 0;
    bool recovery_ = false;
    std::uint16_t minor_ = 1;
};
} // namespace gb::decisions
