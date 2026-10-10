#pragma once
#include "AppIdentity.h"
#include <array>
#include <atomic>
#include <limits>
#include <mutex>
#include <optional>

namespace gatebouncer::service::windows::allapps {
namespace ai = gatebouncer::appidentity;
constexpr std::size_t MaxRecordBytes = 66 * 1024, MaxRecords = 256, MaxQueueBytes = 8 * 1024 * 1024;
constexpr unsigned MaxCopiers = 8;
constexpr std::uint32_t AppSet = 0x20, UserSet = 0x40, PackageSet = 0x400;
constexpr std::uint32_t IpVersionSet = 0x100, LocalAddrSet = 2, RemoteAddrSet = 4;
enum class Health : std::uint8_t { Absent, Unsupported, Ready, Degraded, Stopping };
enum class Reason : std::uint8_t { None, Unsupported, BadPresence, Unreadable, Oversized, InvalidSid,
    SourceGap, Exhausted, InvalidEvent, StaleStamp, ForeignFilter, Ambiguous, ScopeUnsupported, IdentityFailure };
struct Stamp { std::uint64_t epoch = 0, sequence = 0, generation = 0; };
inline bool operator==(const Stamp& a, const Stamp& b) noexcept
{ return a.epoch == b.epoch && a.sequence == b.sequence && a.generation == b.generation; }
struct HealthSnapshot { Health health; std::uint64_t lossRevision; };
class SourceState {
public:
    static constexpr std::uint64_t MaxLossRevision = std::numeric_limits<std::uint64_t>::max() >> 3;
    // Semillas permiten comprobar agotamiento offline; el owner futuro no las recibe por IPC.
    SourceState(std::uint64_t epoch, std::uint64_t generation, std::uint64_t lastSequence = 0,
                std::uint64_t lossRevision = 0) noexcept;
    class Lease {
    public:
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& other) noexcept;
        ~Lease();
        explicit operator bool() const noexcept { return owner_ != nullptr; }
        Stamp stamp{};
        std::uint64_t lossRevision = 0;
    private:
        friend class SourceState;
        explicit Lease(SourceState* owner = nullptr) noexcept : owner_(owner) {}
        SourceState* owner_;
    };
    Lease acquire() noexcept;
    void lost() noexcept;
    void stop() noexcept;
    bool recover(std::uint64_t reconciledLossRevision) noexcept;
    HealthSnapshot health() const noexcept;
    bool current(const Stamp& stamp) const noexcept;
    unsigned inFlight() const noexcept { return copiers_.load(); }
private:
    const std::uint64_t epoch_, generation_;
    std::atomic<std::uint64_t> sequence_, status_;
    std::atomic<unsigned> copiers_{0};
};
struct FieldView {
    const std::uint8_t* data = nullptr;
    std::size_t available = 0, declared = 0;
};
struct NetEventView {
    std::uint32_t profile = 3, type = 3, flags = 0;
    FieldView app, user, package;
    bool classifyPresent = false;
    std::uint32_t classifyType = 0, rawDirection = 0, ipVersion = 0;
    std::uint64_t filterId = 0;
    std::uint16_t layerId = 0;
    bool loopback = false;
    std::optional<std::uint32_t> reauth;
    std::optional<std::uint64_t> timestamp;
    std::uint64_t receivedMonotonic = 0;
};
enum class Direction : std::uint8_t { Unknown, Outbound, Inbound };
struct OwnedNetEvent {
    // Origen de metadata, no certificado ni capability: Source custodia la causa.
    enum class Origin : std::uint8_t { NetEvent, ClassifierInitial };
    Origin origin = Origin::NetEvent;
    std::size_t classifierBytes = 0;
    ai::CopiedIdentity identity;
    Stamp acquired;
    std::uint64_t acquiredLossRevision = 0;
    std::uint32_t profile = 0, type = 0, flags = 0, rawDirection = 0, ipVersion = 0;
    Direction direction = Direction::Unknown;
    std::uint64_t filterId = 0;
    std::uint16_t layerId = 0;
    bool loopback = false;
    std::optional<std::uint32_t> reauth;
    std::optional<std::uint64_t> timestamp;
    std::uint64_t receivedMonotonic = 0;
};
struct CopyOutcome { Reason reason = Reason::None; std::optional<OwnedNetEvent> event; };
CopyOutcome copyMetadata(const NetEventView& view, SourceState& source) noexcept;
std::size_t chargedBytes(const OwnedNetEvent& event) noexcept;
class BoundedQueue {
public:
    explicit BoundedQueue(SourceState& source) noexcept : source_(source) {}
    bool push(OwnedNetEvent&& event) noexcept;
    std::optional<OwnedNetEvent> take() noexcept;
    void clear() noexcept;
private:
    SourceState& source_;
    std::mutex mutex_;
    std::array<std::optional<OwnedNetEvent>, MaxRecords> slots_{};
    std::size_t head_ = 0, count_ = 0, bytes_ = 0;
};
} // namespace gatebouncer::service::windows::allapps
