#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace gb::wire {
using Bytes = std::vector<std::uint8_t>;
using Id = std::array<std::uint8_t, 16>;
using Digest = std::array<std::uint8_t, 32>;
constexpr std::size_t HeaderBytes = 64;
constexpr std::size_t MaxFrameBytes = 65536;
enum class Type : std::uint16_t { Hello=1, HelloAck=2, GetStatus=3, Status=4,
    ListRules=5, RulesPage=6, ListPending=7, PendingPage=8, CommitDecision=9,
    CreateRule=10, RevokeRule=11, MutationAck=12, Attempt=13, Authorization=14,
    Traffic=15, ProtocolError=16, GetCommandStatus=17, CommandStatus=18,
    GetPending=19, PendingRecord=20, SubscribeEvents=21, SubscriptionAck=22, ObservationGap=23 };
enum class Error : std::uint16_t { Ok=0, Unsupported=1, Unauthorized=2, Stale=3,
    Malformed=4, VersionMismatch=5, Conflict=6, Capacity=7, StoreFailure=8,
    WfpFailure=9, RecoveryRequired=10, IdentityUnavailable=11, Timeout=12,
    BackendUnavailable=13, PipeAuthenticationFailure=14, NotFound=15,
    SnapshotExpired=16, CommandUnknown=17 };
enum class State : std::uint8_t { Prepared=1, Applied=2, Failed=3,
    RecoveryRequired=4, AppliedUnrecorded=5 };
enum class EngineState : std::uint8_t { Simulation=0, Unavailable=1,
    Reconciling=2, ReadyUnvalidated=3, RecoveryRequired=4, ValidatedProfile=5 };
enum class BackendMode : std::uint8_t { Simulation=0, WfpUsermode=1, WfpKernel=2 };
enum class Tag : std::uint16_t { ClientRole=1, ServiceEpoch=2, BootId=3,
    Capabilities=4, DesiredRev=5, EffectiveRev=6, EffectiveKnown=7, EngineState=8,
    RequestId=9, RequestVersion=10, ExpectedDesiredRev=11, Decision=12,
    Remember=13, ScopeKind=14, SelectorId=15, RuleId=16, CommandState=17,
    ErrorCode=18, Text=19, EventSeq=20, Timestamp=21, Presence=22, Source=23,
    FlowDirection=24, PacketDirection=25, GapCount=26, SnapshotId=27, Cursor=28,
    NextCursor=29, Limit=30, Count=31, BackendMode=32, Records=33, CommandId=34,
    SelectorRevision=35, CollectorState=36, SourceCoverage=37, EventMask=38,
    AfterEventSeq=39, LostCount=40, LostCountKnown=41, GapReason=42,
    NativeFilterId=43, FilterGuid=44, FilterGeneration=45, RuleRevision=46,
    LocalAddress=47, RemoteAddress=48, LocalPort=49, RemotePort=50, Protocol=51,
    ByteCount=52, PacketCount=53, RequestState=54, RemainingTtlMs=55,
    SelectorState=56, CommandFound=58, OriginalCommandType=59, ObservedResult=60,
    PendingSnapshotRevision=61, AttemptLink=62, PolicyDirection=63,
    ObservationRevision=64, ProfileGeneration=65, ReviewProfileState=66,
    SourceAccountMatched=67 };
constexpr std::uint64_t ReadStatus=1ull<<0, PathPermanentRule=1ull<<1,
    BlockRetry=1ull<<2, RuleRevoke=1ull<<3, Ipv4Ale=1ull<<4, Ipv6Ale=1ull<<5;
struct Field { Tag tag; bool required=true; Bytes bytes; };
struct Frame {
    std::uint16_t minor=0;
    Type type=Type::GetStatus;
    Id connection{}, correlation{};
    std::uint64_t sequence=1;
    std::vector<Field> fields;
};
bool zero(const Id& id);
bool supported(Type type, std::uint16_t minor=0);
bool validUtf8(const Bytes& bytes);
Bytes integer(std::uint64_t value, std::size_t width);
std::uint64_t number(const Field& field);
Field value(Tag tag, std::uint64_t number, std::size_t width=8);
Field value(Tag tag, const Id& id);
const Field* find(const Frame& frame, Tag tag);
Id idValue(const Frame& frame, Tag tag);
std::uint64_t get(const Frame& frame, Tag tag);
Error validate(const Frame& frame);
Error encode(const Frame& frame, Bytes& out);
Error decode(const Bytes& input, Frame& frame);
// El acumulador no reserva memoria según tamaños aún no validados.
class Decoder {
public:
    Error feed(const std::uint8_t* input, std::size_t size,
               std::vector<Frame>& complete);
    bool incomplete() const { return !buffer_.empty(); }
    void reset() { buffer_.clear(); }
private:
    Bytes buffer_;
};
std::string hex(const Id& id);
bool parseId(const std::string& text, Id& id);
}
