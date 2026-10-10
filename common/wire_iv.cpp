#include "wire_iv.h"
#include <algorithm>
#include <limits>
#include <map>
#include <type_traits>

namespace gb::wire::iv {
namespace {
using T = Tag;
using Schema = std::map<T, std::size_t>;
constexpr auto Variable = std::numeric_limits<std::size_t>::max();
std::uint64_t n(const Bytes &b, std::size_t p, std::size_t w) {
  std::uint64_t v = 0;
  for (std::size_t i = 0; i < w; ++i)
    v |= std::uint64_t(b[p + i]) << (8 * i);
  return v;
}
void put(Bytes &b, std::size_t p, std::uint64_t v, std::size_t w) {
  for (std::size_t i = 0; i < w; ++i)
    b[p + i] = std::uint8_t(v >> (8 * i));
}
template <std::size_t N>
void put(Bytes &b, std::size_t p, const std::array<std::uint8_t, N> &v) {
  std::copy(v.begin(), v.end(), b.begin() + p);
}
template <std::size_t N>
std::array<std::uint8_t, N> array(const Bytes &b, std::size_t p) {
  std::array<std::uint8_t, N> v{};
  std::copy_n(b.begin() + p, N, v.begin());
  return v;
}
bool zeros(const Bytes &b, std::size_t p, std::size_t w) {
  return std::all_of(b.begin() + p, b.begin() + p + w,
                     [](auto c) { return !c; });
}
bool text(const Bytes &b) {
  if (!validUtf8(b))
    return false;
  for (auto c : b)
    if (c < 32 || c == 127)
      return false;
  for (std::size_t i = 0; i + 2 < b.size(); ++i)
    if (b[i] == 0xe2 &&
        ((b[i + 1] == 0x80 && b[i + 2] >= 0xaa && b[i + 2] <= 0xae) ||
         (b[i + 1] == 0x81 && b[i + 2] >= 0xa6 && b[i + 2] <= 0xa9)))
      return false;
  return true;
}
bool display(const Display &d) {
  return d.projection >= 1 && d.projection <= 2 && d.name.size() <= 256 &&
         d.principal.size() <= 256 && d.package.size() <= 256 &&
         d.path.size() <= 4096 && (d.projection != 1 || d.path.empty()) &&
         text(d.name) && text(d.principal) && text(d.package) && text(d.path);
}
bool present(std::uint32_t bits, unsigned bit, std::uint64_t v) {
  return (bits & (1u << bit)) || !v;
}
std::uint8_t mode(std::uint8_t action, std::uint8_t direction) {
  return action == 1 || direction == 2 ? 0 : direction == 1 ? 1 : 2;
}
void tail(Bytes &b, std::size_t at, const Display &d) {
  const Bytes *strings[] = {&d.name, &d.principal, &d.package, &d.path};
  for (auto s : strings) {
    put(b, at, s->size(), 2);
    at += 2;
    b.insert(b.end(), s->begin(), s->end());
  }
}
bool tail(const Bytes &b, std::size_t fixed, std::size_t at, Display &d) {
  const std::size_t caps[] = {256, 256, 256, 4096};
  Bytes *strings[] = {&d.name, &d.principal, &d.package, &d.path};
  auto offset = fixed;
  for (unsigned i = 0; i < 4; ++i) {
    const auto size = std::size_t(n(b, at + 2 * i, 2));
    if (size > caps[i] || size > b.size() - offset)
      return false;
    strings[i]->assign(b.begin() + offset, b.begin() + offset + size);
    offset += size;
  }
  return offset == b.size();
}
Bytes payload(const ObservedRecord &r) {
  Bytes b(96);
  put(b, 0, r.observed);
  put(b, 16, r.revision, 8);
  put(b, 24, r.source);
  put(b, 40, r.binding);
  put(b, 56, r.firstUtc, 8);
  put(b, 64, r.lastUtc, 8);
  put(b, 72, r.presence, 4);
  b[76] = r.state;
  b[77] = r.temporal;
  b[78] = r.package;
  b[79] = r.display.projection;
  put(b, 88, static_cast<unsigned>(r.reason), 2);
  tail(b, 80, r.display);
  return b;
}
Bytes payload(const FutureDraftRecord &r) {
  Bytes b(240);
  put(b, 0, r.draft);
  put(b, 16, r.version, 8);
  put(b, 24, r.observed);
  put(b, 40, r.observedRevision, 8);
  put(b, 48, r.source);
  put(b, 64, r.binding);
  put(b, 80, r.selector);
  put(b, 96, r.targetRevision, 8);
  put(b, 104, r.expectedDesired, 8);
  put(b, 112, r.target);
  put(b, 144, r.challenge);
  put(b, 160, r.profile, 8);
  put(b, 168, r.ttl, 4);
  b[172] = r.state;
  b[173] = r.package;
  b[174] = r.direction;
  b[175] = r.scope;
  put(b, 176, r.accepted, 2);
  b[178] = static_cast<std::uint8_t>(r.proof);
  b[179] = r.display.projection;
  put(b, 188, static_cast<unsigned>(r.reason), 2);
  put(b, 192, r.migration);
  put(b, 224, r.durationMs, 4);
  tail(b, 180, r.display);
  return b;
}
Bytes payload(const PrincipalRuleRecord &r) {
  Bytes b(160);
  put(b, 0, r.rule);
  put(b, 16, r.selector);
  put(b, 32, r.revision, 8);
  put(b, 40, r.targetRevision, 8);
  put(b, 48, r.desired, 8);
  put(b, 56, r.target);
  put(b, 88, r.created, 8);
  put(b, 96, r.authorized, 8);
  put(b, 104, r.presence, 4);
  b[108] = r.action;
  b[109] = r.direction;
  b[110] = r.mode;
  b[111] = r.scope;
  b[112] = r.package;
  b[113] = r.origin;
  b[114] = r.admin;
  b[115] = r.effective;
  b[116] = static_cast<std::uint8_t>(r.proof);
  b[117] = r.display.projection;
  b[118] = r.targetKind;
  put(b, 128, r.generation, 8);
  if (!r.originalTarget.empty()) put(b, 136, r.originalTarget.size(), 4);
  tail(b, 120, r.display);
  b.insert(b.end(), r.originalTarget.begin(), r.originalTarget.end());
  return b;
}
Bytes payload(const FileFutureDraftRecord &r) {
  auto b=payload(r.draft);
  b.insert(b.begin()+240,32,0);
  put(b,228,r.originalTarget.size(),4);
  put(b,240,r.file.volumeSerial,4);put(b,244,r.file.fileIndexHigh,4);
  put(b,248,r.file.fileIndexLow,4);put(b,252,r.file.fileSizeHigh,4);
  put(b,256,r.file.fileSizeLow,4);put(b,260,r.file.attributes,4);
  put(b,264,r.file.lastWrite,8);
  b.insert(b.end(),r.originalTarget.begin(),r.originalTarget.end());
  return b;
}
Bytes payload(const ProcessFacts &r) {
  Bytes b(60);
  put(b,0,r.pid,8); put(b,8,r.created,8); put(b,16,r.volumeSerial,4);
  put(b,20,r.fileIndexHigh,4); put(b,24,r.fileIndexLow,4);
  put(b,28,r.fileSizeHigh,4); put(b,32,r.fileSizeLow,4); put(b,36,r.lastWrite,8);
  put(b,44,r.appId.size(),2); put(b,46,r.image.size(),2); put(b,48,r.accountSid.size(),2);
  put(b,52,r.tokenSession,4); put(b,56,r.logonSid.size(),2);
  for(const auto *part:{&r.appId,&r.image,&r.accountSid,&r.logonSid})
    b.insert(b.end(),part->begin(),part->end());
  return b;
}
bool parse(const Bytes &b, ProcessFacts &r) {
  if(b.size()<60 || !zeros(b,50,2) || !zeros(b,58,2)) return false;
  r.pid=n(b,0,8);r.created=n(b,8,8);r.volumeSerial=std::uint32_t(n(b,16,4));
  r.fileIndexHigh=std::uint32_t(n(b,20,4));r.fileIndexLow=std::uint32_t(n(b,24,4));
  r.fileSizeHigh=std::uint32_t(n(b,28,4));r.fileSizeLow=std::uint32_t(n(b,32,4));
  r.lastWrite=n(b,36,8);r.tokenSession=std::uint32_t(n(b,52,4));
  Bytes *parts[]={&r.appId,&r.image,&r.accountSid,&r.logonSid};
  const std::size_t positions[]={44,46,48,56},caps[]={8192,4096,68,68};
  std::size_t at=60;
  for(unsigned i=0;i<4;++i) {
    const auto size=std::size_t(n(b,positions[i],2));
    if(size>caps[i] || size>b.size()-at) return false;
    parts[i]->assign(b.begin()+at,b.begin()+at+size);at+=size;
  }
  return at==b.size() && valid(r);
}
bool parse(const Bytes &b, ObservedRecord &r) {
  if (b.size() < 96 || !zeros(b, 90, 6))
    return false;
  r.observed = array<16>(b, 0);
  r.revision = n(b, 16, 8);
  r.source = array<16>(b, 24);
  r.binding = array<16>(b, 40);
  r.firstUtc = n(b, 56, 8);
  r.lastUtc = n(b, 64, 8);
  r.presence = std::uint32_t(n(b, 72, 4));
  r.state = b[76];
  r.temporal = b[77];
  r.package = b[78];
  r.display.projection = b[79];
  r.reason = static_cast<Error>(n(b, 88, 2));
  return tail(b, 96, 80, r.display) && valid(r);
}
void draftFields(const Bytes &b, FutureDraftRecord &r) {
  r.draft = array<16>(b, 0);
  r.version = n(b, 16, 8);
  r.observed = array<16>(b, 24);
  r.observedRevision = n(b, 40, 8);
  r.source = array<16>(b, 48);
  r.binding = array<16>(b, 64);
  r.selector = array<16>(b, 80);
  r.targetRevision = n(b, 96, 8);
  r.expectedDesired = n(b, 104, 8);
  r.target = array<32>(b, 112);
  r.challenge = array<16>(b, 144);
  r.profile = n(b, 160, 8);
  r.ttl = std::uint32_t(n(b, 168, 4));
  r.state = b[172];
  r.package = b[173];
  r.direction = b[174];
  r.scope = b[175];
  r.accepted = std::uint16_t(n(b, 176, 2));
  r.proof = static_cast<Proof>(b[178]);
  r.display.projection = b[179];
  r.reason = static_cast<Error>(n(b, 188, 2));
  r.migration = array<32>(b, 192);
  r.durationMs = std::uint32_t(n(b, 224, 4));
}
bool parse(const Bytes &b, FutureDraftRecord &r) {
  if (b.size() < 240 || !zeros(b,190,2) || !zeros(b,228,12)) return false;
  draftFields(b,r);
  return tail(b, 240, 180, r.display) && valid(r);
}
bool parse(const Bytes &b, FileFutureDraftRecord &r) {
  if(b.size()<272 || !zeros(b,190,2) || !zeros(b,232,8))return false;
  const auto target=std::size_t(n(b,228,4));
  if(!target || target>b.size()-272)return false;
  draftFields(b,r.draft);
  r.file={std::uint32_t(n(b,240,4)),std::uint32_t(n(b,244,4)),std::uint32_t(n(b,248,4)),
    std::uint32_t(n(b,252,4)),std::uint32_t(n(b,256,4)),std::uint32_t(n(b,260,4)),n(b,264,8)};
  r.originalTarget.assign(b.end()-target,b.end());
  Bytes displayBytes(b.begin(),b.end()-target);
  return tail(displayBytes,272,180,r.draft.display) && valid(r);
}
bool parse(const Bytes &b, PrincipalRuleRecord &r, unsigned version) {
  if (b.size() < 160 || b[119] ||
      (version==1 ? !zeros(b,136,24) : version!=2 || !zeros(b,140,20)))
    return false;
  r.rule = array<16>(b, 0);
  r.selector = array<16>(b, 16);
  r.revision = n(b, 32, 8);
  r.targetRevision = n(b, 40, 8);
  r.desired = n(b, 48, 8);
  r.target = array<32>(b, 56);
  r.created = n(b, 88, 8);
  r.authorized = n(b, 96, 8);
  r.presence = std::uint32_t(n(b, 104, 4));
  r.action = b[108];
  r.direction = b[109];
  r.mode = b[110];
  r.scope = b[111];
  r.package = b[112];
  r.origin = b[113];
  r.admin = b[114];
  r.effective = b[115];
  r.proof = static_cast<Proof>(b[116]);
  r.display.projection = b[117];
  r.targetKind = b[118];
  r.generation = n(b, 128, 8);
  const auto target=version==2 ? std::size_t(n(b,136,4)) : 0;
  if(target>b.size()-160 || (version==2 && !target))return false;
  r.originalTarget.assign(b.end()-target,b.end());
  Bytes displayBytes(b.begin(),b.end()-target);
  return tail(displayBytes, 160, 120, r.display) && valid(r);
}
template <class R>
Error packRecords(const std::vector<R> &rows, Bytes &out, unsigned kind) {
  if (rows.size() > 32)
    return Error::Capacity;
  Bytes b;
  for (const auto &r : rows) {
    if (!valid(r))
      return Error::Malformed;
    auto p = payload(r);
    if (p.size() + 8 > MaxRecordsBytes - b.size())
      return Error::Capacity;
    unsigned version=1;
    if constexpr(std::is_same_v<R,PrincipalRuleRecord>)
      if(!r.originalTarget.empty())version=2;
    if constexpr(std::is_same_v<R,FileFutureDraftRecord>)
      if(validConditionalFileTarget(r.originalTarget))version=2;
    for (auto v : {integer(p.size(), 4), integer(kind, 2), integer(version, 2)})
      b.insert(b.end(), v.begin(), v.end());
    b.insert(b.end(), p.begin(), p.end());
  }
  out = std::move(b);
  return Error::Ok;
}
template <class R>
Error unpackRecords(const Bytes &b, std::size_t count, std::vector<R> &out,
                    unsigned kind, std::size_t max) {
  if (b.size() > MaxRecordsBytes || count > 32)
    return Error::Capacity;
  std::vector<R> rows;
  std::size_t at = 0;
  for (std::size_t i = 0; i < count; ++i) {
    if (b.size() - at < 8)
      return Error::Malformed;
    auto size = std::size_t(n(b, at, 4));
    const auto version=unsigned(n(b,at+6,2));
    if (n(b, at + 4, 2) != kind ||
        ((std::is_same_v<R,PrincipalRuleRecord> || std::is_same_v<R,FileFutureDraftRecord>) ?
            version!=1 && version!=2 : version!=1))
      return Error::Unsupported;
    if (size > max || size > b.size() - at - 8)
      return Error::Malformed;
    Bytes p(b.begin() + at + 8, b.begin() + at + 8 + size);
    R r;
    bool parsed;
    if constexpr(std::is_same_v<R,PrincipalRuleRecord>) parsed=parse(p,r,version);
    else parsed=parse(p,r);
    if (!parsed)
      return Error::Malformed;
    if constexpr(std::is_same_v<R,FileFutureDraftRecord>)
      if((version==2)!=validConditionalFileTarget(r.originalTarget))return Error::Malformed;
    rows.push_back(std::move(r));
    at += 8 + size;
  }
  if (at != b.size())
    return Error::Malformed;
  out = std::move(rows);
  return Error::Ok;
}
Schema schemaBase(const Frame &f) {
  Schema ref = {{T::ServiceEpoch, 16},
                {T::ObservedId, 16},
                {T::ObservedRevision, 8},
                {T::SourceEpoch, 16}};
  Schema result = {{T::ServiceEpoch, 16},
                   {T::DesiredRev, 8},
                   {T::EffectiveRev, 8},
                   {T::EffectiveKnown, 1},
                   {T::CommandState, 1},
                   {T::ErrorCode, 2},
                   {T::CommandId, 16},
                   {T::ProofState, 1},
                   {T::KnownAppliedUnrecorded, 1},
                   {T::Durable, 1}};
  switch (f.type) {
  case Type::GetNativeProcessContext:
  case Type::NativeProcessContext: {
    Schema s={{T::ServiceEpoch,16},{T::SourceEpoch,16},{T::ServiceContext,56},
              {T::ProfileGeneration,8},{T::ObservedId,16},{T::ObservedRevision,8},
              {T::CaptureBindingId,16},{T::AttemptLink,16}};
    if(f.type==Type::NativeProcessContext) {
      s[T::ErrorCode]=2;s[T::Count]=4;s[T::Source]=1;s[T::SourceCoverage]=1;
      if(get(f,T::ErrorCode)==0)s[T::Records]=Variable;
    }
    return s;
  }
  case Type::SubscribeEvents:
    return {{T::ServiceEpoch,16},{T::EventMask,4},{T::AfterEventSeq,8},
            {T::ProfileGeneration,8},{T::SourceEpoch,16}};
  case Type::SubscriptionAck:
    return {{T::ServiceEpoch,16},{T::EventSeq,8},{T::SourceCoverage,1},
            {T::EventMask,4},{T::ProfileGeneration,8},{T::SourceEpoch,16},
            {T::ServiceContext,56}};
  case Type::ObservationGap:
    return {{T::ServiceEpoch,16},{T::EventSeq,8},{T::Timestamp,8},{T::Presence,8},
            {T::Source,1},{T::GapCount,8},{T::SourceCoverage,1},{T::AfterEventSeq,8},
            {T::LostCount,8},{T::LostCountKnown,1},{T::GapReason,1},
            {T::ProfileGeneration,8},{T::SourceEpoch,16},{T::ServiceContext,56}};
  case Type::Attempt:
  case Type::Authorization:
  case Type::Traffic: {
    Schema s={{T::ServiceEpoch,16},{T::EventSeq,8},{T::Timestamp,8},{T::Presence,8},
              {T::Source,1},{T::FlowDirection,1},{T::SourceCoverage,1},
              {T::ProfileGeneration,8},{T::ObservedId,16},{T::ObservedRevision,8},
              {T::SourceEpoch,16},{T::CaptureBindingId,16},{T::ServiceContext,56}};
    if(get(f,T::Presence)&2) s[T::Protocol]=1;
    if(get(f,T::Presence)&4) s[T::Records]=Variable;
    if(f.type==Type::Authorization) {
      s[T::CommandId]=16; s[T::AttemptLink]=16; s[T::EffectiveRev]=8;
      s[T::Decision]=1; s[T::ScopeKind]=1; s[T::Durable]=1; s[T::ProofState]=1;
    }
    if(f.type==Type::Traffic) {
      s[T::CommandId]=16;s[T::AttemptLink]=16;s[T::EffectiveRev]=8;
      s[T::ByteCount]=8;s[T::PacketCount]=8;s[T::PacketDirection]=1;
      s[T::ScopeKind]=1;s[T::Durable]=1;s[T::ProofState]=1;
    }
    return s;
  }
  case Type::ListObserved:
  case Type::ListPrincipalRules:
    return {{T::ServiceEpoch, 16},
            {T::SnapshotId, 16},
            {T::Cursor, 4},
            {T::Limit, 2}};
  case Type::ObservedPage:
    return {{T::ServiceEpoch, 16}, {T::SnapshotId, 16},
            {T::Cursor, 4},        {T::NextCursor, 4},
            {T::Count, 2},         {T::Records, Variable},
            {T::SourceEpoch, 16},  {T::ObservedSnapshotRevision, 8}};
  case Type::GetObservedRecord:
  case Type::OpenReview:
  case Type::ReviewQueued:
    return ref;
  case Type::ObservedRecord:
    if (find(f, T::PolicyDirection))
      return {{T::ServiceEpoch, 16}, {T::Records, Variable}, {T::SourceEpoch, 16}, {T::PolicyDirection, 1}};
    return {{T::ServiceEpoch, 16}, {T::Records, Variable}, {T::SourceEpoch, 16}};
  case Type::FutureDraftRecord:
    return {
        {T::ServiceEpoch, 16}, {T::Records, Variable}, {T::SourceEpoch, 16}};
  case Type::PrepareFuturePolicy:
    ref[T::ExpectedDesiredRev] = 8;
    ref[T::PolicyDirection] = 1;
    ref[T::ProfileGeneration] = 8;
    ref[T::IVProfile] = 1;
    if (find(f, T::ScopeKind)) ref[T::ScopeKind] = 1;
    if (get(f, T::ScopeKind) == 5) ref[T::ScopeDurationMs] = 4;
    return ref;
  case Type::PrepareFileFuturePolicy: {
    Schema file={{T::ServiceEpoch,16},{T::ExpectedDesiredRev,8},{T::PolicyDirection,1},
      {T::ProfileGeneration,8},{T::SourceEpoch,16},{T::IVProfile,1},
      {T::ScopeKind,1},{T::PackageMode,1},{T::Text,Variable}};
    if(find(f,T::Records))file[T::Records]=Variable;
    if(find(f,T::RuleId)) {
      file[T::RuleId]=16;file[T::RuleRevision]=8;file[T::SelectorRevision]=8;
      file[T::PreviousTargetDigest]=32;
    }
    return file;
  }
  case Type::FileFutureDraftRecord: {
    Schema file={{T::ServiceEpoch,16},{T::Records,Variable},{T::SourceEpoch,16},{T::ServiceContext,56}};
    if(find(f,T::RuleId)) {
      file[T::RuleId]=16;file[T::RuleRevision]=8;file[T::SelectorRevision]=8;
      file[T::PreviousTargetDigest]=32;
    }
    return file;
  }
  case Type::GetFutureDraft:
    return {{T::ServiceEpoch, 16},
            {T::ProfileGeneration, 8},
            {T::DraftId, 16},
            {T::DraftVersion, 8},
            {T::IVProfile, 1}};
  case Type::CommitFuturePolicy:
  case Type::ReplacePrincipalRule: {
    Schema command = {{T::ServiceEpoch, 16},     {T::ExpectedDesiredRev, 8},
            {T::Decision, 1},          {T::ScopeKind, 1},
            {T::SelectorId, 16},       {T::PolicyDirection, 1},
            {T::ProfileGeneration, 8}, {T::SourceEpoch, 16},
            {T::DraftId, 16},          {T::DraftVersion, 8},
            {T::TargetRevision, 8},    {T::PackageMode, 1},
            {T::AcceptedScope, 2},     {T::TargetDigest, 32},
            {T::MigrationDigest, 32},  {T::ConsentChallengeId, 16},
            {T::CaptureBindingId, 16}, {T::IVProfile, 1}};
    if (get(f,T::ScopeKind) == 5) command[T::ScopeDurationMs] = 4;
    if(f.type==Type::ReplacePrincipalRule) {
      command[T::RuleId]=16;command[T::RuleRevision]=8;command[T::SelectorRevision]=8;
      command[T::PreviousTargetDigest]=32;
    }
    return command;
  }
  case Type::RevokePrincipalRule:
    return {{T::ServiceEpoch, 16},     {T::ExpectedDesiredRev, 8},
            {T::RuleId, 16},           {T::RuleRevision, 8},
            {T::ProfileGeneration, 8}, {T::TargetRevision, 8},
            {T::TargetDigest, 32},     {T::MigrationDigest, 32},
            {T::IVProfile, 1}};
  case Type::FuturePolicyAck:
    if (find(f,T::ScopeKind)) result[T::ScopeKind] = 1;
    return result;
  case Type::GetFutureCommandStatus:
    return {{T::ServiceEpoch, 16}, {T::CommandId, 16}};
  case Type::FutureCommandStatus:
    if (get(f, T::CommandFound) == 1) {
      result[T::CommandFound] = 1;
      result[T::OriginalCommandType] = 2;
      if (find(f,T::ScopeKind)) result[T::ScopeKind] = 1;
      return result;
    }
    return {{T::ServiceEpoch, 16},
            {T::ErrorCode, 2},
            {T::CommandId, 16},
            {T::CommandFound, 1}};
  case Type::PrincipalRulesPage: {
    Schema page={{T::ServiceEpoch, 16}, {T::DesiredRev, 8}, {T::SnapshotId, 16},
            {T::Cursor, 4},        {T::NextCursor, 4}, {T::Count, 2},
            {T::Records, Variable}};
    if(find(f,T::ServiceContext)) {
      page[T::ServiceContext]=56;page[T::SourceEpoch]=16;page[T::ProfileGeneration]=8;
    }
    return page;
  }
  default:
    return {};
  }
}
Schema schema(const Frame &f) {
  auto s=schemaBase(f);
  if(find(f,T::PrincipalObservationOwner) &&
     (f.type==Type::GetObservedRecord || f.type==Type::ObservedRecord))
    s[T::PrincipalObservationOwner]=16;
  if(find(f,T::OriginalSourceSelection)) {
    switch(f.type) {
    case Type::PrepareFileFuturePolicy: case Type::FileFutureDraftRecord:
      s[T::OriginalSourcePath]=Variable;
      if(f.type==Type::FileFutureDraftRecord)s[T::Decision]=1;
      [[fallthrough]];
    case Type::GetFutureDraft: case Type::CommitFuturePolicy:
      s[T::OriginalSourceSelection]=Variable;break;
    default: break;
    }
  }
  if(find(f,T::DestinationContext)) {
    switch(f.type) {
    case Type::GetObservedRecord: case Type::SubscribeEvents: case Type::SubscriptionAck:
      s[T::DestinationContext]=1;break;
    case Type::ObservedRecord:
      s[T::DestinationContext]=48;s[T::ServiceContext]=56;s[T::ProfileGeneration]=8;break;
    case Type::Attempt: case Type::Authorization: case Type::Traffic:
      s[T::DestinationContext]=48;break;
    default: break;
    }
  }
  if(!find(f,T::AdministrativeMode))return s;
  switch(f.type) {
  case Type::ListObserved: case Type::ObservedPage:
  case Type::ListPrincipalRules: case Type::PrincipalRulesPage:
  case Type::GetObservedRecord:
    s[T::AdministrativeMode]=1;break;
  case Type::ObservedRecord: case Type::FutureDraftRecord:
    s[T::OriginalTarget]=Variable;
    [[fallthrough]];
  case Type::OpenReview: case Type::ReviewQueued:
  case Type::PrepareFuturePolicy: case Type::GetFutureDraft:
  case Type::CommitFuturePolicy: case Type::RevokePrincipalRule:
  case Type::PrepareFileFuturePolicy: case Type::FileFutureDraftRecord:
  case Type::ReplacePrincipalRule:
    s[T::AdministrativeMode]=1;s[T::SelectedPrincipalSid]=Variable;break;
  default: break;
  }
  return s;
}
bool outcome(const Frame &f) {
  auto d = get(f, T::DesiredRev), e = get(f, T::EffectiveRev),
       k = get(f, T::EffectiveKnown), p = get(f, T::ProofState);
  bool u = !k && !e && !p, c = k == 1 && d > 0 && e == d && p == 2;
  if (!u && !c)
    return false;
  auto state = get(f, T::CommandState), err = get(f, T::ErrorCode),
       dur = get(f, T::Durable), flag = get(f, T::KnownAppliedUnrecorded);
  if (f.type == Type::FutureCommandStatus && !d)
    return false;
  switch (state) {
  case 1:
    return d && err == 0 && u && !flag &&
           (dur == 1 || (dur == 0 && f.type == Type::FutureCommandStatus));
  case 2:
    return d && err == 0 && dur == 1 && !flag;
  case 3:
    return err >= 1 && err <= 18 && err != 17 && dur <= 1 && u && !flag;
  case 4:
    return (err == 8 || err == 9 || err == 10 || err == 13) && dur <= 1 && u &&
           !flag;
  case 5:
    return d && err == 8 && !dur && ((u && !flag) || (c && flag == 1));
  default:
    return false;
  }
}
} // namespace
bool valid(const OriginalSourceSelection &selection) {
  return selection.rawDigest!=Digest{} && !selection.candidate.empty() &&
    selection.candidate.size()<=256 && text(selection.candidate);
}
Error packOriginalSourceSelection(const OriginalSourceSelection &selection,Bytes &out) {
  if(!valid(selection))return Error::Malformed;
  Bytes bytes(40);bytes[0]=1;put(bytes,4,selection.rawDigest);
  put(bytes,36,selection.candidate.size(),2);
  bytes.insert(bytes.end(),selection.candidate.begin(),selection.candidate.end());
  out=std::move(bytes);return Error::Ok;
}
Error unpackOriginalSourceSelection(const Bytes &bytes,OriginalSourceSelection &out) {
  if(bytes.size()<41 || bytes.size()>296 || bytes[0]!=1 || !zeros(bytes,1,3) ||
     !zeros(bytes,38,2) || n(bytes,36,2)!=bytes.size()-40)return Error::Malformed;
  OriginalSourceSelection selection;
  selection.rawDigest=array<32>(bytes,4);selection.candidate.assign(bytes.begin()+40,bytes.end());
  if(!valid(selection))return Error::Malformed;
  out=std::move(selection);return Error::Ok;
}
bool valid(const DestinationContext &context) {
  const auto empty=[](const auto &address) {
    return std::all_of(address.begin(),address.end(),[](auto byte){return byte==0;});
  };
  if(!context.present)return !context.family && !context.protocol && !context.direction &&
    !context.localPort && !context.remotePort && !context.compartment &&
    empty(context.localAddress) && empty(context.remoteAddress);
  if((context.family!=4 && context.family!=6) || (context.protocol!=6 && context.protocol!=17) ||
     (context.direction!=1 && context.direction!=2))return false;
  return context.family!=4 ||
    (std::all_of(context.localAddress.begin()+4,context.localAddress.end(),[](auto byte){return byte==0;}) &&
     std::all_of(context.remoteAddress.begin()+4,context.remoteAddress.end(),[](auto byte){return byte==0;}));
}
Error packDestinationContext(const DestinationContext &context,Bytes &out) {
  if(!valid(context))return Error::Malformed;
  Bytes result(48);result[0]=1;result[1]=context.present ? 1 : 0;
  result[2]=context.family;result[3]=context.protocol;result[4]=context.direction;
  put(result,8,context.localPort,2);put(result,10,context.remotePort,2);put(result,12,context.compartment,4);
  put(result,16,context.localAddress);put(result,32,context.remoteAddress);
  out=std::move(result);return Error::Ok;
}
Error unpackDestinationContext(const Bytes &bytes,DestinationContext &out) {
  if(bytes.size()!=48 || bytes[0]!=1 || bytes[1]>1 || !zeros(bytes,5,3))return Error::Malformed;
  DestinationContext result;
  result.present=bytes[1]!=0;result.family=bytes[2];result.protocol=bytes[3];result.direction=bytes[4];
  result.localPort=static_cast<std::uint16_t>(n(bytes,8,2));
  result.remotePort=static_cast<std::uint16_t>(n(bytes,10,2));
  result.compartment=static_cast<std::uint32_t>(n(bytes,12,4));
  result.localAddress=array<16>(bytes,16);result.remoteAddress=array<16>(bytes,32);
  if(!valid(result))return Error::Malformed;
  out=std::move(result);return Error::Ok;
}
bool supported(Type t) {
  return t == Type::Hello || t == Type::HelloAck || t == Type::GetStatus ||
         t == Type::Status || t == Type::ProtocolError ||
         t == Type::SubscribeEvents || t == Type::SubscriptionAck ||
         t == Type::Attempt || t == Type::Authorization || t == Type::Traffic || t == Type::ObservationGap ||
         (t >= Type::ListObserved && t <= Type::ReplacePrincipalRule);
}
Id attemptLink(std::uint64_t sequence) {
  Id id{};
  for(unsigned i=0;i<8;++i) id[i]=std::uint8_t(sequence>>(8*i));
  return id;
}
std::uint64_t attemptSequence(const Id &link) {
  if(std::any_of(link.begin()+8,link.end(),[](auto c){return c!=0;})) return 0;
  std::uint64_t sequence=0;
  for(unsigned i=0;i<8;++i) sequence|=std::uint64_t(link[i])<<(8*i);
  return sequence;
}
Error encodeServiceContext(const ServiceContext &context, Bytes &out) {
  out.clear();
  if (zero(context.serviceEpoch) || zero(context.boot) ||
      zero(context.engineContext) != (context.engineBindingGeneration == 0))
    return Error::Malformed;
  out.resize(56);
  put(out, 0, context.serviceEpoch);
  put(out, 16, context.boot);
  put(out, 32, context.engineContext);
  put(out, 48, context.engineBindingGeneration, 8);
  return Error::Ok;
}
Error decodeServiceContext(const Frame &frame, ServiceContext &out) {
  out = {};
  if (frame.minor != 3 ||
      (frame.type != Type::HelloAck && frame.type != Type::Status &&
       frame.type != Type::SubscriptionAck && frame.type != Type::Attempt &&
       frame.type != Type::Authorization && frame.type != Type::Traffic && frame.type != Type::ObservationGap &&
       frame.type != Type::GetNativeProcessContext && frame.type != Type::NativeProcessContext &&
       frame.type != Type::FileFutureDraftRecord && frame.type != Type::PrincipalRulesPage &&
       !(frame.type==Type::ObservedRecord && find(frame,T::DestinationContext))))
    return Error::Unsupported;
  const auto error = iv::validate(frame);
  if (error != Error::Ok) return error;
  if(!find(frame,T::ServiceContext))return Error::Unsupported;
  if (get(frame, T::IVProfile) != 0 || (get(frame, T::Capabilities) & FuturePolicyControl))
    return Error::Malformed;
  const auto &bytes = find(frame, T::ServiceContext)->bytes;
  out = {array<16>(bytes, 0), array<16>(bytes, 16), array<16>(bytes, 32), n(bytes, 48, 8)};
  return Error::Ok;
}
bool valid(const ObservedRecord &r) {
  auto reason = static_cast<unsigned>(r.reason);
  return !zero(r.observed) && r.revision && !zero(r.source) && r.state >= 1 &&
         r.state <= 3 && (r.temporal == 1 || r.temporal == 2) && r.package <= 2 && r.presence <= 3 &&
         present(r.presence, 0, r.firstUtc) &&
         present(r.presence, 1, r.lastUtc) &&
         (r.state == 1 ? !zero(r.binding) && reason <= 18
                       : zero(r.binding) && reason >= 1 && reason <= 18) &&
         display(r.display);
}
bool valid(const ProcessFacts &r) {
  auto sid=[](const Bytes &b) { return b.size()>=8 && b.size()<=68 && b[0]==1 &&
    b[1]<=15 && b.size()==8+std::size_t(b[1])*4; };
  if(!r.pid || r.pid>UINT32_MAX || !r.created || r.created>INT64_MAX || !r.lastWrite || r.lastWrite>INT64_MAX ||
     (!r.fileIndexHigh && !r.fileIndexLow) || r.appId.size()<4 || r.appId.size()>8192 ||
     (r.appId.size()&1) || r.appId[r.appId.size()-1] || r.appId[r.appId.size()-2] ||
     r.image.empty() || r.image.size()>4096 || !text(r.image) || !sid(r.accountSid) || !sid(r.logonSid))
    return false;
  // El AppId conserva UTF16 del ALE original; rechazar NUL interior y surrogates rotos.
  for(std::size_t i=0;i+2<r.appId.size();i+=2) {
    auto c=n(r.appId,i,2);
    if(!c || (c>=0xdc00 && c<=0xdfff)) return false;
    if(c>=0xd800 && c<=0xdbff) {
      if(i+4>=r.appId.size()) return false;
      const auto low=n(r.appId,i+2,2);
      if(low<0xdc00 || low>0xdfff) return false;
      i+=2;
    }
  }
  return true;
}
bool valid(const FutureDraftRecord &r) {
  if (zero(r.draft) || !r.version || zero(r.observed) || !r.observedRevision ||
      zero(r.source) || zero(r.binding) || !r.profile || r.state < 1 ||
      r.state > 4 || r.direction < 1 || r.direction > 3 || r.scope < 2 || r.scope > 5 ||
      r.package > 2 || r.display.projection != 2 || !display(r.display))
    return false;
  auto reason = static_cast<unsigned>(r.reason);
  if (r.state == 3)
    return !zero(r.selector) && r.targetRevision && r.target != Digest{} &&
           !zero(r.challenge) && r.ttl >= 1 && r.ttl <= 120000 &&
           r.package >= 1 && r.proof == Proof::CurrentShapeUnproven &&
           reason == 0 && (r.scope == 2 ? !r.durationMs && r.accepted == (r.package == 1 ? 3 : 1) :
             r.package == 1 && (r.direction == 1 || r.direction == 2) && r.accepted == (std::uint64_t{1} << r.scope) &&
             (r.scope == 5 ? r.durationMs >= 1 && r.durationMs <= 900000 : !r.durationMs));
  return zero(r.selector) && !r.targetRevision && r.target == Digest{} &&
         zero(r.challenge) && !r.ttl && r.proof == Proof::Unknown &&
         !r.accepted &&
         (r.state == 1   ? reason == 0
          : r.state == 2 ? reason >= 1 && reason <= 18
                         : reason == 3 || reason == 12);
}
bool valid(const PrincipalRuleRecord &r) {
  if(!r.originalTarget.empty() &&
     (r.targetKind==1 ? !validPrincipalTarget(r.originalTarget,r.package) :
      r.targetKind!=3 || !validConditionalTarget(r.originalTarget,r.package)))return false;
  if (zero(r.rule) || zero(r.selector) || !r.revision || !r.targetRevision ||
      r.target == Digest{} || r.action < 1 || r.action > 2 || r.direction < 1 ||
      r.direction > 3 || r.mode != mode(r.action, r.direction) || r.admin < 1 ||
      r.admin > 2 || r.effective > 2 || (r.admin == 2 && r.effective == 1) ||
      r.presence > 7 || !present(r.presence, 0, r.created) ||
      !present(r.presence, 1, r.authorized) ||
      bool(r.presence & 4) != (r.generation != 0) || !display(r.display))
    return false;
  if (r.proof == Proof::Unknown) {
    if (r.effective || r.generation)
      return false;
  } else if (r.proof != Proof::CurrentEffect || r.effective < 1)
    return false;
  return r.targetKind == 1 || r.targetKind == 3
             ? r.scope == 2 && r.package >= 1 && r.package <= 2 && r.origin == 1
                 && (r.targetKind!=3 || (r.direction==1 && !r.originalTarget.empty()))
             : r.targetKind == 2 && r.scope == 1 && !r.package && !r.origin &&
                   r.display.principal.empty() && r.display.package.empty();
}
bool validPrincipalTarget(const Bytes &b,std::uint8_t package) {
  if(b.size()<24 || b.size()>65696 || b[0]!='A' || b[1]!='P' || b[2]!='T' || b[3]!='1' ||
     n(b,4,2)!=1 || n(b,6,2)!=24 || b[17]!=2 || !zeros(b,18,6))return false;
  const auto app=n(b,8,4),user=n(b,12,2),sid=n(b,14,2);
  const auto mode=b[16];
  if(!app || app>65536 || user<8 || user>68 || sid>68 || mode<1 || mode>2 ||
     (package && mode!=package) || (mode==1 && sid) || 24+app+user+sid!=b.size())return false;
  auto validSid=[&](std::size_t at,std::size_t size) {
    return size>=8 && b[at]==1 && b[at+1]<=15 && size==8+std::size_t(b[at+1])*4;
  };
  return validSid(24+std::size_t(app),std::size_t(user)) &&
    (mode==1 || validSid(24+std::size_t(app+user),std::size_t(sid)));
}
bool validFileTarget(const Bytes &target) {
  if(!validPrincipalTarget(target,1))return false;
  const auto size=n(target,8,4);
  if(size<4 || size>8192 || (size&1) || target[24+size-1] || target[24+size-2])return false;
  for(std::size_t i=24;i<24+size-2;i+=2) {
    const auto unit=n(target,i,2);
    if(!unit || (unit>=0xdc00 && unit<=0xdfff))return false;
    if(unit>=0xd800 && unit<=0xdbff) {
      if(i+4>=24+size)return false;
      const auto low=n(target,i+2,2);
      if(low<0xdc00 || low>0xdfff)return false;
      i+=2;
    }
  }
  return true;
}
bool validConditionalTarget(const Bytes &target,std::uint8_t package) {
  if(target.size()<72 || target.size()>65744 || target[0]!='A' || target[1]!='P' ||
     target[2]!='T' || target[3]!='2' || n(target,4,2)!=1 || n(target,6,2)!=72 ||
     !zeros(target,28,4))return false;
  RemoteCondition condition;
  condition.kind=static_cast<RemoteKind>(target[18]);condition.match=target[19];
  condition.sourceWeight=std::uint32_t(n(target,20,4));condition.sourceOrdinal=std::uint32_t(n(target,24,4));
  condition.first=std::uint32_t(n(target,32,4));condition.last=std::uint32_t(n(target,36,4));
  condition.sourceRule=array<16>(target,40);condition.sourceFilter=array<16>(target,56);
  if(condition.kind!=RemoteKind::Ipv4Range || !remoteConditionValid(condition))return false;
  Bytes base(target.begin(),target.begin()+24);base[3]='1';put(base,6,24,2);
  base[18]=base[19]=base[20]=base[21]=base[22]=base[23]=0;
  base.insert(base.end(),target.begin()+72,target.end());
  return validPrincipalTarget(base,package);
}
bool validConditionalFileTarget(const Bytes &target) {
  if(!validConditionalTarget(target,1))return false;
  Bytes base(target.begin(),target.begin()+24);base[3]='1';put(base,6,24,2);
  std::fill(base.begin()+18,base.end(),0);base.insert(base.end(),target.begin()+72,target.end());
  return validFileTarget(base);
}
bool valid(const FileFutureDraftRecord &r) {
  const auto &d=r.draft;
  if(!zero(d.observed) || d.observedRevision || d.migration!=Digest{} ||
    zero(d.draft) || !d.version || zero(d.source) || zero(d.binding) || zero(d.selector) ||
    !d.targetRevision || zero(d.challenge) || !d.profile || d.expectedDesired==UINT64_MAX ||
    d.target==Digest{} || d.ttl<1 || d.ttl>120000 || d.state!=3 || d.package!=1 ||
    d.direction<1 || d.direction>3 || d.scope!=2 || d.durationMs || d.accepted!=3 ||
    d.proof!=Proof::CurrentShapeUnproven || d.reason!=Error::Ok || d.display.projection!=2 ||
    !display(d.display) || (!validFileTarget(r.originalTarget) &&
      !(d.direction==1 && validConditionalFileTarget(r.originalTarget))) ||
    (!r.file.fileIndexHigh && !r.file.fileIndexLow) || !r.file.lastWrite || r.file.lastWrite>INT64_MAX ||
    (r.file.attributes & (0x10u|0x400u)))return false;
  return true;
}
Error unpackOriginalTarget(const Bytes &b,OriginalTarget &out) {
  out={};
  const bool conditional=validConditionalTarget(b);
  if(!conditional && !validPrincipalTarget(b))return Error::Malformed;
  const auto offset=conditional ? 72u : 24u;
  const auto app=std::size_t(n(b,8,4)),user=std::size_t(n(b,12,2));
  out.appId.assign(b.begin()+offset,b.begin()+offset+app);
  out.accountSid.assign(b.begin()+offset+app,b.begin()+offset+app+user);
  out.packageSid.assign(b.begin()+offset+app+user,b.end());
  out.packageMode=b[16];return Error::Ok;
}
Error principalTargetDigestInput(const Bytes &b,Bytes &out) {
  out.clear();
  if(!validPrincipalTarget(b) && !validConditionalTarget(b))return Error::Malformed;
  out={'G','B','S','4','T','G','T','1'};
  const auto size=integer(b.size(),4);out.insert(out.end(),size.begin(),size.end());
  out.insert(out.end(),b.begin(),b.end());return Error::Ok;
}
Error pack(const std::vector<ObservedRecord> &r, Bytes &b) {
  return packRecords(r, b, 3);
}
Error pack(const std::vector<FutureDraftRecord> &r, Bytes &b) {
  return packRecords(r, b, 4);
}
Error pack(const std::vector<PrincipalRuleRecord> &r, Bytes &b) {
  return packRecords(r, b, 5);
}
Error pack(const std::vector<FileFutureDraftRecord> &r,Bytes &b) {
  return r.size()==1 ? packRecords(r,b,7) : Error::Malformed;
}
Error pack(const std::vector<ProcessFacts> &r, Bytes &b) {
  return r.size()==1 ? packRecords(r,b,6) : Error::Malformed;
}
Error unpack(const Bytes &b, std::size_t c, std::vector<ObservedRecord> &r) {
  return unpackRecords(b, c, r, 3, 4960);
}
Error unpack(const Bytes &b, std::size_t c, std::vector<FutureDraftRecord> &r) {
  return unpackRecords(b, c, r, 4, 5104);
}
Error unpack(const Bytes &b, std::size_t c,
             std::vector<PrincipalRuleRecord> &r) {
  return unpackRecords(b, c, r, 5, MaxRecordsBytes-8);
}
Error unpack(const Bytes &b,std::size_t c,std::vector<FileFutureDraftRecord> &r) {
  return c==1 ? unpackRecords(b,c,r,7,MaxRecordsBytes-8) : Error::Malformed;
}
Error unpack(const Bytes &b,std::size_t c,std::vector<ProcessFacts> &r) {
  return c==1 ? unpackRecords(b,c,r,6,60+8192+4096+136) : Error::Malformed;
}
Error validate(const Frame &f) {
  if (f.minor != 3)
    return Error::VersionMismatch;
  if (!iv::supported(f.type))
    return Error::Unsupported;
  if (f.fields.size() > 64)
    return Error::Capacity;
  if (!f.sequence || zero(f.correlation))
    return Error::Malformed;
  if (f.type == Type::Hello) {
    if (!zero(f.connection) || f.sequence != 1)
      return Error::Malformed;
  } else if (f.type != Type::ProtocolError && zero(f.connection))
    return Error::Malformed;
  if (f.type == Type::HelloAck && f.sequence != 1)
    return Error::Malformed;
  std::size_t body = 0;
  unsigned previous = 0;
  for (const auto &v : f.fields) {
    auto tag = static_cast<unsigned>(v.tag);
    if (tag < 1 || tag > static_cast<unsigned>(T::PrincipalObservationOwner) || tag == 57 ||
        (v.tag == T::ServiceContext && f.type != Type::HelloAck && f.type != Type::Status &&
         f.type != Type::SubscriptionAck && f.type != Type::Attempt &&
         f.type != Type::Authorization && f.type != Type::Traffic && f.type != Type::ObservationGap &&
         f.type != Type::GetNativeProcessContext && f.type != Type::NativeProcessContext &&
         f.type != Type::FileFutureDraftRecord && f.type != Type::PrincipalRulesPage &&
         !(f.type==Type::ObservedRecord && find(f,T::DestinationContext))))
      return Error::Unsupported;
    if (tag <= previous)
      return Error::Malformed;
    previous = tag;
    if (v.bytes.size() > MaxFrameBytes - HeaderBytes - 8 ||
        body > MaxFrameBytes - HeaderBytes - 8 - v.bytes.size())
      return Error::Capacity;
    body += 8 + v.bytes.size();
  }
  if (f.type <= Type::Status || f.type == Type::ProtocolError) {
    Frame base = f;
    base.minor = 2;
    bool status = f.type == Type::HelloAck || f.type == Type::Status;
    if (status) {
      auto source = find(f, T::SourceEpoch), profile = find(f, T::IVProfile),
           caps = find(f, T::Capabilities), context = find(f, T::ServiceContext);
      if (!source || source->bytes.size() != 16 || !source->required ||
          !profile || profile->bytes.size() != 1 || !profile->required ||
          number(*profile) > 1 || !caps || caps->bytes.size() != 8 ||
          !context || !context->required || context->bytes.size() != 56)
        return Error::Malformed;
      const auto epoch = array<16>(context->bytes, 0), boot = array<16>(context->bytes, 16),
                 engine = array<16>(context->bytes, 32);
      const auto generation = n(context->bytes, 48, 8);
      if (zero(epoch) || zero(boot) || epoch != idValue(f, T::ServiceEpoch) ||
          boot != idValue(f, T::BootId) || engine != idValue(f, T::SourceEpoch) ||
          zero(engine) != (generation == 0)) return Error::Malformed;
      auto c = number(*caps);
      if ((c >> 31) || (c & ((0x3full << 6) | (1ull << 16))) ||
          ((c & AdministrativeObservedRead) &&
           (c!=(ReadStatus|ObservedRead|AdministrativeObservedRead) || number(*profile) ||
            zero(engine) || get(f,T::ReviewProfileState)!=1)) ||
          ((c & NativeEvents) && (!(c & ObservedRead) || zero(engine) || get(f,T::ReviewProfileState)!=1)) ||
          ((c & NativeTraffic) && !(c & NativeEvents)) ||
          ((c & NativeProcessFacts) && !(c & NativeEvents)) ||
          ((c & FuturePolicyControl) && !number(*profile)) ||
          ((c & FileFutureControl) && !(c & FuturePolicyControl)) ||
          ((c & AdministrativePrincipalControl) && !(c & FuturePolicyControl)))
        return Error::Malformed;
      base.fields.erase(std::remove_if(base.fields.begin(), base.fields.end(),
                                       [](const auto &v) {
                                         return v.tag == T::SourceEpoch ||
                                                v.tag == T::IVProfile ||
                                                v.tag == T::ServiceContext;
                                       }),
                        base.fields.end());
      for (auto &v : base.fields)
        if (v.tag == T::Capabilities)
          v.bytes = integer(c & ~(ObservedRead | FuturePolicyControl | NativeEvents | NativeTraffic | NativeProcessFacts | FileFutureControl | AdministrativePrincipalControl | AdministrativeObservedRead), 8);
    }
    if (f.type == Type::ProtocolError && get(f, T::ErrorCode) == 18)
      for (auto &v : base.fields)
        if (v.tag == T::ErrorCode)
          v.bytes = integer(1, 2);
    return ii::validate(base);
  }
  auto expected = schema(f);
  if (expected.size() != f.fields.size())
    return Error::Malformed;
  for (const auto &v : f.fields) {
    auto it = expected.find(v.tag);
    if (it == expected.end())
      return Error::Malformed;
    if (!v.required || (it->second != Variable && v.bytes.size() != it->second))
      return Error::Malformed;
    if (it->second == 16 && v.tag != T::SnapshotId && zero(idValue(f, v.tag)))
      return Error::Malformed;
  }
  if(find(f,T::PrincipalObservationOwner)) {
    if(!find(f,T::AdministrativeMode) || zero(idValue(f,T::PrincipalObservationOwner)) ||
       !find(f,T::DestinationContext))return Error::Malformed;
  }
  if(find(f,T::AdministrativeMode)) {
    if(get(f,T::AdministrativeMode)!=1)return Error::Malformed;
    if(const auto sid=find(f,T::SelectedPrincipalSid)) {
      const auto &b=sid->bytes;
      if(b.size()<8 || b.size()>68 || b[0]!=1 || b[1]>15 || b.size()!=8+std::size_t(b[1])*4)
        return Error::Malformed;
    }
    if(const auto target=find(f,T::OriginalTarget)) {
      OriginalTarget parsed;
      if(unpackOriginalTarget(target->bytes,parsed)!=Error::Ok || parsed.accountSid!=find(f,T::SelectedPrincipalSid)->bytes)
        return Error::Malformed;
    }
    if(f.type==Type::PrincipalRulesPage && !find(f,T::ServiceContext))return Error::Malformed;
  }
  const bool activity=f.type==Type::Attempt || f.type==Type::Authorization || f.type==Type::Traffic;
  const bool stream=activity || f.type==Type::ObservationGap || f.type==Type::SubscriptionAck;
  const bool processContext=f.type==Type::GetNativeProcessContext || f.type==Type::NativeProcessContext;
  const bool fileContext=f.type==Type::FileFutureDraftRecord ||
    (f.type==Type::PrincipalRulesPage && find(f,T::ServiceContext));
  const bool destinationReply=f.type==Type::ObservedRecord && find(f,T::DestinationContext);
  if(stream || processContext || fileContext || destinationReply) {
    const auto &b=find(f,T::ServiceContext)->bytes;
    if(array<16>(b,0)!=idValue(f,T::ServiceEpoch) || zero(array<16>(b,16)) ||
       array<16>(b,32)!=idValue(f,T::SourceEpoch) || !n(b,48,8) ||
       ((stream || f.type==Type::NativeProcessContext) && get(f,T::SourceCoverage)!=1)) return Error::Malformed;
  }
  if(const auto destination=find(f,T::DestinationContext)) {
    if(f.type==Type::GetObservedRecord || f.type==Type::SubscribeEvents || f.type==Type::SubscriptionAck) {
      if(number(*destination)!=1)return Error::Malformed;
    } else {
      DestinationContext context;
      if(unpackDestinationContext(destination->bytes,context)!=Error::Ok ||
         (context.present && activity && (get(f,T::Source)!=2 || std::uint64_t{context.direction}!=get(f,T::FlowDirection) ||
           ((get(f,T::Presence)&2) && std::uint64_t{context.protocol}!=get(f,T::Protocol)))) ||
         (context.present && destinationReply && find(f,T::PolicyDirection) &&
           std::uint64_t{context.direction}!=get(f,T::PolicyDirection)))return Error::Malformed;
    }
  }
  if(processContext) {
    if(!attemptSequence(idValue(f,T::AttemptLink)))return Error::Malformed;
    if(f.type==Type::NativeProcessContext &&
       (get(f,T::Source)!=2 || get(f,T::ErrorCode)>18 ||
        (get(f,T::ErrorCode)==0 ? get(f,T::Count)!=1 : get(f,T::Count)!=0)))return Error::Malformed;
  }
  if(f.type==Type::SubscribeEvents || f.type==Type::SubscriptionAck)
    if(get(f,T::EventMask)!=3 && get(f,T::EventMask)!=7) return Error::Malformed;
  if(activity) {
    auto p=get(f,T::Presence), stamp=get(f,T::Timestamp), origin=get(f,T::Source);
    if(!get(f,T::EventSeq) || p>7 || ((p&1) ? !stamp : stamp!=0) ||
       origin<1 || origin>2 || get(f,T::FlowDirection)<1 || get(f,T::FlowDirection)>2 ||
       ((p&2) && (origin!=2 || (get(f,T::Protocol)!=6 && get(f,T::Protocol)!=17))) ||
       ((p&4) && origin!=2))
      return Error::Malformed;
    if(f.type==Type::Authorization) {
      const auto link=attemptSequence(idValue(f,T::AttemptLink));
      if(origin!=2 || !link || link>=get(f,T::EventSeq) ||
         !get(f,T::EffectiveRev) || get(f,T::Decision)<1 || get(f,T::Decision)>2 ||
         get(f,T::ScopeKind)<3 || get(f,T::ScopeKind)>5 ||
         get(f,T::Durable)!=1 || get(f,T::ProofState)!=2) return Error::Malformed;
    }
    if(f.type==Type::Traffic) {
      const auto link=attemptSequence(idValue(f,T::AttemptLink));
      if(origin!=2 || (p!=3 && p!=7) || !link || link>=get(f,T::EventSeq) || !get(f,T::PacketCount) ||
         get(f,T::PacketDirection)<1 || get(f,T::PacketDirection)>2 || !get(f,T::EffectiveRev) ||
         get(f,T::ScopeKind)<3 || get(f,T::ScopeKind)>5 || get(f,T::Durable)!=1 || get(f,T::ProofState)!=2)
        return Error::Malformed;
    }
  }
  if(f.type==Type::ObservationGap) {
    auto known=get(f,T::LostCountKnown), lost=get(f,T::LostCount),
         before=get(f,T::AfterEventSeq), after=get(f,T::EventSeq);
    if(get(f,T::Timestamp) || get(f,T::Presence) || get(f,T::Source)!=3 ||
       known>1 || get(f,T::GapReason)<1 || get(f,T::GapReason)>4 || before>after ||
       (known ? !lost || before>=after || lost!=after-before : lost!=0)) return Error::Malformed;
  }
  for (auto tag :
       {T::ObservedRevision, T::DraftVersion, T::TargetRevision,
        T::RuleRevision, T::ProfileGeneration, T::ObservedSnapshotRevision})
    if (find(f, tag) && !get(f, tag))
      return Error::Malformed;
  if (find(f, T::IVProfile) && get(f, T::IVProfile) != 1)
    return Error::Malformed;
  if (find(f, T::PolicyDirection) &&
      (get(f, T::PolicyDirection) < 1 || get(f, T::PolicyDirection) > 3))
    return Error::Malformed;
  if (f.type == Type::ObservedRecord && find(f,T::PolicyDirection) && get(f,T::PolicyDirection)>2)
    return Error::Malformed;
  if (find(f, T::ExpectedDesiredRev) &&
      get(f, T::ExpectedDesiredRev) == UINT64_MAX)
    return Error::Malformed;
  if (f.type == Type::ListObserved || f.type == Type::ListPrincipalRules) {
    if (!get(f, T::Limit) || get(f, T::Limit) > 32 ||
        (zero(idValue(f, T::SnapshotId)) && get(f, T::Cursor)))
      return Error::Malformed;
  }
  if(f.type==Type::PrepareFileFuturePolicy) {
    const auto &path=find(f,T::Text)->bytes;
    if(path.empty() || path.size()>4096 || !text(path) || get(f,T::ScopeKind)!=2 ||
       get(f,T::PackageMode)!=1 ||
       (find(f,T::Records) &&
         !(find(f,T::OriginalSourceSelection) ? validConditionalFileTarget(find(f,T::Records)->bytes) :
              validPrincipalTarget(find(f,T::Records)->bytes))))return Error::Malformed;
  }
  if(const auto source=find(f,T::OriginalSourceSelection)) {
    OriginalSourceSelection selection;
    if(unpackOriginalSourceSelection(source->bytes,selection)!=Error::Ok)return Error::Malformed;
    if(f.type==Type::PrepareFileFuturePolicy || f.type==Type::FileFutureDraftRecord) {
      const auto path=find(f,T::OriginalSourcePath);
      if(!path || path->bytes.empty() || path->bytes.size()>4096 || !text(path->bytes) || find(f,T::RuleId))return Error::Malformed;
    } else if(f.type!=Type::GetFutureDraft && f.type!=Type::CommitFuturePolicy)return Error::Malformed;
    if(f.type==Type::PrepareFileFuturePolicy || f.type==Type::CommitFuturePolicy) {
      if(get(f,T::ScopeKind)!=2 || get(f,T::PackageMode)!=1 || get(f,T::PolicyDirection)!=1)
        return Error::Malformed;
    }
    if(f.type==Type::FileFutureDraftRecord && (get(f,T::Decision)<1 || get(f,T::Decision)>2))return Error::Malformed;
  }
  if(f.type==Type::ReplacePrincipalRule ||
     ((f.type==Type::PrepareFileFuturePolicy || f.type==Type::FileFutureDraftRecord) && find(f,T::RuleId))) {
    if(!get(f,T::RuleRevision) || get(f,T::RuleRevision)==UINT64_MAX ||
       !get(f,T::SelectorRevision) || get(f,T::SelectorRevision)==UINT64_MAX ||
       find(f,T::PreviousTargetDigest)->bytes==Bytes(32))return Error::Malformed;
    if(f.type==Type::ReplacePrincipalRule &&
       (get(f,T::ScopeKind)!=2 || get(f,T::PackageMode)!=1 || find(f,T::MigrationDigest)->bytes!=Bytes(32)))return Error::Malformed;
  }
  if (f.type == Type::CommitFuturePolicy || f.type==Type::ReplacePrincipalRule) {
    auto a = get(f, T::Decision), p = get(f, T::PackageMode),
         d = get(f, T::PolicyDirection);
    auto scope = get(f,T::ScopeKind);
    if (a < 1 || a > 2 || p < 1 || p > 2 || scope < 2 || scope > 5 ||
        (scope == 2 ? get(f, T::AcceptedScope) !=
            (1u | (p == 1 ? 2u : 0u) | (a == 2 && d == 3 ? 4u : 0u)) :
            p != 1 || (d != 1 && d != 2) || get(f,T::AcceptedScope) != (std::uint64_t{1} << scope)))
      return Error::Malformed;
  }
  if (f.type == Type::PrepareFuturePolicy || f.type == Type::CommitFuturePolicy) {
    const auto scope = find(f,T::ScopeKind) ? get(f,T::ScopeKind) : 2;
    if (scope < 2 || scope > 5 || (scope >= 3 && get(f,T::PolicyDirection) != 1 && get(f,T::PolicyDirection) != 2) ||
        (scope == 5 && (!get(f,T::ScopeDurationMs) || get(f,T::ScopeDurationMs) > 900000)))
      return Error::Malformed;
  }
  if ((f.type == Type::FuturePolicyAck || f.type == Type::FutureCommandStatus) &&
      find(f,T::ScopeKind) && (get(f,T::ScopeKind) < 3 || get(f,T::ScopeKind) > 5))
    return Error::Malformed;
  if (find(f, T::TargetDigest) &&
      std::all_of(find(f, T::TargetDigest)->bytes.begin(),
                  find(f, T::TargetDigest)->bytes.end(),
                  [](auto c) { return !c; }))
    return Error::Malformed;
  if (f.type == Type::GetFutureCommandStatus ||
      f.type == Type::FutureCommandStatus)
    if (f.correlation == idValue(f, T::CommandId))
      return Error::Malformed;
  if (f.type == Type::FuturePolicyAck) {
    if (f.correlation != idValue(f, T::CommandId) || !outcome(f))
      return Error::Malformed;
  }
  if (f.type == Type::FutureCommandStatus) {
    auto found = get(f, T::CommandFound);
    if (found > 1)
      return Error::Malformed;
    if (!found)
      return get(f, T::ErrorCode) == 17 ? Error::Ok : Error::Malformed;
    auto type = get(f, T::OriginalCommandType);
    if ((type != 31 && type != 37 && type!=44) || !outcome(f))
      return Error::Malformed;
  }
  if (auto records = find(f, T::Records); records && f.type!=Type::PrepareFileFuturePolicy) {
    bool page =
        f.type == Type::ObservedPage || f.type == Type::PrincipalRulesPage;
    auto count = page ? get(f, T::Count) : 1;
    if (page) {
      auto next = get(f, T::NextCursor), cursor = get(f, T::Cursor);
      if (count > 32 || zero(idValue(f, T::SnapshotId)) ||
          (!count && next != UINT32_MAX) ||
          (next != UINT32_MAX &&
           (cursor > UINT32_MAX - count || next != cursor + count)))
        return Error::Malformed;
    }
    Error e;
    if(activity || f.type==Type::NativeProcessContext) {
      std::vector<ProcessFacts> rows;
      e=unpack(records->bytes,1,rows);
    } else if (f.type == Type::ObservedPage || f.type == Type::ObservedRecord) {
      std::vector<ObservedRecord> rows;
      e = unpack(records->bytes, count, rows);
      if(destinationReply && (e!=Error::Ok || rows.size()!=1 || rows.front().state!=1 || zero(rows.front().binding)))
        return Error::Malformed;
      if (f.type == Type::ObservedRecord && find(f,T::PolicyDirection) &&
          (e != Error::Ok || rows.size()!=1 || rows.front().state!=1 || zero(rows.front().binding)))
        return Error::Malformed;
      if (e == Error::Ok)
        for (const auto &r : rows)
          if (r.source != idValue(f, T::SourceEpoch))
            return Error::Malformed;
    } else if(f.type==Type::FileFutureDraftRecord) {
      std::vector<FileFutureDraftRecord> rows;
      e=unpack(records->bytes,1,rows);
      if(e==Error::Ok && rows.front().draft.source!=idValue(f,T::SourceEpoch))return Error::Malformed;
      if(e==Error::Ok && bool(find(f,T::OriginalSourceSelection))!=
          validConditionalFileTarget(rows.front().originalTarget))return Error::Malformed;
    } else if (f.type == Type::FutureDraftRecord) {
      std::vector<FutureDraftRecord> rows;
      e = unpack(records->bytes, count, rows);
      if (e == Error::Ok)
        for (const auto &r : rows)
          if (r.source != idValue(f, T::SourceEpoch))
            return Error::Malformed;
    } else {
      std::vector<PrincipalRuleRecord> rows;
      e = unpack(records->bytes, count, rows);
    }
    if (e != Error::Ok)
      return e;
  }
  return Error::Ok;
}
Error canonical(const Frame &f, Bytes &out) {
  if (f.type != Type::CommitFuturePolicy && f.type != Type::RevokePrincipalRule && f.type!=Type::ReplacePrincipalRule)
    return Error::Unsupported;
  auto error = iv::validate(f);
  if (error != Error::Ok)
    return error;
  // El payload de scopes temporales sólo se conserva en ScopedJournal;
  // Snapshot durable sigue rechazándolo en su command/bind propios.
  Frame c = f;
  c.connection.fill(1);
  c.sequence = 1;
  std::sort(c.fields.begin(), c.fields.end(),
            [](const auto &a, const auto &b) { return a.tag < b.tag; });
  Bytes b;
  auto e = encode(c, b);
  if (e != Error::Ok)
    return e;
  if (b.size() > 1024)
    return Error::Capacity;
  out = std::move(b);
  return Error::Ok;
}
} // namespace gb::wire::iv
