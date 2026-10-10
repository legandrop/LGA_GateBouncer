#include "wire_iv.h"
#include <algorithm>
#include <limits>
#include <map>

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
  tail(b, 120, r.display);
  return b;
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
bool parse(const Bytes &b, FutureDraftRecord &r) {
  if (b.size() < 240 || !zeros(b, 190, 2) || !zeros(b, 228, 12))
    return false;
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
  return tail(b, 240, 180, r.display) && valid(r);
}
bool parse(const Bytes &b, PrincipalRuleRecord &r) {
  if (b.size() < 160 || b[119] || !zeros(b, 136, 24))
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
  return tail(b, 160, 120, r.display) && valid(r);
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
    for (auto v : {integer(p.size(), 4), integer(kind, 2), integer(1, 2)})
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
    if (n(b, at + 4, 2) != kind || n(b, at + 6, 2) != 1)
      return Error::Unsupported;
    if (size > max || size > b.size() - at - 8)
      return Error::Malformed;
    Bytes p(b.begin() + at + 8, b.begin() + at + 8 + size);
    R r;
    if (!parse(p, r))
      return Error::Malformed;
    rows.push_back(std::move(r));
    at += 8 + size;
  }
  if (at != b.size())
    return Error::Malformed;
  out = std::move(rows);
  return Error::Ok;
}
Schema schema(const Frame &f) {
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
  case Type::GetFutureDraft:
    return {{T::ServiceEpoch, 16},
            {T::ProfileGeneration, 8},
            {T::DraftId, 16},
            {T::DraftVersion, 8},
            {T::IVProfile, 1}};
  case Type::CommitFuturePolicy: {
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
  case Type::PrincipalRulesPage:
    return {{T::ServiceEpoch, 16}, {T::DesiredRev, 8}, {T::SnapshotId, 16},
            {T::Cursor, 4},        {T::NextCursor, 4}, {T::Count, 2},
            {T::Records, Variable}};
  default:
    return {};
  }
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
bool supported(Type t) {
  return t == Type::Hello || t == Type::HelloAck || t == Type::GetStatus ||
         t == Type::Status || t == Type::ProtocolError ||
         (t >= Type::ListObserved && t <= Type::ReviewQueued);
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
      (frame.type != Type::HelloAck && frame.type != Type::Status))
    return Error::Unsupported;
  const auto error = iv::validate(frame);
  if (error != Error::Ok) return error;
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
             r.package == 1 && r.direction == 1 && r.accepted == (1u << r.scope) &&
             (r.scope == 5 ? r.durationMs >= 1 && r.durationMs <= 900000 : !r.durationMs));
  return zero(r.selector) && !r.targetRevision && r.target == Digest{} &&
         zero(r.challenge) && !r.ttl && r.proof == Proof::Unknown &&
         !r.accepted &&
         (r.state == 1   ? reason == 0
          : r.state == 2 ? reason >= 1 && reason <= 18
                         : reason == 3 || reason == 12);
}
bool valid(const PrincipalRuleRecord &r) {
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
  return r.targetKind == 1
             ? r.scope == 2 && r.package >= 1 && r.package <= 2 && r.origin == 1
             : r.targetKind == 2 && r.scope == 1 && !r.package && !r.origin &&
                   r.display.principal.empty() && r.display.package.empty();
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
Error unpack(const Bytes &b, std::size_t c, std::vector<ObservedRecord> &r) {
  return unpackRecords(b, c, r, 3, 4960);
}
Error unpack(const Bytes &b, std::size_t c, std::vector<FutureDraftRecord> &r) {
  return unpackRecords(b, c, r, 4, 5104);
}
Error unpack(const Bytes &b, std::size_t c,
             std::vector<PrincipalRuleRecord> &r) {
  return unpackRecords(b, c, r, 5, 5024);
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
    if (tag < 1 || tag > static_cast<unsigned>(T::ScopeDurationMs) || tag == 57 ||
        (v.tag == T::ServiceContext && f.type != Type::HelloAck && f.type != Type::Status))
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
      if ((c >> 25) || (c & ((0x3full << 6) | (1ull << 16))) ||
          ((c & FuturePolicyControl) && !number(*profile)))
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
          v.bytes = integer(c & ~(ObservedRead | FuturePolicyControl), 8);
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
  if (find(f, T::ExpectedDesiredRev) &&
      get(f, T::ExpectedDesiredRev) == UINT64_MAX)
    return Error::Malformed;
  if (f.type == Type::ListObserved || f.type == Type::ListPrincipalRules) {
    if (!get(f, T::Limit) || get(f, T::Limit) > 32 ||
        (zero(idValue(f, T::SnapshotId)) && get(f, T::Cursor)))
      return Error::Malformed;
  }
  if (f.type == Type::CommitFuturePolicy) {
    auto a = get(f, T::Decision), p = get(f, T::PackageMode),
         d = get(f, T::PolicyDirection);
    auto scope = get(f,T::ScopeKind);
    if (a < 1 || a > 2 || p < 1 || p > 2 || scope < 2 || scope > 5 ||
        (scope == 2 ? get(f, T::AcceptedScope) !=
            (1u | (p == 1 ? 2u : 0u) | (a == 2 && d == 3 ? 4u : 0u)) :
            p != 1 || d != 1 || get(f,T::AcceptedScope) != (1u << scope)))
      return Error::Malformed;
  }
  if (f.type == Type::PrepareFuturePolicy || f.type == Type::CommitFuturePolicy) {
    const auto scope = find(f,T::ScopeKind) ? get(f,T::ScopeKind) : 2;
    if (scope < 2 || scope > 5 || (scope >= 3 && get(f,T::PolicyDirection) != 1) ||
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
    if ((type != 31 && type != 37) || !outcome(f))
      return Error::Malformed;
  }
  if (auto records = find(f, T::Records)) {
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
    if (f.type == Type::ObservedPage || f.type == Type::ObservedRecord) {
      std::vector<ObservedRecord> rows;
      e = unpack(records->bytes, count, rows);
      if (e == Error::Ok)
        for (const auto &r : rows)
          if (r.source != idValue(f, T::SourceEpoch))
            return Error::Malformed;
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
  if (f.type != Type::CommitFuturePolicy && f.type != Type::RevokePrincipalRule)
    return Error::Unsupported;
  auto error = iv::validate(f);
  if (error != Error::Ok)
    return error;
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
