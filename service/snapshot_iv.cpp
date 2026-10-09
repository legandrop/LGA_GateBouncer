#include "snapshot_iv.h"
#include <algorithm>
#include <bcrypt.h>
#include <set>
#include <stdexcept>

namespace gb::principal {
ByteView::ByteView(Bytes b)
    : owner_(std::make_shared<const Bytes>(std::move(b))),
      size_(owner_->size()) {}
const std::uint8_t *ByteView::data() const {
  return owner_ && !owner_->empty() ? owner_->data() + offset_ : nullptr;
}
ByteView ByteView::sub(std::size_t p, std::size_t n) const {
  if (p > size_ || n > size_ - p)
    throw std::out_of_range("Vista fuera del buffer");
  auto v = *this;
  v.offset_ += p;
  v.size_ = n;
  return v;
}
Bytes ByteView::copy() const {
  return size_ ? Bytes(data(), data() + size_) : Bytes{};
}
bool ByteView::operator==(const ByteView &b) const {
  return size_ == b.size_ &&
         (!size_ || std::equal(data(), data() + size_, b.data()));
}
namespace {
std::uint64_t n(const ByteView &b, std::size_t p, std::size_t w) {
  auto v = b.sub(p, w);
  std::uint64_t x = 0;
  for (std::size_t i = 0; i < w; ++i)
    x |= std::uint64_t(v.data()[i]) << (8 * i);
  return x;
}
template <std::size_t N>
std::array<std::uint8_t, N> array(const ByteView &b, std::size_t p) {
  auto v = b.sub(p, N);
  std::array<std::uint8_t, N> a{};
  std::copy_n(v.data(), N, a.begin());
  return a;
}
bool zeros(const ByteView &b, std::size_t p, std::size_t w) {
  auto v = b.sub(p, w);
  return !w || std::all_of(v.data(), v.data() + w, [](auto c) { return !c; });
}
bool magic(const ByteView &b, const char *s) {
  return b.size() >= 4 && std::equal(s, s + 4, b.data());
}
void put(Bytes &b, std::size_t p, std::uint64_t v, std::size_t w) {
  for (std::size_t i = 0; i < w; ++i)
    b[p + i] = std::uint8_t(v >> (8 * i));
}
template <std::size_t N>
void put(Bytes &b, std::size_t p, const std::array<std::uint8_t, N> &v) {
  std::copy(v.begin(), v.end(), b.begin() + p);
}
void append(Bytes &b, const ByteView &v) {
  if (v.size())
    b.insert(b.end(), v.data(), v.data() + v.size());
}
template <std::size_t N>
void append(Bytes &b, const std::array<std::uint8_t, N> &v) {
  b.insert(b.end(), v.begin(), v.end());
}
void append(Bytes &b, std::uint64_t v, std::size_t w) {
  auto a = integer(v, w);
  b.insert(b.end(), a.begin(), a.end());
}
// Hash por segmentos: los APP_ID, journal y archive permanecen en su buffer
// original.
class Hash {
  BCRYPT_ALG_HANDLE alg_ = nullptr;
  BCRYPT_HASH_HANDLE hash_ = nullptr;

public:
  Hash() {
    if (BCryptOpenAlgorithmProvider(&alg_, BCRYPT_SHA256_ALGORITHM, nullptr,
                                    0) < 0 ||
        BCryptCreateHash(alg_, &hash_, nullptr, 0, nullptr, 0, 0) < 0) {
      if (alg_)
        BCryptCloseAlgorithmProvider(alg_, 0);
      throw std::runtime_error("No se pudo iniciar SHA256");
    }
  }
  ~Hash() {
    if (hash_)
      BCryptDestroyHash(hash_);
    if (alg_)
      BCryptCloseAlgorithmProvider(alg_, 0);
  }
  Hash(const Hash &) = delete;
  Hash &operator=(const Hash &) = delete;
  void add(const ByteView &b) {
    if (b.size() && BCryptHashData(hash_, const_cast<PUCHAR>(b.data()),
                                   ULONG(b.size()), 0) < 0)
      throw std::runtime_error("SHA256 fallo");
  }
  void add(const Bytes &b) {
    if (!b.empty() && BCryptHashData(hash_, const_cast<PUCHAR>(b.data()),
                                     ULONG(b.size()), 0) < 0)
      throw std::runtime_error("SHA256 fallo");
  }
  template <std::size_t N> void add(const std::array<std::uint8_t, N> &b) {
    if (BCryptHashData(hash_, const_cast<PUCHAR>(b.data()), ULONG(N), 0) < 0)
      throw std::runtime_error("SHA256 fallo");
  }
  void domain(const char *s) {
    if (BCryptHashData(hash_, reinterpret_cast<PUCHAR>(const_cast<char *>(s)),
                       8, 0) < 0)
      throw std::runtime_error("SHA256 fallo");
  }
  Digest end() {
    Digest d{};
    if (BCryptFinishHash(hash_, d.data(), 32, 0) < 0)
      throw std::runtime_error("SHA256 fallo");
    return d;
  }
};
Digest hash(const ByteView &b) {
  Hash h;
  h.add(b);
  return h.end();
}
Digest domainHash(const char *s, const ByteView &b) {
  Hash h;
  h.domain(s);
  h.add(integer(b.size(), 4));
  h.add(b);
  return h.end();
}
bool checksum(const ByteView &b) {
  return b.size() >= 32 &&
         hash(b.sub(0, b.size() - 32)) == array<32>(b, b.size() - 32);
}
std::uint8_t mode(unsigned action, unsigned direction) {
  return action == 1 || direction == 2 ? 0 : direction == 1 ? 1 : 2;
}
bool legacyRule(const Rule &r) {
  const auto &b = r.target;
  if (b.size() < 57 || b.size() > 53 + 32768 || n(b, 49, 4) != b.size() - 53 ||
      b.size() % 2 != 1 || array<16>(b, 0) != r.id ||
      array<16>(b, 16) != r.selector || n(b, 32, 8) != r.revision ||
      n(b, 40, 8) != r.targetRevision || n(b, 48, 1) != r.action ||
      r.targetRevision != 1)
    return false;
  return n(b, 53, 2) == '\\';
}
ByteView app(const Rule &r) {
  if (r.kind == 2)
    return r.target.sub(53, r.target.size() - 53);
  Target t;
  if (!parseTarget(r.target, t))
    throw std::runtime_error("Target invalido");
  return t.app;
}
bool oldEntry(const ByteView &envelope, directional::Entry &out) {
  if (envelope.size() < 136 || envelope.size() > 1544 ||
      n(envelope, 0, 4) != envelope.size() - 8 || n(envelope, 4, 2) != 1)
    return false;
  auto version = n(envelope, 6, 2);
  auto p = envelope.sub(8, envelope.size() - 8);
  directional::Entry e;
  auto &c = e.command;
  if (version == 1) {
    Bytes j(64);
    j[0] = 'G';
    j[1] = 'B';
    j[2] = 'J';
    j[3] = '2';
    put(j, 4, 1, 2);
    put(j, 12, 1, 4);
    put(j, 16, 1, 8);
    put(j, 24, n(p, 72, 8), 8);
    j[32] = 1;
    append(j, envelope);
    put(j, 8, j.size() + 32, 4);
    append(j, native::digest(j));
    decisions::JournalSnapshot s;
    if (!decisions::parseJournal(j, s) || s.entries.size() != 1)
      return false;
    e.command = std::move(s.entries[0]);
    e.legacyEnvelope = envelope.copy();
  } else if (version == 2) {
    if (p.size() < 232 || n(p, 113, 1) > 1 || n(p, 133, 1) != 1 ||
        !zeros(p, 134, 2))
      return false;
    auto ca = n(p, 116, 4), a = n(p, 120, 2), l = n(p, 122, 2),
         pr = n(p, 128, 4);
    if (ca > 512 || a > 68 || l > 68 || pr > 512 ||
        232 + ca + pr + a + l != p.size())
      return false;
    c.id = array<16>(p, 0);
    c.commandEpoch = array<16>(p, 16);
    c.principal = array<16>(p, 32);
    c.logon = array<16>(p, 48);
    c.profileGeneration = n(p, 64, 8);
    c.desired = n(p, 72, 8);
    c.effective = n(p, 80, 8);
    c.completedAt = n(p, 88, 8);
    c.boot = array<16>(p, 96);
    c.state = static_cast<State>(n(p, 112, 1));
    c.effectiveKnown = n(p, 113, 1) != 0;
    c.error = static_cast<Error>(n(p, 114, 2));
    c.sessionId = std::uint32_t(n(p, 124, 4));
    e.effect = std::uint8_t(n(p, 132, 1));
    e.admission = array<32>(p, 136);
    e.projection = array<32>(p, 168);
    e.target = array<32>(p, 200);
    c.payload = p.sub(232, ca).copy();
    e.projected = p.sub(232 + ca, pr).copy();
    c.accountSid = p.sub(232 + ca + pr, a).copy();
    c.logonSid = p.sub(232 + ca + pr + a, l).copy();
  } else
    return false;
  if (!directional::entryValid(e))
    return false;
  out = std::move(e);
  return true;
}
Bytes prefix(const Entry &e) {
  const auto &c = e.command;
  Bytes p(304);
  put(p, 0, c.id);
  put(p, 16, c.commandEpoch);
  put(p, 32, c.principal);
  put(p, 48, c.logon);
  put(p, 64, c.profileGeneration, 8);
  put(p, 72, c.desired, 8);
  put(p, 80, c.effective, 8);
  put(p, 88, c.completedAt, 8);
  put(p, 96, c.boot);
  p[112] = static_cast<std::uint8_t>(c.state);
  p[113] = c.effectiveKnown ? 1 : 0;
  put(p, 114, static_cast<unsigned>(c.error), 2);
  put(p, 116, c.payload.size(), 4);
  put(p, 120, c.accountSid.size(), 2);
  put(p, 122, c.logonSid.size(), 2);
  put(p, 124, c.sessionId, 4);
  put(p, 128, 160, 4);
  p[132] = e.effect;
  p[133] = 1;
  p[134] = 1;
  put(p, 136, e.admission);
  put(p, 168, e.projection);
  put(p, 200, e.targetSet);
  put(p, 232, e.draft);
  put(p, 248, e.draftVersion, 8);
  put(p, 256, e.targetRevision, 8);
  put(p, 264, e.source);
  put(p, 280, e.binding);
  put(p, 296, e.accepted, 2);
  p[298] = e.direction;
  p[299] = e.packageMode;
  return p;
}
Digest admission(const Entry &e) {
  ByteView p(prefix(e));
  Hash h;
  h.domain("GBS4CMD1");
  h.add(p.sub(0, 80));
  h.add(p.sub(96, 16));
  h.add(p.sub(124, 12));
  h.add(p.sub(232, 72));
  h.add(integer(e.command.payload.size(), 4));
  h.add(e.command.payload);
  h.add(integer(160, 4));
  h.add(e.projected);
  h.add(integer(e.command.accountSid.size(), 2));
  h.add(e.command.accountSid);
  h.add(integer(e.command.logonSid.size(), 2));
  h.add(e.command.logonSid);
  h.add(e.targetSet);
  return h.end();
}
bool command(const Entry &e, Frame &f) {
  const auto &c = e.command;
  if (zero(c.id) || zero(c.commandEpoch) || zero(c.principal) ||
      zero(c.logon) || zero(c.boot) || !c.profileGeneration ||
      c.payload.size() > 1024 || !sidValid(ByteView(c.accountSid)) ||
      !sidValid(ByteView(c.logonSid)) || decode(c.payload, f) != Error::Ok ||
      f.minor != 3 ||
      (f.type != Type::CommitFuturePolicy &&
       f.type != Type::RevokePrincipalRule) ||
      f.correlation != c.id || f.sequence != 1 ||
      f.connection != Id{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1} ||
      idValue(f, Tag::ServiceEpoch) != c.commandEpoch ||
      get(f, Tag::ProfileGeneration) != c.profileGeneration ||
      get(f, Tag::ExpectedDesiredRev) == UINT64_MAX ||
      c.desired != get(f, Tag::ExpectedDesiredRev) + 1)
    return false;
  const auto account = hash(ByteView(c.accountSid)),
             logon = hash(ByteView(c.logonSid));
  if (!std::equal(c.principal.begin(), c.principal.end(), account.begin()) ||
      !std::equal(c.logon.begin(), c.logon.end(), logon.begin()))
    return false;
  auto s = static_cast<unsigned>(c.state), err = static_cast<unsigned>(c.error);
  if (s < 1 || s > 4 || err > 18 || err == 17 || c.effective > c.desired ||
      (!c.effectiveKnown && c.effective) ||
      (c.effectiveKnown && c.effective != c.desired))
    return false;
  if (s == 1 && (err || c.effectiveKnown || c.completedAt))
    return false;
  if (s == 2 && (err || !c.effectiveKnown))
    return false;
  if (s == 3 && (!err || c.effectiveKnown))
    return false;
  if (s == 4 &&
      ((err != 8 && err != 9 && err != 10 && err != 13) || c.effectiveKnown))
    return false;
  return true;
}
bool readEntry(const ByteView &p, Entry &e) {
  if (p.size() < 304 || p.size() > 1624 || n(p, 113, 1) > 1 ||
      n(p, 128, 4) != 160 || n(p, 133, 1) != 1 || n(p, 134, 1) != 1 ||
      !zeros(p, 135, 1) || !zeros(p, 300, 4))
    return false;
  auto ca = n(p, 116, 4), a = n(p, 120, 2), l = n(p, 122, 2);
  if (ca > 1024 || a > 68 || l > 68 || 304 + ca + 160 + a + l != p.size())
    return false;
  auto &c = e.command;
  c.id = array<16>(p, 0);
  c.commandEpoch = array<16>(p, 16);
  c.principal = array<16>(p, 32);
  c.logon = array<16>(p, 48);
  c.profileGeneration = n(p, 64, 8);
  c.desired = n(p, 72, 8);
  c.effective = n(p, 80, 8);
  c.completedAt = n(p, 88, 8);
  c.boot = array<16>(p, 96);
  c.state = static_cast<State>(n(p, 112, 1));
  c.effectiveKnown = n(p, 113, 1) != 0;
  c.error = static_cast<Error>(n(p, 114, 2));
  c.sessionId = std::uint32_t(n(p, 124, 4));
  e.effect = std::uint8_t(n(p, 132, 1));
  e.admission = array<32>(p, 136);
  e.projection = array<32>(p, 168);
  e.targetSet = array<32>(p, 200);
  e.draft = array<16>(p, 232);
  e.draftVersion = n(p, 248, 8);
  e.targetRevision = n(p, 256, 8);
  e.source = array<16>(p, 264);
  e.binding = array<16>(p, 280);
  e.accepted = std::uint16_t(n(p, 296, 2));
  e.direction = std::uint8_t(n(p, 298, 1));
  e.packageMode = std::uint8_t(n(p, 299, 1));
  c.payload = p.sub(304, ca).copy();
  e.projected = p.sub(304 + ca, 160).copy();
  c.accountSid = p.sub(464 + ca, a).copy();
  c.logonSid = p.sub(464 + ca + a, l).copy();
  return entryValid(e);
}
bool headerRules(const ByteView &p, const ByteView &d, std::uint64_t desired,
                 unsigned version, std::vector<Rule> &out) {
  const bool modern = version == 4;
  const auto fixed = modern ? 24u : 16u;
  if (p.size() < fixed || d.size() < 24 ||
      !magic(p, modern ? "PRL4" : "PRL3") || n(p, 4, 2) != 1 ||
      (modern ? (n(p, 6, 2) != 24 || n(p, 8, 4) != p.size() ||
                 n(p, 16, 2) != 1 || !zeros(p, 18, 6))
              : (n(p, 6, 2) || n(p, 12, 2) != 53 || n(p, 14, 2))) ||
      !magic(d, "DIR1") || n(d, 4, 2) != 1 || n(d, 6, 2) != 40 || n(d, 12, 4) ||
      n(d, 16, 8) != desired)
    return false;
  auto count = n(p, modern ? 12 : 8, 4);
  if (count > 4096 || count != n(d, 8, 4) || 24 + count * 40 != d.size())
    return false;
  std::vector<Rule> rows;
  std::size_t at = fixed;
  for (std::size_t i = 0; i < count; ++i) {
    Rule r;
    ByteView row;
    if (modern) {
      if (p.size() - at < 72)
        return false;
      auto size = std::size_t(n(p, at, 4));
      auto kind = n(p, at + 4, 2);
      if (size < 64 || size > 65760 || size > p.size() - at - 8 || kind < 1 ||
          kind > 2 || n(p, at + 6, 2) != 1)
        return false;
      row = p.sub(at + 8, size);
      r.kind = std::uint8_t(kind);
      at += 8 + size;
      if (!zeros(row, 50, 6) || !zeros(row, 60, 4) ||
          n(row, 56, 4) != size - 64 || n(row, 49, 1) != (kind == 1 ? 1 : 0))
        return false;
      r.target = row.sub(64, size - 64);
    } else {
      if (p.size() - at < 53)
        return false;
      auto size = n(p, at + 49, 4);
      if (size > 32768 || size > p.size() - at - 53)
        return false;
      row = p.sub(at, 53 + std::size_t(size));
      at += row.size();
      r.kind = 2;
      r.target = row;
    }
    r.id = array<16>(row, 0);
    r.selector = array<16>(row, 16);
    r.revision = n(row, 32, 8);
    r.targetRevision = n(row, 40, 8);
    r.action = std::uint8_t(n(row, 48, 1));
    const auto q = 24 + 40 * i;
    r.direction = std::uint8_t(n(d, q + 32, 1));
    r.mode = std::uint8_t(n(d, q + 33, 1));
    if (r.id != array<16>(d, q) || r.selector != array<16>(d, q + 16) ||
        !zeros(d, q + 34, 6) || (!rows.empty() && rows.back().id >= r.id))
      return false;
    rows.push_back(std::move(r));
  }
  if (at != p.size() || !rulesValid(rows))
    return false;
  out = std::move(rows);
  return true;
}
} // namespace
bool sidValid(const ByteView &b) {
  return b.size() >= 8 && b.size() <= 68 && n(b, 0, 1) == 1 &&
         n(b, 1, 1) <= 15 && b.size() == 8 + 4 * n(b, 1, 1);
}
bool parseTarget(const ByteView &b, Target &out) {
  try {
    if (b.size() < 24 || b.size() > MaxTargetBytes || !magic(b, "APT1") ||
        n(b, 4, 2) != 1 || n(b, 6, 2) != 24 || n(b, 17, 1) != 2 ||
        !zeros(b, 18, 6))
      return false;
    auto a = n(b, 8, 4), u = n(b, 12, 2), p = n(b, 14, 2), m = n(b, 16, 1);
    if (!a || a > 65536 || u > 68 || p > 68 || 24 + a + u + p != b.size() ||
        m < 1 || m > 2 || (m == 1 && p))
      return false;
    Target t;
    t.encoded = b;
    t.app = b.sub(24, std::size_t(a));
    t.user = b.sub(24 + std::size_t(a), std::size_t(u));
    t.package = b.sub(24 + std::size_t(a + u), std::size_t(p));
    t.packageMode = std::uint8_t(m);
    if (!sidValid(t.user) || (m == 2 && !sidValid(t.package)))
      return false;
    out = std::move(t);
    return true;
  } catch (...) {
    return false;
  }
}
bool serializeTarget(const ByteView &a, const ByteView &u, std::uint8_t m,
                     const ByteView &p, Bytes &out) {
  if (!a.size() || a.size() > 65536 || !sidValid(u) || m < 1 || m > 2 ||
      (m == 1 ? p.size() != 0 : !sidValid(p)))
    return false;
  Bytes b(24);
  b[0] = 'A';
  b[1] = 'P';
  b[2] = 'T';
  b[3] = '1';
  put(b, 4, 1, 2);
  put(b, 6, 24, 2);
  put(b, 8, a.size(), 4);
  put(b, 12, u.size(), 2);
  put(b, 14, p.size(), 2);
  b[16] = m;
  b[17] = 2;
  append(b, a);
  append(b, u);
  append(b, p);
  out = std::move(b);
  return true;
}
Digest targetDigest(const ByteView &b, bool legacy) {
  return domainHash(legacy ? "GBS4LGT1" : "GBS4TGT1", b);
}
bool overlaps(const Rule &a, const Rule &b) {
  if (!(a.direction & b.direction) || app(a) != app(b))
    return false;
  if (a.kind == 2 || b.kind == 2)
    return true;
  Target x, y;
  if (!parseTarget(a.target, x) || !parseTarget(b.target, y))
    return true;
  return x.user == y.user &&
         (x.packageMode == 1 || y.packageMode == 1 || x.package == y.package);
}
bool rulesValid(const std::vector<Rule> &rows) {
  try {
    if (rows.size() > 4096)
      return false;
    std::set<Id> ids;
    for (std::size_t i = 0; i < rows.size(); ++i) {
      const auto &r = rows[i];
      Target t;
      if (zero(r.id) || zero(r.selector) || !ids.insert(r.id).second ||
          r.revision != 1 || !r.targetRevision || r.action < 1 ||
          r.action > 2 || r.direction < 1 || r.direction > 3 ||
          r.mode != mode(r.action, r.direction) ||
          (r.kind == 1 ? !parseTarget(r.target, t)
                       : r.kind != 2 || !legacyRule(r)))
        return false;
      for (std::size_t j = 0; j < i; ++j)
        if ((rows[j].selector == r.selector && rows[j].target != r.target) ||
            overlaps(rows[j], r))
          return false;
    }
    return true;
  } catch (...) {
    return false;
  }
}
bool sections(const std::vector<Rule> &rows, std::uint64_t desired,
              Bytes &policy, Bytes &directions) {
  if (!rulesValid(rows))
    return false;
  std::size_t size = 24;
  for (const auto &r : rows) {
    if (r.target.size() + 72 > MaxSnapshotBytes - size)
      return false;
    size += 72 + r.target.size();
  }
  std::vector<const Rule *> ordered;
  for (const auto &r : rows)
    ordered.push_back(&r);
  std::sort(ordered.begin(), ordered.end(),
            [](auto a, auto b) { return a->id < b->id; });
  Bytes p(24), d(24);
  p[0] = 'P';
  p[1] = 'R';
  p[2] = 'L';
  p[3] = '4';
  put(p, 4, 1, 2);
  put(p, 6, 24, 2);
  put(p, 8, size, 4);
  put(p, 12, rows.size(), 4);
  put(p, 16, 1, 2);
  d[0] = 'D';
  d[1] = 'I';
  d[2] = 'R';
  d[3] = '1';
  put(d, 4, 1, 2);
  put(d, 6, 40, 2);
  put(d, 8, rows.size(), 4);
  put(d, 16, desired, 8);
  p.reserve(size);
  for (auto r : ordered) {
    append(p, r->target.size() + 64, 4);
    append(p, r->kind, 2);
    append(p, 1, 2);
    auto at = p.size();
    p.resize(at + 64);
    put(p, at, r->id);
    put(p, at + 16, r->selector);
    put(p, at + 32, r->revision, 8);
    put(p, at + 40, r->targetRevision, 8);
    p[at + 48] = r->action;
    p[at + 49] = r->kind == 1 ? 1 : 0;
    put(p, at + 56, r->target.size(), 4);
    append(p, r->target);
    append(d, r->id);
    append(d, r->selector);
    append(d, r->direction, 1);
    append(d, r->mode, 1);
    d.resize(d.size() + 6);
  }
  policy = std::move(p);
  directions = std::move(d);
  return true;
}
Digest targetSetDigest(std::uint64_t desired, const ByteView &p,
                       const ByteView &d) {
  Hash h;
  h.domain("GBS4SET1");
  h.add(integer(desired, 8));
  h.add(integer(p.size(), 4));
  h.add(p);
  h.add(integer(d.size(), 4));
  h.add(d);
  return h.end();
}
bool project(const Frame &f, const Digest &set, Bytes &out) {
  if (f.minor != 3 || validate(f) != Error::Ok ||
      (f.type != Type::CommitFuturePolicy &&
       f.type != Type::RevokePrincipalRule))
    return false;
  Bytes p(160);
  p[0] = 'P';
  p[1] = 'R';
  p[2] = 'J';
  p[3] = '4';
  put(p, 4, 1, 2);
  put(p, 6, 160, 2);
  put(p, 8, 160, 4);
  bool create = f.type == Type::CommitFuturePolicy;
  p[12] = create ? 1 : 2;
  put(p, 16, get(f, Tag::ExpectedDesiredRev), 8);
  put(p, 24, create ? 1 : get(f, Tag::RuleRevision), 8);
  put(p, 32, create ? f.correlation : idValue(f, Tag::RuleId));
  put(p, 64, get(f, Tag::TargetRevision), 8);
  auto target = find(f, Tag::TargetDigest);
  std::copy(target->bytes.begin(), target->bytes.end(), p.begin() + 72);
  put(p, 104, set);
  p[138] = 1;
  if (create) {
    p[13] = std::uint8_t(get(f, Tag::PolicyDirection));
    p[14] = std::uint8_t(get(f, Tag::Decision));
    p[15] = mode(p[14], p[13]);
    put(p, 48, idValue(f, Tag::SelectorId));
    put(p, 136, get(f, Tag::AcceptedScope), 2);
    p[139] = std::uint8_t(get(f, Tag::PackageMode));
  }
  out = std::move(p);
  return true;
}
bool entryValid(const Entry &e) {
  try {
    if (e.legacyEnvelope.size()) {
      directional::Entry old;
      if (!oldEntry(e.legacyEnvelope, old))
        return false;
      const auto &a = e.command, &b = old.command;
      return a.id == b.id && a.commandEpoch == b.commandEpoch &&
             a.principal == b.principal && a.logon == b.logon &&
             a.profileGeneration == b.profileGeneration &&
             a.desired == b.desired && a.effective == b.effective &&
             a.completedAt == b.completedAt && a.boot == b.boot &&
             a.state == b.state && a.effectiveKnown == b.effectiveKnown &&
             a.error == b.error && a.sessionId == b.sessionId &&
             a.payload == b.payload && a.accountSid == b.accountSid &&
             a.logonSid == b.logonSid && e.projected.empty() && !e.effect &&
             !e.direction && !e.packageMode && !e.accepted && zero(e.draft) &&
             zero(e.source) && zero(e.binding) && !e.draftVersion &&
             !e.targetRevision && e.admission == Digest{} &&
             e.projection == Digest{} && e.targetSet == Digest{};
    }
    Frame f;
    Bytes p;
    if (!command(e, f) || !project(f, e.targetSet, p) || p != e.projected ||
        e.projection != domainHash("GBS4PRJ1", ByteView(p)) ||
        e.admission != admission(e))
      return false;
    if (e.targetRevision != get(f, Tag::TargetRevision))
      return false;
    if (f.type == Type::CommitFuturePolicy)
      return e.effect == 1 && e.draft == idValue(f, Tag::DraftId) &&
             e.draftVersion == get(f, Tag::DraftVersion) &&
             e.source == idValue(f, Tag::SourceEpoch) &&
             e.binding == idValue(f, Tag::CaptureBindingId) &&
             e.accepted == get(f, Tag::AcceptedScope) &&
             e.direction == get(f, Tag::PolicyDirection) &&
             e.packageMode == get(f, Tag::PackageMode);
    return e.effect == 2 && zero(e.draft) && !e.draftVersion &&
           zero(e.source) && zero(e.binding) && !e.accepted && !e.direction &&
           !e.packageMode;
  } catch (...) {
    return false;
  }
}
bool bindEntry(Entry &e, const Digest &set) {
  try {
    Frame f;
    if (e.legacyEnvelope.size() || !command(e, f))
      return false;
    e.targetSet = set;
    if (!project(f, set, e.projected))
      return false;
    e.effect = f.type == Type::CommitFuturePolicy ? 1 : 2;
    e.targetRevision = get(f, Tag::TargetRevision);
    if (e.effect == 1) {
      e.draft = idValue(f, Tag::DraftId);
      e.draftVersion = get(f, Tag::DraftVersion);
      e.source = idValue(f, Tag::SourceEpoch);
      e.binding = idValue(f, Tag::CaptureBindingId);
      e.accepted = std::uint16_t(get(f, Tag::AcceptedScope));
      e.direction = std::uint8_t(get(f, Tag::PolicyDirection));
      e.packageMode = std::uint8_t(get(f, Tag::PackageMode));
    } else {
      e.draft = {};
      e.draftVersion = 0;
      e.source = {};
      e.binding = {};
      e.accepted = 0;
      e.direction = 0;
      e.packageMode = 0;
    }
    e.projection = domainHash("GBS4PRJ1", ByteView(e.projected));
    e.admission = admission(e);
    return entryValid(e);
  } catch (...) {
    return false;
  }
}
bool serializeJournal(const std::vector<Entry> &entries, std::uint64_t sequence,
                      std::uint64_t desired, const Id &writer, Bytes &out) {
  try {
    if (!sequence || zero(writer) || entries.size() > 4096)
      return false;
    std::size_t total = 96;
    for (const auto &e : entries) {
      auto size = e.legacyEnvelope.size()
                      ? e.legacyEnvelope.size()
                      : 304 + e.command.payload.size() + 160 +
                            e.command.accountSid.size() +
                            e.command.logonSid.size();
      if (size + 8 > decisions::MaxJournalBytes - total)
        return false;
      total += 8 + size;
    }
    Bytes b(64);
    b[0] = 'G';
    b[1] = 'B';
    b[2] = 'J';
    b[3] = '4';
    put(b, 4, 1, 2);
    put(b, 6, 64, 2);
    put(b, 8, total, 4);
    put(b, 12, entries.size(), 4);
    put(b, 16, sequence, 8);
    put(b, 24, desired, 8);
    put(b, 32, writer);
    b.reserve(total);
    std::set<Id> ids;
    for (const auto &e : entries) {
      if (!entryValid(e) || !ids.insert(e.command.id).second)
        return false;
      if (e.legacyEnvelope.size()) {
        append(b, e.legacyEnvelope.size(), 4);
        append(b, 2, 2);
        append(b, 1, 2);
        append(b, e.legacyEnvelope);
      } else {
        auto p = prefix(e);
        p.insert(p.end(), e.command.payload.begin(), e.command.payload.end());
        p.insert(p.end(), e.projected.begin(), e.projected.end());
        p.insert(p.end(), e.command.accountSid.begin(),
                 e.command.accountSid.end());
        p.insert(p.end(), e.command.logonSid.begin(), e.command.logonSid.end());
        append(b, p.size(), 4);
        append(b, 1, 2);
        append(b, 1, 2);
        b.insert(b.end(), p.begin(), p.end());
      }
    }
    append(b, native::digest(b));
    out = std::move(b);
    return true;
  } catch (...) {
    return false;
  }
}
bool decodeEntry(const ByteView &b, Entry &out) {
  try {
    if (b.size() < 8 || b.size() > 1632 || n(b, 0, 4) != b.size() - 8 ||
        n(b, 6, 2) != 1)
      return false;
    auto p = b.sub(8, b.size() - 8);
    Entry e;
    if (n(b, 4, 2) == 1) {
      if (!readEntry(p, e))
        return false;
    } else if (n(b, 4, 2) == 2) {
      directional::Entry old;
      if (!oldEntry(p, old))
        return false;
      e.command = std::move(old.command);
      e.legacyEnvelope = p;
    } else
      return false;
    out = std::move(e);
    return true;
  } catch (...) {
    return false;
  }
}
bool serializeJournal(const std::vector<ByteView> &entries,
                      std::uint64_t sequence, std::uint64_t desired,
                      const Id &writer, Bytes &out) {
  try {
    if (!sequence || zero(writer) || entries.size() > 4096)
      return false;
    std::size_t total = 96;
    for (const auto &e : entries) {
      if (e.size() > decisions::MaxJournalBytes - total)
        return false;
      total += e.size();
    }
    Bytes b(64);
    b[0] = 'G';
    b[1] = 'B';
    b[2] = 'J';
    b[3] = '4';
    put(b, 4, 1, 2);
    put(b, 6, 64, 2);
    put(b, 8, total, 4);
    put(b, 12, entries.size(), 4);
    put(b, 16, sequence, 8);
    put(b, 24, desired, 8);
    put(b, 32, writer);
    b.reserve(total);
    std::set<Id> ids;
    for (const auto &v : entries) {
      Entry e;
      if (!decodeEntry(v, e) || !ids.insert(e.command.id).second)
        return false;
      append(b, v);
    }
    append(b, native::digest(b));
    out = std::move(b);
    return true;
  } catch (...) {
    return false;
  }
}
bool parseLegacy(const ByteView &b, Legacy &out) {
  try {
    if (b.size() < 328 || b.size() > 22184152 || !magic(b, "GBS3") ||
        n(b, 4, 2) != 3 || n(b, 6, 2) || n(b, 8, 4) != b.size() ||
        n(b, 12, 4) != 160 || !n(b, 16, 8) || n(b, 40, 1) > 1 ||
        !zeros(b, 42, 6) || !zeros(b, 108, 4) || !zeros(b, 144, 16) ||
        !checksum(b))
      return false;
    auto ps = n(b, 96, 4), ds = n(b, 100, 4), js = n(b, 104, 4);
    if (ps < 16 || ps > 16 * 1024 * 1024 || ds < 24 || ds > 163864 || js < 96 ||
        js > decisions::MaxJournalBytes || 160 + ps + ds + js + 32 != b.size())
      return false;
    Legacy s;
    s.encoded = b;
    s.sequence = n(b, 16, 8);
    s.desired = n(b, 24, 8);
    auto p = b.sub(160, std::size_t(ps)),
         d = b.sub(160 + std::size_t(ps), std::size_t(ds)),
         j = b.sub(160 + std::size_t(ps + ds), std::size_t(js));
    if (!headerRules(p, d, s.desired, 3, s.rules) || !magic(j, "GBJ2") ||
        n(j, 4, 2) != 2 || n(j, 6, 2) || n(j, 8, 4) != j.size() ||
        n(j, 12, 4) > 4096 || n(j, 16, 8) != s.sequence ||
        n(j, 24, 8) != s.desired || zero(array<16>(j, 32)) ||
        !zeros(j, 48, 16) || !checksum(j))
      return false;
    auto active = array<16>(b, 48);
    directional::Entry activeEntry;
    bool found = false, terminal = true;
    std::set<Id> ids;
    std::size_t at = 64;
    for (std::size_t i = 0; i < n(j, 12, 4); ++i) {
      if (at > j.size() - 32 || j.size() - 32 - at < 8)
        return false;
      auto size = n(j, at, 4);
      if (size > 1536 || size > j.size() - 32 - at - 8)
        return false;
      auto envelope = j.sub(at, 8 + std::size_t(size));
      directional::Entry e;
      if (!oldEntry(envelope, e) || !ids.insert(e.command.id).second)
        return false;
      terminal = terminal && (e.command.state == State::Applied ||
                              e.command.state == State::Failed);
      if (e.command.id == active) {
        activeEntry = e;
        found = true;
      }
      s.entries.push_back(envelope);
      at += envelope.size();
    }
    if (at != j.size() - 32)
      return false;
    auto state = n(b, 41, 1), effective = n(b, 32, 8), known = n(b, 40, 1);
    if (state < 1 || state > 5 || effective > s.desired ||
        (!known && effective))
      return false;
    if (zero(active)) {
      if (array<32>(b, 64) != Digest{} || array<32>(b, 112) != Digest{} ||
          !s.rules.empty() || !s.entries.empty() || s.desired || effective ||
          known || state != 4)
        return false;
    } else {
      Hash h;
      h.domain("GBS3SET1");
      h.add(integer(s.desired, 8));
      h.add(integer(ps, 4));
      h.add(p);
      h.add(integer(ds, 4));
      h.add(d);
      if (!found || activeEntry.legacyEnvelope.size() || !activeEntry.effect ||
          activeEntry.command.desired != s.desired ||
          activeEntry.target != h.end() ||
          activeEntry.projection != array<32>(b, 64) ||
          activeEntry.admission != array<32>(b, 112))
        return false;
      if (state == 2 || state == 5) {
        if (static_cast<unsigned>(activeEntry.command.state) != state ||
            !known || effective != s.desired ||
            !activeEntry.command.effectiveKnown ||
            activeEntry.command.effective != effective)
          return false;
      } else if (state == 1) {
        if (activeEntry.command.state != State::Prepared)
          return false;
      } else if (state != 4 || known || effective)
        return false;
    }
    s.confirmedHistory =
        state == 2 && known && effective == s.desired && terminal;
    out = std::move(s);
    return true;
  } catch (...) {
    return false;
  }
}
bool parse(ByteView b, Snapshot &out) {
  try {
    if (b.size() < 400 || b.size() > MaxSnapshotBytes || !magic(b, "GBS4") ||
        n(b, 4, 2) != 4 || n(b, 6, 2) || n(b, 8, 4) != b.size() ||
        n(b, 12, 4) != 224 || !n(b, 16, 8) || n(b, 40, 1) > 1 ||
        !zeros(b, 42, 6) || !zeros(b, 216, 8) || !checksum(b))
      return false;
    auto ps = n(b, 96, 4), ds = n(b, 100, 4), js = n(b, 104, 4),
         as = n(b, 108, 4);
    if (ps < 24 || ps > MaxSnapshotBytes || ds < 24 || ds > 163864 || js < 96 ||
        js > decisions::MaxJournalBytes || as > 22184152 ||
        224 + ps + ds + js + as + 32 != b.size())
      return false;
    Snapshot s;
    s.encoded = b;
    s.sequence = n(b, 16, 8);
    s.desired = n(b, 24, 8);
    s.effective = n(b, 32, 8);
    s.storedKnown = n(b, 40, 1) != 0;
    s.storedState = static_cast<State>(n(b, 41, 1));
    s.active = array<16>(b, 48);
    s.activeProjection = array<32>(b, 64);
    s.activeAdmission = array<32>(b, 112);
    s.targetSet = array<32>(b, 144);
    s.archiveDigest = array<32>(b, 176);
    s.migrationBase = n(b, 208, 8);
    s.policy = b.sub(224, std::size_t(ps));
    s.directions = b.sub(224 + std::size_t(ps), std::size_t(ds));
    s.journal = b.sub(224 + std::size_t(ps + ds), std::size_t(js));
    s.archive = b.sub(224 + std::size_t(ps + ds + js), std::size_t(as));
    if (s.effective > s.desired || (!s.storedKnown && s.effective) ||
        (s.storedState != State::Prepared && s.storedState != State::Applied &&
         s.storedState != State::RecoveryRequired) ||
        !headerRules(s.policy, s.directions, s.desired, 4, s.rules) ||
        s.targetSet != targetSetDigest(s.desired, s.policy, s.directions))
      return false;
    Legacy archive;
    if (as) {
      if (!parseLegacy(s.archive, archive) || !archive.confirmedHistory ||
          archive.sequence != s.migrationBase ||
          s.sequence <= s.migrationBase ||
          s.archiveDigest != domainHash("GBS4LEG1", s.archive))
        return false;
    } else if (s.migrationBase || s.archiveDigest != Digest{})
      return false;
    for (const auto &r : s.rules)
      if (r.kind == 2) {
        auto it = std::find_if(archive.rules.begin(), archive.rules.end(),
                               [&](const Rule &a) { return a.id == r.id; });
        if (it == archive.rules.end() || it->target != r.target ||
            it->direction != r.direction || it->mode != r.mode)
          return false;
      }
    const auto &j = s.journal;
    if (!magic(j, "GBJ4") || n(j, 4, 2) != 1 || n(j, 6, 2) != 64 ||
        n(j, 8, 4) != j.size() || n(j, 12, 4) > 4096 ||
        n(j, 16, 8) != s.sequence || n(j, 24, 8) != s.desired ||
        zero(array<16>(j, 32)) || !zeros(j, 48, 16) || !checksum(j))
      return false;
    s.writerEpoch = array<16>(j, 32);
    std::size_t at = 64, legacyAt = 0;
    std::set<Id> ids;
    for (std::size_t i = 0; i < n(j, 12, 4); ++i) {
      if (at > j.size() - 32 || j.size() - 32 - at < 8)
        return false;
      auto size = n(j, at, 4), kind = n(j, at + 4, 2);
      if (n(j, at + 6, 2) != 1 || size > 1624 || size > j.size() - 32 - at - 8)
        return false;
      auto p = j.sub(at + 8, std::size_t(size));
      Entry e;
      if (kind == 1) {
        if (!readEntry(p, e))
          return false;
      } else if (kind == 2) {
        directional::Entry old;
        if (!as || !oldEntry(p, old))
          return false;
        e.command = old.command;
        e.legacyEnvelope = p;
        while (legacyAt < archive.entries.size() &&
               archive.entries[legacyAt] != p)
          ++legacyAt;
        if (legacyAt == archive.entries.size())
          return false;
        ++legacyAt;
      } else
        return false;
      if (!ids.insert(e.command.id).second)
        return false;
      s.entries.push_back(j.sub(at, 8 + std::size_t(size)));
      at += 8 + std::size_t(size);
    }
    if (at != j.size() - 32)
      return false;
    if (zero(s.active)) {
      if (s.activeProjection != Digest{} || s.activeAdmission != Digest{} ||
          s.desired || s.effective || s.storedKnown ||
          s.storedState != State::RecoveryRequired || !s.rules.empty() ||
          !s.entries.empty() || as)
        return false;
    } else {
      auto it = std::find_if(
          s.entries.begin(), s.entries.end(), [&](const ByteView &v) {
            Entry e;
            return decodeEntry(v, e) && e.command.id == s.active;
          });
      Entry active;
      if (it == s.entries.end() || !decodeEntry(*it, active) ||
          active.legacyEnvelope.size() || !active.effect ||
          active.command.desired != s.desired ||
          active.targetSet != s.targetSet ||
          active.admission != s.activeAdmission ||
          active.projection != s.activeProjection)
        return false;
      if (s.storedState == State::Applied) {
        if (active.command.state != State::Applied || !s.storedKnown ||
            s.effective != s.desired)
          return false;
      } else if (s.storedKnown || s.effective ||
                 (s.storedState == State::Prepared &&
                  active.command.state != State::Prepared))
        return false;
      Frame f;
      if (!command(active, f))
        return false;
      auto ruleId = active.effect == 1 ? s.active : idValue(f, Tag::RuleId);
      auto row = std::find_if(s.rules.begin(), s.rules.end(),
                              [&](const Rule &r) { return r.id == ruleId; });
      if (active.effect == 1) {
        if (row == s.rules.end() || row->kind != 1 ||
            row->selector != idValue(f, Tag::SelectorId) ||
            row->targetRevision != get(f, Tag::TargetRevision) ||
            row->action != get(f, Tag::Decision) ||
            row->direction != active.direction ||
            targetDigest(row->target) !=
                array<32>(ByteView(find(f, Tag::TargetDigest)->bytes), 0))
          return false;
        Target t;
        if (!parseTarget(row->target, t) || t.packageMode != active.packageMode)
          return false;
      } else if (row != s.rules.end())
        return false;
    }
    out = std::move(s);
    return true;
  } catch (...) {
    return false;
  }
}
bool serialize(const Snapshot &s, Bytes &out) {
  try {
    const auto total = std::uint64_t(256) + s.policy.size() +
                       s.directions.size() + s.journal.size() +
                       s.archive.size();
    if (total > MaxSnapshotBytes)
      return false;
    Bytes b(224);
    b[0] = 'G';
    b[1] = 'B';
    b[2] = 'S';
    b[3] = '4';
    put(b, 4, 4, 2);
    put(b, 8, total, 4);
    put(b, 12, 224, 4);
    put(b, 16, s.sequence, 8);
    put(b, 24, s.desired, 8);
    put(b, 32, s.effective, 8);
    b[40] = s.storedKnown ? 1 : 0;
    b[41] = static_cast<std::uint8_t>(s.storedState);
    put(b, 48, s.active);
    put(b, 64, s.activeProjection);
    put(b, 96, s.policy.size(), 4);
    put(b, 100, s.directions.size(), 4);
    put(b, 104, s.journal.size(), 4);
    put(b, 108, s.archive.size(), 4);
    put(b, 112, s.activeAdmission);
    put(b, 144, s.targetSet);
    put(b, 176, s.archiveDigest);
    put(b, 208, s.migrationBase, 8);
    b.reserve(std::size_t(total));
    append(b, s.policy);
    append(b, s.directions);
    append(b, s.journal);
    append(b, s.archive);
    append(b, native::digest(b));
    // Validación sin copia de candidato/targets. La propiedad se transfiere al
    // documento temporal.
    {
      ByteView borrowed;
      borrowed.owner_ = std::shared_ptr<const Bytes>(&b, [](const Bytes *) {});
      borrowed.size_ = b.size();
      Snapshot checked;
      if (!parse(borrowed, checked))
        return false;
    }
    out = std::move(b);
    return true;
  } catch (...) {
    return false;
  }
}
bool validTransition(const ByteView &before, const Snapshot &after) {
  try {
    auto sameRule = [](const Rule &a, const Rule &b) {
      return a.id == b.id && a.selector == b.selector &&
             a.revision == b.revision && a.targetRevision == b.targetRevision &&
             a.action == b.action && a.direction == b.direction &&
             a.mode == b.mode && a.kind == b.kind && a.target == b.target;
    };
    auto sameEntry = [](const ByteView &left, const ByteView &right,
                        bool outcome) {
      if (outcome)
        return left == right;
      Entry a, b;
      if (!decodeEntry(left, a) || !decodeEntry(right, b))
        return false;
      if (a.legacyEnvelope.size() || b.legacyEnvelope.size())
        return a.legacyEnvelope == b.legacyEnvelope;
      ByteView x(prefix(a)), y(prefix(b));
      return x.sub(0, 80) == y.sub(0, 80) && x.sub(96, 16) == y.sub(96, 16) &&
             x.sub(116, 188) == y.sub(116, 188) &&
             (!outcome || (x.sub(80, 16) == y.sub(80, 16) &&
                           x.sub(112, 4) == y.sub(112, 4))) &&
             a.command.payload == b.command.payload &&
             a.projected == b.projected &&
             a.command.accountSid == b.command.accountSid &&
             a.command.logonSid == b.command.logonSid;
    };
    auto ruleChange = [&](const std::vector<Rule> &old, const Frame &f) {
      bool create = f.type == Type::CommitFuturePolicy;
      auto removed = create ? Id{} : idValue(f, Tag::RuleId);
      if (create) {
        if (after.rules.size() != old.size() + 1 ||
            std::any_of(old.begin(), old.end(),
                        [&](const Rule &r) { return r.id == f.correlation; }))
          return false;
      } else {
        auto found = std::find_if(old.begin(), old.end(), [&](const Rule &r) {
          return r.id == removed;
        });
        if (found == old.end() || after.rules.size() + 1 != old.size() ||
            found->revision != get(f, Tag::RuleRevision) ||
            found->targetRevision != get(f, Tag::TargetRevision))
          return false;
        auto digest = targetDigest(found->target, found->kind == 2);
        if (find(f, Tag::TargetDigest)->bytes !=
            Bytes(digest.begin(), digest.end()))
          return false;
      }
      for (const auto &r : old) {
        if (r.id == removed)
          continue;
        auto it = std::find_if(after.rules.begin(), after.rules.end(),
                               [&](const Rule &v) { return v.id == r.id; });
        if (it == after.rules.end() || !sameRule(r, *it))
          return false;
      }
      return true;
    };
    if (magic(before, "GBS4")) {
      Snapshot old;
      if (!parse(before, old) || old.sequence == UINT64_MAX ||
          after.sequence != old.sequence + 1 || after.archive != old.archive ||
          after.migrationBase != old.migrationBase)
        return false;
      if (after.desired != old.desired &&
          (old.desired == UINT64_MAX || after.desired != old.desired + 1))
        return false;
      if (after.active == old.active) {
        if (after.desired != old.desired || after.policy != old.policy ||
            after.directions != old.directions ||
            after.entries.size() != old.entries.size())
          return false;
        for (std::size_t i = 0; i < old.entries.size(); ++i) {
          Entry prior;
          if (!decodeEntry(old.entries[i], prior))
            return false;
          bool active = prior.command.id == old.active;
          if (!sameEntry(old.entries[i], after.entries[i], !active))
            return false;
          if (active && prior.command.state != State::Prepared &&
              !sameEntry(old.entries[i], after.entries[i], true))
            return false;
        }
        return true;
      }
      // El bootstrap vacío sólo abre la primera transición de formato;
      // no acredita autoridad ni prueba corriente del runtime.
      const bool bootstrap =
          old.sequence == 1 && old.desired == 0 && zero(old.active) &&
          old.rules.empty() && old.entries.empty() && old.archive.size() == 0 &&
          old.migrationBase == 0 && old.effective == 0 && !old.storedKnown &&
          old.storedState == State::RecoveryRequired &&
          old.activeProjection == Digest{} && old.activeAdmission == Digest{} &&
          old.archiveDigest == Digest{};
      if ((old.storedState != State::Applied && !bootstrap) ||
          after.storedState != State::Prepared || old.desired == UINT64_MAX ||
          after.desired != old.desired + 1 ||
          after.entries.size() != old.entries.size() + 1)
        return false;
      for (std::size_t i = 0; i < old.entries.size(); ++i)
        if (!sameEntry(old.entries[i], after.entries[i], true))
          return false;
      for (const auto &r : after.rules)
        if (r.kind == 2) {
          auto it = std::find_if(old.rules.begin(), old.rules.end(),
                                 [&](const Rule &a) { return a.id == r.id; });
          if (it == old.rules.end() || it->target != r.target ||
              it->direction != r.direction)
            return false;
        }
      if (after.active != old.active) {
        auto it = std::find_if(
            after.entries.begin(), after.entries.end(), [&](const ByteView &v) {
              Entry e;
              return decodeEntry(v, e) && e.command.id == after.active;
            });
        Frame f;
        Entry active;
        if (it == after.entries.end() || !decodeEntry(*it, active) ||
            !command(active, f) ||
            !zeros(ByteView(find(f, Tag::MigrationDigest)->bytes), 0, 32))
          return false;
        if (it != after.entries.end() - 1 ||
            get(f, Tag::ExpectedDesiredRev) != old.desired ||
            !ruleChange(old.rules, f))
          return false;
      }
      return true;
    }
    Legacy old;
    if (!parseLegacy(before, old) || !old.confirmedHistory ||
        old.sequence == UINT64_MAX || old.desired == UINT64_MAX ||
        after.sequence != old.sequence + 1 ||
        after.desired != old.desired + 1 || after.archive != before ||
        after.migrationBase != old.sequence ||
        after.storedState != State::Prepared)
      return false;
    auto it = std::find_if(
        after.entries.begin(), after.entries.end(), [&](const ByteView &v) {
          Entry e;
          return decodeEntry(v, e) && e.command.id == after.active;
        });
    Frame f;
    Entry active;
    if (it == after.entries.end() || !decodeEntry(*it, active) ||
        !command(active, f) || get(f, Tag::ExpectedDesiredRev) != old.desired ||
        find(f, Tag::MigrationDigest)->bytes !=
            Bytes(after.archiveDigest.begin(), after.archiveDigest.end()))
      return false;
    if (it != after.entries.end() - 1 ||
        after.entries.size() != old.entries.size() + 1 ||
        !ruleChange(old.rules, f))
      return false;
    for (std::size_t i = 0; i < old.entries.size(); ++i)
      if (n(after.entries[i], 4, 2) != 2 ||
          after.entries[i].sub(8, after.entries[i].size() - 8) !=
              old.entries[i])
        return false;
    auto revoked =
        f.type == Type::RevokePrincipalRule ? idValue(f, Tag::RuleId) : Id{};
    if (!zero(revoked)) {
      auto r = std::find_if(old.rules.begin(), old.rules.end(),
                            [&](const Rule &a) { return a.id == revoked; });
      if (r == old.rules.end())
        return false;
      auto digest = targetDigest(r->target, true);
      if (find(f, Tag::TargetDigest)->bytes !=
          Bytes(digest.begin(), digest.end()))
        return false;
    }
    for (const auto &r : old.rules)
      if (r.id != revoked) {
        auto a = std::find_if(after.rules.begin(), after.rules.end(),
                              [&](const Rule &v) { return v.id == r.id; });
        if (a == after.rules.end() || a->kind != 2 || a->target != r.target ||
            a->direction != r.direction)
          return false;
      }
    return true;
  } catch (...) {
    return false;
  }
}
} // namespace gb::principal
