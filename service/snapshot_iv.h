#pragma once
#include "../common/wire_iv.h"
#include "snapshot_iii.h"
#include <memory>

namespace gatebouncer::service::windows::allapps::native {
class CatalogStorageBuilder;
}
namespace gb::decisions { class NativeRuntime; }
namespace gb::principal {
struct Snapshot;
struct Entry;
class SnapshotStore;
constexpr std::size_t MaxSnapshotBytes = 33554432, MaxTargetBytes = 65744;
// Vistas inmutables fuertes: ningún APP_ID o archivo se copia por cada regla.
class ByteView {
public:
  ByteView() = default;
  explicit ByteView(Bytes bytes);
  const std::uint8_t *data() const;
  std::size_t size() const { return size_; }
  std::size_t ownedCapacityBytes() const noexcept;
  ByteView sub(std::size_t offset, std::size_t length) const;
  Bytes copy() const;
  bool operator==(const ByteView &other) const;
  bool operator!=(const ByteView &other) const { return !(*this == other); }

private:
  friend class gb::decisions::NativeRuntime;
  friend class SnapshotStore;
  static bool prepareOwned(const Snapshot &, const Entry &, ByteView &) noexcept;
  bool sealApplied(std::uint64_t completedAt, Snapshot &) noexcept;
  friend bool serialize(const Snapshot &, Bytes &);
  friend class gatebouncer::service::windows::allapps::native::CatalogStorageBuilder;
  using BudgetFactory = std::shared_ptr<const void> (*)(void *, std::size_t) noexcept;
  enum class BudgetRetention { Attached, Existing, RegistryMismatch, Rejected };
  BudgetRetention retainBudget(std::shared_ptr<const void> registry, void *context,
                               BudgetFactory factory) const noexcept;
  struct Storage;
  std::shared_ptr<const Storage> owner_;
  std::size_t offset_ = 0, size_ = 0;
};
struct Target {
  ByteView encoded, app, user, package;
  std::uint8_t packageMode = 0;
  wire::iv::RemoteCondition remoteCondition;
};
bool sidValid(const ByteView &sid);
bool parseTarget(const ByteView &bytes, Target &out);
// APT1 permanece estricto. APT2/kind 3 sólo representa la condición original;
// el actor debe adquirir su propia admisión antes de escribir filtros.
bool parseConditionalTarget(const ByteView &bytes, Target &out);
bool serializeTarget(const ByteView &app, const ByteView &user,
                     std::uint8_t packageMode, const ByteView &package,
                     Bytes &out);
bool serializeConditionalTarget(const ByteView &app, const ByteView &user,
                     std::uint8_t packageMode, const ByteView &package,
                     const wire::iv::RemoteCondition &, Bytes &out);
Digest targetDigest(const ByteView &target, bool legacy = false);
struct Rule {
  Id id{}, selector{};
  std::uint64_t revision = 1, targetRevision = 1;
  std::uint8_t action = 1, direction = 1, mode = 0, kind = 1;
  ByteView target;
  // Bytes físicos del archivo capturado, no identidad de una imagen cargada.
  const ByteView &durableWitness() const { return durableWitness_; }
private:
  ByteView durableWitness_;
  friend class gb::decisions::NativeRuntime;
  friend class ByteView;
  friend bool decodeRuleWitness(Rule &, const ByteView &);
  friend bool sections(const std::vector<Rule> &, std::uint64_t, Bytes &, Bytes &);
};
// Validación de formato puro. Sólo Runtime liga estos bytes a handles originales.
bool validRuleWitness(const ByteView &);
struct Entry {
  decisions::CommandEntry command;
  ByteView legacyEnvelope;
  Bytes projected;
  std::uint8_t effect = 0, direction = 0, packageMode = 0;
  std::uint16_t accepted = 0;
  Id draft{}, source{}, binding{};
  std::uint64_t draftVersion = 0, targetRevision = 0;
  Digest admission{}, projection{}, targetSet{};
};
struct Snapshot {
  ByteView encoded, policy, directions, journal, archive;
  std::uint64_t sequence = 0, desired = 0, effective = 0, migrationBase = 0;
  bool storedKnown = false;
  State storedState = State::RecoveryRequired;
  Id active{}, writerEpoch{};
  Digest activeProjection{}, activeAdmission{}, targetSet{}, archiveDigest{};
  std::vector<Rule> rules;
  std::vector<ByteView> entries;
  // Carga de formato, nunca mint de prueba corriente ni llamada al backend.
  wire::iv::Proof currentProof() const { return wire::iv::Proof::Unknown; }
};
struct Legacy {
  ByteView encoded;
  std::uint64_t sequence = 0, desired = 0;
  bool confirmedHistory = false;
  std::vector<Rule> rules;
  std::vector<ByteView> entries;
};
bool parseLegacy(const ByteView &bytes, Legacy &out);
bool rulesValid(const std::vector<Rule> &rules);
bool overlaps(const Rule &left, const Rule &right);
bool sections(const std::vector<Rule> &rules, std::uint64_t desired,
              Bytes &policy, Bytes &directions);
Digest targetSetDigest(std::uint64_t desired, const ByteView &policy,
                       const ByteView &directions);
bool project(const Frame &canonical, const Digest &targetSet, Bytes &out);
bool bindEntry(Entry &entry, const Digest &targetSet);
bool entryValid(const Entry &entry);
bool serializeJournal(const std::vector<Entry> &entries, std::uint64_t sequence,
                      std::uint64_t desired, const Id &writer, Bytes &out);
bool decodeEntry(const ByteView &envelope, Entry &out);
bool serializeJournal(const std::vector<ByteView> &entries,
                      std::uint64_t sequence, std::uint64_t desired,
                      const Id &writer, Bytes &out);
bool serialize(const Snapshot &snapshot, Bytes &out);
bool parse(ByteView bytes, Snapshot &out);
inline bool parse(Bytes bytes, Snapshot &out) {
  return parse(ByteView(std::move(bytes)), out);
}
// La transición sólo valida bytes. La autoridad/confirmación actual pertenece
// al runtime.
bool validTransition(const ByteView &before, const Snapshot &after);
} // namespace gb::principal
