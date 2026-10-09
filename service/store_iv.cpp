#include "store_iv.h"

namespace gb::principal {
SnapshotStore::~SnapshotStore() {
  if (lease_)
    file_->releaseWriter(this);
}
bool SnapshotStore::observe(StoreRead &out) {
  Bytes b;
  bool exists = false;
  if (!file_->read(b, exists))
    return false;
  StoreRead s;
  if (!exists) {
    s.kind = StoredImage::Missing;
    out = std::move(s);
    return true;
  }
  ByteView bytes(std::move(b));
  if (retainRead_ && !retainRead_(readContext_, bytes))
    return false;
  if (parse(bytes, s.snapshot))
    s.kind = StoredImage::Principal;
  else if (parseLegacy(bytes, s.legacy))
    s.kind = StoredImage::LegacyReadOnly;
  else
    return false;
  out = std::move(s);
  return true;
}
bool SnapshotStore::load(StoreRead &out) {
  return loadRetained(out, nullptr, nullptr);
}
bool SnapshotStore::loadRetained(StoreRead &out, void *context, RetainRead retain) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (loaded_ || lease_ || !file_ || !file_->claimWriter(this))
    return false;
  lease_ = true;
  readContext_ = context;
  retainRead_ = retain;
  struct ClearRead {
    SnapshotStore &owner;
    ~ClearRead() { owner.readContext_ = nullptr; owner.retainRead_ = nullptr; }
  } clear{*this};
  StoreRead s;
  if (!observe(s))
    return false;
  active_ =
      s.kind == StoredImage::Principal ? s.snapshot.encoded : s.legacy.encoded;
  read_ = s;
  loaded_ = true;
  uncertain_ = false;
  out = std::move(s);
  return true;
}
bool SnapshotStore::uncertain() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return uncertain_;
}
StoreWrite SnapshotStore::replace(std::uint64_t sequence, std::uint64_t desired,
                                  Bytes candidate) {
  return replaceOwned(sequence, desired, ByteView(std::move(candidate)), true);
}
StoreWrite SnapshotStore::replaceOwned(std::uint64_t sequence, std::uint64_t desired,
                                       ByteView candidate, bool rereadFailure) {
  std::lock_guard<std::mutex> lock(mutex_);
  StoreWrite result;
  if (!loaded_ || !lease_ || uncertain_)
    return result;
  if (candidate.size() > MaxSnapshotBytes) {
    result.error = Error::Capacity;
    return result;
  }
  Snapshot next;
  if (!parse(candidate, next)) {
    result.error = Error::Malformed;
    return result;
  }
  auto actualSequence = read_.kind == StoredImage::Principal
                            ? read_.snapshot.sequence
                            : read_.legacy.sequence;
  auto actualDesired = read_.kind == StoredImage::Principal
                           ? read_.snapshot.desired
                           : read_.legacy.desired;
  if (sequence != actualSequence || desired != actualDesired) {
    result.error = Error::Stale;
    return result;
  }
  if (read_.kind == StoredImage::Missing) {
    if (next.sequence != 1 || next.desired || !zero(next.active)) {
      result.error = Error::Conflict;
      return result;
    }
  } else if (!validTransition(active_, next)) {
    result.error = Error::Conflict;
    return result;
  }
  // Relectura exacta bajo lease antes de replace: CAS no se deduce de un bool
  // viejo.
  bool same = false, exists = false;
  if (!file_->compare(active_.data(), active_.size(), same, exists)) {
    uncertain_ = true;
    return result;
  }
  if (exists != (read_.kind != StoredImage::Missing) || (exists && !same)) {
    uncertain_ = true;
    result.error = Error::Stale;
    return result;
  }
  // El archivo nativo realiza temp protegido, flush, replace y comprobaciones
  // físicas III.
  bool saved = file_->replaceView(next.encoded.data(), next.encoded.size());
  bool compared =
      file_->compare(next.encoded.data(), next.encoded.size(), same, exists);
  if (!saved || !compared || !exists || !same) {
    // Soltar ambos buffers internos antes de observar: no tercer buffer
    // de32MiB.
    uncertain_ = true;
    active_ = {};
    read_ = {};
    next = {};
    candidate = {};
    StoreRead after;
    // Un candidato anclado pertenece al productor que ya reservó A+B.
    // No asignar una tercera imagen durante una recuperación automática.
    if (rereadFailure && observe(after)) {
      result.observed = after.kind;
      result.observedSequence = after.kind == StoredImage::Principal
                                    ? after.snapshot.sequence
                                    : after.legacy.sequence;
      read_ = std::move(after);
    }
    return result;
  }
  active_ = next.encoded;
  read_.kind = StoredImage::Principal;
  read_.legacy = {};
  read_.snapshot = std::move(next);
  result.observed = StoredImage::Principal;
  result.observedSequence = read_.snapshot.sequence;
  result.error = Error::Ok;
  result.physicallyConfirmed = true;
  return result;
}
} // namespace gb::principal
