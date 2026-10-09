#pragma once
#include "coordinator_iii.h"
#include "snapshot_iv.h"

namespace gb::principal {
enum class StoredImage { Missing, LegacyReadOnly, Principal, Uncertain };
struct StoreRead {
  StoredImage kind = StoredImage::Uncertain;
  Snapshot snapshot;
  Legacy legacy;
};
struct StoreWrite {
  Error error = Error::StoreFailure;
  bool physicallyConfirmed = false;
  StoredImage observed = StoredImage::Uncertain;
  std::uint64_t observedSequence = 0;
};
// Adaptador físico puro: ningún método aplica/reconcilia/reproduce efectos del
// motor. El runtime futuro debe adquirir su autoridad actual antes de proponer
// un candidato.
class SnapshotStore {
public:
  explicit SnapshotStore(std::shared_ptr<directional::SnapshotFile> file)
      : file_(std::move(file)) {}
  ~SnapshotStore();
  SnapshotStore(const SnapshotStore &) = delete;
  SnapshotStore &operator=(const SnapshotStore &) = delete;
  bool load(StoreRead &out);
  StoreWrite replace(std::uint64_t expectedSequence,
                     std::uint64_t expectedDesired, Bytes candidate);
  bool uncertain() const;

private:
  bool observe(StoreRead &out);
  std::shared_ptr<directional::SnapshotFile> file_;
  mutable std::mutex mutex_;
  ByteView active_;
  StoreRead read_;
  bool lease_ = false, loaded_ = false, uncertain_ = true;
};
} // namespace gb::principal
