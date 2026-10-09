#pragma once
#include "../common/protected_file_win.h"
#include "decisions_ii.h"

namespace gb::decisions {
constexpr std::size_t MaxJournalBytes = 5 * 1024 * 1024;
struct JournalSnapshot {
    Id writerEpoch{};
    std::uint64_t sequence = 0, observedDesired = 0;
    std::vector<CommandEntry> entries;
};
bool validSidBytes(const Bytes &sid);
bool serializeJournal(const JournalSnapshot &snapshot, Bytes &bytes);
bool parseJournal(const Bytes &bytes, JournalSnapshot &snapshot);
class NativeJournal final : public JournalSink {
  public:
    NativeJournal(std::filesystem::path root, Id epoch)
        : directory_(std::move(root)), epoch_(epoch) {}
    bool load(JournalSnapshot &snapshot, bool &exists);
    bool persist(const std::vector<CommandEntry> &entries) override;
    void observedDesired(std::uint64_t revision) { observed_ = revision; }

  private:
    native::ProtectedDirectory directory_;
    Id epoch_;
    std::uint64_t sequence_ = 0, observed_ = 0;
};
} // namespace gb::decisions
