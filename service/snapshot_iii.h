#pragma once
#include "journal_ii_store.h"
#include "policy.h"

namespace gb::directional {
constexpr std::size_t MaxSnapshotBytes = 32 * 1024 * 1024;
struct Rule {
    Id id{}, selector{};
    std::uint64_t revision = 1, selectorRevision = 1;
    std::uint8_t action = 1, direction = 3, mode = 0;
    Bytes appId;
};
struct Entry {
    decisions::CommandEntry command;
    Bytes legacyEnvelope, projected;
    std::uint8_t effect = 0;
    Digest admission{}, projection{}, target{};
};
struct Snapshot {
    std::uint64_t sequence = 0, desired = 0, effective = 0;
    bool effectiveKnown = false;
    State state = State::RecoveryRequired;
    Id active{}, writerEpoch{};
    Digest activeProjection{}, activeAdmission{};
    std::vector<Rule> rules;
    std::vector<Entry> entries;
    bool legacyConsistent = false; // Sólo lectura legacy; no campo del formato GBS3.
};
bool rulesValid(const std::vector<Rule> &rules);
bool sections(const Snapshot &snapshot, Bytes &policy, Bytes &directions);
Digest targetDigest(const Snapshot &snapshot);
// La proyección interna no es el esquema completo de CreateRule IPC.
bool project(const Frame &command, Bytes &projection, std::uint8_t &effect);
bool entryValid(const Entry &entry);
bool bindEntry(Entry &entry, const Digest &target);
bool serialize(const Snapshot &snapshot, Bytes &bytes);
bool parse(const Bytes &bytes, Snapshot &snapshot);
bool runtimeAdmissible(const Snapshot &snapshot);
bool importLegacy(const Bytes &policy, const Bytes *journal, const Id &writer, Snapshot &snapshot);
} // namespace gb::directional
