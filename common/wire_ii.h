#pragma once
#include "wire_v1.h"

namespace gb::wire::ii {
constexpr std::size_t MaxRecordsBytes = 57344, MaxRecordBytes = 4608;
enum class RequestState : std::uint8_t { Pending = 1, Resolved = 2, Expired = 3, Stale = 4 };
struct RuleRecord {
    Id rule{}, selector{};
    std::uint64_t revision = 0, desired = 0, selectorRevision = 0, presence = 0;
    std::uint64_t created = 0, updated = 0, filterGeneration = 0;
    std::uint8_t action = 1, scope = 1, admin = 1, effective = 0, direction = 3, identity = 1;
    Bytes path, name;
    std::uint8_t mode = 0;
};
struct PendingRecord {
    Id request{}, selector{}, attempt{};
    std::uint64_t authority = 0, selectorRevision = 0, desired = 0, firstUtc = 0, lastUtc = 0;
    std::uint64_t presence = 0, filterId = 0, filterGeneration = 0, eventSequence = 0;
    std::uint64_t observation = 0, profileGeneration = 0;
    std::uint32_t ttl = 0;
    RequestState state = RequestState::Pending;
    std::uint8_t selectorState = 0, flow = 0, scope = 1, source = 1, identity = 1, direction = 3;
    bool accountMatched = false;
    Bytes path, name;
    std::uint8_t origin = 0, recommendedMode = 0;
};
bool valid(const RuleRecord &record, std::uint16_t minor = 1);
bool valid(const PendingRecord &record, std::uint16_t minor = 1);
bool eligible(const PendingRecord &record, std::uint16_t minor = 1);
Error pack(const std::vector<RuleRecord> &records, Bytes &bytes, std::uint16_t minor = 1);
Error pack(const std::vector<PendingRecord> &records, Bytes &bytes, std::uint16_t minor = 1);
Error unpack(const Bytes &bytes, std::size_t count, std::vector<RuleRecord> &records, std::uint16_t minor = 1);
Error unpack(const Bytes &bytes, std::size_t count, std::vector<PendingRecord> &records, std::uint16_t minor = 1);
Error validate(const Frame &frame);
bool filetimeUtc(std::uint64_t filetime, std::uint64_t &unixNanoseconds);
} // namespace gb::wire::ii
