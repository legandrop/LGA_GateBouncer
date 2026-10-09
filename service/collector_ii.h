#pragma once
#include "observations_ii.h"
#include "policy.h"
#include "profile_ii.h"
#include <deque>
#include <fwpmu.h>
#include <mutex>

namespace gb::decisions {
struct LedgerFilter {
    std::uint64_t filterId = 0, generation = 0, desired = 0;
    Id guid{};
    std::uint16_t layerId = 0;
    // CONNECT2 / RECV_ACCEPT1. LISTEN no tiene originalFlow en schema II.
    std::uint8_t originalFlow = 0;
    bool drop = false;
};
Id canonicalGuid(const GUID &guid);
struct Capture {
    Bytes appId, accountSid;
    std::uint64_t filetime = 0, receivedMs = 0;
    LedgerFilter filter;
    bool mapped = false;
};
class NativeCollector {
  public:
    NativeCollector(SelectorRegistry &registry, Engine &engine, ObservationRing &ring, Id epoch)
        : registry_(registry), engine_(engine), ring_(ring), epoch_(epoch) {}
    // Sólo backend después de inventario/readback exacto; publicación y callback serializados.
    bool publish(std::vector<LedgerFilter> filters, std::uint64_t verifiedFiletime);
    void unavailable(std::uint8_t reason);
    void whitelist(std::vector<Bytes> ownLocalTools);
    void capture(const FWPM_NET_EVENT1 *event);
    void drain(const NativeProfile &profile, std::uint64_t now);
    std::uint8_t state() const;
    std::uint64_t gaps() const;
    bool clientGap(std::uint64_t profile, std::uint8_t state) { return gap(3, profile, state); }

  private:
    bool gap(std::uint8_t reason, std::uint64_t profile, std::uint8_t state);
    SelectorRegistry &registry_;
    Engine &engine_;
    ObservationRing &ring_;
    Id epoch_;
    mutable std::mutex mutex_;
    std::vector<LedgerFilter> ledger_;
    std::vector<Bytes> tools_;
    std::deque<Capture> queue_;
    std::uint64_t publishedAt_ = 0, lastUtc_ = 0, gaps_ = 0;
    std::uint8_t state_ = 0, pendingGap_ = 0;
};
} // namespace gb::decisions
