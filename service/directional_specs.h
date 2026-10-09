#pragma once
#include "snapshot_iii.h"

namespace gb::directional {
enum class Layer : std::uint8_t {
    Connect4,
    Connect6,
    Receive4,
    Receive6,
    Listen4,
    Listen6,
    Resource4,
    Resource6
};
enum class Origin : std::uint8_t {
    Unknown = 0,
    OutboundFlow = 1,
    InboundFlow = 2,
    InboundListen = 3
};
enum class PolicyDirection : std::uint8_t { Outbound = 1, Inbound = 2, Both = 3 };
enum class OriginalFlow : std::uint8_t { Unknown = 0, InboundInitiated = 1, OutboundInitiated = 2 };
struct FilterSpec {
    Id rule{};
    std::uint8_t slot = 0, action = 1, direction = 0, mode = 0;
    Layer layer = Layer::Connect4;
    bool boot = false, rawEndpoint = false, unicast = false;
    std::uint32_t promiscuous = 0;
    std::uint64_t weight = 0;
    Bytes appId, metadata;
};
Origin origin(Layer layer);
OriginalFlow originalFlow(Origin origin);
std::optional<PolicyDirection> suggested(Origin origin);
bool generate(const std::vector<Rule> &rules, std::uint64_t revision,
              std::vector<FilterSpec> &specs);
} // namespace gb::directional
