#include "directional_specs.h"

namespace gb::directional {
Origin origin(Layer layer) {
    if (layer == Layer::Connect4 || layer == Layer::Connect6)
        return Origin::OutboundFlow;
    if (layer == Layer::Receive4 || layer == Layer::Receive6)
        return Origin::InboundFlow;
    if (layer == Layer::Listen4 || layer == Layer::Listen6)
        return Origin::InboundListen;
    return Origin::Unknown;
}
OriginalFlow originalFlow(Origin value) {
    if (value == Origin::OutboundFlow)
        return OriginalFlow::OutboundInitiated;
    if (value == Origin::InboundFlow)
        return OriginalFlow::InboundInitiated;
    return OriginalFlow::Unknown;
}
std::optional<PolicyDirection> suggested(Origin value) {
    if (value == Origin::OutboundFlow)
        return PolicyDirection::Outbound;
    if (value == Origin::InboundFlow || value == Origin::InboundListen)
        return PolicyDirection::Inbound;
    return std::nullopt;
}
bool generate(const std::vector<Rule> &rules, std::uint64_t revision,
              std::vector<FilterSpec> &out) {
    if (!rulesValid(rules) || revision == UINT64_MAX)
        return false;
    std::vector<FilterSpec> rows;
    auto add = [&](FilterSpec spec) {
        spec.metadata = {'G', 'B', 'F', '2'};
        auto v = integer(revision, 8);
        spec.metadata.insert(spec.metadata.end(), v.begin(), v.end());
        spec.metadata.push_back(spec.direction);
        spec.metadata.push_back(spec.mode);
        spec.metadata.push_back(spec.slot);
        spec.metadata.push_back(0);
        spec.metadata.insert(spec.metadata.end(), spec.rule.begin(), spec.rule.end());
        rows.push_back(std::move(spec));
    };
    Id baseline{};
    baseline[0] = 0xab;
    std::uint8_t slot = 0;
    for (bool boot : {false, true}) {
        for (unsigned layer = 0; layer < 6; ++layer) {
            FilterSpec s;
            s.rule = baseline;
            s.slot = slot++;
            s.layer = static_cast<Layer>(layer);
            s.boot = boot;
            add(s);
        }
        for (auto layer : {Layer::Resource4, Layer::Resource6}) {
            FilterSpec raw;
            raw.rule = baseline;
            raw.slot = slot++;
            raw.layer = layer;
            raw.boot = boot;
            raw.weight = 200;
            raw.rawEndpoint = true;
            add(raw);
            for (auto mode : {0x98000001u, 0x98000002u, 0x98000003u}) {
                FilterSpec s;
                s.rule = baseline;
                s.slot = slot++;
                s.layer = layer;
                s.boot = boot;
                s.weight = 200;
                s.promiscuous = mode;
                add(s);
            }
        }
    }
    for (const auto &r : rules) {
        for (unsigned layer = 0; layer < 6; ++layer) {
            auto mask = layer < 2 ? 1 : 2;
            if (!(r.direction & mask))
                continue;
            FilterSpec s;
            s.rule = r.id;
            s.slot = static_cast<std::uint8_t>(layer);
            s.layer = static_cast<Layer>(layer);
            s.action = r.action;
            s.direction = r.direction;
            s.mode = r.mode;
            s.appId = r.appId;
            s.weight = r.action == 1 ? 200 : 100;
            s.unicast = r.action == 2 && r.direction == 1;
            add(s);
        }
    }
    out = std::move(rows);
    return true;
}
} // namespace gb::directional
