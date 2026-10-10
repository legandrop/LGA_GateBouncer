#include "contracts.h"

namespace Gate::Data {
bool decimalUnsigned(const QString &text, quint64 *value) {
    if (text.isEmpty() || text.size() > 20 || (text.size() > 1 && text.front() == '0'))
        return false;
    for (const auto ch : text)
        if (ch < '0' || ch > '9')
            return false;
    bool ok = false;
    const auto parsed = text.toULongLong(&ok);
    if (ok && value)
        *value = parsed;
    return ok;
}
QString actionName(Action action) {
    switch (action) {
    case Action::Ask: return "Ask";
    case Action::Allow: return "Allow";
    case Action::Block: return "Block";
    }
    return {};
}
std::optional<Action> readAction(const QString &text) {
    if (text == "Ask") return Action::Ask;
    if (text == "Allow") return Action::Allow;
    if (text == "Block") return Action::Block;
    return std::nullopt;
}
QString directionName(Direction direction) {
    switch (direction) {
    case Direction::In: return "In";
    case Direction::Out: return "Out";
    case Direction::Both: return "Both";
    case Direction::Unknown: return "Unknown";
    }
    return {};
}
Direction readDirection(const QString &text) {
    if (text == "In") return Direction::In;
    if (text == "Out") return Direction::Out;
    if (text == "Both") return Direction::Both;
    return Direction::Unknown;
}
ApplicationRuleScopeText applicationRuleScopeText(quint8 package, Direction direction, Action action, bool held) {
    ApplicationRuleScopeText text;
    text.package = package == 1 ? "Unrestricted · any package" : package == 2
        ? "The displayed package" : "Package restriction is unknown";
    text.scope = "This application and account, including other matching instances and sessions. "
        + QString(package == 1 ? "Any package is included. " : package == 2
            ? "The displayed package is included. " : "Package restriction is unknown. ")
        + "The rule applies only to future connections; it does not resume this attempt. ";
    text.connections = direction == Direction::Out
        ? action == Action::Block ? "Outbound · all destinations and protocols"
                                  : "Outbound · Allow covers unicast destinations only"
        : direction == Direction::In ? "Inbound · all destinations and protocols"
        : direction == Direction::Both
            ? action == Action::Block ? "Both · inbound and outbound; all destinations and protocols"
                                      : "Both · inbound and outbound; Allow includes non-unicast destinations"
        : "Network direction unknown; decisions are not ready";
    text.originalAttempt = held
        ? "Saving an Always rule will cancel this request and keep its original connection blocked."
        : "The original attempt stays blocked; no connection is waiting.";
    text.coverage = "Protection coverage has not been validated.";
    return text;
}
} // namespace Gate::Data
