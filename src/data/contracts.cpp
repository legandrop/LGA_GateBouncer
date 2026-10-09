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
} // namespace Gate::Data
