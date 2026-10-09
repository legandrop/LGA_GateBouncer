#include "journal_iii.h"
#include <algorithm>

namespace gb::directional {
Error SnapshotJournal::admission(const Frame &command) const {
    return command.minor == 2 && command.type == Type::CommitDecision &&
                   !get(command, Tag::Remember) && coordinator_.legacy()
               ? Error::Unsupported
               : Error::Ok;
}
bool SnapshotJournal::persist(const std::vector<decisions::CommandEntry> &rows) {
    auto s = coordinator_.snapshot();
    const decisions::CommandEntry *changed = nullptr;
    bool admission = false;
    for (const auto &c : rows) {
        auto it = std::find_if(s.entries.begin(), s.entries.end(),
                               [&](const auto &e) { return e.command.id == c.id; });
        if (it == s.entries.end()) {
            if (changed)
                return false;
            changed = &c;
            admission = true;
        } else if (it->command.state != c.state || it->command.error != c.error ||
                   it->command.effectiveKnown != c.effectiveKnown ||
                   it->command.effective != c.effective ||
                   (it->command.completedAt != c.completedAt &&
                    it->command.state != State::Applied && it->command.state != State::Failed)) {
            if (changed)
                return false;
            changed = &c;
        } else if (it->command.payload != c.payload || it->command.accountSid != c.accountSid ||
                   it->command.logonSid != c.logonSid || it->command.principal != c.principal ||
                   it->command.logon != c.logon || it->command.sessionId != c.sessionId)
            return false;
    }
    if (!changed)
        return true;
    if (!admission)
        return coordinator_.complete(*changed).durable;
    Frame f;
    if (decode(changed->payload, f) != Error::Ok || f.minor != 2)
        return false;
    auto rules = s.rules;
    if (f.type == Type::CreateRule || (f.type == Type::CommitDecision && get(f, Tag::Remember))) {
        auto app = registry_.lookup(idValue(f, Tag::SelectorId));
        if (!app)
            return false;
        auto action = static_cast<std::uint8_t>(get(f, Tag::Decision));
        auto direction = static_cast<std::uint8_t>(get(f, Tag::PolicyDirection));
        rules.push_back({f.correlation, idValue(f, Tag::SelectorId), 1, 1, action, direction,
                         static_cast<std::uint8_t>(action == 1 || direction == 2 ? 0
                                                   : direction == 1              ? 1
                                                                                 : 2),
                         *app});
    } else if (f.type == Type::RevokeRule) {
        auto it = std::find_if(rules.begin(), rules.end(),
                               [&](const auto &r) { return r.id == idValue(f, Tag::RuleId); });
        if (it == rules.end())
            return false;
        rules.erase(it);
    }
    auto prepared = coordinator_.prepare(*changed, rules, s.sequence);
    if (prepared.error != Error::Ok || prepared.state != State::Prepared || !prepared.durable)
        return false;
    // Engine II no llama commit() para Blockfalse; sólo constatar el target sin efecto.
    return f.type != Type::CommitDecision || get(f, Tag::Remember) ||
           coordinator_.applyPrepared(changed->id);
}
bool SnapshotEffects::ready() const {
    auto s = coordinator_.snapshot();
    return !coordinator_.recovery() && coordinator_.currentReadback(s.desired);
}
bool SnapshotEffects::commit(const Frame &command) {
    auto s = coordinator_.snapshot();
    auto it = std::find_if(s.entries.begin(), s.entries.end(),
                           [&](const auto &e) { return e.command.id == command.correlation; });
    if (it == s.entries.end())
        return false;
    Frame canonical = command;
    canonical.connection.fill(1);
    canonical.sequence = 1;
    std::sort(canonical.fields.begin(), canonical.fields.end(),
              [](auto &a, auto &b) { return a.tag < b.tag; });
    Bytes bytes;
    if (encode(canonical, bytes) != Error::Ok || bytes != it->command.payload)
        return false;
    return coordinator_.applyPrepared(command.correlation);
}
} // namespace gb::directional
