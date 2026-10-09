#include "effects_ii.h"
namespace gb::decisions {
bool projectPermanent(const Frame &f, Frame &out, Bytes &bytes) {
    if (f.minor != 1 || f.type != Type::CommitDecision || wire::validate(f) != Error::Ok ||
        !get(f, Tag::Remember))
        return false;
    Frame p;
    p.minor = 0;
    p.type = Type::CreateRule;
    p.connection[0] = 1;
    p.sequence = 2;
    p.correlation = f.correlation;
    p.fields = {value(Tag::ExpectedDesiredRev, get(f, Tag::ExpectedDesiredRev)),
                value(Tag::Decision, get(f, Tag::Decision), 1), value(Tag::ScopeKind, 1, 1),
                value(Tag::SelectorId, idValue(f, Tag::SelectorId))};
    Bytes b;
    if (wire::encode(p, b) != Error::Ok)
        return false;
    out = std::move(p);
    bytes = std::move(b);
    return true;
}
} // namespace gb::decisions
