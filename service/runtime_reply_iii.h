#pragma once
#include "../common/wire_ii.h"

namespace gb::decisions {
// DTO observable; no altera el journal histórico ni convierte bytes Applied en prueba actual.
inline wire::Frame mutationAck(wire::Id epoch, wire::State state, wire::Error error,
                               std::uint64_t desired, std::uint64_t effective, bool known) {
    using namespace wire;
    if (!known && (state == State::Applied || state == State::AppliedUnrecorded)) {
        state = State::RecoveryRequired;
        error = Error::RecoveryRequired;
    }
    Frame reply;
    reply.minor = 2;
    reply.type = Type::MutationAck;
    reply.fields = {value(Tag::ServiceEpoch, epoch), value(Tag::DesiredRev, desired),
                    value(Tag::EffectiveRev, known ? effective : 0),
                    value(Tag::EffectiveKnown, known, 1),
                    value(Tag::CommandState, unsigned(state), 1),
                    value(Tag::ErrorCode, unsigned(error), 2)};
    return reply;
}
} // namespace gb::decisions
