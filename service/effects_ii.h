#pragma once
#include "journal_ii_store.h"
#include "policy.h"
namespace gb::decisions {
// Proyección cerrada Commit9→CreateRule10 del núcleo A, orden fijo de tags.
bool projectPermanent(const Frame &command, Frame &projected, Bytes &canonicalPolicy);
class NativeEffects final : public EffectBackend {
  public:
    NativeEffects(Coordinator &coordinator, NativeJournal &journal, Backend &backend)
        : coordinator_(coordinator), journal_(journal), backend_(backend) {}
    bool ready() const override;
    bool commit(const Frame &command) override;
    bool readback(std::uint64_t revision) override;
    bool actualOs() const override { return backend_.actualOs(); }
    bool proveApplied(const CommandEntry &command);

  private:
    Coordinator &coordinator_;
    NativeJournal &journal_;
    Backend &backend_;
};
} // namespace gb::decisions
