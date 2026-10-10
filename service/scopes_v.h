#pragma once
#include "coordinator_iii.h"
#include <winioctl.h>
#include "../common/classifier_protocol.h"
namespace gb::decisions {
struct ScopedEntry {
    Id command{}, epoch{}, boot{};
    Bytes payload, account, logon;
    std::uint32_t pid = 0, session = 0;
    std::uint64_t created = 0;
    GB_SCOPE_RECEIPT kernel{};
    State state = State::Prepared;
};
// Historial durable de permisos efímeros: load jamás rearma un efecto kernel.
class ScopedJournal {
public:
    explicit ScopedJournal(std::filesystem::path root)
        : parent_(root), directory_(root / L"scopes") {}
    bool load();
    bool prepare(const ScopedEntry &);
    bool complete(const Id &, const GB_SCOPE_RECEIPT &);
    const ScopedEntry *find(const Id &) const;
    std::uint64_t revision() const { return revision_; }
    bool uncertain() const { return uncertain_; }
private:
    bool persist(const std::vector<ScopedEntry> &);
    native::ProtectedDirectory parent_, directory_;
    native::Handle lease_;
    std::vector<ScopedEntry> entries_;
    std::uint64_t revision_ = 0;
    bool loaded_ = false, uncertain_ = true;
};
}
