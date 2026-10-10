#pragma once
#include "coordinator_iii.h"
#include "../common/token_ii_win.h"
#include <winioctl.h>
#include <mutex>
#include "../common/classifier_protocol.h"
namespace gb::decisions {
struct ScopedEntry {
    Id command{}, epoch{}, boot{};
    Bytes payload, account, logon;
    std::uint32_t pid = 0, session = 0;
    std::uint64_t created = 0;
    std::uint32_t format = 1;
    BY_HANDLE_FILE_INFORMATION image{};
    GB_SCOPE_RECEIPT kernel{};
    State state = State::Prepared;
};
bool scopedActorMatches(const ScopedEntry &,const Id &epoch,const Id &boot,std::uint64_t profile,
    DWORD pid,const FILETIME &,const BY_HANDLE_FILE_INFORMATION &,const native::TokenEvidence &);
// Historial durable de permisos efímeros: load jamás rearma un efecto kernel.
class ScopedJournal {
public:
    explicit ScopedJournal(std::filesystem::path root)
        : parent_(root), directory_(root / L"scopes") {}
    bool load();
    bool prepare(const ScopedEntry &);
    bool complete(const Id &, const GB_SCOPE_RECEIPT &);
    bool read(const Id &, ScopedEntry &, bool &found);
    std::uint64_t revision() const { std::lock_guard<std::mutex> lock(mutex_); return revision_; }
    bool uncertain() const { std::lock_guard<std::mutex> lock(mutex_); return uncertain_; }
private:
    bool initialize();
    bool readOwned(const Id &, ScopedEntry &, bool &found);
    bool persist(const ScopedEntry &, const Bytes &before, bool existed);
    bool reserve(std::uint64_t);
    native::ProtectedDirectory parent_, directory_;
    native::Handle lease_;
    std::vector<ScopedEntry> legacy_;
    Bytes counter_;
    mutable std::mutex mutex_;
    std::uint64_t revision_ = 0;
    bool loaded_ = false, uncertain_ = true;
};
}
