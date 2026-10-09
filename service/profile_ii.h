#pragma once
#include "../common/token_ii_win.h"
#include "decisions_ii.h"

namespace gb::decisions {
class NativeProfile {
  public:
    explicit NativeProfile(Bytes configuredAccount) : account_(std::move(configuredAccount)) {}
    bool refresh();
    bool accepts(const native::TokenEvidence &peer, bool control) const;
    const Profile &value() const { return profile_; }
    const Bytes &account() const { return account_; }
    const Bytes &logon() const { return logon_; }
    DWORD session() const { return session_; }
    VerifiedControl authority(const native::TokenEvidence &peer, bool fullServer) const;

  private:
    Bytes account_, logon_;
    DWORD session_ = 0;
    Profile profile_;
};
} // namespace gb::decisions
