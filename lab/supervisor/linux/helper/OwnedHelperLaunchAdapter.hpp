#pragma once
#include "OwnedHelperContainer.hpp"
#include "OwnedSuspendedProcess.hpp"
namespace gb {
class OwnedHelperLaunchAdapter final {
public:
    // Crea y registra exclusivamente un miembro suspendido propio; jamás Resume/entry.
    static std::shared_ptr<OwnedSuspendedProcess> AcquireSuspendedMemberOwn(
        const std::shared_ptr<OwnedHelperContainer>&, const std::wstring&,
        std::vector<wchar_t>, const std::vector<wchar_t>&, const std::wstring&);
private:
    friend class OwnedHelperContainer;
    static bool CurrentMemberOwn(const std::shared_ptr<OwnedSuspendedProcess>&,
        HANDLE, bool, DWORD&);
    static bool CloseMemberOwn(const std::shared_ptr<OwnedSuspendedProcess>&);
};
}
