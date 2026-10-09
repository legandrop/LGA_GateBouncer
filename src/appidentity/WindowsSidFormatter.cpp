#include "AppIdentity.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>

#include <cstring>
#include <vector>

namespace gatebouncer::appidentity {
namespace {

class LocalText {
public:
    LPWSTR value = nullptr;
    ~LocalText() { if (value) LocalFree(value); }
};

class WindowsSidFormatter final : public SidFormatter {
public:
    bool format(const Bytes& sid, std::u16string& text) override
    {
        text.clear();
        // No pasar el vector externo a Win32: longitud exacta y alineación primero.
        if (sid.size() < 8 || sid.size() > SECURITY_MAX_SID_SIZE
            || sid[0] != SID_REVISION || sid[1] > SID_MAX_SUB_AUTHORITIES
            || sid.size() != 8u + 4u * sid[1]) return false;
        std::vector<DWORD> aligned((sid.size() + sizeof(DWORD) - 1) / sizeof(DWORD));
        std::memcpy(aligned.data(), sid.data(), sid.size());
        auto* value = static_cast<PSID>(aligned.data());
        if (!IsValidSid(value) || GetLengthSid(value) != sid.size()) return false;
        LocalText display;
        if (!ConvertSidToStringSidW(value, &display.value) || !display.value) return false;
        std::size_t count = 0;
        while (count <= MaximumPrincipalDisplayUnits && display.value[count] != 0) ++count;
        if (count == 0 || count > MaximumPrincipalDisplayUnits) return false;
        text.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
            text.push_back(static_cast<char16_t>(display.value[i]));
        return true;
    }
};

} // namespace

std::unique_ptr<SidFormatter> makeWindowsSidFormatter()
{
    return std::make_unique<WindowsSidFormatter>();
}

} // namespace gatebouncer::appidentity
