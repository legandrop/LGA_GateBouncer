#include "../common/pipe_ii_win.h"
#include "../common/token_ii_win.h"
#include "deployment_win.h"
#include <sddl.h>

// Ejecutable nativo sin imports Qt: las comprobaciones preceden al primer loader Qt.
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    try {
        gb::native::Handle token;
        HANDLE raw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
            return 20;
        token.reset(raw);
        gb::native::TokenEvidence identity;
        if (!gb::native::tokenEvidence(token.value, identity) || !identity.administrator ||
            !identity.elevated || identity.uiAccess ||
            identity.integrity < SECURITY_MANDATORY_HIGH_RID)
            return 21;
        wchar_t path[32768]{};
        auto n = GetModuleFileNameW(nullptr, path, 32768);
        if (!n || n >= 32768)
            return 22;
        auto own = std::filesystem::path(std::wstring(path, n));
        gb::controller::Deployment deployment(own.parent_path());
        if (!deployment.verify(own) || !deployment.prepareEnvironment())
            return 23;
        auto mutexName =
            L"Local\\LGA.GateBouncer.DecisionController." + std::to_wstring(identity.session);
        auto mutexDescriptor =
            L"O:" + gb::native::sidString(identity.account) +
            L"G:BAD:P(A;;0x00020000;;;OW)(A;;0x001f0001;;;SY)(A;;0x001f0001;;;BA)S:P(ML;;NW;;;HI)";
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                mutexDescriptor.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
            return 27;
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
        gb::native::Handle sessionMutex(CreateMutexW(&attributes, FALSE, mutexName.c_str()));
        auto mutexError = GetLastError();
        LocalFree(descriptor);
        if (!sessionMutex || mutexError == ERROR_ALREADY_EXISTS ||
            !gb::ipc::ii::exactDescriptor(sessionMutex.value, mutexDescriptor))
            return 28;
        auto module =
            LoadLibraryExW((deployment.root() / L"GateBouncerDecisionStage.dll").c_str(), nullptr,
                           LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32 |
                               LOAD_LIBRARY_SEARCH_USER_DIRS);
        if (!module)
            return 24;
        using Stage = int (*)(const wchar_t *, DWORD);
        auto stage =
            reinterpret_cast<Stage>(GetProcAddress(module, "GateBouncerDecisionStageMain"));
        if (!stage) {
            FreeLibrary(module);
            return 25;
        }
        auto result = stage(deployment.root().c_str(), identity.session);
        FreeLibrary(module);
        return result;
    } catch (...) {
        return 26;
    }
}
