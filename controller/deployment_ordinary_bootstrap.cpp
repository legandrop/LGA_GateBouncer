#include "deployment_win.h"
#include "deployment_ordinary_args.h"
#include "../common/token_ii_win.h"
#include <shellapi.h>

// Bootstrap nativo asInvoker: el loader Qt sólo entra después del paquete retenido.
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    try {
        int argc = 0;
        struct Arguments {
            wchar_t **value = nullptr;
            ~Arguments() { if (value) LocalFree(value); }
        } arguments{CommandLineToArgvW(GetCommandLineW(), &argc)};
        if (!gb::controller::ordinaryArguments(argc, arguments.value)) return 27;
        gb::native::Handle token;
        HANDLE raw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) return 20;
        token.reset(raw);
        gb::native::TokenEvidence identity;
        if (!gb::native::tokenEvidence(token.value, identity) || identity.uiAccess ||
            identity.integrity < SECURITY_MANDATORY_MEDIUM_RID) return 21;
        wchar_t path[32768]{};
        const auto count = GetModuleFileNameW(nullptr, path, 32768);
        if (!count || count >= 32768) return 22;
        const std::filesystem::path image(std::wstring(path, count));
        gb::controller::Deployment deployment(image.parent_path());
        if (!deployment.verify(image, gb::controller::DeploymentRole::OrdinaryGui) ||
            !deployment.prepareEnvironment()) return 23;
        HMODULE module = LoadLibraryExW((deployment.root() / L"GateBouncerGuiStage.dll").c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS);
        if (!module) return 24;
        using Entry = int (*)(int, wchar_t **);
        auto entry = reinterpret_cast<Entry>(GetProcAddress(module, "GateBouncerGuiStageMain"));
        // Nunca reenviar la command line: path propio y único literal admitido.
        wchar_t minimized[] = L"--start-minimized";
        wchar_t *argv[] = {path, argc == 2 ? minimized : nullptr, nullptr};
        const auto result = entry && deployment.current() ? entry(argc, argv) : 25;
        FreeLibrary(module);
        return result;
    } catch (...) { return 26; }
}
