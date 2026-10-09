#include "NativeSdk.h"

namespace gatebouncer::service::windows::allapps::native {
SdkApi systemSdk()
{
    SdkApi api;
    const auto module = LoadLibraryExW(L"fwpuclnt.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) return api;
    api.module = std::shared_ptr<void>(module, [](void* p) { FreeLibrary(static_cast<HMODULE>(p)); });
    // GetProcAddress exige este cast; el tipo es exactamente el declarado por fwpmu.h.
#pragma warning(push)
#pragma warning(disable: 4191)
    api.subscribe = reinterpret_cast<decltype(api.subscribe)>(GetProcAddress(module, "FwpmNetEventSubscribe2"));
#pragma warning(pop)
    return api;
}
} // namespace gatebouncer::service::windows::allapps::native
