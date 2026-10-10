#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <array>
#include <cstdint>
#include <memory>
namespace gb {
class FixedGuestBrokerSource;
class GuestBrokerBoundary;
class GuestNoJobObserver;
class OwnedSuspendedProcess;
class RetainedFile;
class DesktopWorkerEntry;
class OwnMemorySshCredential;
class BrokerAdmission final {
    friend class GuestBrokerBoundary;
    friend class FixedGuestBrokerSource;
    friend class DesktopWorkerEntry;
    friend class OwnMemorySshCredential;
    BrokerAdmission() = default;
    bool CurrentOwn() const;
    std::shared_ptr<GuestBrokerBoundary> boundary_;
    std::shared_ptr<GuestNoJobObserver> noJob_;
    std::array<std::shared_ptr<RetainedFile>, 7> pins_{};
};
class GuestBrokerBoundary final : public std::enable_shared_from_this<GuestBrokerBoundary> {
    friend class FixedGuestBrokerSource;
    friend class BrokerAdmission;
public:
    static int ServiceOwn();
    static std::shared_ptr<BrokerAdmission> AdmitHelperOwn();
    static bool CloseHelperOwn(const std::shared_ptr<BrokerAdmission>&);
private:
    friend class DesktopWorkerEntry;
    static void WINAPI ServiceMainOwn(DWORD,wchar_t**);
    static bool RunBrokerOwn(DWORD,std::uint64_t,std::uint64_t);
    GuestBrokerBoundary() = default;
    bool CurrentOwn() const;
    struct Resources;
    std::shared_ptr<Resources> resources_;
};
}
#if defined(GB_GUEST_NATIVE_EXPORTS)
#define GB_GUEST_API extern "C" __declspec(dllexport)
#else
#define GB_GUEST_API extern "C"
#endif
// ABI privado del wrapper que retiene runspace y SafeHandles originales.
// La hoja pertenece al registro del MISMO proceso, nunca es un adopter.
GB_GUEST_API bool GbBootstrapReserveOwn(const HANDLE*, const BYTE*, HANDLE, const wchar_t*, void**);
GB_GUEST_API bool GbBootstrapStartOwn(void*);
GB_GUEST_API bool GbBootstrapReadyOwn(void*);
GB_GUEST_API bool GbBootstrapBeginAccountOwn(void*);
GB_GUEST_API bool GbBootstrapAccountOwn(void*, const wchar_t*);
GB_GUEST_API bool GbControllerReserveOwn(const HANDLE*, const BYTE*, HANDLE, void**, DWORD*, std::uint64_t*, std::uint64_t*);
GB_GUEST_API bool GbBootstrapBindOwn(void*, DWORD, std::uint64_t, std::uint64_t);
GB_GUEST_API bool GbControllerBindOwn(void*);
GB_GUEST_API bool GbBootstrapSealOwn(void*);
GB_GUEST_API bool GbNativeCurrentOwn(void*);
GB_GUEST_API bool GbNativeRevokeOwn(void*);
GB_GUEST_API bool GbNativeCloseOwn(void*);
