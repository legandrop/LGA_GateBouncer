#pragma once
#include <windows.h>
#include <string>
#include <cstdint>
#include <optional>
namespace gb {
class GuestConversionLauncher;
// Capacidad local del worker: sólo su entry validado puede construirla.
// El padre conserva el Job y los archivos hasta salida y accounting cero.
class OwnedConversion final {
    friend class GuestConversionLauncher;
    friend struct NativeConversion;
    HANDLE input_, output_, cancel_;
    BY_HANDLE_FILE_INFORMATION identity_;
    std::wstring run_;
    std::uint32_t interface_;
    std::int64_t start_, end_;
    OwnedConversion(HANDLE input, HANDLE output, HANDLE cancel,
                    BY_HANDLE_FILE_INFORMATION identity, std::wstring run,
                    std::uint32_t interfaceIndex, std::int64_t start, std::int64_t end)
        : input_(input), output_(output), cancel_(cancel), identity_(identity),
          run_(std::move(run)), interface_(interfaceIndex), start_(start), end_(end) {}
public:
    OwnedConversion(const OwnedConversion&) = delete;
    OwnedConversion& operator=(const OwnedConversion&) = delete;
};
struct ConversionReport {
    const char* outcome = "NotStarted";
    const char* originalLength = "Unknown";
    const char* retention = "Unknown";
    const char* logBuffersLost = "Unknown";
    const char* realTimeBuffersLost = "Unknown";
    std::uint32_t packets = 0, records = 0, otherProviderRecords = 0;
    std::optional<std::uint32_t> nativeEventsLost, nativeBuffersLost, nativeMode;
    bool nativeHeaderAvailable = false;
    std::uint64_t reservedBytes = 0;
    std::optional<std::uint64_t> emittedBytes;
};
// Invocado exclusivamente dentro del worker asociado a su Job inmediato.
ConversionReport ConvertOwnedEtl(OwnedConversion& owned) noexcept;
}
