#include "P3Transfer.hpp"
#include "convert_ndis.hpp"
#include <cwchar>
#include <cstring>
#include <set>
namespace gb {
class GuestConversionLauncher final {
public:
    static int RunWorkerOwn(HANDLE descriptorHandle) {
        auto view = MapViewOfFile(descriptorHandle, FILE_MAP_READ, 0, 0, sizeof(P3Descriptor));
        if (!view) return 4;
        P3Descriptor d{}; std::memcpy(&d, view, sizeof(d));
        if (!UnmapViewOfFile(view)) return 4;
        if (d.magic != 0x33504247 || d.bytes != sizeof(d) || d.run[36] != 0 || !d.interfaceIndex ||
            d.start < 116444736000000000LL || d.end <= d.start || d.end - d.start > 600000000) return 4;
        std::set<std::uint64_t> unique;
        for (auto handle : d.handles) if (!handle || !unique.insert(handle).second) return 4;
        if (d.handles[3] != reinterpret_cast<std::uintptr_t>(descriptorHandle)) return 4;
        std::array<HANDLE, 5> h{};
        for (std::size_t i = 0; i < h.size(); ++i) {
            h[i] = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(d.handles[i]));
            DWORD flags = 0;
            if (!GetHandleInformation(h[i], &flags) || !SetHandleInformation(h[i], HANDLE_FLAG_INHERIT, 0)) return 4;
        }
        // El Job inmediato fue asignado por el padre antes de Resume; el worker no posee HANDLE Job.
        if (!P3LimitsCurrent(nullptr) || WaitForSingleObject(h[2], 0) != WAIT_TIMEOUT) return 4;
        auto resultView = MapViewOfFile(h[4], FILE_MAP_WRITE, 0, 0, sizeof(P3Result));
        if (!resultView) return 4;
        OwnedConversion owned(h[0], h[1], h[2], d.input, d.run, d.interfaceIndex, d.start, d.end);
        const auto report = ConvertOwnedEtl(owned);
        P3Result result{};
        result.completed = 1;
        result.converted = std::strcmp(report.outcome, "ConvertedOriginalLengthUnknown") == 0 ? 1u : 0u;
        result.packets = report.packets; result.records = report.records;
        result.header = report.nativeHeaderAvailable ? 1u : 0u;
        result.eventsKnown = report.nativeEventsLost.has_value() ? 1u : 0u;
        result.eventsLost = report.nativeEventsLost.value_or(0);
        result.buffersKnown = report.nativeBuffersLost.has_value() ? 1u : 0u;
        result.buffersLost = report.nativeBuffersLost.value_or(0);
        result.emittedKnown = report.emittedBytes.has_value() ? 1u : 0u;
        result.reserved = report.reservedBytes; result.emitted = report.emittedBytes.value_or(0);
        std::memcpy(resultView, &result, sizeof(result));
        bool closed = UnmapViewOfFile(resultView) != FALSE;
        // El padre conserva duplicados y no suelta archivos hasta exit/accounting0.
        for (auto handle : h) if (!CloseHandle(handle)) closed = false;
        return closed ? (result.converted ? 0 : 2) : 3;
    }
};
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 2 || !argv[1] || !*argv[1]) return 4;
    std::uint64_t value = 0;
    for (const wchar_t* p = argv[1]; *p; ++p) {
        if (*p < L'0' || *p > L'9' || value > (UINT64_MAX - 9) / 10) return 4;
        value = value * 10 + static_cast<unsigned>(*p - L'0');
    }
    if (!value || value > UINTPTR_MAX) return 4;
    try { return gb::GuestConversionLauncher::RunWorkerOwn(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value))); }
    catch (...) { return 5; }
}
