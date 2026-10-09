#pragma once
#include "../files/RetainedFile.hpp"
#include <atomic>
namespace gb {
class GuestConversionLauncher;
// Custodia de archivos; no emite permiso de captura ni ejecuta el conversor en el padre.
class P3OwnedConversionFileSeal final : public std::enable_shared_from_this<P3OwnedConversionFileSeal> {
public:
    enum class State { Acquiring, Sealed, ClosePending, Closed };
    struct Snapshot { State state; bool cancelled; };
    Snapshot InspectOwn();
    Snapshot CancelOwn();
    Snapshot CloseOwn();
    ~P3OwnedConversionFileSeal() noexcept = default;
private:
    friend class GuestConversionLauncher;
    P3OwnedConversionFileSeal() = default;
    // Solo el launcher de captura propio podra invocarlo tras Stop/FileFinal actuales.
    static std::shared_ptr<P3OwnedConversionFileSeal> AcquireOwn(const std::wstring&,
        std::uint32_t, std::int64_t, std::int64_t);
    bool CurrentOwn();
    bool LimitsOwn() const;
    std::recursive_mutex mutex_;
    std::atomic<bool> cancelled_{false};
    State state_ = State::Acquiring;
    bool active_ = false;
    std::wstring run_;
    std::uint32_t interface_ = 0;
    std::int64_t start_ = 0, end_ = 0;
    std::shared_ptr<RetainedFile> input_, output_;
    HANDLE job_ = nullptr, cancel_ = nullptr;
    static std::mutex registryMutex_;
    static std::map<P3OwnedConversionFileSeal*, std::shared_ptr<P3OwnedConversionFileSeal>> retained_;
};
}
