#pragma once
#include "NativeRead.h"

namespace gatebouncer::service::windows::allapps::native {
enum class Stage : std::uint8_t { Created, Starting, Active, Stopping, FaultRetained, Drained };
// Control local del protocolo, sin capacidad de engine ni prueba Windows.
class Lifecycle {
public:
    bool begin();
    HANDLE requestStop();
    HANDLE publish(DWORD result, HANDLE handle, bool callbackObserved);
    bool activate();
    void finishStart();
    void finishCancel(DWORD result);
    bool beginWorker(bool starting = false);
    HANDLE finishWorker();
    bool drain(unsigned callbacks, unsigned copiers);
    Stage stage() const;
private:
    HANDLE claim() noexcept;
    mutable std::mutex mutex_;
    Stage state_ = Stage::Created;
    HANDLE handle_ = nullptr;
    bool start_ = false, cancelPending_ = false, cancel_ = false, noCreation_ = false, cancelled_ = false;
    bool worker_ = false;
};
} // namespace gatebouncer::service::windows::allapps::native
