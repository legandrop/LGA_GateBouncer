#include "NativeLifecycle.h"

namespace gatebouncer::service::windows::allapps::native {
HANDLE Lifecycle::claim() noexcept
{ if (!handle_ || cancel_ || worker_) return nullptr; cancel_ = true; return handle_; }
bool Lifecycle::begin()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != Stage::Created) return false;
    state_ = Stage::Starting; start_ = true; return true;
}
HANDLE Lifecycle::requestStop()
{
    std::lock_guard<std::mutex> lock(mutex_); cancelPending_ = true;
    if (state_ == Stage::Created) noCreation_ = true;
    if (state_ != Stage::Drained && state_ != Stage::FaultRetained) state_ = Stage::Stopping;
    return claim();
}
HANDLE Lifecycle::publish(DWORD result, HANDLE handle, bool seen)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!start_ || handle_) { state_ = Stage::FaultRetained; return nullptr; }
    if (result == ERROR_SUCCESS && handle) {
        handle_ = handle; return cancelPending_ ? claim() : nullptr;
    }
    // Este error documenta que Subscribe no se puede ejecutar en una transacción.
    noCreation_ = result == static_cast<DWORD>(FWP_E_TXN_IN_PROGRESS) && !handle && !seen;
    if (!noCreation_) state_ = Stage::FaultRetained;
    return nullptr;
}
bool Lifecycle::activate()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != Stage::Starting || cancelPending_ || !handle_ || cancel_) return false;
    state_ = Stage::Active; return true;
}
void Lifecycle::finishStart() { std::lock_guard<std::mutex> lock(mutex_); start_ = false; }
void Lifecycle::finishCancel(DWORD result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!cancel_ || !handle_) { state_ = Stage::FaultRetained; return; }
    cancel_ = false;
    if (result == ERROR_SUCCESS) { handle_ = nullptr; cancelled_ = true; }
    else state_ = Stage::FaultRetained;
}
bool Lifecycle::beginWorker(bool starting)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if ((state_ != Stage::Active && !(starting && state_ == Stage::Starting && start_)) || cancelPending_ || worker_) return false;
    worker_ = true; return true;
}
HANDLE Lifecycle::finishWorker()
{
    std::lock_guard<std::mutex> lock(mutex_); worker_ = false;
    return cancelPending_ ? claim() : nullptr;
}
bool Lifecycle::drain(unsigned callbacks, unsigned copiers)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == Stage::Drained) return true;
    if (!cancelPending_ || start_ || cancel_ || handle_ || (!noCreation_ && !cancelled_) ||
        state_ == Stage::FaultRetained || callbacks || copiers || worker_) return false;
    state_ = Stage::Drained; return true;
}
Stage Lifecycle::stage() const { std::lock_guard<std::mutex> lock(mutex_); return state_; }
} // namespace gatebouncer::service::windows::allapps::native
