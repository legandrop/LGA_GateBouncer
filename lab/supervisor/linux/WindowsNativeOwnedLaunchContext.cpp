#include "WindowsNativeOwnedLaunchContext.hpp"
#include <limits>
#include <stdexcept>

namespace gb {
std::mutex WindowsNativeOwnedLaunchContext::registryMutex_;
std::map<WindowsNativeOwnedLaunchContext*, std::shared_ptr<WindowsNativeOwnedLaunchContext>>
    WindowsNativeOwnedLaunchContext::retained_;
namespace {
constexpr DWORD limits = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_JOB_MEMORY;
constexpr SIZE_T memory = 268435456;
constexpr DWORD uiLimits = 0xFF;
static_assert(limits == 0x2208, "Unexpected job limit flags");
}
void WindowsNativeOwnedLaunchContext::Retain(
    const std::shared_ptr<WindowsNativeOwnedLaunchContext>& owner) {
    // Registro y allocation completos ANTES del primer HANDLE/efecto SDK.
    std::lock_guard<std::mutex> lock(registryMutex_);
    retained_.emplace(owner.get(), owner);
}
void WindowsNativeOwnedLaunchContext::ReleaseClosed(
    const std::shared_ptr<WindowsNativeOwnedLaunchContext>& owner) {
    std::shared_ptr<WindowsNativeOwnedLaunchContext> release;
    {
        std::lock_guard<std::mutex> lock(registryMutex_);
        auto found = retained_.find(owner.get());
        if (found != retained_.end()) {
            release = std::move(found->second);
            retained_.erase(found);
        }
    }
    // La ultima referencia/destructor nunca se libera bajo el lock del registry.
    release.reset();
}
std::shared_ptr<WindowsNativeOwnedLaunchContext>
WindowsNativeOwnedLaunchContext::CreateJobOwn() {
    auto owner = std::shared_ptr<WindowsNativeOwnedLaunchContext>(
        new WindowsNativeOwnedLaunchContext);
    Retain(owner);
    bool close = false;
    {
        std::lock_guard<std::mutex> lock(owner->mutex_);
        owner->job_ = CreateJobObjectW(nullptr, nullptr);
        if (!owner->job_) {
            owner->RevokeLocked(Cause::CreateFailed);
            owner->state_ = State::Closed;
            close = true;
        } else {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION information{};
            information.BasicLimitInformation.LimitFlags = limits;
            information.BasicLimitInformation.ActiveProcessLimit = 1;
            information.JobMemoryLimit = memory;
            JOBOBJECT_BASIC_UI_RESTRICTIONS ui{uiLimits};
            if (!SetInformationJobObject(owner->job_, JobObjectExtendedLimitInformation,
                    &information, sizeof(information)) ||
                !SetInformationJobObject(owner->job_, JobObjectBasicUIRestrictions,
                    &ui, sizeof(ui)) || !owner->ReadLimitsOwn()) {
                owner->RevokeLocked(Cause::LimitsUnconfirmed);
                owner->state_ = State::ClosePending;
                close = true;
            } else {
                owner->state_ = State::JobOwned;
            }
        }
    }
    // La factory siempre conserva el owner real cuando un cierre resulta ambiguo.
    if (close) { owner->CloseOwn(); }
    return owner;
}
bool WindowsNativeOwnedLaunchContext::ReadLimitsOwn() const {
    if (!job_) { return false; }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION information{};
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
    if (!QueryInformationJobObject(job_, JobObjectExtendedLimitInformation,
            &information, sizeof(information), nullptr) ||
        !QueryInformationJobObject(job_, JobObjectBasicUIRestrictions,
            &ui, sizeof(ui), nullptr)) { return false; }
    // Solo campos normativos; padding, IO y picos no son limites de admision.
    return information.BasicLimitInformation.LimitFlags == limits &&
        information.BasicLimitInformation.ActiveProcessLimit == 1 &&
        information.JobMemoryLimit == memory && ui.UIRestrictionsClass == uiLimits;
}
void WindowsNativeOwnedLaunchContext::RevokeLocked(Cause cause) {
    if (!revoked_) {
        revoked_ = true;
        if (generation_ == std::numeric_limits<std::uint64_t>::max()) {
            cause = Cause::GenerationExhausted;
        } else { ++generation_; }
    }
    cause_ = cause;
    if (state_ != State::Closed) { state_ = State::Revoked; }
}
WindowsNativeOwnedLaunchContext::Snapshot
WindowsNativeOwnedLaunchContext::ViewLocked() const {
    return {state_, cause_, generation_};
}
WindowsNativeOwnedLaunchContext::Snapshot
WindowsNativeOwnedLaunchContext::InspectOwn() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == State::JobOwned && !ReadLimitsOwn()) {
        RevokeLocked(Cause::LimitsUnconfirmed);
        state_ = State::ClosePending;
    }
    return ViewLocked();
}
WindowsNativeOwnedLaunchContext::Guard::Guard(
    std::shared_ptr<WindowsNativeOwnedLaunchContext> owner, std::uint64_t generation)
    : owner_(std::move(owner)), lock_(owner_->mutex_) {
    if (owner_->revoked_ || owner_->state_ != State::JobOwned ||
        owner_->generation_ != generation) { throw std::runtime_error("JobGuardRevoked"); }
    if (!owner_->ReadLimitsOwn()) {
        owner_->RevokeLocked(Cause::LimitsUnconfirmed);
        owner_->state_ = State::ClosePending;
        throw std::runtime_error("JobGuardUnconfirmed");
    }
}
WindowsNativeOwnedLaunchContext::Guard
WindowsNativeOwnedLaunchContext::GuardCurrent(std::uint64_t generation) {
    return Guard(shared_from_this(), generation);
}
WindowsNativeOwnedLaunchContext::Snapshot
WindowsNativeOwnedLaunchContext::CancelOwn() {
    const auto live = shared_from_this();
    (void)live;
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == State::Closed) { return ViewLocked(); }
    RevokeLocked(Cause::Cancelled);
    if (job_ && !TerminateJobObject(job_, ERROR_CANCELLED)) {
        state_ = State::ClosePending;
        cause_ = Cause::CancelUnconfirmed;
    }
    // Terminate solicitado no demuestra salida de un proceso/guest.
    return ViewLocked();
}
WindowsNativeOwnedLaunchContext::Snapshot
WindowsNativeOwnedLaunchContext::CloseOwn() {
    const auto live = shared_from_this();
    Snapshot result{};
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_ != State::Closed) {
            RevokeLocked(cause_ == Cause::None ? Cause::Cancelled : cause_);
            state_ = State::ClosePending;
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
            // Corte Job-only: nunca asigna procesos. Miembros desconocidos no son cierre.
            if (job_ && (!QueryInformationJobObject(job_, JobObjectBasicAccountingInformation,
                    &accounting, sizeof(accounting), nullptr) || accounting.ActiveProcesses != 0)) {
                cause_ = Cause::AccountingUnconfirmed;
            } else if (job_ && !CloseHandle(job_)) {
                cause_ = Cause::CloseUnconfirmed;
            } else {
                job_ = nullptr;
                state_ = State::Closed;
            }
        }
        result = ViewLocked();
    }
    if (result.state == State::Closed) { ReleaseClosed(live); }
    return result;
}
WindowsNativeOwnedLaunchContext::~WindowsNativeOwnedLaunchContext() noexcept {
    // Shutdown del proceso: best-effort, sin fabricar receipt ni adoptar otros handles.
    if (job_) { CloseHandle(job_); }
}
}
