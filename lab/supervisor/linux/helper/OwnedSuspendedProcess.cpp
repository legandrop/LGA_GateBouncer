#include "OwnedSuspendedProcess.hpp"
namespace gb {
std::mutex OwnedSuspendedProcess::registryMutex_;
std::map<OwnedSuspendedProcess*, std::shared_ptr<OwnedSuspendedProcess>>
    OwnedSuspendedProcess::retained_;
namespace {
std::uint64_t Stamp(const FILETIME& time) {
    return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}
bool AbsoluteLocal(const std::wstring& path) {
    return path.size() > 3 && ((path[0] >= L'A' && path[0] <= L'Z') ||
        (path[0] >= L'a' && path[0] <= L'z')) && path[1] == L':' &&
        path[2] == L'\\' && path.find(L'\0') == std::wstring::npos;
}
}
OwnedSuspendedProcess::Snapshot OwnedSuspendedProcess::ViewLocked() const {
    return {state_, cause_, pid_, creation_, revoked_, exitObserved_};
}
void OwnedSuspendedProcess::RevokeLocked(Cause cause) {
    revoked_ = true;
    cause_ = cause;
    if (state_ != State::Closed) state_ = State::ClosePending;
}
void OwnedSuspendedProcess::ReleaseClosed(const std::shared_ptr<OwnedSuspendedProcess>& owner) {
    std::shared_ptr<OwnedSuspendedProcess> release;
    {
        std::lock_guard<std::mutex> lock(registryMutex_);
        auto found = retained_.find(owner.get());
        if (found != retained_.end()) {
            release = std::move(found->second);
            retained_.erase(found);
        }
    }
    release.reset();
}
std::shared_ptr<OwnedSuspendedProcess> OwnedSuspendedProcess::CreateSuspendedOwn(
    const std::wstring& image, std::vector<wchar_t> command,
    const std::vector<wchar_t>& environment, const std::wstring& cwd) {
    auto owner = std::shared_ptr<OwnedSuspendedProcess>(new OwnedSuspendedProcess);
    {
        // Reserva fuerte antes de CreateProcess; no SDK si allocation/registry falla.
        std::lock_guard<std::mutex> registryLock(registryMutex_);
        retained_.emplace(owner.get(), owner);
    }
    bool cleanup = false;
    {
        std::lock_guard<std::recursive_mutex> lock(owner->mutex_);
        if (!AbsoluteLocal(image) || !AbsoluteLocal(cwd) || command.empty() ||
            command.size() > 32767 || command.back() != L'\0' ||
            environment.size() < 2 || environment.size() > 32767 ||
            environment.back() != L'\0' || environment[environment.size() - 2] != L'\0') {
            owner->RevokeLocked(Cause::InputInvalid);
            owner->state_ = State::Closed;
            cleanup = true;
        } else {
            STARTUPINFOEXW startup{};
            startup.StartupInfo.cb = sizeof(startup);
            PROCESS_INFORMATION process{};
            owner->acquiring_ = true;
            const BOOL created = CreateProcessW(image.c_str(), command.data(), nullptr,
                nullptr, FALSE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT |
                EXTENDED_STARTUPINFO_PRESENT, const_cast<wchar_t*>(environment.data()),
                cwd.c_str(), &startup.StartupInfo, &process);
            // Cada HANDLE devuelto se retiene antes de identidad u otra validación.
            owner->process_ = process.hProcess;
            owner->thread_ = process.hThread;
            owner->pid_ = process.dwProcessId;
            owner->acquiring_ = false;
            FILETIME creation{}, exit{}, kernel{}, user{};
            if (created && owner->process_ && owner->thread_ && owner->pid_ &&
                GetProcessId(owner->process_) == owner->pid_ &&
                GetProcessTimes(owner->process_, &creation, &exit, &kernel, &user) &&
                Stamp(creation) != 0) {
                owner->creation_ = Stamp(creation);
                if (!owner->cancelRequested_.load() && !owner->revoked_)
                    owner->state_ = State::Suspended;
                else { owner->RevokeLocked(Cause::Cancelled); cleanup = true; }
            } else {
                owner->RevokeLocked(created ? Cause::IdentityUnconfirmed : Cause::CreateFailed);
                cleanup = true;
            }
        }
    }
    if (cleanup) owner->CloseOwn();
    return owner;
}
bool OwnedSuspendedProcess::ReadIdentityOwn() const {
    FILETIME creation{}, exit{}, kernel{}, user{};
    return process_ && pid_ && creation_ && GetProcessId(process_) == pid_ &&
        GetProcessTimes(process_, &creation, &exit, &kernel, &user) &&
        Stamp(creation) == creation_ && WaitForSingleObject(process_, 0) == WAIT_TIMEOUT;
}
OwnedSuspendedProcess::Snapshot OwnedSuspendedProcess::InspectOwn() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (state_ == State::Suspended && (cancelRequested_.load() || !ReadIdentityOwn()))
        RevokeLocked(cancelRequested_.load() ? Cause::Cancelled : Cause::IdentityUnconfirmed);
    return ViewLocked();
}
OwnedSuspendedProcess::Snapshot OwnedSuspendedProcess::CancelOwn() {
    cancelRequested_.store(true);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (state_ != State::Closed) RevokeLocked(Cause::Cancelled);
    return ViewLocked();
}
OwnedSuspendedProcess::Snapshot OwnedSuspendedProcess::CloseOwn() {
    const auto live = shared_from_this();
    cancelRequested_.store(true);
    Snapshot result{};
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (state_ != State::Closed) {
            RevokeLocked(cause_ == Cause::None ? Cause::Cancelled : cause_);
            // Create/close reentrante conserva Pending; no cierra durante acquisition SDK.
            if (acquiring_ || closing_ || noJobObservers_) return ViewLocked();
            closing_ = true;
            if (process_ && !exitObserved_) {
                const DWORD before = WaitForSingleObject(process_, 0);
                if (before == WAIT_OBJECT_0) exitObserved_ = true;
                else if (before != WAIT_TIMEOUT) cause_ = Cause::ExitUnconfirmed;
                else if (!TerminateProcess(process_, ERROR_CANCELLED)) cause_ = Cause::TerminateUnconfirmed;
                else if (WaitForSingleObject(process_, 0) == WAIT_OBJECT_0) exitObserved_ = true;
                else cause_ = Cause::ExitUnconfirmed;
            }
            if ((!process_ || exitObserved_) && thread_) {
                if (CloseHandle(thread_)) thread_ = nullptr;
                else cause_ = Cause::CloseUnconfirmed;
            }
            if ((!process_ || exitObserved_) && !thread_ && process_) {
                if (CloseHandle(process_)) process_ = nullptr;
                else cause_ = Cause::CloseUnconfirmed;
            }
            if (!process_ && !thread_) state_ = State::Closed;
            closing_ = false;
        }
        result = ViewLocked();
    }
    if (result.state == State::Closed) ReleaseClosed(live);
    return result;
}
}
