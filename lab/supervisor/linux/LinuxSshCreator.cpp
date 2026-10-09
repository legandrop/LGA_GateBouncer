#include "LinuxSshCreator.hpp"
#include <stdexcept>
namespace gb {
std::mutex LinuxSshCreator::registryMutex_;
std::map<LinuxSshCreator*, std::shared_ptr<LinuxSshCreator>> LinuxSshCreator::retained_;
namespace {
struct Attributes {
    std::vector<BYTE> data;
    LPPROC_THREAD_ATTRIBUTE_LIST list = nullptr;
    ~Attributes() { if (list) DeleteProcThreadAttributeList(list); }
    bool Init(HANDLE* handles, SIZE_T bytes) {
        SIZE_T size = 0;
        if (InitializeProcThreadAttributeList(nullptr, 1, 0, &size) || GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
            !size || size > 65536) return false;
        data.resize(size);
        auto candidate = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(data.data());
        if (!InitializeProcThreadAttributeList(candidate, 1, 0, &size)) return false;
        list = candidate;
        return UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, bytes, nullptr, nullptr) != FALSE;
    }
};
}
LinuxSshCreator::Snapshot LinuxSshCreator::ViewOwn() const { return {state_, resumeSubmitted_, cancelled_.load()}; }
void LinuxSshCreator::RevokeOwn() { cancelled_.store(true); if (state_ != State::Closed) state_ = State::ClosePending; }
bool LinuxSshCreator::CurrentOwn() {
    if (cancelled_.load() || !desktop_ || !job_ || !helper_ || desktop_->cancelRequested_.load() ||
        job_->cancelRequested_.load() || helper_->cancelRequested_.load() || desktop_->revoked_ || job_->revoked_ ||
        desktop_->generation_ != desktopGeneration_ || job_->generation_ != jobGeneration_ ||
        desktop_->state_ != PrivateDesktopOwner::State::DesktopOwned ||
        job_->state_ != WindowsNativeOwnedLaunchContext::State::JobOwned || !helper_->ReadActualOwn() ||
        GetProcessId(helper_->child_ ? helper_->childProcess_ : helper_->creator_) != GetCurrentProcessId() ||
        !desktop_->ReadSecurityOwn(desktop_->station_, 0x2000A) || !desktop_->ReadSecurityOwn(desktop_->desktop_, 0x20083) ||
        !job_->ReadLimitsOwn() || desktop_->NamespaceOwn() != desktopName_) return false;
    for (const auto& file : files_) if (!file || !file->CurrentOwn()) return false;
    return !cancelled_.load() && !helper_->cancelRequested_.load() && !desktop_->cancelRequested_.load() &&
        !job_->cancelRequested_.load();
}
std::shared_ptr<LinuxSshCreator> LinuxSshCreator::StartPreparedOwn(
    const std::shared_ptr<PrivateDesktopOwner>& desktop,
    const std::shared_ptr<WindowsNativeOwnedLaunchContext>& job,
    const std::shared_ptr<GuestNoJobObserver>& helper,
    const std::array<std::array<BYTE, 32>, 4>& pins, const std::wstring& temporary, const std::wstring& address) {
    auto owner = std::shared_ptr<LinuxSshCreator>(new LinuxSshCreator);
    { std::lock_guard<std::mutex> registry(registryMutex_); retained_.emplace(owner.get(), owner); }
    std::lock_guard<std::recursive_mutex> operation(owner->mutex_);
    owner->desktop_ = desktop; owner->job_ = job; owner->helper_ = helper; owner->temporary_ = temporary; owner->address_ = address;
    owner->active_ = true;
    try {
        if (!desktop || !job || !helper || temporary.size() != 54 || address.empty() || address.size() > 45 ||
            temporary.substr(0, 22) != L"C:\\GateBouncerLab\\tmp\\") throw std::runtime_error("OwnContextMissing");
        bool punctuation = false;
        for (auto ch : address) {
            if (ch == L'.' || ch == L':') punctuation = true;
            else if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f'))) throw std::runtime_error("OwnAddressInvalid");
        }
        if (!punctuation) throw std::runtime_error("OwnAddressInvalid");
        for (auto ch : temporary.substr(22)) if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f')))
            throw std::runtime_error("OwnTemporaryInvalid");
        // Orden: operacion -> NoJob helper -> desktop -> Job -> hoja SSH.
        auto helperGuard = helper->GuardOwn();
        auto desktopGuard = desktop->GuardOwn(desktop->InspectOwn().generation);
        auto jobGuard = job->GuardCurrent(job->InspectOwn().generation);
        if (desktop->child_ || job->member_) throw std::runtime_error("OwnSlotOccupied");
        owner->desktopGeneration_ = desktop->generation_; owner->jobGeneration_ = job->generation_;
        owner->desktopName_ = desktop->NamespaceOwn();
        const std::array<std::wstring, 4> paths{L"C:\\Windows\\System32\\OpenSSH\\ssh.exe",
            L"C:\\GateBouncerLab\\ssh\\lab_config", L"C:\\GateBouncerLab\\ssh\\lab_known_hosts",
            L"C:\\GateBouncerLab\\ssh\\lab_identity"};
        for (std::size_t i = 0; i < paths.size(); ++i) {
            owner->files_[i] = RetainedFile::OpenOwn(paths[i], false, i ? 4096 : 16777216);
            if (!owner->files_[i]->HashOwn(pins[i]) || owner->cancelled_.load()) throw std::runtime_error("OwnImagePinLost");
        }
        if (!owner->CurrentOwn() || !owner->CreateAssignResumeOwn()) owner->RevokeOwn();
    } catch (...) { owner->RevokeOwn(); }
    owner->active_ = false;
    return owner;
}
bool LinuxSshCreator::CreateAssignResumeOwn() {
    child_ = std::shared_ptr<OwnedSuspendedProcess>(new OwnedSuspendedProcess);
    { std::lock_guard<std::mutex> registry(OwnedSuspendedProcess::registryMutex_);
      OwnedSuspendedProcess::retained_.emplace(child_.get(), child_); }
    // Reservas fuertes ANTES de Create, incluso si el SDK retorna HANDLEs parciales.
    desktop_->child_ = child_; desktop_->childJob_ = job_; job_->member_ = child_;
    job_->acquiring_ = true;
    struct Acquisition { bool& value; ~Acquisition() { value = false; } } acquisition{job_->acquiring_};
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (input == INVALID_HANDLE_VALUE) return false;
    inherited_[0] = input;
    for (std::size_t i = 0; i < reads_.size(); ++i) {
        if (!CreatePipe(&reads_[i], &inherited_[i + 1], &security, 0) ||
            !SetHandleInformation(reads_[i], HANDLE_FLAG_INHERIT, 0)) return false;
    }
    Attributes attributes;
    if (!attributes.Init(inherited_.data(), sizeof(inherited_)) || !CurrentOwn()) return false;
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup); startup.lpAttributeList = attributes.list;
    startup.StartupInfo.lpDesktop = desktopName_.data(); startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inherited_[0]; startup.StartupInfo.hStdOutput = inherited_[1];
    startup.StartupInfo.hStdError = inherited_[2];
    std::wstring command = L"\"C:\\Windows\\System32\\OpenSSH\\ssh.exe\" -F C:\\GateBouncerLab\\ssh\\lab_config -T " + address_ + L" bootstrap";
    std::vector<wchar_t> argv(command.begin(), command.end()); argv.push_back(L'\0');
    std::wstring block = L"SystemRoot=C:\\Windows"; block.push_back(L'\0');
    block += L"TEMP=" + temporary_; block.push_back(L'\0'); block += L"TMP=" + temporary_;
    block.push_back(L'\0'); block += L"WINDIR=C:\\Windows"; block.push_back(L'\0'); block.push_back(L'\0');
    PROCESS_INFORMATION process{};
    { std::lock_guard<std::recursive_mutex> childLock(child_->mutex_);
      child_->acquiring_ = true;
      const BOOL created = CreateProcessW(L"C:\\Windows\\System32\\OpenSSH\\ssh.exe", argv.data(), nullptr, nullptr,
          TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
          block.data(), L"C:\\GateBouncerLab\\ssh", &startup.StartupInfo, &process);
      child_->process_ = process.hProcess; child_->thread_ = process.hThread; child_->pid_ = process.dwProcessId;
      child_->acquiring_ = false;
      FILETIME createdAt{}, exit{}, kernel{}, user{};
      if (!created || !child_->process_ || !child_->thread_ || !child_->pid_ ||
          GetProcessId(child_->process_) != child_->pid_ || !GetProcessTimes(child_->process_, &createdAt, &exit, &kernel, &user)) return false;
      child_->creation_ = (static_cast<std::uint64_t>(createdAt.dwHighDateTime) << 32) | createdAt.dwLowDateTime;
      if (!child_->creation_ || !CurrentOwn() || child_->cancelRequested_.load()) return false;
      child_->state_ = OwnedSuspendedProcess::State::Suspended;
    }
    childNoJob_ = GuestNoJobObserver::ObserveChildOwn(child_);
    if (childNoJob_->InspectOwn().state != GuestNoJobObserver::State::Observed || !CurrentOwn()) return false;
    // Retirar SOLO la observacion SSH: helper conserva su guard NoJob.
    if (childNoJob_->CloseOwn().state != GuestNoJobObserver::State::Closed) return false;
    childNoJob_.reset();
    std::lock_guard<std::recursive_mutex> childLock(child_->mutex_);
    if (child_->noJobObservers_ || !CurrentOwn() || !child_->ReadIdentityOwn()) return false;
    const BOOL assigned = AssignProcessToJobObject(job_->job_, child_->process_);
    job_->assigned_ = assigned != FALSE;
    if (!assigned || !CurrentOwn() || !job_->ReadMemberOwn() || !child_->ReadIdentityOwn() ||
        child_->cancelRequested_.load() || child_->revoked_) return false;
    resumeSubmitted_ = true;
    if (!CurrentOwn() || child_->cancelRequested_.load() || child_->revoked_) return false;
    const DWORD previous = ResumeThread(child_->thread_);
    if (previous != 1 || !CurrentOwn() || child_->cancelRequested_.load() || child_->revoked_) {
        child_->RevokeLocked(OwnedSuspendedProcess::Cause::ResumeUnconfirmed); return false;
    }
    child_->state_ = OwnedSuspendedProcess::State::Running; state_ = State::Running;
    for (auto& handle : inherited_) { if (!CloseHandle(handle)) return false; handle = nullptr; }
    return true;
}
LinuxSshCreator::Snapshot LinuxSshCreator::InspectOwn() {
    std::lock_guard<std::recursive_mutex> operation(mutex_);
    if (active_) return {State::Preparing, resumeSubmitted_, cancelled_.load()};
    if (state_ == State::Running) {
        try {
            auto helperGuard = helper_->GuardOwn();
            auto desktopGuard = desktop_->GuardOwn(desktopGeneration_);
            auto jobGuard = job_->GuardCurrent(jobGeneration_);
            if (!CurrentOwn() || !child_ || child_->InspectOwn().state != OwnedSuspendedProcess::State::Running)
                RevokeOwn();
        } catch (...) { RevokeOwn(); }
    }
    return ViewOwn();
}
LinuxSshCreator::Snapshot LinuxSshCreator::CancelOwn() {
    cancelled_.store(true);
    std::lock_guard<std::recursive_mutex> operation(mutex_); RevokeOwn();
    if (!active_ && job_) job_->CancelOwn();
    return ViewOwn();
}
LinuxSshCreator::Snapshot LinuxSshCreator::CloseOwn() {
    cancelled_.store(true);
    auto live = shared_from_this();
    std::lock_guard<std::recursive_mutex> operation(mutex_);
    if (state_ == State::Closed) return ViewOwn();
    RevokeOwn(); if (active_) return ViewOwn();
    if (childNoJob_) {
        if (childNoJob_->CloseOwn().state != GuestNoJobObserver::State::Closed) return ViewOwn();
        childNoJob_.reset();
    }
    if (desktop_) {
        std::lock_guard<std::recursive_mutex> desktopLock(desktop_->mutex_);
        if (!desktop_->ReleaseChildOwn()) return ViewOwn();
    }
    if (job_ && job_->CloseOwn().state != WindowsNativeOwnedLaunchContext::State::Closed) return ViewOwn();
    if (child_ && child_->CloseOwn().state != OwnedSuspendedProcess::State::Closed) return ViewOwn();
    for (auto& handle : inherited_) if (handle) { if (!CloseHandle(handle)) return ViewOwn(); handle = nullptr; }
    for (auto& handle : reads_) if (handle) { if (!CloseHandle(handle)) return ViewOwn(); handle = nullptr; }
    for (auto& file : files_) if (file) { if (!file->CloseOwn()) return ViewOwn(); file.reset(); }
    child_.reset(); state_ = State::Closed;
    { std::lock_guard<std::mutex> registry(registryMutex_); retained_.erase(this); }
    return ViewOwn();
}
}
