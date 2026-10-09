#include "P3OwnedConversionFileSeal.hpp"
namespace gb {
std::mutex P3OwnedConversionFileSeal::registryMutex_;
std::map<P3OwnedConversionFileSeal*, std::shared_ptr<P3OwnedConversionFileSeal>> P3OwnedConversionFileSeal::retained_;
namespace {
constexpr DWORD flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY |
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_TIME;
constexpr SIZE_T memory = 128u * 1024 * 1024;
constexpr LONGLONG ticks = 100000000;
bool RunValid(const std::wstring& run) {
    if (run.size() != 36 || run == L"00000000-0000-0000-0000-000000000000") return false;
    for (std::size_t i = 0; i < run.size(); ++i) {
        auto ch = run[i];
        if ((i == 8 || i == 13 || i == 18 || i == 23) ? ch != L'-' :
            !((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f'))) return false;
    }
    return true;
}
}
std::shared_ptr<P3OwnedConversionFileSeal> P3OwnedConversionFileSeal::AcquireOwn(
    const std::wstring& run, std::uint32_t interfaceIndex, std::int64_t start, std::int64_t end) {
    auto owner = std::shared_ptr<P3OwnedConversionFileSeal>(new P3OwnedConversionFileSeal);
    { std::lock_guard<std::mutex> registry(registryMutex_); retained_.emplace(owner.get(), owner); }
    std::lock_guard<std::recursive_mutex> operation(owner->mutex_);
    owner->active_ = true;
    try {
        if (!RunValid(run) || !interfaceIndex || start < 116444736000000000LL || end <= start || end - start > 600000000)
            throw 1;
        owner->run_ = run; owner->interface_ = interfaceIndex; owner->start_ = start; owner->end_ = end;
        auto path = L"C:\\GateBouncerLab\\captures\\" + run;
        owner->input_ = RetainedFile::OpenOwn(path + L"\\capture.etl", false, 8388608);
        if (!owner->input_->CurrentOwn() || owner->cancelled_.load()) throw 1;
        owner->output_ = RetainedFile::OpenOwn(path + L"\\capture.pcapng", true, 8388608);
        if (!owner->output_->CurrentOwn() || owner->cancelled_.load()) throw 1;
        owner->cancel_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!owner->cancel_ || owner->cancelled_.load()) throw 1;
        owner->job_ = CreateJobObjectW(nullptr, nullptr);
        if (!owner->job_ || owner->cancelled_.load()) throw 1;
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = flags; limits.BasicLimitInformation.ActiveProcessLimit = 1;
        limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = ticks; limits.ProcessMemoryLimit = memory;
        if (!SetInformationJobObject(owner->job_, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
            !owner->LimitsOwn() || owner->cancelled_.load()) throw 1;
        owner->state_ = State::Sealed;
        if (!owner->CurrentOwn()) throw 1;
    } catch (...) { owner->cancelled_.store(true); owner->state_ = State::ClosePending; }
    owner->active_ = false;
    return owner;
}
bool P3OwnedConversionFileSeal::LimitsOwn() const {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    return job_ && QueryInformationJobObject(job_, JobObjectExtendedLimitInformation, &limits, sizeof(limits), nullptr) &&
        limits.BasicLimitInformation.LimitFlags == flags && limits.BasicLimitInformation.ActiveProcessLimit == 1 &&
        limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart == ticks && limits.ProcessMemoryLimit == memory;
}
bool P3OwnedConversionFileSeal::CurrentOwn() {
    return state_ == State::Sealed && !cancelled_.load() && input_ && output_ && input_->CurrentOwn() &&
        output_->CurrentOwn() && cancel_ && WaitForSingleObject(cancel_, 0) == WAIT_TIMEOUT && LimitsOwn() &&
        !cancelled_.load();
}
P3OwnedConversionFileSeal::Snapshot P3OwnedConversionFileSeal::InspectOwn() {
    std::lock_guard<std::recursive_mutex> operation(mutex_);
    if (active_) return {State::Acquiring, cancelled_.load()};
    if (state_ == State::Sealed && !CurrentOwn()) { cancelled_.store(true); state_ = State::ClosePending; }
    return {state_, cancelled_.load()};
}
P3OwnedConversionFileSeal::Snapshot P3OwnedConversionFileSeal::CancelOwn() {
    cancelled_.store(true);
    std::lock_guard<std::recursive_mutex> operation(mutex_);
    if (state_ != State::Closed) state_ = State::ClosePending;
    if (!active_ && cancel_) SetEvent(cancel_);
    return {state_, cancelled_.load()};
}
P3OwnedConversionFileSeal::Snapshot P3OwnedConversionFileSeal::CloseOwn() {
    cancelled_.store(true); auto live = shared_from_this();
    std::lock_guard<std::recursive_mutex> operation(mutex_);
    if (state_ == State::Closed) return {state_, true};
    state_ = State::ClosePending;
    if (active_) return {state_, true};
    if (cancel_ && !SetEvent(cancel_)) return {state_, true};
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
    // El worker futuro debe entregar salida propia observada; no cerrar con miembros desconocidos.
    if (job_ && (!QueryInformationJobObject(job_, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), nullptr) ||
        accounting.ActiveProcesses != 0)) return {state_, true};
    if (input_ && !input_->CloseOwn()) return {state_, true};
    if (output_ && !output_->CloseOwn()) return {state_, true};
    if (job_) { if (!CloseHandle(job_)) return {state_, true}; job_ = nullptr; }
    if (cancel_) { if (!CloseHandle(cancel_)) return {state_, true}; cancel_ = nullptr; }
    input_.reset(); output_.reset(); state_ = State::Closed;
    { std::lock_guard<std::mutex> registry(registryMutex_); retained_.erase(this); }
    return {state_, true};
}
}
