#include "P3Transfer.hpp"
#include "P3OwnedConversionFileSeal.hpp"
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
namespace gb {
namespace {
struct P3Attributes {
    std::vector<BYTE> bytes;
    LPPROC_THREAD_ATTRIBUTE_LIST list = nullptr;
    ~P3Attributes() { if (list) DeleteProcThreadAttributeList(list); }
    bool Init(std::array<HANDLE, 5>& handles) {
        SIZE_T size = 0;
        if (InitializeProcThreadAttributeList(nullptr, 1, 0, &size) || GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
            !size || size > 65536) return false;
        bytes.resize(size);
        list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(bytes.data());
        if (!InitializeProcThreadAttributeList(list, 1, 0, &size)) { list = nullptr; return false; }
        return UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles.data(), sizeof(handles), nullptr, nullptr) != FALSE;
    }
};
bool Close(HANDLE& handle) { if (!handle) return true; if (!CloseHandle(handle)) return false; handle = nullptr; return true; }
}
class GuestConversionLauncher final : public std::enable_shared_from_this<GuestConversionLauncher> {
public:
    static int Convert(HANDLE input, const std::wstring& run, std::uint32_t index, std::int64_t start,
        std::int64_t end, const BYTE* pin, P3Current current, P3Result* result) {
        if (!pin || !current || !result || run.size() != 36) return 1;
        // No nesting heredado: rechazo antes del registry y de adquirir archivos/eventos/Jobs.
        if (!CreatorNoJobOwn()) return 1;
        auto owner = std::shared_ptr<GuestConversionLauncher>(new GuestConversionLauncher);
        { std::lock_guard<std::mutex> lock(registryMutex_);
          if (retained_.count(run)) return 2;
          owner->run_ = run; retained_.emplace(run, owner); }
        std::lock_guard<std::recursive_mutex> operation(owner->mutex_);
        owner->current_ = current;
        try {
            if (!owner->PermitOwn() || !CreatorNoJobOwn()) throw 1;
            owner->seal_ = P3OwnedConversionFileSeal::AcquireOwn(input, run, index, start, end);
            if (!owner->CurrentOwn()) throw 1;
            owner->image_ = RetainedFile::OpenOwn(L"C:\\GateBouncerLab\\bin\\conversion_worker.exe", false, 16777216);
            std::array<BYTE, 32> expected{}; std::memcpy(expected.data(), pin, expected.size());
            if (!owner->image_->HashOwn(expected) || !owner->CurrentOwn() || !owner->PrepareOwn() ||
                !owner->CreateOwn()) throw 1;
            const auto began = GetTickCount64();
            for (;;) {
                const DWORD wait = WaitForSingleObject(owner->process_, 50);
                if (wait == WAIT_OBJECT_0) { owner->exit_ = true; break; }
                if (wait != WAIT_TIMEOUT || GetTickCount64() - began >= 30000 || !owner->CurrentOwn()) throw 1;
            }
            DWORD exitCode = 0;
            if (!owner->IdentityOwn() || !GetExitCodeProcess(owner->process_, &exitCode) ||
                !owner->AccountingOwn(0) || !owner->CurrentOwn()) throw 1;
            P3Result received{};
            auto view = MapViewOfFile(owner->resultMap_, FILE_MAP_READ, 0, 0, sizeof(received));
            if (!view) throw 1;
            std::memcpy(&received, view, sizeof(received));
            if (!UnmapViewOfFile(view) || received.magic != 0x52504247 || received.bytes != sizeof(received) ||
                received.completed != 1 || received.converted > 1 || received.header > 1 || received.eventsKnown > 1 ||
                received.buffersKnown > 1 || received.emittedKnown > 1 || received.reserved > 8388608 ||
                received.emitted > received.reserved || received.records > 25000 ||
                received.packets > received.records || exitCode != (received.converted ? 0u : 2u)) throw 1;
            LARGE_INTEGER output{};
            if (!GetFileSizeEx(owner->seal_->output_->file_, &output) || output.QuadPart < 0 || output.QuadPart > 8388608 ||
                (received.emittedKnown && static_cast<std::uint64_t>(output.QuadPart) != received.emitted)) throw 1;
            if (received.converted && (!received.header || !received.eventsKnown || received.eventsLost ||
                !received.buffersKnown || received.buffersLost || !received.emittedKnown || !owner->CurrentOwn())) throw 1;
            *result = received; owner->converted_ = received.converted != 0;
        } catch (...) { owner->cancelled_ = true; }
        owner->current_ = nullptr;
        const bool converted = owner->converted_ && !owner->cancelled_;
        if (!owner->CloseOwn()) return 2;
        return converted ? 0 : 1;
    }
    static int Drain(const std::wstring& run) {
        std::shared_ptr<GuestConversionLauncher> owner;
        { std::lock_guard<std::mutex> lock(registryMutex_);
          auto found = retained_.find(run); if (found == retained_.end()) return 0; owner = found->second; }
        std::lock_guard<std::recursive_mutex> operation(owner->mutex_);
        owner->cancelled_ = true; owner->current_ = nullptr;
        return owner->CloseOwn() ? 0 : 2;
    }
private:
    static bool CreatorNoJobOwn() {
        BOOL member = TRUE;
        return IsProcessInJob(GetCurrentProcess(), nullptr, &member) && !member;
    }
    bool PermitOwn() { return current_ && current_() == 1; }
    bool CurrentOwn() {
        return !cancelled_ && CreatorNoJobOwn() && PermitOwn() && seal_ && seal_->CurrentOwn() &&
            (!image_ || image_->CurrentOwn()) && PermitOwn() && CreatorNoJobOwn();
    }
    bool IdentityOwn() const {
        FILETIME created{}, exited{}, kernel{}, user{};
        return process_ && pid_ && creation_ && GetProcessId(process_) == pid_ &&
            GetProcessTimes(process_, &created, &exited, &kernel, &user) &&
            ((static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime) == creation_;
    }
    bool AccountingOwn(DWORD expected) const {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
        return seal_ && seal_->job_ && QueryInformationJobObject(seal_->job_, JobObjectBasicAccountingInformation,
            &accounting, sizeof(accounting), nullptr) && accounting.ActiveProcesses == expected;
    }
    bool DuplicateOwn(HANDLE source, HANDLE& destination, DWORD access) {
        return CurrentOwn() && DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &destination,
            access, TRUE, 0) && CurrentOwn();
    }
    bool PrepareOwn() {
        descriptorMap_ = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(P3Descriptor), nullptr);
        if (!descriptorMap_ || !CurrentOwn()) return false;
        resultMap_ = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(P3Result), nullptr);
        if (!resultMap_ || !CurrentOwn() ||
            !DuplicateOwn(seal_->input_->file_, inherited_[0], GENERIC_READ) ||
            !DuplicateOwn(seal_->output_->file_, inherited_[1], GENERIC_READ | GENERIC_WRITE) ||
            !DuplicateOwn(seal_->cancel_, inherited_[2], SYNCHRONIZE) ||
            !DuplicateOwn(descriptorMap_, inherited_[3], FILE_MAP_READ) ||
            !DuplicateOwn(resultMap_, inherited_[4], FILE_MAP_WRITE)) return false;
        P3Descriptor descriptor{};
        descriptor.input = seal_->input_->identity_; descriptor.interfaceIndex = seal_->interface_;
        descriptor.start = seal_->start_; descriptor.end = seal_->end_;
        std::memcpy(descriptor.run, run_.c_str(), (run_.size() + 1) * sizeof(wchar_t));
        for (std::size_t i = 0; i < inherited_.size(); ++i)
            descriptor.handles[i] = reinterpret_cast<std::uintptr_t>(inherited_[i]);
        auto view = MapViewOfFile(descriptorMap_, FILE_MAP_WRITE, 0, 0, sizeof(descriptor));
        if (!view) return false;
        std::memcpy(view, &descriptor, sizeof(descriptor));
        return UnmapViewOfFile(view) && CurrentOwn();
    }
    bool CreateOwn() {
        P3Attributes attributes;
        if (!attributes.Init(inherited_) || !CurrentOwn() || !AccountingOwn(0)) return false;
        STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup); startup.lpAttributeList = attributes.list;
        std::wstring command = L"\"C:\\GateBouncerLab\\bin\\conversion_worker.exe\" " +
            std::to_wstring(reinterpret_cast<std::uintptr_t>(inherited_[3]));
        std::vector<wchar_t> argv(command.begin(), command.end()); argv.push_back(0);
        const wchar_t environment[] = L"SystemRoot=C:\\Windows\0WINDIR=C:\\Windows\0";
        PROCESS_INFORMATION child{};
        // Registry, seal y slots existen antes del intento incluso con salida parcial.
        const BOOL created = CreateProcessW(L"C:\\GateBouncerLab\\bin\\conversion_worker.exe", argv.data(), nullptr, nullptr,
            TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            const_cast<wchar_t*>(environment), L"C:\\GateBouncerLab\\bin", &startup.StartupInfo, &child);
        process_ = child.hProcess; thread_ = child.hThread; pid_ = child.dwProcessId;
        FILETIME at{}, exited{}, kernel{}, user{};
        if (process_ && GetProcessTimes(process_, &at, &exited, &kernel, &user))
            creation_ = (static_cast<std::uint64_t>(at.dwHighDateTime) << 32) | at.dwLowDateTime;
        if (!created || !IdentityOwn() || !thread_ || GetProcessIdOfThread(thread_) != pid_ || !CurrentOwn()) return false;
        BOOL inheritedJob = TRUE;
        // El mismo HANDLE/creation suspendido debe ser NoJob real antes de Assign.
        if (!IsProcessInJob(process_, nullptr, &inheritedJob) || inheritedJob ||
            !IdentityOwn() || !CurrentOwn()) return false;
        if (!AssignProcessToJobObject(seal_->job_, process_)) return false;
        assigned_ = true; BOOL member = FALSE;
        if (!CurrentOwn() || !IdentityOwn() || !IsProcessInJob(process_, seal_->job_, &member) || !member ||
            !P3LimitsCurrent(seal_->job_)) return false;
        // El parent ya no retiene clones heredables: sólo worker tiene sus cinco handles.
        for (auto& handle : inherited_) if (!Close(handle)) return false;
        if (!CurrentOwn() || !IdentityOwn() || !AccountingOwn(1)) return false;
        resumeSubmitted_ = true;
        return ResumeThread(thread_) == 1 && CurrentOwn();
    }
    bool CloseOwn() {
        if (seal_ && seal_->cancel_ && !SetEvent(seal_->cancel_)) return false;
        if (process_) {
            if (!IdentityOwn()) return false;
            const DWORD wait = WaitForSingleObject(process_, 0);
            if (wait == WAIT_TIMEOUT) {
                if (!TerminateProcess(process_, 2) || WaitForSingleObject(process_, 5000) != WAIT_OBJECT_0) return false;
            } else if (wait != WAIT_OBJECT_0) return false;
            exit_ = true;
        } else if (thread_) return false;
        if (seal_ && seal_->job_ && !AccountingOwn(0)) return false;
        if (!Close(thread_) || !Close(process_)) return false;
        for (auto& handle : inherited_) if (!Close(handle)) return false;
        if (!Close(descriptorMap_) || !Close(resultMap_)) return false;
        if (image_ && !image_->CloseOwn()) return false;
        if (seal_ && seal_->CloseOwn().state != P3OwnedConversionFileSeal::State::Closed) return false;
        image_.reset(); seal_.reset();
        auto live = shared_from_this();
        { std::lock_guard<std::mutex> lock(registryMutex_); retained_.erase(run_); }
        return true;
    }
    std::recursive_mutex mutex_;
    std::wstring run_;
    P3Current current_ = nullptr;
    std::shared_ptr<P3OwnedConversionFileSeal> seal_;
    std::shared_ptr<RetainedFile> image_;
    std::array<HANDLE, 5> inherited_{};
    HANDLE descriptorMap_ = nullptr, resultMap_ = nullptr, process_ = nullptr, thread_ = nullptr;
    DWORD pid_ = 0;
    std::uint64_t creation_ = 0;
    bool cancelled_ = false, converted_ = false, assigned_ = false, resumeSubmitted_ = false, exit_ = false;
    static std::mutex registryMutex_;
    static std::map<std::wstring, std::shared_ptr<GuestConversionLauncher>> retained_;
};
std::mutex GuestConversionLauncher::registryMutex_;
std::map<std::wstring, std::shared_ptr<GuestConversionLauncher>> GuestConversionLauncher::retained_;
}
extern "C" int __cdecl GbP3Convert(HANDLE input, const wchar_t* run, std::uint32_t index, std::int64_t start,
    std::int64_t end, const BYTE* pin, gb::P3Current current, gb::P3Result* result) noexcept {
    try { return run ? gb::GuestConversionLauncher::Convert(input, run, index, start, end, pin, current, result) : 1; }
    catch (...) { return 2; }
}
extern "C" int __cdecl GbP3Drain(const wchar_t* run) noexcept {
    try { return run ? gb::GuestConversionLauncher::Drain(run) : 2; } catch (...) { return 2; }
}
