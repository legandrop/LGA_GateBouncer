#include "WinFile.h"
#include "SignatureWire.h"
#include "../../controller/deployment_win.h"
#include <algorithm>
#include <cwchar>
#include <utility>

namespace gatebouncer::localfacts {
WindowsSignatureBackend::WindowsSignatureBackend(std::shared_ptr<gb::controller::Deployment> deployment)
    : deployment_(std::move(deployment)) {}
Signature WindowsSignatureBackend::verify(const SignatureInput& input, std::chrono::milliseconds budget,
                                         const Cancellation& cancel) {
    Signature result;
    if (cancel.requested.load()) { result.state = SignatureState::Cancelled; return result; }
    if (budget.count() <= 0) { result.state = SignatureState::TimedOut; return result; }
    // El inventario sale del GBD1 protegido y su dueño vive hasta el último readback.
    std::filesystem::path helperPath; gb::wire::Digest expectedHash{};
    if (!deployment_ || !deployment_->signatureHelperInventory(helperPath, expectedHash)) return result;
    std::string expectedHex; expectedHex.reserve(64);
    constexpr char hex[] = "0123456789abcdef";
    for (auto byte : expectedHash) { expectedHex.push_back(hex[byte >> 4]); expectedHex.push_back(hex[byte & 15]); }
    detail::OpenFile helper;
    DWORD error = 0;
    if (detail::openLocal({helperPath.native(), 0, {}}, helper, error) != State::Complete) return result;
    BY_HANDLE_FILE_INFORMATION helperIdentity{};
    if (!GetFileInformationByHandle(helper.file.value, &helperIdentity) ||
        !deployment_->matchesImage(helperPath, helperIdentity)) return result;
    Limits inventoryLimits; inventoryLimits.maxBytes = 16 * 1024 * 1024;
    inventoryLimits.hashBudget = std::chrono::milliseconds(1000);
    std::string hash;
    if (detail::hashFile(helper.file.value, helper.binding.size, inventoryLimits, cancel, hash, error) != State::Complete
        || hash != expectedHex || !deployment_->current()) return result;
    // Sólo el archivo y el mapping se heredan. No stdout, sockets, claves ni perfiles.
    HANDLE duplicate = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), reinterpret_cast<HANDLE>(input.fileHandle),
        GetCurrentProcess(), &duplicate, GENERIC_READ, TRUE, 0)) return result;
    detail::Handle subject(duplicate);
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    detail::Handle mapping(CreateFileMappingW(INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0,
                                              sizeof(detail::SignatureWire), nullptr));
    if (!mapping) return result;
    auto wire = static_cast<detail::SignatureWire*>(MapViewOfFile(mapping.value, FILE_MAP_ALL_ACCESS, 0, 0,
                                                                sizeof(detail::SignatureWire)));
    if (!wire) return result;
    struct Unmap { void* p; ~Unmap() { UnmapViewOfFile(p); } } unmap{wire};
    *wire = {};
    detail::Handle job(CreateJobObjectW(nullptr, nullptr));
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo{};
    jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    jobInfo.BasicLimitInformation.ActiveProcessLimit = 1;
    if (!job || !SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &jobInfo, sizeof(jobInfo)))
        return result;
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 2, 0, &bytes);
    std::vector<unsigned char> storage(bytes);
    auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if (!InitializeProcThreadAttributeList(attributes, 2, 0, &bytes)) return result;
    struct DeleteAttributes { LPPROC_THREAD_ATTRIBUTE_LIST p; ~DeleteAttributes() {
        DeleteProcThreadAttributeList(p); } } deleteAttributes{attributes};
    HANDLE inherited[] = {subject.value, mapping.value};
    // Imports estáticos sólo Kernel32 con CRT estático; otros módulos desde System32.
    DWORD64 mitigation = PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON;
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited,
        sizeof(inherited), nullptr, nullptr)
        || !UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigation,
        sizeof(mitigation), nullptr, nullptr)) return result;
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup); startup.lpAttributeList = attributes;
    std::wstring command = L"\"" + helperPath.native() + L"\" "
        + std::to_wstring(reinterpret_cast<std::uintptr_t>(subject.value)) + L" "
        + std::to_wstring(reinterpret_cast<std::uintptr_t>(mapping.value));
    wchar_t windows[512]{};
    const auto length = GetWindowsDirectoryW(windows, 512);
    if (!length || length >= 512) return result;
    std::wstring environment = L"SystemRoot=" + std::wstring(windows) + L'\0'
        + L"WINDIR=" + std::wstring(windows) + L'\0';
    environment.push_back(L'\0');
    PROCESS_INFORMATION process{};
    if (!deployment_->current() || !CreateProcessW(helperPath.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
        environment.data(), windows, &startup.StartupInfo, &process)) return result;
    detail::Handle child(process.hProcess), thread(process.hThread);
    // Sólo se termina el proceso creado por esta llamada y retenido por handle.
    if (!AssignProcessToJobObject(job.value, child.value)) {
        TerminateProcess(child.value, ERROR_CANCELLED); WaitForSingleObject(child.value, 1000); return result;
    }
    if (!deployment_->current()) {
        TerminateJobObject(job.value, ERROR_CANCELLED); WaitForSingleObject(child.value, 1000); return result;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::min(budget, std::chrono::milliseconds(30000));
    if (ResumeThread(thread.value) == static_cast<DWORD>(-1)) {
        TerminateJobObject(job.value, ERROR_CANCELLED); WaitForSingleObject(child.value, 1000); return result;
    }
    while (true) {
        if (cancel.requested.load() || std::chrono::steady_clock::now() >= deadline) {
            result.state = cancel.requested.load() ? SignatureState::Cancelled : SignatureState::TimedOut;
            TerminateJobObject(job.value, ERROR_CANCELLED);
            // No devolvemos datos del mapping hasta que el writer murió.
            WaitForSingleObject(child.value, 1000);
            return result;
        }
        const auto wait = WaitForSingleObject(child.value, 10);
        if (wait == WAIT_OBJECT_0) break;
        if (wait == WAIT_FAILED) { TerminateJobObject(job.value, ERROR_CANCELLED); return result; }
    }
    DWORD exitCode = 1;
    if (!deployment_->current() || !GetFileInformationByHandle(helper.file.value, &helperIdentity) ||
        !deployment_->matchesImage(helperPath, helperIdentity) ||
        !GetExitCodeProcess(child.value, &exitCode) || exitCode != 0 || wire->magic != detail::wireMagic
        || wire->state > 3 || wire->publisherLength > 255) return result;
    result.state = static_cast<SignatureState>(wire->state);
    result.nativeStatus = wire->nativeStatus;
    if (result.state == SignatureState::VerifiedOffline)
        result.publisherLocal.assign(wire->publisher, wire->publisherLength);
    return result;
}
} // namespace gatebouncer::localfacts
