#include "ProcessCatalog.h"
#include <QUuid>
#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#endif

namespace Gate::Data {
ProcessCatalog::ProcessCatalog() : epoch_(QUuid::createUuid().toString(QUuid::WithoutBraces)) {}
ProcessCatalogResult ProcessCatalog::refresh() {
    ProcessCatalogResult result;
    result.generation = ++generation_;
#ifdef Q_OS_WIN
    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        result.error = "Could not enumerate processes";
        return result;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        result.error = "Could not read the process catalog";
        CloseHandle(snapshot);
        return result;
    }
    do {
        ProcessObservation observation;
        observation.instance = {epoch_, entry.th32ProcessID, 0};
        observation.observedAtUtc = QDateTime::currentDateTimeUtc();
        // El snapshot aporta un PID candidato, no la identidad del ocupante abierto.
        const auto process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                         FALSE, entry.th32ProcessID);
        if (!process) {
            const auto error = GetLastError();
            observation.status = error == ERROR_ACCESS_DENIED ? FieldStatus::AccessDenied
                                : error == ERROR_INVALID_PARAMETER ? FieldStatus::Gone
                                                                   : FieldStatus::Unknown;
        } else {
            FILETIME creation{}, exit{}, kernel{}, user{};
            wchar_t image[32768]{};
            DWORD length = 32768;
            const bool fieldsKnown = GetProcessTimes(process, &creation, &exit, &kernel, &user) &&
                                     QueryFullProcessImageNameW(process, 0, image, &length);
            const auto fieldError = fieldsKnown ? ERROR_SUCCESS : GetLastError();
            const auto live = WaitForSingleObject(process, 0);
            if (fieldsKnown && live == WAIT_TIMEOUT) {
                observation.instance.creationFiletime = (quint64(creation.dwHighDateTime) << 32) |
                                                        creation.dwLowDateTime;
                observation.imagePath = QString::fromWCharArray(image, int(length));
                observation.name = observation.imagePath.section('\\', -1);
                observation.status = FieldStatus::Known;
            } else {
                observation.status = live == WAIT_OBJECT_0 ? FieldStatus::Gone
                                     : fieldError == ERROR_ACCESS_DENIED ? FieldStatus::AccessDenied
                                                                        : FieldStatus::Unknown;
            }
            CloseHandle(process);
        }
        result.processes.push_back(std::move(observation));
    } while (Process32NextW(snapshot, &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES)
        result.error = "Process catalog is incomplete due to an enumeration error";
    CloseHandle(snapshot);
#else
    result.error = "The Win32 process catalog is unavailable on this platform";
#endif
    return result;
}
} // namespace Gate::Data
