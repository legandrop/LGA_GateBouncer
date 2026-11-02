#include <winsock2.h>
#include <ws2tcpip.h>
#include "dns_names.h"
#include "wfp_engine.h"
#include <tdh.h>
#include <algorithm>
#include <cstring>
#include <cwctype>
#include <iterator>
#include <vector>

namespace gbe {
namespace {

// Microsoft-Windows-DNS-Client. El evento 3008 es «consulta terminada»: trae el nombre, el estado y las respuestas.
constexpr GUID DnsClientProvider = {0x1c95126e, 0x7eea, 0x49a9, {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}};
constexpr USHORT QueryCompleted = 3008;
// Microsoft-Windows-Kernel-Process, evento 1 (proceso iniciado): PID y ruta del ejecutable. Hace falta porque el evento
// de DNS llega hasta un segundo tarde y para entonces la app bloqueada suele haber terminado: abrir su PID ya no sirve.
constexpr GUID KernelProcessProvider = {0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};
constexpr USHORT ProcessStarted = 1;
constexpr ULONGLONG ProcessKeyword = 0x10; // WINEVENT_KEYWORD_PROCESS
constexpr std::size_t PerAddress = 8;
constexpr std::size_t AddressLimit = 20000;
constexpr ULONGLONG NameAgeMs = 2ULL * 3600 * 1000; // un nombre más viejo ya no describe esa conexión
constexpr ULONGLONG PruneEveryMs = 10ULL * 60 * 1000;
constexpr ULONGLONG ImageCacheMs = 60 * 1000;
constexpr ULONGLONG FromProcessStart = ~0ULL; // ruta tomada del arranque: vale mientras ese PID no se reutilice

std::vector<unsigned char> sessionProperties(const std::wstring &name) {
    std::vector<unsigned char> buffer(sizeof(EVENT_TRACE_PROPERTIES) + (name.size() + 1) * sizeof(wchar_t));
    auto *p = reinterpret_cast<EVENT_TRACE_PROPERTIES *>(buffer.data());
    p->Wnode.BufferSize = ULONG(buffer.size());
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 1; // reloj de alta resolución
    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    p->FlushTimer = 1; // entregar cada segundo aunque el búfer no se llene
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    return buffer;
}

std::wstring property(PEVENT_RECORD record, const wchar_t *name) {
    PROPERTY_DATA_DESCRIPTOR d{};
    d.PropertyName = reinterpret_cast<ULONGLONG>(name);
    d.ArrayIndex = ULONG_MAX;
    ULONG size = 0;
    if (TdhGetPropertySize(record, 0, nullptr, 1, &d, &size) != ERROR_SUCCESS || size < sizeof(wchar_t) ||
        size > 64 * 1024)
        return {};
    std::wstring text(size / sizeof(wchar_t), L'\0');
    if (TdhGetProperty(record, 0, nullptr, 1, &d, size, reinterpret_cast<PBYTE>(text.data())) != ERROR_SUCCESS)
        return {};
    text.resize(wcsnlen(text.c_str(), text.size()));
    return text;
}

bool propertyUInt32(PEVENT_RECORD record, const wchar_t *name, ULONG &value) {
    PROPERTY_DATA_DESCRIPTOR d{};
    d.PropertyName = reinterpret_cast<ULONGLONG>(name);
    d.ArrayIndex = ULONG_MAX;
    return TdhGetProperty(record, 0, nullptr, 1, &d, sizeof(value), reinterpret_cast<PBYTE>(&value)) == ERROR_SUCCESS;
}

std::wstring lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return wchar_t(std::towlower(c)); });
    return s;
}

std::wstring trim(const std::wstring &s) {
    const auto a = s.find_first_not_of(L" \t\r\n");
    if (a == std::wstring::npos) return {};
    return s.substr(a, s.find_last_not_of(L" \t\r\n") - a + 1);
}

} // namespace

DnsNames::~DnsNames() { stop(); }

std::wstring DnsNames::normalize(const std::wstring &address) {
    std::wstring a = trim(address);
    const auto zone = a.find(L'%');
    if (zone != std::wstring::npos) a.resize(zone);
    wchar_t text[INET6_ADDRSTRLEN] = {};
    IN_ADDR v4{};
    if (InetPtonW(AF_INET, a.c_str(), &v4) == 1)
        return InetNtopW(AF_INET, &v4, text, INET6_ADDRSTRLEN) ? text : std::wstring();
    IN6_ADDR v6{};
    if (InetPtonW(AF_INET6, a.c_str(), &v6) != 1) return {};
    if (IN6_IS_ADDR_V4MAPPED(&v6)) {
        std::memcpy(&v4, &v6.u.Byte[12], 4);
        return InetNtopW(AF_INET, &v4, text, INET6_ADDRSTRLEN) ? text : std::wstring();
    }
    return InetNtopW(AF_INET6, &v6, text, INET6_ADDRSTRLEN) ? text : std::wstring();
}

void DnsNames::stopOrphanTestSessions() {
    // Las sesiones de prueba llevan el PID del motor: una cuyo proceso ya no existe quedó de un motor cortado.
    constexpr ULONG Max = 64, NameChars = 1024;
    const ULONG each = sizeof(EVENT_TRACE_PROPERTIES) + 2 * NameChars * sizeof(wchar_t);
    std::vector<unsigned char> buffer(std::size_t(each) * Max);
    EVENT_TRACE_PROPERTIES *list[Max] = {};
    for (ULONG i = 0; i < Max; ++i) {
        auto *p = reinterpret_cast<EVENT_TRACE_PROPERTIES *>(buffer.data() + std::size_t(each) * i);
        p->Wnode.BufferSize = each;
        p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        p->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + NameChars * sizeof(wchar_t);
        list[i] = p;
    }
    ULONG count = 0;
    if (QueryAllTracesW(list, Max, &count) != ERROR_SUCCESS) return;
    const std::wstring prefix = TestSessionPrefix;
    for (ULONG i = 0; i < count && i < Max; ++i) {
        const auto *name = reinterpret_cast<const wchar_t *>(reinterpret_cast<const unsigned char *>(list[i]) +
                                                             list[i]->LoggerNameOffset);
        const std::wstring session(name, wcsnlen(name, NameChars));
        if (session.rfind(prefix, 0) != 0) continue;
        const DWORD pid = DWORD(_wtoi(session.c_str() + prefix.size()));
        if (pid == GetCurrentProcessId()) continue;
        if (HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, pid)) {
            const bool alive = WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
            CloseHandle(process);
            if (alive) continue;
        }
        auto props = sessionProperties(session);
        ControlTraceW(0, session.c_str(), reinterpret_cast<EVENT_TRACE_PROPERTIES *>(props.data()),
                      EVENT_TRACE_CONTROL_STOP);
    }
}

bool DnsNames::start(const std::wstring &sessionName, std::wstring &error) {
    stop();
    stopOrphanTestSessions();
    sessionName_ = sessionName;
    auto props = sessionProperties(sessionName_);
    ULONG r = StartTraceW(&session_, sessionName_.c_str(), reinterpret_cast<EVENT_TRACE_PROPERTIES *>(props.data()));
    if (r == ERROR_ALREADY_EXISTS) {
        // Quedó de un motor anterior que se cortó sin cerrarla: el servicio es uno solo y las pruebas llevan su PID.
        auto old = sessionProperties(sessionName_);
        ControlTraceW(0, sessionName_.c_str(), reinterpret_cast<EVENT_TRACE_PROPERTIES *>(old.data()),
                      EVENT_TRACE_CONTROL_STOP);
        props = sessionProperties(sessionName_);
        r = StartTraceW(&session_, sessionName_.c_str(), reinterpret_cast<EVENT_TRACE_PROPERTIES *>(props.data()));
    }
    if (r != ERROR_SUCCESS) {
        session_ = 0;
        error = L"StartTrace: " + std::to_wstring(r);
        return false;
    }
    r = EnableTraceEx2(session_, &DnsClientProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, ~0ULL, 0,
                       0, nullptr);
    if (r != ERROR_SUCCESS) {
        error = L"EnableTraceEx2: " + std::to_wstring(r);
        stop();
        return false;
    }
    // Sin los arranques de procesos igual hay nombres para las apps que siguen abiertas al llegar su consulta.
    processStarts_ = EnableTraceEx2(session_, &KernelProcessProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                    TRACE_LEVEL_INFORMATION, ProcessKeyword, 0, 0, nullptr) == ERROR_SUCCESS;
    EVENT_TRACE_LOGFILEW log{};
    log.LoggerName = sessionName_.data();
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = &DnsNames::onRecord;
    log.Context = this;
    trace_ = OpenTraceW(&log);
    if (trace_ == INVALID_PROCESSTRACE_HANDLE) {
        error = L"OpenTrace: " + std::to_wstring(GetLastError());
        stop();
        return false;
    }
    listening_ = true;
    thread_ = std::thread([this, handle = trace_]() mutable {
        ProcessTrace(&handle, 1, nullptr, nullptr);
        // Termina al cerrar el motor o si alguien detuvo la sesión: los contadores lo muestran.
        listening_ = false;
    });
    return true;
}

void DnsNames::stop() {
    if (session_) {
        auto props = sessionProperties(sessionName_);
        ControlTraceW(session_, nullptr, reinterpret_cast<EVENT_TRACE_PROPERTIES *>(props.data()),
                      EVENT_TRACE_CONTROL_STOP);
        session_ = 0;
    }
    if (trace_ != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(trace_);
        trace_ = INVALID_PROCESSTRACE_HANDLE;
    }
    if (thread_.joinable()) thread_.join();
}

void WINAPI DnsNames::onRecord(PEVENT_RECORD record) {
    if (record && record->UserContext) static_cast<DnsNames *>(record->UserContext)->handle(record);
}

std::wstring DnsNames::imageOf(DWORD pid) {
    if (pid <= 4) return {};
    const ULONGLONG tick = GetTickCount64();
    const auto cached = images_.find(pid);
    if (cached != images_.end() &&
        (cached->second.second == FromProcessStart || tick - cached->second.second < ImageCacheMs))
        return cached->second.first;
    std::wstring path;
    if (HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)) {
        wchar_t image[MAX_PATH * 2] = {};
        DWORD size = DWORD(std::size(image));
        if (QueryFullProcessImageNameW(process, 0, image, &size)) path = lower(image);
        CloseHandle(process);
    }
    if (images_.size() > 4096) images_.clear();
    images_[pid] = {path, tick};
    return path;
}

void DnsNames::handle(PEVENT_RECORD record) {
    ++events_;
    if (record->EventHeader.EventDescriptor.Id == ProcessStarted &&
        IsEqualGUID(record->EventHeader.ProviderId, KernelProcessProvider)) {
        // Un PID reutilizado queda pisado por el arranque nuevo.
        ULONG pid = 0;
        const std::wstring image = property(record, L"ImageName");
        if (propertyUInt32(record, L"ProcessID", pid) && pid > 4 && !image.empty()) {
            if (images_.size() > 8192) images_.clear();
            images_[pid] = {lower(WfpEngine::devicePathToDos(image)), FromProcessStart};
        }
        return;
    }
    if (record->EventHeader.EventDescriptor.Id != QueryCompleted ||
        !IsEqualGUID(record->EventHeader.ProviderId, DnsClientProvider))
        return;
    ++completed_;
    ULONG status = 1;
    if (!propertyUInt32(record, L"QueryStatus", status)) {
        ++unreadable_;
        return;
    }
    if (status != 0) return;
    std::wstring name = lower(trim(property(record, L"QueryName")));
    while (!name.empty() && name.back() == L'.') name.pop_back();
    if (name.empty() || name.size() > 253) {
        ++unreadable_;
        return;
    }
    // Respuestas: "type:  5 alias.example.net;::ffff:203.0.113.7;2001:db8::1;". Los alias se saltean.
    const std::wstring results = property(record, L"QueryResults");
    std::vector<std::wstring> addresses;
    std::size_t start = 0;
    while (start <= results.size()) {
        const auto end = results.find(L';', start);
        const auto token = trim(results.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start));
        if (!token.empty() && token.rfind(L"type:", 0) != 0) {
            const auto a = normalize(token);
            if (!a.empty()) addresses.push_back(a);
        }
        if (end == std::wstring::npos) break;
        start = end + 1;
    }
    if (addresses.empty()) return;
    const std::wstring app = imageOf(record->EventHeader.ProcessId);
    const ULONGLONG tick = GetTickCount64();
    std::lock_guard<std::mutex> lock(mutex_);
    if (byAddress_.size() > AddressLimit || tick - lastPrune_ > PruneEveryMs) {
        lastPrune_ = tick;
        for (auto it = byAddress_.begin(); it != byAddress_.end();) {
            auto &list = it->second;
            list.erase(std::remove_if(list.begin(), list.end(), [&](const Entry &e) { return tick - e.tick > NameAgeMs; }),
                       list.end());
            it = list.empty() ? byAddress_.erase(it) : std::next(it);
        }
        if (byAddress_.size() > AddressLimit) byAddress_.clear();
    }
    ++stored_;
    for (const auto &a : addresses) {
        auto &list = byAddress_[a];
        list.erase(std::remove_if(list.begin(), list.end(), [&](const Entry &e) { return e.app == app; }), list.end());
        list.push_front({name, app, tick});
        if (list.size() > PerAddress) list.pop_back();
    }
}

std::wstring DnsNames::stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::wstring(listening_ ? L"" : L"not listening; ") +
           (processStarts_ ? L"" : L"no process starts; ") + std::to_wstring(events_.load()) + L" events, " + std::to_wstring(completed_.load()) + L" completed, " +
           std::to_wstring(unreadable_.load()) + L" unreadable, " + std::to_wstring(stored_.load()) + L" stored, " +
           std::to_wstring(byAddress_.size()) + L" addresses";
}

std::wstring DnsNames::nameFor(const std::wstring &address, const std::wstring &appKey) {
    const auto a = normalize(address);
    if (a.empty()) return {};
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = byAddress_.find(a);
    if (appKey.empty() || it == byAddress_.end()) return {};
    // Sólo el nombre que resolvió esa misma app, y reciente. El de otra app para la misma dirección (una CDN compartida)
    // sería un dato ajeno en el aviso y en lo que se manda a la IA: mejor ningún nombre.
    const ULONGLONG tick = GetTickCount64();
    for (const auto &e : it->second)
        if (e.app == appKey && tick - e.tick <= NameAgeMs) return e.name;
    return {};
}

} // namespace gbe
