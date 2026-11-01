#include "pipe_server.h"
#include <sddl.h>
#include <sstream>

namespace gbe {
namespace {

std::string utf8(const std::wstring &w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring wide(const std::string &s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), w.data(), n);
    return w;
}

// Un texto de error no puede romper el formato de líneas y tabuladores.
std::string field(const std::wstring &w) {
    std::string s = utf8(w);
    for (char &c : s)
        if (c == '\t' || c == '\r' || c == '\n') c = ' ';
    return s;
}

std::string err(const std::wstring &text) { return "ERR\t" + field(text) + "\nEND\n"; }

constexpr DWORD MaxRequest = 8192;
constexpr int MaxClients = 16;
constexpr DWORD IdleTimeoutMs = 60000;
constexpr DWORD WriteTimeoutMs = 10000;

} // namespace

PipeServer::PipeServer(FirewallCore &core, std::vector<std::wstring> trustedClients)
    : core_(core), trusted_(std::move(trustedClients)) {}

PipeServer::~PipeServer() { stop(); }

HANDLE PipeServer::createInstance(bool first) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd_, FALSE};
    return CreateNamedPipeW(PipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
                            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                            PIPE_UNLIMITED_INSTANCES, 64 * 1024, 4096, 0, &sa);
}

bool PipeServer::start(std::wstring &error) {
    // SYSTEM y administradores: todo. Usuarios interactivos: leer y escribir (0x12019b), sin
    // FILE_CREATE_PIPE_INSTANCE: no pueden abrir instancias propias con este nombre y hacerse pasar por el motor.
    // Los cambios de reglas además se filtran por proceso.
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)",
                                                              SDDL_REVISION_1, &sd_, nullptr)) {
        error = L"Pipe security: " + WfpEngine::errorText(GetLastError());
        return false;
    }
    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    // La primera instancia falla si otro proceso ya tiene el nombre; se usa como primera conexión aceptada.
    firstInstance_ = createInstance(true);
    if (firstInstance_ == INVALID_HANDLE_VALUE) {
        error = L"CreateNamedPipeW: " + WfpEngine::errorText(GetLastError());
        return false;
    }
    running_ = true;
    acceptThread_ = std::thread([this] { acceptLoop(); });
    return true;
}

void PipeServer::stop() {
    if (!running_.exchange(false)) return;
    SetEvent(stopEvent_);
    if (acceptThread_.joinable()) acceptThread_.join();
    while (clients_ > 0) Sleep(10);
    if (firstInstance_ != INVALID_HANDLE_VALUE) CloseHandle(firstInstance_);
    firstInstance_ = INVALID_HANDLE_VALUE;
    CloseHandle(stopEvent_);
    stopEvent_ = nullptr;
    if (sd_) LocalFree(sd_);
    sd_ = nullptr;
}

void PipeServer::acceptLoop() {
    while (running_) {
        HANDLE pipe = firstInstance_ != INVALID_HANDLE_VALUE ? firstInstance_ : createInstance(false);
        firstInstance_ = INVALID_HANDLE_VALUE;
        if (pipe == INVALID_HANDLE_VALUE) {
            WaitForSingleObject(stopEvent_, 1000);
            continue;
        }
        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        BOOL connected = ConnectNamedPipe(pipe, &ov);
        DWORD e = GetLastError();
        if (!connected && e == ERROR_IO_PENDING) {
            HANDLE waits[2] = {ov.hEvent, stopEvent_};
            if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0) {
                CancelIo(pipe);
                CloseHandle(ov.hEvent);
                CloseHandle(pipe);
                break;
            }
            DWORD ignored = 0;
            connected = GetOverlappedResult(pipe, &ov, &ignored, FALSE);
        } else if (!connected && e == ERROR_PIPE_CONNECTED) {
            connected = TRUE;
        }
        CloseHandle(ov.hEvent);
        // Tope de clientes: la ventana usa uno; más de MaxClients es abuso o error y se corta. La ventana de confianza
        // entra igual, para que nadie la deje afuera ocupando el cupo.
        if (!connected || (clients_ >= MaxClients && !clientMayChange(pipe))) {
            if (connected) DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            continue;
        }
        ++clients_;
        std::thread([this, pipe] {
            serve(pipe);
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            --clients_;
        }).detach();
    }
}

bool PipeServer::clientMayChange(HANDLE pipe) {
    ULONG pid = 0;
    if (!GetNamedPipeClientProcessId(pipe, &pid)) return false;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return false;
    bool ok = false;
    wchar_t image[MAX_PATH * 2] = {};
    DWORD size = DWORD(std::size(image));
    if (QueryFullProcessImageNameW(process, 0, image, &size)) {
        const auto k = FirewallCore::key(image);
        for (const auto &t : trusted_)
            if (FirewallCore::key(t) == k) ok = true;
    }
    if (!ok) {
        HANDLE token = nullptr;
        if (OpenProcessToken(process, TOKEN_QUERY, &token)) {
            TOKEN_ELEVATION elevation{};
            DWORD n = 0;
            ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &n) && elevation.TokenIsElevated;
            CloseHandle(token);
        }
    }
    CloseHandle(process);
    return ok;
}

void PipeServer::serve(HANDLE pipe) {
    const bool mayChange = clientMayChange(pipe);
    std::string buffer;
    char chunk[1024];
    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    while (running_) {
        const auto newline = buffer.find('\n');
        if (newline != std::string::npos) {
            std::string request = buffer.substr(0, newline);
            buffer.erase(0, newline + 1);
            if (!request.empty() && request.back() == '\r') request.pop_back();
            const std::string reply = handle(request, mayChange);
            DWORD written = 0;
            ResetEvent(ov.hEvent);
            if (!WriteFile(pipe, reply.data(), DWORD(reply.size()), &written, &ov)) {
                if (GetLastError() != ERROR_IO_PENDING) break;
                // Un cliente que no lee no retiene este hilo ni el cierre del motor.
                HANDLE waits[2] = {ov.hEvent, stopEvent_};
                if (WaitForMultipleObjects(2, waits, FALSE, WriteTimeoutMs) != WAIT_OBJECT_0 ||
                    !GetOverlappedResult(pipe, &ov, &written, FALSE)) {
                    CancelIo(pipe);
                    GetOverlappedResult(pipe, &ov, &written, TRUE);
                    break;
                }
            }
            continue;
        }
        if (buffer.size() > MaxRequest) break;
        DWORD read = 0;
        ResetEvent(ov.hEvent);
        if (!ReadFile(pipe, chunk, sizeof(chunk), &read, &ov)) {
            if (GetLastError() != ERROR_IO_PENDING) break;
            // La ventana pide cada segundo: un cliente callado por más de IdleTimeoutMs se desconecta.
            HANDLE waits[2] = {ov.hEvent, stopEvent_};
            if (WaitForMultipleObjects(2, waits, FALSE, IdleTimeoutMs) != WAIT_OBJECT_0) {
                CancelIo(pipe);
                // Esperar la cancelación: la lectura escribe en un búfer de esta función.
                GetOverlappedResult(pipe, &ov, &read, TRUE);
                break;
            }
            if (!GetOverlappedResult(pipe, &ov, &read, FALSE)) break;
        }
        if (read == 0) break;
        buffer.append(chunk, read);
    }
    CloseHandle(ov.hEvent);
}

std::string PipeServer::handle(const std::string &request, bool mayChange) {
    std::vector<std::string> f;
    {
        std::size_t start = 0;
        for (;;) {
            const auto tab = request.find('\t', start);
            f.push_back(request.substr(start, tab == std::string::npos ? std::string::npos : tab - start));
            if (tab == std::string::npos) break;
            start = tab + 1;
        }
    }
    const std::string &command = f[0];
    std::ostringstream out;
    if (command == "HELLO") {
        out << "OK\tGateBouncerEngine\t1\t" << (mayChange ? "control" : "view") << "\nEND\n";
        return out.str();
    }
    if (command == "STATUS") {
        const auto s = core_.status();
        out << "OK\n"
            << "mode\t" << (s.ask ? "ask" : "off") << "\n"
            << "scope\t" << (s.allApps ? "all" : "apps") << "\n"
            << "dynamic\t" << (s.dynamic ? 1 : 0) << "\n"
            << "started\t" << s.started << "\n"
            << "pending\t" << s.pending << "\n"
            << "rules\t" << s.rules << "\n"
            << "control\t" << (mayChange ? 1 : 0) << "\n"
            << "lastError\t" << field(s.lastError) << "\nEND\n";
        return out.str();
    }
    if (command == "PENDING") {
        out << "OK\n";
        for (const auto &p : core_.pending())
            out << p.first << "\t" << p.last << "\t" << p.attempts << "\t" << field(p.remoteAddress) << "\t"
                << p.remotePort << "\t" << int(p.protocol) << "\t" << field(p.path) << "\n";
        out << "END\n";
        return out.str();
    }
    if (command == "RULES") {
        out << "OK\n";
        for (const auto &r : core_.rules())
            out << (r.action == Action::Allow ? "allow" : "block") << "\t" << r.created << "\t" << r.lastBlock << "\t"
                << field(r.path) << "\n";
        out << "END\n";
        return out.str();
    }
    if (command == "ACTIVITY") {
        out << "OK\n";
        for (const auto &a : core_.activity())
            out << a.time << "\t" << field(a.kind) << "\t" << field(a.remoteAddress) << "\t" << a.remotePort << "\t"
                << int(a.protocol) << "\t" << field(a.path) << "\n";
        out << "END\n";
        return out.str();
    }
    const bool changes = command == "DECIDE" || command == "REMOVE" || command == "MODE";
    if (!changes) return err(L"Unknown command");
    if (!mayChange) return err(L"Only GateBouncer or an administrator can change rules");
    std::wstring error;
    bool ok = false;
    if (command == "DECIDE" && f.size() == 3 && (f[1] == "allow" || f[1] == "block"))
        ok = core_.decide(wide(f[2]), f[1] == "allow" ? Action::Allow : Action::Block, error);
    else if (command == "REMOVE" && f.size() == 2)
        ok = core_.removeRule(wide(f[1]), error);
    else if (command == "MODE" && f.size() == 2 && (f[1] == "ask" || f[1] == "off"))
        ok = core_.setAsk(f[1] == "ask", error);
    else
        error = L"Invalid arguments";
    return ok ? "OK\nEND\n" : err(error);
}

} // namespace gbe
