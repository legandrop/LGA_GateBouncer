#include "pipe_ii_win.h"
#include <aclapi.h>
#include <array>
#include <memory>
#include <mutex>
#include <sddl.h>

namespace gb::ipc::ii {
namespace {
struct Transfer {
    OVERLAPPED ov{};
    native::Handle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    wire::Bytes bytes;
    Transfer() { ov.hEvent = event.value; }
};
std::mutex quarantineMutex;
std::array<std::shared_ptr<Transfer>, 8> quarantine;
bool slotsAvailable() {
    std::lock_guard<std::mutex> lock(quarantineMutex);
    for (auto &slot : quarantine)
        if (slot && WaitForSingleObject(slot->event.value, 0) == WAIT_OBJECT_0)
            slot.reset();
    for (auto &slot : quarantine)
        if (!slot)
            return true;
    return false;
}
bool reserve(const std::shared_ptr<Transfer> &t) {
    std::lock_guard<std::mutex> lock(quarantineMutex);
    for (auto &slot : quarantine)
        if (!slot) {
            slot = t;
            return true;
        }
    return false;
}
void release(const std::shared_ptr<Transfer> &t) {
    std::lock_guard<std::mutex> lock(quarantineMutex);
    for (auto &slot : quarantine)
        if (slot == t)
            slot.reset();
}
bool finish(HANDLE pipe, const std::shared_ptr<Transfer> &t, HANDLE stop, DWORD timeout,
            DWORD &done) {
    HANDLE waits[] = {t->event.value, stop};
    auto w = WaitForMultipleObjects(stop ? 2 : 1, waits, FALSE, timeout);
    if (w == WAIT_OBJECT_0) {
        bool ok = GetOverlappedResult(pipe, &t->ov, &done, FALSE) != FALSE;
        release(t);
        return ok;
    }
    CancelIoEx(pipe, &t->ov);
    if (WaitForSingleObject(t->event.value, 5000) == WAIT_OBJECT_0) {
        GetOverlappedResult(pipe, &t->ov, &done, FALSE);
        release(t);
        return false;
    }
    // Cota global de buffers en vuelo. Sin completion no se libera OVERLAPPED/buffer.
    return false;
}
bool sameAcl(PACL a, PACL b) {
    return a && b && IsValidAcl(a) && IsValidAcl(b) && a->AclSize == b->AclSize &&
           memcmp(a, b, a->AclSize) == 0;
}
native::Handle create(const std::wstring &name, Channel channel, const Principals &p, bool first) {
    if (!slotsAvailable())
        return {};
    auto text = descriptor(channel, p);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (text.empty() || !ConvertStringSecurityDescriptorToSecurityDescriptorW(
                            text.c_str(), SDDL_REVISION_1, &sd, nullptr))
        return {};
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
    native::Handle pipe(CreateNamedPipeW(
        name.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 2, 65536,
        65536, 5000, &sa));
    LocalFree(sd);
    if (!pipe || !exactDescriptor(pipe.value, text))
        return {};
    return pipe;
}
} // namespace
std::wstring descriptor(Channel c, const Principals &p) {
    auto u = native::sidString(p.account), l = native::sidString(p.logon),
         s = native::sidString(p.service);
    if (u.empty() || l.empty() || (c != Channel::ReviewOpen && s.empty()))
        return {};
    std::wstring text = c == Channel::ReviewOpen ? L"O:" + u + L"G:BA" : L"O:SYG:SY";
    text += L"D:P(D;;0x001f01ff;;;NU)(D;;0x001f01ff;;;AN)(A;;0x00020000;;;OW)(A;;0x001f01ff;;;SY)";
    text += c == Channel::ReviewOpen ? L"(A;;0x001f01ff;;;BA)" : L"(A;;0x001f01ff;;;" + s + L")";
    text += L"(A;;0x00120083;;;" + (c == Channel::Control ? std::wstring(L"BA") : l) + L")";
    text += c == Channel::Control ? L"S:P(ML;;NW;;;HI)" : L"S:P(ML;;NW;;;ME)";
    return text;
}
bool exactDescriptor(HANDLE pipe, const std::wstring &text) {
    PSECURITY_DESCRIPTOR expected = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(text.c_str(), SDDL_REVISION_1,
                                                              &expected, nullptr))
        return false;
    DWORD bytes = 0;
    constexpr DWORD info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                           DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
    GetKernelObjectSecurity(pipe, info, nullptr, 0, &bytes);
    wire::Bytes buffer(bytes);
    bool ok = bytes && bytes <= 65536 &&
              GetKernelObjectSecurity(pipe, info, buffer.data(), bytes, &bytes);
    if (ok) {
        PSID eo = nullptr, eg = nullptr, ao = nullptr, ag = nullptr;
        PACL ed = nullptr, es = nullptr, ad = nullptr, as = nullptr;
        BOOL def = FALSE, present = FALSE;
        SECURITY_DESCRIPTOR_CONTROL ec = 0, ac = 0;
        DWORD er = 0, ar = 0;
        ok = GetSecurityDescriptorOwner(expected, &eo, &def) &&
             GetSecurityDescriptorOwner(buffer.data(), &ao, &def) && EqualSid(eo, ao) &&
             GetSecurityDescriptorGroup(expected, &eg, &def) &&
             GetSecurityDescriptorGroup(buffer.data(), &ag, &def) && EqualSid(eg, ag) &&
             GetSecurityDescriptorDacl(expected, &present, &ed, &def) && present &&
             GetSecurityDescriptorDacl(buffer.data(), &present, &ad, &def) && present &&
             sameAcl(ed, ad) && GetSecurityDescriptorSacl(expected, &present, &es, &def) &&
             present && GetSecurityDescriptorSacl(buffer.data(), &present, &as, &def) && present &&
             sameAcl(es, as) && GetSecurityDescriptorControl(expected, &ec, &er) &&
             GetSecurityDescriptorControl(buffer.data(), &ac, &ar) &&
             (ac & (SE_DACL_PROTECTED | SE_SACL_PROTECTED)) ==
                 (SE_DACL_PROTECTED | SE_SACL_PROTECTED);
    }
    LocalFree(expected);
    return ok;
}
native::Handle anchor(const std::wstring &n, Channel c, const Principals &p) {
    return create(n, c, p, true);
}
native::Handle instance(const std::wstring &n, Channel c, const Principals &p) {
    return create(n, c, p, false);
}
bool connect(HANDLE pipe, HANDLE stop, DWORD timeout) {
    if (!slotsAvailable())
        return false;
    auto t = std::make_shared<Transfer>();
    if (!t->event || !reserve(t))
        return false;
    if (ConnectNamedPipe(pipe, &t->ov)) {
        release(t);
        return true;
    }
    auto e = GetLastError();
    if (e != ERROR_IO_PENDING) {
        release(t);
        return e == ERROR_PIPE_CONNECTED;
    }
    DWORD done = 0;
    return finish(pipe, t, stop, timeout, done);
}
bool transfer(HANDLE pipe, bool writing, wire::Bytes &b, std::size_t count, HANDLE stop,
              DWORD timeout) {
    if (count > wire::MaxFrameBytes || !slotsAvailable() || (writing && b.size() != count))
        return false;
    auto t = std::make_shared<Transfer>();
    if (!t->event)
        return false;
    t->bytes = writing ? b : wire::Bytes(count);
    auto start = GetTickCount64();
    std::size_t offset = 0;
    while (offset < count) {
        auto elapsed = GetTickCount64() - start;
        ResetEvent(t->event.value);
        t->ov = {};
        t->ov.hEvent = t->event.value;
        if (elapsed >= timeout || !reserve(t))
            return false;
        DWORD done = 0;
        bool immediate = (writing ? WriteFile(pipe, t->bytes.data() + offset, DWORD(count - offset),
                                              &done, &t->ov)
                                  : ReadFile(pipe, t->bytes.data() + offset, DWORD(count - offset),
                                             &done, &t->ov)) != FALSE;
        if (immediate)
            release(t);
        else if (GetLastError() != ERROR_IO_PENDING) {
            release(t);
            return false;
        } else if (!finish(pipe, t, stop, DWORD(timeout - elapsed), done))
            return false;
        if (!done || done > count - offset)
            return false;
        offset += done;
    }
    if (!writing)
        b = std::move(t->bytes);
    return true;
}
bool receive(HANDLE pipe, wire::Frame &f, HANDLE stop) {
    const auto started = GetTickCount64();
    constexpr DWORD budget = 5000;
    wire::Bytes b;
    if (!transfer(pipe, false, b, wire::HeaderBytes, stop))
        return false;
    if (b.size() != 64 || b[0] != 'G' || b[1] != 'B' || b[2] != 'C' || b[3] != '1')
        return false;
    std::size_t body = 0;
    for (unsigned i = 0; i < 4; ++i)
        body |= std::size_t(b[12 + i]) << (8 * i);
    if (body > wire::MaxFrameBytes - 64)
        return false;
    if (body) {
        wire::Bytes rest;
        const auto elapsed = GetTickCount64() - started;
        if (elapsed >= budget || !transfer(pipe, false, rest, body, stop, DWORD(budget - elapsed)))
            return false;
        b.insert(b.end(), rest.begin(), rest.end());
    }
    return GetTickCount64() - started < budget && wire::decode(b, f) == wire::Error::Ok;
}
bool send(HANDLE pipe, const wire::Frame &f, HANDLE stop) {
    wire::Bytes b;
    return wire::encode(f, b) == wire::Error::Ok && transfer(pipe, true, b, b.size(), stop);
}
bool clientEvidence(HANDLE pipe, native::TokenEvidence &token, native::ProcessEvidence &process) {
    DWORD before = 0, after = 0;
    native::Handle h;
    if (!GetNamedPipeClientProcessId(pipe, &before) || !before || !process.acquire(before) ||
        !ImpersonateNamedPipeClient(pipe))
        return false;
    HANDLE raw = nullptr;
    bool ok = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw) != FALSE;
    h.reset(raw);
    if (ok)
        ok = native::tokenEvidence(h.value, token);
    bool reverted = RevertToSelf() != FALSE;
    if (!reverted) {
        // No continuar un servidor privilegiado con impersonación no retirada.
        TerminateProcess(GetCurrentProcess(), ERROR_CANNOT_IMPERSONATE);
        std::terminate();
    }
    return reverted && ok && GetNamedPipeClientProcessId(pipe, &after) && before == after &&
           process.current();
}
bool serverEvidence(HANDLE pipe, native::ProcessEvidence &process) {
    DWORD before = 0, after = 0;
    if (!GetNamedPipeServerProcessId(pipe, &before) || !before || !process.acquire(before))
        return false;
    native::Handle token;
    HANDLE raw = nullptr;
    if (!OpenProcessToken(process.process.value, TOKEN_QUERY, &raw))
        return false;
    token.reset(raw);
    return native::systemServiceToken(token.value) && GetNamedPipeServerProcessId(pipe, &after) &&
           before == after && process.current();
}
bool ownClient(const native::ProcessEvidence &peer, const std::filesystem::path &image) {
    if (!peer.current() || peer.image != image || !native::fixedPath(image))
        return false;
    native::ProtectedDirectory directory(image.parent_path(), true);
    if (!directory.acquire())
        return false;
    native::Handle h(CreateFileW(image.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
                                 FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    return h && native::protectedObject(h.value, false, false, true) && peer.current();
}
bool readableServerEvidence(HANDLE pipe, const std::filesystem::path &image,
                            native::ProcessEvidence &process) {
    // Alternativa sólo View II, nunca fallback de Control ni del cliente I.
    DWORD pid = 0, after = 0;
    if (!GetNamedPipeServerProcessId(pipe, &pid) || !process.acquire(pid) ||
        !ownClient(process, image))
        return false;
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager)
        return false;
    SC_HANDLE service =
        OpenServiceW(manager, L"LGAGateBouncerLab", SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    bool ok = false;
    if (service) {
        SERVICE_STATUS_PROCESS status{};
        DWORD n = 0, needed = 0;
        QueryServiceConfigW(service, nullptr, 0, &needed);
        wire::Bytes b(needed <= 65536 ? needed : 0);
        if (needed && needed <= 65536 &&
            QueryServiceConfigW(service, reinterpret_cast<QUERY_SERVICE_CONFIGW *>(b.data()),
                                needed, &needed) &&
            QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE *>(&status),
                                 sizeof(status), &n)) {
            auto config = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(b.data());
            std::wstring command = config->lpBinaryPathName ? config->lpBinaryPathName : L"";
            ok = config->dwServiceType == SERVICE_WIN32_OWN_PROCESS && config->lpServiceStartName &&
                 _wcsicmp(config->lpServiceStartName, L"LocalSystem") == 0 &&
                 command == L"\"" + image.native() + L"\" --service --guest-wfp" &&
                 status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId == pid;
            SERVICE_STATUS_PROCESS repeated{};
            ok = ok && GetNamedPipeServerProcessId(pipe, &after) && after == pid &&
                 QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                      reinterpret_cast<BYTE *>(&repeated), sizeof(repeated), &n) &&
                 repeated.dwCurrentState == SERVICE_RUNNING && repeated.dwProcessId == pid;
        }
        CloseServiceHandle(service);
    }
    CloseServiceHandle(manager);
    if (ok) {
        HANDLE raw = nullptr;
        if (OpenProcessToken(process.process.value, TOKEN_QUERY, &raw)) {
            native::Handle token(raw);
            ok = native::systemServiceToken(token.value);
        } else if (GetLastError() != ERROR_ACCESS_DENIED)
            ok = false;
    }
    return ok && GetNamedPipeServerProcessId(pipe, &after) && after == pid && process.current();
}
} // namespace gb::ipc::ii
