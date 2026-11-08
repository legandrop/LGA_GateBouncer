#include "folder_watch.h"
#include "folder_rule.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <algorithm>
#include <memory>

namespace gbe {
namespace {

// 64 KB por carpeta: un build escribe unos pocos archivos; si se llena, se pierde ese lote de avisos y nada más.
constexpr DWORD BufferWords = 16384;
// Una carpeta que no se pudo abrir (todavía no existe, se movió) se vuelve a intentar cada tanto.
constexpr DWORD RetryMs = 60000;

bool sameText(const std::wstring &a, const std::wstring &b) {
    return CompareStringOrdinal(a.c_str(), int(a.size()), b.c_str(), int(b.size()), TRUE) == CSTR_EQUAL;
}

struct Watch {
    std::wstring folder;
    HANDLE dir = INVALID_HANDLE_VALUE;
    OVERLAPPED ov{};
    std::vector<DWORD> buffer; // DWORD: FILE_NOTIFY_INFORMATION va alineado
    bool pending = false;

    bool issue() {
        ResetEvent(ov.hEvent);
        pending = ReadDirectoryChangesW(dir, buffer.data(), DWORD(buffer.size() * sizeof(DWORD)), TRUE,
                                        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                                        nullptr, &ov, nullptr) != FALSE;
        return pending;
    }

    bool open(const std::wstring &path) {
        // Como el resto de las reglas por carpeta: sólo un disco local fijo y la carpeta real. Los enlaces se miran sin
        // abrir nada (linkFreePath) y el handle se abre sin seguirlos: si la carpeta pasó a ser un enlace, no se vigila.
        if (!linkFreePath(path)) return false;
        dir = CreateFileW(path.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          nullptr, OPEN_EXISTING,
                          FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (dir == INVALID_HANDLE_VALUE) return false;
        FILE_BASIC_INFO basic{};
        if (!GetFileInformationByHandleEx(dir, FileBasicInfo, &basic, sizeof(basic)) ||
            (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || !(basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            return false;
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent) return false;
        folder = path;
        buffer.assign(BufferWords, 0);
        return issue();
    }

    void close() {
        if (pending) {
            CancelIoEx(dir, &ov);
            DWORD n = 0;
            GetOverlappedResult(dir, &ov, &n, TRUE); // el búfer sigue en uso hasta que termine la cancelación
            pending = false;
        }
        if (dir != INVALID_HANDLE_VALUE) CloseHandle(dir);
        dir = INVALID_HANDLE_VALUE;
        if (ov.hEvent) CloseHandle(ov.hEvent);
        ov.hEvent = nullptr;
    }

    ~Watch() { close(); }
};

} // namespace

bool isExeName(const std::wstring &name) {
    static const std::wstring ext = L".exe";
    return name.size() > ext.size() && sameText(name.substr(name.size() - ext.size()), ext);
}

FolderWatch::FolderWatch(Callback onExe) : onExe_(std::move(onExe)) {
    wake_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
}

FolderWatch::~FolderWatch() {
    stop();
    if (wake_) CloseHandle(wake_);
}

void FolderWatch::setFolders(std::vector<std::wstring> folders) {
    if (!wake_) return;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stop_) return;
        wanted_ = std::move(folders);
        changed_ = true;
        if (!thread_.joinable()) thread_ = std::thread([this] { loop(); });
    }
    SetEvent(wake_);
}

void FolderWatch::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stop_ = true;
    }
    if (wake_) SetEvent(wake_);
    if (thread_.joinable()) thread_.join();
}

void FolderWatch::loop() {
    std::vector<std::unique_ptr<Watch>> watches;
    std::vector<std::wstring> wanted;
    bool missing = false; // alguna carpeta pedida no se pudo abrir
    // Plazo absoluto del reintento: relativo a cada espera, con avisos seguidos de otra carpeta no vencería nunca.
    ULONGLONG retryAt = 0;
    bool reconcile = false;
    for (;;) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stop_) break;
            if (changed_) {
                wanted = wanted_;
                changed_ = false;
                reconcile = true;
            }
        }
        if (reconcile) {
            reconcile = false;
            // Las que ya no se piden se cierran; las nuevas se abren, hasta el máximo.
            watches.erase(std::remove_if(watches.begin(), watches.end(),
                                         [&](const std::unique_ptr<Watch> &w) {
                                             return std::none_of(wanted.begin(), wanted.end(), [&](const std::wstring &f) {
                                                 return sameText(f, w->folder);
                                             });
                                         }),
                          watches.end());
            missing = false;
            for (const auto &f : wanted) {
                if (std::any_of(watches.begin(), watches.end(),
                                [&](const std::unique_ptr<Watch> &w) { return sameText(w->folder, f); }))
                    continue;
                if (watches.size() >= MaxFolders) break;
                auto w = std::make_unique<Watch>();
                if (w->open(f)) {
                    watches.push_back(std::move(w));
                } else {
                    missing = true;
                }
            }
            watching_ = watches.size();
            retryAt = GetTickCount64() + RetryMs;
        }
        std::vector<HANDLE> handles{static_cast<HANDLE>(wake_)};
        for (const auto &w : watches) handles.push_back(w->ov.hEvent);
        const ULONGLONG t = GetTickCount64();
        if (missing && t >= retryAt) {
            reconcile = true;
            continue;
        }
        const DWORD r = WaitForMultipleObjects(DWORD(handles.size()), handles.data(), FALSE,
                                               missing ? DWORD(retryAt - t) : INFINITE);
        if (r == WAIT_TIMEOUT) {
            reconcile = true;
            continue;
        }
        if (r == WAIT_OBJECT_0) continue;
        if (r == WAIT_FAILED || r < WAIT_OBJECT_0 + 1 || r >= WAIT_OBJECT_0 + handles.size()) {
            Sleep(1000);
            continue;
        }
        Watch &w = *watches[r - WAIT_OBJECT_0 - 1];
        DWORD bytes = 0;
        const bool ok = GetOverlappedResult(w.dir, &w.ov, &bytes, FALSE) != FALSE;
        w.pending = false;
        // bytes == 0: se desbordó el búfer y se perdió ese lote; lo de ahí se cubre en su primer bloqueo.
        if (ok && bytes >= sizeof(FILE_NOTIFY_INFORMATION) - sizeof(WCHAR)) {
            const auto *base = reinterpret_cast<const BYTE *>(w.buffer.data());
            for (DWORD offset = 0;;) {
                const auto *info = reinterpret_cast<const FILE_NOTIFY_INFORMATION *>(base + offset);
                if (info->Action == FILE_ACTION_ADDED || info->Action == FILE_ACTION_MODIFIED ||
                    info->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                    const std::wstring name(info->FileName, info->FileNameLength / sizeof(WCHAR));
                    if (isExeName(name)) onExe_(w.folder + L"\\" + name);
                }
                if (!info->NextEntryOffset) break;
                offset += info->NextEntryOffset;
                if (offset >= bytes) break;
            }
        }
        // Si no se puede seguir vigilando (la carpeta se borró o se movió), se cierra y se reintenta más tarde.
        if (!ok || !w.issue()) {
            const auto it = std::find_if(watches.begin(), watches.end(),
                                         [&](const std::unique_ptr<Watch> &x) { return x.get() == &w; });
            watches.erase(it);
            watching_ = watches.size();
            if (!missing) retryAt = GetTickCount64() + RetryMs;
            missing = true;
        }
    }
    watches.clear();
    watching_ = 0;
}

} // namespace gbe
