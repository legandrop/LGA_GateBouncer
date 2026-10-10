#include "ProcessCatalog.h"
#include <QUuid>
#include "../data/activityhistory.h"
#include "NativeProcessReceipt.h"
#include "../../common/client_ii_win.h"
#include <mutex>
#include <atomic>
#include <map>
#include <array>
#include <set>
#include <algorithm>
#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <fwpmu.h>
#include "../../common/token_ii_win.h"
#endif

namespace Gate::Data {

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

namespace Gate::Data {
namespace {
struct OwnBudget {
    std::atomic<unsigned> slots{0};
    std::atomic<quint64> bytes{32768}; // Quarantine física y contenedores compartidos.
#ifdef Q_OS_WIN
    std::mutex closingMutex;
    std::array<std::pair<HANDLE,HANDLE>,64> closing{};
    void quarantine(HANDLE process, HANDLE token) {
        std::lock_guard<std::mutex> lock(closingMutex);
        for (auto &p : closing) if (!p.first && !p.second) { p = {process,token}; return; }
        std::terminate(); // Invariante física64: nunca perder un owner en vuelo.
    }
    ~OwnBudget() {
        for (const auto &p : closing) { if (p.first) CloseHandle(p.first); if (p.second) CloseHandle(p.second); }
    }
#endif
    bool charge(quint64 amount) {
        auto used = bytes.load();
        while (amount <= 2*1024*1024 - std::min<quint64>(used, 2*1024*1024))
            if (bytes.compare_exchange_weak(used, used + amount)) return true;
        return false;
    }
    bool reserve() {
        auto used = slots.load();
        while (used < 64) if (slots.compare_exchange_weak(used, used + 1)) return true;
        return false;
    }
};
struct OwnInstance {
    std::shared_ptr<OwnBudget> budget;
#ifdef Q_OS_WIN
    HANDLE process = nullptr, token = nullptr;
#endif
    ~OwnInstance() {
        bool closed = true;
#ifdef Q_OS_WIN
        HANDLE failedToken = token && !CloseHandle(token) ? token : nullptr;
        HANDLE failedProcess = process && !CloseHandle(process) ? process : nullptr;
        closed = !failedToken && !failedProcess;
        if (!closed && budget) budget->quarantine(failedProcess,failedToken);
#endif
        // Un fallo físico de cierre no recicla disponibilidad por un contador.
        if (closed && budget) --budget->slots;
    }
};
struct OwnEntry {
    ActivityEvent attempt;
    std::shared_ptr<OwnInstance> own;
    std::shared_ptr<OwnBudget> budget;
    quint64 charge = 0;
    ~OwnEntry() { own.reset(); if (budget && charge) budget->bytes.fetch_sub(charge); }
};
quint64 descriptorCharge(const ActivityEvent &e) {
    const auto &f = *e.native->process;
    quint64 bytes = 8192; // Contenedores, stamps, receipts y solicitud en tránsito.
    for (const auto *s : {&e.sourceId, &e.sourceEpoch, &e.sequence, &e.subjectId, &e.native->connection,
        &e.native->observed, &e.native->captureBinding, &f.image}) bytes += quint64(s->capacity())*2;
    for (const auto *b : {&f.appId, &f.accountSid, &f.logonSid}) bytes += quint64(b->capacity());
    return bytes;
}
#ifdef Q_OS_WIN
quint64 filetime(const FILETIME &t) { return (quint64(t.dwHighDateTime)<<32) | t.dwLowDateTime; }
bool ownCurrent(const OwnEntry &e, bool full) {
    if (!e.own || !e.own->process || !e.own->token) return false;
    const auto &f = *e.attempt.native->process;
    FILETIME created{}, exit{}, kernel{}, user{};
    if (GetProcessId(e.own->process) != f.pid || WaitForSingleObject(e.own->process,0) != WAIT_TIMEOUT ||
        !GetProcessTimes(e.own->process,&created,&exit,&kernel,&user) || filetime(created) != f.created) return false;
    if (!full) return true;
    gb::native::TokenEvidence held, fresh;
    if (!gb::native::tokenEvidence(e.own->token, held)) return false;
    HANDLE raw = nullptr;
    if (!OpenProcessToken(e.own->process,TOKEN_QUERY,&raw)) return false;
    gb::native::Handle currentToken(raw);
    if (!gb::native::tokenEvidence(raw,fresh)) return false;
    const auto bytes = [](const gb::wire::Bytes &b) { return QByteArray(reinterpret_cast<const char *>(b.data()),qsizetype(b.size())); };
    if (held.session != f.tokenSession || fresh.session != f.tokenSession ||
        bytes(held.account) != f.accountSid || bytes(held.logon) != f.logonSid ||
        bytes(fresh.account) != f.accountSid || bytes(fresh.logon) != f.logonSid) return false;
    std::array<wchar_t,32768> image{}; DWORD size = DWORD(image.size());
    if (!QueryFullProcessImageNameW(e.own->process,0,image.data(),&size) ||
        QString::fromWCharArray(image.data(),int(size)) != f.image) return false;
    FWP_BYTE_BLOB *app = nullptr;
    const auto ok = FwpmGetAppIdFromFileName0(image.data(),&app) == ERROR_SUCCESS;
    bool matches = ok && app && app->data && app->size <= 8192 &&
        QByteArray(reinterpret_cast<const char *>(app->data),app->size) == f.appId;
    if (app) FwpmFreeMemory0(reinterpret_cast<void **>(&app));
    return matches && ownCurrent(e,false);
}
#endif
}
struct NativeOwnBatch {
    struct Item {
        QString key; std::shared_ptr<OwnEntry> entry; bool before = false, after = false, valid = true;
        std::shared_ptr<const Gate::NativeProcessReceipt> firstRead, secondRead;
    };
    QVector<Item> items;
    mutable std::mutex mutex;
    NativeSourceBinding binding;
    std::shared_ptr<const gb::ipc::ii::ReadPeerLease> peer;
    QString connection;
    quint64 generation = 0;
};
struct ProcessCatalog::NativeBridge {
    mutable std::mutex mutex;
    std::shared_ptr<OwnBudget> budget = std::make_shared<OwnBudget>();
    std::map<QString,std::shared_ptr<OwnEntry>> entries, pending;
    std::set<QString> opening;
    NativeSourceBinding binding;
    std::shared_ptr<const gb::ipc::ii::ReadPeerLease> peer;
    QString connection, error;
    quint64 generation = 1;
};
ProcessCatalog::ProcessCatalog() : native_(std::make_unique<NativeBridge>()),
    epoch_(QUuid::createUuid().toString(QUuid::WithoutBraces)) {}
ProcessCatalog::~ProcessCatalog() = default;
bool ProcessCatalog::setNativeContext(const NativeSourceBinding &binding,
    std::shared_ptr<const gb::ipc::ii::ReadPeerLease> peer,const QString &connection) {
    if (!validNativeBinding(binding) || !peer || connection != QString::fromStdString(gb::wire::hex(peer->connection())) ||
        peer->checkLive() != gb::ipc::ii::ReadPeerState::Current) return false;
    std::map<QString,std::shared_ptr<OwnEntry>> retired, discarded;
    {
        std::lock_guard<std::mutex> lock(native_->mutex);
        if (!(native_->binding == binding) || native_->peer != peer || native_->connection != connection) {
            if (native_->generation == UINT64_MAX) return false;
            ++native_->generation; retired.swap(native_->entries); discarded.swap(native_->pending);
            native_->opening.clear();
        }
        native_->binding = binding; native_->peer = std::move(peer); native_->connection = connection;
    }
    return true;
}
void ProcessCatalog::revokeNative() {
    std::map<QString,std::shared_ptr<OwnEntry>> retired, discarded;
    {
        std::lock_guard<std::mutex> lock(native_->mutex);
        if (native_->generation != UINT64_MAX) ++native_->generation;
        native_->peer.reset(); native_->connection.clear();
        retired.swap(native_->entries); discarded.swap(native_->pending); native_->opening.clear();
    }
}
bool ProcessCatalog::queueNativeAttempt(const ActivityEvent &e) {
    if (!validNativeEvent(e) || e.kind != ActivityKind::Attempt || !e.native->process || e.native->externalPartial) return false;
    const auto key = nativeEventKey(e);
    std::lock_guard<std::mutex> lock(native_->mutex);
    if (!native_->peer || e.sourceId != nativeSourceId(native_->binding) ||
        e.sourceEpoch != nativeEpochKey(native_->binding) || e.native->connection != native_->connection) return false;
    for (const auto *map : {&native_->entries,&native_->pending}) {
        const auto found = map->find(key);
        if (found != map->end()) return found->second->attempt.native->process == e.native->process;
    }
    if (native_->opening.count(key)) return true;
    const auto charge = descriptorCharge(e);
    if (native_->entries.size()+native_->pending.size()+native_->opening.size() >= 64 || !native_->budget->charge(charge)) {
        native_->error = "Process bridge capacity reached; current attribution is incomplete."; return false;
    }
    bool transferred = false;
    try {
        auto entry = std::make_shared<OwnEntry>(); entry->budget = native_->budget; entry->charge = charge;
        transferred = true;
        entry->attempt = e; native_->pending.emplace(key,std::move(entry));
    } catch (...) { if (!transferred) native_->budget->bytes.fetch_sub(charge); return false; }
    return true;
}
bool ProcessCatalog::batchCurrent(const std::shared_ptr<NativeOwnBatch> &batch) const {
    if (!batch) return false;
    std::shared_ptr<const gb::ipc::ii::ReadPeerLease> peer;
    {
        std::lock_guard<std::mutex> lock(native_->mutex);
        if (native_->generation != batch->generation || !(native_->binding == batch->binding) ||
            native_->peer != batch->peer || native_->connection != batch->connection) return false;
        peer = native_->peer;
    }
    return peer && peer->checkLive() == gb::ipc::ii::ReadPeerState::Current;
}
std::shared_ptr<NativeOwnBatch> ProcessCatalog::acquireNative() {
    auto batch = std::make_shared<NativeOwnBatch>();
    std::map<QString,std::shared_ptr<OwnEntry>> pending;
    {
        std::lock_guard<std::mutex> lock(native_->mutex);
        batch->binding = native_->binding; batch->peer = native_->peer;
        batch->connection = native_->connection; batch->generation = native_->generation;
        pending.swap(native_->pending);
        for (const auto &p : pending) native_->opening.insert(p.first);
        for (const auto &p : native_->entries) batch->items.push_back({p.first,p.second});
    }
    for (const auto &p : pending) {
        bool acquired = false;
#ifdef Q_OS_WIN
        if (batchCurrent(batch) && native_->budget->reserve()) {
            std::shared_ptr<OwnInstance> own;
            try { own = std::make_shared<OwnInstance>(); }
            catch (...) { --native_->budget->slots; }
            if (own) {
                own->budget = native_->budget;
                const auto &f = *p.second->attempt.native->process;
                own->process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,f.pid);
                if (own->process) OpenProcessToken(own->process,TOKEN_QUERY,&own->token);
                p.second->own = std::move(own);
                acquired = ownCurrent(*p.second,true) && batchCurrent(batch);
            }
        }
#endif
        std::lock_guard<std::mutex> lock(native_->mutex);
        if (native_->generation == batch->generation) {
            native_->opening.erase(p.first);
            if (acquired && native_->peer == batch->peer) {
                native_->entries.emplace(p.first,p.second); batch->items.push_back({p.first,p.second});
            } else native_->error = "Original process custody is unavailable; dates remain unknown.";
        }
    }
    for (auto &item : batch->items) {
#ifdef Q_OS_WIN
        item.valid = batchCurrent(batch) && ownCurrent(*item.entry,true) && batchCurrent(batch);
#else
        item.valid = false;
#endif
    }
    return batch;
}
QVector<QString> ProcessCatalog::nativeSubjects(const std::shared_ptr<NativeOwnBatch> &batch) const {
    QVector<QString> keys;
    if (!batchCurrent(batch)) return keys;
    std::lock_guard<std::mutex> lock(batch->mutex);
    for (const auto &item : batch->items) if (item.valid) keys.push_back(item.key);
    return keys;
}
std::optional<ActivityEvent> ProcessCatalog::nativeAttempt(const std::shared_ptr<NativeOwnBatch> &batch,const QString &key) const {
    if (!batchCurrent(batch)) return {};
    std::lock_guard<std::mutex> lock(batch->mutex);
    for (const auto &item : batch->items) if (item.key == key && item.valid) return item.entry->attempt;
    return {};
}
bool ProcessCatalog::admitNativeRead(const std::shared_ptr<NativeOwnBatch> &batch,
    std::shared_ptr<const Gate::NativeProcessReceipt> receipt,int phase) {
    if (!receipt || !batchCurrent(batch) || (phase != 1 && phase != 2) ||
        !(receipt->binding()==batch->binding) || receipt->peer()!=batch->peer ||
        receipt->connection()!=batch->connection || receipt->correlation().isEmpty() || !receipt->sequence()) return false;
    std::lock_guard<std::mutex> lock(batch->mutex);
    for (auto &item : batch->items) if (item.key == receipt->descriptor() && item.valid) {
        if ((phase == 1 && item.before) || (phase == 2 && (!item.before || item.after))) return false;
        if (!(receipt->facts()==*item.entry->attempt.native->process) ||
            (phase==2 && (!item.firstRead || item.firstRead->correlation()==receipt->correlation() ||
                item.firstRead->sequence()>=receipt->sequence()))) return false;
        if (!receipt->accepted()) item.valid = false;
        else if (phase == 1) { item.before = true; item.firstRead=std::move(receipt); }
        else { item.after = true; item.secondRead=std::move(receipt); }
        return true;
    }
    return false;
}
bool ProcessCatalog::validateNative(const std::shared_ptr<NativeOwnBatch> &batch) {
    if (!batchCurrent(batch)) return false;
    QVector<NativeOwnBatch::Item> items;
    { std::lock_guard<std::mutex> lock(batch->mutex); items = batch->items; }
    for (const auto &copy : items) {
        bool valid = false;
#ifdef Q_OS_WIN
        valid = copy.valid && copy.before && ownCurrent(*copy.entry,true) && batchCurrent(batch);
#endif
        if (!valid) {
            { std::lock_guard<std::mutex> lock(batch->mutex);
              for (auto &item : batch->items) if (item.key == copy.key) item.valid = false; }
            std::shared_ptr<OwnEntry> retired;
            { std::lock_guard<std::mutex> lock(native_->mutex);
              if (native_->generation == batch->generation) {
                  auto found = native_->entries.find(copy.key);
                  if (found != native_->entries.end() && found->second == copy.entry) {
                      retired = std::move(found->second); native_->entries.erase(found);
                  }
              } }
        }
    }
    return batchCurrent(batch);
}
ProcessCatalogResult ProcessCatalog::finishNative(const std::shared_ptr<NativeOwnBatch> &batch) {
    auto result = refresh();
    if (!validateNative(batch)) return result;
    QVector<NativeOwnBatch::Item> items;
    { std::lock_guard<std::mutex> lock(batch->mutex); items = batch->items; }
    for (const auto &item : items) {
        bool current = false;
#ifdef Q_OS_WIN
        current = item.valid && item.before && item.after && ownCurrent(*item.entry,false);
#endif
        if (!current || !batchCurrent(batch)) continue;
        const auto &e = item.entry->attempt; const auto &f = *e.native->process;
        // Sólo deduplicación de presentación contra el snapshot; la historia usa subjectIds propios.
        ProcessObservation *row = nullptr;
        for (auto &p : result.processes) if (p.instance.pid == f.pid && p.instance.creationFiletime == f.created) { row = &p; break; }
        if (!row) { result.processes.push_back({}); row = &result.processes.last(); }
        row->instance = {nativeEpochKey(batch->binding),f.pid,f.created}; row->name = f.image.section('\\',-1);
        row->imagePath = f.image; row->status = FieldStatus::Known;
        row->identityEvidence = "SourceRetainedImageAndOwnInstance";
        row->sourceImage = f;
        row->observedAtUtc = QDateTime::currentDateTimeUtc(); row->historySubjects.push_back(e.subjectId);
        row->historyCauses.push_back(std::make_shared<const ActivityEvent>(e));
    }
    { std::lock_guard<std::mutex> lock(native_->mutex); if (!native_->error.isEmpty()) result.error = native_->error; }
    return result;
}
bool ProcessCatalog::hasNativeCandidates() const {
    std::lock_guard<std::mutex> lock(native_->mutex);
    return !native_->pending.empty() || !native_->entries.empty();
}
bool ProcessCatalog::publicationCurrent(const std::shared_ptr<NativeOwnBatch> &batch) const {
    if (!batchCurrent(batch)) return false;
    QVector<NativeOwnBatch::Item> items;
    { std::lock_guard<std::mutex> lock(batch->mutex); items=batch->items; }
    for (const auto &item : items) if (item.valid && item.before && item.after) {
#ifdef Q_OS_WIN
        if (!ownCurrent(*item.entry,false)) return false;
#else
        return false;
#endif
    }
    return batchCurrent(batch);
}
} // namespace Gate::Data
