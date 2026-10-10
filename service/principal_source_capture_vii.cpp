#include "principal_source_capture_vii.h"
#include "../controller/deployment_win.h"
#include "../src/data/netlimiterxmlprofile.h"
#include <winternl.h>
#include <algorithm>
#include <atomic>
#include <exception>
#include <mutex>
#include <optional>
#include <utility>

namespace gb::decisions {
namespace {
std::atomic<bool> physicalSource{false};
constexpr std::size_t RawLimit = 8 * 1024 * 1024;
bool sameIdentity(const BY_HANDLE_FILE_INFORMATION &a, const BY_HANDLE_FILE_INFORMATION &b) {
    return a.dwFileAttributes == b.dwFileAttributes && a.dwVolumeSerialNumber == b.dwVolumeSerialNumber &&
        a.nFileIndexHigh == b.nFileIndexHigh && a.nFileIndexLow == b.nFileIndexLow &&
        a.nFileSizeHigh == b.nFileSizeHigh && a.nFileSizeLow == b.nFileSizeLow &&
        a.ftLastWriteTime.dwHighDateTime == b.ftLastWriteTime.dwHighDateTime &&
        a.ftLastWriteTime.dwLowDateTime == b.ftLastWriteTime.dwLowDateTime;
}
bool sameDirectory(const BY_HANDLE_FILE_INFORMATION &a, const BY_HANDLE_FILE_INFORMATION &b) {
    return a.dwVolumeSerialNumber == b.dwVolumeSerialNumber && a.nFileIndexHigh == b.nFileIndexHigh &&
        a.nFileIndexLow == b.nFileIndexLow && (b.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        !(b.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
}
bool pathOf(HANDLE h, std::filesystem::path &out) {
    wchar_t buffer[32768]{};
    const auto n = GetFinalPathNameByHandleW(h, buffer, 32768, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!n || n >= 32768) return false;
    std::wstring text(buffer, n);
    if (text.rfind(L"\\\\?\\", 0) != 0) return false;
    out = std::filesystem::path(text.substr(4));
    return native::fixedPath(out);
}
bool samePath(const std::filesystem::path &a, const std::filesystem::path &b) {
    return CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) == CSTR_EQUAL;
}
native::Handle duplicate(HANDLE h) {
    HANDLE copy = nullptr;
    if (!h || h == INVALID_HANDLE_VALUE || !DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(),
        &copy, 0, FALSE, DUPLICATE_SAME_ACCESS)) return {};
    return native::Handle(copy);
}
native::Handle relative(HANDLE parent, const std::wstring &name, bool directory) {
    using Open = NTSTATUS (NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
        PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto open = module ? reinterpret_cast<Open>(GetProcAddress(module, "NtCreateFile")) : nullptr;
    if (!open || name.empty() || name.size() > 255 || name == L"." || name == L".." ||
        name.find_first_of(L"\\/:*") != std::wstring::npos) return {};
    UNICODE_STRING leaf{};
    leaf.Buffer = const_cast<PWSTR>(name.data());
    leaf.Length = static_cast<USHORT>(name.size() * sizeof(wchar_t)); leaf.MaximumLength = leaf.Length;
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes); attributes.RootDirectory = parent;
    attributes.ObjectName = &leaf; attributes.Attributes = 0x40; // OBJ_CASE_INSENSITIVE.
    IO_STATUS_BLOCK io{}; HANDLE value = nullptr;
    const auto access = FILE_READ_ATTRIBUTES | SYNCHRONIZE | (directory ? FILE_LIST_DIRECTORY : FILE_READ_DATA);
    // FILE_OPEN + SYNCHRONOUS_IO_NONALERT + OPEN_REPARSE_POINT; nunca seguir un reparse.
    const auto status = open(&value, access, &attributes, &io, nullptr, 0, FILE_SHARE_READ, 1,
        0x20 | 0x200000 | (directory ? 1 : 0x40), nullptr, 0);
    native::Handle result(value);
    return status >= 0 ? std::move(result) : native::Handle{};
}
void append(wire::Bytes &out, std::uint64_t n, unsigned count) {
    while (count--) { out.push_back(std::uint8_t(n)); n >>= 8; }
}
void string(wire::Bytes &out, const QByteArray &s) {
    append(out, std::uint64_t(s.size()), 4); out.insert(out.end(), s.begin(), s.end());
}
bool sourceId(QString text, wire::Id &out) {
    // UUID lexical, sin inventar IDs a partir de nombres fuente no representables.
    if (text.size() == 38 && text.front() == QLatin1Char('{') && text.back() == QLatin1Char('}'))
        text = text.mid(1, 36);
    if (text.size() == 36) {
        if (text[8] != QLatin1Char('-') || text[13] != QLatin1Char('-') ||
            text[18] != QLatin1Char('-') || text[23] != QLatin1Char('-')) return false;
        text.remove(23, 1); text.remove(18, 1); text.remove(13, 1); text.remove(8, 1);
    }
    return wire::parseId(text.toStdString(), out);
}
}
struct PrincipalSourceCapture::Data {
    std::shared_ptr<controller::Deployment> deployment;
    native::ProcessEvidence actor;
    native::TokenEvidence identity;
    native::Handle primary, stop, file;
    std::vector<native::Handle> directories;
    std::vector<std::filesystem::path> paths;
    std::vector<BY_HANDLE_FILE_INFORMATION> ids;
    std::filesystem::path path;
    BY_HANDLE_FILE_INFORMATION fileId{};
    std::uint64_t deadline = 0;
    wire::Bytes raw;
    wire::Digest digest{};
    // Sólo se crea Data después de admitir el módulo original; comparte un grafo.
    std::optional<Gate::Data::QNameEvidence> evidence;
    Gate::Data::QNameProfileView view;
    mutable std::mutex io;
    bool metadataCurrent() const {
        BY_HANDLE_FILE_INFORMATION actual{}; std::filesystem::path p;
        if (!file || paths.size() != directories.size() || paths.size() != ids.size() ||
            !GetFileInformationByHandle(file.value, &actual) || !sameIdentity(actual, fileId) ||
            !pathOf(file.value, p) || !samePath(p, path)) return false;
        for (std::size_t i = 0; i < paths.size(); ++i)
            if (!GetFileInformationByHandle(directories[i].value, &actual) || !sameDirectory(actual, ids[i]) ||
                !pathOf(directories[i].value, p) || !samePath(p, paths[i])) return false;
        return true;
    }
    bool bytesCurrent() const {
        LARGE_INTEGER start{};
        if (!SetFilePointerEx(file.value, start, nullptr, FILE_BEGIN)) return false;
        bool matches = false;
        const auto read = [](void *context, std::uint8_t *buffer, std::uint32_t cap, std::uint32_t &done) {
            DWORD count = 0; const bool okay = ReadFile(static_cast<HANDLE>(context), buffer, cap, &count, nullptr) != FALSE;
            done = count; return okay;
        };
        return native::compareStream(raw.data(), raw.size(), file.value, read, matches) && matches;
    }
};
PrincipalSourceCapture::PrincipalSourceCapture() = default;
PrincipalSourceCapture::~PrincipalSourceCapture() {
    data_.reset(); // Grafo, bytes y HANDLEs se cierran antes de devolver el slot.
    if (physical_) physicalSource.store(false);
}
bool PrincipalSourceCapture::actorCurrent() const noexcept {
    try {
        if (!data_ || !physical_) return false;
        const auto &d = *data_;
        if (!d.deployment || !d.actor.current() || !d.primary || !d.stop ||
            GetTickCount64() >= d.deadline || WaitForSingleObject(d.stop.value, 0) != WAIT_TIMEOUT) return false;
        HANDLE raw = nullptr; native::Handle primary;
        if (!OpenProcessToken(d.actor.process.value, TOKEN_QUERY, &raw)) return false;
        primary.reset(raw); native::TokenEvidence actual;
        return controller::compareObjectHandles(primary.value, d.primary.value) && native::tokenEvidence(primary.value, actual) &&
            actual.account == d.identity.account && actual.logon == d.identity.logon && actual.session == d.identity.session &&
            actual.integrity == d.identity.integrity && actual.administrator == d.identity.administrator &&
            actual.elevated == d.identity.elevated && actual.uiAccess == d.identity.uiAccess && d.actor.current();
    } catch (...) { return false; }
}
bool PrincipalSourceCapture::current() const noexcept {
    try {
        if (!actorCurrent() || !data_->deployment->serviceAdmittedCurrent() || !data_->deployment->serviceQtModule()) return false;
        std::unique_lock<std::mutex> lock(data_->io, std::try_to_lock);
        if (!lock.owns_lock()) return false;
        return data_->metadataCurrent() && data_->bytesCurrent() && data_->metadataCurrent() && actorCurrent() &&
            data_->deployment->serviceAdmittedCurrent();
    } catch (...) { return false; }
}
std::shared_ptr<PrincipalSourceCapture> PrincipalSourceCapture::acquire(const std::filesystem::path &path,
    const wire::Digest &digest,
    const native::ProcessEvidence &actor, const native::TokenEvidence &identity, HANDLE primary, HANDLE stop,
    const std::shared_ptr<controller::Deployment> &deployment, std::uint64_t deadline, wire::Error &reason) noexcept {
    reason = wire::Error::IdentityUnavailable;
    struct Failure {
        wire::Error &reason; std::uint64_t deadline;
        ~Failure() { if (reason == wire::Error::IdentityUnavailable && GetTickCount64() >= deadline) reason = wire::Error::Timeout; }
    } failure{reason, deadline};
    struct Slot { bool held = false; ~Slot() { if (held) physicalSource.store(false); } } slot;
    struct Revert {
        bool active = false;
        ~Revert() { if (active && !RevertToSelf()) { TerminateProcess(GetCurrentProcess(), ERROR_CANNOT_IMPERSONATE); std::terminate(); } }
    } revert;
    try {
        if (!native::fixedPath(path) || path.native().size() > 4096 ||
            path.native().find(L':', 2) != std::wstring::npos || path.native().find(L'/') != std::wstring::npos ||
            digest == wire::Digest{}) { reason = wire::Error::ScopeUnsupported; return {}; }
        if (!deployment || !deployment->serviceAdmittedCurrent() || !deployment->serviceQtModule() ||
            !actor.current() || GetTickCount64() >= deadline) return {};
        bool expected = false;
        if (!physicalSource.compare_exchange_strong(expected, true)) { reason = wire::Error::Capacity; return {}; }
        slot.held = true;
        auto capture = std::shared_ptr<PrincipalSourceCapture>(new PrincipalSourceCapture);
        capture->self_ = capture;
        capture->physical_ = true; slot.held = false;
        capture->data_ = std::make_unique<Data>(); auto &d = *capture->data_;
        d.deployment = deployment; d.path = path; d.digest = digest; d.deadline = deadline;
        d.actor.process = duplicate(actor.process.value); d.actor.pid = actor.pid; d.actor.created = actor.created; d.actor.image = actor.image;
        d.identity = identity; d.primary = duplicate(primary); d.stop = duplicate(stop);
        if (!capture->actorCurrent()) return {};
        HANDLE impersonated = nullptr; native::Handle token;
        if (!DuplicateTokenEx(d.primary.value, TOKEN_QUERY | TOKEN_IMPERSONATE, nullptr, SecurityImpersonation,
            TokenImpersonation, &impersonated)) return {};
        token.reset(impersonated);
        if (!SetThreadToken(nullptr, token.value)) return {};
        revert.active = true;
        auto root = path.root_path();
        native::Handle directory(CreateFileW(root.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!directory) return {};
        auto retainDirectory = [&](native::Handle h, const std::filesystem::path &expectedPath) {
            BY_HANDLE_FILE_INFORMATION id{}; std::filesystem::path actual;
            if (!h || !GetFileInformationByHandle(h.value, &id) || !(id.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
                (id.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || !pathOf(h.value, actual) || !samePath(actual, expectedPath)) return false;
            d.paths.push_back(actual); d.ids.push_back(id); d.directories.push_back(std::move(h)); return true;
        };
        if (!retainDirectory(std::move(directory), root)) return {};
        const auto rel = path.relative_path(); auto at = root;
        for (const auto &part : rel.parent_path()) {
            if (d.directories.size() >= 64 || !capture->actorCurrent()) return {};
            at /= part;
            if (!retainDirectory(relative(d.directories.back().value, part.native(), true), at)) return {};
        }
        d.file = relative(d.directories.back().value, rel.filename().native(), false);
        std::filesystem::path actual;
        if (!d.file || !GetFileInformationByHandle(d.file.value, &d.fileId) ||
            (d.fileId.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
            (!d.fileId.nFileIndexHigh && !d.fileId.nFileIndexLow) || !pathOf(d.file.value, actual) || !samePath(actual, path)) return {};
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(d.file.value, &size)) return {};
        if (size.QuadPart <= 0 || size.QuadPart > RawLimit) { reason = wire::Error::ScopeUnsupported; return {}; }
        d.raw.resize(static_cast<std::size_t>(size.QuadPart));
        for (std::size_t offset = 0; offset < d.raw.size();) {
            if (!capture->actorCurrent()) return {};
            DWORD done = 0; const auto take = DWORD(std::min<std::size_t>(65536, d.raw.size() - offset));
            if (!ReadFile(d.file.value, d.raw.data() + offset, take, &done, nullptr) || done != take) return {};
            offset += done;
        }
        if (native::digest(d.raw) != digest) return {};
        if (!RevertToSelf()) { TerminateProcess(GetCurrentProcess(), ERROR_CANNOT_IMPERSONATE); std::terminate(); }
        revert.active = false;
        if (!capture->current()) return {};
        reason = wire::Error::ScopeUnsupported;
        // Vista raw sin otra copia 8 MiB. Import conserva las cotas originales.
        const auto raw = QByteArray::fromRawData(reinterpret_cast<const char *>(d.raw.data()), qsizetype(d.raw.size()));
        auto imported = Gate::Data::importQNameProfile(raw);
        if (!imported.report.accepted || !imported.evidence || !imported.view.valid || !imported.view.profileKnown ||
            !imported.view.diagnosticsComplete) return {};
        reason = wire::Error::IdentityUnavailable;
        if (!capture->current()) return {};
        d.evidence = std::move(imported.evidence); d.view = std::move(imported.view);
        reason = wire::Error::Ok;
        return capture;
    } catch (...) { return {}; }
}
std::shared_ptr<const PrincipalSourceCapture::Selection> PrincipalSourceCapture::compareAgainst(const wire::Bytes &candidate,
    const wire::Bytes &app,
    const wire::Bytes &sid, const std::filesystem::path &image) const noexcept {
    try {
        if (!current() || candidate.empty() || candidate.size() > 256 || !wire::validUtf8(candidate) || app.empty() || sid.empty() ||
            !native::fixedPath(image)) return {};
        auto &d = *data_; std::unique_lock<std::mutex> lock(d.io, std::try_to_lock);
        if (!lock.owns_lock()) return {};
        if (!d.evidence) return {};
        const auto appBytes = QByteArray::fromRawData(reinterpret_cast<const char *>(app.data()), qsizetype(app.size()));
        const auto sidBytes = QByteArray::fromRawData(reinterpret_cast<const char *>(sid.data()), qsizetype(sid.size()));
        const auto imageText = QString::fromStdWString(image.native());
        const auto candidateText = QString::fromUtf8(reinterpret_cast<const char *>(candidate.data()), qsizetype(candidate.size()));
        if (candidateText.toUtf8() != QByteArray(reinterpret_cast<const char *>(candidate.data()), qsizetype(candidate.size()))) return {};
        QMap<int, QByteArray> canonical;
        for (const auto &f : d.view.filters) for (const auto &p : f.predicates) for (const auto &a : p.applications)
            if (a.pathExact && a.path.known() && a.path.value == imageText) canonical[a.node] = appBytes;
        const auto compared = Gate::Data::compareQNameConditionalScope(*d.evidence, candidateText, appBytes, sidBytes, imageText, canonical);
        if (!compared.representable || !compared.interferingCandidates.isEmpty() || compared.sourceOrdinal < 0) return {};
        auto selected = std::shared_ptr<Selection>(new Selection); auto &facts = *selected;
        facts.owner = self_.lock(); facts.appId = app; facts.accountSid = sid; facts.image = image;
        if (facts.owner.get() != this) return {};
        facts.direction = 1;
        facts.action = compared.candidate.action.value == Gate::Data::SourceFwAction::Allow ? 2 : 1;
        auto &remote = facts.condition; remote.kind = wire::iv::RemoteKind::Ipv4Range;
        remote.first = compared.range.first.value; remote.last = compared.range.last.value;
        remote.sourceWeight = std::uint32_t(compared.candidate.weight.value); remote.sourceOrdinal = std::uint32_t(compared.sourceOrdinal);
        if (!sourceId(compared.candidate.id.value, remote.sourceRule) ||
            !sourceId(compared.filterId.value, remote.sourceFilter) || !wire::iv::remoteConditionValid(remote)) return {};
        facts.candidate = candidate; facts.rawDigest = d.digest;
        wire::Bytes closure{'G','B','S','R','C','1','C','L'};
        closure.insert(closure.end(), d.digest.begin(), d.digest.end());
        string(closure, candidateText.toUtf8()); string(closure, appBytes); string(closure, sidBytes); string(closure, imageText.toUtf8());
        append(closure, remote.first, 4); append(closure, remote.last, 4);
        append(closure, remote.sourceWeight, 4); append(closure, remote.sourceOrdinal, 4);
        closure.insert(closure.end(), remote.sourceRule.begin(), remote.sourceRule.end());
        closure.insert(closure.end(), remote.sourceFilter.begin(), remote.sourceFilter.end());
        append(closure, facts.action, 1); append(closure, facts.direction, 1);
        append(closure, compared.closureCandidates.size(), 4);
        for (const auto &candidate : compared.closureCandidates) string(closure, candidate.toUtf8());
        facts.closureDigest = native::digest(closure);
        if (!d.metadataCurrent() || !d.bytesCurrent() || !d.metadataCurrent() || !actorCurrent() ||
            !d.deployment->serviceAdmittedCurrent()) return {};
        return selected;
    } catch (...) { return {}; }
}
bool PrincipalSourceCapture::ownsSelection(const std::shared_ptr<const Selection> &selection,
    const wire::Bytes &app, const wire::Bytes &sid, const std::filesystem::path &image) const noexcept {
    try {
        return selection && data_ && selection->owner.get() == this && selection->rawDigest == data_->digest &&
            selection->appId == app && selection->accountSid == sid && selection->image == image &&
            actorCurrent();
    } catch (...) { return false; }
}
}
