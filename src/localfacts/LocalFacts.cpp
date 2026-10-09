#include "WinFile.h"
#include <bcrypt.h>
#include <algorithm>
#include <cwctype>
#include <limits>

namespace gatebouncer::localfacts {
bool sameBinding(const Binding& a, const Binding& b) noexcept {
    return a.absolutePath == b.absolutePath && a.volume == b.volume && a.fileId == b.fileId
        && a.size == b.size && a.modified == b.modified && a.generation == b.generation;
}
namespace detail {
bool bindingFor(HANDLE file, const std::wstring& path, std::uint64_t generation,
                Binding& result, DWORD& error) {
    FILE_ID_INFO id{};
    FILE_STANDARD_INFO standard{};
    FILE_BASIC_INFO basic{};
    if (GetFileType(file) != FILE_TYPE_DISK
        || !GetFileInformationByHandleEx(file, FileIdInfo, &id, sizeof(id))
        || !GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard))
        || !GetFileInformationByHandleEx(file, FileBasicInfo, &basic, sizeof(basic))) {
        error = GetLastError(); return false;
    }
    if (standard.Directory || standard.DeletePending || standard.EndOfFile.QuadPart < 0
        || basic.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE
                                  | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)) {
        error = ERROR_INVALID_DATA; return false;
    }
    result.absolutePath = path;
    result.volume = id.VolumeSerialNumber;
    std::copy(std::begin(id.FileId.Identifier), std::end(id.FileId.Identifier), result.fileId.begin());
    result.size = static_cast<std::uint64_t>(standard.EndOfFile.QuadPart);
    result.modified = static_cast<std::uint64_t>(basic.LastWriteTime.QuadPart);
    result.generation = generation;
    return true;
}
static bool validPath(const std::wstring& p) {
    if (p.size() < 4 || p.size() > 240 || !iswalpha(p[0]) || p[1] != L':' || p[2] != L'\\') return false;
    std::size_t start = 3;
    for (std::size_t i = 3; i <= p.size(); ++i) {
        if (i < p.size() && (p[i] < 32 || p[i] == L':' || p[i] == L'/' || p[i] == L'"'
            || p[i] == L'*' || p[i] == L'?' || p[i] == L'<' || p[i] == L'>' || p[i] == L'|')) return false;
        if (i == p.size() || p[i] == L'\\') {
            if (i == start || p[i-1] == L'.' || p[i-1] == L' ') return false;
            const auto component = p.substr(start, i-start);
            if (component == L"." || component == L"..") return false;
            start = i + 1;
        }
    }
    return true;
}
State openLocal(const Request& request, OpenFile& result, DWORD& error) {
    if (!validPath(request.absolutePath)) return State::Rejected;
    const auto root = request.absolutePath.substr(0, 3);
    const auto drive = GetDriveTypeW(root.c_str());
    if (drive != DRIVE_FIXED && drive != DRIVE_RAMDISK) return State::Rejected;
    // Cada ancestro queda abierto sin SHARE_DELETE: impide reemplazo/rename durante la operación.
    for (std::size_t end = 2; end != std::wstring::npos;) {
        const auto path = request.absolutePath.substr(0, end == 2 ? 3 : end);
        Handle directory(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        if (!directory || !GetFileInformationByHandleEx(directory.value, FileAttributeTagInfo,
            &attributes, sizeof(attributes))) { error = GetLastError(); return State::Unavailable; }
        if (!(attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            || (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) return State::Rejected;
        result.ancestors.push_back(std::move(directory));
        end = request.absolutePath.find(L'\\', end + 1);
    }
    result.file = Handle(CreateFileW(request.absolutePath.c_str(), GENERIC_READ,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (!result.file) { error = GetLastError(); return State::Unavailable; }
    if (!bindingFor(result.file.value, request.absolutePath, request.generation, result.binding, error))
        return State::Rejected;
    // La identidad final resuelta debe continuar en la misma ruta DOS local.
    wchar_t finalPath[512]{};
    const DWORD count = GetFinalPathNameByHandleW(result.file.value, finalPath, 512,
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!count || count >= 512) { error = GetLastError(); return State::Unavailable; }
    const std::wstring expected = L"\\\\?\\" + request.absolutePath;
    if (_wcsicmp(finalPath, expected.c_str()) != 0) return State::Rejected;
    if (request.expected && !sameBinding(result.binding, *request.expected)) return State::Stale;
    return State::Complete;
}
State hashFile(HANDLE file, std::uint64_t size, const Limits& limits, const Cancellation& cancel,
               std::string& result, DWORD& error) {
    if (size > limits.maxBytes) return State::TooLarge;
    if (cancel.requested.load()) return State::Cancelled;
    if (limits.hashBudget.count() <= 0) return State::TimedOut;
    const auto end = std::chrono::steady_clock::now()
        + std::min(limits.hashBudget, std::chrono::milliseconds(30000));
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    struct Cleanup { BCRYPT_ALG_HANDLE& a; BCRYPT_HASH_HANDLE& h; ~Cleanup() {
        if (h) BCryptDestroyHash(h); if (a) BCryptCloseAlgorithmProvider(a, 0); } } cleanup{algorithm, hash};
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0
        || BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) < 0) return State::Unavailable;
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN)) { error = GetLastError(); return State::Unavailable; }
    std::array<unsigned char, 64 * 1024> buffer{};
    std::uint64_t total = 0;
    while (true) {
        if (cancel.requested.load()) return State::Cancelled;
        if (std::chrono::steady_clock::now() >= end) return State::TimedOut;
        DWORD read = 0;
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
            error = GetLastError(); return State::Unavailable;
        }
        if (!read) break;
        total += read;
        if (total > limits.maxBytes) return State::TooLarge;
        if (total > size) return State::Stale;
        if (BCryptHashData(hash, buffer.data(), read, 0) < 0) return State::Unavailable;
    }
    if (cancel.requested.load()) return State::Cancelled;
    if (std::chrono::steady_clock::now() >= end) return State::TimedOut;
    if (total != size) return State::Stale;
    std::array<unsigned char, 32> digest{};
    if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) return State::Unavailable;
    constexpr char hex[] = "0123456789abcdef";
    result.clear(); result.reserve(64);
    for (auto byte: digest) { result.push_back(hex[byte >> 4]); result.push_back(hex[byte & 15]); }
    return State::Complete;
}
} // namespace detail
Snapshot inspect(const Request& request, const Limits& limits, const Cancellation& cancel,
                 SignatureBackend& backend) {
    Snapshot result;
    if (cancel.requested.load()) { result.state = State::Cancelled; return result; }
    detail::OpenFile opened;
    DWORD error = 0;
    result.state = detail::openLocal(request, opened, error);
    result.nativeError = error;
    if (result.state != State::Complete) return result;
    result.binding = opened.binding;
    result.state = detail::hashFile(opened.file.value, opened.binding.size, limits, cancel, result.sha256, error);
    result.nativeError = error;
    if (result.state != State::Complete) return result;
    try { result.signature = backend.verify({reinterpret_cast<std::uintptr_t>(opened.file.value), opened.binding},
                                            limits.signatureBudget, cancel); }
    catch (...) { result.signature = {}; }
    Binding after;
    if (!detail::bindingFor(opened.file.value, request.absolutePath, request.generation, after, error)
        || !sameBinding(opened.binding, after)) {
        result.state = State::Stale; result.sha256.clear(); result.signature = {};
    } else if (cancel.requested.load()) {
        result.state = State::Cancelled; result.sha256.clear(); result.signature = {};
    }
    result.nativeError = error;
    return result;
}
} // namespace gatebouncer::localfacts
