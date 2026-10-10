#include "RetainedFile.hpp"
#include <bcrypt.h>
namespace gb {
std::mutex RetainedFile::registryMutex_;
std::map<RetainedFile*, std::shared_ptr<RetainedFile>> RetainedFile::retained_;
namespace {
bool SameFile(const BY_HANDLE_FILE_INFORMATION& a, const BY_HANDLE_FILE_INFORMATION& b, bool output) {
    return a.dwVolumeSerialNumber == b.dwVolumeSerialNumber && a.nFileIndexHigh == b.nFileIndexHigh &&
        a.nFileIndexLow == b.nFileIndexLow && b.nNumberOfLinks == 1 &&
        !(b.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) &&
        (output || (a.nFileSizeHigh == b.nFileSizeHigh && a.nFileSizeLow == b.nFileSizeLow &&
        a.ftLastWriteTime.dwHighDateTime == b.ftLastWriteTime.dwHighDateTime &&
        a.ftLastWriteTime.dwLowDateTime == b.ftLastWriteTime.dwLowDateTime));
}
bool PathMatches(HANDLE handle, const std::wstring& path) {
    std::vector<wchar_t> result(1024);
    const DWORD count = GetFinalPathNameByHandleW(handle, result.data(), static_cast<DWORD>(result.size()), FILE_NAME_NORMALIZED);
    return count && count < result.size() && std::wstring(result.data(), count) == L"\\\\?\\" + path;
}
}
std::shared_ptr<RetainedFile> RetainedFile::OpenOwn(const std::wstring& path, bool output, std::uint64_t cap) {
    auto owner = std::shared_ptr<RetainedFile>(new RetainedFile);
    { std::lock_guard<std::mutex> lock(registryMutex_); retained_.emplace(owner.get(), owner); }
    owner->path_ = path; owner->output_ = output;
    if (path.size() < 4 || path.size() > 512 || path[1] != L':' || path[2] != L'\\' ||
        path.find(L'\0') != std::wstring::npos || path.find(L"..") != std::wstring::npos ||
        path.find(L':', 2) != std::wstring::npos || path.find(L'/') != std::wstring::npos) return owner;
    std::wstring parent = path.substr(0, path.find_last_of(L'\\'));
    while (parent.size() > 2) {
        HANDLE directory = CreateFileW(parent.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (directory == INVALID_HANDLE_VALUE) return owner;
        owner->parents_.push_back(directory);
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(directory, &info) || !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || !PathMatches(directory, parent)) return owner;
        parent = parent.substr(0, parent.find_last_of(L'\\'));
    }
    HANDLE file = CreateFileW(path.c_str(), output ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ,
        output ? 0 : FILE_SHARE_READ, nullptr, output ? CREATE_NEW : OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) return owner;
    owner->file_ = file;
    if (GetFileType(file) != FILE_TYPE_DISK || !GetFileInformationByHandle(file, &owner->identity_) ||
        !SameFile(owner->identity_, owner->identity_, output) || !PathMatches(file, path)) return owner;
    const auto size = (static_cast<std::uint64_t>(owner->identity_.nFileSizeHigh) << 32) | owner->identity_.nFileSizeLow;
    if (output ? size != 0 : (size == 0 || size > cap)) return owner;
    owner->acquired_ = true;
    return owner;
}
bool RetainedFile::CurrentOwn() const {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!acquired_ || !file_ || !GetFileInformationByHandle(file_, &info) ||
        !SameFile(identity_, info, output_) || !PathMatches(file_, path_)) return false;
    std::wstring parent = path_.substr(0, path_.find_last_of(L'\\'));
    for (HANDLE directory : parents_) {
        if (!GetFileInformationByHandle(directory, &info) || !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || !PathMatches(directory, parent)) return false;
        parent = parent.substr(0, parent.find_last_of(L'\\'));
    }
    return true;
}
std::shared_ptr<RetainedFile> RetainedFile::RetainInputOwn(HANDLE source, const std::wstring& path, std::uint64_t cap) {
    // Abrir conserva los padres; el archivo adoptado es el HANDLE exacto del productor.
    auto owner = OpenOwn(path, false, cap);
    if (!owner->CurrentOwn() || !source || source == INVALID_HANDLE_VALUE) { owner->acquired_ = false; return owner; }
    // Slot fijo del owner ya retenido ANTES de Duplicate: no asignacion posterior que pueda lanzar.
    if (!DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &owner->partial_, GENERIC_READ, FALSE, 0)) {
        owner->acquired_ = false; return owner;
    }
    const HANDLE exact = owner->partial_;
    BY_HANDLE_FILE_INFORMATION actual{};
    if (!GetFileInformationByHandle(exact, &actual) || !SameFile(owner->identity_, actual, false) || !PathMatches(exact, path)) {
        owner->acquired_ = false; return owner;
    }
    if (!CloseHandle(owner->file_)) { owner->acquired_ = false; return owner; }
    owner->file_ = exact;
    owner->partial_ = nullptr;
    return owner;
}
bool RetainedFile::HashOwn(const std::array<BYTE, 32>& expected) const {
    if (!CurrentOwn() || output_) return false;
    BCRYPT_ALG_HANDLE algorithm = nullptr; BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD size = 0, returned = 0; bool valid = false;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return false;
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&size), sizeof(size), &returned, 0) == 0 &&
        returned == sizeof(size) && size && size <= 65536) {
        std::vector<BYTE> object(size);
        if (BCryptCreateHash(algorithm, &hash, object.data(), size, nullptr, 0, 0) == 0) {
            LARGE_INTEGER zero{}; valid = SetFilePointerEx(file_, zero, nullptr, FILE_BEGIN) != FALSE;
            std::array<BYTE, 32768> bytes{}; DWORD read = 0;
            std::uint64_t total = 0;
            const auto expectedSize = (static_cast<std::uint64_t>(identity_.nFileSizeHigh) << 32) | identity_.nFileSizeLow;
            while (valid) {
                if (!ReadFile(file_, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr)) { valid = false; break; }
                if (!read) break;
                total += read;
                if (total > expectedSize || BCryptHashData(hash, bytes.data(), read, 0) != 0) valid = false;
            }
            std::array<BYTE, 32> digest{};
            valid = valid && total == expectedSize && BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) == 0 &&
                digest == expected && CurrentOwn();
            if (BCryptDestroyHash(hash) != 0) valid = false;
            if (!SetFilePointerEx(file_, zero, nullptr, FILE_BEGIN)) valid = false;
        }
    }
    if (BCryptCloseAlgorithmProvider(algorithm, 0) != 0) valid = false;
    return valid;
}
bool RetainedFile::CloseOwn() {
    acquired_ = false;
    if (file_) { if (!CloseHandle(file_)) return false; file_ = nullptr; }
    if (partial_) { if (!CloseHandle(partial_)) return false; partial_ = nullptr; }
    for (auto& parent : parents_) {
        if (parent) { if (!CloseHandle(parent)) return false; parent = nullptr; }
    }
    auto live = shared_from_this();
    { std::lock_guard<std::mutex> lock(registryMutex_); retained_.erase(this); }
    return true;
}
}
