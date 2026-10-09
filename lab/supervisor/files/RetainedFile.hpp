#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
namespace gb {
class LinuxSshCreator;
class P3OwnedConversionFileSeal;
class RetainedFile final : public std::enable_shared_from_this<RetainedFile> {
public:
    bool CloseOwn();
    ~RetainedFile() noexcept = default;
    RetainedFile(const RetainedFile&) = delete;
    RetainedFile& operator=(const RetainedFile&) = delete;
private:
    friend class LinuxSshCreator;
    friend class P3OwnedConversionFileSeal;
    RetainedFile() = default;
    static std::shared_ptr<RetainedFile> OpenOwn(const std::wstring&, bool, std::uint64_t);
    bool CurrentOwn() const;
    bool HashOwn(const std::array<BYTE, 32>&) const;
    HANDLE file_ = nullptr;
    std::vector<HANDLE> parents_;
    BY_HANDLE_FILE_INFORMATION identity_{};
    std::wstring path_;
    bool output_ = false, acquired_ = false;
    static std::mutex registryMutex_;
    static std::map<RetainedFile*, std::shared_ptr<RetainedFile>> retained_;
};
}
