#pragma once
#include <windows.h>
#include <QString>
#include <array>
#include <vector>
#include <utility>

namespace Gate::Assistance::Broker {
class Handle final {
public:
    Handle() : value(INVALID_HANDLE_VALUE) {}
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() { reset(); }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    Handle(Handle &&o) noexcept : value(std::exchange(o.value, INVALID_HANDLE_VALUE)) {}
    Handle &operator=(Handle &&o) noexcept { if (this != &o) { reset(); value = std::exchange(o.value, INVALID_HANDLE_VALUE); } return *this; }
    void reset(HANDLE h = INVALID_HANDLE_VALUE) { if (*this) CloseHandle(value); value = h; }
    explicit operator bool() const { return value && value != INVALID_HANDLE_VALUE; }
    HANDLE value;
};
class SensitiveBytes final {
public:
    SensitiveBytes() = default;
    explicit SensitiveBytes(size_t size) : data_(size) {}
    ~SensitiveBytes() { if (!data_.empty()) SecureZeroMemory(data_.data(), data_.size()); }
    SensitiveBytes(const SensitiveBytes &) = delete;
    SensitiveBytes &operator=(const SensitiveBytes &) = delete;
    SensitiveBytes(SensitiveBytes &&) noexcept = default;
    SensitiveBytes &operator=(SensitiveBytes &&o) noexcept { if (this != &o) { if (!data_.empty()) SecureZeroMemory(data_.data(), data_.size()); data_ = std::move(o.data_); } return *this; }
    unsigned char *data() { return data_.data(); }
    const unsigned char *data() const { return data_.data(); }
    size_t size() const { return data_.size(); }
private:
    std::vector<unsigned char> data_;
};
using Id = std::array<unsigned char, 16>;
struct TokenIdentity {
    std::vector<unsigned char> user, logon;
    DWORD session = 0;
    bool ordinary = false;
};
bool tokenIdentity(HANDLE process, TokenIdentity &out);
bool identityFromToken(HANDLE token, TokenIdentity &out);
bool sameIdentity(const TokenIdentity &a, const TokenIdentity &b);
bool processCreated(HANDLE process, quint64 &created);
bool randomId(Id &id);
bool nonzero(const Id &id);
bool exactFileSecurity(HANDLE file, const TokenIdentity &identity);
QString imagePath(HANDLE process);
}
