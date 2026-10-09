#pragma once
#ifndef GATE_ASSISTANCE_SYNTHETIC_VAULT_HARNESS
#error El vault sintetico solo se construye en el arnes separado.
#endif
#include <windows.h>
#include <vector>
namespace Gate::Assistance {
class SyntheticCredentialVault;
class SecretBuffer final {
public:
    SecretBuffer() = default;
    ~SecretBuffer() { clear(); }
    SecretBuffer(const SecretBuffer &) = delete;
    SecretBuffer &operator=(const SecretBuffer &) = delete;
    SecretBuffer(SecretBuffer &&other) noexcept : bytes_(std::move(other.bytes_)) {}
    SecretBuffer &operator=(SecretBuffer &&other) noexcept {
        if (this != &other) { clear(); bytes_ = std::move(other.bytes_); }
        return *this;
    }
private:
    friend class SyntheticCredentialVault;
    friend class SyntheticVaultProbe;
    explicit SecretBuffer(size_t size) : bytes_(size) {}
    void clear() { if (!bytes_.empty()) SecureZeroMemory(bytes_.data(), bytes_.size()); bytes_.clear(); }
    std::vector<unsigned char> bytes_;
};
} // namespace Gate::Assistance
