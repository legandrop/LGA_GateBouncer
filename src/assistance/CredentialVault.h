#pragma once
#include "SecretBuffer.h"
#include <QString>
#include <functional>
#include <memory>
namespace Gate::Assistance {
enum class VaultState { Absent, Present, Unavailable };
enum class VaultResult { Ok, InvalidRoot, AccessDenied, Corrupt, IoError };
enum class SyntheticCredential { Alpha, Beta };
enum class SyntheticCorruption { Magic, Schema, Length, Digest, Trailing };
class SyntheticVaultBroker;
class SyntheticVaultProbe;
class SyntheticCredentialVault final {
public:
    explicit SyntheticCredentialVault(QString explicitQaRoot);
    ~SyntheticCredentialVault();
    SyntheticCredentialVault(const SyntheticCredentialVault &) = delete;
    SyntheticCredentialVault &operator=(const SyntheticCredentialVault &) = delete;
    VaultResult prepare();
    VaultState status();
    VaultResult configure(SyntheticCredential fixture);
    VaultResult forget();
private:
    friend class SyntheticVaultBroker;
    friend class SyntheticVaultProbe;
    struct Impl;
    std::unique_ptr<Impl> impl_;
    VaultResult withSecret(const std::function<void(const unsigned char *, size_t)> &consumer);
    static SecretBuffer record(SyntheticCredential fixture);
    static VaultResult validate(SecretBuffer &record, const std::function<void(const unsigned char *, size_t)> &consumer);
};
class SyntheticVaultBroker final {
public:
    explicit SyntheticVaultBroker(SyntheticCredentialVault &vault) : vault_(vault) {}
    bool matches(SyntheticCredential expected);
private:
    SyntheticCredentialVault &vault_;
};
class SyntheticVaultProbe final {
public:
    static bool corruptPlaintextRejected(SyntheticCorruption corruption);
};
} // namespace Gate::Assistance
