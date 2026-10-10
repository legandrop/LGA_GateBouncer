#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <vector>
namespace gb {
class BrokerAdmission;
class DesktopWorkerEntry;
class OwnHostLinuxOriginal;
// Credencial efímera: el helper guest conserva su admisión; el host usa su owner propio.
class OwnMemorySshCredential final : public std::enable_shared_from_this<OwnMemorySshCredential> {
public:
    enum class State { Reserved, MemoryOwned, SignatureSubmitted, ClosePending, Closed };
    enum class Cause { None, OriginalAdmissionLost, CryptoUnconfirmed, PipeUnconfirmed,
        LinuxBindingUnavailable, Cancelled, IoUnconfirmed, CloseUnconfirmed, ReplayRejected };
    struct Snapshot { State state; Cause cause; };
    Snapshot InspectOwn();
    Snapshot CancelOwn();
    Snapshot CloseOwn();
    ~OwnMemorySshCredential() noexcept = default;
    OwnMemorySshCredential(const OwnMemorySshCredential&) = delete;
    OwnMemorySshCredential& operator=(const OwnMemorySshCredential&) = delete;
private:
    friend class DesktopWorkerEntry;
    friend class OwnHostLinuxOriginal;
    OwnMemorySshCredential() = default;
    static std::shared_ptr<OwnMemorySshCredential> CreateOwn(const std::shared_ptr<BrokerAdmission>&);
#ifdef GB_ORIGINAL_HOST_ONLY
    static std::shared_ptr<OwnMemorySshCredential> CreateHostOwn(const std::shared_ptr<OwnHostLinuxOriginal>&);
#endif
    static std::shared_ptr<OwnMemorySshCredential> CreateCoreOwn(const std::shared_ptr<BrokerAdmission>&,const std::shared_ptr<OwnHostLinuxOriginal>&);
    bool ReplyHostOwn(const std::vector<BYTE>&);
    bool OriginalCurrentOwn() const;
    bool CurrentOwn();
    bool PublicBlobOwn(std::vector<BYTE>&);
    bool PollOwn();
    bool BeginConnectOwn();
    bool BeginReadOwn(DWORD);
    bool DrainIoOwn();
    bool CloseCryptoOwn();
    void RevokeOwn(Cause);
    Snapshot ViewOwn() const { return {state_, cause_}; }
    struct IoOwn;
    std::shared_ptr<IoOwn> io_;
    std::shared_ptr<BrokerAdmission> admission_;
    std::weak_ptr<OwnHostLinuxOriginal> host_;
    bool hostRoute_=false,signConsumed_=false;
    std::recursive_mutex mutex_;
    std::mutex signalMutex_;
    std::atomic<bool> cancelled_{false};
    DWORD thread_ = 0;
    State state_ = State::Reserved;
    Cause cause_ = Cause::None;
    bool active_ = false;
    BCRYPT_ALG_HANDLE provider_ = nullptr;
    BCRYPT_KEY_HANDLE key_ = nullptr;
    HANDLE stop_ = nullptr, pipe_ = nullptr;
    std::vector<BYTE> publicBlob_;
    static std::mutex registryMutex_;
    static std::map<OwnMemorySshCredential*,std::shared_ptr<OwnMemorySshCredential>> retained_;
    static std::vector<std::weak_ptr<BrokerAdmission>> attempted_;
};
}
