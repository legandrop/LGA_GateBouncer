#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <atomic>
#include <memory>
#include <mutex>
#include <vector>
#include <cstdint>
#include <string>
namespace gb {
class OwnMemorySshCredential;
class LinuxSshCreator;
int RunOwnHostLinuxOriginal(int,wchar_t**);
class OwnHostLinuxOriginal final:public std::enable_shared_from_this<OwnHostLinuxOriginal> {
public:
    enum class State {Reserved,MediaOwned,BootSubmitted,LinuxReady,SshRunning,ClosePending,Closed};
    struct Snapshot {State state;bool bootSubmitted;bool sshAuthenticated;};
    Snapshot InspectOwn();Snapshot CancelOwn();Snapshot CloseOwn();
    ~OwnHostLinuxOriginal() noexcept;
    OwnHostLinuxOriginal(const OwnHostLinuxOriginal&)=delete;
    OwnHostLinuxOriginal& operator=(const OwnHostLinuxOriginal&)=delete;
private:
    friend int RunOwnHostLinuxOriginal(int,wchar_t**);
    friend class OwnMemorySshCredential;
    friend class LinuxSshCreator;
    OwnHostLinuxOriginal();
    bool OriginalCurrentOwn()const;
    bool FreshLinuxOwn();
    bool AgentPeerOwn(HANDLE,DWORD,std::uint64_t)const;
    bool SignDataOwn(const std::vector<BYTE>&)const;
    std::wstring AgentNameOwn()const;
    bool PrepareOwn(int,wchar_t**);
    bool RunOwn();
    struct Impl;std::unique_ptr<Impl> own_;
    std::atomic<bool> cancelled_{false};std::recursive_mutex mutex_;
};
}
