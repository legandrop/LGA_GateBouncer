#pragma once
#include <memory>

namespace gb::linuxlocal {
int RunLocalLinuxReadOnlyEntry(int argumentCount);

// Observación local: ninguna hoja acredita instalación, transporte ni autorización.
class LocalLinuxReaders final {
public:
    ~LocalLinuxReaders() noexcept;
    LocalLinuxReaders(const LocalLinuxReaders&) = delete;
    LocalLinuxReaders& operator=(const LocalLinuxReaders&) = delete;
private:
    friend int RunLocalLinuxReadOnlyEntry(int);
    enum class State { Reserved, ObservedLocalReaders, ClosePending, Closed };
    enum class Cause { None, ArgumentsRejected, ProcessUnconfirmed, FilesystemUnconfirmed,
        AccountUnconfirmed, PublicKeyUnconfirmed, NicUnconfirmed, ObservationChanged,
        Cancelled, CloseUnconfirmed };
    struct Snapshot { State state; Cause cause; unsigned ownedDescriptorCount; };
    struct Impl;
    LocalLinuxReaders();
    static std::unique_ptr<LocalLinuxReaders> OpenLocalOwn();
    Snapshot InspectLocalOwn();
    void CancelLocalOwn();
    Snapshot CloseLocalOwn();
    std::unique_ptr<Impl> own_;
};
}
