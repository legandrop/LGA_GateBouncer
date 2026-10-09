#pragma once
#include "policy.h"
#define NOMINMAX
#include <windows.h>
#include <string>

namespace gb {
constexpr wchar_t ViewPipe[]=L"\\\\.\\pipe\\LGA.GateBouncer.View.v1";
constexpr wchar_t ControlPipe[]=L"\\\\.\\pipe\\LGA.GateBouncer.Control.v1";
bool elevatedAdministrator(HANDLE token);
bool serviceTokenIdentity(HANDLE token);
class PipeServer {
public:
    PipeServer(Coordinator& coordinator,Id epoch,Id boot,std::wstring viewSid,DWORD viewSession);
    void run(HANDLE stop);
private:
    void channel(bool control,HANDLE stop);
    bool authority(HANDLE pipe,bool control);
    Coordinator& coordinator_;Id epoch_,boot_;
    std::wstring viewSid_;DWORD viewSession_;
};
// Cliente sin Qt; verificacion del proceso SCM antes de confiar en bytes.
class PipeClient {
public:
    ~PipeClient();
    bool open(bool control);
    bool transact(Frame command,Frame& reply);
private:
    HANDLE pipe_=INVALID_HANDLE_VALUE;
    Id connection_{};std::uint64_t send_=1,receive_=1;
};
}
