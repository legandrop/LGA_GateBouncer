#pragma once
#include "policy.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>

namespace gb {
constexpr wchar_t ViewPipe[]=L"\\\\.\\pipe\\LGA.GateBouncer.View.v1";
constexpr wchar_t ControlPipe[]=L"\\\\.\\pipe\\LGA.GateBouncer.Control.v1";
constexpr DWORD PipeClientRights=FILE_READ_DATA|FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE;
constexpr wchar_t PipeClientRightsSddl[]=L"0x100083";
static_assert(FILE_READ_DATA==0x1&&FILE_WRITE_DATA==0x2&&FILE_READ_ATTRIBUTES==0x80&&SYNCHRONIZE==0x100000);
static_assert(PipeClientRights==0x00100083);
static_assert((PipeClientRights&(FILE_CREATE_PIPE_INSTANCE|READ_CONTROL|WRITE_DAC|WRITE_OWNER|
    FILE_WRITE_ATTRIBUTES|FILE_WRITE_EA|DELETE|GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE|GENERIC_ALL))==0);
// La mascara declarada no prueba GrantedAccess ni capacidad de crear otra instancia.
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
