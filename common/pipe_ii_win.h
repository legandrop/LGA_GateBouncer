#pragma once
#include "pipe_rights_ii.h"
#include "token_ii_win.h"
#include <functional>

namespace gb::ipc::ii {
enum class Channel { View, Control, ReviewOpen };
struct Principals {
    wire::Bytes account, logon, service;
};
std::wstring descriptor(Channel channel, const Principals &principals);
bool exactDescriptor(HANDLE pipe, const std::wstring &expected);
native::Handle anchor(const std::wstring &name, Channel channel, const Principals &principals);
native::Handle instance(const std::wstring &name, Channel channel, const Principals &principals);
bool connect(HANDLE pipe, HANDLE stop, DWORD timeoutMs = 5000);
bool transfer(HANDLE pipe, bool writing, wire::Bytes &bytes, std::size_t count, HANDLE stop,
              DWORD timeoutMs = 5000);
bool receive(HANDLE pipe, wire::Frame &frame, HANDLE stop);
bool send(HANDLE pipe, const wire::Frame &frame, HANDLE stop);
// Siempre revierte antes de entregar DTO; token de impersonación nunca sale del canal.
bool clientEvidence(HANDLE pipe, native::TokenEvidence &token, native::ProcessEvidence &process);
// Control sólo token SYSTEM+serviceSID completo. No activa SeDebug ni eleva.
bool serverEvidence(HANDLE pipe, native::ProcessEvidence &process);
bool readableServerEvidence(HANDLE pipe, const std::filesystem::path &protectedImage,
                            native::ProcessEvidence &process);
bool ownClient(const native::ProcessEvidence &peer, const std::filesystem::path &protectedImage);
} // namespace gb::ipc::ii
