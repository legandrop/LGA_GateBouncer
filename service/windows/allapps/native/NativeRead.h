#pragma once
#include "../AllAppsMetadata.h"
#include <windows.h>
#include <fwpmu.h>

namespace gatebouncer::service::windows::allapps::native {
struct SdkWorkspace {
    std::array<std::uint8_t, ai::MaximumAppIdBytes> app{};
    std::array<std::uint8_t, ai::MaximumSidBytes> user{}, package{};
    NetEventView view;
};
static_assert(sizeof(SdkWorkspace) <= MaxRecordBytes);
// Memoria prestada del SDK; la salida sólo referencia el workspace propietario.
Reason copySdk(const FWPM_NET_EVENT3*, SdkWorkspace&, std::uint64_t receivedMonotonic) noexcept;
bool guardedRead(void* output, const void* input, std::size_t length) noexcept;
} // namespace gatebouncer::service::windows::allapps::native
