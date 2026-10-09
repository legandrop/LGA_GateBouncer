#pragma once
#include <windows.h>
namespace Gate::Assistance {
// Valores del SDK 10.0.26100 ausentes en MinGW 13.1; el OS debe aceptarlos.
constexpr DWORD FailedConnectionRetriesOption = 162;
constexpr DWORD DisableGlobalPoolingOption = 195;
struct FailedConnectionRetries { DWORD maxRetries; DWORD allowedConditions; };
static_assert(sizeof(FailedConnectionRetries) == 8);
}
