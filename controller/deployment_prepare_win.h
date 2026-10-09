#pragma once
#include "deployment_win.h"
namespace gb::controller {
// Sólo preparación administrativa explícita en un invitado previamente autorizado.
// No inicia procesos, servicio ni motor; no actualiza ni repara objetos existentes.
bool prepareGuestDeployment(const std::filesystem::path &source,
    const std::filesystem::path &package, const std::filesystem::path &store,
    const std::wstring &accountSid);
}
