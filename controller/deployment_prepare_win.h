#pragma once
#include "deployment_win.h"
namespace gb::controller {
// Fuente original protegida y administrador elevado; no inicia el servicio ni el driver.
bool prepareProductDeployment(const std::filesystem::path &source,
    const std::filesystem::path &package, const std::filesystem::path &store,
    const std::wstring &accountSid);
// Sólo preparación administrativa explícita en un invitado previamente autorizado.
// No inicia procesos, servicio ni motor; no actualiza ni repara objetos existentes.
bool prepareGuestDeployment(const std::filesystem::path &source,
    const std::filesystem::path &package, const std::filesystem::path &store,
    const std::wstring &accountSid);
}
