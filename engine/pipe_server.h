#pragma once
// Canal local entre el motor (servicio elevado) y la ventana (usuario común).
// Pipe con nombre en modo bytes; cada pedido es una línea UTF-8 con campos separados por tabulador y cada
// respuesta son líneas terminadas por "END". Leer lo puede cualquier usuario interactivo; cambiar reglas sólo
// la ventana instalada de GateBouncer o un proceso elevado.
#include "firewall_core.h"
#include <atomic>
#include <thread>

namespace gbe {

constexpr wchar_t PipeName[] = L"\\\\.\\pipe\\LGA.GateBouncer.Engine";

class PipeServer {
  public:
    // name: otro canal para las pruebas en consola con el servicio instalado corriendo al mismo tiempo.
    PipeServer(FirewallCore &core, std::vector<std::wstring> trustedClients, std::wstring name = PipeName);
    ~PipeServer();
    bool start(std::wstring &error);
    void stop();

  private:
    void acceptLoop();
    void serve(HANDLE pipe);
    std::string handle(const std::string &request, bool mayChange);
    bool clientMayChange(HANDLE pipe);
    HANDLE createInstance(bool first);

    FirewallCore &core_;
    std::vector<std::wstring> trusted_;
    std::wstring name_;
    std::atomic<bool> running_{false};
    std::atomic<int> clients_{0}; // hilos de clientes vivos: stop() los espera antes de liberar
    std::thread acceptThread_;
    HANDLE stopEvent_ = nullptr;
    HANDLE firstInstance_ = INVALID_HANDLE_VALUE; // creada con FIRST_PIPE_INSTANCE: nadie más tiene el nombre
    PSECURITY_DESCRIPTOR sd_ = nullptr;
};

} // namespace gbe
