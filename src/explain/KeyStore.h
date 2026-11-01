#pragma once
// Key de NVIDIA del usuario para las explicaciones con IA. Se guarda cifrada con DPAPI para esta cuenta de Windows,
// en una carpeta que sólo leen esta cuenta y SYSTEM. Nunca se devuelve a la interfaz, a un log ni a otro proceso: se
// entrega un momento a quien arma el pedido y el buffer se borra al volver.
// DPAPI no protege contra código que ya corre con esta cuenta ni contra un administrador: es la misma protección que
// tienen las contraseñas guardadas del navegador.
#include <QString>
#include <functional>
#include <string>

namespace Gate::Explain {

class KeyStore {
  public:
    // Forma de una Developer API key de NVIDIA: «nvapi-» y caracteres imprimibles sin espacios.
    static bool plausible(const QString &key);
    static bool has();
    static bool save(const QString &key, QString &error);
    static bool clear(QString &error);
    static bool withKey(const std::function<void(const std::string &key)> &use, QString &error);
    static QString folder();
};

} // namespace Gate::Explain
