#pragma once
// Keys del usuario para las explicaciones con IA, una por proveedor (NVIDIA, Anthropic). Se guardan cifradas con DPAPI
// para esta cuenta de Windows, en una carpeta que sólo leen esta cuenta y SYSTEM. Nunca se devuelven a la interfaz, a
// un log ni a otro proceso: se entregan un momento a quien arma el pedido y el buffer se borra al volver.
// DPAPI no protege contra código que ya corre con esta cuenta ni contra un administrador: es la misma protección que
// tienen las contraseñas guardadas del navegador.
#include <QString>
#include <functional>
#include <string>

namespace Gate::Explain {

enum class Provider { Nvidia, Anthropic };

class KeyStore {
  public:
    // Forma de la key: «nvapi-» (NVIDIA) o «sk-ant-» (Anthropic) y caracteres imprimibles sin espacios.
    static bool plausible(Provider provider, const QString &key);
    static bool has(Provider provider);
    static bool save(Provider provider, const QString &key, QString &error);
    static bool clear(Provider provider, QString &error);
    static bool withKey(Provider provider, const std::function<void(const std::string &key)> &use, QString &error);
    static QString folder();
};

} // namespace Gate::Explain
