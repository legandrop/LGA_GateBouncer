#pragma once
// Vigía de las carpetas con reglas por carpeta: avisa cada ejecutable (.exe) que se crea, se escribe o llega por un
// cambio de nombre dentro de esas carpetas y sus subcarpetas. Sin driver el motor no puede retener una conexión, así
// que un build nuevo perdería su primer intento: con este aviso el motor lo cubre apenas aparece, antes de que intente.
//
// Sólo es una pista para adelantarse: la decisión la toma el motor con la ruta final del archivo (placeOf), igual que
// con un bloqueo. Sólo se abren carpetas con letra de unidad de un disco local fijo que no son un enlace. Si se pierde
// un aviso (demasiados cambios juntos), el archivo se cubre en su primer bloqueo, como antes.
#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace gbe {

class FolderWatch {
  public:
    using Callback = std::function<void(const std::wstring &path)>;
    // WaitForMultipleObjects espera hasta 64 objetos: uno es el de despertar.
    static constexpr std::size_t MaxFolders = 60;

    // onExe se llama desde el hilo del vigía, con la ruta completa del .exe; puede repetirse para el mismo archivo.
    explicit FolderWatch(Callback onExe);
    ~FolderWatch();
    FolderWatch(const FolderWatch &) = delete;
    FolderWatch &operator=(const FolderWatch &) = delete;

    // Las carpetas a vigilar (rutas DOS finales), en lugar de las anteriores. La primera vez arranca el hilo.
    void setFolders(std::vector<std::wstring> folders);
    void stop();
    // Cuántas carpetas se están vigilando de verdad.
    std::size_t watching() const { return watching_; }

  private:
    void loop();

    Callback onExe_;
    std::mutex mutex_;
    std::vector<std::wstring> wanted_;
    bool changed_ = false, stop_ = false;
    void *wake_ = nullptr; // evento de despertar (HANDLE)
    std::thread thread_;
    std::atomic<std::size_t> watching_{0};
};

// El nombre termina en «.exe» (sin distinguir mayúsculas) y tiene algo antes.
bool isExeName(const std::wstring &name);

} // namespace gbe
