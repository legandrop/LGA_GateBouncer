#pragma once
// Ícono de un programa, igual en la ventana y en el aviso.
#include <QPainterPath>
#include <QPixmap>
#include <QString>
#include <QStringList>
#include <functional>

class QLabel;
class QObject;

namespace Gate {

// Glifo de «programa sin ícono propio», en la grilla de 20 x 20 de los íconos de línea.
QPainterPath genericAppGlyph();

// Ícono real del programa (el que muestra Windows) en un cuadrado de `glyph` px lógicos a la escala `dpr`. Si el
// archivo ya no existe o Windows no da ícono, el glifo genérico en gris. Queda en memoria por ruta, tamaño y escala.
// Lo pide en el acto (frena hasta que Windows contesta): para un ícono suelto, como el del aviso. Las listas usan
// AppIcons.
QPixmap appIconPixmap(const QString &path, int glyph, qreal dpr);

// Íconos para listas, sin frenar la interfaz. Windows tarda en darlos (decenas de ms por programa la primera vez, y
// segundos con una unidad de red caída): se piden en un hilo propio, de a uno, y quedan en memoria. Mientras llegan se
// ve el glifo genérico. Un ícono que no se pudo leer se vuelve a probar recién a los 5 minutos.
namespace AppIcons {
// El ícono si ya llegó; si no, el glifo genérico, y lo pide (primero en la fila). `ready` dice si es el definitivo.
QPixmap get(const QString &path, int glyph, qreal dpr, bool *ready = nullptr);
// Pone el ícono en `label`: ya, o cuando llegue (si la etiqueta sigue viva).
void apply(QLabel *label, const QString &path, int glyph, qreal dpr);
// Los pide sin apuro, al final de la fila: al arrancar, para que Apps abra con sus íconos.
void prefetch(const QStringList &paths, int glyph, qreal dpr);
// `callback` corre en el hilo de la interfaz cuando llega un lote de íconos, mientras `context` viva: para repintar
// una tabla que los pinta a mano.
void onLoaded(QObject *context, std::function<void()> callback);
} // namespace AppIcons

} // namespace Gate
