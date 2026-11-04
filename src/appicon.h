#pragma once
// Ícono de un programa, igual en la ventana y en el aviso.
#include <QPainterPath>
#include <QPixmap>
#include <QString>

namespace Gate {

// Glifo de «programa sin ícono propio», en la grilla de 20 x 20 de los íconos de línea.
QPainterPath genericAppGlyph();

// Ícono real del programa (el que muestra Windows) en un cuadrado de `glyph` px lógicos a la escala `dpr`. Si el
// archivo ya no existe o Windows no da ícono, el glifo genérico en gris. Queda en memoria por ruta, tamaño y escala.
QPixmap appIconPixmap(const QString &path, int glyph, qreal dpr);

} // namespace Gate
