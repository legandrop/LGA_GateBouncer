#pragma once
#include <QSize>
#include <QString>
#include <QtGlobal>

// Zoom de la interfaz, como en Mighty Tools: 100, 110 (el de fábrica) y 120 %. Agranda todo por igual con el factor
// de escala global de Qt (QT_SCALE_FACTOR), como si la pantalla tuviera más DPI: el layout en píxeles lógicos no
// cambia. Qt lo lee una sola vez, al crear la QApplication, así que cambiarlo reinicia la ventana. La variable se
// saca apenas existe la aplicación para que no la herede lo que la ventana lanza.
namespace Gate::UiScale {

inline constexpr int kMaxLevel = 2;
inline constexpr int kDefaultLevel = 1;

qreal factor(int level);
int clampLevel(int level);
int percent(int level);

// Un nivel vale si la ventana en su tamaño mínimo entra entera en el área útil de la pantalla principal (píxeles
// lógicos del sistema, sin el factor de la app). El 0 siempre vale.
int maxFittingLevel(const QSize &unscaledArea);

// Nivel guardado (sin nada guardado o roto, el de fábrica). Se puede leer antes de la QApplication.
int readSavedLevel();
void saveLevel(int level);

// Antes de la QApplication: fija QT_SCALE_FACTOR y recuerda el nivel de esta sesión.
void applyBeforeApp(int level);
// Después: devuelve el entorno como estaba.
void clearEnvironmentAfterApp();
int sessionLevel();

} // namespace Gate::UiScale
