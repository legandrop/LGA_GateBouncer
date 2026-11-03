#pragma once
// Marco de una ventana que dibuja su propia barra de título, igual que en Mighty Tools. Una ventana Qt sin marco es un
// WS_POPUP: sin sombra, sin esquinas redondeadas, sin bordes para estirarla ni acomodo contra los costados. Se le
// devuelven los estilos de una ventana con título y WM_NCCALCSIZE deja el área no-cliente en cero; la que se estira
// responde WM_NCHITTEST con los bordes y las esquinas de una franja interior.
#include <QtGlobal>

class QWidget;

namespace Gate::WindowFrame {

// Franja interior que estira la ventana, en píxeles a 96 ppp (toda la ventana es cliente, así que la franja se
// superpone al contenido). A la derecha es de 2: la barra de desplazamiento va contra ese borde. Las esquinas toman
// un tramo más largo de cada borde, para agarrarlas sin puntería.
constexpr int kResizeBorder = 5;
constexpr int kResizeBorderRight = 2;
constexpr int kResizeCorner = 14;

// Se llama una vez, la primera vez que se muestra la ventana (ya existe la ventana nativa). True si quedó aplicado:
// desde ahí la ventana pasa sus eventos nativos por handleNativeEvent.
bool apply(QWidget *window, bool resizable);
// True si el evento ya quedó atendido (resultado en *result).
bool handleNativeEvent(void *message, qintptr *result);

} // namespace Gate::WindowFrame
