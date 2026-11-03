#include "platform/WindowFrame.h"

#include <QGuiApplication>
#include <QWidget>

#include <windows.h>
#include <windowsx.h>
#include <dwmapi.h>

namespace Gate::WindowFrame {
namespace {

bool isResizable(HWND hwnd) { return (GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_THICKFRAME) != 0; }

} // namespace

bool apply(QWidget *window, bool resizable) {
    if (QGuiApplication::platformName() != QLatin1String("windows")) return false;
    // Los estilos de una ventana con título: Windows la sigue tratando como ventana normal aunque el título nativo no
    // se dibuje. WS_THICKFRAME en la que se estira: Windows hace el estiramiento y el acomodo contra los costados.
    const HWND hwnd = reinterpret_cast<HWND>(window->winId());
    const LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
    SetWindowLongPtrW(hwnd, GWL_STYLE,
                      style | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | (resizable ? WS_THICKFRAME : 0));
    // Un píxel de «marco» metido en el cliente es lo que hace que DWM pinte la sombra.
    const MARGINS margins{0, 0, 1, 0};
    DwmExtendFrameIntoClientArea(hwnd, &margins);
    // Esquinas redondeadas de Windows 11 (DWMWA_WINDOW_CORNER_PREFERENCE = 33, DWMWCP_ROUND = 2).
    const DWORD corners = 2;
    DwmSetWindowAttribute(hwnd, 33, &corners, sizeof(corners));
    SetWindowPos(hwnd, nullptr, 0, 0, 0, 0, SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    return true;
}

bool handleNativeEvent(void *message, qintptr *result) {
    const MSG *msg = static_cast<const MSG *>(message);
    if (msg->message == WM_NCCALCSIZE && msg->wParam == TRUE) {
        // Todo el rectángulo de la ventana es cliente. Maximizada, Windows la corre afuera de la pantalla lo que mide el
        // marco: se le descuenta para que no quede cortada.
        if (isResizable(msg->hwnd) && IsZoomed(msg->hwnd)) {
            auto *params = reinterpret_cast<NCCALCSIZE_PARAMS *>(msg->lParam);
            const UINT dpi = GetDpiForWindow(msg->hwnd);
            const int frameX = GetSystemMetricsForDpi(SM_CXSIZEFRAME, dpi) + GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi);
            const int frameY = GetSystemMetricsForDpi(SM_CYSIZEFRAME, dpi) + GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi);
            InflateRect(&params->rgrc[0], -frameX, -frameY);
        }
        *result = 0;
        return true;
    }
    if (msg->message == WM_NCHITTEST && isResizable(msg->hwnd) && !IsZoomed(msg->hwnd)) {
        RECT rect;
        if (!GetWindowRect(msg->hwnd, &rect)) return false;
        const POINT point{GET_X_LPARAM(msg->lParam), GET_Y_LPARAM(msg->lParam)};
        const UINT dpi = GetDpiForWindow(msg->hwnd);
        const int border = MulDiv(kResizeBorder, int(dpi), 96);
        const int borderRight = MulDiv(kResizeBorderRight, int(dpi), 96);
        const int corner = MulDiv(kResizeCorner, int(dpi), 96);
        const bool left = point.x < rect.left + border;
        const bool right = point.x >= rect.right - borderRight;
        const bool top = point.y < rect.top + border;
        const bool bottom = point.y >= rect.bottom - border;
        if (!left && !right && !top && !bottom) return false; // adentro: lo atiende Qt
        const bool nearLeft = point.x < rect.left + corner;
        const bool nearRight = point.x >= rect.right - corner;
        const bool nearTop = point.y < rect.top + corner;
        const bool nearBottom = point.y >= rect.bottom - corner;
        if ((top && nearLeft) || (left && nearTop)) *result = HTTOPLEFT;
        else if ((top && nearRight) || (right && nearTop)) *result = HTTOPRIGHT;
        else if ((bottom && nearLeft) || (left && nearBottom)) *result = HTBOTTOMLEFT;
        else if ((bottom && nearRight) || (right && nearBottom)) *result = HTBOTTOMRIGHT;
        else if (left) *result = HTLEFT;
        else if (right) *result = HTRIGHT;
        else if (top) *result = HTTOP;
        else *result = HTBOTTOM;
        return true;
    }
    return false;
}

} // namespace Gate::WindowFrame
