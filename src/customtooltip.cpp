// Copia del tooltip propio de las apps LGA (LGA_Base_QT_C_Py, src/utils/CustomTooltip.cpp, dbfd041). Fuente de verdad del
// diseño: LGA_Base_QT_C_Py/docs/Doc_CustomTooltip.md. GateBouncer no tiene ajustes de tooltips ni banderas de
// depuración: siempre activos, con la demora de 600 ms, y sin trazas.
#include "customtooltip.h"
#include <QApplication>
#include <QPainter>
#include <QPainterPath>
#include <QVBoxLayout>
#include <QScreen>
#include <QHoverEvent>
#include <QTimer>
#include <QCursor>
#include <QDebug>
#include <QPixmap>
#include <QRegularExpression>
#include <QTextDocument>
#include <QtMath>

#define CONDITIONAL_DEBUG(flag, message) ((void)0)

namespace {
struct TooltipSettings {
    static TooltipSettings &instance() {
        static TooltipSettings settings;
        return settings;
    }
    bool tooltipsEnabled() const { return true; }
    bool tooltipDelayEnabled() const { return true; }
};
using AppSettings = TooltipSettings;
} // namespace

// Definir la constante estática
const int CustomTooltip::TOOLTIP_MAX_WIDTH;

namespace {
const int TOOLTIP_SHOW_DELAY_MS = 600; // ✅✅⚠️⚠️📛📛📛 Ajustar delay de aparición de tooltips (ms)
const int SMALL_BREAK_PX = 4;
const int SECTION_BREAK_PX = 10;

// ✅✅⚠️⚠️📛📛📛 Ajustes del triángulo apuntador del tooltip.
const int TRIANGLE_WIDTH = 16;    // base del triángulo (px)
const int TRIANGLE_HEIGHT = 11;   // altura del triángulo desde el borde del rect al pico (px)
const qreal TRIANGLE_OVERLAP = 0.2; // px que el triángulo entra DENTRO del rect para tapar el border en la unión (fraccional OK: 0.5, 0.75, etc.)
}

// Clase personalizada para el widget de tooltip - Ahora basada directamente en QLabel
class TooltipWidget : public QLabel {
public:
    // Dirección del triángulo apuntador:
    // - Up: triángulo arriba, tooltip aparece DEBAJO del ancla (default).
    // - Down: triángulo abajo, tooltip aparece ARRIBA del ancla (cuando no entra abajo).
    enum TriangleDirection { Up, Down };

    TooltipWidget(QWidget* parent = nullptr, Qt::WindowFlags f = Qt::WindowFlags())
        : QLabel(parent, f),
          m_triangleHeight(TRIANGLE_HEIGHT),
          m_triangleWidth(TRIANGLE_WIDTH),
          m_borderRadius(6),
          m_shadowPadding(6),
          m_backgroundColor(QColor("#242424")),
          m_triangleOffset(0),
          m_triangleDirection(Up)
    {
        // Configuración base
        setObjectName("tooltipLabel");
        setTextFormat(Qt::RichText);
        setAlignment(Qt::AlignLeft | Qt::AlignVCenter);

        // Configuración de margen: el triangleHeight va arriba o abajo según dirección.
        // Margen derecho menor que el izquierdo: el texto es left-aligned, así que
        // cualquier sobra de medición cae a la derecha; con 6 en vez de 10 se compensa.
        applyContentsMargins();

        // Configuración para ventana con transparencia
        setAttribute(Qt::WA_TranslucentBackground);
        setAttribute(Qt::WA_ShowWithoutActivating);
        // ⚠️ Qt::NoDropShadowWindowHint es CRÍTICO en macOS: sin este flag, Cocoa
        //    aplica la sombra nativa de sistema al alpha shape del widget translúcido,
        //    ADEMÁS de la sombra que pintamos nosotros en paintEvent. El resultado es un
        //    doble halo con un "hueco" visible entre ambas sombras — más notorio sobre
        //    backgrounds saturados donde el alpha blend de la sombra nativa contrasta.
        //    Windows/Linux ignoran este flag, no cambia nada ahí.
        setWindowFlags(Qt::ToolTip | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint | Qt::NoDropShadowWindowHint);

        setWordWrap(true);
    }

    void setTriangleSize(int width, int height) {
        if (width != m_triangleWidth || height != m_triangleHeight) {
            m_triangleWidth = width;
            m_triangleHeight = height;
            applyContentsMargins();
            updateGeometry();
        }
    }

    void setTriangleDirection(TriangleDirection dir) {
        if (m_triangleDirection == dir) return;
        m_triangleDirection = dir;
        applyContentsMargins();
        updateGeometry();
        update();
    }

    TriangleDirection triangleDirection() const { return m_triangleDirection; }
    
    void setBorderRadius(int radius) {
        if (radius != m_borderRadius) {
            m_borderRadius = radius;
            update();
        }
    }
    
    void setBackgroundColor(const QColor& color) {
        if (color != m_backgroundColor) {
            m_backgroundColor = color;
            update();
        }
    }
    
    void setTriangleOffset(int offset) {
        if (m_triangleOffset != offset) {
            m_triangleOffset = offset;
            update();
        }
    }

    int triangleHeight() const { return m_triangleHeight; }
    int shadowPadding() const { return m_shadowPadding; }

private:
    // Reserva el espacio del triángulo del lado correcto según dirección.
    // El total (top+bottom) es el mismo independiente de la dirección, así que
    // finalHeight no cambia al flipear — solo se mueve el "hueco" del triángulo
    // dentro del widget.
    void applyContentsMargins() {
        int topMargin = 10 + (m_triangleDirection == Up ? m_triangleHeight : 0);
        int bottomMargin = 10 + (m_triangleDirection == Down ? m_triangleHeight : 0);
        setContentsMargins(10 + m_shadowPadding, topMargin,
                           6 + m_shadowPadding, bottomMargin);
    }

protected:
    void paintEvent(QPaintEvent* event) override {
        // LOG INICIAL DE DIMENSIONES REALES
        CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [TooltipWidget::paintEvent] DIMENSIONES - Widget rect: [%1,%2,%3,%4], ContentsRect: [%5,%6,%7,%8]")
            .arg(rect().x()).arg(rect().y()).arg(rect().width()).arg(rect().height())
            .arg(contentsRect().x()).arg(contentsRect().y()).arg(contentsRect().width()).arg(contentsRect().height()));

        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        
        // Limpiar el fondo
        painter.fillRect(rect(), Qt::transparent);
        
        // Calcular posición del triángulo, considerando el padding y el offset
        int triangleCenter = (width() / 2) + m_triangleOffset;
        int triangleX = triangleCenter - (m_triangleWidth / 2);

        // Asegurar que el triángulo no se salga del widget
        int minX = m_shadowPadding + m_borderRadius;
        int maxX = width() - m_shadowPadding - m_borderRadius - m_triangleWidth;

        if (triangleX < minX) {
            CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [TooltipWidget::paintEvent] Triángulo limitado por borde izquierdo, movido de %1 a %2").arg(triangleX).arg(minX));
            triangleX = minX;
        } else if (triangleX > maxX) {
            CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [TooltipWidget::paintEvent] Triángulo limitado por borde derecho, movido de %1 a %2").arg(triangleX).arg(maxX));
            triangleX = maxX;
        }

        // El rect ocupa toda la altura menos el shadow padding en ambos lados y
        // el triangleHeight del lado donde apunta el triángulo.
        int rectTop = m_shadowPadding + (m_triangleDirection == Up ? m_triangleHeight : 0);
        int rectBottom = height() - m_shadowPadding - (m_triangleDirection == Down ? m_triangleHeight : 0);
        QRectF mainRect(m_shadowPadding, rectTop,
                       width() - 2 * m_shadowPadding,
                       rectBottom - rectTop);

        // LOG DEL RECTÁNGULO DE FONDO REAL QUE SE PINTA
        CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [TooltipWidget::paintEvent] ÁREA PINTADA - Fondo mainRect: [%1,%2,%3,%4] direction=%5")
            .arg(mainRect.x()).arg(mainRect.y()).arg(mainRect.width()).arg(mainRect.height())
            .arg(m_triangleDirection == Up ? "Up" : "Down"));

        // 3 paths separados:
        //   - fillPath: rect ∪ triángulo (para el fill, sin border).
        //   - borderPath: outline exterior CONTINUO trazado a mano (rect con el top
        //     "abierto" en la zona del triángulo, subiendo al pico y bajando).
        //     Al no depender del overlap para tapar el border, no hay conflicto de
        //     AA (que hacía que `TRIANGLE_OVERLAP` no tuviera intermedio visible).
        //   - shadowPath: outline exterior para dibujar la sombra atrás.
        QPainterPath rectPath;
        rectPath.addRoundedRect(mainRect, m_borderRadius, m_borderRadius);

        const qreal triPeakY = (m_triangleDirection == Up) ? qreal(m_shadowPadding) : qreal(height() - m_shadowPadding);
        const qreal triBaseYFill = (m_triangleDirection == Up) ? qreal(rectTop) + TRIANGLE_OVERLAP : qreal(rectBottom) - TRIANGLE_OVERLAP;
        const qreal triBaseYShape = (m_triangleDirection == Up) ? qreal(rectTop) : qreal(rectBottom);
        const qreal triLeftX = qreal(triangleX);
        const qreal triRightX = qreal(triangleX + m_triangleWidth);
        const qreal triMidX = triLeftX + qreal(m_triangleWidth) / 2.0;

        // fillPath: rect + triángulo (base entra `TRIANGLE_OVERLAP` px al rect
        // para que el fill se una sin costura visible entre ambos).
        QPainterPath trianglePathFill;
        trianglePathFill.moveTo(triLeftX, triBaseYFill);
        trianglePathFill.lineTo(triMidX, triPeakY);
        trianglePathFill.lineTo(triRightX, triBaseYFill);
        trianglePathFill.closeSubpath();
        QPainterPath fillPath = rectPath.united(trianglePathFill);

        // borderPath: trazado manual del outline exterior. En el top edge (para Up)
        // saltamos del arranque del triángulo al pico y bajamos al final del triángulo,
        // sin trazar la base. Análogo para Down.
        QPainterPath borderPath;
        const qreal r = qreal(m_borderRadius);
        const qreal L = mainRect.left();
        const qreal R = mainRect.right();
        const qreal T = mainRect.top();
        const qreal B = mainRect.bottom();
        if (m_triangleDirection == Up) {
            borderPath.moveTo(L + r, T);
            borderPath.lineTo(triLeftX, T);
            borderPath.lineTo(triMidX, triPeakY);
            borderPath.lineTo(triRightX, T);
            borderPath.lineTo(R - r, T);
            borderPath.arcTo(R - 2 * r, T, 2 * r, 2 * r, 90, -90);
            borderPath.lineTo(R, B - r);
            borderPath.arcTo(R - 2 * r, B - 2 * r, 2 * r, 2 * r, 0, -90);
            borderPath.lineTo(L + r, B);
            borderPath.arcTo(L, B - 2 * r, 2 * r, 2 * r, 270, -90);
            borderPath.lineTo(L, T + r);
            borderPath.arcTo(L, T, 2 * r, 2 * r, 180, -90);
        } else {
            borderPath.moveTo(L + r, T);
            borderPath.lineTo(R - r, T);
            borderPath.arcTo(R - 2 * r, T, 2 * r, 2 * r, 90, -90);
            borderPath.lineTo(R, B - r);
            borderPath.arcTo(R - 2 * r, B - 2 * r, 2 * r, 2 * r, 0, -90);
            borderPath.lineTo(triRightX, B);
            borderPath.lineTo(triMidX, triPeakY);
            borderPath.lineTo(triLeftX, B);
            borderPath.lineTo(L + r, B);
            borderPath.arcTo(L, B - 2 * r, 2 * r, 2 * r, 270, -90);
            borderPath.lineTo(L, T + r);
            borderPath.arcTo(L, T, 2 * r, 2 * r, 180, -90);
        }

        // shadowPath: outline exterior del shape con el triángulo apoyado en la base
        // del rect (sin overlap) — el shadow va detrás del fill así que el overlap
        // no le importa; usar el shape real da un halo más limpio.
        Q_UNUSED(triBaseYShape);
        QPainterPath shadowShapePath = borderPath;

        // 1) Dibujar la SOMBRA primero como strokes concéntricos (detrás del fill).
        painter.save();
        const int numLayers = 4;
        const qreal expandStep = 2.2;
        for (int i = 0; i < numLayers; ++i) {
            QColor shadowColor(0, 0, 0, 11 - i * 2);
            painter.setPen(QPen(shadowColor, (i + 1) * expandStep, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
            painter.setBrush(Qt::NoBrush);
            painter.drawPath(shadowShapePath);
        }
        painter.restore();

        // 2) Dibujar el FILL del shape completo (rect + triángulo unidos), SIN border.
        //    No hay border interno porque el fillPath es la unión — el AA fade del
        //    fill contra el fondo transparente se sella con la sombra atrás.
        painter.setPen(Qt::NoPen);
        painter.setBrush(m_backgroundColor);
        painter.drawPath(fillPath);

        // 3) Dibujar el BORDER como outline exterior continuo (trazado a mano en
        //    `borderPath`), 1px `#3a3a3a`. NO trazamos la base del triángulo — el
        //    outline sube al pico y baja, unificado con el top del rect. Así no hay
        //    dependencia del overlap para tapar un border interno.
        //    ⚠️ El "hueco" macOS lo arregla Qt::NoDropShadowWindowHint aparte.
        painter.setPen(QPen(QColor("#3a3a3a"), 1, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        painter.setBrush(Qt::NoBrush);
        painter.drawPath(borderPath);

        // Dibujar el texto (sin la traza del área de texto de la base: acá las trazas van apagadas)
        painter.setPen(palette().color(QPalette::WindowText));
        QLabel::paintEvent(event);
    }

    void showEvent(QShowEvent* event) override { QLabel::showEvent(event); }

private:
    int m_triangleHeight;
    int m_triangleWidth;
    int m_borderRadius;
    int m_shadowPadding;
    QColor m_backgroundColor;
    int m_triangleOffset;
    TriangleDirection m_triangleDirection;
};

// Inicializar el puntero estático
CustomTooltip* CustomTooltip::m_instance = nullptr;

// Método para obtener la instancia única
CustomTooltip* CustomTooltip::instance() {
    if (!m_instance) {
        m_instance = new CustomTooltip();
    }
    return m_instance;
}

// Constructor privado
CustomTooltip::CustomTooltip()
    : m_tooltipWidget(nullptr),
      m_textLabel(nullptr),
      m_triangleHeight(TRIANGLE_HEIGHT),
      m_triangleWidth(TRIANGLE_WIDTH),
      m_borderRadius(6),
      m_shadowPadding(6),
      m_backgroundColor(QColor("#242424")),
      m_showDelayTimer(new QTimer(this)),
      m_directDelayTimer(new QTimer(this)),
      m_hideWatchdogTimer(new QTimer(this))
{
    // Crear el widget de tooltip
    createTooltipWidget();

    m_showDelayTimer->setSingleShot(true);
    QObject::connect(m_showDelayTimer, &QTimer::timeout, this, &CustomTooltip::showPendingToolTip);

    m_directDelayTimer->setSingleShot(true);
    QObject::connect(m_directDelayTimer, &QTimer::timeout, this, &CustomTooltip::showPendingDirectToolTip);

    // Watchdog de respaldo: mientras el tooltip esté visible, chequea periódicamente que el
    // cursor siga sobre el ancla. Cubre el caso en que el cursor abandona la app sin que
    // lleguen más eventos de mouse (el MouseMove global no alcanza si no hay movimiento dentro
    // de la app). NO es single-shot: corre repetidamente solo mientras hay tooltip visible.
    m_hideWatchdogTimer->setInterval(120);
    QObject::connect(m_hideWatchdogTimer, &QTimer::timeout, this, &CustomTooltip::onHideWatchdogTick);

    // Instalar filtro de eventos global para detectar pérdida de foco de la app
    // y para ocultar al instante cuando el cursor sale del ancla (MouseMove global).
    QApplication::instance()->installEventFilter(this);
}

// Destructor
CustomTooltip::~CustomTooltip() {
    cancelPendingToolTip();
    // Eliminar el widget de tooltip si existe
    if (m_tooltipWidget) {
        m_tooltipWidget->deleteLater();
    }
}

// Método para crear el widget de tooltip - Ahora mucho más simple
void CustomTooltip::createTooltipWidget() {
    // Crear el widget como TooltipWidget que hereda de QLabel
    TooltipWidget* tooltipWidget = new TooltipWidget(nullptr, Qt::ToolTip | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint | Qt::NoDropShadowWindowHint);
    m_tooltipWidget = tooltipWidget;
    m_textLabel = tooltipWidget; // Ahora son el mismo objeto
    
    // Configurar las propiedades del widget
    tooltipWidget->setAttribute(Qt::WA_TranslucentBackground);
    tooltipWidget->setAttribute(Qt::WA_ShowWithoutActivating);
    tooltipWidget->setAttribute(Qt::WA_DeleteOnClose, false);
    tooltipWidget->setFocusPolicy(Qt::NoFocus);
    
    // Configurar las propiedades específicas usando el tipo correcto
    tooltipWidget->setTriangleSize(m_triangleWidth, m_triangleHeight);
    tooltipWidget->setBorderRadius(m_borderRadius);
    tooltipWidget->setBackgroundColor(m_backgroundColor);
    
    // Establecer una política de tamaño flexible
    tooltipWidget->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Minimum);
    
    // Inicialmente oculto
    tooltipWidget->hide();
}

// Filtro de eventos para los widgets con tooltip
bool CustomTooltip::eventFilter(QObject* watched, QEvent* event) {
    // OCULTAR TOOLTIP SI LA APP PIERDE FOCO (evento global)
    if (event->type() == QEvent::ApplicationDeactivate || event->type() == QEvent::WindowDeactivate) {
        cancelPendingToolTip();
        hideToolTip();
        // No interferimos con otros filtros, dejamos pasar el evento
        return QObject::eventFilter(watched, event);
    }

    // OCULTADO INSTANTÁNEO: ante cualquier movimiento del mouse en la app, si hay un tooltip
    // visible y el cursor ya NO está sobre el ancla que lo disparó, ocultarlo de inmediato.
    // Esto reemplaza la dependencia del QEvent::Leave (que Qt no entrega de forma confiable al
    // mover el mouse rápido) por un chequeo geométrico en vivo contra la posición del cursor.
    if (event->type() == QEvent::MouseMove && m_tooltipWidget && m_tooltipWidget->isVisible()) {
        if (!cursorOverAnchor()) {
            QString anchorName = m_anchorWidget
                ? (m_anchorWidget->objectName().isEmpty() ? m_anchorWidget->metaObject()->className() : m_anchorWidget->objectName())
                : "null";
            CONDITIONAL_DEBUG("TooltipHide", QString("{TooltipHide} [CustomTooltip::eventFilter] MouseMove global: cursor fuera del ancla '%1' -> ocultar instantáneo")
                .arg(anchorName));
            hideToolTip();
        }
        // Nunca consumimos el MouseMove: dejamos que siga su curso normal.
        return QObject::eventFilter(watched, event);
    }

    QWidget* widget = qobject_cast<QWidget*>(watched);
    if (!widget) {
        return QObject::eventFilter(watched, event);
    }
    if (!m_widgetTooltips.contains(widget)) {
        return QObject::eventFilter(watched, event);
    }
    
    switch (event->type()) {
        case QEvent::Enter: {
            // Mostrar el tooltip cuando el mouse entra en el widget
            QString widgetName = widget->objectName().isEmpty() ? widget->metaObject()->className() : widget->objectName();
            const bool withDelay = shouldShowToolTipWithDelay();
            CONDITIONAL_DEBUG("TooltipDelay", QString("{TooltipDelay} [eventFilter::Enter] widget='%1', delayEnabled=%2")
                .arg(widgetName).arg(withDelay ? "ON" : "OFF"));

            QPoint pos = widget->mapToGlobal(QPoint(widget->width() / 2, widget->height()));
            QString tooltip = m_widgetTooltips.value(widget);
            if (!tooltip.isEmpty()) {
                if (withDelay) {
                    // Si ya hay un timer corriendo para ESTE mismo widget, NO lo reiniciamos:
                    // reiniciarlo en cada Enter (p.ej. churn de Enter/Leave por widgets hijos)
                    // posterga el disparo indefinidamente y el tooltip nunca aparece.
                    if (m_pendingWidget == widget && m_showDelayTimer->isActive()) {
                        CONDITIONAL_DEBUG("TooltipDelay", QString("{TooltipDelay} [eventFilter::Enter] '%1' ya tiene timer activo (restante=%2ms), NO se reinicia")
                            .arg(widgetName).arg(m_showDelayTimer->remainingTime()));
                    } else {
                        m_pendingWidget = widget;
                        m_showDelayTimer->start(TOOLTIP_SHOW_DELAY_MS);
                        CONDITIONAL_DEBUG("TooltipDelay", QString("{TooltipDelay} [eventFilter::Enter] '%1' timer iniciado (%2ms)")
                            .arg(widgetName).arg(TOOLTIP_SHOW_DELAY_MS));
                    }
                } else {
                    cancelPendingToolTip();
                    CONDITIONAL_DEBUG("TooltipDelay", QString("{TooltipDelay} [eventFilter::Enter] '%1' mostrando tooltip INMEDIATO").arg(widgetName));
                    showToolTip(tooltip, widget, pos);
                }
            }
            return true;
        }

        case QEvent::Leave: {
            // Qt manda Leave al padre cuando el cursor entra a un widget HIJO, aunque el
            // cursor siga visualmente "dentro" del padre. Si cancelamos el timer en ese
            // caso, el tooltip con delay nunca llega a dispararse. Por eso solo cancelamos
            // cuando el cursor realmente salió de la geometría del widget.
            QString widgetName = widget->objectName().isEmpty() ? widget->metaObject()->className() : widget->objectName();
            const bool stillInside = widget->rect().contains(widget->mapFromGlobal(QCursor::pos()));
            if (stillInside) {
                CONDITIONAL_DEBUG("TooltipDelay", QString("{TooltipDelay} [eventFilter::Leave] '%1' Leave IGNORADO: cursor sigue dentro (probable hijo), timer intacto")
                    .arg(widgetName));
                return true;
            }
            CONDITIONAL_DEBUG("TooltipDelay", QString("{TooltipDelay} [eventFilter::Leave] '%1' cursor fuera -> cancelar pending + ocultar")
                .arg(widgetName));
            if (m_pendingWidget == widget) {
                cancelPendingToolTip();
            }
            hideToolTip();
            return true;
        }

        case QEvent::Hide:
        case QEvent::Close: {
            // Ocultar el tooltip cuando el widget se oculta o cierra
            if (m_pendingWidget == widget) {
                cancelPendingToolTip();
            }
            hideToolTip();
            return true;
        }

        default:
            break;
    }
    
    return QObject::eventFilter(watched, event);
}

// Método para asignar un tooltip a un widget
void CustomTooltip::setToolTip(QWidget* widget, const QString& text) {
    if (!widget) return;
    
    // Eliminar cualquier tooltip nativo de Qt
    widget->setToolTip("");
    
    // Si ya teníamos un tooltip asignado, eliminar el filtro anterior
    if (m_widgetTooltips.contains(widget)) {
        widget->removeEventFilter(this);
    }
    
    // Guardar el tooltip para este widget
    if (!text.isEmpty()) {
        m_widgetTooltips[widget] = text;
        // Instalar filtro de eventos para este widget
        widget->installEventFilter(this);
        QObject::connect(widget, &QObject::destroyed, this, &CustomTooltip::onWidgetDestroyed, Qt::UniqueConnection);
    } else {
        // Si el texto está vacío, eliminar cualquier tooltip existente
        m_widgetTooltips.remove(widget);
        if (m_pendingWidget == widget) {
            cancelPendingToolTip();
        }
    }
}

void CustomTooltip::refreshIfVisible(QWidget* widget, const QString& text) {
    if (!widget) return;
    // Registrar/actualizar el texto (y el event filter) igual que setToolTip().
    setToolTip(widget, text);
    // Si el tooltip está visible y su ancla es justamente este widget, re-render en vivo.
    if (m_tooltipWidget && m_tooltipWidget->isVisible() &&
        m_anchorWidget == widget && !text.isEmpty()) {
        const QPoint pos = widget->mapToGlobal(QPoint(widget->width() / 2, widget->height()));
        showToolTip(text, widget, pos);
    }
}

bool CustomTooltip::debugGrabToFile(const QString& text, const QString& outputPath) {
    if (!m_tooltipWidget || text.isEmpty() || outputPath.isEmpty()) {
        return false;
    }

    // La captura se usa desde --tooltip-shot; no tiene ancla real, por lo que
    // alcanza con una posición global estable dentro del escritorio.
    showToolTip(text, nullptr, QPoint(100, 100));
    QApplication::processEvents();

    const bool saved = m_tooltipWidget->grab().save(outputPath);
    hideToolTip();
    return saved;
}

void CustomTooltip::onWidgetDestroyed(QObject* obj) {
    QWidget* widget = qobject_cast<QWidget*>(obj);
    if (!widget) {
        return;
    }
    if (m_pendingWidget == widget) {
        cancelPendingToolTip();
    }
    m_widgetTooltips.remove(widget);
}

bool CustomTooltip::shouldShowToolTipWithDelay() const {
    // Lectura EN VIVO desde SecureConfig: el setting se aplica apenas se guarda
    // (SettingsTab::saveSettings escribe en la misma instancia singleton), sin reiniciar.
    const bool enabled = AppSettings::instance().tooltipDelayEnabled();
    CONDITIONAL_DEBUG("TooltipDelay", QString("{TooltipDelay} [shouldShowToolTipWithDelay] Tooltips/ShowDelay = %1")
        .arg(enabled ? "true" : "false"));
    return enabled;
}

void CustomTooltip::cancelPendingToolTip() {
    if (m_showDelayTimer && m_showDelayTimer->isActive()) {
        m_showDelayTimer->stop();
    }
    m_pendingWidget.clear();
}

void CustomTooltip::cancelPendingDirectToolTip() {
    if (m_directDelayTimer && m_directDelayTimer->isActive()) {
        m_directDelayTimer->stop();
    }
    m_pendingDirectParent.clear();
    m_pendingDirectText.clear();
}

// Pedido "directo" (no ligado a un widget registrado) que respeta el setting de delay.
void CustomTooltip::requestToolTip(const QString& text, QWidget* parent, const QPoint& pos) {
    if (text.isEmpty()) return;
    // Master switch: si el setting global de tooltips está OFF, no mostramos nada.
    // Se lee en vivo desde SecureConfig (aplica apenas se guarda, sin reiniciar).
    if (!AppSettings::instance().tooltipsEnabled()) {
        cancelPendingDirectToolTip();
        hideToolTip();
        return;
    }

    QString parentName = parent ? (parent->objectName().isEmpty() ? parent->metaObject()->className() : parent->objectName()) : "null";

    if (shouldShowToolTipWithDelay()) {
        // Si había un tooltip visible (p.ej. de otro tab), su contenido quedó obsoleto:
        // lo ocultamos para no mostrar texto viejo durante la espera del delay.
        if (m_tooltipWidget && m_tooltipWidget->isVisible()) {
            m_tooltipWidget->hide();
        }
        m_pendingDirectParent = parent;
        m_pendingDirectText = text;
        m_pendingDirectPos = pos;
        m_directDelayTimer->start(TOOLTIP_SHOW_DELAY_MS);
        CONDITIONAL_DEBUG("TooltipDelay", QString("{TooltipDelay} [requestToolTip] '%1' timer DIRECTO iniciado (%2ms)")
            .arg(parentName).arg(TOOLTIP_SHOW_DELAY_MS));
    } else {
        cancelPendingDirectToolTip();
        CONDITIONAL_DEBUG("TooltipDelay", QString("{TooltipDelay} [requestToolTip] '%1' mostrando tooltip DIRECTO inmediato").arg(parentName));
        showToolTip(text, parent, pos);
    }
}

void CustomTooltip::showPendingDirectToolTip() {
    if (m_pendingDirectText.isEmpty()) {
        return;
    }
    const QString text = m_pendingDirectText;
    QWidget* parent = m_pendingDirectParent.data();
    const QPoint pos = m_pendingDirectPos;
    m_pendingDirectText.clear();

    QString parentName = parent ? (parent->objectName().isEmpty() ? parent->metaObject()->className() : parent->objectName()) : "null";
    CONDITIONAL_DEBUG("TooltipDelay", QString("{TooltipDelay} [showPendingDirectToolTip] MOSTRANDO tooltip DIRECTO retrasado para '%1'").arg(parentName));
    showToolTip(text, parent, pos);
}

void CustomTooltip::showPendingToolTip() {
    QWidget* widget = m_pendingWidget.data();
    m_pendingWidget.clear();
    if (!widget) {
        CONDITIONAL_DEBUG("TooltipDelay", "{TooltipDelay} [showPendingToolTip] ABORT: widget nulo (destruido durante el delay)");
        return;
    }

    QString widgetName = widget->objectName().isEmpty() ? widget->metaObject()->className() : widget->objectName();

    if (!widget->isVisible()) {
        CONDITIONAL_DEBUG("TooltipDelay", QString("{TooltipDelay} [showPendingToolTip] ABORT '%1': widget no visible").arg(widgetName));
        return;
    }

    // Usamos hit-test geométrico en lugar de underMouse(): cuando el cursor está sobre un
    // widget hijo, WA_UnderMouse del padre queda en false aunque el cursor siga dentro.
    const bool insideGeom = widget->rect().contains(widget->mapFromGlobal(QCursor::pos()));
    CONDITIONAL_DEBUG("TooltipDelay", QString("{TooltipDelay} [showPendingToolTip] '%1' timer disparado: insideGeom=%2, underMouse=%3")
        .arg(widgetName).arg(insideGeom).arg(widget->underMouse()));

    if (!insideGeom) {
        CONDITIONAL_DEBUG("TooltipDelay", QString("{TooltipDelay} [showPendingToolTip] ABORT '%1': cursor fuera de la geometría").arg(widgetName));
        return;
    }

    if (!m_widgetTooltips.contains(widget)) {
        CONDITIONAL_DEBUG("TooltipDelay", QString("{TooltipDelay} [showPendingToolTip] ABORT '%1': sin tooltip registrado").arg(widgetName));
        return;
    }

    const QString tooltip = m_widgetTooltips.value(widget);
    if (tooltip.isEmpty()) {
        return;
    }

    CONDITIONAL_DEBUG("TooltipDelay", QString("{TooltipDelay} [showPendingToolTip] MOSTRANDO tooltip retrasado para '%1'").arg(widgetName));
    QPoint pos = widget->mapToGlobal(QPoint(widget->width() / 2, widget->height()));
    showToolTip(tooltip, widget, pos);
}

// Método para mostrar el tooltip - Ahora con manejo de tamaño mejorado
void CustomTooltip::showToolTip(const QString& text, QWidget* parent, const QPoint& pos) {
    if (!m_tooltipWidget || text.isEmpty()) return;
    // Master switch: si el setting global de tooltips está OFF, no mostramos nada.
    if (!AppSettings::instance().tooltipsEnabled()) {
        hideToolTip();
        return;
    }

    QString parentName = parent ? (parent->objectName().isEmpty() ? parent->metaObject()->className() : parent->objectName()) : "null";
    CONDITIONAL_DEBUG("TooltipDelay", QString("{TooltipDelay} [showToolTip] -> tooltip VISIBLE para widget '%1'").arg(parentName));
    CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] Mostrando tooltip para widget '%1', texto: '%2'")
        .arg(parentName).arg(text.left(50) + (text.length() > 50 ? "..." : "")));

    // Tags custom:
    // - <sbr/>: separación compacta (small break) entre líneas relacionadas.
    // - <sbr/>: separación reforzada (section break) para segundos títulos/labels.
    // Qt rich text NO soporta <div> como bloque (lo trata inline), pero SÍ soporta <p> con
    // margin-top. Por eso convertimos los tags en cortes de párrafo y compensamos el alto.
    QRegularExpression smallBreakRe("<sbr\\s*/?>");
    QRegularExpression sectionBreakRe("<sBR\\s*/?>");
    int smallBreakCount = static_cast<int>(text.count(smallBreakRe));
    int sectionBreakCount = static_cast<int>(text.count(sectionBreakRe));

    // Texto a mostrar: envolver en párrafos y reemplazar <sbr/> por límite de párrafo con margen
    QString displayText = text;
    displayText.replace(sectionBreakRe, QString("</p><p style=\"margin-top:%1px; margin-bottom:0px;\">").arg(SECTION_BREAK_PX));
    displayText.replace(smallBreakRe, QString("</p><p style=\"margin-top:%1px; margin-bottom:0px;\">").arg(SMALL_BREAK_PX));
    displayText = "<p style=\"margin:0px;\">" + displayText + "</p>";

    // Auto-conversión de atajos a las etiquetas macOS (texto plano, mantiene los `+`).
    // Los tooltips se escriben en forma canónica "Ctrl+X"/"Alt+X"/"Shift+X" (funciona
    // literal en Win/Linux). En mac se traducen a "Cmd+"/"Opt+"/"Ctrl+" (real).
    // Qt ya swappea Ctrl↔Cmd en QKeySequence, así que la funcionalidad del atajo sigue
    // OK sin tocar nada más.
    //   Ctrl+ / Command+     → Cmd+   (Qt::CTRL en QKeySequence = tecla Cmd en Mac)
    //   Meta+                → Ctrl+  (Qt::META en QKeySequence = tecla Ctrl real en Mac)
    //   Alt+  / Option+      → Opt+
    //   Shift+               (se queda igual)
    // Usa regex para aceptar espacios opcionales alrededor del `+` (matchea tanto
    // "Ctrl+" como "Ctrl + ") — defensivo contra formatos inconsistentes en tooltips
    // existentes. La forma canónica recomendada para tooltips nuevos es SIN espacios
    // ("Ctrl+X").
    // Orden importa: Ctrl/Command → Cmd PRIMERO, luego Meta → Ctrl. Si fuera al
    // revés, el "Ctrl+" recién creado por Meta→Ctrl se convertiría de nuevo a "Cmd+".
#ifdef Q_OS_MAC
    static const QRegularExpression kReCtrl("(?:Ctrl|Command)\\s*\\+\\s*",     QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression kReMeta("Meta\\s*\\+\\s*",                  QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression kReAlt ("(?:Alt|Option|Opt)\\s*\\+\\s*",    QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression kReShift("Shift\\s*\\+\\s*",                QRegularExpression::CaseInsensitiveOption);
    displayText.replace(kReCtrl,  "Cmd+");
    displayText.replace(kReMeta,  "Ctrl+");
    displayText.replace(kReAlt,   "Opt+");
    displayText.replace(kReShift, "Shift+");
#endif

    m_textLabel->setText(displayText);
    QFontMetrics fm(m_textLabel->font());

    // 1. Preparar texto para medición: reemplazar <br>, <sbr>, <sBR> y <div> por \n
    //    IMPORTANTE: <div align='center'> (usado para poner un atajo en línea inferior
    //    centrada) renderiza como bloque en la QLabel, pero si no lo contamos acá la
    //    medición pone el contenido del div en la misma línea → ancho de más a la derecha
    //    y alto de menos (texto cropeado). Lo convertimos a salto de línea y compensamos alto.
    QRegularExpression divOpenRe("<div\\b[^>]*>", QRegularExpression::CaseInsensitiveOption);
    int divCount = static_cast<int>(text.count(divOpenRe));
    QString plainText = text;
    plainText.replace(sectionBreakRe, "\n");
    plainText.replace(smallBreakRe, "\n");
    plainText.replace(QRegularExpression("<br\\s*/?>", QRegularExpression::CaseInsensitiveOption), "\n");
    plainText.replace(divOpenRe, "\n");
    plainText.remove(QRegularExpression("<[^>]*>"));
    CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] Texto plano para medición: '%1'").arg(plainText));

    // 2. Definir márgenes internos (deben coincidir con los de setContentsMargins)
    int marginLeft = 10 + m_shadowPadding;
    int marginRight = 6 + m_shadowPadding; // menor que el izquierdo: compensa la sobra de medición que cae a la derecha (texto left-aligned)
    int marginTop = 10 + m_triangleHeight;
    int marginBottom = 10;
    int horizontalMargins = marginLeft + marginRight;
    int verticalMargins = marginTop + marginBottom;
    CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] Márgenes usados - Izq:%1 Der:%2 Arriba:%3 Abajo:%4").arg(marginLeft).arg(marginRight).arg(marginTop).arg(marginBottom));

    // 3. Definir ancho máximo de contenido
    int maxContentWidth = CustomTooltip::TOOLTIP_MAX_WIDTH - horizontalMargins;
    if (maxContentWidth < 50) maxContentWidth = 50; // Evitar valores absurdos
    CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] maxContentWidth: %1 (TOOLTIP_MAX_WIDTH: %2, horizontalMargins: %3)").arg(maxContentWidth).arg(CustomTooltip::TOOLTIP_MAX_WIDTH).arg(horizontalMargins));

    // 4. Medir el tamaño real del contenido HTML que el QLabel va a renderizar.
    //    Usamos QTextDocument con el mismo displayText y font que el label: da el
    //    ancho y alto EXACTOS del render final (incluye <p>/<br>/<sbr>/<sBR>/<div>/<table>
    //    con sus margins, line-height y block spacing de Qt Rich Text). Antes se medía el
    //    plainText con QFontMetrics + compensaciones fijas por tag, que subestimaban el alto
    //    cuando había varios <p> o <br> anidados → tooltips multi-línea cropeados abajo.
    //    El ancho de layout se le impone antes de leer el alto para que el word-wrap sea
    //    idéntico al del label.
    Q_UNUSED(smallBreakCount);
    Q_UNUSED(sectionBreakCount);
    Q_UNUSED(divCount);
    Q_UNUSED(plainText);
    Q_UNUSED(fm);

    QTextDocument measureDoc;
    // ⚠️ documentMargin default = 4px por lado. Sin poner esto en 0, idealWidth() y
    //    size().height() incluyen 4px extra a cada lado (8px total en cada dimensión).
    //    Ese sobrante hace que finalWidth sea mayor al necesario y como el texto es
    //    left-aligned, TODO el exceso cae a la derecha → "demasiado padding a la derecha".
    measureDoc.setDocumentMargin(0);
    measureDoc.setDefaultFont(m_textLabel->font());
    measureDoc.setHtml(displayText);
    measureDoc.setTextWidth(maxContentWidth);
    int idealW = qCeil(measureDoc.idealWidth());
    int contentWidth = qMin(idealW, maxContentWidth);
    // Con el ancho real fijado, size().height() da la altura final del render.
    measureDoc.setTextWidth(contentWidth);
    int contentHeight = qCeil(measureDoc.size().height());
    CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] contentWidth: %1, contentHeight: %2 (QTextDocument)").arg(contentWidth).arg(contentHeight));

    // 5. Calcular tamaño final del widget (sin compensaciones por tag: QTextDocument
    //    ya midió los <p>/<br>/margins/line-height reales del render).
    int finalWidth = contentWidth + horizontalMargins + 4; // +4 buffer chico; el texto es left-aligned así que la sobra cae a la derecha, se mantiene mínima
    int finalHeight = contentHeight + verticalMargins + 4; // +4 buffer chico de seguridad para redondeos del render
    CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] finalWidth: %1, finalHeight: %2 antes de mínimos").arg(finalWidth).arg(finalHeight));

    // Tamaños mínimos razonables
    if (finalWidth < 80) {
        CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] Ajustando finalWidth a mínimo: 80 (antes: %1)").arg(finalWidth));
        finalWidth = 80;
    }
    if (finalHeight < 40) {
        CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] Ajustando finalHeight a mínimo: 40 (antes: %1)").arg(finalHeight));
        finalHeight = 40;
    }
    CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] finalWidth: %1, finalHeight: %2 después de mínimos").arg(finalWidth).arg(finalHeight));

    // Forzar el tamaño exacto del tooltip y evitar que Qt lo redimensione automáticamente
    m_tooltipWidget->setFixedSize(finalWidth, finalHeight);
    CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] Tooltip tamaño fijado a: %1 x %2").arg(finalWidth).arg(finalHeight));

    // Calcular la posición donde debería estar el widget (centrado bajo el punto)
    int widgetCenterX = pos.x();
    QPoint idealPos = pos;
    idealPos.setX(widgetCenterX - finalWidth / 2); // Centrado inicialmente

    // --- Y positioning: se decide más abajo con flip Up/Down según espacio disponible.
    //    posBelowY: tooltip.top cuando se muestra DEBAJO del ancla (triángulo Up).
    //    posAboveY: tooltip.top cuando se muestra ARRIBA del ancla (triángulo Down).
    //    En ambos casos el pico del triángulo apenas roza el borde del ancla (overlap
    //    de ~7px, que sumado al shadowPadding de 6 deja el pico a 1px del ancla).
    const int kAnchorOverlap = 7;
    int posBelowY = pos.y() - kAnchorOverlap;
    // Para posAboveY necesitamos el TOP global del ancla. Si no hay parent, no podemos
    // calcularlo confiablemente — dejamos posAboveY inválido y no flipeamos.
    int anchorTopY = pos.y();
    bool canFlip = false;
    if (parent) {
        anchorTopY = parent->mapToGlobal(QPoint(0, 0)).y();
        canFlip = true;
    }
    int posAboveY = anchorTopY + kAnchorOverlap - finalHeight;

    // Asegurar que el tooltip esté dentro de la ventana de la aplicación
    int triangleOffset = 0; // Offset del triángulo respecto al centro
    
    // Obtener los límites de la ventana de la aplicación en lugar de la pantalla
    QRect windowGeometry;
    QWidget* activeWindow = QApplication::activeWindow();
    
    if (activeWindow) {
        // Usar las coordenadas globales de la ventana de la aplicación
        windowGeometry = QRect(activeWindow->mapToGlobal(QPoint(0, 0)),
                              QSize(activeWindow->width(), activeWindow->height()));
        
        // Logging para depuración de límites
        CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] Límites de la ventana: [%1,%2,%3,%4]")
            .arg(windowGeometry.left()).arg(windowGeometry.top())
            .arg(windowGeometry.right()).arg(windowGeometry.bottom()));
        
        CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] Tooltip sin ajustar: [%1,%2,%3,%4]")
            .arg(idealPos.x()).arg(idealPos.y())
            .arg(idealPos.x() + finalWidth).arg(idealPos.y() + finalHeight));
        
        // Ajuste horizontal con margen de seguridad
        if (idealPos.x() < windowGeometry.left()) {
            // Tooltip se sale por la izquierda
            CONDITIONAL_DEBUG("CustomTooltip", "{CustomTooltip} [CustomTooltip::showToolTip] Ajustando posición X por fuera de ventana a la izquierda");
            triangleOffset = idealPos.x() - (windowGeometry.left() + 10); // Negativo (el tooltip se movió a la derecha)
            CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] → El tooltip se movió %1px a la DERECHA, triángulo irá %1px a la IZQUIERDA").arg(-triangleOffset));
            idealPos.setX(windowGeometry.left() + 10);
        } else if (idealPos.x() + finalWidth > windowGeometry.right()) {
            // Tooltip se sale por la derecha
            CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] Ajustando posición X por fuera de ventana a la derecha (desborde: %1px)")
                             .arg((idealPos.x() + finalWidth) - windowGeometry.right()));
            
            triangleOffset = (idealPos.x() + finalWidth) - (windowGeometry.right() - 10); // Positivo (el tooltip se movió a la izquierda)
            CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] → El tooltip se movió %1px a la IZQUIERDA, triángulo irá %1px a la DERECHA").arg(triangleOffset));
            idealPos.setX(windowGeometry.right() - finalWidth - 10);
        }
        
        // Log después del ajuste
        CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] Tooltip AJUSTADO: [%1,%2,%3,%4]")
            .arg(idealPos.x()).arg(idealPos.y())
            .arg(idealPos.x() + finalWidth).arg(idealPos.y() + finalHeight));
        
        // El triangleOffset ahora nos dice cuánto tuvo que moverse el tooltip
        // Si el tooltip se mueve hacia la izquierda (valor positivo), el triángulo debe moverse hacia la derecha
        // Si el tooltip se mueve hacia la derecha (valor negativo), el triángulo debe moverse hacia la izquierda
        // No invertimos el signo, porque ya está en el sistema de coordenadas correcto:
        // - El tooltip se movió a la izquierda, así que triangleOffset es positivo (triángulo hacia la derecha)
        // - El tooltip se movió a la derecha, así que triangleOffset es negativo (triángulo hacia la izquierda)
        
        CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] Offset del triángulo: %1").arg(triangleOffset));
        
        // Establecer el offset en el widget
        // No usamos qobject_cast porque TooltipWidget no tiene Q_OBJECT
        TooltipWidget* tooltipWidget = static_cast<TooltipWidget*>(m_tooltipWidget);
        tooltipWidget->setTriangleOffset(triangleOffset);
        
        // --- Ajuste vertical: decidir mostrar ABAJO (Up) o ARRIBA (Down) del ancla,
        //     y flipear la dirección del triángulo en consecuencia.
        //
        //     Preferimos ABAJO (comportamiento clásico). Solo flipeamos si abajo NO entra
        //     completo y arriba SÍ, o si arriba tiene más espacio libre. Requiere `parent`
        //     para conocer el TOP del ancla; sin parent nos quedamos abajo.
        bool placeAbove = false;
        if (canFlip && (posBelowY + finalHeight > windowGeometry.bottom())) {
            if (posAboveY >= windowGeometry.top()) {
                placeAbove = true;
            } else {
                int spaceBelow = windowGeometry.bottom() - pos.y();
                int spaceAbove = anchorTopY - windowGeometry.top();
                placeAbove = (spaceAbove > spaceBelow);
            }
        }
        if (placeAbove) {
            idealPos.setY(posAboveY);
            tooltipWidget->setTriangleDirection(TooltipWidget::Down);
            CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] Flip Y: ARRIBA del ancla (triángulo Down). anchorTop=%1, posAboveY=%2").arg(anchorTopY).arg(posAboveY));
        } else {
            idealPos.setY(posBelowY);
            tooltipWidget->setTriangleDirection(TooltipWidget::Up);
            CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] Posición Y: DEBAJO del ancla (triángulo Up). posBelowY=%1").arg(posBelowY));
        }
    } else {
        // Si no podemos obtener la ventana, intentamos usar la pantalla como fallback.
        // Sin ventana no ajustamos X (no hay bordes conocidos) y usamos el default abajo (Up).
        QScreen* screen = QApplication::screenAt(idealPos);
        if (screen) {
            windowGeometry = screen->availableGeometry();
            CONDITIONAL_DEBUG("CustomTooltip", "{CustomTooltip} [CustomTooltip::showToolTip] No se pudo obtener la ventana, usando los límites de pantalla como fallback");
        } else {
            CONDITIONAL_DEBUG("CustomTooltip", "{CustomTooltip} [CustomTooltip::showToolTip] ADVERTENCIA: No se pudo obtener ni la ventana ni la pantalla para el tooltip");
        }
        // Default: mostrar abajo (Up), sin flip.
        idealPos.setY(posBelowY);
        TooltipWidget* fallbackWidget = static_cast<TooltipWidget*>(m_tooltipWidget);
        fallbackWidget->setTriangleDirection(TooltipWidget::Up);
    }

    // Asegurar que la X quede dentro del window/screen conocido (el Y ya se seteó
    // arriba a posBelowY o posAboveY, que están calculados con overlap intencional).
    idealPos.setX(qMax(windowGeometry.left(), idealPos.x()));
    
    CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] Posición final: %1,%2 (triangleOffset: %3)").arg(idealPos.x()).arg(idealPos.y()).arg(triangleOffset));
    
    // Mover y mostrar
    m_tooltipWidget->move(idealPos);

    // LOG DEL TAMAÑO REAL DEL WIDGET TRAS TODOS LOS AJUSTES
    CONDITIONAL_DEBUG("CustomTooltip", QString("{CustomTooltip} [CustomTooltip::showToolTip] TAMAÑO REAL FINAL DEL TOOLTIP: %1 x %2").arg(m_tooltipWidget->width()).arg(m_tooltipWidget->height()));
    m_tooltipWidget->show();

    // Registrar el ancla (widget que disparó este tooltip) y arrancar el watchdog de ocultado.
    startHideWatchdog(parent);
}

// Método para ocultar el tooltip
void CustomTooltip::hideToolTip() {
    // Cancelar tambien tooltips de widgets registrados que esten esperando el delay.
    cancelPendingToolTip();
    // Cancelar cualquier pedido directo pendiente (p.ej. al salir de un tab antes del delay)
    cancelPendingDirectToolTip();
    // Frenar el watchdog y olvidar el ancla: ya no hay tooltip que vigilar.
    stopHideWatchdog();
    if (m_tooltipWidget && m_tooltipWidget->isVisible()) {
        CONDITIONAL_DEBUG("TooltipHide", "{TooltipHide} [CustomTooltip::hideToolTip] ocultando tooltip (estaba visible)");
        m_tooltipWidget->hide();
    }
}

// --- Ocultado robusto: watchdog + chequeo geométrico contra el ancla ---

void CustomTooltip::startHideWatchdog(QWidget* anchor) {
    m_anchorWidget = anchor;
    QString anchorName = anchor
        ? (anchor->objectName().isEmpty() ? anchor->metaObject()->className() : anchor->objectName())
        : "null";

    if (!anchor) {
        // Sin ancla no podemos hacer el chequeo geométrico; no arrancamos el watchdog.
        // (El ocultado seguirá dependiendo de los caminos clásicos para este caso raro.)
        CONDITIONAL_DEBUG("TooltipHide", "{TooltipHide} [CustomTooltip::startHideWatchdog] sin ancla (parent null): watchdog NO iniciado");
        m_hideWatchdogTimer->stop();
        return;
    }

    m_hideWatchdogTimer->start();
    CONDITIONAL_DEBUG("TooltipHide", QString("{TooltipHide} [CustomTooltip::startHideWatchdog] ancla='%1', watchdog ON (intervalo=%2ms)")
        .arg(anchorName).arg(m_hideWatchdogTimer->interval()));
}

void CustomTooltip::stopHideWatchdog() {
    if (m_hideWatchdogTimer->isActive()) {
        m_hideWatchdogTimer->stop();
        CONDITIONAL_DEBUG("TooltipHide", "{TooltipHide} [CustomTooltip::stopHideWatchdog] watchdog OFF");
    }
    m_anchorWidget.clear();
}

bool CustomTooltip::cursorOverAnchor() const {
    // El ancla fue destruida: el cursor ya no puede estar sobre ella.
    if (!m_anchorWidget) {
        return false;
    }
    // El ancla dejó de estar visible (p.ej. cambio de tab/pantalla).
    if (!m_anchorWidget->isVisible()) {
        return false;
    }
    // Chequeo geométrico en vivo contra la posición real del cursor. Se infla 2px el rect
    // para evitar churn justo en el borde (donde Enter/Leave podrían oscilar).
    const QPoint local = m_anchorWidget->mapFromGlobal(QCursor::pos());
    const QRect tolerantRect = m_anchorWidget->rect().adjusted(-2, -2, 2, 2);
    return tolerantRect.contains(local);
}

void CustomTooltip::onHideWatchdogTick() {
    // Si por algún motivo el tooltip ya no está visible, frenar el watchdog.
    if (!m_tooltipWidget || !m_tooltipWidget->isVisible()) {
        stopHideWatchdog();
        return;
    }

    if (!m_anchorWidget) {
        CONDITIONAL_DEBUG("TooltipHide", "{TooltipHide} [CustomTooltip::onHideWatchdogTick] ancla destruida -> ocultar");
        hideToolTip();
        return;
    }
    if (!m_anchorWidget->isVisible()) {
        QString anchorName = m_anchorWidget->objectName().isEmpty() ? m_anchorWidget->metaObject()->className() : m_anchorWidget->objectName();
        CONDITIONAL_DEBUG("TooltipHide", QString("{TooltipHide} [CustomTooltip::onHideWatchdogTick] ancla '%1' no visible -> ocultar").arg(anchorName));
        hideToolTip();
        return;
    }
    if (!cursorOverAnchor()) {
        QString anchorName = m_anchorWidget->objectName().isEmpty() ? m_anchorWidget->metaObject()->className() : m_anchorWidget->objectName();
        CONDITIONAL_DEBUG("TooltipHide", QString("{TooltipHide} [CustomTooltip::onHideWatchdogTick] cursor fuera del ancla '%1' (sin MouseMove) -> ocultar")
            .arg(anchorName));
        hideToolTip();
    }
}
