#pragma once
// El tooltip propio de las apps LGA (caja oscura con flecha hacia el control, 600 ms), copiado de LGA_Base_QT_C_Py
// (include/lga_base_qt_c_py/CustomTooltip.h). Nunca el nativo de Qt: CustomTooltip::instance()->setToolTip(w, texto).

#include <QObject>
#include <QWidget>
#include <QLabel>
#include <QEvent>
#include <QApplication>
#include <QPainter>
#include <QPainterPath>
#include <QPointer>
#include <QTimer>
#include <QPoint>
#include <QString>

/**
 * @brief Clase singleton para gestionar tooltips personalizados con flecha superior
 * 
 * Esta clase permite mostrar tooltips personalizados con un estilo consistente
 * en toda la aplicación. Los tooltips pueden aparecer inmediatamente o con un
 * delay configurable al pasar el mouse sobre un elemento, y desaparecen cuando
 * el mouse sale del elemento.
 */
class CustomTooltip : public QObject {
    Q_OBJECT

public:
    /**
     * @brief Obtiene la instancia única del singleton
     * @return Puntero a la instancia de CustomTooltip
     */
    static CustomTooltip* instance();

    /**
     * @brief Destructor
     */
    ~CustomTooltip();

    /**
     * @brief Asigna un tooltip a un widget
     * @param widget El widget al que asignar el tooltip
     * @param text El texto del tooltip
     */
    void setToolTip(QWidget* widget, const QString& text);

    /**
     * @brief Muestra el tooltip en una posición específica (inmediato, sin delay)
     * @param text El texto a mostrar
     * @param parent El widget padre (para posicionamiento)
     * @param pos La posición donde mostrar el tooltip
     */
    void showToolTip(const QString& text, QWidget* parent, const QPoint& pos);

    /**
     * @brief Solicita mostrar un tooltip respetando el setting de delay.
     *
     * Pensado para casos que NO usan setToolTip() sobre un widget registrado (p.ej. el
     * hover por MouseMove de los tabs principales, donde un mismo QTabBar muestra textos
     * distintos según el tab). Centraliza la decisión inmediato/delay en el tooltip, igual
     * que el path del eventFilter, para que el setting aplique en todos lados por igual.
     */
    void requestToolTip(const QString& text, QWidget* parent, const QPoint& pos);

    /**
     * @brief Oculta el tooltip si está visible y cancela cualquier tooltip pendiente
     */
    void hideToolTip();

    /**
     * @brief Actualiza el texto de un widget y, si su tooltip está visible en este
     *        momento (el mouse está encima), lo re-renderiza en vivo.
     *
     * Pensado para contenido dinámico (ej. el tooltip de pasos del circular progress
     * que cambia de amarillo a verde y actualiza contadores mientras corre el sync).
     * Registra el widget igual que setToolTip(), así que puede usarse como único punto
     * de entrada para asignar y luego refrescar.
     */
    void refreshIfVisible(QWidget* widget, const QString& text);

    // Genera una captura del tooltip para pruebas visuales no interactivas.
    bool debugGrabToFile(const QString& text, const QString& outputPath);

protected:
    /**
     * @brief Filtra eventos para la gestión de tooltips
     * @param watched El objeto observado
     * @param event El evento recibido
     * @return true si el evento fue procesado, false en caso contrario
     */
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    /**
     * @brief Constructor privado (singleton)
     */
    CustomTooltip();
    
    /**
     * @brief Crea el widget de tooltip
     */
    void createTooltipWidget();
    void onWidgetDestroyed(QObject* obj);
    void showPendingToolTip();
    void cancelPendingToolTip();
    void showPendingDirectToolTip();
    void cancelPendingDirectToolTip();
    bool shouldShowToolTipWithDelay() const;

    // --- Ocultado robusto: watchdog + chequeo geométrico contra el "ancla" ---
    // El ancla es el widget que disparó el tooltip visible (el widget registrado en
    // setToolTip(), o el parent pasado a requestToolTip()/showToolTip()). El ocultado
    // ya NO depende de recibir un QEvent::Leave (poco confiable al mover el mouse rápido):
    // un MouseMove global oculta al instante cuando el cursor sale del ancla, y un timer
    // de respaldo cubre el caso en que el cursor abandona la app sin más eventos.
    void startHideWatchdog(QWidget* anchor);
    void stopHideWatchdog();
    bool cursorOverAnchor() const;
    void onHideWatchdogTick();

    static CustomTooltip* m_instance; // Instancia única
    QWidget* m_tooltipWidget;         // Widget del tooltip
    QLabel* m_textLabel;              // Etiqueta para el texto
    int m_triangleHeight;             // Altura del triángulo
    int m_triangleWidth;              // Ancho del triángulo
    int m_borderRadius;               // Radio de las esquinas
    int m_shadowPadding;              // Padding extra para la sombra
    QColor m_backgroundColor;         // Color de fondo del tooltip
    
    // Caché para mejorar el rendimiento
    QMap<QWidget*, QString> m_widgetTooltips;
    QTimer* m_showDelayTimer;
    QPointer<QWidget> m_pendingWidget;

    // Estado para pedidos "directos" con delay (requestToolTip), no ligados a un widget registrado
    QTimer* m_directDelayTimer;
    QPointer<QWidget> m_pendingDirectParent;
    QString m_pendingDirectText;
    QPoint m_pendingDirectPos;

    // Ocultado robusto del tooltip visible
    QTimer* m_hideWatchdogTimer;       // Respaldo: oculta si el cursor abandonó el ancla
    QPointer<QWidget> m_anchorWidget;  // Widget que disparó el tooltip actualmente visible
    
    // Constantes
    static const int TOOLTIP_MARGIN = 8;
    static const int TOOLTIP_PADDING = 8;
    static const int TOOLTIP_MAX_WIDTH = 1800; // Valor razonable pero generoso
}; 
