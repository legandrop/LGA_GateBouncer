#pragma once
#include <QAbstractButton>
#include <QWidget>

class QLabel;
class QVariantAnimation;

// Interruptor de encendido y apagado (30 x 17), copiado del ToggleSwitch de LGA_MightyTools: mismas medidas,
// colores y animacion. Checkable: toggled() y clicked() avisan como en un QCheckBox. No toma foco de teclado.
// Con un click del usuario la perilla desliza 160 ms con frenado al final y el color se funde parejo en el mismo
// tiempo. Un setChecked() del codigo (reflejar un estado) salta al final sin animar.
class ToggleSwitch : public QAbstractButton {
    Q_OBJECT
  public:
    explicit ToggleSwitch(QWidget *parent = nullptr);
    QSize sizeHint() const override;

  protected:
    void paintEvent(QPaintEvent *event) override;
    void nextCheckState() override;
    void checkStateSet() override;

  private:
    void animateTo(qreal target);

    QVariantAnimation *anim_ = nullptr; // se crea con el primer click
    bool byUser_ = false;
    qreal target_ = 0;  // hacia donde va la animacion en marcha
    qreal knob_ = 0;    // posicion de la perilla: 0 apagado, 1 prendido (con la curva)
    qreal tint_ = 0;    // mezcla de colores: 0 apagado, 1 prendido (lineal)
    qreal knobFrom_ = 0;
    qreal tintFrom_ = 0;
};

// Una opcion de encendido y apagado: texto a la izquierda y el switch a la derecha (el SwitchRow de Mighty
// Tools). Reemplaza a las casillas de verificacion. Un click en el texto tambien cambia el switch. La logica
// trabaja sobre toggle(): ahi van el objectName, setChecked, setEnabled y las conexiones; si el switch se
// deshabilita, el texto se atenua y deja de responder.
class SwitchRow : public QWidget {
    Q_OBJECT
  public:
    explicit SwitchRow(const QString &text, QWidget *parent = nullptr);
    ToggleSwitch *toggle() const { return switch_; }
    QLabel *textLabel() const { return label_; }

  protected:
    void mousePressEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;
    bool eventFilter(QObject *watched, QEvent *event) override;

  private:
    void syncEnabled();

    QLabel *label_ = nullptr;
    ToggleSwitch *switch_ = nullptr;
    bool pressed_ = false; // el click empezó en la fila (no en el switch ni afuera)
};
