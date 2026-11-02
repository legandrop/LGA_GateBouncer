#include "toggleswitch.h"
#include <QEasingCurve>
#include <QEvent>
#include <QHBoxLayout>
#include <QLabel>
#include <QMouseEvent>
#include <QPainter>
#include <QPointer>
#include <QVariantAnimation>
#include <utility>

namespace {
// Colores del interruptor de Mighty Tools (Theme.h: kPrimary, kPrimaryBorder, kSwitchOff, kSwitchOffBorder,
// kSwitchKnobOff, kSwitchKnobOn). El violeta prendido es el mismo del boton principal de GateBouncer.
const QColor kOnFill("#443a91");
const QColor kOnBorder("#5243a8");
const QColor kOffFill("#2d2d33");
const QColor kOffBorder("#3a3a44");
const QColor kKnobOff("#7a7a80");
const QColor kKnobOn("#dddbee");
// Deshabilitado: Mighty Tools no lo dibuja distinto; aca hay consentimientos que esperan un estado, asi que el
// switch entero se atenua para que no parezca disponible.
constexpr qreal kDisabledOpacity = 0.4;

QColor mix(const QColor &a, const QColor &b, qreal t) {
    return QColor::fromRgbF(a.redF() + (b.redF() - a.redF()) * t, a.greenF() + (b.greenF() - a.greenF()) * t,
                            a.blueF() + (b.blueF() - a.blueF()) * t, a.alphaF() + (b.alphaF() - a.alphaF()) * t);
}
} // namespace

// ------------------------------------------------------------------ ToggleSwitch

ToggleSwitch::ToggleSwitch(QWidget *parent) : QAbstractButton(parent) {
    setCheckable(true);
    setFocusPolicy(Qt::NoFocus);
    setCursor(Qt::PointingHandCursor);
    setFixedSize(30, 17);
}

QSize ToggleSwitch::sizeHint() const { return QSize(30, 17); }

void ToggleSwitch::nextCheckState() {
    // Todo click del usuario pasa por aca (mouse, o click() desde el texto de su SwitchRow). Con el mouse, Qt
    // bloquea el refresco y su setChecked NO llama a checkStateSet() (igual que QCheckBox): la animacion se
    // arranca aca, al volver de la base. El guard cubre un handler de toggled que borre el switch.
    QPointer<ToggleSwitch> guard(this);
    byUser_ = true;
    QAbstractButton::nextCheckState();
    if (!guard)
        return;
    byUser_ = false;
    animateTo(isChecked() ? 1.0 : 0.0);
}

void ToggleSwitch::checkStateSet() {
    // Un setChecked() del codigo: refleja un estado y salta al final. Si repite el destino de una animacion en
    // marcha (una vista que refresca apenas se hizo click), la deja seguir.
    if (byUser_)
        return;
    const qreal target = isChecked() ? 1.0 : 0.0;
    if (anim_ && anim_->state() == QAbstractAnimation::Running && target == target_)
        return;
    if (anim_)
        anim_->stop();
    knob_ = tint_ = target_ = target;
    update();
}

void ToggleSwitch::animateTo(qreal target) {
    target_ = target;
    if (!isVisible()) {
        if (anim_)
            anim_->stop();
        knob_ = tint_ = target;
        update();
        return;
    }
    if (!anim_) {
        anim_ = new QVariantAnimation(this);
        anim_->setStartValue(0.0);
        anim_->setEndValue(1.0);
        anim_->setDuration(160);
        // El tiempo corre lineal: el color se funde parejo y la perilla toma la curva en valueChanged.
        connect(anim_, &QVariantAnimation::valueChanged, this, [this](const QVariant &value) {
            // cubic-bezier(.2, .8, .2, 1): arranca rapido y frena al llegar, sin rebote.
            static const QEasingCurve knobCurve = [] {
                QEasingCurve curve(QEasingCurve::BezierSpline);
                curve.addCubicBezierSegment(QPointF(0.2, 0.8), QPointF(0.2, 1.0), QPointF(1.0, 1.0));
                return curve;
            }();
            const qreal f = value.toReal();
            knob_ = knobFrom_ + (target_ - knobFrom_) * knobCurve.valueForProgress(f);
            tint_ = tintFrom_ + (target_ - tintFrom_) * f;
            update();
        });
    }
    // Un click en medio de una animacion arranca la vuelta desde donde esta.
    anim_->stop();
    knobFrom_ = knob_;
    tintFrom_ = tint_;
    anim_->start();
}

void ToggleSwitch::paintEvent(QPaintEvent *) {
    // Caja 30 x 17 con borde de 1 y radio 8,5; perilla de 11 a 2 px del borde interno (left 3 apagado, left 16
    // prendido). Durante la animacion los colores se mezclan por tint_ y la perilla va por knob_.
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);
    if (!isEnabled())
        painter.setOpacity(kDisabledOpacity);
    const QRectF box = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
    painter.setPen(QPen(mix(kOffBorder, kOnBorder, tint_), 1.0));
    painter.setBrush(mix(kOffFill, kOnFill, tint_));
    painter.drawRoundedRect(box, 8.5, 8.5);
    painter.setPen(Qt::NoPen);
    painter.setBrush(mix(kKnobOff, kKnobOn, tint_));
    const qreal left = 1 + 2 + 13 * knob_;
    painter.drawEllipse(QRectF(left, 1 + 2, 11, 11));
}

// ------------------------------------------------------------------ SwitchRow

SwitchRow::SwitchRow(const QString &text, QWidget *parent) : QWidget(parent) {
    auto *row = new QHBoxLayout(this);
    row->setContentsMargins(0, 0, 0, 0);
    row->setSpacing(12);
    // Con wordWrap el texto no fija el ancho minimo de la fila: si no entra baja de linea en vez de empujar el
    // switch fuera del panel. Sin interaccion de texto, el click pasa a la fila.
    label_ = new QLabel(text, this);
    label_->setObjectName("switch-label");
    label_->setTextFormat(Qt::PlainText);
    label_->setWordWrap(true);
    row->addWidget(label_, 1);
    switch_ = new ToggleSwitch(this);
    switch_->setAccessibleName(text);
    row->addWidget(switch_, 0, Qt::AlignVCenter);
    switch_->installEventFilter(this);
    syncEnabled();
}

void SwitchRow::syncEnabled() {
    const bool enabled = switch_->isEnabled();
    label_->setEnabled(enabled);
    setCursor(enabled ? Qt::PointingHandCursor : Qt::ArrowCursor);
}

bool SwitchRow::eventFilter(QObject *watched, QEvent *event) {
    if (watched == switch_ && event->type() == QEvent::EnabledChange)
        syncEnabled();
    return QWidget::eventFilter(watched, event);
}

void SwitchRow::mousePressEvent(QMouseEvent *event) {
    pressed_ = event->button() == Qt::LeftButton;
    QWidget::mousePressEvent(event);
}

void SwitchRow::mouseReleaseEvent(QMouseEvent *event) {
    // Click en el texto o en el aire de la fila: como un click en el switch. Sólo si también empezó en la fila: un
    // click que arrancó en el switch y se soltó sobre el texto no cuenta.
    const bool started = std::exchange(pressed_, false);
    if (started && event->button() == Qt::LeftButton && switch_->isEnabled() &&
        rect().contains(event->position().toPoint())) {
        switch_->click();
        return;
    }
    QWidget::mouseReleaseEvent(event);
}
