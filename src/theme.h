#pragma once
#include <QApplication>
#include <QColor>
#include <QVariant>
#include <QWidget>
#include <QFont>
#include <QFontDatabase>
#include <QRegularExpression>
#include <QString>
#include "palette.h"

// Tokens del Pliego (los de src/ui/Theme.h de LGA Mighty Tools) con el acento violeta de las apps LGA en lugar del
// magenta: botón principal, links, selección y ayuda abierta. Cian = funciona, amarillo = pide atención, rojo = error.
namespace Gate::Theme {

inline constexpr const char *kDesk = "#0D0D0F";   // la mesa: barra de título, índice
inline constexpr const char *kSheet = "#17171B";  // la hoja de cada página y el aviso
inline constexpr const char *kCard = "#1E1E23";
inline constexpr const char *kCardBorder = "#25252B";
inline constexpr const char *kTile = "#2A2A31";   // caja de ícono y botones
inline constexpr const char *kField = "#15151A";
inline constexpr const char *kBorder = "#2E2E36";
inline constexpr const char *kFieldBorder = "#2F2F37";
inline constexpr const char *kDivider = "#2A2A31";
inline constexpr const char *kBorderStrong = "#3A3A43";
inline constexpr const char *kNavHover = "#131317";
inline constexpr const char *kRowHover = "#26262D";

inline constexpr const char *kTextBright = "#ECE9E2";
inline constexpr const char *kTextStrong = "#E3E1DA";
inline constexpr const char *kText = "#C4C3C9";
inline constexpr const char *kTextMuted = "#A6A5AC";
inline constexpr const char *kTextCaption = "#9C9BA2";
inline constexpr const char *kTextFaint = "#8C8B93";
inline constexpr const char *kTextPlaceholder = "#7A7982";
inline constexpr const char *kTextDisabled = "#5E5D66";

inline constexpr const char *kAccent = "#9D8FE0";       // links, ayuda abierta
inline constexpr const char *kAccentHover = "#C5BBF4";
inline constexpr const char *kPrimary = "#443A91";      // botón principal (Allow)
inline constexpr const char *kPrimaryBorder = "#5243A8";
inline constexpr const char *kPrimaryHover = "#5446B4";
inline constexpr const char *kPrimaryHoverBorder = "#7060D0";
inline constexpr const char *kOnAccent = "#DDDBEE";
inline constexpr const char *kChosenBg = "#2A2552";     // segmento elegido
inline constexpr const char *kChosenBorder = "#5243A8";
inline constexpr const char *kListSelected = "#25223B";

inline constexpr const char *kOk = "#4CC9EE";
inline constexpr const char *kOkText = "#57CDEF";
inline constexpr const char *kOkBg = "#0D2A33";
inline constexpr const char *kOkBorder = "#24586A";
inline constexpr const char *kWarn = "#F2CB3F";
inline constexpr const char *kWarnInk = "#1C1606";
inline constexpr const char *kWarnBorder = "#5A4E26";
inline constexpr const char *kError = "#F0645C";
inline constexpr const char *kErrBg = "#361B1D";
inline constexpr const char *kErrBorder = "#6B2E31";

inline constexpr const char *kSwitchOff = "#26262D";
inline constexpr const char *kSwitchOffBorder = "#4A4A55";
inline constexpr const char *kSwitchKnobOff = "#77767E";
inline constexpr const char *kSwitchOn = "#0D3542";
inline constexpr const char *kSwitchOnBorder = "#2A97BC";
inline constexpr const char *kSwitchKnobOn = "#4CC9EE";

inline constexpr const char *kKeyBorder = "#3B3B44";
inline constexpr const char *kKeyBottom = "#0F0F12";

// Con la paleta elegida (palette.h): los tokens guardan el valor de fábrica y se traducen al usarlos.
inline QColor color(const char *token) { return Palette::map(QString::fromLatin1(token)); }
inline QColor colorIn(const char *roleId, const char *token) {
    return Palette::mapIn(QString::fromLatin1(roleId), QString::fromLatin1(token));
}
inline QString hex(const char *token) { return Palette::hex(QString::fromLatin1(token)); }

// Títulos en Bricolage Grotesque (tres pesos embebidos); si no cargó, Inter SemiBold.
inline bool hasTitleFamily() { return QFontDatabase::families().contains(QStringLiteral("Bricolage Grotesque")); }
inline QFont titleFont(qreal pixelSize, int weight) {
    const bool bricolage = hasTitleFamily();
    QFont f(bricolage ? QStringLiteral("Bricolage Grotesque") : QStringLiteral("Inter"));
    f.setPixelSize(qRound(pixelSize));
    f.setWeight(static_cast<QFont::Weight>(bricolage ? weight : qMin(weight, int(QFont::DemiBold))));
    return f;
}
inline QString titleFamilyCss() {
    return hasTitleFamily() ? QStringLiteral("'Bricolage Grotesque'") : QStringLiteral("'Inter'");
}

// La hoja de estilo admite sólo píxeles enteros: los tamaños del diseño con medio píxel (12.5px, 13.5px) pasan a
// puntos (96 ppp lógicos en Windows: 1px = 0,75pt). «@title» se reemplaza por la familia de los títulos.
inline QString css(QString sheet) {
    static const QRegularExpression half(QStringLiteral("font-size:\\s*(\\d+\\.\\d+)px"));
    QString out;
    qsizetype last = 0;
    for (auto it = half.globalMatch(sheet); it.hasNext();) {
        const auto m = it.next();
        out += sheet.mid(last, m.capturedStart() - last);
        out += QStringLiteral("font-size: %1pt").arg(m.captured(1).toDouble() * 0.75, 0, 'f', 3);
        last = m.capturedEnd();
    }
    out += sheet.mid(last);
    return Palette::remapSheet(out.replace(QStringLiteral("@title"), titleFamilyCss()));
}

// Pone una hoja en un widget y guarda la de fábrica: al cambiar la paleta, reapplySheets() la vuelve a traducir.
inline void sheet(QWidget *widget, const QString &raw) {
    widget->setProperty("gbSheet", raw);
    widget->setStyleSheet(css(raw));
}
inline void reapplySheets() {
    for (QWidget *w : QApplication::allWidgets()) {
        const QVariant raw = w->property("gbSheet");
        if (raw.isValid()) w->setStyleSheet(css(raw.toString()));
    }
}

} // namespace Gate::Theme
