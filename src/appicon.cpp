#include "appicon.h"
#include <QColor>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QHash>
#include <QIcon>
#include <QPainter>
#include <QPen>

namespace Gate {

QPainterPath genericAppGlyph() {
    QPainterPath path;
    path.addRoundedRect(QRectF(3, 4, 14, 12), 2, 2);
    path.moveTo(3, 7.5);
    path.lineTo(17, 7.5);
    return path;
}

QPixmap appIconPixmap(const QString &path, int glyph, qreal dpr) {
    // Viven hasta el final del proceso a propósito: destruir pixmaps después de cerrar la aplicación de Qt no es seguro.
    static auto *cache = new QHash<QString, QPixmap>;
    static auto *provider = new QFileIconProvider;
    const QString key = path.toLower() + "|" + QString::number(glyph) + "|" + QString::number(dpr);
    const auto found = cache->constFind(key);
    if (found != cache->constEnd()) return *found;
    QPixmap pm;
    // Sin el archivo, Windows devolvería el ícono genérico de su extensión: se prefiere el glifo propio.
    if (!path.isEmpty() && QFileInfo::exists(path)) pm = provider->icon(QFileInfo(path)).pixmap(QSize(glyph, glyph), dpr);
    if (!pm.isNull()) {
        cache->insert(key, pm);
        return pm;
    }
    // El glifo no se guarda: si el programa aparece después en esa ruta, se ve su ícono real.
    const int size = glyph - 2;
    QPixmap glyphPm(QSize(size, size) * dpr);
    glyphPm.setDevicePixelRatio(dpr);
    glyphPm.fill(Qt::transparent);
    QPainter p(&glyphPm);
    p.setRenderHint(QPainter::Antialiasing);
    p.scale(size / 20.0, size / 20.0);
    p.setPen(QPen(QColor("#a8a8a8"), 1.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    p.drawPath(genericAppGlyph());
    p.end();
    return glyphPm;
}

} // namespace Gate
