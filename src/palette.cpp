#include "palette.h"

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSaveFile>
#include <algorithm>
#include <cmath>

namespace Gate::Palette {

namespace {

// Cada color de fábrica en un solo grupo. «title», «section» y «switch» no tienen miembros por valor: se piden por
// nombre (@color(rol) en las hojas, mapIn en el código que pinta), porque su valor de fábrica es el mismo de otro grupo.
const QVector<Role> kRoles = {
    {"desk", "Mesa: fondo exterior, barra de título e índice", "#0D0D0F", {"#0D0D0F", "#0F0F12", "#131317", "#1B1B20"}},
    {"sheet", "Hoja: fondo de cada página, del aviso y de los campos", "#17171B", {"#17171B", "#15151A", "#1A1A1F"}},
    {"card", "Tarjetas, filas y hover", "#1E1E23", {"#1E1E23", "#202026", "#222227", "#26262D"}},
    {"control", "Botones, cajas de ícono y divisores", "#2A2A31", {"#2A2A31", "#34343C"}},
    {"border", "Bordes", "#2E2E36", {"#25252B", "#2E2E36", "#2F2F37", "#3A3A43", "#3B3B44", "#44444E", "#4A4A55"}},
    {"title", "Títulos (tarjetas, páginas, aviso)", "#ECE9E2", {}},
    {"section", "Rótulos del índice (FIREWALL, APP)", "#8C8B93", {}},
    {"ink1", "Texto blanco: valores, nombres, botones", "#E3E1DA", {"#ECE9E2", "#F3F0E9", "#E3E1DA", "#DCDAD3", "#CFCDD4"}},
    {"ink2", "Texto común: párrafos", "#C4C3C9", {"#C4C3C9", "#A6A5AC", "#A8A8A8"}},
    {"ink3", "Texto gris: subtítulos, columnas, horas", "#8C8B93", {"#9C9BA2", "#8C8B93"}},
    {"ink4", "Texto apagado: deshabilitado, contadores", "#6E6D75", {"#7A7982", "#77767E", "#6E6D75", "#5E5D66"}},
    {"accent", "Acento (base = botón Allow): links, selección, elegido", "#443A91",
     {"#443A91", "#5243A8", "#5446B4", "#7060D0", "#9D8FE0", "#C5BBF4", "#A39DD0", "#DDDBEE", "#2A2552", "#25223B",
      "#1D1B2C", "#3A3466"}},
    {"switch", "Interruptores encendidos", "#4CC9EE", {}},
    {"ok", "Funciona: protección activa, firma válida, listo", "#4CC9EE", {"#4CC9EE", "#57CDEF", "#24586A", "#0D2A33"}},
    {"warn", "Pide atención", "#F2CB3F", {"#F2CB3F", "#5A4E26", "#1C1606"}},
    {"allow", "Permitir: botones, etiquetas y sugerencias", "#5ACB8B",
     {"#5ACB8B", "#3AA36B", "#26603F", "#133A27", "#0E2B1D"}},
    {"error", "Bloquear / error", "#F0645C", {"#F0645C", "#8A3A3E", "#6B2E31", "#4A2326", "#361B1D"}},
};

// Los tonos del interruptor encendido (theme.h), calculados dentro de «switch».
const QStringList kSwitchMembers = {"#4CC9EE", "#2A97BC", "#0D3542"};

QString norm(const QString &hex) { return hex.trimmed().toUpper(); }

const QHash<QString, QString> &memberRole() {
    static const QHash<QString, QString> table = [] {
        QHash<QString, QString> t;
        for (const auto &r : kRoles)
            for (const auto &m : r.members) t.insert(norm(m), QString::fromLatin1(r.id));
        return t;
    }();
    return table;
}

Data &state() {
    static Data d = factory();
    return d;
}

QHash<QString, QColor> &cache() {
    static QHash<QString, QColor> c;
    return c;
}

bool &factoryFlag() {
    static bool f = true;
    return f;
}

// El tono de fábrica «m» relativo al base de fábrica «b», puesto junto al base nuevo «n»: corre el tono, escala la
// saturación y conserva dónde cae la luz entre el base y el blanco (o el negro).
QColor derive(const QColor &m, const QColor &b, const QColor &n) {
    if (b == n) return m;
    float mh, ms, ml, bh, bs, bl, nh, ns, nl;
    m.getHslF(&mh, &ms, &ml);
    b.getHslF(&bh, &bs, &bl);
    n.getHslF(&nh, &ns, &nl);
    float h;
    if (nh < 0) h = mh < 0 ? 0 : mh;             // base nuevo gris puro: el tono no importa (saturación 0)
    else if (mh < 0 || bh < 0) h = nh;           // sin tono de partida: el del base nuevo
    else h = std::fmod(mh + (nh - bh) + 2.0f, 1.0f);
    float s = bs > 0.02f ? ms * ns / bs : ms + (ns - bs);
    s = std::clamp(s, 0.0f, 1.0f);
    float l;
    if (ml >= bl) l = bl >= 0.999f ? nl : nl + (ml - bl) * (1.0f - nl) / (1.0f - bl);
    else l = bl <= 0.001f ? nl : nl * ml / bl;
    l = std::clamp(l, 0.0f, 1.0f);
    return QColor::fromHslF(h, s, l);
}

void changed() {
    cache().clear();
    bool f = state().overrides.isEmpty();
    for (const auto &r : kRoles)
        if (state().bases.contains(r.id) && state().bases.value(r.id) != QColor(r.base)) f = false;
    factoryFlag() = f;
    emit Notifier::instance()->changed();
}

} // namespace

const QVector<Role> &roles() { return kRoles; }

const Role *role(const QString &id) {
    for (const auto &r : kRoles)
        if (id == QLatin1String(r.id)) return &r;
    return nullptr;
}

Data factory() {
    Data d;
    d.name = QStringLiteral("Violeta (fábrica)");
    for (const auto &r : kRoles) d.bases.insert(r.id, QColor(r.base));
    return d;
}

const Data &current() { return state(); }

void apply(const Data &data) {
    Data d = factory();
    d.name = data.name;
    d.liked = data.liked;
    for (auto it = data.bases.cbegin(); it != data.bases.cend(); ++it)
        if (role(it.key()) && it.value().isValid()) d.bases.insert(it.key(), it.value());
    d.overrides = data.overrides;
    state() = d;
    changed();
}

void setBase(const QString &roleId, const QColor &color) {
    if (!role(roleId) || !color.isValid()) return;
    state().bases.insert(roleId, color);
    changed();
}

void setOverride(const QString &roleId, const QString &hex, const QColor &color) {
    const QString key = roleId + '/' + norm(hex);
    if (color.isValid()) state().overrides.insert(key, color);
    else state().overrides.remove(key);
    changed();
}

QColor base(const QString &roleId) {
    const Role *r = role(roleId);
    if (!r) return {};
    return state().bases.value(roleId, QColor(r->base));
}

bool isFactory() { return factoryFlag(); }

QColor mapIn(const QString &roleId, const QString &hex) {
    const QString h = norm(hex);
    if (isFactory()) return QColor(h);
    const QString key = roleId + '/' + h;
    auto &c = cache();
    if (const auto it = c.constFind(key); it != c.cend()) return it.value();
    QColor out(h);
    if (const Role *r = role(roleId)) {
        const QColor fixed = state().overrides.value(key);
        out = fixed.isValid() ? fixed : derive(QColor(h), QColor(r->base), base(roleId));
    }
    c.insert(key, out);
    return out;
}

QColor map(const QString &hex) {
    const QString h = norm(hex);
    const QString roleId = memberRole().value(h);
    if (roleId.isEmpty()) return QColor(h);
    return mapIn(roleId, h);
}

QString hex(const QString &factoryHex) { return map(factoryHex).name(QColor::HexRgb).toUpper(); }

QString remapSheet(const QString &sheet) {
    static const QRegularExpression hexRe(QStringLiteral("#[0-9A-Fa-f]{6}(?![0-9A-Za-z_-])"));
    static const QRegularExpression rgbaRe(QStringLiteral("rgba\\(\\s*(\\d+)\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)\\s*,"));
    static const QRegularExpression roleRe(QStringLiteral("@color\\((\\w+)\\)"));
    QString s = sheet;
    if (!isFactory()) {
        QString out;
        qsizetype last = 0;
        for (auto it = hexRe.globalMatch(s); it.hasNext();) {
            const auto m = it.next();
            out += s.mid(last, m.capturedStart() - last) + hex(m.captured(0));
            last = m.capturedEnd();
        }
        s = out + s.mid(last);
        out.clear();
        last = 0;
        for (auto it = rgbaRe.globalMatch(s); it.hasNext();) {
            const auto m = it.next();
            const QColor c = map(QColor(m.captured(1).toInt(), m.captured(2).toInt(), m.captured(3).toInt())
                                     .name(QColor::HexRgb));
            out += s.mid(last, m.capturedStart() - last) +
                   QStringLiteral("rgba(%1,%2,%3,").arg(c.red()).arg(c.green()).arg(c.blue());
            last = m.capturedEnd();
        }
        s = out + s.mid(last);
    }
    // Después de los valores: el base que se pone acá ya es el actual.
    QString out;
    qsizetype last = 0;
    for (auto it = roleRe.globalMatch(s); it.hasNext();) {
        const auto m = it.next();
        const QColor c = base(m.captured(1));
        out += s.mid(last, m.capturedStart() - last) + (c.isValid() ? c.name(QColor::HexRgb).toUpper() : QString("#FF00FF"));
        last = m.capturedEnd();
    }
    return out + s.mid(last);
}

bool load(const QString &path, Data *out, QString *error) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        if (error) *error = f.errorString();
        return false;
    }
    QJsonParseError pe;
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &pe);
    if (!doc.isObject()) {
        if (error) *error = pe.errorString();
        return false;
    }
    const QJsonObject o = doc.object();
    Data d;
    d.name = o.value("name").toString();
    d.liked = o.value("liked").toBool();
    const QJsonObject colors = o.value("colors").toObject();
    for (auto it = colors.begin(); it != colors.end(); ++it) {
        const QColor c(it.value().toString());
        if (role(it.key()) && c.isValid()) d.bases.insert(it.key(), c);
    }
    const QJsonObject ov = o.value("overrides").toObject();
    for (auto it = ov.begin(); it != ov.end(); ++it) {
        const QColor c(it.value().toString());
        if (c.isValid() && it.key().contains('/')) d.overrides.insert(it.key().section('/', 0, 0) + '/' + norm(it.key().section('/', 1)), c);
    }
    *out = d;
    return true;
}

bool save(const QString &path, const Data &data, QString *error) {
    QJsonObject colors;
    for (const auto &r : kRoles) colors.insert(r.id, data.bases.value(r.id, QColor(r.base)).name(QColor::HexRgb).toUpper());
    QJsonObject ov;
    for (auto it = data.overrides.cbegin(); it != data.overrides.cend(); ++it)
        ov.insert(it.key(), it.value().name(QColor::HexRgb).toUpper());
    QJsonObject o{{"name", data.name}, {"liked", data.liked}, {"colors", colors}};
    if (!ov.isEmpty()) o.insert("overrides", ov);
    QSaveFile f(path);
    if (!f.open(QIODevice::WriteOnly)) {
        if (error) *error = f.errorString();
        return false;
    }
    f.write(QJsonDocument(o).toJson(QJsonDocument::Indented));
    if (!f.commit()) {
        if (error) *error = f.errorString();
        return false;
    }
    return true;
}

Notifier *Notifier::instance() {
    static Notifier n;
    return &n;
}

QStringList switchMembers() { return kSwitchMembers; }

} // namespace Gate::Palette
