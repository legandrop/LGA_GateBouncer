#pragma once
#include <QColor>
#include <QHash>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVector>

// Paleta de colores de la ventana y el aviso. Los colores del diseño (theme.h y las hojas de estilo) siguen escritos con
// sus valores de fábrica; cada uno pertenece a un grupo («rol») y se recalcula a partir del color base de ese grupo:
// conserva su distancia en tono, saturación y luz respecto del base de fábrica. Así un solo color por grupo mueve todos
// sus tonos (fondo, hover, borde, texto encima) y cada tono se puede ajustar aparte si hace falta.
namespace Gate::Palette {

struct Role {
    const char *id;
    const char *label;   // para el editor de desarrollo
    const char *base;    // color base de fábrica
    QStringList members; // los colores de fábrica que siguen a este grupo (incluye el base si se usa tal cual)
    bool byValue = true; // false: sus tonos se piden por nombre (@color(rol:#HEX), mapIn), no por valor
};

const QVector<Role> &roles();
const Role *role(const QString &id);

struct Data {
    QString name;
    bool liked = false;
    QHash<QString, QColor> bases;     // rol -> color base elegido (falta = el de fábrica)
    QHash<QString, QColor> overrides; // "rol/#RRGGBB" -> color fijo para ese tono
};

Data factory();
const Data &current();
void apply(const Data &data); // reemplaza la paleta y avisa
void setBase(const QString &roleId, const QColor &color);
void setOverride(const QString &roleId, const QString &hex, const QColor &color); // color inválido = sin ajuste
QColor base(const QString &roleId);
bool isFactory();

// El color actual de un color de fábrica. «mapIn» lo calcula dentro de un grupo dado (el interruptor usa el mismo cian
// que «funciona» pero tiene su propio grupo); «map» busca el grupo del color y deja igual el que no es de ninguno.
QColor map(const QString &hex);
QColor mapIn(const QString &roleId, const QString &hex);
QString hex(const QString &factoryHex); // map() como #RRGGBB

// Una hoja de estilo con los colores actuales: cada #RRGGBB y rgba(r,g,b,a) de fábrica, y «@color(rol)» (el base del
// grupo; los títulos y los rótulos del índice no comparten valor de fábrica con otros textos).
QString remapSheet(const QString &sheet);

bool load(const QString &path, Data *out, QString *error = nullptr);
bool save(const QString &path, const Data &data, QString *error = nullptr);

class Notifier final : public QObject {
    Q_OBJECT
  public:
    static Notifier *instance();
  signals:
    void changed();
};

} // namespace Gate::Palette
