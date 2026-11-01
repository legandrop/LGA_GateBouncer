#pragma once
// Reglas de firewall de NetLimiter (nl_settings.xml) que se pueden pasar al motor sin driver tal cual: una regla
// activa, saliente (o en ambos sentidos), Allow o Deny, cuyo filtro es sólo «la app es esta ruta». Las demás (con
// destinos, puertos, zonas, horarios, Ask o sólo entrantes) se listan con el motivo y no se importan: GateBouncer
// no tiene cómo representarlas igual, y una aproximación permitiría o bloquearía de más.
#include <QIODevice>
#include <QString>
#include <QVector>

namespace Gate {

struct NetLimiterRule {
    QString path;
    QString ruleName;   // nombre del filtro en NetLimiter
    QString action;     // la acción tal como está en NetLimiter: Allow, Deny, Ask
    bool allow = true;
    bool importable = false;
    QString reason;     // por qué no se importa (vacío si se importa)
};

class NetLimiterRules {
  public:
    static QVector<NetLimiterRule> read(QIODevice &input, QString &error);
    // Carpeta donde NetLimiter 5 guarda su configuración, si existe en esta PC.
    static QString defaultFolder();
};

} // namespace Gate
