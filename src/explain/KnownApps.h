#pragma once
// Catálogo de apps conocidas: decisiones revisadas a mano que viajan con la app (resources/catalog/known_apps.json).
// Sólo ayuda a decidir, como la explicación con IA: nunca concede ni bloquea nada por su cuenta.
#include <QString>

namespace Gate::KnownApps {

// Texto para el aviso si la app (firmante + nombre de archivo, y el destino si la entrada tiene uno) está en el
// catálogo; vacío si no. Sin firma no hay coincidencia: el nombre solo lo puede usar cualquiera.
QString hint(const QString &signer, const QString &path, const QString &host);

} // namespace Gate::KnownApps
