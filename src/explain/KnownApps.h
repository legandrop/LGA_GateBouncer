#pragma once
// Catálogo de apps conocidas: decisiones revisadas a mano que viajan con la app (resources/catalog/known_apps.json).
// Sólo ayuda a decidir, como la explicación con IA: nunca concede ni bloquea nada por su cuenta.
#include <QString>

namespace Gate::KnownApps {

// Texto para el aviso si la app (firmante + nombre de archivo, y el destino si la entrada tiene uno) está en el
// catálogo; vacío si no. Sin firma no hay coincidencia: el nombre solo lo puede usar cualquiera. Si no está en el
// catálogo y es una app LGA (isLgaApp), «LGA app · usually Allow».
QString hint(const QString &signer, const QString &path, const QString &host);

// "allow" o "block" según lo que recomienda un texto de hint(); vacío si no recomienda nada.
QString suggestion(const QString &hint);

// App LGA: las que escribe y usa el dueño de esta PC. No están firmadas, así que se reconocen por la carpeta:
// instaladas en C:\Portable\LGA\<App>\, en C:\Program Files\LGA <App>\, o compiladas en una carpeta build* de un repo
// C:\Portable\LGA_<Repo>\. Se conectan para actualizarse o para funciones que necesitan internet.
bool isLgaApp(const QString &path);

} // namespace Gate::KnownApps
