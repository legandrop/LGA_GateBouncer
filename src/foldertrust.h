#pragma once
// Reglas por carpeta desde la ventana: qué carpeta proponer para una app y si se puede confiar en ella. La validación es
// la misma del motor (engine/folder_rule.cpp se compila también acá), leída con la cuenta del usuario; el motor la repite
// al crear la regla y es el que decide.
#include <QPair>
#include <QString>
#include <QVector>

namespace Gate::FolderTrust {

// La carpeta para proponer en el aviso: la del repositorio Git que contiene al exe (la que tiene la carpeta «.git»,
// también desde un worktree de adentro, donde «.git» es un archivo) o, fuera de un repositorio, la del worktree o la del
// exe. Vacío si no se puede confiar en ninguna. inRepository dice si fue un repositorio. Guarda el resultado unos
// segundos: se pide en cada repintado.
QString suggestion(const QString &exePath, bool *inRepository = nullptr);
// Por qué no se puede confiar en esa carpeta, en inglés (el texto del motor), o vacío si se puede.
QString problem(const QString &folder);
// Un texto de problem() (o de gbe::resolveTrustedFolder) en el idioma de la interfaz.
QString problemText(const QString &problem);
// Cómo se nombra la carpeta en las opciones: su último tramo («LGA_DayTrace»).
QString label(const QString &folder);
// La carpeta entera para un texto que se parte en renglones, sin cortar entre «C:» y el resto.
QString shown(const QString &folder);
// El exe está dentro de la carpeta (por texto, sólo para mostrar: el motor decide por la ruta final).
bool contains(const QString &folder, const QString &path);

// Opciones de «Apply to» del aviso y de Requests, en su orden, con el texto en el idioma de la interfaz: la primera es la
// que se preselecciona (y la que usan Allow y Block rápidos). Con firma: «This app, any version», «This file only» y, si se puede, «All apps from <editor>». Un exe
// dentro de un repositorio Git (también desde un worktree) suma «This app in LGA_DayTrace»: ese nombre de exe en todo el
// repositorio, sin mirar la firma («foldername:<carpeta>»). Sin firma va primero, porque cada build es otro archivo. No
// en modo por destino: esa app ya tiene reglas por servidor, que van antes que cualquier carpeta. La carpeta entera
// («folder:<carpeta>») no se ofrece acá: se agrega a mano desde Apps. FirewallClient::decide las convierte en reglas.
QVector<QPair<QString, QString>> scopeChoices(const QString &exePath, const QString &signer, bool perDestination);
// Una opción de carpeta: la regla es para la app entera, así que el destino no corre.
bool isFolderScope(const QString &scope);
// Qué cubre una opción de carpeta, con la carpeta entera, para mostrar debajo de lo elegido; vacío si no es de carpeta.
QString note(const QString &scope, const QString &exePath);

} // namespace Gate::FolderTrust
