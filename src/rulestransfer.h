#pragma once
// Exportar, importar y depurar reglas: el archivo .gbrules (JSON) y las cuentas que hace la ventana antes de mandarle
// algo al motor. Sin interfaz: los diálogos viven en firewallwindow.cpp. El motor valida de nuevo todo lo que recibe.
#include "engine/FirewallClient.h"
#include <QHash>
#include <QString>
#include <QVector>

namespace Gate::RulesTransfer {

// Una regla del archivo, ya validada. scope: "path", "app", "publisher" o "folder".
struct Rule {
    bool allow = true;
    QString scope, path, signer, name, destination;
};

// Una entrada que no se importa, con su motivo en el idioma de la interfaz.
struct Skipped {
    QString what, reason;
};

struct File {
    bool full = true; // "full" o "share"
    QString exported, app;
    bool hasProtection = false, ask = true, localNetwork = true;
    QVector<Rule> rules;
    QVector<Skipped> skipped;
};

constexpr qint64 MaxFileBytes = 8 * 1024 * 1024;
constexpr int MaxRules = 20000;

// «GateBouncer rules 2026-11-09.gbrules».
QString defaultFileName();
// La carpeta de los respaldos automáticos (%LOCALAPPDATA%\LGA\GateBouncer\Backups).
QString backupFolder();

// Las reglas permanentes que entran en cada modo: Full backup (todas) o Share (sólo por firma). Sin filas covered ni
// temporales.
QVector<FirewallClient::RuleItem> exportable(const QVector<FirewallClient::RuleItem> &rules, bool full);
// El archivo entero. Full lleva los dos interruptores de Protection.
QByteArray build(const QVector<FirewallClient::RuleItem> &rules, const FirewallClient::Status &status, bool full);
// Lee y valida (formato, versión, tamaño, cantidad, cada campo). error vacío si se pudo leer; lo que no sirve de cada
// regla queda en skipped.
bool read(const QString &fileName, File &out, QString &error);
bool parse(const QByteArray &bytes, File &out, QString &error);

// Lo que dice la regla, como FirewallClient::describe: «any version of node.exe from OpenJS Foundation to x.com».
QString describe(const Rule &rule);
// Nombre corto para la lista: el exe, el editor o la carpeta.
QString title(const Rule &rule);
QString title(const FirewallClient::RuleItem &rule);

// ---- Importar
enum class State { New, Same, Conflict, Skipped };
struct Planned {
    Rule rule;
    State state = State::New;
    QString yours;  // Conflict: cómo es la tuya
    QString reason; // Skipped: por qué
    QString note;   // New o Conflict: un aviso (el archivo no está en esta PC)
};
// Compara cada regla del archivo con las tuyas. folderExists / fileExists: lo que se averiguó del disco fuera del hilo
// de la interfaz (clave: la ruta en minúsculas).
QVector<Planned> plan(const File &file, const QVector<FirewallClient::RuleItem> &current,
                      const QHash<QString, bool> &folderExists, const QHash<QString, bool> &fileExists);
// Las rutas que hay que mirar en el disco antes de plan(): carpetas de reglas de carpeta y archivos de reglas de ruta.
void pathsToCheck(const File &file, QStringList &folders, QStringList &files);
// El pedido al motor: IMPORT (path, app, publisher) o FOLDER (carpeta). replace: el usuario tildó el choque.
QString commandFor(const Rule &rule, bool replace);
// La respuesta de IMPORT con keep: ya la tenías, o choca con la tuya.
bool isExists(const QString &error);
bool isConflict(const QString &error);

// ---- Depurar
enum Group { MissingProgram = 0, MissingFolder = 1, Installer = 2, Unused = 3 };
constexpr qint64 InstallerDays = 14, UnusedDays = 90;
struct Candidate {
    FirewallClient::RuleItem rule;
    Group group = Unused;
    qint64 lastUse = 0;
};
// Las rutas a mirar en el disco: archivos de reglas de ruta y carpetas de reglas de carpeta.
void cleanupPaths(const QVector<FirewallClient::RuleItem> &rules, QStringList &files, QStringList &folders);
// Sólo reglas permanentes; cada una en un solo grupo, el primero que le toca. exists: la ruta en minúsculas -> si está;
// una ruta que no figura (disco o servidor que no responde) no es candidata por «ya no existe».
QVector<Candidate> cleanup(const QVector<FirewallClient::RuleItem> &rules, const QHash<QString, qint64> &lastUse,
                           qint64 since, qint64 now, const QHash<QString, bool> &exists);
// Exe de instalador o actualizador: en Temp o Downloads, o con setup, install, update o uninst en el nombre.
bool installerLike(const QString &path, const QString &name);
// Mira en el disco cada ruta (hilo aparte): sí, no, o sin respuesta (unidad o servidor ausente: no figura).
QHash<QString, bool> checkPaths(const QStringList &files, const QStringList &folders);

} // namespace Gate::RulesTransfer
