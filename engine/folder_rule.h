#pragma once
// Reglas por carpeta («Trust this folder»): todo ejecutable dentro de una carpeta de confianza, y de sus subcarpetas,
// hereda la regla, también los que se compilen o copien ahí después. Las apps LGA en desarrollo no están firmadas y
// cada build en otra carpeta (un worktree nuevo) es otra ruta: sin esto, cada una vuelve a preguntar.
//
// Seguridad. La carpeta y cada ejecutable se comparan por su ruta final (GetFinalPathNameByHandleW, con el volumen
// por su GUID): un junction o symlink dentro de la carpeta que apunta afuera no extiende la confianza, una carpeta
// reemplazada por un enlace deja de coincidir y la regla queda atada al disco donde se creó. Una ruta informada que pasa
// por un enlace tampoco se cubre. No se puede confiar en la raíz de una unidad o de un volumen, ni en una unidad de red,
// extraíble u óptica, ni en carpetas del sistema o de usuario (Windows, Program Files, ProgramData, Users, cada perfil,
// AppData, Desktop, Documents, Temp, Downloads, la papelera), ni en una carpeta dentro de Windows, Temp o Downloads, ni
// en una que contenga cualquiera de ellas. Confiar en una carpeta es confiar en todo lo que pueda escribir en ella.
#include <string>
#include <vector>

namespace gbe {

struct FinalPath {
    std::wstring dos;    // «C:\Portable\LGA_DayTrace\build\DayTrace.exe», con las mayúsculas reales
    std::wstring volume; // «\\?\Volume{…}\Portable\LGA_DayTrace\build\DayTrace.exe»
};

// La ruta final de un archivo (directory=false) o carpeta (directory=true) que existe en un disco local fijo. Sigue
// los enlaces. Falso si no existe, es del otro tipo, está en la red o en un disco extraíble, o Windows no da su volumen.
// Sólo abre rutas con letra de unidad de un disco local fijo: nunca una ruta de red ni una pipe.
bool finalPathOf(const std::wstring &path, bool directory, FinalPath &out);

// La ruta con los nombres cortos 8.3 expandidos (sin seguir enlaces); la misma si no se puede.
std::wstring longPathOf(const std::wstring &path);
// El nombre de archivo de una ruta como lo comparan las reglas por carpeta: en minúsculas con la tabla invariante
// (también fuera del ASCII).
std::wstring folderNameKey(const std::wstring &path);

// La ruta que informó WFP es un archivo de un disco local y no pasa por enlaces (sí admite nombres cortos 8.3): su
// ruta final es la misma. Así lo que se cubre por carpeta es siempre el archivo que está de verdad ahí.
bool placeOf(const std::wstring &reportedPath, FinalPath &out);

// Ruta de volumen de un archivo dentro de la de una carpeta: prefijo exacto, con mayúsculas, seguido de «\».
bool volumePathInside(const std::wstring &fileVolume, const std::wstring &folderVolume);

// Precedencia entre dos reglas por carpeta que cubren el mismo archivo: la carpeta más profunda; en la misma carpeta,
// la que nombra el ejecutable; a igualdad, Block (si dos reglas no se ponen de acuerdo, se cierra).
bool folderRuleBeats(const std::wstring &volumeA, bool namedA, bool blockA, const std::wstring &volumeB, bool namedB,
                     bool blockB);

// Una carpeta protegida: no se puede confiar en ella ni en una carpeta que la contenga. subtree: tampoco en nada de
// adentro.
struct ProtectedFolder {
    std::wstring path; // ruta DOS
    std::wstring label; // cómo se la nombra en el mensaje, en inglés («Downloads», «Program Files»)
    bool subtree = false;
};
// Las de esta PC, con sus rutas finales cuando son enlaces: Windows, Program Files, ProgramData, Users, la papelera de
// cada disco y, de cada perfil (cuentas locales, de dominio y de Entra ID), el perfil, AppData, Desktop, Documents, Temp
// y Downloads, también si se movieron de lugar. Una de subárbol que es una unidad entera protege toda la unidad. Sólo
// guarda rutas con letra de unidad: el motor corre como SYSTEM y algunos valores los escribe el usuario.
std::vector<ProtectedFolder> protectedFolders();

// Un valor de la configuración de un usuario (sus carpetas, su TEMP) con las %VARIABLES% como las ve ese usuario: las de
// su sesión, las suyas y las de su perfil (home), y después las de la máquina. El motor corre como SYSTEM: con sus
// propias variables, %HOMEDRIVE%%HOMEPATH% o %USERNAME% darían otra carpeta. sid vacío: sólo las del perfil.
std::wstring expandForUser(const std::wstring &value, const std::wstring &sid, const std::wstring &home);

// Por qué no se puede confiar en esa carpeta (ruta DOS final), o vacío si se puede. Sin E/S: para las pruebas.
std::wstring folderProblem(const std::wstring &folder, const std::vector<ProtectedFolder> &protectedList);

// Valida y resuelve la carpeta de una regla nueva. Devuelve el motivo del rechazo, en inglés para la ventana, o vacío.
std::wstring resolveTrustedFolder(const std::wstring &input, FinalPath &folder);

// La ruta de volumen guardada de una regla por carpeta es de una carpeta («\\?\Volume{GUID}\algo»), no un volumen
// entero ni algo con «:». Para rechazar al cargar una línea editada a mano.
bool validFolderVolume(const std::wstring &volume);

// Un nombre de ejecutable para una regla por carpeta: vacío (todos) o un nombre de archivo sin carpeta, como lo da
// folderNameKey. Vacío y falso si no es válido.
bool normalizeFolderRuleName(const std::wstring &name, std::wstring &out);

} // namespace gbe
