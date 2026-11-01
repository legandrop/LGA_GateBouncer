#pragma once
// Firma Authenticode de un ejecutable: quién lo firmó, si la firma es válida.
// Sólo firmas embebidas en el archivo; los ejecutables de Windows firmados únicamente por catálogo (powershell.exe,
// certutil.exe) cuentan como sin firma. Algunos traen además firma embebida (curl.exe: «Microsoft 3rd Party
// Application Component»), por eso los firmantes de Microsoft no admiten reglas de editor completo.
#include <string>

namespace gbe {

// Nombre del firmante (el CN del certificado, el que muestra Windows en «Firmas digitales») o vacío si el archivo
// no tiene una firma embebida válida. No consulta la red: sin revocación en línea.
std::wstring signerOf(const std::wstring &path);

// «All apps from» un firmante de Microsoft incluiría herramientas de Windows que descargan archivos.
bool publisherRuleAllowed(const std::wstring &signer);

} // namespace gbe
