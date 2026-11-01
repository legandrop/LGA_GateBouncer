#pragma once
// Firma Authenticode de un ejecutable: quién lo firmó, si la firma es válida.
// En orden: la firma embebida en el archivo; un catálogo de Windows que lo incluye (powershell.exe, certutil.exe); y
// para las apps de paquete (Store, MSIX) que viven en Program Files\WindowsApps, el editor del paquete. Muchas
// herramientas de Windows que descargan archivos quedan firmadas por Microsoft (curl.exe trae además firma embebida
// «Microsoft 3rd Party Application Component»), por eso los firmantes de Microsoft no admiten reglas de editor completo.
#include <string>

namespace gbe {

// Nombre del firmante (el CN del certificado, el que muestra Windows en «Firmas digitales») o vacío si el archivo
// no tiene ninguna de esas firmas válida. No consulta la red: sin revocación en línea.
std::wstring signerOf(const std::wstring &path);

// «All apps from» un firmante de Microsoft incluiría herramientas de Windows que descargan archivos.
bool publisherRuleAllowed(const std::wstring &signer);

} // namespace gbe
