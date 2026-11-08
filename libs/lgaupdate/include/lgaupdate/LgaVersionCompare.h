#pragma once

#include <QString>
#include <QVersionNumber>

/**
 * Comparacion de versiones LGA. **Fuente unica de verdad** para decidir si una version
 * publicada es mas nueva que la instalada.
 *
 * La regla es el zero-padding del minor: el versionado LGA escribe el minor con ancho fijo,
 * asi que `1.5` es `1.500` y NO `1.5 < 1.05`. Sin el padding, `QVersionNumber::fromString`
 * crudo da veredictos OPUESTOS sobre el mismo release —con local `0.985` y tag `v0.99`,
 * `[0,99] < [0,985]` dice que no hay update cuando si lo hay—. Un tag abreviado (`0.46` por
 * `0.460`) se tolera.
 *
 * Portado del `FM_VersionCompare` de FileManagerS3, que nacio justo de esa divergencia.
 */
namespace LGA::Update::VersionCompare {

/// Ancho del minor: 2 para `X.YY` (tools de Nuke), 3 para `X.YYY` (las apps Qt).
inline constexpr int kMinorWidthTwoDigits = 2;
inline constexpr int kMinorWidthThreeDigits = 3;

/**
 * Normaliza `X.Y` a `X.<minor con ancho fijo>`. Acepta el prefijo `v`.
 * @param okOut false si la version no tiene la forma `X.Y` (obligatorio: sin el no se puede
 *              distinguir un resultado vacio de uno valido).
 */
QString normalize(const QString &rawVersion, int minorWidth, bool *okOut);

/// Igual que `normalize()` pero devuelve el `QVersionNumber` ya parseado.
QVersionNumber toVersionNumber(const QString &rawVersion, int minorWidth, bool *okOut);

/**
 * @return <0, 0 o >0.
 * ⚠️ El `0` significa "iguales" Y TAMBIEN "no comparable": los out-params son OBLIGATORIOS
 * porque son la unica forma de distinguirlos.
 */
int compare(const QString &leftRawVersion,
            const QString &rightRawVersion,
            int minorWidth,
            bool *leftOkOut,
            bool *rightOkOut);

/**
 * @return true si `candidateVersion` es mas nueva que `referenceVersion`.
 *
 * Si alguna de las dos NO tiene la forma `X.Y` (por ejemplo un semver `1.2.3`), cae a
 * `QVersionNumber` para no rechazar esquemas que esta funcion no contempla. Ese fallback es
 * deliberado y esta ACA, en un solo lugar, en vez de repartido en cada llamador.
 */
bool isNewer(const QString &candidateVersion, const QString &referenceVersion, int minorWidth);

} // namespace LGA::Update::VersionCompare
