#include "lgaupdate/LgaVersionCompare.h"

#include <QRegularExpression>

namespace LGA::Update::VersionCompare {

namespace {

/// Saca el prefijo `v` y los espacios. `v0.46` y ` 0.46 ` son la misma version.
QString stripped(const QString &rawVersion)
{
    QString candidate = rawVersion.trimmed();
    if (candidate.startsWith(QLatin1Char('v'), Qt::CaseInsensitive)) {
        candidate = candidate.mid(1).trimmed();
    }
    return candidate;
}

bool parseMajorMinor(const QString &rawVersion, int *majorOut, QString *minorDigitsOut)
{
    const QString candidate = stripped(rawVersion);
    if (candidate.isEmpty()) {
        return false;
    }

    static const QRegularExpression kVersionRegex(QStringLiteral("^([0-9]+)\\.([0-9]+)$"));
    const QRegularExpressionMatch match = kVersionRegex.match(candidate);
    if (!match.hasMatch()) {
        return false;
    }

    bool majorOk = false;
    const int major = match.captured(1).toInt(&majorOk);
    const QString minorDigits = match.captured(2);
    if (!majorOk || minorDigits.isEmpty()) {
        return false;
    }

    if (majorOut) {
        *majorOut = major;
    }
    if (minorDigitsOut) {
        *minorDigitsOut = minorDigits;
    }
    return true;
}

} // namespace

QString normalize(const QString &rawVersion, int minorWidth, bool *okOut)
{
    if (okOut) {
        *okOut = false;
    }

    int major = 0;
    QString minorDigits;
    if (!parseMajorMinor(rawVersion, &major, &minorDigits)) {
        return QString();
    }

    if (minorDigits.size() < minorWidth) {
        // Zero-padding A LA DERECHA, que es lo que hace que 1.5 > 1.05 > 1.005: el minor se
        // escribe con ancho fijo, asi que un tag abreviado (0.46) vale por 0.460.
        minorDigits += QString(minorWidth - minorDigits.size(), QLatin1Char('0'));
    }

    if (okOut) {
        *okOut = true;
    }
    return QStringLiteral("%1.%2").arg(major).arg(minorDigits);
}

QVersionNumber toVersionNumber(const QString &rawVersion, int minorWidth, bool *okOut)
{
    bool normalizedOk = false;
    const QString normalized = normalize(rawVersion, minorWidth, &normalizedOk);
    if (!normalizedOk) {
        if (okOut) {
            *okOut = false;
        }
        return {};
    }

    qsizetype parsePosition = -1;
    const QVersionNumber version = QVersionNumber::fromString(normalized, &parsePosition);
    const bool versionOk = !version.isNull() && parsePosition == normalized.size();
    if (okOut) {
        *okOut = versionOk;
    }
    return versionOk ? version : QVersionNumber();
}

int compare(const QString &leftRawVersion,
            const QString &rightRawVersion,
            int minorWidth,
            bool *leftOkOut,
            bool *rightOkOut)
{
    bool leftOk = false;
    bool rightOk = false;
    const QVersionNumber left = toVersionNumber(leftRawVersion, minorWidth, &leftOk);
    const QVersionNumber right = toVersionNumber(rightRawVersion, minorWidth, &rightOk);

    if (leftOkOut) {
        *leftOkOut = leftOk;
    }
    if (rightOkOut) {
        *rightOkOut = rightOk;
    }
    if (!leftOk || !rightOk) {
        return 0;
    }
    return QVersionNumber::compare(left, right);
}

bool isNewer(const QString &candidateVersion, const QString &referenceVersion, int minorWidth)
{
    bool candidateOk = false;
    bool referenceOk = false;
    const int result =
        compare(candidateVersion, referenceVersion, minorWidth, &candidateOk, &referenceOk);

    if (candidateOk && referenceOk) {
        return result > 0;
    }

    // Fallback para esquemas que no son `X.Y` (por ejemplo un semver `1.2.3`): rechazarlos de
    // golpe dejaria a una app sin poder actualizarse nunca. Vive ACA para que siga habiendo un
    // solo lugar donde se decide si una version es mas nueva.
    //
    // Exige que NINGUNO de los dos sea `X.Y`. Si solo uno lo es, se compararian en ESCALAS
    // DISTINTAS: con minorWidth=3, `0.46` paddeado da [0,460] y el crudo `v0.46.1` da [0,46,1],
    // asi que 46 < 460 y un hotfix con tercer componente desapareceria en silencio.
    if (candidateOk != referenceOk) {
        return false;
    }

    const QVersionNumber candidate = QVersionNumber::fromString(stripped(candidateVersion));
    const QVersionNumber reference = QVersionNumber::fromString(stripped(referenceVersion));
    if (candidate.isNull() || reference.isNull()) {
        return false;
    }
    return QVersionNumber::compare(candidate, reference) > 0;
}

} // namespace LGA::Update::VersionCompare
