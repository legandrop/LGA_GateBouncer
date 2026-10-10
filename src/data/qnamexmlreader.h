#pragma once
#include "contracts.h"
#include <QByteArray>

namespace Gate::Data {
enum class QNameReadGuard {
    None, TextUnits, StringUnits, TotalUnits, InvalidUtf16, JsonStringBytes,
    JsonContentBytes, MergedTextUnits, InvalidBudget
};
// Sólo cantidades: nunca conserva texto, nombres, atributos ni datos del XML.
struct QNameReadDiagnostic {
    QNameReadGuard guard = QNameReadGuard::None;
    qint64 textUnits = 0, textLimit = 0, stringUnitLimit = 32768;
    qint64 unitsBefore = 0, unitsAfter = 0, unitLimit = QNameBudget::unitLimit;
    qint64 jsonBefore = 0, jsonAfter = 0, jsonLimit = QNameBudget::byteLimit;
    qint64 stringCharge = 0, contentCharge = 48;
    qint64 nodes = 0, contentItems = 0, textChunks = 0, mergedUnits = 0;
};
struct QNameReadResult {
    bool accepted = false;
    QString error;
    QVector<QNameNode> nodes;
    QNameReadDiagnostic diagnostic;
};
QNameReadDiagnostic lastQNameReadDiagnostic() noexcept;
QNameReadResult readQNameXml(const QByteArray &bytes, const ImportLimits &limits = {});
std::optional<ExpandedName> resolveQName(const QString &lexical, const QMap<QString, QString> &bindings);
bool validateQNameEvidence(const QNameEvidence &evidence, const ImportLimits &limits = {});
bool projectQNameRoles(const QVector<QNameNode> &input, QNameEvidence &evidence);
QVector<int> qnameChildren(const QNameNode &node);
QString qnameCandidateId(const QNameEvidence &evidence, int node);
} // namespace Gate::Data
