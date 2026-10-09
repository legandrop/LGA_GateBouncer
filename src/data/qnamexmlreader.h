#pragma once
#include "contracts.h"
#include <QByteArray>

namespace Gate::Data {
struct QNameReadResult {
    bool accepted = false;
    QString error;
    QVector<QNameNode> nodes;
};
QNameReadResult readQNameXml(const QByteArray &bytes, const ImportLimits &limits = {});
std::optional<ExpandedName> resolveQName(const QString &lexical, const QMap<QString, QString> &bindings);
bool validateQNameEvidence(const QNameEvidence &evidence, const ImportLimits &limits = {});
bool projectQNameRoles(const QVector<QNameNode> &input, QNameEvidence &evidence);
QVector<int> qnameChildren(const QNameNode &node);
QString qnameCandidateId(const QNameEvidence &evidence, int node);
} // namespace Gate::Data
