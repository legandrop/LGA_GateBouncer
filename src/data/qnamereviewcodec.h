#pragma once
#include "contracts.h"
#include <QByteArray>
#include <QJsonObject>

namespace Gate::Data {
struct ReviewJsonPreflight { bool syntax = false, schema2Budget = false; int schema = -1; };
ReviewJsonPreflight scanReviewJson(const QByteArray &bytes);
bool budgetQNameReview(const ReviewDocument &document, qint64 *bound = nullptr);
QJsonObject qnameEvidenceJson(const QNameEvidence &evidence);
bool qnameEvidenceRead(const QJsonValue &value, QNameEvidence &evidence);
bool rebuildQNameReport(ReviewDocument &document);
} // namespace Gate::Data
