#include "GroundedParser.h"
#include "StrictJson.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <set>
namespace Gate::Assistance::Retrieval {
    std::optional<Inference> parseInference(const QByteArray &body,
                                            const std::vector<Source> &sources) {
        auto j = strictJson(body, 2048);
        if (!j || !j->exact({"possible_purpose", "possible_network_reason", "caution", "certainty",
                             "source_ids"}))
            return {};
        Inference i;
        QString *dest[] = {&i.text.possiblePurpose, &i.text.possibleNetworkReason, &i.text.caution};
        const char *names[] = {"possible_purpose", "possible_network_reason", "caution"};
        static const QRegularExpression forbidden(
            "(?:https?|ftp|file|data|javascript|mailto)\\s*:|www\\.|\\[.*\\]\\(|[`*_#]|<|>|malware["
            "- ]free|is safe|safe to allow|no malware|allow "
            "this|system\\s*:|assistant\\s*:",
            QRegularExpression::CaseInsensitiveOption);
        for (int k = 0; k < 3; ++k) {
            auto t = j->get(names[k])->text();
            if (!t || !safeText(*t, 512) || forbidden.match(*t).hasMatch())
                return {};
            *dest[k] = *t;
        }
        auto certainty = j->get("certainty")->text();
        if (!certainty || (*certainty != "possible" && *certainty != "unclear"))
            return {};
        i.text.certainty = *certainty == "possible" ? ExplanationText::Certainty::Possible
                                                    : ExplanationText::Certainty::Unclear;
        const auto *ids = j->get("source_ids");
        if (ids->kind != Json::Kind::Array || ids->array.size() > 3)
            return {};
        std::set<quint8> seen;
        for (const auto &v : ids->array) {
            auto n = v.integer();
            if (!n || *n < 1 || *n > 3 || !seen.insert(quint8(*n)).second)
                return {};
            bool exists = false;
            for (const auto &s : sources)
                if (s.id == *n)
                    exists = true;
            if (!exists)
                return {};
            i.sourceIds.push_back(quint8(*n));
        }
        if (i.text.certainty == ExplanationText::Certainty::Possible && i.sourceIds.empty())
            return {};
        return i;
    }
    std::optional<Inference> parseGroundedEnvelope(const QByteArray &body,
                                                   const std::vector<Source> &sources) {
        auto j = strictJson(body, 32768);
        if (!j || !j->exact({"choices"}))
            return {};
        auto *choices = j->get("choices");
        if (choices->kind != Json::Kind::Array || choices->array.size() != 1)
            return {};
        const auto &choice = choices->array.front();
        if (!choice.exact({"finish_reason", "message"}) ||
            choice.get("finish_reason")->text() != std::optional<QString>("stop"))
            return {};
        const auto *msg = choice.get("message");
        if (!msg->exact({"role", "content"}) ||
            msg->get("role")->text() != std::optional<QString>("assistant"))
            return {};
        auto t = msg->get("content")->text();
        return t ? parseInference(t->toUtf8(), sources) : std::nullopt;
    }
    QByteArray inferenceJson(const Inference &i) {
        QJsonArray ids;
        for (auto n : i.sourceIds)
            ids.append(n);
        return QJsonDocument(QJsonObject{{"possible_purpose", i.text.possiblePurpose},
                                         {"possible_network_reason", i.text.possibleNetworkReason},
                                         {"caution", i.text.caution},
                                         {"certainty",
                                          i.text.certainty == ExplanationText::Certainty::Possible
                                              ? "possible"
                                              : "unclear"},
                                         {"source_ids", ids}})
            .toJson(QJsonDocument::Compact);
    }
} // namespace Gate::Assistance::Retrieval
