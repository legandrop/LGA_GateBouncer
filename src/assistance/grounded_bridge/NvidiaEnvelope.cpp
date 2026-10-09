#include "NvidiaEnvelope.h"
#include "retrieval/StrictJson.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
namespace Gate::Assistance::GroundedBridge {
std::optional<QByteArray> normalizeNvidiaEnvelope(const QByteArray &body) {
    auto root=Retrieval::strictJson(body,32768);
    if(!root || root->kind!=Retrieval::Json::Kind::Object)return {};
    if(auto model=root->get("model");model && model->text()!=std::optional<QString>("nvidia/nemotron-3-ultra-550b-a55b"))return {};
    const auto *choices=root->get("choices");
    if(!choices || choices->kind!=Retrieval::Json::Kind::Array || choices->array.size()!=1)return {};
    const auto &choice=choices->array.front();
    const auto *finish=choice.get("finish_reason"),*message=choice.get("message");
    if(!finish || finish->text()!=std::optional<QString>("stop") || !message || message->kind!=Retrieval::Json::Kind::Object)return {};
    if(auto index=choice.get("index");index && index->integer()!=std::optional<quint64>(0))return {};
    const auto *role=message->get("role"),*content=message->get("content");
    if(!role || role->text()!=std::optional<QString>("assistant") || !content)return {};
    for(const char *name:{"refusal","tool_calls","function_call","reasoning_content","reasoning"}) {
        auto value=message->get(name);if(!value || value->kind==Retrieval::Json::Kind::Null)continue;
        if(value->text()!=std::optional<QString>(QString()))return {};
    }
    auto text=content->text();if(!text || text->isEmpty() || text->toUtf8().size()>2048)return {};
    // El parser grounded valida contenido/citas contra las fuentes reales del Coordinator.
    return QJsonDocument(QJsonObject{{"choices",QJsonArray{QJsonObject{{"finish_reason","stop"},{"message",QJsonObject{{"role","assistant"},{"content",*text}}}}}}}).toJson(QJsonDocument::Compact);
}
}
