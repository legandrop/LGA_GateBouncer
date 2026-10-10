#include "InferenceEncoding.h"
#include "GeneralPayload.h"
namespace Gate::Assistance::General::Detail {
std::optional<std::string> inferenceJson(const Inference& i,const std::vector<Citation>& cs){
    // Contar escapes antes de asignar; el límite no depende del serializador de Qt.
    auto encode=[&](std::string* out){std::size_t size=0;bool good=true;
        auto raw=[&](std::string_view value){if(value.size()>3072-size){good=false;return;}size+=value.size();if(out)out->append(value);};
        auto text=[&](std::string_view value){raw("\"");for(char c:value){if(c=='"')raw("\\\"");else if(c=='\\')raw("\\\\");else raw(std::string_view(&c,1));}raw("\"");};
        raw("{\"possible_purpose\":");text(i.purpose);raw(",\"possible_network_reason\":");text(i.networkReason);raw(",\"caution\":");text(i.caution);
        raw(",\"possible_service\":");text(i.service);raw(",\"possible_impact\":");text(i.impact);raw(",\"conditional_advice\":");text(i.advice);
        raw(",\"certainty\":");text(i.possible?"possible":"unclear");raw(",\"source_ids\":[");bool first=true;
        for(auto id:i.sourceIds){if(!first)raw(",");first=false;raw(std::to_string(id));}raw("]}");return std::make_pair(good,size);};
    if(!safeText(i.purpose,512)||!safeText(i.networkReason,512)||!safeText(i.caution,512)||!safeText(i.service,256)||!safeText(i.impact,256)||!safeText(i.advice,256)||i.sourceIds.empty()||i.sourceIds.size()>3)return {};
    const auto count=encode(nullptr);if(!count.first)return {};
    std::string out;out.reserve(count.second);const auto written=encode(&out);
    if(!written.first||!General3ResponseContract::parseInference(out,cs))return {};
    return out;
}
}
