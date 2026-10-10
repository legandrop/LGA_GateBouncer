#pragma once
#include "../general/PendingPresentationContext.h"
#include "../../engine/OrdinaryDecisionClient.h"
#include <QUuid>
#include <type_traits>
#include <utility>

namespace Gate::Assistance::Ui {
// Copia descriptiva del aviso actual. Su Current nunca concede control del motor.
struct ObservationSelection {
    General::PendingServiceContext service;
    gb::wire::Id connection{};
    gb::wire::iv::ObservedRecord record;
    std::uint64_t profile=0,desired=0,selection=0;
    std::optional<General::PrincipalObservationContext> principal;
    bool operator==(const ObservationSelection& other) const {
        gb::wire::Bytes left,right;
        return service==other.service&&connection==other.connection&&profile==other.profile&&
            desired==other.desired&&selection==other.selection&&principal==other.principal&&
            gb::wire::iv::pack({record},left)==gb::wire::Error::Ok&&
            gb::wire::iv::pack({other.record},right)==gb::wire::Error::Ok&&left==right;
    }
    bool matches(const General::FullBinding& binding) const {
        const auto request=QUuid::fromRfc4122(QByteArray(reinterpret_cast<const char*>(record.observed.data()),16));
        return binding.requestId==request.toString().toStdString()&&binding.applicationToken==record.binding&&
            binding.snapshotRevision==record.revision&&binding.serviceEpoch==service.engineBindingGeneration&&
            binding.generation==profile;
    }
    bool matches(const General::PendingPresentationContext& pending) const {
        return pending.service()==service&&pending.request()==record.observed&&pending.selector()==record.binding&&
            pending.requestRevision()==record.revision&&pending.selectorRevision()==record.revision&&pending.profileGeneration()==profile&&
            principal==pending.principal();
    }
};
namespace Detail {
template<class T,class=void>struct HasObservationContext:std::false_type{};
template<class T>struct HasObservationContext<T,std::void_t<decltype(std::declval<const T&>().observationContext())>>:std::true_type{};
}
template<class T>std::optional<ObservationSelection> currentObservation(const T* source){
    if constexpr(!Detail::HasObservationContext<T>::value){
        // La base sin accessor auténtico permanece indisponible, sin stub de producto.
        Q_UNUSED(source);return {};
    }else{
        if(!source||!source->current()||!source->visible())return {};
        const auto before=source->observationContext();const auto row=source->observed();
        if(!before||!row||row->state!=1||!gb::wire::iv::valid(*row)||
            row->source!=before->service.engineContext||gb::wire::zero(before->connection)||
            !before->profile||!before->selection||before->observedRevision!=row->revision)return {};
        General::PendingServiceContext context{before->service.serviceEpoch,before->service.boot,
            before->service.engineContext,before->service.engineBindingGeneration};
        if(!General::validPendingService(context))return {};
        ObservationSelection result{context,before->connection,*row,before->profile,before->desired,before->selection};
        if(before->administrative){
            result.principal=General::principalObservationContext(before->connection,before->selectedSid,before->originalTarget);
            if(!result.principal)return {};
        }
        const auto after=source->observationContext();const auto second=source->observed();
        if(!after||!second||!source->current()||!source->visible()||after->observedRevision!=second->revision)return {};
        ObservationSelection checked{{after->service.serviceEpoch,after->service.boot,after->service.engineContext,
            after->service.engineBindingGeneration},after->connection,*second,after->profile,after->desired,after->selection};
        if(after->administrative){
            checked.principal=General::principalObservationContext(after->connection,after->selectedSid,after->originalTarget);
            if(!checked.principal)return {};
        }
        return result==checked?std::optional<ObservationSelection>(std::move(result)):std::nullopt;
    }
}
}
