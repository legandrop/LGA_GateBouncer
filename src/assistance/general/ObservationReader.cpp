#include "ObservationReader.h"
#include <QElapsedTimer>
#include <algorithm>
#include <set>

namespace Gate::Assistance::General {
namespace W=gb::wire;
namespace {
bool status(const W::Frame& frame,ObservationRead& out){
    W::iv::ServiceContext context;
    if(frame.type!=W::Type::Status||W::iv::decodeServiceContext(frame,context)!=W::Error::Ok||
        !context.engineBindingGeneration||W::get(frame,W::Tag::Capabilities)!=(W::ReadStatus|W::ObservedRead)||
        W::get(frame,W::Tag::EffectiveKnown)||W::get(frame,W::Tag::EffectiveRev)||
        !W::get(frame,W::Tag::ProfileGeneration))return false;
    out.service={context.serviceEpoch,context.boot,context.engineContext,context.engineBindingGeneration};
    out.profile=W::get(frame,W::Tag::ProfileGeneration);out.desired=W::get(frame,W::Tag::DesiredRev);
    return true;
}
bool sameContext(const ObservationRead& a,const ObservationRead& b){
    return a.service==b.service&&a.connection==b.connection&&a.profile==b.profile&&a.desired==b.desired;
}
}
bool ObservationReader::sameRecord(const W::iv::ObservedRecord& a,const W::iv::ObservedRecord& b,bool projected){
    auto left=a,right=b;
    if(projected){left.display.projection=right.display.projection=1;left.display.path.clear();right.display.path.clear();}
    W::Bytes x,y;
    return W::iv::pack({left},x)==W::Error::Ok&&W::iv::pack({right},y)==W::Error::Ok&&x==y;
}
std::optional<ObservationRead> ObservationReader::read(gb::ipc::ii::Client& source,const Id128& request,
    const ObservationRead* expected){
    const auto peer=source.readonlyPeer();
    if(!peer||peer->checkLive()!=gb::ipc::ii::ReadPeerState::Current||
        (expected&&expected->peer!=peer))return {};
    const auto connection=peer->connection();QElapsedTimer age;age.start();
    auto live=[&source,peer,connection]{const auto current=source.readonlyPeer();
        return current==peer&&current->connection()==connection&&
            peer->checkLive()==gb::ipc::ii::ReadPeerState::Current;};
    auto result=observe(source,request,connection,live,[&age]{return age.elapsed();},expected);
    if(!result||!live())return {};
    result->peer=peer;return result;
}
std::optional<ObservationRead> ObservationReader::observe(gb::ipc::ii::SessionChannel& source,
    const Id128& request,const Id128& connection,std::function<bool()> live,
    std::function<std::int64_t()> age,const ObservationRead* expected){
    if(W::zero(request)||W::zero(connection)||!live||!age)return {};
    // Copia exacta antes de callbacks; el caller no puede cambiar el scope a mitad de lectura.
    const auto prior=expected?std::optional<ObservationRead>(*expected):std::nullopt;
    auto ready=[&]{const auto elapsed=age();return elapsed>=0&&elapsed<5000&&live();};
    auto transact=[&](W::Frame query,W::Frame& reply,W::Type type){
        query.minor=3;query.connection=connection;
        return ready()&&source.transact(std::move(query),reply)&&ready()&&reply.type==type&&
            reply.minor==3&&reply.connection==connection&&W::iv::validate(reply)==W::Error::Ok;
    };
    ObservationRead initial;initial.connection=connection;
    W::Frame query,before;query.type=W::Type::GetStatus;
    if(!transact(query,before,W::Type::Status)||!status(before,initial)||
        (prior&&!sameContext(initial,*prior)))return {};
    W::iv::ObservedRecord selected;bool found=false;
    if(prior){
        if(prior->record.observed!=request||prior->record.state!=1||prior->record.display.projection!=2)return {};
        selected=prior->record;found=true;
    }else{
        Id128 snapshot{};std::uint64_t revision=0;std::uint32_t cursor=0;std::set<Id128> ids;bool terminal=false;
        // El límite de bytes puede producir páginas de una sola fila: no asumir dos páginas.
        for(unsigned page=0;page<65;++page){
            W::Frame rows;query.type=W::Type::ListObserved;
            query.fields={W::value(W::Tag::ServiceEpoch,initial.service.serviceEpoch),W::value(W::Tag::SnapshotId,snapshot),
                W::value(W::Tag::Cursor,cursor,4),W::value(W::Tag::Limit,32,2)};
            if(!transact(query,rows,W::Type::ObservedPage)||W::idValue(rows,W::Tag::ServiceEpoch)!=initial.service.serviceEpoch||
                W::idValue(rows,W::Tag::SourceEpoch)!=initial.service.engineContext||W::get(rows,W::Tag::Cursor)!=cursor||
                (!W::zero(snapshot)&&(W::idValue(rows,W::Tag::SnapshotId)!=snapshot||
                    W::get(rows,W::Tag::ObservedSnapshotRevision)!=revision)))return {};
            const auto bytes=W::find(rows,W::Tag::Records);std::vector<W::iv::ObservedRecord> records;
            if(!bytes||W::iv::unpack(bytes->bytes,W::get(rows,W::Tag::Count),records)!=W::Error::Ok||
                records.size()>64-ids.size())return {};
            for(const auto& row:records){
                if(row.display.projection!=1||!row.display.path.empty()||!ids.insert(row.observed).second)return {};
                if(row.observed==request){if(row.state!=1)return {};selected=row;found=true;}
            }
            snapshot=W::idValue(rows,W::Tag::SnapshotId);revision=W::get(rows,W::Tag::ObservedSnapshotRevision);
            const auto next=W::get(rows,W::Tag::NextCursor);
            if(next==UINT32_MAX){terminal=true;break;}
            if(records.empty()||next!=cursor+records.size()||ids.size()>=64)return {};
            cursor=std::uint32_t(next);
        }
        if(!terminal||!found)return {};
    }
    W::Frame row;query.type=W::Type::GetObservedRecord;
    query.fields={W::value(W::Tag::ServiceEpoch,initial.service.serviceEpoch),W::value(W::Tag::ObservedId,request),
        W::value(W::Tag::ObservedRevision,selected.revision),W::value(W::Tag::SourceEpoch,initial.service.engineContext)};
    if(!transact(query,row,W::Type::ObservedRecord)||W::idValue(row,W::Tag::ServiceEpoch)!=initial.service.serviceEpoch||
        W::idValue(row,W::Tag::SourceEpoch)!=initial.service.engineContext)return {};
    const auto bytes=W::find(row,W::Tag::Records);std::vector<W::iv::ObservedRecord> records;
    if(!bytes||W::iv::unpack(bytes->bytes,1,records)!=W::Error::Ok||records[0].state!=1||
        records[0].display.projection!=2||records[0].display.path.empty()||
        !sameRecord(records[0],selected,!prior))return {};
    initial.record=std::move(records[0]);
    W::Frame after;query.type=W::Type::GetStatus;query.fields.clear();ObservationRead final;final.connection=connection;
    if(!transact(query,after,W::Type::Status)||!status(after,final)||!sameContext(initial,final)||!ready())return {};
    return initial;
}
}
