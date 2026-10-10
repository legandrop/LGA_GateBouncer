#include "ObservationReader.h"
#include <QElapsedTimer>
#include <QUuid>
#include <QStringList>
#include <cstring>
#include "websearch/DestinationEvidence.h"
#include <algorithm>
#include <set>

namespace Gate::Assistance::General {
namespace W=gb::wire;
namespace {
bool status(const W::Frame& frame,ObservationRead& out,bool administrative=false){
    W::iv::ServiceContext context;
    if(frame.type!=W::Type::Status||W::iv::decodeServiceContext(frame,context)!=W::Error::Ok||
        !context.engineBindingGeneration||W::get(frame,W::Tag::Capabilities)!=
            (W::ReadStatus|W::ObservedRead|(administrative?W::iv::AdministrativeObservedRead:0))||
        W::get(frame,W::Tag::EffectiveKnown)||W::get(frame,W::Tag::EffectiveRev)||
        !W::get(frame,W::Tag::ProfileGeneration))return false;
    out.service={context.serviceEpoch,context.boot,context.engineContext,context.engineBindingGeneration};
    out.profile=W::get(frame,W::Tag::ProfileGeneration);out.desired=W::get(frame,W::Tag::DesiredRev);
    return true;
}
bool sameContext(const ObservationRead& a,const ObservationRead& b){
    return a.service==b.service&&a.connection==b.connection&&a.profile==b.profile&&a.desired==b.desired;
}
std::optional<Destination> outbound(const W::iv::DestinationContext& tuple,std::uint64_t utcNanos){
    if(!tuple.present||tuple.direction!=1||!W::iv::valid(tuple)||!utcNanos)return {};
    const auto& bytes=tuple.remoteAddress;QString literal;
    if(tuple.family==4)literal=QString("%1.%2.%3.%4").arg(bytes[0]).arg(bytes[1]).arg(bytes[2]).arg(bytes[3]);
    else{QStringList groups;for(unsigned n=0;n<16;n+=2)groups<<QString::number((unsigned(bytes[n])<<8)|bytes[n+1],16);literal=groups.join(':');}
    const auto canonical=gatebouncer::websearch::canonicalAddress(literal);if(!canonical)return {};
    Destination d{canonical->toStdString(),tuple.remotePort,tuple.protocol,utcNanos/1000000};
    return validDestination(d)?std::optional<Destination>(std::move(d)):std::nullopt;
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
    if(source.readIntent()!=gb::ipc::ii::Client::ReadIntent::OwnAccount)return {};
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
std::optional<ObservationRead> ObservationReader::readPrincipal(gb::ipc::ii::Client& source,
    const PendingQuerySelection& selection,const ObservationRead* expected){
    if(source.readIntent()!=gb::ipc::ii::Client::ReadIntent::AdministrativeObservation ||
       W::zero(selection.owner)||!selection.revision)return {};
    const auto peer=source.readonlyPeer();
    if(!peer||peer->checkLive()!=gb::ipc::ii::ReadPeerState::Current||
       (expected&&expected->peer!=peer))return {};
    const auto connection=peer->connection();QElapsedTimer age;age.start();
    auto live=[&source,peer,connection]{const auto current=source.readonlyPeer();
        return current==peer&&current->connection()==connection&&peer->checkLive()==gb::ipc::ii::ReadPeerState::Current;};
    auto result=observe(source,selection.request,connection,live,[&age]{return age.elapsed();},expected,&selection);
    if(!result||!live())return {};result->peer=peer;return result;
}
std::optional<ObservationRead> ObservationReader::observe(gb::ipc::ii::SessionChannel& source,
    const Id128& request,const Id128& connection,std::function<bool()> live,
    std::function<std::int64_t()> age,const ObservationRead* expected,const PendingQuerySelection* principal){
    if(W::zero(request)||W::zero(connection)||!live||!age)return {};
    const auto selection=principal?std::optional<PendingQuerySelection>(*principal):std::nullopt;
    if(selection&&(selection->request!=request||W::zero(selection->owner)||!selection->revision))return {};
    // Copia exacta antes de callbacks; el caller no puede cambiar el scope a mitad de lectura.
    const auto prior=expected?std::optional<ObservationRead>(*expected):std::nullopt;
    auto ready=[&]{const auto elapsed=age();return elapsed>=0&&elapsed<5000&&live();};
    auto transact=[&](W::Frame query,W::Frame& reply,W::Type type){
        const auto random=QUuid::createUuid().toRfc4122();Id128 correlation{};std::memcpy(correlation.data(),random.data(),16);query.correlation=correlation;
        query.minor=3;query.connection=connection;
        return ready()&&source.transact(std::move(query),reply)&&ready()&&reply.type==type&&
            reply.minor==3&&reply.connection==connection&&reply.correlation==correlation&&W::iv::validate(reply)==W::Error::Ok;
    };
    ObservationRead initial;initial.connection=connection;
    W::Frame query,before;query.type=W::Type::GetStatus;
    if(!transact(query,before,W::Type::Status)||!status(before,initial,bool(selection))||
        (prior&&!sameContext(initial,*prior)))return {};
    W::iv::ObservedRecord selected;bool found=false;
    if(prior){
        if(bool(prior->principal)!=bool(selection) ||
           (selection&&(prior->principal->owner!=selection->owner||prior->record.revision!=selection->revision)))return {};
        if(prior->record.observed!=request||prior->record.state!=1||prior->record.display.projection!=2)return {};
        selected=prior->record;found=true;
    }else if(selection){
        selected.observed=request;selected.revision=selection->revision;found=true;
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
        W::value(W::Tag::ObservedRevision,selected.revision),W::value(W::Tag::SourceEpoch,initial.service.engineContext),
        W::value(W::Tag::DestinationContext,1,1)};
    if(selection){query.fields.push_back(W::value(W::Tag::AdministrativeMode,1,1));
        query.fields.push_back(W::value(W::Tag::PrincipalObservationOwner,selection->owner));
        std::sort(query.fields.begin(),query.fields.end(),[](const auto& a,const auto& b){return a.tag<b.tag;});}
    if(!transact(query,row,W::Type::ObservedRecord)||W::idValue(row,W::Tag::ServiceEpoch)!=initial.service.serviceEpoch||
        W::idValue(row,W::Tag::SourceEpoch)!=initial.service.engineContext)return {};
    const auto bytes=W::find(row,W::Tag::Records);std::vector<W::iv::ObservedRecord> records;
    if(!bytes||W::iv::unpack(bytes->bytes,1,records)!=W::Error::Ok||records[0].state!=1||
        records[0].display.projection!=2||records[0].display.path.empty()||
        (selection&&!prior ? records[0].observed!=request||records[0].revision!=selection->revision||
            records[0].source!=initial.service.engineContext : !sameRecord(records[0],selected,!prior)))return {};
    if(selection){
        const auto sid=W::find(row,W::Tag::SelectedPrincipalSid),target=W::find(row,W::Tag::OriginalTarget);
        W::iv::OriginalTarget parsed;
        if(W::get(row,W::Tag::AdministrativeMode)!=1||W::idValue(row,W::Tag::PrincipalObservationOwner)!=selection->owner||!sid||!target)return {};
        if(W::iv::unpackOriginalTarget(target->bytes,parsed)!=W::Error::Ok||parsed.packageMode!=records[0].package)return {};
        initial.principal=principalObservationContext(selection->owner,sid->bytes,target->bytes);
        if(!initial.principal)return {};initial.originalTarget=target->bytes;
        if(prior&&(initial.principal!=prior->principal||initial.originalTarget!=prior->originalTarget))return {};
        // Dos respuestas del productor, correlaciones diferentes, mismo grupo
        // completo. Un digest o snapshot presentado por GUI no suple este READ.
        W::Frame checked;
        if(!transact(query,checked,W::Type::ObservedRecord)||checked.fields.size()!=row.fields.size())return {};
        for(std::size_t i=0;i<row.fields.size();++i)
            if(checked.fields[i].tag!=row.fields[i].tag||checked.fields[i].required!=row.fields[i].required||
               checked.fields[i].bytes!=row.fields[i].bytes)return {};
    }else if(W::find(row,W::Tag::PrincipalObservationOwner)||W::find(row,W::Tag::AdministrativeMode))return {};
    W::iv::ServiceContext context;W::iv::DestinationContext tuple;
    const auto original=W::find(row,W::Tag::DestinationContext);
    if(!original||W::iv::decodeServiceContext(row,context)!=W::Error::Ok||
        !(PendingServiceContext{context.serviceEpoch,context.boot,context.engineContext,context.engineBindingGeneration}==initial.service)||
        W::get(row,W::Tag::ProfileGeneration)!=initial.profile||
        W::iv::unpackDestinationContext(original->bytes,tuple)!=W::Error::Ok)return {};
    initial.destinationContext=original->bytes;
    initial.destination=outbound(tuple,records[0].lastUtc);
    if(tuple.present&&tuple.direction==1&&!initial.destination)return {};
    if(prior&&(initial.destinationContext!=prior->destinationContext||initial.destination!=prior->destination))return {};
    initial.record=std::move(records[0]);
    W::Frame after;query.type=W::Type::GetStatus;query.fields.clear();ObservationRead final;final.connection=connection;
    if(!transact(query,after,W::Type::Status)||!status(after,final,bool(selection))||!sameContext(initial,final)||!ready())return {};
    return initial;
}
}
