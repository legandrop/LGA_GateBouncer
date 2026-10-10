#include "runtime_ii.h"
#include "principal_actor_vi.h"
#include "../src/appidentity/AppIdentity.h"
#include <algorithm>
#include <cstring>

namespace gb::decisions {
namespace {
constexpr std::size_t PendingLimit = 64, PendingBytesLimit = 4 * 1024 * 1024;
bool sameImage(const BY_HANDLE_FILE_INFORMATION &a, const BY_HANDLE_FILE_INFORMATION &b) noexcept {
    return a.dwVolumeSerialNumber == b.dwVolumeSerialNumber &&
        a.nFileIndexHigh == b.nFileIndexHigh && a.nFileIndexLow == b.nFileIndexLow &&
        a.nFileSizeHigh == b.nFileSizeHigh && a.nFileSizeLow == b.nFileSizeLow &&
        CompareFileTime(&a.ftLastWriteTime, &b.ftLastWriteTime) == 0;
}
Frame ordered(Frame frame) {
    std::sort(frame.fields.begin(), frame.fields.end(), [](const auto &a, const auto &b) { return a.tag < b.tag; });
    return frame;
}
Bytes displayText(const std::u16string &text, std::size_t cap) {
    if (text.empty()) return {};
    const auto n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        reinterpret_cast<const wchar_t *>(text.data()), static_cast<int>(text.size()),
        nullptr, 0, nullptr, nullptr);
    if (n <= 0 || static_cast<std::size_t>(n) > cap) return {};
    Bytes bytes(static_cast<std::size_t>(n));
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        reinterpret_cast<const wchar_t *>(text.data()), static_cast<int>(text.size()),
        reinterpret_cast<char *>(bytes.data()), n, nullptr, nullptr) != n) return {};
    return bytes;
}
}
struct NativeRuntime::PrincipalObservation {
    wire::iv::ObservedRecord row;
    wire::iv::Display fullDisplay;
    principal::ByteView target;
    Digest digest{};
    std::shared_ptr<allnative::NativeSource> source;
    std::optional<allnative::NativeCopiedMetadata> event;
    std::optional<allnative::NativeProof> proof;
    std::uint64_t profile = 0;
    std::size_t charged = 0;
    Frame activityAttempt;
    Frame pendingAttempt;
    std::uint64_t imageJob=0,imageDeadline=0;
    bool imageGap=false;
};
bool NativeRuntime::principalEventsReady() const noexcept {
    return principalEvents_.ready() && principalMode_ && !principalWriteFault_ &&
        principalSource_ && principalCatalog_ && profile_.value().state == 1 &&
        principalSource_->stage() == allnative::Stage::Active &&
        principalSource_->source_.health().health == gatebouncer::service::windows::allapps::Health::Ready &&
        principalEvents_.profile() == profile_.value().generation &&
        principalEvents_.context().serviceEpoch == epoch_ && principalEvents_.context().boot == boot_ &&
        principalEvents_.context().engineContext == principalSource_->binding_->epoch &&
        principalEvents_.context().engineBindingGeneration == principalSource_->binding_->generation;
}
bool NativeRuntime::principalTrafficReady() const noexcept {
    return principalTrafficAcquired_ && principalEventsReady();
}
bool NativeRuntime::principalProcessReady() const noexcept {
    return principalProcessAcquired_ && principalEventsReady();
}
bool NativeRuntime::processBudget(std::size_t extra,std::size_t prior) const noexcept {
    if(prior>principalPendingBytes_)return false;
    const auto pending=principalPendingBytes_-prior;
    // Reservar íntegra la cuota legacy de outcomes: evidencia de imagen no consume la admisión causal.
    const std::size_t charges[]={pending,principalTrafficBytes_,principalProcessBytes_,principalRetiredBytes_,
        principalImageBaseCharge_,principalImageJobCharge_,principalPendingAppBytes_,512*1024,extra};
    std::size_t total=0;
    for(const auto charge:charges) {if(charge>PendingBytesLimit-total)return false;total+=charge;}
    return true;
}
std::size_t NativeRuntime::activityCauseBytes(const allnative::ClassifierCause &cause) noexcept {
    return sizeof(cause)+128+cause.process_.image.native().capacity()*sizeof(wchar_t)+
        cause.token_.account.capacity()+cause.token_.logon.capacity();
}
bool NativeRuntime::principalEventCurrent(const PrincipalPeer &peer, const Frame &event) noexcept {
  try {
    if (!principalPeerCurrent(peer) || peer.profile != principalEvents_.profile()) return false;
    wire::iv::ServiceContext actual;
    if (wire::iv::decodeServiceContext(event, actual) != Error::Ok ||
        !NativeActivityRing::same(actual, principalEvents_.context()) ||
        get(event, Tag::ProfileGeneration) != peer.profile) return false;
    const auto source = principalSource_;
    const auto catalog = principalCatalog_;
    const auto current = readServiceContext(); // READ/reconcile real, también entre frames del mismo lote.
    const bool live = source == principalSource_ && catalog == principalCatalog_ &&
        NativeActivityRing::same(current, actual) && principalEventsReady();
    if (!live) principalEvents_.lose();
    if (!principalPeerCurrent(peer)) return false;
    // El único frame admisible al perder fuente es Gap, con contexto original.
    return live || (event.type == Type::ObservationGap && !principalEvents_.ready());
  } catch (...) { principalEvents_.fail(); return false; }
}
Frame NativeRuntime::subscribePrincipalEvents(const Frame &request, const std::shared_ptr<PrincipalPeer> &peer) {
    const auto retainedSource = principalSource_;
    const auto retainedCatalog = principalCatalog_;
    const auto context = readServiceContext();
    if (!peer || !principalPeerCurrent(*peer) || !principalEventsReady() ||
        retainedSource != principalSource_ || retainedCatalog != principalCatalog_ ||
        !NativeActivityRing::same(context, principalEvents_.context()) ||
        idValue(request, Tag::SourceEpoch) != context.engineContext ||
        get(request, Tag::ProfileGeneration) != peer->profile) return principalError(Error::Stale);
    const auto cursor = get(request, Tag::AfterEventSeq);
    const auto mask=principalTrafficReady() ? 7u : 3u;
    if(get(request,Tag::EventMask)!=mask)return principalError(Error::Stale);
    if (cursor > principalEvents_.latest()) return principalError(Error::Stale);
    auto ack = principalEvents_.frame(Type::SubscriptionAck);
    for (auto &field : ack.fields)
        if (field.tag == Tag::EventSeq) field = value(Tag::EventSeq, cursor ? cursor : principalEvents_.latest());
    ack.fields.push_back(value(Tag::EventMask, mask, 4));
    if(peer->subscriptionMask==3 && mask!=3 && principalMask3Subscribers_)--principalMask3Subscribers_;
    if(peer->subscriptionMask!=3 && mask==3)++principalMask3Subscribers_;
    peer->subscriptionMask=mask; // Reservado antes del send; close libera incluso un ACK fallido.
    return ordered(std::move(ack));
}
void NativeRuntime::publishPrincipalAuthorization(PrincipalOutcome &outcome) noexcept {
  try {
    if (outcome.activityCompleted || outcome.activityAttempt.type != Type::Attempt ||
        !get(outcome.activityAttempt, Tag::EventSeq) || outcome.scope < 3 ||
        outcome.result.state != State::Applied || outcome.result.error != Error::Ok ||
        !outcome.result.durable || !outcome.result.appliedReal) return;
    outcome.activityCompleted = true; // El fallo de historia nunca repite el efecto aplicado.
    wire::iv::ServiceContext original;
    if (wire::iv::decodeServiceContext(outcome.activityAttempt, original) != Error::Ok ||
        !principalEventsReady() || !NativeActivityRing::same(original, principalEvents_.context()) ||
        outcome.profile != principalEvents_.profile() ||
        outcome.scoped.session != outcome.activitySession || outcome.scoped.cause != outcome.activityCause ||
        outcome.scoped.version != GB_CLASSIFIER_VERSION || outcome.scoped.bytes != sizeof(outcome.scoped) ||
        !outcome.scoped.revision || outcome.scoped.action < 1 || outcome.scoped.action > 2 ||
        outcome.scoped.revision != outcome.result.desired || outcome.scoped.scope != outcome.scope ||
        get(outcome.activityAttempt,Tag::Source) != 2) {
        principalEvents_.lose(); return;
    }
    Frame commandFrame;
    if (wire::decode(outcome.payload,commandFrame)!=Error::Ok || commandFrame.type!=Type::CommitFuturePolicy ||
        idValue(commandFrame,Tag::SourceEpoch)!=original.engineContext ||
        idValue(commandFrame,Tag::CaptureBindingId)!=idValue(outcome.activityAttempt,Tag::CaptureBindingId) ||
        get(commandFrame,Tag::ProfileGeneration)!=outcome.profile ||
        get(commandFrame,Tag::Decision)!=outcome.scoped.action || get(commandFrame,Tag::ScopeKind)!=outcome.scope) {
        principalEvents_.lose(); return;
    }
    auto event = outcome.activityAttempt; event.type = Type::Authorization;
    GB_ACTIVITY_SNAPSHOT activity{};
    const auto source=principalSource_;const auto catalog=principalCatalog_;
    const auto current=readServiceContext();
    const bool originalSource=source==principalSource_ && catalog==principalCatalog_ &&
        source==outcome.activitySource && catalog==outcome.activityCatalog && principalEventsReady() &&
        NativeActivityRing::same(current,original);
    const bool acquired=originalSource && outcome.activityOwner && principalClassifier_ &&
        outcome.activityOwner->owner_==principalClassifier_ &&
        principalClassifier_->activity(*outcome.activityOwner,outcome.scoped,backend_.engine_,activity);
    if(!originalSource) {principalEvents_.lose();return;}
    const auto after=readServiceContext();
    if(source!=principalSource_ || catalog!=principalCatalog_ || !principalEventsReady() ||
       !NativeActivityRing::same(after,original)) {principalEvents_.lose();return;}
    std::uint64_t authorizedUtc=0;
    if(acquired && (activity.flags & GB_ACTIVITY_AUTH_UTC))ii::filetimeUtc(activity.authorizedUtc,authorizedUtc);
    if(acquired)principalTrafficAcquired_=true;
    for (auto &field : event.fields) {
        if (field.tag == Tag::Timestamp) field = value(Tag::Timestamp, authorizedUtc);
        if (field.tag == Tag::Presence) field = value(Tag::Presence, (get(event, Tag::Presence) & ~1ull) | (authorizedUtc ? 1ull : 0ull));
    }
    Id command{}; std::copy(std::begin(outcome.scoped.command), std::end(outcome.scoped.command), command.begin());
    if (commandFrame.correlation!=command) { principalEvents_.lose(); return; }
    event.fields.insert(event.fields.end(), {value(Tag::CommandId, command),
        value(Tag::AttemptLink, wire::iv::attemptLink(get(outcome.activityAttempt, Tag::EventSeq))),
        value(Tag::EffectiveRev, outcome.scoped.revision), value(Tag::Decision, outcome.scoped.action, 1),
        value(Tag::ScopeKind, outcome.scope, 1), value(Tag::Durable, 1, 1), value(Tag::ProofState, 2, 1)});
    if (principalEvents_.append(std::move(event)) != Error::Ok) {principalEvents_.lose();return;}
    if(outcome.scoped.action!=2 || !acquired)return;
    if(activity.flags & GB_ACTIVITY_INCOMPLETE) {principalEvents_.discontinuity();return;}
    try {
    const auto charged=sizeof(PrincipalTrafficWatcher)+128+NativeActivityRing::bytes(outcome.activityAttempt)+outcome.activityCharge;
    if(principalTraffic_.size()>=64 || !processBudget(charged)) {
        principalEvents_.discontinuity();return;
    }
    auto watcher=std::make_shared<PrincipalTrafficWatcher>();
    watcher->attempt=outcome.activityAttempt;watcher->source=source;watcher->catalog=catalog;
    watcher->cause=outcome.activityOwner;watcher->decision=outcome.scoped;
    watcher->charged=sizeof(PrincipalTrafficWatcher)+128+NativeActivityRing::bytes(watcher->attempt)+outcome.activityCharge;
    if(!processBudget(watcher->charged)) {principalEvents_.discontinuity();return;}
    const auto retainedCharge=watcher->charged;
    if(!principalTraffic_.emplace(command,std::move(watcher)).second) {principalEvents_.discontinuity();return;}
    principalTrafficBytes_+=retainedCharge;
    } catch(...) {principalEvents_.discontinuity();} // Ya insertada Auth: asignar watcher no la suprime.
  } catch (...) { principalEvents_.fail(); }
}
void NativeRuntime::pollPrincipalTraffic() noexcept {
  try {
    if(!principalTrafficReady() || principalMask3Subscribers_)return;
    const auto limit=std::min<std::size_t>(8,principalTraffic_.size());
    for(std::size_t work=0;work<limit && !principalTraffic_.empty();++work) {
        auto it=principalTraffic_.upper_bound(principalTrafficCursor_);
        if(it==principalTraffic_.end())it=principalTraffic_.begin();
        const auto command=it->first;const auto watcher=it->second;principalTrafficCursor_=command;
        auto retire=[&]() {
            auto present=principalTraffic_.find(command);
            if(present!=principalTraffic_.end() && present->second==watcher) {
                principalTrafficBytes_-=watcher->charged;principalTraffic_.erase(present);
            }
            if(principalEvents_.ready())principalEvents_.discontinuity();
        };
        wire::iv::ServiceContext original;
        if(wire::iv::decodeServiceContext(watcher->attempt,original)!=Error::Ok) {retire();continue;}
        const auto current=readServiceContext(); // No Ready cacheado, también sin nuevos paquetes.
        auto present=principalTraffic_.find(command);
        if(present==principalTraffic_.end() || present->second!=watcher)continue;
        if(!principalTrafficReady() || principalSource_!=watcher->source || principalCatalog_!=watcher->catalog ||
           !NativeActivityRing::same(original,current) || !principalClassifier_ || !watcher->cause ||
           watcher->cause->owner_!=principalClassifier_) {retire();continue;}
        GB_ACTIVITY_SNAPSHOT snapshot{};
        if(!principalClassifier_->activity(*watcher->cause,watcher->decision,backend_.engine_,snapshot) ||
           (snapshot.flags & GB_ACTIVITY_INCOMPLETE)) {retire();continue;}
        const auto after=readServiceContext();
        present=principalTraffic_.find(command);
        if(present==principalTraffic_.end() || present->second!=watcher)continue;
        if(watcher->source!=principalSource_ || watcher->catalog!=principalCatalog_ || !principalTrafficReady() ||
           !NativeActivityRing::same(after,original)) {retire();continue;}
        bool broken=false;
        for(unsigned direction=1;direction<=2 && !broken;++direction) {
            const bool outbound=direction==1;
            const auto flag=outbound ? GB_ACTIVITY_OUTBOUND : GB_ACTIVITY_INBOUND;
            const auto bytes=outbound ? snapshot.outboundBytes : snapshot.inboundBytes;
            const auto packets=outbound ? snapshot.outboundPackets : snapshot.inboundPackets;
            const auto utc=outbound ? snapshot.outboundUtc : snapshot.inboundUtc;
            const auto revision=outbound ? snapshot.outboundRevision : snapshot.inboundRevision;
            auto &last=watcher->published;
            const auto beforeBytes=outbound ? last.outboundBytes : last.inboundBytes;
            const auto beforePackets=outbound ? last.outboundPackets : last.inboundPackets;
            const auto beforeUtc=outbound ? last.outboundUtc : last.inboundUtc;
            const auto beforeRevision=outbound ? last.outboundRevision : last.inboundRevision;
            if(bytes<beforeBytes || packets<beforePackets || utc<beforeUtc || revision<beforeRevision ||
               (!(snapshot.flags & flag) && (last.flags & flag))) {broken=true;break;}
            if(packets==beforePackets) {
                if(bytes!=beforeBytes || utc!=beforeUtc || revision!=beforeRevision)broken=true;
                continue;
            }
            std::uint64_t unixUtc=0;
            if(!(snapshot.flags & flag) || revision<=beforeRevision || !ii::filetimeUtc(utc,unixUtc) || !unixUtc) {
                broken=true;break;
            }
            auto event=watcher->attempt;event.type=Type::Traffic;
            for(auto &field:event.fields) {
                if(field.tag==Tag::Timestamp)field=value(Tag::Timestamp,unixUtc);
                if(field.tag==Tag::Presence)field=value(Tag::Presence,3|(get(watcher->attempt,Tag::Presence)&4));
            }
            event.fields.insert(event.fields.end(),{value(Tag::CommandId,command),
                value(Tag::AttemptLink,wire::iv::attemptLink(get(watcher->attempt,Tag::EventSeq))),
                value(Tag::ByteCount,bytes-beforeBytes),value(Tag::PacketCount,packets-beforePackets),
                value(Tag::PacketDirection,direction,1),value(Tag::EffectiveRev,watcher->decision.revision),
                value(Tag::ScopeKind,watcher->decision.scope,1),value(Tag::Durable,1,1),value(Tag::ProofState,2,1)});
            if(principalEvents_.append(std::move(event))!=Error::Ok) {broken=true;break;}
            // Sólo la inserción admite avance; READ repetido produce cero eventos.
            if(outbound) {last.outboundBytes=bytes;last.outboundPackets=packets;last.outboundUtc=utc;last.outboundRevision=revision;}
            else {last.inboundBytes=bytes;last.inboundPackets=packets;last.inboundUtc=utc;last.inboundRevision=revision;}
            last.flags|=flag;
        }
        if(broken)retire();
    }
  } catch(...) {
    principalTraffic_.clear();principalTrafficBytes_=0;
    if(principalEvents_.ready())principalEvents_.discontinuity();
  }
}
bool NativeRuntime::principalPeerCurrent(const PrincipalPeer &peer) const noexcept {
    struct Check { const NativeRuntime &runtime; const PrincipalPeer &peer; } check{*this, peer};
    auto accepts = [](void *raw, const native::TokenEvidence &fresh) noexcept {
        auto &c = *static_cast<Check *>(raw);
        try {
            if (c.runtime.principalImageCheck_)
                return !c.peer.cancelled && c.peer.profile == c.runtime.profile_.value().generation &&
                    c.runtime.profile_.accepts(fresh, false) && !fresh.uiAccess &&
                    c.runtime.principalImageCheck_(c.peer, c.runtime.ordinaryImage_);
            DWORD pid = 0, length = 32768;
            wchar_t path[32768]{};
            BY_HANDLE_FILE_INFORMATION actual{};
            FILE_ATTRIBUTE_TAG_INFO attributes{};
            return !c.peer.cancelled && c.peer.profile == c.runtime.profile_.value().generation &&
                c.runtime.profile_.accepts(fresh, false) && !fresh.uiAccess &&
                c.runtime.deploymentCurrent() &&
                c.peer.image && c.peer.pipe && c.peer.directory &&
                GetNamedPipeClientProcessId(c.peer.pipe.value, &pid) && pid == c.peer.actor.pid &&
                QueryFullProcessImageNameW(c.peer.actor.process.value, 0, path, &length) && length &&
                std::filesystem::path(std::wstring(path, length)) == c.peer.admittedImage &&
                GetFileInformationByHandle(c.peer.image.value, &actual) && sameImage(actual, c.peer.imageId) &&
                c.runtime.deployment_->matchesImage(c.peer.admittedImage,actual) &&
                GetFileInformationByHandleEx(c.peer.image.value, FileAttributeTagInfo, &attributes, sizeof(attributes)) &&
                !(attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
                native::protectedObject(c.peer.image.value, false, false, true);
        } catch (...) { return false; }
    };
    return PrincipalActorQuery::current(peer.actor, peer.identity, peer.cancelled, &check, accepts, principalActorApi_);
}
bool NativeRuntime::ordinaryPeer(HANDLE pipe, std::shared_ptr<PrincipalPeer> &peer, bool readonly) {
    if (peer) return peer->readonly == readonly && principalPeerCurrent(*peer);
    if (ordinaryImage_.empty() || !native::fixedPath(ordinaryImage_) || !principalMode_ ||
        !deploymentCurrent() || ((!principalSource_ || !principalCatalog_ || principalWriteFault_) &&
            (readonly || principalOutcomes_.empty()))) return false;
    try {
        native::Handle serviceToken;
        HANDLE raw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) return false;
        serviceToken.reset(raw);
        if (!native::systemServiceToken(serviceToken.value)) return false;
        auto acquired = std::make_shared<PrincipalPeer>();
        acquired->readonly = readonly;
        acquired->admittedImage = readonly ? deployment_->root()/L"GateBouncerAssistant.exe" : ordinaryImage_;
        if (!ipc::ii::clientEvidence(pipe, acquired->identity, acquired->actor) ||
            !profile_.accepts(acquired->identity, false) || acquired->identity.uiAccess ||
            acquired->actor.image != acquired->admittedImage) return false;
        acquired->directory = std::make_unique<native::ProtectedDirectory>(acquired->admittedImage.parent_path(), true);
        if (!acquired->directory->acquire()) return false;
        acquired->image.reset(CreateFileW(acquired->admittedImage.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!acquired->image || !native::protectedObject(acquired->image.value, false, false, true) ||
            !GetFileInformationByHandle(acquired->image.value, &acquired->imageId) ||
            !deployment_->matchesImage(acquired->admittedImage,acquired->imageId)) return false;
        HANDLE duplicate = nullptr;
        if (!DuplicateHandle(GetCurrentProcess(), pipe, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
            return false;
        acquired->pipe.reset(duplicate);
        acquired->profile = profile_.value().generation;
        if (!principalPeerCurrent(*acquired)) return false;
        peer = std::move(acquired);
        return true;
    } catch (...) { return false; }
}
void NativeRuntime::closeOrdinaryPeer(const std::shared_ptr<PrincipalPeer> &peer) noexcept {
    if(peer && peer->subscriptionMask==3) {
        if(principalMask3Subscribers_)--principalMask3Subscribers_;
        peer->subscriptionMask=0;
    }
    if (!peer) return;
    peer->cancelled = true;
    for (auto &entry : principalAdmissions_) if (entry.second->owner == peer) entry.second->cancelled = true;
    peer->pages.clear();
}
Frame NativeRuntime::principalError(Error error) const {
    Frame frame; frame.minor = 3; frame.type = Type::ProtocolError;
    frame.fields = {value(Tag::ErrorCode, static_cast<unsigned>(error), 2)};
    return frame;
}
bool NativeRuntime::principalPolicyReady() const noexcept {
    if (!principalStore_ || principalStore_->uncertain() || principalRead_.kind != principal::StoredImage::Principal)
        return false;
    const auto &s = principalRead_.snapshot;
    if (s.storedState == State::Applied) return true;
    // El bootstrap de formato sólo es escribible si el Source leyó el catálogo
    // real; no crea baseline ni constituye prueba de protección por sí mismo.
    return s.storedState == State::RecoveryRequired && s.sequence == 1 && !s.desired && zero(s.active) &&
        s.rules.empty() && s.entries.empty() && !s.archive.size() && !s.migrationBase &&
        !s.effective && !s.storedKnown && s.activeProjection == Digest{} && s.activeAdmission == Digest{} &&
        s.archiveDigest == Digest{};
}
Frame NativeRuntime::ordinaryStatus(Type type, const std::shared_ptr<PrincipalPeer> &peer) const {
    auto frame = status(type, 3);
    if (frame.type == Type::ProtocolError) return frame;
    const bool admitted = peer && principalPeerCurrent(*peer) && principalMode_ && !principalWriteFault_ &&
        principalStore_ && !principalStore_->uncertain() && principalSource_ && principalCatalog_ &&
        principalSource_->stage() == allnative::Stage::Active && !zero(idValue(frame, Tag::SourceEpoch));
    if (peer && peer->readonly && !admitted) peer->pages.clear();
    for (auto &field : frame.fields) {
        if (field.tag == Tag::Capabilities) field = value(Tag::Capabilities,
            ReadStatus | (admitted ? ObservedRead | (principalEventsReady() ? wire::iv::NativeEvents : 0) |
                (principalTrafficReady() ? wire::iv::NativeTraffic : 0) |
                (principalProcessReady() ? wire::iv::NativeProcessFacts : 0) |
                (!peer->readonly && principalPolicyReady() ? FuturePolicyControl : 0) : 0));
        if (field.tag == Tag::IVProfile) field = value(Tag::IVProfile, admitted && !peer->readonly && principalPolicyReady() ? 1 : 0, 1);
    }
    return ordered(std::move(frame));
}
Frame NativeRuntime::principalResult(const Id &command, const directional::Result &result, Type type) const {
    Frame frame; frame.minor = 3; frame.type = type;
    // El receipt registra el outcome de este writer. No acredita continuidad
    // temporal, cobertura ni permisos efectivos del cliente.
    auto state = result.state;
    auto error = result.error;
    const bool prepared = state == State::Prepared && result.observed == directional::Observed::Prepared;
    if (state == State::Prepared && !prepared) state = State::RecoveryRequired;
    if (state == State::AppliedUnrecorded) error = Error::StoreFailure;
    if (state == State::Prepared) error = Error::Ok;
    frame.fields = {value(Tag::ServiceEpoch, epoch_), value(Tag::DesiredRev, result.desired),
        value(Tag::EffectiveRev, 0), value(Tag::EffectiveKnown, 0, 1),
        value(Tag::CommandState, static_cast<unsigned>(state), 1),
        value(Tag::ErrorCode, static_cast<unsigned>(error), 2), value(Tag::CommandId, command),
        value(Tag::ProofState, 0, 1), value(Tag::KnownAppliedUnrecorded, 0, 1),
        value(Tag::Durable, result.durable || prepared ? 1 : 0, 1)};
    return ordered(std::move(frame));
}
Frame NativeRuntime::preparePrincipal(const Frame &frame, const std::shared_ptr<PrincipalPeer> &peer) {
    if (!principalPolicyReady()) return principalError(Error::BackendUnavailable);
    const auto found = principalObservations_.find(idValue(frame, Tag::ObservedId));
    if (found == principalObservations_.end()) return principalError(Error::NotFound);
    auto &observation = *found->second;
    const auto scope = find(frame, Tag::ScopeKind) ? get(frame, Tag::ScopeKind) : 2;
    const auto duration = get(frame, Tag::ScopeDurationMs);
    const bool held = observation.event && observation.event->classifier_;
    const auto causeDirection = observation.event ?
        (observation.event->owned().direction == gatebouncer::service::windows::allapps::Direction::Inbound ? 2u :
         observation.event->owned().direction == gatebouncer::service::windows::allapps::Direction::Outbound ? 1u : 0u) : 0u;
    if ((!held && scope != 2) ||
        (scope >= 3 && (observation.row.package != 1 ||
            get(frame, Tag::PolicyDirection) != causeDirection || !causeDirection)) ||
        (scope == 5 && (!duration || duration > GB_SCOPE_MAX_MS)))
        return principalError(Error::ScopeUnsupported);
    if (observation.row.state != 1 || observation.row.revision != get(frame, Tag::ObservedRevision) ||
        observation.row.source != idValue(frame, Tag::SourceEpoch) || !observation.event || !observation.proof ||
        observation.profile != peer->profile || observation.source != principalSource_ ||
        get(frame, Tag::ExpectedDesiredRev) != principalDesired_ ||
        get(frame, Tag::ProfileGeneration) != peer->profile ||
        !principalSource_->retainedCause(*observation.event, *observation.proof,
            allnative::CatalogReceipt(principalCatalog_), allnative::Stage::Active)) return principalError(Error::Stale);
    // Ninguna mutación/receipt puede adelantarse al Attempt original pendiente.
    if(observation.pendingAttempt.type==Type::Attempt)publishPrincipalAttempt(observation);
    for (auto entry = principalAdmissions_.begin(); entry != principalAdmissions_.end();) {
        if (entry->second->owner == peer || entry->second->binding == observation.row.binding) {
            entry->second->cancelled = true; entry = principalAdmissions_.erase(entry);
        } else ++entry;
    }
    if (principalAdmissions_.size() >= PendingLimit) return principalError(Error::Capacity);
    auto admission = std::make_shared<PrincipalAdmission>();
    HANDLE duplicate = nullptr;
    if (!principalDuplicate_(GetCurrentProcess(), peer->actor.process.value, GetCurrentProcess(),
        &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) return principalError(Error::IdentityUnavailable);
    admission->actor.process.reset(duplicate); admission->actor.pid = peer->actor.pid;
    admission->actor.created = peer->actor.created; // Imagen retenida una vez en owner.
    admission->identity = peer->identity; admission->owner = peer;
    admission->request = native::randomIdentity(); admission->challenge = native::randomIdentity();
    admission->selector = native::randomIdentity(); admission->binding = observation.row.binding;
    admission->observed = observation.row.observed; admission->observedRevision = observation.row.revision;
    admission->revision = 1; admission->profile = peer->profile;
    admission->target = observation.digest; admission->fullTarget = observation.target;
    admission->source = observation.source; admission->event = observation.event; admission->proof = observation.proof;
    admission->activityAttempt = observation.activityAttempt;
    if (observation.event && observation.event->classifier_) {
        admission->activitySession = observation.event->classifier_->record_.session;
        admission->activityCause = observation.event->classifier_->record_.cause;
    }
    admission->direction = static_cast<std::uint8_t>(get(frame, Tag::PolicyDirection));
    admission->package = observation.row.package; admission->expectedDesired = principalDesired_;
    admission->scope = static_cast<std::uint8_t>(scope);
    admission->durationMs = static_cast<std::uint32_t>(duration);
    admission->deadline = principalNow_() + 120000;
    if (zero(admission->request) || zero(admission->challenge) || zero(admission->selector) ||
        !principalPeerCurrent(*peer)) return principalError(Error::IdentityUnavailable);
    wire::iv::FutureDraftRecord record;
    record.draft = admission->request; record.observed = admission->observed;
    record.source = observation.row.source; record.binding = admission->binding; record.selector = admission->selector;
    record.challenge = admission->challenge; record.version = admission->revision;
    record.observedRevision = admission->observedRevision; record.targetRevision = 1;
    record.expectedDesired = principalDesired_; record.profile = peer->profile;
    record.target = admission->target;
    record.ttl = 120000; record.state = 3; record.package = admission->package;
    record.direction = admission->direction; record.accepted = admission->package == 1 ? 3 : 1;
    record.scope = admission->scope; record.durationMs = admission->durationMs;
    if (scope >= 3) record.accepted = 1u << scope;
    record.proof = wire::iv::Proof::CurrentShapeUnproven; record.display = observation.fullDisplay;
    Bytes payload;
    if (wire::iv::pack(std::vector<wire::iv::FutureDraftRecord>{record}, payload) != Error::Ok)
        return principalError(Error::IdentityUnavailable);
    principalAdmissions_[admission->request] = std::move(admission);
    Frame response; response.minor = 3; response.type = Type::FutureDraftRecord;
    response.fields = {value(Tag::ServiceEpoch, epoch_), {Tag::Records, true, std::move(payload)},
        value(Tag::SourceEpoch, observation.row.source)};
    return ordered(std::move(response));
}
Frame NativeRuntime::commitPrincipal(const Frame &frame, const std::shared_ptr<PrincipalPeer> &peer) {
    Bytes canonical;
    if (wire::iv::canonical(frame, canonical) != Error::Ok) return principalError(Error::Malformed);
    auto existing = principalOutcomes_.find(frame.correlation);
    auto sameActor = [&](const PrincipalOutcome &outcome) {
        return outcome.profile == peer->profile && outcome.pid == peer->actor.pid &&
            CompareFileTime(&outcome.created, &peer->actor.created) == 0 && sameImage(outcome.imageId, peer->imageId) &&
            outcome.identity.account == peer->identity.account && outcome.identity.logon == peer->identity.logon &&
            outcome.identity.session == peer->identity.session;
    };
    if (existing != principalOutcomes_.end()) {
        if (!sameActor(existing->second)) return principalError(Error::Unauthorized);
        if (existing->second.payload != canonical) return principalError(Error::Conflict);
        refreshScoped(existing->second);
        return outcomeResult(frame.correlation, existing->second);
    }
    PrincipalOutcome archived;bool found=false;
    const auto disk=readScopedOutcome(frame.correlation,peer,archived,found);
    if(disk!=Error::Ok)return principalError(disk);
    if(found) {
        if(archived.payload!=canonical)return principalError(Error::Conflict);
        return outcomeResult(frame.correlation,archived);
    }
    if(principalOutcomes_.size()>=128 || principalOutcomeBytes_>512*1024-4096-sizeof(PrincipalOutcome))pruneScopedOutcomes();
    if (principalOutcomes_.size() >= 128 || canonical.capacity() > 4096 ||
        principalOutcomeBytes_ > 512 * 1024 - 4096 - sizeof(PrincipalOutcome)) return principalError(Error::Capacity);
    if (principalWriteFault_ || !principalPolicyReady() || !principalCatalog_ ||
        !principalSource_ || principalRead_.kind != principal::StoredImage::Principal ||
        get(frame, Tag::ExpectedDesiredRev) != principalDesired_ ||
        get(frame, Tag::ProfileGeneration) != peer->profile ||
        principalRead_.snapshot.sequence == UINT64_MAX || principalDesired_ == UINT64_MAX)
        return principalError(Error::BackendUnavailable);
    std::shared_ptr<PrincipalAdmission> admission;
    auto target = principalRead_.snapshot;
    if (frame.type == Type::CommitFuturePolicy) {
        auto found = principalAdmissions_.find(idValue(frame, Tag::DraftId));
        if (found == principalAdmissions_.end()) return principalError(Error::Stale);
        admission = found->second;
        const auto observed = principalObservations_.find(admission->observed);
        if (admission->owner != peer || admission->cancelled || admission->consumed ||
            principalNow_() >= admission->deadline || observed == principalObservations_.end() ||
            observed->second->row.revision != admission->observedRevision || observed->second->row.state != 1 ||
            find(frame, Tag::MigrationDigest)->bytes != Bytes(32))
            return principalError(Error::Stale);
        principal::Rule rule;
        rule.id = frame.correlation; rule.selector = admission->selector;
        rule.action = static_cast<std::uint8_t>(get(frame, Tag::Decision));
        rule.direction = admission->direction;
        rule.mode = rule.action == 1 || rule.direction == 2 ? 0 : rule.direction == 1 ? 1 : 2;
        rule.target = admission->fullTarget;
        if (admission->scope == 2) target.rules.push_back(std::move(rule));
    } else if (frame.type == Type::RevokePrincipalRule) {
        auto rule = std::find_if(target.rules.begin(), target.rules.end(), [&](const auto &r) {
            return r.id == idValue(frame, Tag::RuleId);
        });
        principal::Target bound;
        if (rule == target.rules.end() || rule->kind != 1 || !principal::parseTarget(rule->target, bound) ||
            bound.user != principal::ByteView(peer->identity.account)) return principalError(Error::Unauthorized);
        admission = std::make_shared<PrincipalAdmission>();
        admission->request = native::randomIdentity(); admission->binding = native::randomIdentity();
        admission->revision = 1; admission->profile = peer->profile;
        admission->expectedDesired = principalDesired_; admission->deadline = principalNow_() + 120000;
        admission->source = principalSource_; admission->revocation = *rule;
        admission->target = principal::targetDigest(rule->target); admission->owner = peer;
        admission->identity = peer->identity;
        HANDLE duplicate = nullptr;
        if (!principalDuplicate_(GetCurrentProcess(), peer->actor.process.value, GetCurrentProcess(),
            &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) return principalError(Error::IdentityUnavailable);
        admission->actor.process.reset(duplicate); admission->actor.pid = peer->actor.pid;
        admission->actor.created = peer->actor.created; // Imagen retenida una vez en owner.
        if (principalAdmissions_.size() >= PendingLimit || zero(admission->request) || zero(admission->binding))
            return principalError(Error::Capacity);
        principalAdmissions_[admission->request] = admission;
        target.rules.erase(rule);
    } else return principalError(Error::Unsupported);
    if (!principal::rulesValid(target.rules)) return principalError(Error::Conflict);
    principal::Entry entry;
    auto &command = entry.command;
    command.id = frame.correlation; command.principal = native::sidKey(peer->identity.account);
    command.logon = native::sidKey(peer->identity.logon); command.profileGeneration = peer->profile;
    command.accountSid = peer->identity.account; command.logonSid = peer->identity.logon;
    command.sessionId = peer->identity.session; command.commandEpoch = epoch_; command.boot = boot_;
    command.payload = std::move(canonical); command.desired = principalDesired_ + 1;
    target.sequence = principalRead_.snapshot.sequence + 1; target.desired = command.desired;
    target.effective = 0; target.storedKnown = false; target.storedState = State::Prepared;
    target.writerEpoch = epoch_;
    if (!principalAdmissionCurrent(*admission, entry)) return principalError(Error::Stale);
    PrincipalOutcome reserved;
    reserved.payload = command.payload; reserved.identity = peer->identity;
    reserved.pid = peer->actor.pid; reserved.created = peer->actor.created; reserved.imageId = peer->imageId;
    reserved.profile = peer->profile; reserved.type = frame.type;
    reserved.scope = admission->scope;
    if (admission->scope >= 3) {
        reserved.activityAttempt = admission->activityAttempt;
        reserved.activitySession = admission->activitySession; reserved.activityCause = admission->activityCause;
        reserved.activitySource=admission->source;
        if(admission->event) {
            reserved.activityCatalog=admission->event->snapshot_;
            reserved.activityOwner=admission->event->classifier_;
            if(reserved.activityOwner)reserved.activityCharge=activityCauseBytes(*reserved.activityOwner);
        }
    }
    const auto charged = reserved.payload.capacity() + reserved.identity.account.capacity() +
        reserved.identity.logon.capacity() + sizeof(PrincipalOutcome) + 128 + NativeActivityRing::bytes(reserved.activityAttempt)+reserved.activityCharge;
    if (charged > 512 * 1024 || principalOutcomeBytes_ > 512 * 1024 - charged) return principalError(Error::Capacity);
    auto inserted = principalOutcomes_.emplace(frame.correlation, std::move(reserved));
    if (!inserted.second) return principalError(Error::Conflict);
    principalOutcomeBytes_ += charged;
    auto &receipt = inserted.first->second;
    // Memoria del receipt ya reservada: toda incertidumbre del writer queda
    // consultable antes de enviar bytes al cliente, sin una segunda operación.
    try { receipt.result = admission->scope >= 3 ? writeScoped(entry, admission, receipt.scoped) :
            writePrincipal(target, entry, admission); }
    catch (...) { principalWriteFault_ = true; receipt.result.error = Error::RecoveryRequired; }
    if (!receipt.result.desired) receipt.result.desired = command.desired;
    publishPrincipalAuthorization(receipt);
    if (admission->scope == 2 && (admission->consumed || principalSource_ != admission->source)) invalidatePrincipalObservations();
    return outcomeResult(frame.correlation, receipt);
}
Frame NativeRuntime::dispatchOrdinary(const Frame &frame, const std::shared_ptr<PrincipalPeer> &peer) {
    if (peer && peer->readonly && frame.type != Type::GetStatus && frame.type != Type::ListObserved &&
        frame.type != Type::GetObservedRecord && frame.type != Type::SubscribeEvents &&
        frame.type != Type::GetNativeProcessContext) return principalError(Error::Unauthorized);
    tick();
    if (frame.minor != 3 || wire::iv::validate(frame) != Error::Ok) return principalError(Error::Malformed);
    if (!peer || frame.connection != peer->connection || !principalPeerCurrent(*peer)) {
        if (peer && peer->readonly) peer->pages.clear();
        return principalError(Error::IdentityUnavailable);
    }
    if (frame.type == Type::GetStatus) return ordinaryStatus(Type::Status, peer);
    if (frame.type == Type::GetNativeProcessContext) return readPrincipalProcess(frame,peer);
    if (idValue(frame, Tag::ServiceEpoch) != epoch_) return principalError(Error::Stale);
    if (frame.type == Type::SubscribeEvents) return subscribePrincipalEvents(frame, peer);
    const auto now = principalNow_();
    auto sameActor = [&](const PrincipalOutcome &outcome) {
        return outcome.profile == peer->profile && outcome.pid == peer->actor.pid &&
            CompareFileTime(&outcome.created, &peer->actor.created) == 0 && sameImage(outcome.imageId, peer->imageId) &&
            outcome.identity.account == peer->identity.account && outcome.identity.logon == peer->identity.logon &&
            outcome.identity.session == peer->identity.session;
    };
    if (frame.type == Type::GetFutureCommandStatus) {
        const auto command = idValue(frame, Tag::CommandId);
        auto found = principalOutcomes_.find(command);
        if (found == principalOutcomes_.end()) {
            PrincipalOutcome archived;bool present=false;
            const auto disk=readScopedOutcome(command,peer,archived,present);
            if(disk!=Error::Ok)return principalError(disk);
            if(present) {
                auto response=outcomeResult(command,archived,Type::FutureCommandStatus);
                response.fields.push_back(value(Tag::CommandFound,1,1));
                response.fields.push_back(value(Tag::OriginalCommandType,static_cast<unsigned>(archived.type),2));
                return ordered(std::move(response));
            }
            Frame response; response.minor = 3; response.type = Type::FutureCommandStatus;
            response.fields = {value(Tag::ServiceEpoch, epoch_), value(Tag::ErrorCode, static_cast<unsigned>(Error::CommandUnknown), 2),
                value(Tag::CommandId, command), value(Tag::CommandFound, 0, 1)};
            return ordered(std::move(response));
        }
        if (!sameActor(found->second)) return principalError(Error::Unauthorized);
        refreshScoped(found->second);
        auto response = outcomeResult(command, found->second, Type::FutureCommandStatus);
        response.fields.push_back(value(Tag::CommandFound, 1, 1));
        response.fields.push_back(value(Tag::OriginalCommandType, static_cast<unsigned>(found->second.type), 2));
        return ordered(std::move(response));
    }
    // Reconsulta de recibo conservado no depende de que el Source B siga sano.
    if (frame.type == Type::CommitFuturePolicy || frame.type == Type::RevokePrincipalRule)
        return commitPrincipal(frame, peer);
    if (!principalMode_ || principalWriteFault_ || !principalSource_ || !principalCatalog_ ||
        principalSource_->stage() != allnative::Stage::Active ||
        principalSource_->source_.health().health != gatebouncer::service::windows::allapps::Health::Ready) {
        if (peer->readonly) peer->pages.clear();
        return principalError(Error::BackendUnavailable);
    }
    const auto causeCurrent = [&](const PrincipalObservation &o) {
        return o.row.state == 1 && o.row.source == principalSource_->binding_->epoch &&
            o.source == principalSource_ && o.profile == peer->profile && o.event && o.proof &&
            o.event->owned().identity.userSid.bytes == peer->identity.account &&
            principalSource_->retainedCause(*o.event,*o.proof,allnative::CatalogReceipt(principalCatalog_),allnative::Stage::Active);
    };
    if (peer->readonly && (frame.type == Type::ListObserved || frame.type == Type::GetObservedRecord)) {
        const auto retainedSource = principalSource_;
        const auto retainedCatalog = principalCatalog_;
        const auto fresh = readServiceContext(); // READ/reconcile real; el cache de páginas no da frescura.
        if (principalSource_ != retainedSource || principalCatalog_ != retainedCatalog ||
            fresh.engineContext != retainedSource->binding_->epoch ||
            fresh.engineBindingGeneration != retainedSource->binding_->generation ||
            !principalPeerCurrent(*peer)) {
            peer->pages.clear(); return principalError(Error::BackendUnavailable);
        }
    }
    if (frame.type == Type::PrepareFuturePolicy) return preparePrincipal(frame, peer);
    if (frame.type == Type::GetFutureDraft) {
        auto found = principalAdmissions_.find(idValue(frame, Tag::DraftId));
        if (found == principalAdmissions_.end() || found->second->owner != peer || found->second->cancelled ||
            found->second->consumed || now >= found->second->deadline ||
            get(frame, Tag::ProfileGeneration) != peer->profile ||
            get(frame, Tag::DraftVersion) != found->second->revision) return principalError(Error::Stale);
        auto &admission = *found->second;
        auto observed = principalObservations_.find(admission.observed);
        if (observed == principalObservations_.end() || observed->second->row.revision != admission.observedRevision ||
            observed->second->row.state != 1 || admission.source != principalSource_ || !admission.event || !admission.proof ||
            !admission.source->retainedCause(*admission.event, *admission.proof,
                allnative::CatalogReceipt(principalCatalog_), allnative::Stage::Active)) return principalError(Error::Stale);
        wire::iv::FutureDraftRecord record;
        record.draft = admission.request; record.observed = admission.observed; record.source = observed->second->row.source;
        record.binding = admission.binding; record.selector = admission.selector; record.challenge = admission.challenge;
        record.version = admission.revision; record.observedRevision = admission.observedRevision;
        record.targetRevision = 1; record.expectedDesired = admission.expectedDesired; record.profile = admission.profile;
        record.target = admission.target;
        record.ttl = static_cast<std::uint32_t>(admission.deadline - now); record.state = 3;
        record.package = admission.package; record.direction = admission.direction;
        record.accepted = admission.package == 1 ? 3 : 1; record.proof = wire::iv::Proof::CurrentShapeUnproven;
        record.scope = admission.scope; record.durationMs = admission.durationMs;
        if (admission.scope >= 3) record.accepted = 1u << admission.scope;
        record.display = observed->second->fullDisplay;
        Bytes records;
        if (wire::iv::pack(std::vector<wire::iv::FutureDraftRecord>{record}, records) != Error::Ok)
            return principalError(Error::IdentityUnavailable);
        Frame response; response.minor = 3; response.type = Type::FutureDraftRecord;
        response.fields = {value(Tag::ServiceEpoch, epoch_), {Tag::Records, true, std::move(records)}, value(Tag::SourceEpoch, record.source)};
        return ordered(std::move(response));
    }
    if (frame.type == Type::GetObservedRecord || frame.type == Type::OpenReview) {
        auto found = principalObservations_.find(idValue(frame, Tag::ObservedId));
        if (found == principalObservations_.end()) return principalError(Error::NotFound);
        const auto &row = found->second->row;
        if (row.revision != get(frame, Tag::ObservedRevision) || row.source != idValue(frame, Tag::SourceEpoch))
            return principalError(Error::Stale);
        if (peer->readonly && !causeCurrent(*found->second)) {
            peer->pages.clear(); return principalError(Error::Stale);
        }
        if (frame.type == Type::OpenReview) {
            Frame response = frame; response.type = Type::ReviewQueued; return response;
        }
        Bytes records;
        auto presented = row;
        if (peer->readonly) presented.display = found->second->fullDisplay;
        if (wire::iv::pack(std::vector<wire::iv::ObservedRecord>{presented}, records) != Error::Ok)
            return principalError(Error::IdentityUnavailable);
        Frame response; response.minor = 3; response.type = Type::ObservedRecord;
        response.fields = {value(Tag::ServiceEpoch, epoch_), {Tag::Records, true, std::move(records)}, value(Tag::SourceEpoch, row.source)};
        if (row.state == 1 && causeCurrent(*found->second) && found->second->event) {
            const auto direction = found->second->event->owned().direction;
            if (direction == gatebouncer::service::windows::allapps::Direction::Inbound ||
                direction == gatebouncer::service::windows::allapps::Direction::Outbound)
                response.fields.push_back(value(Tag::PolicyDirection,
                    direction == gatebouncer::service::windows::allapps::Direction::Inbound ? 2 : 1, 1));
        }
        return ordered(std::move(response));
    }
    if (frame.type == Type::ListObserved) {
        for (auto page = peer->pages.begin(); page != peer->pages.end();) {
            if (now >= page->second.deadline || page->second.revision != principalObservedRevision_)
                page = peer->pages.erase(page);
            else ++page;
        }
        auto snapshot = idValue(frame, Tag::SnapshotId);
        if (zero(snapshot)) {
            if (peer->pages.size() >= 2) return principalError(Error::Capacity);
            PrincipalPage page;
            page.revision = principalObservedRevision_ ? principalObservedRevision_ : 1;
            page.source = principalSource_->binding_->epoch; page.deadline = now + 5000;
            for (const auto &entry : principalObservations_) {
                if (peer->readonly && entry.second->row.state != 1) continue;
                if (peer->readonly && !causeCurrent(*entry.second)) {
                    peer->pages.clear(); return principalError(Error::Stale);
                }
                page.rows.push_back(entry.second->row);
            }
            snapshot = native::randomIdentity();
            if (zero(snapshot) || !peer->pages.emplace(snapshot, std::move(page)).second) return principalError(Error::Capacity);
        }
        auto found = peer->pages.find(snapshot);
        if (found == peer->pages.end()) return principalError(Error::SnapshotExpired);
        auto &page = found->second;
        if (peer->readonly) {
            if (page.source != principalSource_->binding_->epoch) {
                peer->pages.clear(); return principalError(Error::Stale);
            }
            for (const auto &row : page.rows) {
                const auto current = principalObservations_.find(row.observed);
                if (current == principalObservations_.end() || current->second->row.revision != row.revision ||
                    !causeCurrent(*current->second)) {
                    peer->pages.clear(); return principalError(Error::Stale);
                }
            }
        }
        const auto cursor = static_cast<std::uint32_t>(get(frame, Tag::Cursor));
        if (cursor != page.next || cursor > page.rows.size()) return principalError(Error::Stale);
        const auto limit = static_cast<std::size_t>(get(frame, Tag::Limit));
        std::vector<wire::iv::ObservedRecord> rows;
        Bytes packed;
        for (auto at = cursor; at < page.rows.size() && rows.size() < limit; ++at) {
            rows.push_back(page.rows[at]);
            Bytes candidate;
            const auto result = wire::iv::pack(rows, candidate);
            if (result == Error::Capacity) { rows.pop_back(); break; }
            if (result != Error::Ok) return principalError(result);
            packed = std::move(candidate);
        }
        if (rows.empty() && cursor < page.rows.size()) return principalError(Error::Capacity);
        const auto next = cursor + static_cast<std::uint32_t>(rows.size());
        const bool terminal = next == page.rows.size();
        page.next = next;
        Frame response; response.minor = 3; response.type = Type::ObservedPage;
        response.fields = {value(Tag::ServiceEpoch, epoch_), value(Tag::SnapshotId, snapshot), value(Tag::Cursor, cursor, 4),
            value(Tag::NextCursor, terminal ? UINT32_MAX : next, 4), value(Tag::Count, rows.size(), 2),
            {Tag::Records, true, std::move(packed)}, value(Tag::SourceEpoch, page.source),
            value(Tag::ObservedSnapshotRevision, page.revision)};
        if (terminal) peer->pages.erase(found);
        return ordered(std::move(response));
    }
    return principalError(Error::Unsupported);
}
void NativeRuntime::invalidatePrincipalObservations() noexcept {
    principalEvents_.lose();
    principalProcessAcquired_=false;
    principalAppCapacityGap_=false;
    if(principalImageWorker_ && principalImageJobId_)principalImageWorker_->abandon(principalImageJobId_);
    for(auto &entry:principalProcesses_)entry.second->retired=true;
    principalTrafficAcquired_=false;principalTraffic_.clear();principalTrafficBytes_=0;
    for (auto &entry : principalAdmissions_) entry.second->cancelled = true;
    principalAdmissions_.clear();
    principalPendingBytes_ = 0;
    for (auto &entry : principalObservations_) {
        auto &o = *entry.second;
        o.pendingAttempt={};o.imageJob=0;o.imageDeadline=0;
        if (o.row.state == 1 && principalObservedRevision_ != UINT64_MAX)
            o.row.revision = ++principalObservedRevision_;
        o.row.state = 2; o.row.binding = {}; o.row.reason = Error::Stale;
        o.target = {}; o.source.reset(); o.event.reset(); o.proof.reset(); o.fullDisplay = {};
        o.charged = sizeof(PrincipalObservation) + o.row.display.name.capacity() +
            o.row.display.principal.capacity() + o.row.display.package.capacity() + o.row.display.path.capacity() +
            NativeActivityRing::bytes(o.activityAttempt) + 128;
        principalPendingBytes_ += o.charged;
    }
}
void NativeRuntime::publishPrincipalAttempt(PrincipalObservation &o,const GB_PROCESS_IMAGE_FACTS *facts) noexcept {
  try {
    if(o.activityAttempt.type==Type::Attempt || o.pendingAttempt.type!=Type::Attempt)return;
    if(principalImageWorker_ && o.imageJob)principalImageWorker_->abandon(o.imageJob);
    o.imageJob=0;o.imageDeadline=0;
    const auto priorCharge=NativeActivityRing::bytes(o.pendingAttempt);
    auto history=std::move(o.pendingAttempt);o.pendingAttempt={};
    wire::iv::ServiceContext context;
    if(wire::iv::decodeServiceContext(history,context)!=Error::Ok || !principalEventsReady() ||
       !NativeActivityRing::same(context,principalEvents_.context()) || o.source!=principalSource_ ||
       o.profile!=principalEvents_.profile() || get(history,Tag::ObservedRevision)!=o.row.revision ||
       idValue(history,Tag::CaptureBindingId)!=o.row.binding) {principalEvents_.lose();return;}
    std::shared_ptr<PrincipalProcessRetainer> retained;
    std::map<Id,std::shared_ptr<PrincipalProcessRetainer>>::node_type preparedNode;
    if(facts && o.event && o.proof && o.event->classifier_) {
      try {
        const auto cause=o.event->classifier_;
        wire::iv::ProcessFacts record;
        record.pid=facts->pid;record.created=facts->created;record.volumeSerial=facts->volumeSerialNumber;
        record.fileIndexHigh=facts->fileIndexHigh;record.fileIndexLow=facts->fileIndexLow;
        record.fileSizeHigh=facts->fileSizeHigh;record.fileSizeLow=facts->fileSizeLow;record.lastWrite=facts->lastWrite;
        record.tokenSession=cause->token_.session;
        record.appId=Bytes(cause->record_.app,cause->record_.app+cause->record_.appBytes);
        record.image=displayText(cause->process_.image.u16string(),4096);
        record.accountSid=cause->token_.account;record.logonSid=cause->token_.logon;
        Bytes records;
        if(wire::iv::pack(std::vector<wire::iv::ProcessFacts>{record},records)==Error::Ok && principalProcessPhysical_<64 &&
           principalProcesses_.find(o.row.observed)==principalProcesses_.end()) {
            auto candidate=history;
            for(auto &field:candidate.fields)if(field.tag==Tag::Presence)field=value(Tag::Presence,get(history,Tag::Presence)|4);
            candidate.fields.push_back({Tag::Records,true,std::move(records)});candidate=ordered(std::move(candidate));
            retained=std::make_shared<PrincipalProcessRetainer>();retained->attempt=candidate;
            retained->source=o.source;retained->catalog=principalCatalog_;retained->cause=cause;
            retained->event=o.event;retained->proof=o.proof;retained->original=*facts;
            retained->charged=sizeof(PrincipalProcessRetainer)+128+NativeActivityRing::bytes(retained->attempt)+
                gatebouncer::service::windows::allapps::chargedBytes(o.event->owned())+activityCauseBytes(*cause)+512;
            // Cobrar también la copia del descriptor conservada en la observación.
            const auto extra=NativeActivityRing::bytes(candidate)-NativeActivityRing::bytes(history);
            if(processBudget(retained->charged+extra)) {
                std::map<Id,std::shared_ptr<PrincipalProcessRetainer>> prepared;
                prepared.emplace(o.row.observed,retained);preparedNode=prepared.extract(o.row.observed);
                history=std::move(candidate);
            }
            else retained.reset();
        }
      } catch(...) {retained.reset();}
    }
    const bool known=retained!=nullptr;
    // La fuente íntegra no depende de adquirir imagen ni de cupos de evidencia.
    if(principalEvents_.latest()==UINT64_MAX) {principalEvents_.fail();return;}
    for(auto &field:history.fields)if(field.tag==Tag::EventSeq)field=value(Tag::EventSeq,principalEvents_.latest()+1);
    if(principalEvents_.append(history)!=Error::Ok) {principalEvents_.lose();return;}
    const auto actualCharge=NativeActivityRing::bytes(history);
    if(actualCharge>=priorCharge) {o.charged+=actualCharge-priorCharge;principalPendingBytes_+=actualCharge-priorCharge;}
    o.activityAttempt=history;
    if(retained) {
        retained->attempt=history;
        if(principalProcesses_.insert(std::move(preparedNode)).inserted) {
            principalProcessBytes_+=retained->charged;++principalProcessPhysical_;principalProcessAcquired_=true;
        } else retained.reset();
    }
    if(get(history,Tag::Source)==2 && (!known || !retained) && !o.imageGap) {
        o.imageGap=true;principalEvents_.discontinuity(); // Cobertura Unknown, pérdida numérica desconocida.
    }
  } catch(...) {principalEvents_.fail();o.pendingAttempt={};}
}
void NativeRuntime::pollPrincipalImages() noexcept {
  try {
    if(!principalImageWorker_)return;
    std::size_t releasedProcesses=0;
    const auto released=principalImageWorker_->releasedCharge(releasedProcesses);
    if(releasedProcesses<=principalProcessPhysical_)principalProcessPhysical_-=releasedProcesses;
    else {principalEvents_.fail();principalProcessPhysical_=0;}
    if(released<=principalRetiredBytes_)principalRetiredBytes_-=released;
    else {principalEvents_.fail();principalRetiredBytes_=0;}
    GB_PROCESS_IMAGE_FACTS facts{};bool valid=false,done=false;
    const auto physical=principalImageJobId_;
    if(physical)done=principalImageWorker_->result(physical,facts,valid);
    for(auto &item:principalObservations_) {
        const auto observation=item.second;auto &o=*observation;
        if(o.pendingAttempt.type!=Type::Attempt)continue;
        const bool completed=o.imageJob==physical && done;
        const bool beforeDeadline=principalNow_()<o.imageDeadline;
        if(!completed && beforeDeadline)continue;
        bool accept=completed && valid && beforeDeadline && o.row.state==1 && o.event && o.proof &&
            o.source==principalSource_ && o.profile==profile_.value().generation && o.event->classifier_;
        if(accept) {
            const auto source=o.source;const auto catalog=principalCatalog_;
            wire::iv::ServiceContext original;
            const auto before=readServiceContext();
            accept=wire::iv::decodeServiceContext(o.pendingAttempt,original)==Error::Ok &&
                source==principalSource_ && catalog==principalCatalog_ && principalEventsReady() &&
                NativeActivityRing::same(before,original) && source->valid(*o.event) &&
                get(o.pendingAttempt,Tag::ObservedRevision)==o.row.revision &&
                idValue(o.pendingAttempt,Tag::CaptureBindingId)==o.row.binding;
            if(accept) {
                auto proof=source->readCurrentProof(*o.event,allnative::CatalogReceipt(catalog));
                accept=proof.proof && source->retainedCause(*o.event,*proof.proof,
                    allnative::CatalogReceipt(catalog),allnative::Stage::Active);
                GB_PROCESS_IMAGE_FACTS live{};
                accept=accept && principalClassifier_ && o.event->classifier_->owner_==principalClassifier_ &&
                    principalClassifier_->imageCurrent(*o.event->classifier_,backend_.engine_,live) &&
                    std::memcmp(&live,&facts,sizeof(facts))==0;
            }
            const auto after=readServiceContext();
            accept=accept && source==principalSource_ && catalog==principalCatalog_ && principalEventsReady() &&
                NativeActivityRing::same(after,original) && o.row.state==1 && o.event && source->valid(*o.event) &&
                principalNow_()<o.imageDeadline;
        }
        publishPrincipalAttempt(o,accept ? &facts : nullptr);
    }
    if(done) {
        bool waiting=false;
        if(principalClassifier_) {
            std::lock_guard<std::mutex> lock(principalClassifier_->mutex_);
            const auto &raw=principalClassifier_->pendingApp_;
            waiting=raw && raw->record_.session==principalImageSession_ && raw->record_.cause==principalImageCause_ && raw->appState_.load()==1;
        }
        principalImageJobCharge_=0;
        if(!waiting)principalImageJobId_=0;
    }
  } catch(...) {principalEvents_.fail();}
}
void NativeRuntime::pollPrincipalPendingApp() noexcept {
  try {
    if(!principalClassifier_ || !principalImageWorker_)return;
    std::shared_ptr<allnative::ClassifierCause> raw;
    {std::lock_guard<std::mutex> lock(principalClassifier_->mutex_);raw=principalClassifier_->pendingApp_;}
    if(!raw) {principalPendingAppBytes_=0;return;}
    const auto charge=activityCauseBytes(*raw)+128;
    if(!principalPendingAppBytes_) {
        if(!processBudget(charge))raw->appState_.store(2);
        principalPendingAppBytes_=charge; // Retenido aun al fallar la admisión.
    }
    auto state=raw->appState_.load();
    if(state==0 && principalImageJobId_ && (raw->record_.session!=principalImageSession_ ||
       raw->record_.cause!=principalImageCause_) && !raw->appGap_) {
        raw->appGap_=true;principalEvents_.discontinuity();
    }
    if(state==0 && (!principalMode_ || !principalSource_ || !principalCatalog_ || principalWriteFault_ ||
       profile_.value().state!=1 || principalSource_->stage()!=allnative::Stage::Active ||
       principalSource_->source_.health().health!=gatebouncer::service::windows::allapps::Health::Ready)) {
        raw->appState_.store(2);state=2;
    }
    if(state==0 && principalImageJobId_ && raw->record_.session==principalImageSession_ &&
       raw->record_.cause==principalImageCause_ && principalNow_()>=principalAppDeadline_) {
        raw->appState_.store(2);principalImageWorker_->abandon(principalImageJobId_);state=2;
    }
    if(state==0 && !principalImageJobId_) {
        const auto source=principalSource_;const auto catalog=principalCatalog_;
        const auto before=readServiceContext();
        if(source!=principalSource_ || catalog!=principalCatalog_ || !principalEventsReady() ||
           before.engineContext!=source->binding_->epoch || before.engineBindingGeneration!=source->binding_->generation) {
            raw->appState_.store(2);state=2;
        }
        const auto jobCharge=sizeof(allnative::NativeImageWorker::Operation)+sizeof(allnative::NativeImageWorker::Job)+charge;
        if(state==0 && processBudget(jobCharge)) {
            const auto job=principalImageWorker_->submit(raw);
            if(job) {
                principalImageJobId_=job;principalImageJobCharge_=jobCharge;
                principalImageSession_=raw->record_.session;principalImageCause_=raw->record_.cause;
                principalAppDeadline_=principalNow_()+250;
            } else {raw->appState_.store(2);state=2;}
        } else {raw->appState_.store(2);state=2;}
    }
    if(state==2) {
        if(principalSource_)principalSource_->lose(); // Mismo rechazo/loss del take anterior.
        {std::lock_guard<std::mutex> lock(principalClassifier_->mutex_);
            if(principalClassifier_->pendingApp_==raw)principalClassifier_->pendingApp_.reset();}
        std::shared_ptr<void> retired=std::move(raw);
        if(principalImageWorker_->retire(retired,charge)) {
            principalPendingAppBytes_=0;principalRetiredBytes_+=charge;
        } else {
            std::lock_guard<std::mutex> lock(principalClassifier_->mutex_);
            principalClassifier_->pendingApp_=std::static_pointer_cast<allnative::ClassifierCause>(retired);
        }
    }
  } catch(...) {if(principalSource_)principalSource_->lose();}
}
void NativeRuntime::finishPrincipalImages() noexcept {
    if(principalImageWorker_)principalImageWorker_->stop();
    // Cancel no acredita drain. Un FS que no retorna conserva STOP_PENDING.
    principalImageWorker_.reset(); // Join fuera de Runtime/Classifier/state mutex.
    std::shared_ptr<allnative::ClassifierCause> pending;
    if(principalClassifier_) {
        std::lock_guard<std::mutex> lock(principalClassifier_->mutex_);
        pending=std::move(principalClassifier_->pendingApp_);
    }
    pending.reset();principalProcesses_.clear(); // Últimas refs también fuera de todos los mutex.
    principalProcessBytes_=principalRetiredBytes_=principalProcessPhysical_=0;
    principalImageJobId_=principalImageJobCharge_=principalPendingAppBytes_=0;
    principalProcessAcquired_=false;
}
bool NativeRuntime::principalProcessCurrent(const PrincipalProcessRetainer &r,GB_PROCESS_IMAGE_FACTS &facts) noexcept {
  try {
    wire::iv::ServiceContext original;
    if(r.retired || !r.event || !r.proof || !r.cause || !r.source || !r.catalog || !principalClassifier_ ||
       wire::iv::decodeServiceContext(r.attempt,original)!=Error::Ok)return false;
    const auto before=readServiceContext();
    const auto &metadata=r.event->owned();
    const auto matches=[&] {
        return !r.retired && principalEventsReady() && r.source==principalSource_ && r.catalog==principalCatalog_ &&
            get(r.attempt,Tag::ProfileGeneration)==profile_.value().generation && r.event->binding_==r.source->binding_ &&
            r.event->snapshot_==r.catalog && r.event->classifier_==r.cause && r.cause->owner_==principalClassifier_ &&
            r.source->source_.current(metadata.acquired) &&
            r.source->source_.health().lossRevision==metadata.acquiredLossRevision;
    };
    if(!matches() || !NativeActivityRing::same(before,original) ||
       !principalClassifier_->imageCurrent(*r.cause,backend_.engine_,facts) ||
       std::memcmp(&facts,&r.original,sizeof(facts))!=0)return false;
    const auto after=readServiceContext();
    // El current postApplied procede de EPROCESS/custodian y catálogo real; jamás del CURRENT pending-only.
    return matches() && NativeActivityRing::same(after,original);
  } catch(...) {return false;}
}
void NativeRuntime::prunePrincipalProcesses() noexcept {
  try {
    if(!principalImageWorker_)return;
    const auto limit=std::min<std::size_t>(8,principalProcesses_.size());
    for(std::size_t n=0;n<limit && !principalProcesses_.empty();++n) {
        auto it=principalProcesses_.upper_bound(principalProcessCursor_);
        if(it==principalProcesses_.end())it=principalProcesses_.begin();
        auto retained=it->second;principalProcessCursor_=it->first;GB_PROCESS_IMAGE_FACTS live{};
        if(!retained->retired && principalProcessCurrent(*retained,live))continue;
        retained->retired=true;
        const auto charge=retained->charged;retained.reset();
        auto node=principalProcesses_.extract(it);std::shared_ptr<void> owner=std::move(node.mapped());
        if(principalImageWorker_->retire(owner,charge,true)) {
            principalProcessBytes_-=charge;principalRetiredBytes_+=charge;
        } else {
            node.mapped()=std::static_pointer_cast<PrincipalProcessRetainer>(owner);
            principalProcesses_.insert(std::move(node));
        } // Ocupado: sigue cargado/retired, nunca current ni eviction heurística.
    }
  } catch(...) {principalEvents_.fail();}
}
Frame NativeRuntime::readPrincipalProcess(const Frame &request,const std::shared_ptr<PrincipalPeer> &peer) {
    Frame response=request;response.type=Type::NativeProcessContext;
    const auto finish=[&](Error error,const Bytes *records=nullptr) {
        response.fields.push_back(value(Tag::ErrorCode,static_cast<unsigned>(error),2));
        response.fields.push_back(value(Tag::Count,records ? 1 : 0,4));
        response.fields.push_back(value(Tag::Source,2,1));response.fields.push_back(value(Tag::SourceCoverage,1,1));
        if(records)response.fields.push_back({Tag::Records,true,*records});
        return ordered(std::move(response));
    };
    if(!peer || !peer->readonly || !principalPeerCurrent(*peer))return finish(Error::Unauthorized);
    if(idValue(request,Tag::ServiceEpoch)!=epoch_ || get(request,Tag::ProfileGeneration)!=peer->profile)
        return finish(Error::Stale);
    const auto found=principalProcesses_.find(idValue(request,Tag::ObservedId));
    if(found==principalProcesses_.end())return finish(Error::NotFound);
    const auto retained=found->second;
    const Tag sameFields[]={Tag::ServiceEpoch,Tag::SourceEpoch,Tag::ServiceContext,Tag::ProfileGeneration,
        Tag::ObservedId,Tag::ObservedRevision,Tag::CaptureBindingId};
    for(const auto tag:sameFields) {
        const auto a=find(request,tag),b=find(retained->attempt,tag);
        if(!a || !b || a->bytes!=b->bytes)return finish(Error::Stale);
    }
    if(idValue(request,Tag::AttemptLink)!=wire::iv::attemptLink(get(retained->attempt,Tag::EventSeq)))return finish(Error::Stale);
    GB_PROCESS_IMAGE_FACTS live{};
    if(!principalProcessReady() || !principalProcessCurrent(*retained,live) || !principalPeerCurrent(*peer)) {
        retained->retired=true;return finish(Error::IdentityUnavailable);
    }
    const auto records=find(retained->attempt,Tag::Records);
    if(!records)return finish(Error::IdentityUnavailable);
    return finish(Error::Ok,&records->bytes);
}
void NativeRuntime::collectPrincipalObservations() {
    using namespace gatebouncer::service::windows::allapps;
    if (!principalMode_ || principalWriteFault_ || !principalSource_ || !principalCatalog_ ||
        principalSource_->stage() != allnative::Stage::Active || profile_.value().state != 1) return;
    const wire::iv::ServiceContext context{epoch_,boot_,principalSource_->binding_->epoch,principalSource_->binding_->generation};
    if (!principalEvents_.bind(context,profile_.value().generation)) return;
    auto formatter = gatebouncer::appidentity::makeWindowsSidFormatter();
    if (!formatter) return;
    for (auto &item : principalObservations_) {
        auto &o = *item.second;
        if (o.row.state == 1 && o.event && o.event->classifier_ && !o.event->classifier_->current()) {
            if(o.pendingAttempt.type==Type::Attempt)publishPrincipalAttempt(o);
            o.row.state = 2; o.row.binding = {}; o.row.reason = Error::Stale;
            if (principalObservedRevision_ != UINT64_MAX) o.row.revision = ++principalObservedRevision_;
            o.target = {}; o.event.reset(); o.proof.reset(); o.source.reset();
        }
    }
    // Trabajo acotado por tick: no drenar indefinidamente ante un productor ocupado.
    for (unsigned work = 0; work < 8; ++work) {
        if(principalClassifier_) {
            bool pending=false;
            {std::lock_guard<std::mutex> lock(principalClassifier_->mutex_);pending=principalClassifier_->pendingApp_!=nullptr;}
            // Reservar rawcause/path máximo antes de adquirir el HANDLE nuevo.
            const auto reserve=sizeof(allnative::ClassifierCause)+128+32768*4*sizeof(wchar_t)+2*68;
            if(!pending && !processBudget(reserve)) {
                if(!principalAppCapacityGap_) {principalAppCapacityGap_=true;principalEvents_.discontinuity();}
                break;
            }
            principalAppCapacityGap_=false;
        }
        auto event = principalSource_->takeCopied();
        if (!event) {pollPrincipalPendingApp();break;}
        auto acquired = principalSource_->readCurrentProof(*event, allnative::CatalogReceipt(principalCatalog_));
        if (!acquired.proof || !principalSource_->retainedCause(*event, *acquired.proof,
            allnative::CatalogReceipt(principalCatalog_), allnative::Stage::Active)) continue;
        const auto &metadata = event->owned();
        if (metadata.type != 3 || metadata.identity.userSid.bytes != profile_.account() ||
            (metadata.direction != Direction::Outbound && metadata.direction != Direction::Inbound)) continue;
        auto identity = gatebouncer::appidentity::attribute(metadata.identity, *formatter);
        if (identity.state != gatebouncer::appidentity::State::Attributed || !identity.target || !identity.scope)
            continue;
        const auto package = static_cast<std::uint8_t>(identity.target->packageSid ? 2 : 1);
        Bytes encoded;
        if (!principal::serializeTarget(principal::ByteView(identity.target->appId),
            principal::ByteView(identity.target->userSid), package,
            principal::ByteView(identity.target->packageSid ? *identity.target->packageSid : Bytes{}), encoded)) continue;
        principal::ByteView target(std::move(encoded));
        const auto digest = principal::targetDigest(target);
        if (digest == Digest{} || principalObservedRevision_ == UINT64_MAX) {
            principalSource_->lose(); break;
        }
        auto same = std::find_if(principalObservations_.begin(), principalObservations_.end(), [&](const auto &p) {
            const auto &o = *p.second;
            return !event->classifier_ && o.row.state == 1 && o.source == principalSource_ && o.digest == digest && o.event && !o.event->classifier_ &&
                o.event->owned().direction == metadata.direction;
        });
        wire::iv::Display projected, full;
        if (same != principalObservations_.end()) {
            projected = same->second->row.display; full = same->second->fullDisplay;
        } else {
            const auto separator = identity.display.appText.find_last_of(u"/\\");
            projected.name = displayText(separator == std::u16string::npos ?
                identity.display.appText : identity.display.appText.substr(separator + 1), 256);
            projected.principal = displayText(identity.display.principalText, 256);
            projected.package = displayText(identity.display.packageText, 256);
            full = projected; full.projection = 2; full.path = displayText(identity.display.appText, 4096);
        }
        auto displayCharge = [](const wire::iv::Display &d) { return d.name.capacity() + d.principal.capacity() +
            d.package.capacity() + d.path.capacity(); };
        // Una admisión conserva otra copia del evento. Cobrar capacidades de
        // bytes, ambos displays y objetos antes de insertarlos, incluso sin draft.
        // No es una afirmación del heap integral del allocator o del proceso.
        const auto charged = 2 * chargedBytes(metadata) + target.ownedCapacityBytes() +
            displayCharge(projected) + displayCharge(full) + sizeof(PrincipalObservation) + sizeof(PrincipalAdmission) +
            2 * gatebouncer::appidentity::MaximumSidBytes + 512 + 8192 +
            (event->classifier_ ? activityCauseBytes(*event->classifier_) : 0);
        const auto prior = same == principalObservations_.end() ? 0 : same->second->charged;
        if (same == principalObservations_.end() && principalObservations_.size() >= PendingLimit) {
            auto oldest = principalObservations_.end();
            for (auto item = principalObservations_.begin(); item != principalObservations_.end(); ++item)
                if (item->second->row.state != 1 &&
                    (oldest == principalObservations_.end() || item->second->row.revision < oldest->second->row.revision))
                    oldest = item;
            if (oldest != principalObservations_.end()) {
                principalPendingBytes_ -= oldest->second->charged; principalObservations_.erase(oldest);
            }
        }
        if (!processBudget(charged,prior) ||
            (same == principalObservations_.end() && principalObservations_.size() >= PendingLimit)) {
            principalSource_->lose(); invalidatePrincipalObservations(); break;
        }
        auto observation = same == principalObservations_.end() ? std::make_shared<PrincipalObservation>() : same->second;
        if (same == principalObservations_.end()) {
            observation->row.observed = native::randomIdentity();
            observation->row.binding = native::randomIdentity();
            if (zero(observation->row.observed) || zero(observation->row.binding)) continue;
            observation->row.source = principalSource_->binding_->epoch;
            observation->row.package = package;
            observation->row.display = std::move(projected); observation->fullDisplay = std::move(full);
            if (metadata.timestamp && *metadata.timestamp) {
                observation->row.firstUtc = *metadata.timestamp; observation->row.presence = 1;
            }
        }
        observation->row.revision = ++principalObservedRevision_;
        if (metadata.timestamp && *metadata.timestamp) {
            observation->row.lastUtc = *metadata.timestamp; observation->row.presence |= 2;
        }
        observation->target = std::move(target); observation->digest = digest;
        observation->source = principalSource_; observation->event = std::move(event);
        observation->row.temporal = observation->event->classifier_ ? 2 : 1;
        observation->proof = std::move(acquired.proof); observation->profile = profile_.value().generation;
        observation->charged = charged;
        // Una nueva causa cambia la revisión: no reutilizar un consentimiento anterior.
        for (auto entry = principalAdmissions_.begin(); entry != principalAdmissions_.end();) {
            if (entry->second->binding == observation->row.binding) {
                entry->second->cancelled = true; entry = principalAdmissions_.erase(entry);
            } else ++entry;
        }
        if (!wire::iv::valid(observation->row)) {
            principalSource_->lose(); invalidatePrincipalObservations(); break;
        }
        principalPendingBytes_ = principalPendingBytes_ - prior + charged;
        principalObservations_[observation->row.observed] = observation;
        // Sólo después de la inserción válida y de las pruebas originales arriba.
      try {
        auto history = principalEvents_.frame(Type::Attempt);
        std::uint64_t timestamp = 0;
        const bool utc = metadata.timestamp && ii::filetimeUtc(*metadata.timestamp,timestamp) && timestamp;
        const bool protocol = observation->event->classifier_ != nullptr;
        history.fields.insert(history.fields.end(), {value(Tag::Timestamp,utc ? timestamp : 0),
            value(Tag::Presence,(utc ? 1 : 0) | (protocol ? 2 : 0)),
            value(Tag::Source,protocol ? 2 : 1,1),
            value(Tag::FlowDirection,metadata.direction==Direction::Outbound ? 1 : 2,1),
            value(Tag::ObservedId,observation->row.observed), value(Tag::ObservedRevision,observation->row.revision),
            value(Tag::CaptureBindingId,observation->row.binding)});
        if (protocol) history.fields.push_back(value(Tag::Protocol,observation->event->classifier_->record_.protocol,1));
        history = ordered(std::move(history));
        observation->pendingAttempt=std::move(history);
        // El descriptor sin Records ya está cubierto por la reserva8KiB de la observación.
        if(protocol && principalImageWorker_ && principalImageJobId_ &&
           observation->event->classifier_->record_.session==principalImageSession_ &&
           observation->event->classifier_->record_.cause==principalImageCause_) {
            observation->imageJob=principalImageJobId_;observation->imageDeadline=principalAppDeadline_;
            principalPendingAppBytes_=0;
        } else if(protocol && principalImageWorker_ && !principalImageJobId_) {
            const auto cause=observation->event->classifier_;
            const auto charge=sizeof(allnative::NativeImageWorker::Operation)+sizeof(allnative::NativeImageWorker::Job)+
                activityCauseBytes(*cause)+128;
            if(processBudget(charge)) {
                const auto job=principalImageWorker_->submit(cause);
                if(job) {
                    observation->imageJob=job;observation->imageDeadline=principalNow_()+250;
                    principalImageJobId_=job;principalImageJobCharge_=charge;
                    principalImageSession_=cause->record_.session;principalImageCause_=cause->record_.cause;
                    principalAppDeadline_=observation->imageDeadline;
                }
            }
        }
        if(!observation->imageJob)publishPrincipalAttempt(*observation);
      } catch (...) { principalEvents_.fail(); observation->activityAttempt = {}; }
    }
}
} // namespace gb::decisions
