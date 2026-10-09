#include "runtime_ii.h"
#include <algorithm>
#include <thread>
namespace gb::decisions {
namespace {
Frame readOnlyA(Frame f) {
    f.minor = 0;
    f.fields.erase(std::remove_if(f.fields.begin(), f.fields.end(),
                                  [](const Field &field) {
                                      return field.tag == Tag::ProfileGeneration ||
                                             field.tag == Tag::ReviewProfileState ||
                                             field.tag == Tag::CollectorState ||
                                             field.tag == Tag::SourceCoverage;
                                  }),
                   f.fields.end());
    for (auto &field : f.fields)
        if (field.tag == Tag::Capabilities)
            field = value(Tag::Capabilities, ReadStatus);
    return f;
}
} // namespace
NativeRuntime::NativeRuntime(Coordinator &c, WfpBackend &b, SelectorRegistry &r,
                             std::filesystem::path store, Bytes account, Id epoch, Id boot)
    : coordinator_(c), backend_(b), epoch_(epoch), boot_(boot), journal_(std::move(store), epoch),
      effects_(c, journal_, b), engine_(epoch, boot, journal_, effects_),
      profile_(std::move(account)), ring_(epoch, 1), collector_(r, engine_, ring_, epoch) {
    backend_.attachCollector(&collector_);
}
NativeRuntime::~NativeRuntime() { backend_.attachCollector(nullptr); }
bool NativeRuntime::initialize() {
    JournalSnapshot snapshot;
    bool exists = false;
    if (!journal_.load(snapshot, exists))
        return false;
    auto now = GetTickCount64();
    bool changed = false;
    for (auto &row : snapshot.entries)
        if (row.state != State::Applied && effects_.proveApplied(row)) {
            row.state = State::Applied;
            row.error = Error::Ok;
            row.effective = row.desired;
            row.effectiveKnown = true;
            row.completedAt = now;
            changed = true;
        }
    if (changed && !journal_.persist(snapshot.entries))
        return false;
    if (exists && !engine_.restore(snapshot.entries, now))
        return false;
    auto status = coordinator_.status();
    journal_.observedDesired(status.desired);
    engine_.initializeRevision(status.desired, effects_.readback(status.desired));
    loaded_ = true;
    tick();
    return true;
}
void NativeRuntime::tick() {
    auto prior = profile_.value().generation;
    profile_.refresh();
    if (prior != profile_.value().generation) {
        engine_.invalidateProfile(0, GetTickCount64());
        ring_.invalidate(profile_.value().generation);
    }
    auto s = coordinator_.status();
    if (!s.effectiveKnown || s.effective != s.desired)
        collector_.unavailable(7);
    collector_.drain(profile_, GetTickCount64());
}
Frame NativeRuntime::error(Error e) const {
    Frame f;
    f.minor = 1;
    f.type = Type::ProtocolError;
    f.fields = {value(Tag::ErrorCode, unsigned(e), 2)};
    return f;
}
Frame NativeRuntime::status(Type type) const {
    auto s = coordinator_.status();
    auto active = loaded_ && !engine_.recoveryRequired() && engine_.profile().state == 1 &&
                  profile_.value().state == 1;
    std::uint64_t capabilities =
        ReadStatus | (1ull << 12) | (1ull << 13) | (1ull << 18) | (1ull << 19);
    if (active && s.effectiveKnown && collector_.state() == 1)
        capabilities |= PathPermanentRule | BlockRetry | Ipv4Ale | Ipv6Ale | (1ull << 17);
    if (collector_.state() == 1)
        capabilities |= (1ull << 14) | (1ull << 20) | (1ull << 21);
    Frame f;
    f.minor = 1;
    f.type = type;
    f.fields = {
        value(Tag::ServiceEpoch, epoch_),
        value(Tag::BootId, boot_),
        value(Tag::Capabilities, capabilities),
        value(Tag::DesiredRev, s.desired),
        value(Tag::EffectiveRev, s.effective),
        value(Tag::EffectiveKnown, s.effectiveKnown, 1),
        value(Tag::EngineState,
              unsigned(!loaded_ || engine_.recoveryRequired() ? EngineState::RecoveryRequired
                                                              : s.state),
              1),
        value(Tag::BackendMode, 1, 1),
        value(Tag::ProfileGeneration, profile_.value().generation),
        value(Tag::ReviewProfileState, profile_.value().state, 1)};
    if (type == Type::Status) {
        f.fields.push_back(value(Tag::GapCount, collector_.gaps()));
        if (capabilities & (1ull << 21)) {
            f.fields.push_back(value(Tag::CollectorState, collector_.state(), 1));
            f.fields.push_back(value(Tag::SourceCoverage, 1, 1));
        }
    }
    return f;
}
bool NativeRuntime::principals(ipc::ii::Principals &out) const {
    if (profile_.value().state != 1)
        return false;
    BYTE sid[SECURITY_MAX_SID_SIZE]{};
    DWORD bytes = sizeof(sid), domainBytes = 256;
    wchar_t domain[256]{};
    SID_NAME_USE use{};
    if (!LookupAccountNameW(L".", L"NT SERVICE\\LGAGateBouncerLab", sid, &bytes, domain,
                            &domainBytes, &use))
        return false;
    out = {profile_.account(), profile_.logon(), Bytes(sid, sid + bytes)};
    return true;
}
bool NativeRuntime::peer(HANDLE pipe, bool control, VerifiedControl &out, bool activate) {
    native::TokenEvidence token;
    native::ProcessEvidence process;
    native::Handle ownToken;
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
        return false;
    ownToken.reset(raw);
    bool full = native::systemServiceToken(ownToken.value);
    if (!full || !ipc::ii::clientEvidence(pipe, token, process) ||
        !profile_.accepts(token, control))
        return false;
    out = profile_.authority(token, full);
    if (control && activate && engine_.profile().state != 1 &&
        !engine_.activate(profile_.value(), true, GetTickCount64()))
        return false;
    return true;
}
std::vector<ii::RuleRecord> NativeRuntime::rules() const {
    auto snapshot = coordinator_.snapshot();
    auto current = coordinator_.status();
    std::vector<ii::RuleRecord> records;
    for (auto &rule : snapshot.rules) {
        ii::RuleRecord r;
        r.rule = rule.id;
        r.selector = rule.selector;
        r.revision = r.selectorRevision = 1;
        r.desired = snapshot.desired;
        r.action = rule.decision;
        r.direction = 3;
        r.effective = current.effectiveKnown && current.effective == snapshot.desired ? 1 : 0;
        records.push_back(std::move(r));
    }
    return records;
}
Frame NativeRuntime::dispatch(const Frame &f, const VerifiedControl &peer, Pages &pages) {
    tick();
    if (f.minor != 1)
        return error(Error::VersionMismatch);
    if (f.type == Type::GetStatus)
        return status(Type::Status);
    if (idValue(f, Tag::ServiceEpoch) != epoch_)
        return error(Error::Stale);
    auto p = profile_.value();
    if (p.state != 1 || peer.account != p.account || peer.logon != p.logon ||
        peer.profileGeneration != p.generation || peer.accountSid != profile_.account() ||
        peer.logonSid != profile_.logon() || peer.sessionId != profile_.session())
        return error(Error::IdentityUnavailable);
    auto now = GetTickCount64();
    if (f.type == Type::ListRules || f.type == Type::ListPending) {
        Frame query = f;
        auto snapshot = idValue(f, Tag::SnapshotId);
        Error e = Error::Ok;
        if (zero(snapshot)) {
            snapshot = native::randomIdentity();
            e = f.type == Type::ListRules
                    ? pages.rules(snapshot, rules(), coordinator_.status().desired, now)
                    : pages.pending(snapshot, engine_.pendingRows(now), ring_.latest(), now);
            for (auto &field : query.fields)
                if (field.tag == Tag::SnapshotId)
                    field = value(Tag::SnapshotId, snapshot);
        }
        Frame reply;
        if (e == Error::Ok)
            e = pages.page(query, p.generation, now, reply);
        return e == Error::Ok ? reply : error(e);
    }
    if (f.type == Type::GetPending) {
        auto record = engine_.lookup(idValue(f, Tag::RequestId), now);
        if (!record)
            return error(Error::NotFound);
        Bytes bytes;
        if (ii::pack(std::vector<ii::PendingRecord>{*record}, bytes) != Error::Ok)
            return error(Error::IdentityUnavailable);
        Frame reply;
        reply.minor = 1;
        reply.type = Type::PendingRecord;
        reply.fields = {value(Tag::ServiceEpoch, epoch_), {Tag::Records, true, std::move(bytes)}};
        return reply;
    }
    if (f.type == Type::SubscribeEvents) {
        if (get(f, Tag::EventMask) != 1 || collector_.state() != 1)
            return error(Error::Unsupported);
        if (get(f, Tag::AfterEventSeq) > ring_.latest())
            return error(Error::Malformed);
        Frame reply;
        reply.minor = 1;
        reply.type = Type::SubscriptionAck;
        reply.fields = {value(Tag::ServiceEpoch, epoch_),
                        value(Tag::EventMask, 1, 4),
                        value(Tag::EventSeq, ring_.latest()),
                        value(Tag::CollectorState, collector_.state(), 1),
                        value(Tag::SourceCoverage, 1, 1),
                        value(Tag::GapCount, collector_.gaps()),
                        value(Tag::ProfileGeneration, p.generation),
                        value(Tag::ReviewProfileState, p.state, 1)};
        return reply;
    }
    if (f.type == Type::GetCommandStatus) {
        if (!peer.highAdministrator)
            return error(Error::Unauthorized);
        auto command = idValue(f, Tag::CommandId);
        auto row = engine_.command(command, peer);
        Frame reply;
        reply.minor = 1;
        reply.type = Type::CommandStatus;
        reply.fields = {
            value(Tag::ServiceEpoch, epoch_), value(Tag::CommandId, command),
            value(Tag::CommandFound, row ? 1 : 0, 1),
            value(Tag::ErrorCode, unsigned(row ? row->error : Error::CommandUnknown), 2)};
        if (row) {
            reply.fields.push_back(value(Tag::OriginalCommandType, 9, 2));
            reply.fields.push_back(value(Tag::CommandState, unsigned(row->state), 1));
            reply.fields.push_back(value(Tag::DesiredRev, row->desired));
            reply.fields.push_back(value(Tag::EffectiveRev, row->effective));
            reply.fields.push_back(value(Tag::EffectiveKnown, row->effectiveKnown, 1));
        }
        return reply;
    }
    if (f.type == Type::CommitDecision) {
        if (!peer.highAdministrator)
            return error(Error::Unauthorized);
        if (collector_.state() != 1)
            return error(Error::BackendUnavailable);
        auto result = engine_.commit(f, peer, now);
        auto pending = engine_.lookup(idValue(f, Tag::RequestId), now);
        Frame reply;
        reply.minor = 1;
        reply.type = Type::MutationAck;
        reply.fields = {
            value(Tag::ServiceEpoch, epoch_),
            value(Tag::DesiredRev, result.desired),
            value(Tag::EffectiveRev, result.effective),
            value(Tag::EffectiveKnown, result.effectiveKnown, 1),
            value(Tag::CommandState, unsigned(result.state), 1),
            value(Tag::ErrorCode, unsigned(result.error), 2),
            value(Tag::RequestId, idValue(f, Tag::RequestId)),
            value(Tag::RequestVersion, pending ? pending->authority : get(f, Tag::RequestVersion)),
            value(Tag::RequestState, unsigned(pending ? pending->state : ii::RequestState::Stale),
                  1)};
        return reply;
    }
    return error(Error::Unsupported);
}
Error NativeRuntime::events(std::uint64_t after, std::uint32_t mask, std::vector<Frame> &rows,
                            bool &gap) const {
    return ring_.after(after, mask, rows, gap);
}
bool NativeServer::run(HANDLE stop) {
    std::thread view([&] { channel(false, stop); }), control([&] { channel(true, stop); });
    while (WaitForSingleObject(stop, 250) == WAIT_TIMEOUT) {
        std::lock_guard<std::mutex> lock(runtime_.mutex);
        runtime_.tick();
    }
    view.join();
    control.join();
    return true;
}
void NativeServer::channel(bool control, HANDLE stop) {
    const std::wstring name = control ? L"\\\\.\\pipe\\LGA.GateBouncer.Control.v1"
                                      : L"\\\\.\\pipe\\LGA.GateBouncer.View.v1";
    while (WaitForSingleObject(stop, 0) == WAIT_TIMEOUT) {
        ipc::ii::Principals principals;
        std::uint64_t profile = 0;
        {
            std::lock_guard<std::mutex> lock(runtime_.mutex);
            if (runtime_.principals(principals))
                profile = runtime_.profileGeneration();
        }
        if (!profile) {
            WaitForSingleObject(stop, 250);
            continue;
        }
        auto channel = control ? ipc::ii::Channel::Control : ipc::ii::Channel::View;
        auto anchor = ipc::ii::anchor(name, channel, principals);
        if (!anchor)
            return;
        while (WaitForSingleObject(stop, 0) == WAIT_TIMEOUT) {
            auto pipe = ipc::ii::instance(name, channel, principals);
            if (!pipe)
                return;
            if (!ipc::ii::connect(pipe.value, stop)) {
                if (WaitForSingleObject(stop, 0) != WAIT_TIMEOUT)
                    return;
                continue;
            }
            Frame hello;
            VerifiedControl peer;
            bool authenticated = false;
            if (ipc::ii::receive(pipe.value, hello, stop) &&
                (hello.minor == 1 || (!control && hello.minor == 0)) && hello.type == Type::Hello &&
                zero(hello.connection) && hello.sequence == 1 &&
                get(hello, Tag::ClientRole) == (control ? 2 : 1)) {
                std::lock_guard<std::mutex> lock(runtime_.mutex);
                runtime_.tick();
                authenticated = runtime_.profileGeneration() == profile &&
                                runtime_.peer(pipe.value, control, peer, true);
            }
            if (!authenticated) {
                DisconnectNamedPipe(pipe.value);
                continue;
            }
            auto connection = native::randomIdentity();
            Frame ack;
            {
                std::lock_guard<std::mutex> lock(runtime_.mutex);
                ack = runtime_.status(Type::HelloAck);
            }
            ack.connection = connection;
            ack.correlation = hello.correlation;
            if (!hello.minor)
                ack = readOnlyA(std::move(ack));
            if (!ipc::ii::send(pipe.value, ack, stop)) {
                DisconnectNamedPipe(pipe.value);
                continue;
            }
            Pages pages(runtime_.epoch(), profile);
            std::uint64_t rx = 2, tx = 2, lastActivity = GetTickCount64(), after = 0;
            std::uint32_t mask = 0;
            while (WaitForSingleObject(stop, 0) == WAIT_TIMEOUT &&
                   GetTickCount64() - lastActivity < 60000) {
                if (mask) {
                    std::vector<Frame> events;
                    bool gap = false;
                    bool usable = true;
                    {
                        std::lock_guard<std::mutex> lock(runtime_.mutex);
                        usable = runtime_.profileGeneration() == profile &&
                                 runtime_.peer(pipe.value, control, peer, false);
                        if (usable) {
                            auto e = runtime_.events(after, mask, events, gap);
                            if (gap || e == Error::Capacity) {
                                auto prior = runtime_.latest();
                                usable = runtime_.clientGap() &&
                                         runtime_.events(prior, mask, events, gap) == Error::Ok;
                            } else if (e != Error::Ok)
                                usable = false;
                        }
                    }
                    if (!usable)
                        break;
                    bool sent = true;
                    for (auto &event : events) {
                        if (tx == UINT64_MAX) {
                            sent = false;
                            break;
                        }
                        event.connection = connection;
                        event.sequence = tx++;
                        if (!ipc::ii::send(pipe.value, event, stop)) {
                            sent = false;
                            break;
                        }
                        after = get(event, Tag::EventSeq);
                    }
                    if (!sent)
                        break;
                }
                DWORD available = 0;
                if (!PeekNamedPipe(pipe.value, nullptr, 0, nullptr, &available, nullptr))
                    break;
                if (!available) {
                    WaitForSingleObject(stop, 50);
                    continue;
                }
                Frame f;
                if (!ipc::ii::receive(pipe.value, f, stop) || f.minor != hello.minor ||
                    f.connection != connection || f.sequence != rx++ || rx == UINT64_MAX ||
                    tx == UINT64_MAX)
                    break;
                Frame response;
                {
                    std::lock_guard<std::mutex> lock(runtime_.mutex);
                    if (runtime_.profileGeneration() != profile ||
                        !runtime_.peer(pipe.value, control, peer, false))
                        break;
                    if (!hello.minor) {
                        response = runtime_.status(Type::Status);
                        if (f.type != Type::GetStatus) {
                            response = {};
                            response.type = Type::ProtocolError;
                            response.fields = {
                                value(Tag::ErrorCode, unsigned(Error::Unsupported), 2)};
                        }
                        response = readOnlyA(std::move(response));
                    } else
                        response = runtime_.dispatch(f, peer, pages);
                }
                response.connection = connection;
                response.sequence = tx++;
                response.correlation = f.correlation;
                if (wire::validate(response) != Error::Ok ||
                    !ipc::ii::send(pipe.value, response, stop))
                    break;
                if (response.type == Type::SubscriptionAck) {
                    mask = std::uint32_t(get(f, Tag::EventMask));
                    after = get(f, Tag::AfterEventSeq);
                    if (!after)
                        after = get(response, Tag::EventSeq);
                }
                lastActivity = GetTickCount64();
            }
            DisconnectNamedPipe(pipe.value);
            {
                std::lock_guard<std::mutex> lock(runtime_.mutex);
                if (runtime_.profileGeneration() != profile)
                    break;
            }
        }
    }
}
} // namespace gb::decisions
