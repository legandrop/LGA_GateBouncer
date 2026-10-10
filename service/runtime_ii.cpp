#include "runtime_ii.h"
#include "runtime_reply_iii.h"
#include "principal_actor_vi.h"
#include "../common/ordinary_iii_win.h"
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
                                             field.tag == Tag::SourceCoverage ||
                                             field.tag == Tag::DirectionProfile;
                                  }),
                   f.fields.end());
    for (auto &field : f.fields)
        if (field.tag == Tag::Capabilities)
            field = value(Tag::Capabilities, ReadStatus);
    return f;
}
Frame readOnlyII(Frame f) {
    f.minor = 1;
    f.fields.erase(std::remove_if(f.fields.begin(), f.fields.end(), [](const Field &field) {
        return field.tag == Tag::DirectionProfile || field.tag == Tag::CollectorState ||
               field.tag == Tag::SourceCoverage;
    }), f.fields.end());
    for (auto &field : f.fields)
        if (field.tag == Tag::Capabilities) field = value(Tag::Capabilities, ReadStatus);
    return f;
}
} // namespace
bool NativeRuntime::principalActorCurrent(const PrincipalAdmission &admission) const noexcept {
    struct Owner { const NativeRuntime &runtime; const PrincipalAdmission &admission; }
        owner{*this, admission};
    auto accepts = [](void *raw, const native::TokenEvidence &fresh) noexcept {
        auto &o = *static_cast<Owner *>(raw);
        try { return o.admission.owner && o.runtime.principalPeerCurrent(*o.admission.owner) &&
            o.runtime.profile_.value().generation == o.admission.profile &&
            o.runtime.profile_.accepts(fresh, false); }
        catch (...) { return false; }
    };
    return PrincipalActorQuery::current(admission.actor, admission.identity,
        admission.cancelled, &owner, accepts, principalActorApi_);
}
bool NativeRuntime::principalAdmissionCurrent(const PrincipalAdmission &admission,
    const principal::Entry &command, allnative::Stage requiredStage) const noexcept {
    try {
        const auto found = principalAdmissions_.find(admission.request);
        if (found == principalAdmissions_.end() || found->second.get() != &admission ||
            admission.cancelled || !admission.revision || admission.source != principalSource_ ||
            !principalCatalog_ || !admission.source || admission.source->stage() != requiredStage ||
            admission.source->poisoned_.load() ||
            (requiredStage != allnative::Stage::Active && requiredStage != allnative::Stage::Drained) ||
            !principalActorCurrent(admission) ||
            admission.profile != profile_.value().generation || command.command.commandEpoch != epoch_ ||
            command.command.boot != boot_ || command.command.profileGeneration != admission.profile ||
            command.command.accountSid != admission.identity.account ||
            command.command.logonSid != admission.identity.logon ||
            command.command.sessionId != admission.identity.session ||
            principalNow_() >= admission.deadline) return false;
        const auto &current = admission.identity;
        Frame frame;
        if (decode(command.command.payload, frame) != Error::Ok ||
            !find(frame, Tag::TargetDigest) || find(frame, Tag::TargetDigest)->bytes !=
                Bytes(admission.target.begin(), admission.target.end()) ||
            !find(frame, Tag::MigrationDigest) || find(frame, Tag::MigrationDigest)->bytes != Bytes(32)) return false;
        if (frame.type == Type::RevokePrincipalRule) {
            if (!admission.revocation) return false;
            const auto &rule = *admission.revocation;
            const auto currentRule = std::find_if(principalCatalog_->rules_.begin(), principalCatalog_->rules_.end(),
                [&](const auto &r) { return r.rule == rule.id; });
            principal::Target target;
            if (currentRule == principalCatalog_->rules_.end() || rule.kind != 1 ||
                !principal::parseTarget(rule.target, target)) return false;
            const auto view = principalCatalog_->ruleView(static_cast<std::size_t>(
                currentRule - principalCatalog_->rules_.begin()));
            auto exact = [](const principal::ByteView &bytes, allnative::recipe::ByteView current) {
                return bytes.size() == current.size && (!current.size ||
                    std::equal(bytes.data(), bytes.data() + bytes.size(), current.data));
            };
            return view.targetKind == 1 && view.packageMode == target.packageMode &&
                exact(target.app, view.app) && exact(target.user, view.user) && exact(target.package, view.package) &&
                currentRule->ruleRevision == rule.revision && currentRule->targetRevision == rule.targetRevision &&
                idValue(frame, Tag::RuleId) == rule.id && get(frame, Tag::RuleRevision) == rule.revision &&
                get(frame, Tag::TargetRevision) == rule.targetRevision &&
                principal::targetDigest(rule.target) == admission.target &&
                target.user == principal::ByteView(current.account);
        }
        if (frame.type != Type::CommitFuturePolicy || !admission.event || !admission.proof ||
            !(admission.cancelSealed ?
                requiredStage == allnative::Stage::Drained && admission.source->retainedCancelledCause(
                    *admission.event, *admission.proof, allnative::CatalogReceipt(principalCatalog_), admission.cancelledDecision, backend_.engine_) :
                admission.source->retainedCause(*admission.event, *admission.proof,
                    allnative::CatalogReceipt(principalCatalog_), requiredStage)) ||
            idValue(frame, Tag::SourceEpoch) != admission.source->binding_->epoch ||
            idValue(frame, Tag::DraftId) != admission.request || get(frame, Tag::DraftVersion) != admission.revision ||
            idValue(frame, Tag::CaptureBindingId) != admission.binding ||
            idValue(frame, Tag::SelectorId) != admission.selector ||
            idValue(frame, Tag::ConsentChallengeId) != admission.challenge ||
            get(frame, Tag::ExpectedDesiredRev) != admission.expectedDesired ||
            get(frame, Tag::TargetRevision) != 1 || get(frame, Tag::PackageMode) != admission.package ||
            get(frame, Tag::PolicyDirection) != admission.direction ||
            get(frame, Tag::ScopeKind) != admission.scope ||
            get(frame, Tag::ScopeDurationMs) != admission.durationMs ||
            get(frame, Tag::AcceptedScope) != (admission.scope >= 3 ? (1u << admission.scope) :
                (1u | (admission.package == 1 ? 2u : 0u) |
                (get(frame, Tag::Decision) == 2 && admission.direction == 3 ? 4u : 0u))))
            return false;
        return true;
    } catch (...) { return false; }
}
directional::Result NativeRuntime::writePrincipal(const principal::Snapshot &target,
    const principal::Entry &command, const std::shared_ptr<PrincipalAdmission> &admission) {
    using Reason = gatebouncer::service::windows::allapps::Reason;
    directional::Result result;
    if (!admission || admission->consumed || principalWriteFault_ || !principalMode_ ||
        !principalStore_ || principalStore_->uncertain() || !observationEngine_ ||
        !principalAdmissionCurrent(*admission, command) ||
        principalRead_.kind != principal::StoredImage::Principal ||
        principalRead_.snapshot.sequence == UINT64_MAX ||
        target.sequence != principalRead_.snapshot.sequence + 1 ||
        principalRead_.snapshot.desired == UINT64_MAX ||
        target.desired != principalRead_.snapshot.desired + 1 ||
        inventoryRevision_ == UINT64_MAX) return result;
    admission->consumed = true; // Un resultado incierto nunca admite retransacción.
    const auto oldCatalog = principalCatalog_;
    const auto oldSource = principalSource_;
    try {
        CatalogPlanBuilder plan(catalogRegistry_, allnative::MaxPolicyArenaBytes,
                                allnative::MaxCatalogRules, allnative::MaxCatalogSlots);
        principal::ByteView bytes;
        if (!principal::ByteView::prepareOwned(target, command, bytes) || !plan.retain(bytes)) return result;
        principal::Snapshot checked;
        if (!principal::parse(bytes, checked) ||
            !principal::validTransition(principalRead_.snapshot.encoded, checked)) return result;
        const auto rule = std::find_if(checked.rules.begin(), checked.rules.end(), [&](const auto &r) {
            return r.id == command.command.id;
        });
        principal::Target principalTarget;
        Frame canonicalCommand;
        if (decode(command.command.payload, canonicalCommand) != Error::Ok) return result;
        if (canonicalCommand.type == Type::CommitFuturePolicy) {
        const auto &identity = admission->event->owned().identity;
        if (rule == checked.rules.end() || !principal::parseTarget(rule->target, principalTarget) ||
            identity.appId.state != gatebouncer::appidentity::FieldState::Copied ||
            identity.userSid.state != gatebouncer::appidentity::FieldState::Copied ||
            principalTarget.app != principal::ByteView(identity.appId.bytes) ||
            principalTarget.user != principal::ByteView(identity.userSid.bytes) ||
            identity.userSid.bytes != admission->identity.account ||
            (principalTarget.packageMode == 2 &&
             (identity.packageSid.state != gatebouncer::appidentity::FieldState::Copied ||
              principalTarget.package != principal::ByteView(identity.packageSid.bytes)))) return result;
        }
        const auto sequence = principalRead_.snapshot.sequence;
        const auto desired = principalRead_.snapshot.desired;
        auto prepared = principalStore_->replaceOwned(sequence, desired, bytes);
        if (!prepared.physicallyConfirmed) { principalWriteFault_ = true; return result; }
        principalRead_ = principalStore_->read_;
        principalDesired_ = target.desired;
        result.state = State::Prepared; result.desired = target.desired;
        result.observedSequence = sequence + 1; result.observed = directional::Observed::Prepared;
        profile_.refresh();
        if (!principalAdmissionCurrent(*admission, command)) return result;
        if (admission->event && admission->event->classifier_) {
            auto cause = admission->event->classifier_;
            if (!principalClassifier_ || cause->owner_ != principalClassifier_ || !cause->current() ||
                !principalClassifier_->filterCurrent(*cause, backend_.engine_)) return result;
            auto &cancel = admission->cancelledDecision;
            cancel.version = GB_CLASSIFIER_VERSION; cancel.bytes = sizeof(cancel);
            cancel.session = cause->record_.session; cancel.cause = cause->record_.cause;
            cancel.revision = command.command.desired; cancel.scope = 2;
            cancel.action = static_cast<UINT32>(get(canonicalCommand, Tag::Decision));
            std::copy(command.command.id.begin(), command.command.id.end(), cancel.command);
            GB_CANCEL_RECEIPT delivered{}, retained{};
            // Prepared ya está durable. CANCEL se manda una vez; guarded no es ACK de Complete.
            if (!principalClassifier_->cancel(cancel, delivered) || !principalClassifier_->cancelReadback(cancel, retained)) return result;
            admission->cancelSealed = true;
        }
        // Retiro irreversible A antes de crear B: conservar A y sus eventos,
        // jamás construir un segundo Source bajo RPC/callback/fault pendiente.
        if (oldSource->stop() != allnative::Stage::Drained) {
            principalWriteFault_ = true; return result;
        }
        auto sdk = principalSdk_();
        auto source = std::shared_ptr<allnative::NativeSource>(new allnative::NativeSource(
            allnative::EngineLease(observationEngine_->handle(), observationEngine_->pin()),
            allnative::BindReceipt(observationEngine_->context_, observationEngine_->generation_), sdk, principalClassifier_));
        std::array<std::uint16_t, 8> domain{};
        std::array<allnative::recipe::SupportField, 32> support{};
        std::size_t count = 0;
        if (observationEngine_->readDomain(domain, support, count) != Reason::None ||
            plan.stage(bytes, source->binding_, inventoryRevision_ + 1, domain,
                       {support.data(), count}) != Reason::None) return result;
        struct BeforeEffect { NativeRuntime &runtime; PrincipalAdmission &admission;
            const principal::Entry &command; std::shared_ptr<allnative::NativeSource> source;
            std::shared_ptr<const allnative::CatalogSnapshot> catalog; } before{
                *this, *admission, command, oldSource, oldCatalog};
        auto verify = [](void *raw) noexcept {
            auto &b = *static_cast<BeforeEffect *>(raw);
            // El Source A está Drained y conserva catálogo; el read exacto se
            // ejecuta en engine NO-DYNAMIC dentro de su write transaction.
            try { b.runtime.profile_.refresh();
                return b.runtime.principalAdmissionCurrent(b.admission, b.command, allnative::Stage::Drained) &&
                (!b.admission.event || b.admission.cancelSealed ||
                    b.source->classifierCurrent(*b.admission.event, b.runtime.backend_.engine_)) &&
                b.source->readInventory(b.runtime.backend_.engine_,
                    allnative::CatalogReceipt(b.catalog)) == Reason::None; }
            catch (...) { return false; }
        };
        auto effect = backend_.applyPrincipalPlan(plan, oldCatalog, verify, &before);
        if (!effect.committed || effect.cleanupUnknown ||
            plan.confirmInventory(observationEngine_->handle(), sdk, &allnative::guardedRead) != Reason::None) {
            principalWriteFault_ = true; result.state = State::RecoveryRequired; return result;
        }
        result.appliedReal = true; result.state = State::AppliedUnrecorded;
        profile_.refresh();
        if (!principalAdmissionCurrent(*admission, command, allnative::Stage::Drained)) {
            principalWriteFault_ = true; return result;
        }
        // Soltar las subviews de validación del target B antes del seal único.
        principalTarget = {};
        struct Seal { CatalogPlanBuilder &plan; principal::ByteView &bytes;
            principal::StoreRead &runtimeRead;
            principal::Snapshot &parsed; std::shared_ptr<const allnative::CatalogSnapshot> catalog;
            static bool before(void *raw) noexcept { auto &s = *static_cast<Seal *>(raw);
                s.bytes = {}; s.parsed = {}; s.runtimeRead = {}; return s.plan.detachOutcomeArena(); }
            static bool after(void *raw, const principal::ByteView &bytes) noexcept {
                auto &s = *static_cast<Seal *>(raw);
                if (!s.plan.attachOutcomeArena(bytes)) return false;
                s.catalog = s.plan.freeze(); return bool(s.catalog); }
        } seal{plan, bytes, principalRead_, checked, {}};
        const auto final = principalStore_->completeOwned(sequence + 1, target.desired,
            principalNow_(), &seal, &Seal::before, &Seal::after);
        if (!final.physicallyConfirmed) { principalWriteFault_ = true; return result; }
        principalRead_ = principalStore_->read_;
        principalCatalog_ = std::move(seal.catalog); principalSource_ = std::move(source);
        ++inventoryRevision_;
        const auto started = principalSource_->start(allnative::CatalogReceipt(principalCatalog_));
        result.durable = true; result.state = State::Applied; result.error = Error::Ok;
        result.observed = directional::Observed::FinalApplied; result.observedSequence = sequence + 2;
        // Read-accessible sólo prueba forma. Ningún outcome anuncia protección,
        // coverageReady ni un permiso efectivo para el cliente.
        profile_.refresh();
        // El flush y start pudieron cruzar un cambio de token: consultar el
        // HANDLE retenido otra vez, sin depender del Source A ya retirado.
        if (started != Reason::None || !principalActorCurrent(*admission)) {
            principalWriteFault_ = true;
            result.state = State::RecoveryRequired; result.error = Error::RecoveryRequired;
        }
        return result;
    } catch (...) { principalWriteFault_ = true; return result; }
}
NativeRuntime::NativeRuntime(WfpBackend &b, SelectorRegistry &r,
                             std::filesystem::path store, Bytes account, Id epoch, Id boot,
                             std::filesystem::path ordinaryImage, std::shared_ptr<controller::Deployment> deployment)
    : ordinaryImage_(std::move(ordinaryImage)), deployment_(std::move(deployment)), scopedJournal_(store), file_(std::move(store)),
      directions_(b), coordinator_(file_, directions_, r, epoch),
      backend_(b), registry_(r), epoch_(epoch), boot_(boot), journal_(coordinator_, r),
      effects_(coordinator_, directions_), engine_(epoch, boot, journal_, effects_, 2),
      profile_(std::move(account)), ring_(epoch, 1, 2), collector_(r, engine_, ring_, epoch) {
    // El cargo de un source retirado puede sobrevivir al Runtime. Compartir
    // el registro del proceso mientras queda cualquier token físico evita
    // reiniciar el límite al construir otro owner; el registro no posee arenas.
    static std::mutex registryMutex;
    static std::weak_ptr<allnative::CatalogRegistry::State> processRegistry;
    {
        std::lock_guard<std::mutex> lock(registryMutex);
        if (auto state = processRegistry.lock()) catalogRegistry_.state_ = std::move(state);
        else processRegistry = catalogRegistry_.state_;
    }
    backend_.attachCollector(&collector_);
}
NativeRuntime::~NativeRuntime() {
    finishPrincipalImages();
    invalidatePrincipalObservations();
    retirePrincipalObservation();
    backend_.attachCollector(nullptr);
}
bool NativeRuntime::deploymentCurrent() const noexcept {
    return deployment_ && deployment_->current();
}
bool NativeRuntime::initialize(bool provision) {
    if (!deploymentCurrent()) return false;
    // Adquisición real opcional del dispositivo del servicio. Su ausencia deja
    // el productor de netevents existente; no anuncia scopes de proceso/Once.
    principalClassifier_ = allnative::NativeClassifier::open();
    provisionRequested_ = provision;
    if (!loadPrincipalImage()) return false;
    if (principalMode_) {
        loaded_ = true;
        tick();
        return true;
    }
    if (!coordinator_.load()) return false;
    directions_.initialLegacy(coordinator_.legacy());
    // Leer/migrar no aplica baseline ni reproduce comandos. Gate U aún sin prueba OS.
    if (directions_.ready()) coordinator_.reconcile();
    auto snapshot = coordinator_.snapshot();
    auto now = GetTickCount64();
    std::vector<CommandEntry> commits;
    for (const auto &entry : snapshot.entries) {
        Frame f;
        if (decode(entry.command.payload, f) != Error::Ok) return false;
        if (f.minor == 2 && f.type == Type::CommitDecision) commits.push_back(entry.command);
    }
    if (!commits.empty() && !engine_.restore(commits, now)) return false;
    engine_.initializeRevision(snapshot.desired, effects_.ready() && effects_.readback(snapshot.desired));
    loaded_ = true;
    tick();
    return true;
}
ServiceContext NativeRuntime::serviceContext() const {
    std::lock_guard<std::mutex> lock(mutex);
    return readServiceContext();
}
ServiceContext NativeRuntime::readServiceContext() const noexcept {
    ServiceContext unavailable{epoch_, boot_, {}, 0};
    if (deployment_ && !deploymentCurrent()) return unavailable;
    const auto source = principalSource_;
    const auto catalog = principalCatalog_;
    const auto engine = observationEngine_;
    bool worker = false;
    try {
      if (!source || !catalog || !engine || source->stage() != allnative::Stage::Active ||
        source->binding_ != catalog->binding_ ||
        source->binding_->epoch != engine->context_ ||
        source->binding_->generation != engine->generation_ ||
        std::atomic_load(&source->catalog_) != catalog ||
        !source->control_.beginWorker()) return unavailable;
        worker = true;
        const auto before = source->source_.health();
        allnative::CatalogReceipt receipt(catalog);
        const auto result = source->reconcile(receipt); // READ actual completo; el cache status no lo sustituye.
        auto handle = source->control_.finishWorker();
        worker = false;
        if (handle) source->cancel(handle);
        source->finalize();
        const auto after = source->source_.health();
        if (result != gatebouncer::service::windows::allapps::Reason::None ||
            source->stage() != allnative::Stage::Active ||
            before.health != gatebouncer::service::windows::allapps::Health::Ready ||
            after.health != gatebouncer::service::windows::allapps::Health::Ready ||
            before.lossRevision != after.lossRevision ||
            std::atomic_load(&source->catalog_) != catalog) {
            source->lose();
            return unavailable;
        }
        return {epoch_, boot_, engine->context_, engine->generation_};
    } catch (...) {
        if (source) {
            source->lose();
            if (worker) {
                if (auto handle = source->control_.finishWorker()) source->cancel(handle);
            }
            source->finalize();
        }
        return unavailable;
    }
}
bool NativeRuntime::acquireObservationEngine() {
    if (observationEngine_) return true;
    if (retainedEngineFault_ || observationGeneration_ == UINT64_MAX) return false;
    auto acquired = EngineResource::acquire(observationGeneration_ + 1, &retainedEngineFault_);
    if (!acquired) return false;
    ++observationGeneration_;
    observationEngine_ = std::move(acquired);
    return true;
}
bool NativeRuntime::loadPrincipalImage() {
    if (principalStore_) return false;
    try {
        // Cargo completo ANTES de read/ByteView/parse. La función retainRead
        // ancla ese mismo cargo al owner físico antes de crear metadata IV.
        CatalogPlanBuilder plan(catalogRegistry_, allnative::MaxPolicyArenaBytes,
                                allnative::MaxCatalogRules, allnative::MaxCatalogSlots);
        if (plan.reservationStatus() != gatebouncer::service::windows::allapps::Reason::None)
            return false;
        auto file = std::shared_ptr<directional::SnapshotFile>(&file_, [](auto *) {});
        principalStore_ = std::make_unique<principal::SnapshotStore>(std::move(file));
        if (!principalStore_->loadRetained(principalRead_, &plan, &CatalogPlanBuilder::retainRead))
            return false;
        if (principalRead_.kind == principal::StoredImage::LegacyReadOnly) {
            // Compatibilidad III: se suelta el lease IV antes del único owner III.
            principalStore_.reset();
            principalRead_ = {};
            return true;
        }
        principalMode_ = true;
        principalDesired_ = principalRead_.snapshot.desired;
        if (principalRead_.kind == principal::StoredImage::Missing && provisionRequested_) {
            if (!provisionPrincipalImage(plan)) principalWriteFault_ = true;
            return true;
        }
        if (principalRead_.kind == principal::StoredImage::Principal)
            bindPrincipalObservation(plan);
        // Un archivo histórico, Missing o un fallo de lectura actual no crea
        // permisos, baseline ni replay. El servicio queda consultable sin efecto conocido.
        return true;
    } catch (...) { return false; }
}
bool NativeRuntime::provisionPrincipalImage(CatalogPlanBuilder &plan) {
    using Reason = gatebouncer::service::windows::allapps::Reason;
    if (initialAttempted_ || !provisionRequested_ || !deploymentCurrent() || !principalStore_ ||
        principalStore_->uncertain() || principalRead_.kind != principal::StoredImage::Missing || principalSource_ ||
        inventoryRevision_ || !file_.cleanForInitial(principalStore_.get())) return false;
    initialAttempted_ = true; // Consumido también si falla reserva, lectura o flush: no retry.
    try {
        if (!acquireObservationEngine()) return false;
        principal::Snapshot bootstrap;
        bootstrap.sequence = 1; bootstrap.writerEpoch = epoch_;
        Bytes policy, directions, journal, serialized;
        if (!principal::sections({},0,policy,directions) ||
            !principal::serializeJournal(std::vector<principal::Entry>{},1,0,epoch_,journal)) return false;
        bootstrap.policy = principal::ByteView(std::move(policy));
        bootstrap.directions = principal::ByteView(std::move(directions));
        bootstrap.journal = principal::ByteView(std::move(journal));
        bootstrap.targetSet = principal::targetSetDigest(0,bootstrap.policy,bootstrap.directions);
        if (!principal::serialize(bootstrap,serialized)) return false;
        principal::ByteView bytes(std::move(serialized));
        if (!plan.retain(bytes)) return false;
        auto sdk = principalSdk_();
        auto source = std::shared_ptr<allnative::NativeSource>(new allnative::NativeSource(
            allnative::EngineLease(observationEngine_->handle(),observationEngine_->pin()),
            allnative::BindReceipt(observationEngine_->context_,observationEngine_->generation_),sdk,principalClassifier_));
        if (!source->prerequisites()) return false;
        std::array<std::uint16_t,8> domain{}; std::array<allnative::recipe::SupportField,32> support{};
        std::size_t count = 0;
        if (observationEngine_->readDomain(domain,support,count) != Reason::None ||
            plan.stage(bytes,source->binding_,1,domain,{support.data(),count}) != Reason::None ||
            !deploymentCurrent() || !file_.cleanForInitial(principalStore_.get())) return false;
        const auto saved = principalStore_->replaceOwned(0,0,bytes);
        if (!saved.physicallyConfirmed) return false;
        principalRead_ = principalStore_->read_;
        struct Before { NativeRuntime &runtime; const principal::ByteView &bytes;
            std::shared_ptr<allnative::NativeSource> source; } before{*this,bytes,source};
        const auto verify = [](void *raw) noexcept {
            auto &b = *static_cast<Before *>(raw);
            try {
                bool same = false, exists = false;
                return b.runtime.deploymentCurrent() && b.source->prerequisites() && b.runtime.principalStore_ &&
                    !b.runtime.principalStore_->uncertain() &&
                    b.runtime.file_.compare(b.bytes.data(),b.bytes.size(),same,exists) && same && exists;
            } catch (...) { return false; }
        };
        const auto effect = backend_.applyInitialPrincipalPlan(plan,verify,&before);
        if (!effect.attempted || !effect.committed || effect.cleanupUnknown || !deploymentCurrent() ||
            plan.confirmInventory(observationEngine_->handle(),sdk,&allnative::guardedRead) != Reason::None) return false;
        const auto catalog = plan.freeze();
        if (!catalog || !deploymentCurrent()) return false;
        const auto started = source->start(allnative::CatalogReceipt(catalog));
        // Un fallo de start conserva el pin hasta el retiro/drenado; nunca publica catálogo parcialmente sano.
        principalSource_ = std::move(source);
        if (started != Reason::None) { retirePrincipalObservation(); return false; }
        principalCatalog_ = catalog; inventoryRevision_ = 1;
        return true; // Bootstrap queda RecoveryRequired/Unknown: sin Applied ni completeOwned.
    } catch (...) { return false; }
}
bool NativeRuntime::bindPrincipalObservation(CatalogPlanBuilder &plan) {
    using Reason = gatebouncer::service::windows::allapps::Reason;
    if (principalRead_.kind != principal::StoredImage::Principal || principalSource_ ||
        inventoryRevision_ == UINT64_MAX || !acquireObservationEngine()) return false;
    try {
        auto sdk = principalSdk_();
        auto source = std::shared_ptr<allnative::NativeSource>(new allnative::NativeSource(
            allnative::EngineLease(observationEngine_->handle(), observationEngine_->pin()),
            allnative::BindReceipt(observationEngine_->context_, observationEngine_->generation_), sdk, principalClassifier_));
        std::array<std::uint16_t, 8> domain{};
        std::array<allnative::recipe::SupportField, 32> support{};
        std::size_t count = 0;
        if (observationEngine_->readDomain(domain, support, count) != Reason::None ||
            plan.stage(principalRead_.snapshot.encoded, source->binding_, inventoryRevision_ + 1,
                       domain, {support.data(), count}) != Reason::None ||
            plan.confirmInventory(observationEngine_->handle(), sdk, &allnative::guardedRead) != Reason::None)
            return false;
        auto catalog = plan.freeze();
        if (!catalog) return false;
        allnative::CatalogReceipt receipt(catalog); // Únicamente owner real, después del readback completo.
        principalSource_ = std::move(source);
        if (principalSource_->start(receipt) != Reason::None) {
            retirePrincipalObservation();
            return false;
        }
        ++inventoryRevision_;
        principalCatalog_ = std::move(catalog);
        return true;
    } catch (...) {
        retirePrincipalObservation();
        return false;
    }
}
void NativeRuntime::retirePrincipalObservation() noexcept {
    principalCatalog_.reset();
    if (principalSource_) {
        const auto stage = principalSource_->stop();
        if (stage != allnative::Stage::Drained) return; // Mantener pin en RPC/callback/fault.
        principalSource_.reset();
    }
    if (observationEngine_ && observationEngine_->retire() == ERROR_SUCCESS)
        observationEngine_.reset();
    if (retainedEngineFault_ && retainedEngineFault_->retire() == ERROR_SUCCESS)
        retainedEngineFault_.reset();
}
void NativeRuntime::tick() {
    pollPrincipalImages();
    pollPrincipalPendingApp();
    auto prior = profile_.value().generation;
    profile_.refresh();
    if (prior != profile_.value().generation) {
        if (principalClassifier_) principalClassifier_->reset();
        invalidatePrincipalObservations();
        engine_.invalidateProfile(0, GetTickCount64());
        ring_.invalidate(profile_.value().generation);
    }
    if (principalMode_) {
        collector_.unavailable(7);
        if (!principalSource_ || principalSource_->stage() != allnative::Stage::Active ||
            principalSource_->source_.health().health != gatebouncer::service::windows::allapps::Health::Ready ||
            principalWriteFault_) { if (principalClassifier_) principalClassifier_->reset(); invalidatePrincipalObservations(); }
        else { pollPrincipalImages(); collectPrincipalObservations(); pollPrincipalImages(); }
        prunePrincipalProcesses();
        // READBACK acotado y circular: conserva la causa histórica precompletion.
        for (std::size_t work=0, limit=std::min<std::size_t>(8,principalOutcomes_.size()); work<limit; ++work) {
            auto outcome=principalOutcomes_.upper_bound(principalOutcomeCursor_);
            if (outcome==principalOutcomes_.end()) outcome=principalOutcomes_.begin();
            principalOutcomeCursor_=outcome->first;
            if (outcome->second.activityAttempt.type==Type::Attempt && !outcome->second.activityCompleted)
                refreshScoped(outcome->second);
        }
        pollPrincipalTraffic();
        const auto now = principalNow_();
        for (auto entry = principalAdmissions_.begin(); entry != principalAdmissions_.end();) {
            auto &admission = *entry->second;
            if (admission.cancelled || admission.consumed || admission.profile != profile_.value().generation ||
                !admission.owner || admission.owner->cancelled || now >= admission.deadline ||
                !principalActorCurrent(admission)) {
                admission.cancelled = true; entry = principalAdmissions_.erase(entry);
            } else ++entry;
        }
        return;
    }
    if (coordinator_.recovery() || !directions_.ready())
        collector_.unavailable(7);
    collector_.drain(profile_, GetTickCount64());
}
Frame NativeRuntime::error(Error e) const {
    Frame f;
    f.minor = 2;
    f.type = Type::ProtocolError;
    f.fields = {value(Tag::ErrorCode, unsigned(e), 2)};
    return f;
}
Frame NativeRuntime::status(Type type, std::uint16_t minor) const {
    if (minor == 3) {
        const auto context = readServiceContext();
        Bytes payload;
        if (wire::iv::encodeServiceContext(context, payload) != Error::Ok) {
            auto failed = error(Error::IdentityUnavailable);
            failed.minor = 3;
            return failed;
        }
        Frame frame;
        frame.minor = 3;
        frame.type = type;
        frame.fields = {value(Tag::ServiceEpoch, epoch_), value(Tag::BootId, boot_),
            value(Tag::Capabilities, ReadStatus),
            value(Tag::DesiredRev, principalMode_ ? principalDesired_ : coordinator_.snapshot().desired),
            value(Tag::EffectiveRev, 0), value(Tag::EffectiveKnown, 0, 1),
            value(Tag::EngineState, unsigned(EngineState::RecoveryRequired), 1)};
        if (type == Type::Status) frame.fields.push_back(value(Tag::GapCount, collector_.gaps()));
        frame.fields.insert(frame.fields.end(), {value(Tag::BackendMode, 1, 1),
            value(Tag::ProfileGeneration, profile_.value().generation),
            value(Tag::ReviewProfileState, profile_.value().state, 1),
            value(Tag::SourceEpoch, context.engineContext), value(Tag::IVProfile, 0, 1),
            {Tag::ServiceContext, true, std::move(payload)}});
        return frame; // View: sólo identidad/readback accesible, sin permiso ni efecto conocido.
    }
    auto s = coordinator_.snapshot();
    if (principalMode_) s.desired = principalDesired_;
    auto known = !principalMode_ && loaded_ && !coordinator_.recovery() && directions_.ready() &&
                 coordinator_.currentReadback(s.desired);
    auto active = known && !engine_.recoveryRequired() && engine_.profile().state == 1 &&
                  profile_.value().state == 1;
    std::uint64_t capabilities =
        ReadStatus | (1ull << 12) | (1ull << 13) | (1ull << 18) | (1ull << 19);
    if (active && collector_.state() == 1)
        capabilities |= PathPermanentRule | RuleRevoke | Ipv4Ale | Ipv6Ale |
                        (1ull << 17) | DirectionalPath;
    if (active && collector_.state() == 1 && !coordinator_.legacy())
        capabilities |= BlockRetry;
    if (collector_.state() == 1)
        capabilities |= (1ull << 14) | (1ull << 20) | (1ull << 21);
    Frame f;
    f.minor = 2;
    f.type = type;
    f.fields = {
        value(Tag::ServiceEpoch, epoch_),
        value(Tag::BootId, boot_),
        value(Tag::Capabilities, capabilities),
        value(Tag::DesiredRev, s.desired),
        value(Tag::EffectiveRev, known ? s.desired : 0),
        value(Tag::EffectiveKnown, known, 1),
        value(Tag::EngineState,
              unsigned(!known || engine_.recoveryRequired() ? EngineState::RecoveryRequired
                                                           : EngineState::ReadyUnvalidated),
              1),
        value(Tag::BackendMode, 1, 1),
        value(Tag::ProfileGeneration, profile_.value().generation),
        value(Tag::ReviewProfileState, profile_.value().state, 1)};
    if (capabilities & DirectionalPath) f.fields.push_back(value(Tag::DirectionProfile, 1, 1));
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
    if (!principalMode_ && control && activate && directions_.ready() && !coordinator_.recovery() && engine_.profile().state != 1 &&
        !engine_.activate(profile_.value(), true, GetTickCount64()))
        return false;
    return true;
}
std::vector<ii::RuleRecord> NativeRuntime::rules() const {
    auto snapshot = coordinator_.snapshot();
    auto known = !coordinator_.recovery() && directions_.ready() && coordinator_.currentReadback(snapshot.desired);
    std::vector<ii::RuleRecord> records;
    for (auto &rule : snapshot.rules) {
        ii::RuleRecord r;
        r.rule = rule.id;
        r.selector = rule.selector;
        r.revision = rule.revision; r.selectorRevision = rule.selectorRevision;
        r.desired = snapshot.desired;
        r.action = rule.action;
        r.direction = rule.direction; r.mode = rule.mode;
        r.effective = known ? 1 : 0;
        records.push_back(std::move(r));
    }
    return records;
}
Frame NativeRuntime::dispatch(const Frame &f, const VerifiedControl &peer, Pages &pages) {
    tick();
    if (f.minor != 2)
        return error(Error::VersionMismatch);
    if (wire::validate(f) != Error::Ok) return error(Error::Malformed);
    if (f.type == Type::GetStatus)
        return status(Type::Status);
    if (principalMode_) return error(Error::BackendUnavailable);
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
                    ? pages.rules(snapshot, rules(), coordinator_.snapshot().desired, now)
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
        if (ii::pack(std::vector<ii::PendingRecord>{*record}, bytes, 2) != Error::Ok)
            return error(Error::IdentityUnavailable);
        Frame reply;
        reply.minor = 2;
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
        reply.minor = 2;
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
        if (!peer.highAdministrator || !peer.fullServerToken)
            return error(Error::Unauthorized);
        auto command = idValue(f, Tag::CommandId);
        auto snapshot = coordinator_.snapshot();
        auto found = std::find_if(snapshot.entries.begin(), snapshot.entries.end(),
                                  [&](const auto &e) { return e.command.id == command; });
        std::optional<CommandEntry> row;
        if (found != snapshot.entries.end()) {
            const auto &c = found->command;
            if (c.principal != peer.account || c.logon != peer.logon || c.accountSid != peer.accountSid ||
                c.logonSid != peer.logonSid || c.sessionId != peer.sessionId ||
                c.profileGeneration != peer.profileGeneration) return error(Error::Unauthorized);
            row = c;
            auto current = coordinator_.query(command);
            row->effectiveKnown = current.effectiveKnown;
            row->effective = current.effective;
            if (!current.effectiveKnown && (row->state == State::Applied || row->state == State::AppliedUnrecorded)) {
                row->state = State::RecoveryRequired; row->error = Error::RecoveryRequired;
            }
        }
        Frame reply;
        reply.minor = 2;
        reply.type = Type::CommandStatus;
        reply.fields = {
            value(Tag::ServiceEpoch, epoch_), value(Tag::CommandId, command),
            value(Tag::CommandFound, row ? 1 : 0, 1),
            value(Tag::ErrorCode, unsigned(row ? row->error : Error::CommandUnknown), 2)};
        if (row) {
            Frame original;
            if (decode(row->payload, original) != Error::Ok) return error(Error::RecoveryRequired);
            reply.fields.push_back(value(Tag::OriginalCommandType, unsigned(original.type), 2));
            reply.fields.push_back(value(Tag::CommandState, unsigned(row->state), 1));
            reply.fields.push_back(value(Tag::DesiredRev, row->desired));
            reply.fields.push_back(value(Tag::EffectiveRev, row->effective));
            reply.fields.push_back(value(Tag::EffectiveKnown, row->effectiveKnown, 1));
        }
        return reply;
    }
    if (f.type == Type::CreateRule || f.type == Type::RevokeRule) {
        if (!peer.highAdministrator || !peer.fullServerToken) return error(Error::Unauthorized);
        auto snapshot = coordinator_.snapshot();
        auto target = snapshot.rules;
        auto replay = std::any_of(snapshot.entries.begin(), snapshot.entries.end(),
                                   [&](const auto &e) { return e.command.id == f.correlation; });
        if (!replay && (!directions_.ready() || coordinator_.recovery() || engine_.recoveryRequired()))
            return error(Error::BackendUnavailable);
        if (!replay && f.type == Type::CreateRule) {
            auto app = registry_.lookup(idValue(f, Tag::SelectorId));
            if (!app) return error(Error::IdentityUnavailable);
            auto action = static_cast<std::uint8_t>(get(f, Tag::Decision));
            auto direction = static_cast<std::uint8_t>(get(f, Tag::PolicyDirection));
            target.push_back({f.correlation,idValue(f,Tag::SelectorId),1,1,action,direction,
                             static_cast<std::uint8_t>(action==1||direction==2?0:direction==1?1:2),*app});
        } else if (!replay) {
            auto rule = std::find_if(target.begin(),target.end(),[&](const auto &r){return r.id==idValue(f,Tag::RuleId);});
            if (rule == target.end()) return error(Error::Stale);
            target.erase(rule);
        }
        CommandEntry command;
        command.id=f.correlation;command.principal=peer.account;command.logon=peer.logon;
        command.accountSid=peer.accountSid;command.logonSid=peer.logonSid;command.sessionId=peer.sessionId;
        command.profileGeneration=peer.profileGeneration;command.commandEpoch=epoch_;command.boot=boot_;
        if (get(f,Tag::ExpectedDesiredRev)==UINT64_MAX) return error(Error::Capacity);
        command.desired=get(f,Tag::ExpectedDesiredRev)+1;
        Frame canonical=f;canonical.connection.fill(1);canonical.sequence=1;
        std::sort(canonical.fields.begin(),canonical.fields.end(),[](auto&a,auto&b){return a.tag<b.tag;});
        if (encode(canonical,command.payload)!=Error::Ok) return error(Error::Malformed);
        auto result=coordinator_.commit(command,target,snapshot.sequence);
        if (result.durable&&result.effectiveKnown&&result.desired>engine_.desiredRevision())
            engine_.advanceRevision(result.desired,true,now);
        return mutationAck(epoch_, result.state, result.error, result.desired, result.effective,
                           result.effectiveKnown);
    }
    if (f.type == Type::CommitDecision) {
        if (!peer.highAdministrator)
            return error(Error::Unauthorized);
        const bool replay = engine_.command(f.correlation, peer).has_value();
        if (!replay && (collector_.state() != 1 || !directions_.ready() || coordinator_.recovery()))
            return error(Error::BackendUnavailable);
        auto result = engine_.commit(f, peer, now);
        auto pending = engine_.lookup(idValue(f, Tag::RequestId), now);
        auto reply = mutationAck(epoch_, result.state, result.error, result.desired,
                                 result.effective, result.effectiveKnown);
        reply.fields.push_back(value(Tag::RequestId, idValue(f, Tag::RequestId)));
        reply.fields.push_back(value(Tag::RequestVersion, pending ? pending->authority : get(f, Tag::RequestVersion)));
        reply.fields.push_back(value(Tag::RequestState, unsigned(pending ? pending->state : ii::RequestState::Stale), 1));
        return reply;
    }
    return error(Error::Unsupported);
}
Error NativeRuntime::events(std::uint64_t after, std::uint32_t mask, std::vector<Frame> &rows,
                            bool &gap) const {
    return ring_.after(after, mask, rows, gap);
}
bool NativeServer::run(HANDLE stop) {
    try {
        runtime_.principalImageWorker_.reset(new allnative::NativeImageWorker());
        runtime_.principalImageBaseCharge_=sizeof(allnative::NativeImageWorker)+sizeof(allnative::NativeImageWorker::State)+128;
    }
    catch (...) { return false; }
    std::thread view([&] { channel(false, stop); }), control([&] { channel(true, stop); }),
        ordinary([&] { channel(false, stop, true); });
    HANDLE waits[]={stop,runtime_.principalImageWorker_->state_->wake.value};
    bool waited=true;
    for(;;) {
        const auto ready=WaitForMultipleObjects(2,waits,FALSE,250);
        if(ready==WAIT_OBJECT_0)break;
        if(ready!=WAIT_TIMEOUT && ready!=WAIT_OBJECT_0+1) {SetEvent(stop);waited=false;break;}
        std::lock_guard<std::mutex> lock(runtime_.mutex);
        runtime_.tick();
    }
    view.join();
    control.join();
    ordinary.join();
    {
        std::lock_guard<std::mutex> lock(runtime_.mutex);
        runtime_.invalidatePrincipalObservations();
        if(runtime_.principalClassifier_)runtime_.principalClassifier_->reset();
    }
    runtime_.finishPrincipalImages();
    return waited;
}
void NativeServer::channel(bool control, HANDLE stop, bool ordinary) {
    const std::wstring name = ordinary ? ipc::iii::OrdinaryPipe : control ? L"\\\\.\\pipe\\LGA.GateBouncer.Control.v1"
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
            std::shared_ptr<NativeRuntime::PrincipalPeer> ordinaryPeer;
            bool principalReader = false;
            bool authenticated = false;
            if (ipc::ii::receive(pipe.value, hello, stop) &&
                (ordinary ? hello.minor == 3 : (hello.minor == 2 || hello.minor == 1 ||
                    (!control && (hello.minor == 0 || hello.minor == 3)))) && hello.type == Type::Hello &&
                zero(hello.connection) && hello.sequence == 1 &&
                get(hello, Tag::ClientRole) == (control ? 2 : 1)) {
                std::lock_guard<std::mutex> lock(runtime_.mutex);
                runtime_.tick();
                principalReader = !ordinary && !control && hello.minor == 3;
                authenticated = runtime_.profileGeneration() == profile &&
                                (ordinary || principalReader ? runtime_.ordinaryPeer(pipe.value, ordinaryPeer, principalReader)
                                    : runtime_.peer(pipe.value, control, peer, true));
            }
            if (!authenticated) {
                DisconnectNamedPipe(pipe.value);
                continue;
            }
            auto connection = native::randomIdentity();
            Frame ack;
            {
                std::lock_guard<std::mutex> lock(runtime_.mutex);
                if (ordinary || principalReader) {
                    ordinaryPeer->connection = connection;
                    ack = runtime_.ordinaryStatus(Type::HelloAck, ordinaryPeer);
                } else ack = runtime_.status(Type::HelloAck, hello.minor == 3 ? 3 : 2);
            }
            ack.connection = connection;
            ack.correlation = hello.correlation;
            if (!hello.minor)
                ack = readOnlyA(std::move(ack));
            else if (hello.minor == 1) ack = readOnlyII(std::move(ack));
            if (!ipc::ii::send(pipe.value, ack, stop)) {
                if (ordinary || principalReader) {
                    std::lock_guard<std::mutex> lock(runtime_.mutex);
                    runtime_.closeOrdinaryPeer(ordinaryPeer);
                }
                DisconnectNamedPipe(pipe.value);
                continue;
            }
            Pages pages(runtime_.epoch(), profile, hello.minor);
            std::uint64_t rx = 2, tx = 2, lastActivity = GetTickCount64(), after = 0;
            std::uint32_t mask = 0;
            wire::iv::ServiceContext subscriptionContext{};
            while (WaitForSingleObject(stop, 0) == WAIT_TIMEOUT &&
                   GetTickCount64() - lastActivity < 60000) {
                if (mask) {
                    std::vector<Frame> events;
                    bool gap = false;
                    bool usable = true;
                    bool terminal = false;
                    {
                        std::lock_guard<std::mutex> lock(runtime_.mutex);
                        if (ordinary || principalReader) {
                            runtime_.tick();
                            usable = runtime_.profileGeneration() == profile && ordinaryPeer &&
                                runtime_.ordinaryPeer(pipe.value,ordinaryPeer,principalReader) &&
                                (!runtime_.principalEventsReady() || mask==(runtime_.principalTrafficReady() ? 7u : 3u)) &&
                                NativeActivityRing::same(runtime_.principalEvents_.context(),subscriptionContext);
                            if (usable) {
                                // También cuando no llegaron causas: Ready cacheado no acredita catálogo actual.
                                const auto source=runtime_.principalSource_;
                                const auto catalog=runtime_.principalCatalog_;
                                const auto current=runtime_.readServiceContext();
                                terminal=source!=runtime_.principalSource_ || catalog!=runtime_.principalCatalog_ ||
                                    !NativeActivityRing::same(current,subscriptionContext) ||
                                    !runtime_.principalEventsReady();
                                if (terminal) runtime_.principalEvents_.lose();
                                usable=runtime_.principalPeerCurrent(*ordinaryPeer) &&
                                    runtime_.principalEvents_.after(after,events)==Error::Ok;
                            }
                        } else {
                            usable = runtime_.profileGeneration() == profile &&
                                     runtime_.peer(pipe.value, control, peer, false);
                        }
                        if (usable && !(ordinary || principalReader)) {
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
                        if (ordinary || principalReader) {
                            std::lock_guard<std::mutex> lock(runtime_.mutex);
                            // Revalidación individual; el wait/cancel/drain posterior no retiene mutex.
                            if (!ordinaryPeer ||
                                (runtime_.principalEventsReady() && mask!=(runtime_.principalTrafficReady() ? 7u : 3u)) ||
                                !NativeActivityRing::same(runtime_.principalEvents_.context(),subscriptionContext) ||
                                !runtime_.principalEventCurrent(*ordinaryPeer,event)) {
                                sent=false; break;
                            }
                        }
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
                    if (!sent || terminal)
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
                        !(ordinary || principalReader ? runtime_.ordinaryPeer(pipe.value, ordinaryPeer, principalReader)
                                   : runtime_.peer(pipe.value, control, peer, false)))
                        break;
                    if (ordinary || principalReader) response = runtime_.dispatchOrdinary(f, ordinaryPeer);
                    else if (!hello.minor) {
                        response = runtime_.status(Type::Status);
                        if (f.type != Type::GetStatus) {
                            response = {};
                            response.type = Type::ProtocolError;
                            response.fields = {
                                value(Tag::ErrorCode, unsigned(Error::Unsupported), 2)};
                        }
                        response = readOnlyA(std::move(response));
                    } else if (hello.minor == 1) {
                        response = f.type == Type::GetStatus ? runtime_.status(Type::Status)
                                                             : runtime_.dispatch(f, peer, pages);
                        response = readOnlyII(std::move(response));
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
                    if ((ordinary || principalReader) &&
                        wire::iv::decodeServiceContext(response,subscriptionContext)!=Error::Ok) break;
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
                if (ordinary || principalReader) runtime_.closeOrdinaryPeer(ordinaryPeer);
                if (runtime_.profileGeneration() != profile)
                    break;
            }
        }
    }
}
} // namespace gb::decisions
