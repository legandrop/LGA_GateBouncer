#include "ExplanationCoordinator.h"
#include <chrono>
namespace Gate::Assistance {
ExplanationCoordinator::ExplanationCoordinator(IExplanationTransport &transport, QObject *parent, Clock clock)
    : QObject(parent), transport_(transport), clock_(std::move(clock)) {
    if (!clock_) clock_ = [] { return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count(); };
    deadline_.setSingleShot(true);
    connect(&deadline_, &QTimer::timeout, this, [this] {
        if (status_ == Status::Loading) { markUncertain(); invalidate(Status::Uncertain); error_ = Error::Timeout; emit changed(); }
    });
}
ExplanationCoordinator::~ExplanationCoordinator() { if (operation_) operation_->cancel(); }
bool ExplanationCoordinator::eligible() const {
    return visible_ && configured_ && consent_ && binding_.context.pending &&
           binding_.context.serviceAvailable && !binding_.context.requestId.isEmpty() &&
           !binding_.context.applicationIdentity.isEmpty();
}
void ExplanationCoordinator::invalidate(Status status) {
    if (status_ == Status::Loading) markUncertain();
    ++binding_.generation;
    deadline_.stop();
    if (operation_) operation_->cancel();
    operation_.reset(); text_.reset(); status_ = status; error_ = Error::None;
}
void ExplanationCoordinator::configureDemo(bool configured, bool consent) {
    const bool wasReady = configured_ && consent_;
    if (configured != configured_ || consent != consent_) {
        if (configured != configured_) ++binding_.credentialEpoch;
        if (consent != consent_) ++binding_.consentEpoch;
        configured_ = configured; consent_ = consent;
        invalidate(); cache_.clear();
        if (!wasReady && configured_ && consent_ && !automaticChosen_) automatic_ = true;
        emit changed(); maybeAutomatic();
    }
}
void ExplanationCoordinator::setAutomatic(bool automatic) {
    automaticChosen_ = true;
    if (automatic_ == automatic) return;
    automatic_ = automatic; emit changed(); maybeAutomatic();
}
void ExplanationCoordinator::open(const RequestContext &context, CatalogEntry entry) {
    invalidate(); binding_.context = context; entry_ = entry; visible_ = true;
    emit changed(); maybeAutomatic();
}
void ExplanationCoordinator::updateContext(const RequestContext &context) {
    if (context == binding_.context) return;
    invalidate(); binding_.context = context; cache_.clear(); emit changed(); maybeAutomatic();
}
void ExplanationCoordinator::close() { if (status_ == Status::Loading) markUncertain(); visible_ = false; invalidate(); emit changed(); }
void ExplanationCoordinator::cancel() { if (status_ == Status::Loading) markUncertain(); invalidate(Status::Cancelled); error_ = Error::Cancelled; emit changed(); }
void ExplanationCoordinator::markUncertain() {
    if (!uncertainRequest()) uncertain_.push_back(binding_.context);
}
bool ExplanationCoordinator::uncertainRequest() const {
    for (const auto &request : uncertain_) {
        const auto &current = binding_.context;
        if (request.requestId == current.requestId && request.applicationIdentity == current.applicationIdentity &&
            request.snapshotRevision == current.snapshotRevision && request.sessionEpoch == current.sessionEpoch) return true;
    }
    return false;
}
bool ExplanationCoordinator::attemptedRequest() const {
    for (const auto &request : attempted_) {
        const auto &current = binding_.context;
        if (request.requestId == current.requestId && request.applicationIdentity == current.applicationIdentity &&
            request.snapshotRevision == current.snapshotRevision && request.sessionEpoch == current.sessionEpoch) return true;
    }
    return false;
}
void ExplanationCoordinator::maybeAutomatic() {
    if (!automatic_ || !eligible()) return;
    const auto generation = binding_.generation;
    QTimer::singleShot(0, this, [this, generation] {
        if (generation == binding_.generation && automatic_ && eligible()) start();
    });
}
bool ExplanationCoordinator::start() {
    if (!eligible() || status_ == Status::Loading || status_ == Status::Uncertain) return false;
    if (uncertainRequest()) { status_ = Status::Uncertain; error_ = Error::Unavailable; emit changed(); return false; }
    const qint64 now = clock_();
    for (const auto &entry : cache_) {
        auto comparable = entry.binding; comparable.generation = binding_.generation;
        if (entry.entry == entry_ && comparable == binding_ && now >= entry.saved && now - entry.saved <= 600000) {
            text_ = entry.text;
            status_ = text_->certainty == ExplanationText::Certainty::Possible ? Status::Known : Status::Unclear;
            error_ = Error::None; emit changed(); return true;
        }
    }
    if (attemptedRequest() || attempts_ >= 60 || now < blockedUntil_ || now < lastAttempt_ || now - lastAttempt_ < 10000) {
        status_ = Status::Limited; error_ = Error::RateLimited; emit changed(); return false;
    }
    const auto payload = buildSamplePayload(PublicAppFacts::sample(entry_));
    if (!payload) { fail(Error::InvalidResponse, Status::Error); return false; }
    invalidate(Status::Loading); started_ = now; lastAttempt_ = now; ++attempts_;
    const auto submitted = binding_;
    // La API no confirma envio: consumir antes de start, aun si retorna null o falla.
    // Maximo 60 registros; cerrar, settings y vencer cache no habilitan otro intento.
    attempted_.push_back(submitted.context);
    deadline_.start(20000);
    QPointer<ExplanationCoordinator> self(this);
    auto operation = transport_.start(submitted, *payload, [self](TransportReply reply) {
        if (self) self->finish(std::move(reply));
    });
    // Un doble puede responder en forma sincrona o emitir changed que invalide el pedido.
    if (status_ == Status::Loading && submitted == binding_) {
        operation_ = std::move(operation);
        if (!operation_) fail(Error::Unavailable, Status::Error);
    } else if (operation) operation->cancel();
    emit changed(); return true;
}
void ExplanationCoordinator::fail(Error error, Status status) {
    deadline_.stop(); if (operation_) operation_->cancel(); operation_.reset();
    text_.reset(); error_ = error; status_ = status;
    if (++failures_ >= 3) { blockedUntil_ = clock_() + 60000; failures_ = 0; }
    emit changed();
}
void ExplanationCoordinator::finish(TransportReply reply) {
    if (status_ != Status::Loading || !(reply.binding == binding_) || !eligible()) return;
    const auto now = clock_();
    if (now < started_ || now - started_ >= 20000) { markUncertain(); fail(Error::Timeout, Status::Uncertain); return; }
    if (reply.statusCode == 202 || reply.error == Error::Timeout) {
        markUncertain();
        fail(reply.error == Error::Timeout ? Error::Timeout : Error::Unavailable, Status::Uncertain); return;
    }
    if (reply.error != Error::None || reply.statusCode != 200) {
        if (reply.statusCode == 0 && reply.error != Error::None) {
            markUncertain(); fail(reply.error, Status::Uncertain); return;
        }
        fail(reply.statusCode == 429 ? Error::RateLimited :
             reply.error == Error::None ? Error::Unavailable : reply.error, Status::Error); return;
    }
    const auto result = parseExplanationEnvelope(reply.body);
    if (!result) { fail(Error::InvalidResponse, Status::Error); return; }
    deadline_.stop(); operation_.reset(); failures_ = 0; error_ = Error::None; text_ = result;
    status_ = result->certainty == ExplanationText::Certainty::Possible ? Status::Known : Status::Unclear;
    cache_.push_back({binding_, entry_, *result, now});
    if (cache_.size() > 32) cache_.pop_front();
    emit changed();
}
} // namespace Gate::Assistance
