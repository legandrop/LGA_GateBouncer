#pragma once
#include "client_ii_win.h"
#include "wire_iv.h"
#include "../controller/deployment_win.h"

namespace gb::ipc::iii {
inline constexpr wchar_t OrdinaryPipe[] = L"\\\\.\\pipe\\LGA.GateBouncer.Ordinary.v1";
// Canal ordinary separado del lector View: autenticar no concede autoridad de
// procesos locales, protección ni efecto actual. El servidor adquiere el actor.
class OrdinaryClient final : public ii::SessionChannel {
public:
    enum class IntentRole : std::uint8_t { OwnAccount = 1, Administrative = 2 };
    explicit OrdinaryClient(IntentRole role = IntentRole::OwnAccount) : role_(role) {}
    ~OrdinaryClient() override { close(); }
    bool open(bool control, const std::filesystem::path &serviceImage) override {
        close();
        if (control || (role_ != IntentRole::OwnAccount && role_ != IntentRole::Administrative) ||
            !native::fixedPath(serviceImage)) return false;
        image_ = serviceImage;
        deployment_ = std::make_unique<controller::Deployment>(image_.parent_path());
        if (!deployment_->verify(image_,controller::DeploymentRole::Service) || !deployment_->current()) {
            close(); return false;
        }
        pipe_.reset(CreateFileW(OrdinaryPipe, ii::ClientAccess, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION, nullptr));
        if (!pipe_ || !authenticated()) { close(); return false; }
        wire::Frame request; request.minor = 3; request.type = wire::Type::Hello;
        request.correlation = native::randomIdentity();
        request.fields = {wire::value(wire::Tag::ClientRole, unsigned(role_), 1)};
        wire::Frame response;
        if (!ii::send(pipe_.value, request, nullptr) || !ii::receive(pipe_.value, response, nullptr) ||
            response.minor != 3 || response.type != wire::Type::HelloAck || response.sequence != 1 ||
            response.correlation != request.correlation || wire::zero(response.connection) ||
            !statusContext(response) || !authenticated() ||
            (role_ == IntentRole::Administrative &&
             !(wire::get(response, wire::Tag::Capabilities) & wire::iv::AdministrativePrincipalControl))) { close(); return false; }
        connection_ = response.connection; hello_ = std::move(response); tx_ = rx_ = 2;
        return true;
    }
    bool transact(wire::Frame request, wire::Frame &response) override {
        response = {};
        if (!authenticated() || wire::zero(connection_) || tx_ == UINT64_MAX || rx_ == UINT64_MAX) {
            close(); return false;
        }
        request.minor = 3; request.connection = connection_; request.sequence = tx_++;
        if (wire::zero(request.correlation)) request.correlation = native::randomIdentity();
        wire::Frame received;
        if (!ii::send(pipe_.value, request, nullptr) || !ii::receive(pipe_.value, received, nullptr) ||
            received.minor != 3 || received.connection != connection_ || received.sequence != rx_++ ||
            received.correlation != request.correlation ||
            (received.type != wire::Type::ProtocolError &&
             wire::idValue(received, wire::Tag::ServiceEpoch) != wire::idValue(hello_, wire::Tag::ServiceEpoch)) ||
            (received.type == wire::Type::Status && !statusContext(received)) || !authenticated()) {
            close(); return false;
        }
        response = std::move(received);
        return true;
    }
    bool events(std::vector<wire::Frame> &batch) override {
        batch.clear(); return authenticated(); // Sin suscripción inventada por este canal.
    }
    void close() override {
        pipe_.reset(); server_ = {}; connection_ = {}; hello_ = {}; tx_ = rx_ = 1; deployment_.reset();
    }
    const wire::Frame &hello() const override { return hello_; }
    bool actualOsAuthenticated() const override {
        return bool(pipe_) && !wire::zero(connection_);
    }
private:
    const IntentRole role_;
    bool authenticated() {
        native::ProcessEvidence acquired;
        if (!pipe_ || !deployment_ || !deployment_->current() || !ii::readableServerEvidence(pipe_.value, image_, acquired)) return false;
        if (server_.pid && (server_.pid != acquired.pid ||
            CompareFileTime(&server_.created, &acquired.created) != 0 || server_.image != acquired.image)) return false;
        server_ = std::move(acquired); return true;
    }
    bool statusContext(const wire::Frame &frame) const {
        if (wire::iv::validate(frame) != wire::Error::Ok ||
            (frame.type != wire::Type::HelloAck && frame.type != wire::Type::Status)) return false;
        // El decoder readonly exige IVProfile0. Aquí se conserva el formato IV
        // existente, incluyendo IVProfile1, sin cambiar el contrato de View.
        return wire::get(frame, wire::Tag::EffectiveKnown) == 0 &&
            wire::get(frame, wire::Tag::EffectiveRev) == 0 &&
            (hello_.type != wire::Type::HelloAck ||
             (wire::idValue(frame, wire::Tag::ServiceEpoch) == wire::idValue(hello_, wire::Tag::ServiceEpoch) &&
              wire::idValue(frame, wire::Tag::BootId) == wire::idValue(hello_, wire::Tag::BootId)));
    }
    native::Handle pipe_;
    std::unique_ptr<controller::Deployment> deployment_;
    native::ProcessEvidence server_;
    std::filesystem::path image_;
    wire::Frame hello_;
    wire::Id connection_{};
    std::uint64_t tx_ = 1, rx_ = 1;
};
} // namespace gb::ipc::iii
