#pragma once
#include "../common/token_ii_win.h"
#include "../common/wire_iv.h"
#include <memory>
namespace gb::controller { class Deployment; }
namespace gb::decisions {
class NativeRuntime;
class CatalogPlanBuilder;
// Custodia de bytes fuente; sus hechos no conceden admisión ni efecto OS.
class PrincipalSourceCapture final {
public:
    struct Selection {
        ~Selection() = default;
        std::uint8_t action = 0, direction = 0;
        wire::iv::RemoteCondition condition;
        wire::Bytes candidate;
        wire::Digest rawDigest{}, closureDigest{};
    private:
        friend class PrincipalSourceCapture;
        Selection() = default;
        Selection(const Selection &) = delete;
        Selection &operator=(const Selection &) = delete;
        std::shared_ptr<const PrincipalSourceCapture> owner;
        wire::Bytes appId, accountSid;
        std::filesystem::path image;
    };
    ~PrincipalSourceCapture();
    PrincipalSourceCapture(const PrincipalSourceCapture &) = delete;
    PrincipalSourceCapture &operator=(const PrincipalSourceCapture &) = delete;
private:
    friend class NativeRuntime;
    friend class CatalogPlanBuilder;
    struct Data;
    PrincipalSourceCapture();
    // Adquirir, comparar/current y destruir fuera del mutex de Runtime.
    // Un único slot físico persiste hasta destruir el último alias del grafo.
    static std::shared_ptr<PrincipalSourceCapture> acquire(const std::filesystem::path &,
        const wire::Digest &,
        const native::ProcessEvidence &, const native::TokenEvidence &, HANDLE primary, HANDLE stop,
        const std::shared_ptr<controller::Deployment> &, std::uint64_t deadline, wire::Error &reason) noexcept;
    std::shared_ptr<const Selection> compareAgainst(const wire::Bytes &candidateUtf8,
        const wire::Bytes &appId, const wire::Bytes &accountSid, const std::filesystem::path &image) const noexcept;
    bool ownsSelection(const std::shared_ptr<const Selection> &, const wire::Bytes &appId,
        const wire::Bytes &accountSid, const std::filesystem::path &image) const noexcept;
    bool current() const noexcept;
    // Guarda breve para el writer: sin parser ni lectura del archivo fuente.
    bool actorCurrent() const noexcept;
    std::unique_ptr<Data> data_;
    std::weak_ptr<PrincipalSourceCapture> self_;
    bool physical_ = false;
};
}
