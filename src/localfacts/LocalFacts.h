#pragma once
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <memory>
#include <string>

namespace gb::controller { class Deployment; }
namespace gatebouncer::localfacts {
enum class State { Complete, Rejected, Unavailable, Stale, TooLarge, TimedOut, Cancelled };
enum class SignatureState { VerifiedOffline, Unsigned, Invalid, Unavailable, TimedOut, Cancelled };
struct Binding {
    std::wstring absolutePath;
    std::uint64_t volume = 0;
    std::array<unsigned char, 16> fileId{};
    std::uint64_t size = 0;
    std::uint64_t modified = 0;
    std::uint64_t generation = 0;
};
bool sameBinding(const Binding&, const Binding&) noexcept;
struct Request {
    std::wstring absolutePath;
    std::uint64_t generation = 0;
    std::optional<Binding> expected;
};
struct Limits {
    std::uint64_t maxBytes = 256ULL * 1024 * 1024;
    std::chrono::milliseconds hashBudget{5000};
    std::chrono::milliseconds signatureBudget{3000};
};
struct Cancellation { std::atomic_bool requested{false}; };
struct Signature {
    SignatureState state = SignatureState::Unavailable;
    std::wstring publisherLocal;
    std::int32_t nativeStatus = 0;
};
struct Snapshot {
    State state = State::Unavailable;
    Binding binding;
    std::string sha256;
    Signature signature;
    std::uint32_t nativeError = 0;
};
// El backend recibe un handle prestado, nunca una ruta para ejecutar.
struct SignatureInput { std::uintptr_t fileHandle = 0; Binding binding; };
class SignatureBackend {
public:
    virtual ~SignatureBackend() = default;
    virtual Signature verify(const SignatureInput&, std::chrono::milliseconds,
                             const Cancellation&) = 0;
};
// Sólo archivo escogido por el caller. No enumera procesos ni transmite información.
// Ejecutar fuera del hilo de UI: hash y apertura tienen plazo cooperativo, no duro.
Snapshot inspect(const Request&, const Limits&, const Cancellation&, SignatureBackend&);
// Retiene el despliegue original; no acepta autoridad por ruta/hash del caller.
class WindowsSignatureBackend final : public SignatureBackend {
public:
    explicit WindowsSignatureBackend(std::shared_ptr<gb::controller::Deployment> deployment);
    Signature verify(const SignatureInput&, std::chrono::milliseconds,
                     const Cancellation&) override;
private:
    std::shared_ptr<gb::controller::Deployment> deployment_;
};
} // namespace gatebouncer::localfacts
