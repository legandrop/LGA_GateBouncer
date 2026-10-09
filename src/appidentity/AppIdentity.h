#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace gatebouncer::appidentity {

using Bytes = std::vector<std::uint8_t>;
inline constexpr std::size_t MaximumAppIdBytes = 65536;
inline constexpr std::size_t MaximumSidBytes = 68;
inline constexpr std::size_t MaximumAppDisplayUnits = 1024;
inline constexpr std::size_t MaximumPrincipalDisplayUnits = 256;
inline constexpr std::size_t MaximumScopeDisplayUnits = 320;

enum class FieldState : std::uint8_t { Missing = 0, Copied = 1, Unreadable = 2 };
struct CopiedField {
    FieldState state = FieldState::Missing;
    Bytes bytes;
};
struct EventBinding {
    std::uint64_t engineEpoch = 0;
    std::uint64_t eventSequence = 0;
};
inline bool operator==(const EventBinding& a, const EventBinding& b) noexcept
{
    return a.engineEpoch == b.engineEpoch && a.eventSequence == b.eventSequence;
}
struct CopiedIdentity {
    EventBinding binding;
    CopiedField appId;
    CopiedField userSid;
    CopiedField packageSid;
};

enum class State : std::uint8_t { Attributed = 0, Unknown = 1, Unavailable = 2 };
enum class Reason : std::uint8_t {
    None = 0, MissingAppId, MissingUserSid, UnreadableField, InconsistentField,
    Oversized, InvalidAppId, InvalidSid, InvalidBinding, NativeFailure
};
enum class PackageScope : std::uint8_t { PackageUnspecified = 0, ExactObservedPackage = 1 };
struct Scope {
    PackageScope package = PackageScope::PackageUnspecified;
    bool allInstances = true;
    bool allSessions = true;
};
struct Target {
    Bytes appId;
    Bytes userSid;
    std::optional<Bytes> packageSid;
    // Clave privada en memoria, nunca un formato de journal o IPC.
    Bytes opaqueKey;
};
struct Display {
    std::u16string appText;
    std::u16string principalText;
    std::u16string packageText;
    std::u16string scopeText;
};
struct Result {
    State state = State::Unknown;
    Reason reason = Reason::None;
    EventBinding binding;
    std::optional<Target> target;
    std::optional<Scope> scope;
    Display display;
};

class SidFormatter {
public:
    virtual ~SidFormatter() = default;
    // Recibe bytes propietarios ya acotados; no resuelve cuentas ni acredita origen.
    virtual bool format(const Bytes& sid, std::u16string& text) = 0;
};

// Attributed sólo describe datos. El consumidor acredita filtro, canal, pending y scope.
// Perfil UTF-16LE experimental: formatos no admitidos devuelven Unknown/InvalidAppId.
Result attribute(const CopiedIdentity& input, SidFormatter& formatter) noexcept;

// Adapter local Win32; compilar de nuevo con el toolchain del consumidor.
std::unique_ptr<SidFormatter> makeWindowsSidFormatter();

} // namespace gatebouncer::appidentity
