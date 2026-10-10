#pragma once
#include "wire_ii.h"

namespace gb::wire::iv {
constexpr std::size_t MaxRecordsBytes = 57344;
constexpr std::uint64_t NativeEvents = 1ull << 25;
constexpr std::uint64_t NativeTraffic = 1ull << 26;
constexpr std::uint64_t NativeProcessFacts = 1ull << 27;
constexpr std::uint64_t FileFutureControl = 1ull << 28;
constexpr std::uint64_t AdministrativePrincipalControl = 1ull << 29;
// Representación de condición original; no capability, admisión ni autoridad.
enum class RemoteKind : std::uint8_t { None = 0, Ipv4Range = 1 };
struct RemoteCondition {
  RemoteKind kind = RemoteKind::None;
  std::uint8_t match = 1;
  // IPv4 numérico a<<24|b<<16|c<<8|d; ordinal de regla en el catálogo fuente,
  // conservado para diagnóstico. No acredita ni decide el orden de un empate.
  std::uint32_t first = 0, last = 0, sourceWeight = 0, sourceOrdinal = 0;
  Id sourceRule{}, sourceFilter{};
};
inline bool remoteConditionValid(const RemoteCondition &c) noexcept {
  if (c.match != 1) return false;
  if (c.kind == RemoteKind::None)
    return !c.first && !c.last && !c.sourceWeight && !c.sourceOrdinal &&
           c.sourceRule == Id{} && c.sourceFilter == Id{};
  return c.kind == RemoteKind::Ipv4Range && c.first <= c.last &&
         c.sourceWeight <= 2147483647u && c.sourceRule != Id{} && c.sourceFilter != Id{};
}
// Tupla informativa del ALE original; no prueba autorización ni entrega en red.
struct DestinationContext {
  bool present=false;
  std::uint8_t family=0, protocol=0, direction=0;
  std::uint16_t localPort=0, remotePort=0;
  std::uint32_t compartment=0;
  std::array<std::uint8_t,16> localAddress{}, remoteAddress{};
};
bool valid(const DestinationContext &);
Error packDestinationContext(const DestinationContext &, Bytes &);
Error unpackDestinationContext(const Bytes &, DestinationContext &);
// Selección de formato. La captura de archivo/grafo original pertenece al servicio.
struct OriginalSourceSelection {
  Digest rawDigest{};
  Bytes candidate;
};
bool valid(const OriginalSourceSelection &);
Error packOriginalSourceSelection(const OriginalSourceSelection &, Bytes &);
Error unpackOriginalSourceSelection(const Bytes &, OriginalSourceSelection &);
// Archivo original custodiado por fuente; no es un HANDLE de imagen del caller.
struct ProcessFacts {
  std::uint64_t pid=0, created=0, lastWrite=0;
  std::uint32_t volumeSerial=0, fileIndexHigh=0, fileIndexLow=0,
                fileSizeHigh=0, fileSizeLow=0, tokenSession=0;
  Bytes appId, image, accountSid, logonSid;
};
// Enlace histórico a secuencia; no es un identificador de autorización.
Id attemptLink(std::uint64_t sequence);
std::uint64_t attemptSequence(const Id &link);
// Identidad readonly; no prueba continuidad, efecto ni derechos.
struct ServiceContext {
  Id serviceEpoch{}, boot{}, engineContext{};
  std::uint64_t engineBindingGeneration = 0;
};
Error encodeServiceContext(const ServiceContext &, Bytes &);
Error decodeServiceContext(const Frame &, ServiceContext &);
enum class Proof : std::uint8_t {
  Unknown = 0,
  CurrentShapeUnproven = 1,
  CurrentEffect = 2
};
struct Display {
  Bytes name, principal, package, path;
  std::uint8_t projection = 1;
};
struct ObservedRecord {
  Id observed{}, source{}, binding{};
  std::uint64_t revision = 0, firstUtc = 0, lastUtc = 0;
  std::uint32_t presence = 0;
  std::uint8_t state = 1, temporal = 1, package = 0;
  Error reason = Error::Ok;
  Display display;
};
struct FutureDraftRecord {
  Id draft{}, observed{}, source{}, binding{}, selector{}, challenge{};
  std::uint64_t version = 0, observedRevision = 0, targetRevision = 0,
                expectedDesired = 0, profile = 0;
  Digest target{}, migration{};
  std::uint32_t ttl = 0, durationMs = 0;
  std::uint8_t state = 1, package = 0, direction = 1, scope = 2;
  std::uint16_t accepted = 0;
  Proof proof = Proof::Unknown;
  Error reason = Error::Ok;
  Display display;
};
struct PrincipalRuleRecord {
  Id rule{}, selector{};
  std::uint64_t revision = 0, targetRevision = 0, desired = 0, created = 0,
                authorized = 0, generation = 0;
  Digest target{};
  std::uint32_t presence = 0;
  std::uint8_t action = 1, direction = 1, mode = 0, scope = 2, package = 1,
               origin = 1;
  std::uint8_t admin = 1, effective = 0, targetKind = 1;
  Proof proof = Proof::Unknown;
  Display display;
  Bytes originalTarget;
};
// Archivo seleccionado y custodiado; ninguna identidad de proceso se inventa.
struct FileIdentity {
  std::uint32_t volumeSerial=0, fileIndexHigh=0, fileIndexLow=0,
                fileSizeHigh=0, fileSizeLow=0, attributes=0;
  std::uint64_t lastWrite=0;
};
struct FileFutureDraftRecord {
  FutureDraftRecord draft;
  Bytes originalTarget;
  FileIdentity file;
};
bool validPrincipalTarget(const Bytes &target, std::uint8_t package=0);
bool validFileTarget(const Bytes &target);
bool validConditionalTarget(const Bytes &target, std::uint8_t package=0);
bool validConditionalFileTarget(const Bytes &target);
struct OriginalTarget {
  Bytes appId, accountSid, packageSid;
  std::uint8_t packageMode=0;
};
Error unpackOriginalTarget(const Bytes &, OriginalTarget &);
// Entrada del SHA256 original: dominio8 + longitud LE4 + target completo.
Error principalTargetDigestInput(const Bytes &, Bytes &);
bool supported(Type type);
bool valid(const ObservedRecord &record);
bool valid(const FutureDraftRecord &record);
bool valid(const PrincipalRuleRecord &record);
bool valid(const FileFutureDraftRecord &record);
bool valid(const ProcessFacts &record);
Error pack(const std::vector<ObservedRecord> &records, Bytes &out);
Error pack(const std::vector<FutureDraftRecord> &records, Bytes &out);
Error pack(const std::vector<PrincipalRuleRecord> &records, Bytes &out);
Error pack(const std::vector<FileFutureDraftRecord> &records, Bytes &out);
Error pack(const std::vector<ProcessFacts> &records, Bytes &out);
Error unpack(const Bytes &bytes, std::size_t count,
             std::vector<ObservedRecord> &out);
Error unpack(const Bytes &bytes, std::size_t count,
             std::vector<FutureDraftRecord> &out);
Error unpack(const Bytes &bytes, std::size_t count,
             std::vector<PrincipalRuleRecord> &out);
Error unpack(const Bytes &bytes, std::size_t count,
             std::vector<FileFutureDraftRecord> &out);
Error unpack(const Bytes &bytes, std::size_t count,
             std::vector<ProcessFacts> &out);
Error validate(const Frame &frame);
// Sólo canoniza un comando de formato; no adquiere actor, target ni
// consentimiento.
Error canonical(const Frame &frame, Bytes &out);
} // namespace gb::wire::iv
