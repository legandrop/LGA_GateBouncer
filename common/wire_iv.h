#pragma once
#include "wire_ii.h"

namespace gb::wire::iv {
constexpr std::size_t MaxRecordsBytes = 57344;
constexpr std::uint64_t NativeEvents = 1ull << 25;
constexpr std::uint64_t NativeTraffic = 1ull << 26;
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
};
bool supported(Type type);
bool valid(const ObservedRecord &record);
bool valid(const FutureDraftRecord &record);
bool valid(const PrincipalRuleRecord &record);
Error pack(const std::vector<ObservedRecord> &records, Bytes &out);
Error pack(const std::vector<FutureDraftRecord> &records, Bytes &out);
Error pack(const std::vector<PrincipalRuleRecord> &records, Bytes &out);
Error unpack(const Bytes &bytes, std::size_t count,
             std::vector<ObservedRecord> &out);
Error unpack(const Bytes &bytes, std::size_t count,
             std::vector<FutureDraftRecord> &out);
Error unpack(const Bytes &bytes, std::size_t count,
             std::vector<PrincipalRuleRecord> &out);
Error validate(const Frame &frame);
// Sólo canoniza un comando de formato; no adquiere actor, target ni
// consentimiento.
Error canonical(const Frame &frame, Bytes &out);
} // namespace gb::wire::iv
