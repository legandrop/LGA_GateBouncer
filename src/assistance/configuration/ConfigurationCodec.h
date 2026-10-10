#pragma once
#include "ConfigurationController.h"

namespace Gate::Assistance::Configuration::Detail {
struct SearchPreference {
    std::uint8_t provider=0;
    Digest256 binding{};
    std::uint64_t policy=0;
};
struct PersistentRecord {
    ConfigurationSnapshot metadata;
    std::uint64_t committedRevision=0;
    std::uint32_t profileRevision=1;
    std::optional<SearchPreference> search;
    Broker::SensitiveBytes secret;
    Digest256 integrity{};
};
std::optional<Broker::SensitiveBytes> encodeRecord(const PersistentRecord &);
std::optional<PersistentRecord> decodeRecord(const Broker::SensitiveBytes &);
std::optional<Broker::SensitiveBytes> protectRecord(const Broker::SensitiveBytes &);
std::optional<Broker::SensitiveBytes> unprotectRecord(const Broker::SensitiveBytes &);
}
