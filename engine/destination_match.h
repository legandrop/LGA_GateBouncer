#pragma once
#include "dns_names.h"
#include <cstddef>
#include <string>

namespace gbe {

// Cuánto se parece un destino de regla a una conexión: 0 no coincide; más alto, más específico (IP, host exacto,
// dominio más largo). Un patrón por nombre no coincide sin host: por eso un bloqueo que llega antes que su consulta
// DNS espera el nombre (name_wait.h) antes de preguntar.
inline std::size_t destinationMatch(const std::wstring &pattern, const std::wstring &host, const std::wstring &address) {
    if (pattern.empty()) return 0;
    if (DnsNames::normalize(pattern) == pattern) return pattern == address ? 10000 : 0;
    if (host.empty()) return 0;
    if (pattern.rfind(L"*.", 0) == 0) {
        const std::wstring suffix = pattern.substr(2);
        const bool under = host.size() > suffix.size() &&
                           host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0 &&
                           host[host.size() - suffix.size() - 1] == L'.';
        return host == suffix || under ? 100 + suffix.size() : 0;
    }
    return host == pattern ? 1000 + pattern.size() : 0;
}

} // namespace gbe
