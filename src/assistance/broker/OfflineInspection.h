#pragma once
#include "../../localfacts/LocalFacts.h"
#include <QStringList>
#include <optional>

namespace Gate::Assistance::Broker {
struct OfflineInspectionOptions {
    gatebouncer::localfacts::Request request;
    gatebouncer::localfacts::Limits limits;
    std::optional<std::chrono::milliseconds> cancelAfter;
};
std::optional<OfflineInspectionOptions> offlineInspectionArguments(const QStringList &);
// Entrada informativa; no compone configuración, servicio ni permisos de red.
int runOfflineInspection(const QStringList &);
}
