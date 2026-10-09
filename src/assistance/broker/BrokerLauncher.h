#pragma once
#include "BrokerPipe.h"
#include "websearch/WebSearch.h"
#include <memory>
#include <optional>

namespace Gate::Assistance::Broker {
class PrivateLaunchEnvironmentTest;
class BrokerEnvironment final {
public:
    static std::optional<BrokerEnvironment> forSibling();
private:
    friend class PrivateLaunchEnvironmentTest;
    friend std::unique_ptr<PipeSession> launchSiblingBroker();
    friend std::unique_ptr<PipeSession> launchSiblingBroker(WireVersion);
    static std::optional<BrokerEnvironment> fromTrustedPaths(QString,QString,QString);
    std::vector<wchar_t> block_;
    std::wstring directory_;
};
// Ruta construida por el despliegue; nunca por metadata de una aplicacion investigada.
std::unique_ptr<PipeSession> launchSiblingBroker();
std::unique_ptr<PipeSession> launchSiblingBroker(WireVersion);
gatebouncer::websearch::ProviderConfig generalSearchConfiguration();
int runBrokerFromBootstrap(quintptr inheritedHandle);
}
