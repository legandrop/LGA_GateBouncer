#pragma once
#include "GeneralServer.h"
#include "GeneralDisclosures.h"
#include "configuration/WindowsConfigurationStore.h"
#include "PendingPresentationContext.h"
namespace Gate::Assistance::General {
// Compositor de una conexión nativa: el ingreso local y la activación son distintos.
class GeneralFactory final {
public:
    static std::unique_ptr<GeneralFactory> forCurrentUser(std::unique_ptr<Broker::PipeSession>,
        GeneralCoordinator::Current,const gatebouncer::websearch::ProviderConfig&);
    ~GeneralFactory();
    GeneralFactory(const GeneralFactory&)=delete;
    GeneralFactory& operator=(const GeneralFactory&)=delete;
    ConfigurationView status() const;
    std::optional<Configuration::SearchBindingRef> searchReference() const;
    void close();
private:
    friend class GeneralBrokerHost;
    friend class PrivateGeneralFactoryTest;
    bool peerCurrent() const;
    struct PendingResolver {
        using Completion=std::function<void(std::shared_ptr<const OwnedPendingPresentation>)>;
        std::function<void(const PendingQuerySelection&,Completion)> resolve;
        std::function<void()> retire;
    };
    static std::unique_ptr<GeneralFactory> forHost(std::unique_ptr<Broker::PipeSession>,
        GeneralCoordinator::Current,const gatebouncer::websearch::ProviderConfig&,PendingResolver);
    struct Data;
    GeneralFactory(std::shared_ptr<FrameChannel>,std::shared_ptr<Configuration::ConfigurationController>,
        std::shared_ptr<Configuration::WindowsConfigurationStore>,
        std::shared_ptr<gatebouncer::websearch::SearchClient>,
        const gatebouncer::websearch::ProviderConfig&,GeneralCoordinator::Current,PendingResolver={});
    std::shared_ptr<Data> data_;
};
}
