#pragma once
#include "GeneralPayload.h"
#include "configuration/ConfigurationPolicy.h"
#include "WinHttpExplanationTransport.h"
namespace Gate::Assistance::Configuration { class ConfigurationController; }
namespace Gate::Assistance::General {
// Sólo la composición del broker construye este adaptador y emite su autorización.
class GeneralModelTransport final : public ModelPort {
public:
    ~GeneralModelTransport() override;
    std::unique_ptr<Operation> begin(const FullBinding&,const SealedGeneralPayload&,Completion) override;
private:
    friend class GeneralRuntime;
    using Authorize=std::function<Configuration::PermitResult(const FullBinding&,
        const SealedGeneralPayload&,const std::shared_ptr<const void>&)>;
    GeneralModelTransport(Broker::BrokerVault&,Authorize);
    GeneralModelTransport(std::shared_ptr<Broker::BrokerVault>,
        std::shared_ptr<Configuration::ConfigurationController>,Authorize);
    struct Data;
    std::shared_ptr<Data> data_;
};
}
