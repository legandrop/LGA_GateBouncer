#pragma once
#include "GeneralContracts.h"
#include "configuration/ConfigurationContracts.h"
#include <QByteArray>
namespace Gate::Assistance::General {
struct ConfigurationView;
class GeneralFactory;
class PrivateGeneralFactoryTest;
// Selección y avisos esperados: nunca se convierten en un snapshot canónico.
class PresentationContext final {
public:
    const Id128& connection() const {return connection_;}
    const Id128& storeInstance() const {return storeInstance_;}
    std::uint64_t configurationRevision() const {return configurationRevision_;}
    std::uint64_t sessionEpoch() const {return sessionEpoch_;}
    const std::optional<Configuration::SearchBindingRef>& searchReference() const {return search_;}
    const std::optional<Configuration::ConsentReceipt>& expectedModel() const {return model_;}
    const std::optional<Configuration::ConsentReceipt>& expectedWeb() const {return web_;}
private:
    friend class GeneralFactory;
    friend class PrivateGeneralFactoryTest;
    friend std::optional<PresentationContext> presentationContext(const QByteArray&,const ConfigurationView&,const Id128&);
    PresentationContext(Id128 connection,Id128 store,std::uint64_t revision,std::uint64_t session,
        std::optional<Configuration::SearchBindingRef> search,std::optional<Configuration::ConsentReceipt> model,
        std::optional<Configuration::ConsentReceipt> web):connection_(connection),storeInstance_(store),
        configurationRevision_(revision),sessionEpoch_(session),search_(std::move(search)),model_(std::move(model)),web_(std::move(web)){}
    Id128 connection_,storeInstance_;
    std::uint64_t configurationRevision_,sessionEpoch_;
    std::optional<Configuration::SearchBindingRef> search_;
    std::optional<Configuration::ConsentReceipt> model_,web_;
};
std::optional<PresentationContext> presentationContext(const QByteArray&,const ConfigurationView&,const Id128&);
std::optional<QByteArray> presentationBytes(const PresentationContext&,const ConfigurationView&,const Id128&);
bool sameConfigurationView(const ConfigurationView&,const ConfigurationView&);
}
