#pragma once
#include "GeneralCoordinator.h"
#include "configuration/ConfigurationContracts.h"
#include <QObject>
#include <QTimer>
namespace Gate::Assistance::Broker { class BrokerVault; }
namespace Gate::Assistance::Configuration { class ConfigurationController; class WindowsConfigurationStore; struct PermitResult; struct SearchBindingRef; struct ConsentReceipt; struct ModelDisclosure; }
namespace Gate::Assistance::General {
class GeneralFactory;
class GeneralJobRegistry;
class PrivateGeneralFactoryTest;
// Composición del broker: Current procede de snapshots canónicos, no de la GUI.
class GeneralRuntime final : public QObject {
public:
    GeneralRuntime(std::shared_ptr<SearchPort>,std::shared_ptr<ModelPort>,GeneralCoordinator::Current,
                   GeneralCoordinator::Clock,QObject* parent=nullptr);
    GeneralRuntime(std::shared_ptr<SearchPort>,Broker::BrokerVault&,
                   std::shared_ptr<Configuration::ConfigurationController>,GeneralCoordinator::Current,
                   GeneralCoordinator::Clock,QObject* parent=nullptr);
    ~GeneralRuntime() override;
    std::shared_ptr<const ApprovalRecord> approve(const FullBinding& pending,const PublicFields&,
                                                 const Id128& connection,const Id128& correlation);
    bool explain(const FullBinding&,const PublicFields&,GeneralCoordinator::Completion,GeneralCoordinator::Progress={});
    void cancel(const Id128& correlation);
    void withdraw();
    void drain();
private:
    struct Data;
    friend class GeneralFactory;
    friend class PrivateGeneralFactoryTest;
    GeneralRuntime(std::shared_ptr<SearchPort>,std::shared_ptr<Broker::BrokerVault>,
                   std::shared_ptr<Configuration::ConfigurationController>,std::shared_ptr<GeneralJobRegistry>,
                   GeneralCoordinator::Current,GeneralCoordinator::Clock);
    static bool admission(const std::shared_ptr<Data>&,const FullBinding&);
    void bindSearch(Configuration::SearchBindingRef,Configuration::ConsentReceipt);
    Configuration::ConsentReceipt modelNotice() const;
    Configuration::ModelDisclosure modelDisclosure() const;
    struct SearchPresentation {
        std::optional<Configuration::SearchBindingRef> binding;
        Configuration::ConsentReceipt notice;
        bool operator==(const SearchPresentation& other) const {return binding==other.binding&&notice==other.notice;}
    };
    SearchPresentation currentSearchPresentation() const;
    bool initializeEntitlement(std::shared_ptr<Configuration::WindowsConfigurationStore>);
    GeneralRuntime(GeneralCoordinator::Current,GeneralCoordinator::Clock,QObject*);
    void compose(std::shared_ptr<SearchPort>,std::shared_ptr<ModelPort>);
    static Configuration::PermitResult authorize(const std::shared_ptr<Data>&,
        const FullBinding&,const SealedGeneralPayload&,const std::shared_ptr<const void>&);
    std::shared_ptr<Data> data_;
    QTimer deadline_;
};
}
