#pragma once
#include "GeneralRuntime.h"
#include "GeneralJobRegistry.h"
#include "configuration/ConfigurationController.h"
#include "configuration/ConfigurationPolicy.h"
#include "configuration/ProviderEntitlementVerifier.h"
namespace Gate::Assistance::General {
struct GeneralRuntime::Data {
    struct Job {
        std::shared_ptr<const ApprovalRecord> record;
        std::shared_ptr<const void> modelToken;
        std::uint64_t serial=0,deadline=0;
        bool claimed=false;
    };
    std::shared_ptr<GeneralCoordinator> coordinator;
    GeneralCoordinator::Current current;
    GeneralCoordinator::Clock clock;
    std::shared_ptr<Configuration::ConfigurationController> configuration;
    std::shared_ptr<QObject> reviewDispatcher;
    std::shared_ptr<Configuration::ProviderEntitlementVerifier> verifier;
    std::shared_ptr<GeneralJobRegistry> registry;
    std::function<bool(const FullBinding&)> admission;
    std::unique_ptr<Configuration::NetworkActivationIssuer> issuer;
    std::shared_ptr<const ApprovalRecord> approval;
    std::shared_ptr<const ApprovalRecord> usedApproval;
    std::shared_ptr<Job> job;
    Id128 connection{},correlation{};
    std::uint64_t epoch=0,serial=0,jobSerial=0;
    bool closed=false;
};
}
