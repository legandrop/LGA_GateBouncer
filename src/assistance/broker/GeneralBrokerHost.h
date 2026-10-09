#pragma once
#include "../general/GeneralFactory.h"
#include <QObject>
#include <memory>

namespace Gate::Assistance::General {
// Sólo compone el broker ordinary y observaciones locales propias.
class GeneralBrokerHost final : public QObject {
public:
    static std::unique_ptr<GeneralBrokerHost> forCurrentUser(std::unique_ptr<Broker::PipeSession>,
        const gatebouncer::websearch::ProviderConfig&);
    ~GeneralBrokerHost() override;
    void close();
private:
    struct Data;
    struct OwnedFacts;
    explicit GeneralBrokerHost(QObject* parent=nullptr);
    std::shared_ptr<Data> data_;
};
}
