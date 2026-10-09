#pragma once
#include "GeneralChannel.h"
#include "GeneralRuntime.h"
#include "GeneralWire.h"
#include <QObject>
namespace Gate::Assistance::General {
class GeneralServer final : public QObject {
public:
    // Configuración/estado los calcula su autoridad privada; no setters de derechos.
    using Control=std::function<std::optional<Broker::Frame>(Broker::Frame)>;
    GeneralServer(std::shared_ptr<FrameChannel>,std::shared_ptr<GeneralRuntime>,Control,QObject* parent=nullptr);
    ~GeneralServer() override;
    void close();
private:
    friend class GeneralFactory;
    using PendingCompletion=std::function<void(Broker::Frame,std::function<bool()>)>;
    using PendingControl=std::function<void(Broker::Frame,PendingCompletion)>;
    void setPendingControl(PendingControl,std::function<void()> retire);
    struct Data;
    std::shared_ptr<Data> data_;
};
}
