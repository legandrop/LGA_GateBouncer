#pragma once
#include "GeneralChannel.h"
#include "GeneralCoordinator.h"
#include "GeneralWire.h"
#include "configuration/ConfigurationController.h"
#include "PendingPresentationContext.h"
#include <QObject>
namespace Gate::Assistance::General {
struct ApprovedPublicContext {FullBinding binding;PublicFields fields;};
class GeneralClient final : public QObject {
public:
    using ApprovalCompletion=std::function<void(std::optional<ApprovedPublicContext>,Failure)>;
    using ControlCompletion=std::function<void(Broker::Frame)>;
    GeneralClient(std::shared_ptr<FrameChannel>,GeneralCoordinator::Current,QObject* parent=nullptr);
    ~GeneralClient() override;
    bool approve(FullBinding,PublicFields,ApprovalCompletion);
    bool explain(const FullBinding&,const PublicFields&,GeneralCoordinator::Completion,GeneralCoordinator::Progress={});
    // El ingreso de credencial pertenece al frente de configuración, no a este wrapper.
    bool control(Broker::Frame,ControlCompletion);
    bool configurationStatus(bool presentation,std::function<bool()> currentContext,ControlCompletion);
    bool pendingStatus(const Id128& request,PendingServiceContext captured,
        std::function<bool()> currentContext,ControlCompletion);
    bool storeCredential(Configuration::ConfigurationIntent,Broker::SensitiveBytes,ControlCompletion);
    void cancel();
    bool settled() const;
    void close();
private:
    struct Data;
    bool presentationStatus(std::optional<Id128>,PendingServiceContext,std::function<bool()>,ControlCompletion);
    std::shared_ptr<Data> data_;
};
}
