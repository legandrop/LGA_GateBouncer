#pragma once
#include "../general/GeneralClient.h"
#include "../general/GeneralDisclosures.h"
#include "../configuration/ProviderEntitlementVerifier.h"
#include <QPointer>

namespace Gate { class OrdinaryDecisionClient; }
namespace Gate::Assistance::Ui {
// Estado de presentación owned: no acuña solicitudes, permisos ni recibos.
class GeneralSession final : public QObject {
    Q_OBJECT
public:
    using Current=General::GeneralCoordinator::Current;
    GeneralSession(std::shared_ptr<General::FrameChannel>,Current,
                   std::function<bool()> presentationCurrent,
                   gatebouncer::websearch::ProviderConfig,QObject* parent=nullptr);
    ~GeneralSession() override;
    bool refresh();
    bool store(Broker::SensitiveBytes);
    bool forget();
    bool consent(Configuration::ConsentTarget,bool);
    bool mode(Configuration::ModeChoice);
    bool serviceUse(Configuration::ServiceUse);
    bool selectSearch();
    bool selectPending(const General::Id128&,General::PendingServiceContext);
    std::optional<General::FullBinding> pendingBinding() const;
    std::optional<General::Destination> observedDestination() const;
    std::optional<General::LocalFilePresentation> localFileFacts() const;
    bool reviewPublicFields(General::PublicFields);
    bool reviewLocalApplication(const OrdinaryDecisionClient&);
    bool clearPublicReview();
    bool publicReviewCurrent() const;
    bool explainReviewed();
    bool explain(General::FullBinding,General::PublicFields);
    bool approvePublic(General::FullBinding,General::PublicFields);
    bool explainApproved();
    bool publicApproved() const {return public_.has_value();}
    bool publicApprovalPending() const {return approving_;}
    void cancel();
    void invalidate();
    void close();
    bool busy() const {return busy_;}
    bool available() const;
    const std::optional<General::ConfigurationView>& configuration() const {return view_;}
    const std::optional<General::PresentationContext>& presentation() const {return presentation_;}
    const QString& modelBody() const {return modelBody_;}
    const QString& webBody() const {return webBody_;}
    const QString& problem() const {return problem_;}
    const std::optional<General::Result>& result() const {return result_;}
    General::State state() const {return state_;}
signals:
    void changed();
private:
    bool current(quint64) const;
    bool registerPublic(General::FullBinding,General::PublicFields,bool startAfterRegistration);
    void failed(const QString&);
    bool adopt(const Broker::Frame&,bool presentation);
    bool mutate(Configuration::ConfigurationMutation,std::shared_ptr<Broker::SensitiveBytes> = {});
    void completeMutation(Broker::Frame,quint64);
    std::shared_ptr<General::FrameChannel> channel_;
    std::unique_ptr<General::GeneralClient> client_;
    Current pendingCurrent_;
    std::function<bool()> presentationCurrent_;
    gatebouncer::websearch::ProviderConfig provider_;
    std::optional<General::ConfigurationView> view_;
    std::optional<General::PresentationContext> presentation_;
    std::optional<General::Result> result_;
    std::optional<General::ApprovedPublicContext> public_;
    std::optional<General::FullBinding> pendingBinding_;
    std::optional<General::PendingPresentationContext> pendingPresentation_;
    // Anotación del usuario para un snapshot exacto; nunca una identidad del archivo.
    struct PublicReview {
        General::FullBinding binding;
        General::PublicFields fields;
        QByteArray pendingBytes;
        General::Id128 connection;
    };
    std::optional<PublicReview> review_;
    QString modelBody_,webBody_,problem_;
    quint64 generation_=1;
    General::State state_=General::State::Insufficient;
    bool busy_=false,closed_=false,approving_=false;
};
}
