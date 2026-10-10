#pragma once
#include "GeneralContracts.h"
#include "websearch/WebSearch.h"
#include <QObject>
namespace Gate::Assistance::General {
class QtSearchAdapter final : public QObject,public SearchPort {
public:
    QtSearchAdapter(std::shared_ptr<gatebouncer::websearch::SearchClient>,QObject* parent=nullptr);
    ~QtSearchAdapter() override;
    bool begin(const FullBinding&,const PublicFields&,Completion) override;
    bool beginCurrent(const FullBinding&,const PublicFields&,Completion,std::function<bool()>) override;
    void cancel() override;
private:
    struct Pending {FullBinding binding;PublicFields fields;Completion completion;};
    void receive(const gatebouncer::websearch::SearchResult&);
    std::shared_ptr<gatebouncer::websearch::SearchClient> client_;
    std::optional<Pending> pending_;
    QMetaObject::Connection connection_;
};
}
