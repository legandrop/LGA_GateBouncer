#pragma once
#include "configuration/ConfigurationContracts.h"
#include "websearch/WebSearch.h"
#include <optional>
namespace Gate::Assistance::General {
// Presentación del aviso esperado: no es un snapshot ni un recibo otorgado.
class WebSearchDisclosure final {
public:
    const std::string& body() const {return body_;}
    const Configuration::ConsentReceipt& descriptor() const {return descriptor_;}
private:
    friend std::optional<WebSearchDisclosure> publicWebDisclosure(const gatebouncer::websearch::ProviderConfig&);
    WebSearchDisclosure(std::string body,Configuration::ConsentReceipt descriptor):body_(std::move(body)),descriptor_(std::move(descriptor)){}
    std::string body_;
    Configuration::ConsentReceipt descriptor_;
};
std::optional<WebSearchDisclosure> publicWebDisclosure(const gatebouncer::websearch::ProviderConfig&);
}
