#include "GeneralDisclosures.h"
#include "GeneralContracts.h"
#include <cstring>
namespace Gate::Assistance::General {
std::optional<WebSearchDisclosure> publicWebDisclosure(const gatebouncer::websearch::ProviderConfig& config) {
    namespace Web=gatebouncer::websearch;
    if(!Web::validConfiguration(config))return {};
    const auto bytes=QByteArray::fromHex(Web::configurationBinding(config));
    const auto body=Web::disclosure(config).toUtf8();
    if(bytes.size()!=32||!safeText(body.toStdString(),2048))return {};
    Configuration::ConsentReceipt descriptor;descriptor.noticeRevision=3;
    descriptor.profileRef=Configuration::GeneralProfile;descriptor.granted=false;descriptor.epoch=0;
    std::memcpy(descriptor.destinationPolicyBinding.data(),bytes.constData(),32);
    descriptor.noticeDigest=Configuration::digest("GB_WEB_NOTICE_1",reinterpret_cast<const unsigned char*>(body.constData()),std::size_t(body.size()));
    if(!Configuration::validReceipt(descriptor,true))return {};
    return WebSearchDisclosure(body.toStdString(),std::move(descriptor));
}
}
