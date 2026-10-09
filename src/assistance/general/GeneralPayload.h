#pragma once
#include "GeneralContracts.h"
namespace Gate::Assistance::General {
class SealedGeneralPayload final {
public:
    SealedGeneralPayload(const SealedGeneralPayload&)=default;
    std::string_view bytes() const { return bytes_; }
    Digest256 payloadDigest() const { return digest_; }
    const std::vector<Citation>& citations() const { return citations_; }
    const PublicFields& publicFields() const { return public_; }
    const Digest256& bindingDigest() const { return binding_; }
private:
    friend class GeneralPayloadBuilder;
    SealedGeneralPayload(std::string,Digest256,PublicFields,std::vector<Citation>);
    const std::string bytes_;
    const Digest256 digest_,binding_;
    const PublicFields public_;
    const std::vector<Citation> citations_;
};
class GeneralPayloadBuilder final {
public:
    static std::optional<SealedGeneralPayload> build(const FullBinding&,const PublicFields&,const std::vector<Citation>&);
    static bool validProfile(const SealedGeneralPayload&,const FullBinding&);
    static std::optional<std::string> publicJson(const PublicFields&);
    static std::optional<std::string> citationsJson(const std::vector<Citation>&);
};
class General3ResponseContract final {
public:
    static std::optional<Inference> parseInference(std::string_view,const std::vector<Citation>&);
    static std::optional<std::string> normalize(std::string_view,const SealedGeneralPayload&);
};
}
