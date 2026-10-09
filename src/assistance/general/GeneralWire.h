#pragma once
#include "GeneralPayload.h"
#include "../broker/BrokerWire.h"
#include "configuration/ConfigurationContracts.h"
#include "PresentationContext.h"
namespace Gate::Assistance::General {
bool validGeneralFrame(const Broker::Frame&);
std::optional<FullBinding> frameBinding(const Broker::Frame&,bool approvalPending=false);
std::optional<PublicFields> framePublicFields(const Broker::Frame&);
std::optional<std::vector<Citation>> frameCitations(const Broker::Frame&);
std::optional<Result> frameResult(const Broker::Frame&);
bool setFrameBinding(Broker::Frame&,const FullBinding&);
bool setPublicFields(Broker::Frame&,const PublicFields&);
bool setResult(Broker::Frame&,const Result&);
struct ConfigurationView { Configuration::ConfigurationSnapshot local; Configuration::NetworkActivationSnapshot activation; };
std::optional<ConfigurationView> configurationView(const QByteArray& snapshot70);
std::optional<QByteArray> configurationBytes(const ConfigurationView&);
std::optional<Configuration::ConfigurationMutation> configurationUpdate(const QByteArray& update74);
std::optional<QByteArray> configurationBytes(const Configuration::ConfigurationMutation&);
}
