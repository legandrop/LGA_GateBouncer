#pragma once
#include "GeneralContracts.h"
namespace Gate::Assistance::General::Detail {
std::optional<std::string> inferenceJson(const Inference&,const std::vector<Citation>&);
}
