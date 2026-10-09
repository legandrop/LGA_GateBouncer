#pragma once
#include "NativeRead.h"
#include "../AllAppsModel.h"

namespace gatebouncer::service::windows::allapps::native {
constexpr std::size_t MaxConditions = 32, MaxProofBytes = 64 * 1024;
struct ConditionShape { Guid key{}; FWP_MATCH_TYPE match{}; FWP_DATA_TYPE type{}; ai::Bytes bytes; };
struct FilterShape {
    Guid key{}, provider{}, sublayer{}, layer{}, actionKey{}, contextKey{};
    std::uint64_t id = 0, rawContext = 0;
    std::uint32_t flags = 0;
    FWP_ACTION_TYPE action{};
    FWP_DATA_TYPE weightType{};
    std::uint64_t weight = 0;
    std::vector<ConditionShape> conditions;
};
// Forma copiada sin autoridad de origen: tampoco una fixture es NativeProof.
Reason copyFilterShape(const FWPM_FILTER0*, FilterShape&) noexcept;
bool sameShape(const FilterShape&, const FilterShape&) noexcept;
Layer logicalLayer(const Guid&) noexcept;
Guid guidBytes(const GUID&) noexcept;
} // namespace gatebouncer::service::windows::allapps::native
