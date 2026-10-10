#pragma once
#include "OriginalBootstrapProtocol.hpp"
#include <utility>
namespace gb {
class OwnHostLinuxOriginal;
class OwnCloudSeed final {
    friend class OwnHostLinuxOriginal;
    OwnCloudSeed()=delete;
    // Constructor de bytes públicos; la operación filesystem pertenece al owner original.
    static original::Bytes MakeOwn(const std::vector<std::pair<std::string,original::Bytes>>&);
};
}
