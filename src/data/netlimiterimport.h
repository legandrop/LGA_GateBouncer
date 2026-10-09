#pragma once
#include "contracts.h"
#include <QIODevice>

namespace Gate::Data {
class NetLimiterImport final {
  public:
    static ImportReport analyze(QIODevice &input, const ImportLimits &limits = {});
};
} // namespace Gate::Data
